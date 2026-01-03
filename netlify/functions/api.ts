/* File: netlify/functions/api.ts */

import type { Config, Context } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config: Config = {
  path: "/api/*",
};

type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

type LeadStatus = "hot" | "new" | "follow_up" | "appointment" | "landed" | "no" | "archived";
type AppointmentStatus = "booked" | "canceled" | "completed";

type Lead = {
  id: string;
  createdAt: string;
  updatedAt: string;
  source: "public";
  status: LeadStatus;
  name: string;
  phone?: string;
  email?: string;
  service?: string;
  notes?: string;
  preferredDate?: string;
  preferredTime?: string;
  followUpAt?: string;

  // pull-once / assignment
  assignedTo?: string;
  pulledAt?: string;

  timeline: Array<{ at: string; type: string; note?: string }>;
};

type Appointment = {
  id: string;
  createdAt: string;
  updatedAt: string;
  status: AppointmentStatus;
  service: string;
  startAt: string;
  endAt: string;
  customer: { name: string; phone?: string; email?: string };
  notes?: string;
  leadId?: string;
};

type Todo = {
  id: string;
  createdAt: string;
  updatedAt: string;
  text: string;
  done: boolean;
  dueAt?: string;
};

/**
 * Device snapshot sync (CRM merges on client).
 * - customers: full device state
 * - tombstones: deletions by id (deletedAt ISO) so deletes sync across devices
 */
type Customer = {
  id: string;
  createdAt: string;
  updatedAt: string;
  [k: string]: any;
};

type DeviceSnapshot = {
  deviceId: string;
  at: string;
  customers: Customer[];
  tombstones: Record<string, string>;
};

type JwtPayload = {
  sub: string;
  role: "admin" | "staff";
  iat: number;
  exp: number;
};

type SlotLock = { ids: string[] };

type SyncMeta = { version: number; updatedAt: string };

type EnvConfig = {
  jwtSecret: string; // JWT_SECRET
  allowedOrigins: string[] | null; // ALLOWED_ORIGINS (comma-separated), null = "*"
  crmUsername: string | null; // CRM_USERNAME
  crmPasswordHash: string | null; // CRM_PASSWORD_HASH (sha256 hex)
  crmPassword: string | null; // optional: CRM_PASSWORD (plaintext fallback)
  slotMinutes: number;
  openHour: number;
  closeHour: number;
  capacityPerSlot: number;
  tz: string;
  publicDailyRateLimit: number;
};

const STORE_NAME = "crm";
const CONSISTENCY: "strong" = "strong";

export default async function handler(req: Request, context: Context) {
  const url = new URL(req.url);
  const path = normalizeApiPath(url.pathname);

  // Always respond to health even if env vars are missing.
  if (path === "/api/health" && req.method === "GET") {
    return respondJson({ ok: true }, 200, buildCorsHeaders(readEnvSafe(), req.headers.get("origin") ?? ""));
  }

  const env = readEnvSafe();
  const origin = req.headers.get("origin") ?? "";
  const corsHeaders = buildCorsHeaders(env, origin);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const store = getStore({ name: STORE_NAME, consistency: CONSISTENCY });
    return await route({ req, context, env, store, url, path, corsHeaders });
  } catch {
    return respondJson({ error: "internal_error" }, 500, corsHeaders);
  }
}

async function route(args: {
  req: Request;
  context: Context;
  env: EnvConfig;
  store: ReturnType<typeof getStore>;
  url: URL;
  path: string;
  corsHeaders: Headers;
}): Promise<Response> {
  const { req, env, store, url, path } = args;

  if (path === "/api/health" && req.method === "GET") {
    return respondJson({ ok: true }, 200, args.corsHeaders);
  }

  // ---- AUTH ----
  if (path === "/api/auth/login" && req.method === "POST") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const body = await safeJson(req);
    const username = asString(body?.username);
    const password = asString(body?.password);
    if (!username || !password) return respondJson({ error: "missing_credentials" }, 400, args.corsHeaders);

    const user = verifyUser(env, username, password);
    if (!user) return respondJson({ error: "invalid_credentials" }, 401, args.corsHeaders);

    const token = signJwt(env.jwtSecret, {
      sub: username,
      role: user.role,
      iat: nowSec(),
      exp: nowSec() + 60 * 60 * 12,
    });

    return respondJson({ token, role: user.role }, 200, args.corsHeaders);
  }

  // ---- Public endpoints ----

  // NEW: Hot leads endpoint (Schedule a Call) with server-side dedupe
  if (path === "/api/public/hot-leads" && req.method === "POST") {
    const ip = clientIp(args);
    const limited = await rateLimit(store, ip, env.publicDailyRateLimit);
    if (!limited.ok) return respondJson({ error: "rate_limited" }, 429, args.corsHeaders);

    const body = await safeJson(req);

    // Honeypot (use "hp" so "website" can be real user data)
    const honeypot = asString(body?.hp);
    if (honeypot) return respondJson({ ok: true }, 200, args.corsHeaders);

    const name = requiredString(body?.name);
    if (!name) return respondJson({ error: "missing_name" }, 400, args.corsHeaders);

    const email = optionalString(body?.email);
    const phone = optionalString(body?.phone);

    // ✅ server-side dedupe: primary id already unique; fallback email/phone
    const existingId = await findExistingLeadIdByContact(store, { email, phone });
    if (existingId) {
      await safeAppendLeadEvent(store, existingId, { type: "duplicate_submit_hot" });
      return respondJson({ ok: true, leadId: existingId, deduped: true }, 200, args.corsHeaders);
    }

    const leadId = crypto.randomUUID();

    // reserve contact indexes (prevents races)
    const reserved = await reserveContactIndexes(store, { id: leadId, email, phone });
    if (!reserved.ok) {
      // another lead won the race; return that id
      await safeAppendLeadEvent(store, reserved.existingId, { type: "duplicate_submit_hot" });
      return respondJson({ ok: true, leadId: reserved.existingId, deduped: true }, 200, args.corsHeaders);
    }

    const lead: Lead = {
      id: leadId,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      source: "public",
      status: "hot",
      name,
      phone,
      email,
      service: optionalString(body?.service),
      notes: optionalString(body?.notes),
      preferredDate: optionalString(body?.preferredDate),
      preferredTime: optionalString(body?.preferredTime),
      timeline: [{ at: nowIso(), type: "hot_created" }],
    };

    const created = await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
    if (!created.modified) {
      await releaseReservedContactIndexes(store, { id: leadId, email, phone });
      return respondJson({ error: "create_failed" }, 500, args.corsHeaders);
    }

    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: true },
    );

    return respondJson({ ok: true, leadId: lead.id }, 200, args.corsHeaders);
  }

  // Existing inquiries endpoint (updated honeypot from "website" -> "hp") with server-side dedupe
  if (path === "/api/public/inquiries" && req.method === "POST") {
    const ip = clientIp(args);
    const limited = await rateLimit(store, ip, env.publicDailyRateLimit);
    if (!limited.ok) return respondJson({ error: "rate_limited" }, 429, args.corsHeaders);

    const body = await safeJson(req);
    const honeypot = asString(body?.hp);
    if (honeypot) return respondJson({ ok: true }, 200, args.corsHeaders);

    const name = requiredString(body?.name);
    if (!name) return respondJson({ error: "missing_name" }, 400, args.corsHeaders);

    const email = optionalString(body?.email);
    const phone = optionalString(body?.phone);

    const existingId = await findExistingLeadIdByContact(store, { email, phone });
    if (existingId) {
      await safeAppendLeadEvent(store, existingId, { type: "duplicate_submit_inquiry" });
      return respondJson({ ok: true, leadId: existingId, deduped: true }, 200, args.corsHeaders);
    }

    const leadId = crypto.randomUUID();

    const reserved = await reserveContactIndexes(store, { id: leadId, email, phone });
    if (!reserved.ok) {
      await safeAppendLeadEvent(store, reserved.existingId, { type: "duplicate_submit_inquiry" });
      return respondJson({ ok: true, leadId: reserved.existingId, deduped: true }, 200, args.corsHeaders);
    }

    const lead: Lead = {
      id: leadId,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      source: "public",
      status: "new",
      name,
      phone,
      email,
      service: optionalString(body?.service),
      notes: optionalString(body?.notes),
      preferredDate: optionalString(body?.preferredDate),
      preferredTime: optionalString(body?.preferredTime),
      timeline: [{ at: nowIso(), type: "created" }],
    };

    const created = await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
    if (!created.modified) {
      await releaseReservedContactIndexes(store, { id: leadId, email, phone });
      return respondJson({ error: "create_failed" }, 500, args.corsHeaders);
    }

    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: true },
    );

    return respondJson({ ok: true, leadId: lead.id }, 200, args.corsHeaders);
  }

  if (path === "/api/public/availability" && req.method === "GET") {
    const date = url.searchParams.get("date") ?? "";
    if (!isDateYmd(date)) return respondJson({ error: "invalid_date" }, 400, args.corsHeaders);

    const service = url.searchParams.get("service") ?? "default";
    const slots = await computeAvailability(store, env, date, service);

    return respondJson({ date, service, slots }, 200, args.corsHeaders);
  }

  if (path === "/api/public/bookings" && req.method === "POST") {
    const ip = clientIp(args);
    const limited = await rateLimit(store, ip, env.publicDailyRateLimit);
    if (!limited.ok) return respondJson({ error: "rate_limited" }, 429, args.corsHeaders);

    const body = await safeJson(req);
    const honeypot = asString(body?.hp);
    if (honeypot) return respondJson({ ok: true }, 200, args.corsHeaders);

    const name = requiredString(body?.name);
    const service = requiredString(body?.service) ?? "default";
    const date = requiredString(body?.date);
    const time = requiredString(body?.time);

    if (!name) return respondJson({ error: "missing_name" }, 400, args.corsHeaders);
    if (!isDateYmd(date)) return respondJson({ error: "invalid_date" }, 400, args.corsHeaders);
    if (!isTimeHm(time)) return respondJson({ error: "invalid_time" }, 400, args.corsHeaders);

    const startAt = toIsoFromLocal(date, time);
    const endAt = new Date(new Date(startAt).getTime() + env.slotMinutes * 60_000).toISOString();

    const appointmentId = crypto.randomUUID();
    const slotKey = slotLockKey(date, time, service);

    const reserved = await reserveSlot(store, slotKey, appointmentId, env.capacityPerSlot);
    if (!reserved.ok) return respondJson({ error: "slot_unavailable" }, 409, args.corsHeaders);

    const appt: Appointment = {
      id: appointmentId,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      status: "booked",
      service,
      startAt,
      endAt,
      customer: {
        name,
        phone: optionalString(body?.phone),
        email: optionalString(body?.email),
      },
      notes: optionalString(body?.notes),
      leadId: optionalString(body?.leadId),
    };

    const created = await store.setJSON(`appointments/${appt.id}`, appt, { onlyIfNew: true });
    if (!created.modified) {
      await releaseSlot(store, slotKey, appointmentId);
      return respondJson({ error: "booking_failed" }, 500, args.corsHeaders);
    }

    if (appt.leadId) {
      await patchLead(store, appt.leadId, (lead) => ({
        ...lead,
        status: lead.status === "landed" ? lead.status : "appointment",
        updatedAt: nowIso(),
        timeline: [...lead.timeline, { at: nowIso(), type: "appointment_created", note: appt.id }],
      }));
    }

    return respondJson(
      {
        ok: true,
        appointmentId: appt.id,
        startAt: appt.startAt,
        endAt: appt.endAt,
      },
      200,
      args.corsHeaders,
    );
  }

  // ---- Device Snapshot Sync (JWT required) ----
  if (path === "/api/snapshots" && req.method === "GET") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);

    const { blobs } = await store.list({ prefix: "snapshots/" });
    const keys = blobs.map((b) => b.key).sort().slice(0, 500);

    const snapshots: DeviceSnapshot[] = [];
    for (const k of keys) {
      const raw = (await store.get(k, { type: "json" })) as any | null;
      if (!raw) continue;

      const deviceIdFromKey = k.split("/").pop() ?? "";
      const snap = asDeviceSnapshot(raw, deviceIdFromKey);
      if (snap) snapshots.push(snap);
    }

    return respondJson({ ok: true, snapshots } as any, 200, args.corsHeaders);
  }

  if (path.startsWith("/api/snapshots/")) {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);

    const deviceId = decodeURIComponent(path.slice("/api/snapshots/".length));
    if (!deviceId || !isSafeDeviceId(deviceId)) {
      return respondJson({ error: "invalid_deviceId" }, 400, args.corsHeaders);
    }

    const key = snapshotKey(deviceId);

    if (req.method === "GET") {
      const raw = (await store.get(key, { type: "json" })) as any | null;
      if (!raw) return respondJson({ error: "not_found" }, 404, args.corsHeaders);

      const snap = asDeviceSnapshot(raw, deviceId);
      if (!snap) return respondJson({ error: "corrupt_snapshot" }, 500, args.corsHeaders);

      return respondJson({ ok: true, snapshot: snap } as any, 200, args.corsHeaders);
    }

    if (req.method === "PUT" || req.method === "POST") {
      const body = await safeJson(req);
      if (!body) return respondJson({ error: "missing_json" }, 400, args.corsHeaders);

      const snap = asDeviceSnapshot(body, deviceId);
      if (!snap) return respondJson({ error: "invalid_snapshot" }, 400, args.corsHeaders);

      const toStore: DeviceSnapshot = {
        ...snap,
        deviceId,
        at: nowIso(),
      };

      await store.setJSON(key, toStore as any);
      return respondJson({ ok: true }, 200, args.corsHeaders);
    }

    return respondJson({ error: "not_found" }, 404, args.corsHeaders);
  }

  // ---- Sync endpoints (JWT required) ----

  // Sync Down (new device bootstrapping)
  if (path === "/api/sync" && req.method === "GET") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);

    const workspaceId = safeText(url.searchParams.get("workspaceId"));
    if (!workspaceId) return respondJson({ error: "missing_workspaceId" }, 400, args.corsHeaders);

    const meta = await getSyncMeta(store, workspaceId);
    const snapshot = await exportSnapshot(store);

    return respondJson(
      {
        ok: true,
        workspaceId,
        meta,
        snapshot,
      } as any,
      200,
      args.corsHeaders,
    );
  }

  // Sync Up (merge client changes)
  if (path === "/api/sync" && req.method === "POST") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);

    const body = await safeJson(req);
    const workspaceId = safeText(body?.workspaceId) || safeText(url.searchParams.get("workspaceId"));
    if (!workspaceId) return respondJson({ error: "missing_workspaceId" }, 400, args.corsHeaders);

    const incoming = body?.snapshot as
      | { leads?: Lead[]; appointments?: Appointment[]; slots?: Record<string, SlotLock>; todos?: Todo[] }
      | undefined;

    if (!incoming) return respondJson({ error: "missing_snapshot" }, 400, args.corsHeaders);

    // Load server state
    const server = await exportSnapshot(store);

    const merged = await mergeSnapshots(store, {
      server,
      incoming,
      actor: auth.payload.sub,
    });

    // Persist merged snapshot (upserts only; does not delete)
    await persistMergedSnapshot(store, merged);

    // Bump meta (version + updatedAt)
    const meta = await bumpSyncMeta(store, workspaceId);

    const latest = await exportSnapshot(store);
    return respondJson(
      {
        ok: true,
        workspaceId,
        meta,
        snapshot: latest,
      } as any,
      200,
      args.corsHeaders,
    );
  }

  // ---- Pull-once leads endpoint (JWT required) ----
  // POST /api/leads/pull -> returns only unpulled/unassigned, consumes them immediately (moves to pulled/)
  if (path === "/api/leads/pull" && req.method === "POST") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);

    const body = await safeJson(req);
    const limit = clampInt(asString(body?.limit) ?? url.searchParams.get("limit"), 1, 200, 50);
    const status = (asString(body?.status) ?? url.searchParams.get("status") ?? "hot") as LeadStatus;

    const pulled = await pullOnceConsumeLeads(store, {
      limit,
      status,
      assignedTo: auth.payload.sub,
    });

    return respondJson({ ok: true, pulled: pulled.length, leads: pulled } as any, 200, args.corsHeaders);
  }

  // ---- CRM endpoints (JWT required) ----
  if (path.startsWith("/api/crm/")) {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);

    if (path === "/api/crm/leads" && req.method === "GET") {
      const status = url.searchParams.get("status");
      const q = url.searchParams.get("q");
      const limit = clampInt(url.searchParams.get("limit"), 1, 200, 50);

      const leads = await listLeads(store, { status: status ?? undefined, q: q ?? undefined, limit });
      return respondJson({ leads } as any, 200, args.corsHeaders);
    }

    if (path.startsWith("/api/crm/leads/")) {
      const id = path.split("/").pop() ?? "";
      if (!id) return respondJson({ error: "missing_id" }, 400, args.corsHeaders);

      if (req.method === "GET") {
        const lead = (await store.get(`leads/${id}`, { type: "json" })) as Lead | null;
        if (!lead) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ lead } as any, 200, args.corsHeaders);
      }

      if (req.method === "PUT") {
        const body = await safeJson(req);
        const status = optionalString(body?.status) as LeadStatus | undefined;
        const notes = optionalString(body?.notes);
        const followUpAt = optionalString(body?.followUpAt);
        const assignedTo = optionalString(body?.assignedTo);

        const updated = await patchLead(store, id, (lead) => ({
          ...lead,
          updatedAt: nowIso(),
          status: status ?? lead.status,
          notes: notes ?? lead.notes,
          followUpAt: followUpAt ?? lead.followUpAt,
          assignedTo: assignedTo ?? lead.assignedTo,
          timeline: [...lead.timeline, { at: nowIso(), type: "updated" }],
        }));

        if (!updated) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ ok: true }, 200, args.corsHeaders);
      }
    }

    if (path === "/api/crm/appointments" && req.method === "GET") {
      const from = url.searchParams.get("from");
      const to = url.searchParams.get("to");
      const limit = clampInt(url.searchParams.get("limit"), 1, 500, 200);

      const appts = await listAppointments(store, { from: from ?? undefined, to: to ?? undefined, limit });
      return respondJson({ appointments: appts } as any, 200, args.corsHeaders);
    }

    if (path === "/api/crm/appointments" && req.method === "POST") {
      const body = await safeJson(req);
      const service = requiredString(body?.service) ?? "default";
      const date = requiredString(body?.date);
      const time = requiredString(body?.time);
      const name = requiredString(body?.name);
      if (!service || !isDateYmd(date) || !isTimeHm(time) || !name) {
        return respondJson({ error: "invalid_input" }, 400, args.corsHeaders);
      }

      const startAt = toIsoFromLocal(date, time);
      const endAt = new Date(new Date(startAt).getTime() + env.slotMinutes * 60_000).toISOString();

      const appointmentId = crypto.randomUUID();
      const slotKey = slotLockKey(date, time, service);

      const reserved = await reserveSlot(store, slotKey, appointmentId, env.capacityPerSlot);
      if (!reserved.ok) return respondJson({ error: "slot_unavailable" }, 409, args.corsHeaders);

      const appt: Appointment = {
        id: appointmentId,
        createdAt: nowIso(),
        updatedAt: nowIso(),
        status: "booked",
        service,
        startAt,
        endAt,
        customer: { name, phone: optionalString(body?.phone), email: optionalString(body?.email) },
        notes: optionalString(body?.notes),
        leadId: optionalString(body?.leadId),
      };

      const created = await store.setJSON(`appointments/${appt.id}`, appt, { onlyIfNew: true });
      if (!created.modified) {
        await releaseSlot(store, slotKey, appointmentId);
        return respondJson({ error: "create_failed" }, 500, args.corsHeaders);
      }

      return respondJson({ ok: true, appointmentId: appt.id } as any, 200, args.corsHeaders);
    }

    if (path.startsWith("/api/crm/appointments/")) {
      const id = path.split("/").pop() ?? "";
      if (!id) return respondJson({ error: "missing_id" }, 400, args.corsHeaders);

      if (req.method === "GET") {
        const appt = (await store.get(`appointments/${id}`, { type: "json" })) as Appointment | null;
        if (!appt) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ appointment: appt } as any, 200, args.corsHeaders);
      }

      if (req.method === "PUT") {
        const body = await safeJson(req);
        const patch = {
          status: optionalString(body?.status) as AppointmentStatus | undefined,
          notes: optionalString(body?.notes),
        };

        const updated = await patchAppointment(store, id, (appt) => ({
          ...appt,
          updatedAt: nowIso(),
          status: patch.status ?? appt.status,
          notes: patch.notes ?? appt.notes,
        }));

        if (!updated) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ ok: true }, 200, args.corsHeaders);
      }

      if (req.method === "DELETE") {
        const appt = (await store.get(`appointments/${id}`, { type: "json" })) as Appointment | null;
        if (!appt) return respondJson({ error: "not_found" }, 404, args.corsHeaders);

        const { date, time } = splitIsoToDateTime(appt.startAt);
        const slotKey = slotLockKey(date, time, appt.service);

        await patchAppointment(store, id, (a) => ({ ...a, updatedAt: nowIso(), status: "canceled" }));
        await releaseSlot(store, slotKey, id);

        return respondJson({ ok: true }, 200, args.corsHeaders);
      }
    }

    if (path === "/api/crm/metrics" && req.method === "GET") {
      const metrics = await computeMetrics(store);
      return respondJson({ metrics } as any, 200, args.corsHeaders);
    }

    if (path === "/api/crm/export" && req.method === "POST") {
      if (auth.payload.role !== "admin") return respondJson({ error: "forbidden" }, 403, args.corsHeaders);
      const snapshot = await exportSnapshot(store);
      return respondJson({ snapshot } as any, 200, args.corsHeaders);
    }

    if (path === "/api/crm/import" && req.method === "POST") {
      if (auth.payload.role !== "admin") return respondJson({ error: "forbidden" }, 403, args.corsHeaders);

      const body = await safeJson(req);
      const snapshot = body?.snapshot as
        | { leads?: Lead[]; appointments?: Appointment[]; slots?: Record<string, SlotLock>; todos?: Todo[] }
        | undefined;
      if (!snapshot) return respondJson({ error: "missing_snapshot" }, 400, args.corsHeaders);

      await importSnapshot(store, snapshot);
      return respondJson({ ok: true }, 200, args.corsHeaders);
    }

    return respondJson({ error: "not_found" }, 404, args.corsHeaders);
  }

  return respondJson({ error: "not_found" }, 404, args.corsHeaders);
}

/* ----------------------------- Availability ----------------------------- */

async function computeAvailability(
  store: ReturnType<typeof getStore>,
  env: EnvConfig,
  date: string,
  service: string,
): Promise<Array<{ time: string; available: boolean; remaining: number }>> {
  const times = buildSlots(env, date);
  const out: Array<{ time: string; available: boolean; remaining: number }> = [];

  for (const time of times) {
    const lock = (await store.get(slotLockKey(date, time, service), { type: "json" })) as SlotLock | null;
    const used = lock?.ids?.length ?? 0;
    const remaining = Math.max(0, env.capacityPerSlot - used);
    out.push({ time, available: remaining > 0, remaining });
  }

  return out;
}

function buildSlots(env: EnvConfig, _date: string): string[] {
  const slots: string[] = [];
  const startMin = env.openHour * 60;
  const endMin = env.closeHour * 60;

  for (let m = startMin; m + env.slotMinutes <= endMin; m += env.slotMinutes) {
    const hh = String(Math.floor(m / 60)).padStart(2, "0");
    const mm = String(m % 60).padStart(2, "0");
    slots.push(`${hh}:${mm}`);
  }

  return slots;
}

/* ------------------------------ Slot Locks ------------------------------ */

function slotLockKey(date: string, time: string, service: string): string {
  const safeService = service.replaceAll("/", "_").slice(0, 80);
  return `slots/${date}/${time}/${safeService}`;
}

async function reserveSlot(
  store: ReturnType<typeof getStore>,
  slotKey: string,
  appointmentId: string,
  capacity: number,
): Promise<{ ok: true } | { ok: false }> {
  for (let i = 0; i < 5; i += 1) {
    const existing = (await store.getWithMetadata(slotKey, { type: "json" })) as
      | { data: SlotLock; etag: string }
      | null;

    if (!existing) {
      const next: SlotLock = { ids: [appointmentId] };
      const res = await store.setJSON(slotKey, next, { onlyIfNew: true });
      if (res.modified) return { ok: true };
      continue;
    }

    const ids = Array.isArray(existing.data?.ids) ? existing.data.ids : [];
    if (ids.includes(appointmentId)) return { ok: true };
    if (ids.length >= capacity) return { ok: false };

    const next: SlotLock = { ids: [...ids, appointmentId] };
    const res = await store.setJSON(slotKey, next, { onlyIfMatch: existing.etag });
    if (res.modified) return { ok: true };
  }

  return { ok: false };
}

async function releaseSlot(store: ReturnType<typeof getStore>, slotKey: string, appointmentId: string): Promise<void> {
  for (let i = 0; i < 5; i += 1) {
    const existing = (await store.getWithMetadata(slotKey, { type: "json" })) as
      | { data: SlotLock; etag: string }
      | null;

    if (!existing) return;

    const ids = Array.isArray(existing.data?.ids) ? existing.data.ids : [];
    const nextIds = ids.filter((x) => x !== appointmentId);

    if (nextIds.length === ids.length) return;

    if (nextIds.length === 0) {
      await store.delete(slotKey);
      return;
    }

    const res = await store.setJSON(slotKey, { ids: nextIds }, { onlyIfMatch: existing.etag });
    if (res.modified) return;
  }
}

/* ------------------------------- Rate Limit ------------------------------ */

async function rateLimit(
  store: ReturnType<typeof getStore>,
  ip: string,
  dailyLimit: number,
): Promise<{ ok: true } | { ok: false }> {
  const day = nowIso().slice(0, 10);

  // IMPORTANT: bump prefix so old "0.0.0.0" counters are ignored
  const key = `ratelimit_v2/${day}/${hashShort(ip)}`;

  for (let i = 0; i < 5; i += 1) {
    const existing = (await store.getWithMetadata(key, { type: "json" })) as
      | { data: { count: number }; etag: string }
      | null;

    if (!existing) {
      const res = await store.setJSON(key, { count: 1 }, { onlyIfNew: true });
      if (res.modified) return { ok: true };
      continue;
    }

    const count = typeof existing.data?.count === "number" ? existing.data.count : 0;
    if (count >= dailyLimit) return { ok: false };

    const res = await store.setJSON(key, { count: count + 1 }, { onlyIfMatch: existing.etag });
    if (res.modified) return { ok: true };
  }

  return { ok: false };
}

/* --------------------------------- Leads -------------------------------- */

function normalizeEmail(email?: string): string | null {
  const e = (email ?? "").trim().toLowerCase();
  return e.length ? e : null;
}

function normalizePhone(phone?: string): string | null {
  const p = (phone ?? "").trim();
  if (!p) return null;
  // keep digits + leading +
  const cleaned = p.startsWith("+")
    ? "+" + p.slice(1).replace(/[^\d]/g, "")
    : p.replace(/[^\d]/g, "");
  return cleaned.length ? cleaned : null;
}

function leadByEmailKey(email: string): string {
  return `indexes/leadByEmail/${hashShort(email)}`;
}
function leadByPhoneKey(phone: string): string {
  return `indexes/leadByPhone/${hashShort(phone)}`;
}

async function findExistingLeadIdByContact(
  store: ReturnType<typeof getStore>,
  c: { email?: string; phone?: string },
): Promise<string | null> {
  const e = normalizeEmail(c.email);
  if (e) {
    const idx = (await store.get(leadByEmailKey(e), { type: "json" })) as { id?: string } | null;
    const id = safeText(idx?.id);
    if (id) return id;
  }

  const p = normalizePhone(c.phone);
  if (p) {
    const idx = (await store.get(leadByPhoneKey(p), { type: "json" })) as { id?: string } | null;
    const id = safeText(idx?.id);
    if (id) return id;
  }

  return null;
}

async function reserveContactIndexes(
  store: ReturnType<typeof getStore>,
  opts: { id: string; email?: string; phone?: string },
): Promise<{ ok: true } | { ok: false; existingId: string }> {
  const e = normalizeEmail(opts.email);
  const p = normalizePhone(opts.phone);

  // Fast check
  const existing = await findExistingLeadIdByContact(store, { email: e ?? undefined, phone: p ?? undefined });
  if (existing) return { ok: false, existingId: existing };

  // Reserve email first
  if (e) {
    const key = leadByEmailKey(e);
    const res = await store.setJSON(key, { id: opts.id }, { onlyIfNew: true });
    if (!res.modified) {
      const idx = (await store.get(key, { type: "json" })) as { id?: string } | null;
      const id = safeText(idx?.id) || opts.id;
      return { ok: false, existingId: id };
    }
  }

  // Reserve phone second; if fails, rollback email reserve
  if (p) {
    const key = leadByPhoneKey(p);
    const res = await store.setJSON(key, { id: opts.id }, { onlyIfNew: true });
    if (!res.modified) {
      if (e) {
        try {
          await store.delete(leadByEmailKey(e));
        } catch {}
      }
      const idx = (await store.get(key, { type: "json" })) as { id?: string } | null;
      const id = safeText(idx?.id) || opts.id;
      return { ok: false, existingId: id };
    }
  }

  return { ok: true };
}

async function releaseReservedContactIndexes(
  store: ReturnType<typeof getStore>,
  opts: { id: string; email?: string; phone?: string },
): Promise<void> {
  const e = normalizeEmail(opts.email);
  const p = normalizePhone(opts.phone);
  if (e) {
    try {
      const key = leadByEmailKey(e);
      const idx = (await store.get(key, { type: "json" })) as { id?: string } | null;
      if (safeText(idx?.id) === opts.id) await store.delete(key);
    } catch {}
  }
  if (p) {
    try {
      const key = leadByPhoneKey(p);
      const idx = (await store.get(key, { type: "json" })) as { id?: string } | null;
      if (safeText(idx?.id) === opts.id) await store.delete(key);
    } catch {}
  }
}

async function safeAppendLeadEvent(
  store: ReturnType<typeof getStore>,
  id: string,
  evt: { type: string; note?: string },
): Promise<void> {
  try {
    await patchLead(store, id, (lead) => ({
      ...lead,
      updatedAt: nowIso(),
      timeline: [...(lead.timeline ?? []), { at: nowIso(), type: evt.type, note: evt.note }],
    }));
  } catch {}
}

async function patchLead(
  store: ReturnType<typeof getStore>,
  id: string,
  updater: (lead: Lead) => Lead,
): Promise<boolean> {
  for (let i = 0; i < 5; i += 1) {
    const existing = (await store.getWithMetadata(`leads/${id}`, { type: "json" })) as
      | { data: Lead; etag: string }
      | null;

    if (!existing) return false;

    const next = updater(existing.data);
    const res = await store.setJSON(`leads/${id}`, next, { onlyIfMatch: existing.etag });
    if (res.modified) return true;
  }

  return false;
}

async function listLeads(
  store: ReturnType<typeof getStore>,
  opts: { status?: string; q?: string; limit: number },
): Promise<Lead[]> {
  const { blobs } = await store.list({ prefix: "indexes/leads/" });
  const keys = blobs.map((b) => b.key).sort().reverse();

  const leads: Lead[] = [];
  for (const k of keys) {
    if (leads.length >= opts.limit) break;
    const idx = (await store.get(k, { type: "json" })) as { id: string } | null;
    if (!idx?.id) continue;

    const lead = (await store.get(`leads/${idx.id}`, { type: "json" })) as Lead | null;
    if (!lead) continue;

    if (opts.status && lead.status !== opts.status) continue;
    if (opts.q && !matchesQuery(lead, opts.q)) continue;

    leads.push(lead);
  }

  return leads;
}

function matchesQuery(lead: Lead, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const hay = [lead.id, lead.name, lead.email ?? "", lead.phone ?? "", lead.service ?? "", lead.notes ?? "", lead.status]
    .join(" ")
    .toLowerCase();
  return hay.includes(needle);
}

async function pullOnceConsumeLeads(
  store: ReturnType<typeof getStore>,
  opts: { limit: number; status: LeadStatus; assignedTo: string },
): Promise<Lead[]> {
  const { blobs } = await store.list({ prefix: "indexes/leads/" });
  const keys = blobs.map((b) => b.key).sort().reverse();

  const out: Lead[] = [];

  for (const k of keys) {
    if (out.length >= opts.limit) break;

    const idx = (await store.get(k, { type: "json" })) as { id?: string; createdAt?: string } | null;
    const id = safeText(idx?.id);
    if (!id) continue;

    const claimed = await tryClaimLead(store, id, opts);
    if (!claimed) continue;

    // consume: move to pulled/ and delete from main lead store + indexes
    await consumeLead(store, claimed);
    out.push(claimed);
  }

  return out;
}

async function tryClaimLead(
  store: ReturnType<typeof getStore>,
  id: string,
  opts: { status: LeadStatus; assignedTo: string },
): Promise<Lead | null> {
  for (let i = 0; i < 5; i += 1) {
    const existing = (await store.getWithMetadata(`leads/${id}`, { type: "json" })) as
      | { data: Lead; etag: string }
      | null;

    if (!existing) return null;

    const lead = existing.data;
    if (!lead) return null;

    // Only pull unpulled/unassigned leads
    if (lead.assignedTo) return null;

    // Status filter (default "hot")
    if (opts.status && lead.status !== opts.status) return null;

    const ts = nowIso();

    const next: Lead = {
      ...lead,
      assignedTo: opts.assignedTo,
      pulledAt: ts,
      updatedAt: ts,
      timeline: [...(lead.timeline ?? []), { at: ts, type: "pulled", note: opts.assignedTo }],
    };

    // CAS write
    const res = await store.setJSON(`leads/${id}`, next, { onlyIfMatch: existing.etag });
    if (res.modified) return next;
  }

  return null;
}

async function consumeLead(store: ReturnType<typeof getStore>, lead: Lead): Promise<void> {
  // keep an audit copy
  await store.setJSON(`pulled/${lead.id}`, lead, { onlyIfNew: true });

  // delete main lead record
  try {
    await store.delete(`leads/${lead.id}`);
  } catch {}

  // delete lead timeline index entry (createdAt + id)
  try {
    await store.delete(`indexes/leads/${lead.createdAt}_${lead.id}`);
  } catch {}

  // delete contact indexes if they still point to this id
  await releaseReservedContactIndexes(store, { id: lead.id, email: lead.email, phone: lead.phone });
}

/* ------------------------------ Appointments ----------------------------- */

async function patchAppointment(
  store: ReturnType<typeof getStore>,
  id: string,
  updater: (appt: Appointment) => Appointment,
): Promise<boolean> {
  for (let i = 0; i < 5; i += 1) {
    const existing = (await store.getWithMetadata(`appointments/${id}`, { type: "json" })) as
      | { data: Appointment; etag: string }
      | null;

    if (!existing) return false;

    const next = updater(existing.data);
    const res = await store.setJSON(`appointments/${id}`, next, { onlyIfMatch: existing.etag });
    if (res.modified) return true;
  }

  return false;
}

async function listAppointments(
  store: ReturnType<typeof getStore>,
  opts: { from?: string; to?: string; limit: number },
): Promise<Appointment[]> {
  const { blobs } = await store.list({ prefix: "appointments/" });
  const keys = blobs.map((b) => b.key).sort().reverse();

  const appts: Appointment[] = [];
  for (const k of keys) {
    if (appts.length >= opts.limit) break;
    const appt = (await store.get(k, { type: "json" })) as Appointment | null;
    if (!appt) continue;

    if (opts.from && appt.startAt < opts.from) continue;
    if (opts.to && appt.startAt > opts.to) continue;

    appts.push(appt);
  }

  return appts;
}

/* -------------------------------- Metrics -------------------------------- */

async function computeMetrics(store: ReturnType<typeof getStore>) {
  const leads = await listLeads(store, { limit: 200, q: undefined, status: undefined });
  const { blobs: apptBlobs } = await store.list({ prefix: "appointments/" });

  const appts: Appointment[] = [];
  for (const b of apptBlobs) {
    const a = (await store.get(b.key, { type: "json" })) as Appointment | null;
    if (a) appts.push(a);
  }

  const today = nowIso().slice(0, 10);
  const last7 = dateAddDays(today, -6);
  const last30 = dateAddDays(today, -29);

  const leadsToday = leads.filter((l) => l.createdAt.startsWith(today)).length;
  const leads7 = leads.filter((l) => l.createdAt.slice(0, 10) >= last7).length;
  const leads30 = leads.filter((l) => l.createdAt.slice(0, 10) >= last30).length;

  const apptsToday = appts.filter((a) => a.createdAt.startsWith(today) && a.status === "booked").length;
  const appts7 = appts.filter((a) => a.createdAt.slice(0, 10) >= last7 && a.status === "booked").length;
  const appts30 = appts.filter((a) => a.createdAt.slice(0, 10) >= last30 && a.status === "booked").length;

  const landedByDay = new Map<string, number>();
  for (const l of leads) {
    if (l.status !== "landed") continue;
    const d = l.updatedAt.slice(0, 10);
    landedByDay.set(d, (landedByDay.get(d) ?? 0) + 1);
  }

  let bestDay = { date: "", landed: 0 };
  for (const [d, n] of landedByDay.entries()) {
    if (n > bestDay.landed) bestDay = { date: d, landed: n };
  }

  return {
    leads: { today: leadsToday, last7: leads7, last30: leads30 },
    appointments: { today: apptsToday, last7: appts7, last30: appts30 },
    bestDay,
  };
}

/* ---------------------------- Export / Import ---------------------------- */

async function exportSnapshot(store: ReturnType<typeof getStore>) {
  const { blobs: leadBlobs } = await store.list({ prefix: "leads/" });
  const { blobs: apptBlobs } = await store.list({ prefix: "appointments/" });
  const { blobs: slotBlobs } = await store.list({ prefix: "slots/" });
  const { blobs: todoBlobs } = await store.list({ prefix: "todos/" });

  const leads: Lead[] = [];
  for (const b of leadBlobs) {
    const l = (await store.get(b.key, { type: "json" })) as Lead | null;
    if (l) leads.push(l);
  }

  const appointments: Appointment[] = [];
  for (const b of apptBlobs) {
    const a = (await store.get(b.key, { type: "json" })) as Appointment | null;
    if (a) appointments.push(a);
  }

  const slots: Record<string, SlotLock> = {};
  for (const b of slotBlobs) {
    const s = (await store.get(b.key, { type: "json" })) as SlotLock | null;
    if (s) slots[b.key] = s;
  }

  const todos: Todo[] = [];
  for (const b of todoBlobs) {
    const t = (await store.get(b.key, { type: "json" })) as Todo | null;
    if (t) todos.push(t);
  }

  return { exportedAt: nowIso(), leads, appointments, slots, todos };
}

async function importSnapshot(
  store: ReturnType<typeof getStore>,
  snapshot: { leads?: Lead[]; appointments?: Appointment[]; slots?: Record<string, SlotLock>; todos?: Todo[] },
): Promise<void> {
  await deleteByPrefix(store, "leads/");
  await deleteByPrefix(store, "appointments/");
  await deleteByPrefix(store, "slots/");
  await deleteByPrefix(store, "todos/");
  await deleteByPrefix(store, "indexes/leads/");
  await deleteByPrefix(store, "indexes/leadByEmail/");
  await deleteByPrefix(store, "indexes/leadByPhone/");

  for (const lead of snapshot.leads ?? []) {
    await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: true },
    );

    const e = normalizeEmail(lead.email);
    const p = normalizePhone(lead.phone);
    if (e) await store.setJSON(leadByEmailKey(e), { id: lead.id }, { onlyIfNew: true });
    if (p) await store.setJSON(leadByPhoneKey(p), { id: lead.id }, { onlyIfNew: true });
  }

  for (const appt of snapshot.appointments ?? []) {
    await store.setJSON(`appointments/${appt.id}`, appt, { onlyIfNew: true });
  }

  const slots = snapshot.slots ?? {};
  for (const [k, v] of Object.entries(slots)) {
    await store.setJSON(k, v, { onlyIfNew: true });
  }

  for (const todo of snapshot.todos ?? []) {
    await store.setJSON(`todos/${todo.id}`, todo, { onlyIfNew: true });
  }
}

async function deleteByPrefix(store: ReturnType<typeof getStore>, prefix: string): Promise<void> {
  const { blobs } = await store.list({ prefix });
  for (const b of blobs) await store.delete(b.key);
}

/* ---------------------------------- Sync --------------------------------- */

function syncMetaKey(workspaceId: string): string {
  return `sync/meta/${workspaceId}`;
}

async function getSyncMeta(store: ReturnType<typeof getStore>, workspaceId: string): Promise<SyncMeta> {
  const meta = (await store.get(syncMetaKey(workspaceId), { type: "json" })) as SyncMeta | null;
  if (meta && typeof meta.version === "number" && typeof meta.updatedAt === "string") return meta;
  return { version: 0, updatedAt: "—" };
}

async function bumpSyncMeta(store: ReturnType<typeof getStore>, workspaceId: string): Promise<SyncMeta> {
  const key = syncMetaKey(workspaceId);

  for (let i = 0; i < 5; i += 1) {
    const existing = (await store.getWithMetadata(key, { type: "json" })) as
      | { data: SyncMeta; etag: string }
      | null;

    if (!existing) {
      const next: SyncMeta = { version: 1, updatedAt: nowIso() };
      const res = await store.setJSON(key, next, { onlyIfNew: true });
      if (res.modified) return next;
      continue;
    }

    const curV = typeof existing.data?.version === "number" ? existing.data.version : 0;
    const next: SyncMeta = { version: curV + 1, updatedAt: nowIso() };
    const res = await store.setJSON(key, next, { onlyIfMatch: existing.etag });
    if (res.modified) return next;
  }

  return await getSyncMeta(store, workspaceId);
}

function isoGt(a?: string, b?: string): boolean {
  if (!a) return false;
  if (!b) return true;
  return a > b;
}

function mergeTimeline(a: Lead["timeline"] | undefined, b: Lead["timeline"] | undefined): Lead["timeline"] {
  const x = Array.isArray(a) ? a : [];
  const y = Array.isArray(b) ? b : [];
  const seen = new Set<string>();
  const out: Lead["timeline"] = [];

  for (const evt of [...x, ...y]) {
    const key = JSON.stringify([evt?.at ?? "", evt?.type ?? "", evt?.note ?? ""]);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ at: String(evt?.at ?? ""), type: String(evt?.type ?? ""), note: evt?.note ? String(evt.note) : undefined });
  }

  out.sort((m, n) => String(m.at).localeCompare(String(n.at)));
  return out;
}

async function mergeSnapshots(
  store: ReturnType<typeof getStore>,
  args: {
    server: { leads: Lead[]; appointments: Appointment[]; slots: Record<string, SlotLock>; todos: Todo[] };
    incoming: { leads?: Lead[]; appointments?: Appointment[]; slots?: Record<string, SlotLock>; todos?: Todo[] };
    actor: string;
  },
): Promise<{ leads: Lead[]; appointments: Appointment[]; slots: Record<string, SlotLock>; todos: Todo[] }> {
  const serverLeads = new Map(args.server.leads.map((l) => [l.id, l]));
  const serverAppts = new Map(args.server.appointments.map((a) => [a.id, a]));
  const serverTodos = new Map(args.server.todos.map((t) => [t.id, t]));
  const mergedSlots: Record<string, SlotLock> = { ...(args.server.slots ?? {}) };

  // Leads (dedupe by id primary; fallback email/phone)
  for (const inc of args.incoming.leads ?? []) {
    if (!inc?.id || !inc?.createdAt) continue;

    const ex = serverLeads.get(inc.id);
    if (ex) {
      const newer = isoGt(inc.updatedAt, ex.updatedAt);
      const next: Lead = newer
        ? { ...ex, ...inc, timeline: mergeTimeline(ex.timeline, inc.timeline) }
        : { ...inc, ...ex, timeline: mergeTimeline(ex.timeline, inc.timeline) };
      serverLeads.set(inc.id, next);
      continue;
    }

    const byContact = await findExistingLeadIdByContact(store, { email: inc.email, phone: inc.phone });
    if (byContact) {
      const ex2 = serverLeads.get(byContact) || ((await store.get(`leads/${byContact}`, { type: "json" })) as Lead | null);
      if (ex2) {
        const newer = isoGt(inc.updatedAt, ex2.updatedAt);
        const next: Lead = newer
          ? { ...ex2, ...inc, id: ex2.id, createdAt: ex2.createdAt, timeline: mergeTimeline(ex2.timeline, inc.timeline) }
          : { ...inc, ...ex2, id: ex2.id, createdAt: ex2.createdAt, timeline: mergeTimeline(ex2.timeline, inc.timeline) };
        serverLeads.set(ex2.id, next);
        continue;
      }
    }

    const reserve = await reserveContactIndexes(store, { id: inc.id, email: inc.email, phone: inc.phone });
    if (!reserve.ok) {
      const ex3 =
        serverLeads.get(reserve.existingId) ||
        ((await store.get(`leads/${reserve.existingId}`, { type: "json" })) as Lead | null);
      if (ex3) {
        const newer = isoGt(inc.updatedAt, ex3.updatedAt);
        const next: Lead = newer
          ? { ...ex3, ...inc, id: ex3.id, createdAt: ex3.createdAt, timeline: mergeTimeline(ex3.timeline, inc.timeline) }
          : { ...inc, ...ex3, id: ex3.id, createdAt: ex3.createdAt, timeline: mergeTimeline(ex3.timeline, inc.timeline) };
        serverLeads.set(ex3.id, next);
      }
      continue;
    }

    const nextNew: Lead = {
      ...inc,
      source: "public",
      timeline: mergeTimeline([], inc.timeline),
    };
    serverLeads.set(nextNew.id, nextNew);
  }

  // Appointments (by id; pick newest updatedAt)
  for (const inc of args.incoming.appointments ?? []) {
    if (!inc?.id) continue;
    const ex = serverAppts.get(inc.id);
    if (!ex) {
      serverAppts.set(inc.id, inc);
      continue;
    }
    serverAppts.set(inc.id, isoGt(inc.updatedAt, ex.updatedAt) ? inc : ex);
  }

  // Todos (by id; pick newest updatedAt)
  for (const inc of args.incoming.todos ?? []) {
    if (!inc?.id) continue;
    const ex = serverTodos.get(inc.id);
    if (!ex) {
      serverTodos.set(inc.id, inc);
      continue;
    }
    serverTodos.set(inc.id, isoGt(inc.updatedAt, ex.updatedAt) ? inc : ex);
  }

  // Slots (union ids)
  const incomingSlots = args.incoming.slots ?? {};
  for (const [k, v] of Object.entries(incomingSlots)) {
    const a = mergedSlots[k]?.ids ?? [];
    const b = v?.ids ?? [];
    const set = new Set<string>([...a, ...b].filter(Boolean));
    mergedSlots[k] = { ids: Array.from(set) };
  }

  return {
    leads: Array.from(serverLeads.values()),
    appointments: Array.from(serverAppts.values()),
    slots: mergedSlots,
    todos: Array.from(serverTodos.values()),
  };
}

async function persistMergedSnapshot(
  store: ReturnType<typeof getStore>,
  merged: { leads: Lead[]; appointments: Appointment[]; slots: Record<string, SlotLock>; todos: Todo[] },
): Promise<void> {
  for (const lead of merged.leads) {
    if (!lead?.id || !lead?.createdAt) continue;
    await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: false } as any);
    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: true },
    );

    const e = normalizeEmail(lead.email);
    const p = normalizePhone(lead.phone);
    if (e) await store.setJSON(leadByEmailKey(e), { id: lead.id }, { onlyIfNew: true });
    if (p) await store.setJSON(leadByPhoneKey(p), { id: lead.id }, { onlyIfNew: true });
  }

  for (const appt of merged.appointments) {
    if (!appt?.id) continue;
    await store.setJSON(`appointments/${appt.id}`, appt, { onlyIfNew: false } as any);
  }

  for (const [k, v] of Object.entries(merged.slots ?? {})) {
    await store.setJSON(k, v, { onlyIfNew: false } as any);
  }

  for (const todo of merged.todos ?? []) {
    if (!todo?.id) continue;
    await store.setJSON(`todos/${todo.id}`, todo, { onlyIfNew: false } as any);
  }
}

/* --------------------------------- Auth --------------------------------- */

function requireAuth(env: EnvConfig, authHeader: string): { ok: true; payload: JwtPayload } | { ok: false } {
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice("Bearer ".length).trim() : "";
  if (!token) return { ok: false };
  const payload = verifyJwt(env.jwtSecret, token);
  if (!payload) return { ok: false };
  return { ok: true, payload };
}

function verifyUser(env: EnvConfig, username: string, password: string): { role: "admin" | "staff" } | null {
  if (!env.crmUsername) return null;
  if (username !== env.crmUsername) return null;

  if (env.crmPasswordHash) {
    const incomingHash = sha256Hex(password);
    if (!timingSafeEqualStr(incomingHash, env.crmPasswordHash)) return null;
    return { role: "admin" };
  }

  if (env.crmPassword) {
    if (!timingSafeEqualStr(password, env.crmPassword)) return null;
    return { role: "admin" };
  }

  return null;
}

function signJwt(secret: string, payload: JwtPayload): string {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = b64url(JSON.stringify(header));
  const encPayload = b64url(JSON.stringify(payload));
  const data = `${encHeader}.${encPayload}`;
  const sig = hmacSha256(secret, data);
  return `${data}.${sig}`;
}

function verifyJwt(secret: string, token: string): JwtPayload | null {
  if (!secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [h, p, s] = parts;
  const data = `${h}.${p}`;
  const expected = hmacSha256(secret, data);
  if (!timingSafeEqualStr(expected, s)) return null;

  try {
    const payload = JSON.parse(b64urlDecode(p)) as JwtPayload;
    if (typeof payload?.exp !== "number" || nowSec() > payload.exp) return null;
    if (typeof payload?.sub !== "string") return null;
    if (payload.role !== "admin" && payload.role !== "staff") return null;
    return payload;
  } catch {
    return null;
  }
}

/* ------------------------------- Utilities ------------------------------- */

function readEnvSafe(): EnvConfig {
  const jwtSecret = envGet("JWT_SECRET") ?? "";

  const allowedOriginsRaw = envGet("ALLOWED_ORIGINS") ?? "";
  const allowedOrigins =
    allowedOriginsRaw.trim().length > 0
      ? allowedOriginsRaw
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : null;

  const crmUsername = envGet("CRM_USERNAME");
  const crmPasswordHash = envGet("CRM_PASSWORD_HASH");
  const crmPassword = envGet("CRM_PASSWORD");

  const slotMinutes = clampInt(envGet("SLOT_MINUTES"), 10, 240, 30);
  const openHour = clampInt(envGet("OPEN_HOUR"), 0, 23, 9);
  const closeHour = clampInt(envGet("CLOSE_HOUR"), 1, 24, 17);
  const capacityPerSlot = clampInt(envGet("CAPACITY_PER_SLOT"), 1, 50, 1);

  const tz = envGet("TZ") ?? "America/Los_Angeles";
  const publicDailyRateLimit = clampInt(envGet("PUBLIC_DAILY_RATE_LIMIT"), 1, 10_000, 5000);

  return {
    jwtSecret,
    allowedOrigins,
    crmUsername,
    crmPasswordHash,
    crmPassword,
    slotMinutes,
    openHour,
    closeHour,
    capacityPerSlot,
    tz,
    publicDailyRateLimit,
  };
}

function envGet(key: string): string | null {
  const v1 = process.env[key];
  if (typeof v1 === "string" && v1.length) return v1;

  const n = (globalThis as any)?.Netlify?.env?.get?.(key);
  if (typeof n === "string" && n.length) return n;

  return null;
}

function buildCorsHeaders(env: EnvConfig, origin: string): Headers {
  const h = new Headers();

  const allowOrigin = env.allowedOrigins === null ? "*" : env.allowedOrigins.includes(origin) ? origin : null;

  if (allowOrigin) h.set("access-control-allow-origin", allowOrigin);
  h.set("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS");
  h.set("access-control-allow-headers", "content-type,authorization");
  h.set("access-control-max-age", "86400");
  if (allowOrigin && allowOrigin !== "*") h.set("vary", "origin");

  return h;
}

function normalizeApiPath(pathname: string): string {
  if (pathname.startsWith("/.netlify/functions/api")) {
    const rest = pathname.slice("/.netlify/functions/api".length);
    return `/api${rest || ""}`.replaceAll("//", "/");
  }
  return pathname.replaceAll("//", "/");
}

function respondJson(data: JsonValue, status: number, corsHeaders: Headers): Response {
  const headers = new Headers(corsHeaders);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(json(data), { status, headers });
}

function json(v: JsonValue): string {
  return JSON.stringify(v);
}

async function safeJson(req: Request): Promise<any | null> {
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.toLowerCase().includes("application/json")) return null;
  try {
    return await req.json();
  } catch {
    return null;
  }
}

function asString(v: any): string | null {
  return typeof v === "string" ? v : null;
}

function requiredString(v: any): string | null {
  const s = asString(v);
  if (!s) return null;
  const t = s.trim();
  return t.length ? t : null;
}

function optionalString(v: any): string | undefined {
  const s = asString(v);
  if (!s) return undefined;
  const t = s.trim();
  return t.length ? t : undefined;
}

function safeText(v: any): string {
  return typeof v === "string" ? v.trim() : "";
}

function nowIso(): string {
  return new Date().toISOString();
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function b64url(input: string): string {
  return Buffer.from(input, "utf8").toString("base64").replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}

function b64urlDecode(input: string): string {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
  const b64 = input.replaceAll("-", "+").replaceAll("_", "/") + pad;
  return Buffer.from(b64, "base64").toString("utf8");
}

function hmacSha256(secret: string, data: string): string {
  const sig = crypto.createHmac("sha256", secret).update(data).digest("base64");
  return sig.replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}

function timingSafeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function hashShort(s: string): string {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex").slice(0, 16);
}

function isDateYmd(s: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function isTimeHm(s: string): boolean {
  return /^\d{2}:\d{2}$/.test(s);
}

function dateAddDays(ymd: string, delta: number): string {
  const d = new Date(`${ymd}T00:00:00.000Z`);
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
}

function toIsoFromLocal(dateYmd: string, timeHm: string): string {
  const [hh, mm] = timeHm.split(":").map((x) => Number(x));
  const dt = new Date(dateYmd);
  dt.setHours(hh, mm, 0, 0);
  return dt.toISOString();
}

function splitIsoToDateTime(iso: string): { date: string; time: string } {
  const d = new Date(iso);
  const yyyy = String(d.getFullYear()).padStart(4, "0");
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return { date: `${yyyy}-${mm}-${dd}`, time: `${hh}:${mi}` };
}

function clampInt(v: string | null | undefined, min: number, max: number, def: number): number {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  const i = Math.floor(n);
  return Math.min(max, Math.max(min, i));
}

function clientIp(args: { req: Request; context: Context }): string {
  const viaContext = (args.context as any)?.ip;
  if (typeof viaContext === "string" && viaContext.trim()) return viaContext.trim();

  const h = args.req.headers;
  const nf = h.get("x-nf-client-connection-ip");
  if (nf) return nf.split(",")[0].trim();
  const xff = h.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return "0.0.0.0";
}

/* ---------------------- Device Snapshot Sync Helpers --------------------- */

function isSafeDeviceId(s: string): boolean {
  return /^[A-Za-z0-9_-]{1,64}$/.test(s);
}

function snapshotKey(deviceId: string): string {
  return `snapshots/${deviceId}`;
}

function asDeviceSnapshot(v: any, fallbackDeviceId: string): DeviceSnapshot | null {
  if (!v || typeof v !== "object") return null;

  const deviceId = safeText(v.deviceId) || fallbackDeviceId;
  const at = safeText(v.at) || nowIso();

  const customersRaw = Array.isArray(v.customers) ? v.customers : [];
  const customers: Customer[] = customersRaw
    .filter((c: any) => c && typeof c === "object" && typeof c.id === "string")
    .map((c: any) => ({
      ...c,
      id: String(c.id),
      createdAt: safeText(c.createdAt) || nowIso(),
      updatedAt: safeText(c.updatedAt) || safeText(c.createdAt) || nowIso(),
    }));

  const tombstonesRaw = v.tombstones && typeof v.tombstones === "object" ? v.tombstones : {};
  const tombstones: Record<string, string> = {};
  for (const [k, val] of Object.entries(tombstonesRaw)) {
    const id = safeText(k);
    const deletedAt = safeText(val);
    if (id && deletedAt) tombstones[id] = deletedAt;
  }

  return { deviceId, at, customers, tombstones };
}
