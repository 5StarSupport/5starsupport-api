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
  assignedTo?: string; // "pulled/assigned" owner
  pulledAt?: string; // when it was pulled/assigned
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

type JwtPayload = {
  sub: string;
  role: "admin" | "staff";
  iat: number;
  exp: number;
};

type SlotLock = { ids: string[] };

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

type SyncSnapshot = {
  workspaceId: string;
  version: number;
  updatedAt: string;

  // common sections
  leads: any[];
  todos: any[];
  appointments: any[];

  // arbitrary extra sections
  sections: Record<string, any[]>;

  // deletion safety
  tombstones: Record<string, Record<string, string>>;
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

  // =========================
  // SYNC (JWT required)
  // =========================
  if (path === "/api/sync" && (req.method === "GET" || req.method === "POST")) {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);

    if (req.method === "GET") {
      const workspaceId = normalizeWorkspaceId(url.searchParams.get("workspaceId"));
      const snap = await getOrInitWorkspaceSnapshot(store, workspaceId);
      return respondJson(
        {
          workspaceId,
          version: snap.version,
          updatedAt: snap.updatedAt,
          leads: snap.leads,
          todos: snap.todos,
          appointments: snap.appointments,
          sections: snap.sections,
          tombstones: snap.tombstones,
        },
        200,
        args.corsHeaders,
      );
    }

    // POST /api/sync
    const body = await safeJson(req);
    const workspaceId = normalizeWorkspaceId(asString(body?.workspaceId) ?? url.searchParams.get("workspaceId"));
    const incoming = (body?.snapshot ?? body?.changes ?? body) as any;

    const merged = await syncUpWorkspace(store, workspaceId, incoming);
    return respondJson(
      {
        workspaceId,
        version: merged.version,
        updatedAt: merged.updatedAt,
        leads: merged.leads,
        todos: merged.todos,
        appointments: merged.appointments,
        sections: merged.sections,
        tombstones: merged.tombstones,
      },
      200,
      args.corsHeaders,
    );
  }

  // =========================
  // Server-enforced "Pull Leads once" (JWT required)
  // POST /api/leads/pull
  // =========================
  if (path === "/api/leads/pull" && req.method === "POST") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);

    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);

    const body = await safeJson(req);
    const limit = clampInt(asString(body?.limit) ?? url.searchParams.get("limit"), 1, 200, 50);
    const statusParam = asString(body?.status) ?? url.searchParams.get("status") ?? "hot";
    const status = statusParam as LeadStatus;

    const pulled = await pullUnassignedLeadsOnce(store, {
      limit,
      status,
      assignee: auth.payload.sub,
    });

    return respondJson({ ok: true, pulled: pulled.length, leads: pulled }, 200, args.corsHeaders);
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

  // NEW: Hot leads endpoint (Schedule a Call)
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

    // Server-side dedupe (email/phone)
    const email = optionalString(body?.email);
    const phone = optionalString(body?.phone);
    const existingId = await findLeadByDedupe(store, { email, phone });
    if (existingId) {
      return respondJson({ ok: true, leadId: existingId, deduped: true }, 200, args.corsHeaders);
    }

    const lead: Lead = {
      id: crypto.randomUUID(),
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

    // Create + establish dedupe keys (safe against retries)
    const created = await createLeadWithDedupe(store, lead);
    if (!created.ok) {
      // If dedupe raced, return the canonical id
      return respondJson({ ok: true, leadId: created.leadId, deduped: true }, 200, args.corsHeaders);
    }

    return respondJson({ ok: true, leadId: lead.id }, 200, args.corsHeaders);
  }

  // Existing inquiries endpoint (updated honeypot from "website" -> "hp")
  if (path === "/api/public/inquiries" && req.method === "POST") {
    const ip = clientIp(args);
    const limited = await rateLimit(store, ip, env.publicDailyRateLimit);
    if (!limited.ok) return respondJson({ error: "rate_limited" }, 429, args.corsHeaders);

    const body = await safeJson(req);
    const honeypot = asString(body?.hp);
    if (honeypot) return respondJson({ ok: true }, 200, args.corsHeaders);

    const name = requiredString(body?.name);
    if (!name) return respondJson({ error: "missing_name" }, 400, args.corsHeaders);

    // Server-side dedupe (email/phone)
    const email = optionalString(body?.email);
    const phone = optionalString(body?.phone);
    const existingId = await findLeadByDedupe(store, { email, phone });
    if (existingId) {
      return respondJson({ ok: true, leadId: existingId, deduped: true }, 200, args.corsHeaders);
    }

    const lead: Lead = {
      id: crypto.randomUUID(),
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

    const created = await createLeadWithDedupe(store, lead);
    if (!created.ok) {
      return respondJson({ ok: true, leadId: created.leadId, deduped: true }, 200, args.corsHeaders);
    }

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
      return respondJson({ leads }, 200, args.corsHeaders);
    }

    if (path.startsWith("/api/crm/leads/")) {
      const id = path.split("/").pop() ?? "";
      if (!id) return respondJson({ error: "missing_id" }, 400, args.corsHeaders);

      if (req.method === "GET") {
        const lead = (await store.get(`leads/${id}`, { type: "json" })) as Lead | null;
        if (!lead) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ lead }, 200, args.corsHeaders);
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
      return respondJson({ appointments: appts }, 200, args.corsHeaders);
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

      return respondJson({ ok: true, appointmentId: appt.id }, 200, args.corsHeaders);
    }

    if (path.startsWith("/api/crm/appointments/")) {
      const id = path.split("/").pop() ?? "";
      if (!id) return respondJson({ error: "missing_id" }, 400, args.corsHeaders);

      if (req.method === "GET") {
        const appt = (await store.get(`appointments/${id}`, { type: "json" })) as Appointment | null;
        if (!appt) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ appointment: appt }, 200, args.corsHeaders);
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
      return respondJson({ metrics }, 200, args.corsHeaders);
    }

    if (path === "/api/crm/export" && req.method === "POST") {
      if (auth.payload.role !== "admin") return respondJson({ error: "forbidden" }, 403, args.corsHeaders);
      const snapshot = await exportSnapshot(store);
      return respondJson({ snapshot }, 200, args.corsHeaders);
    }

    if (path === "/api/crm/import" && req.method === "POST") {
      if (auth.payload.role !== "admin") return respondJson({ error: "forbidden" }, 403, args.corsHeaders);

      const body = await safeJson(req);
      const snapshot = body?.snapshot as
        | { leads?: Lead[]; appointments?: Appointment[]; slots?: Record<string, SlotLock> }
        | undefined;
      if (!snapshot) return respondJson({ error: "missing_snapshot" }, 400, args.corsHeaders);

      await importSnapshot(store, snapshot);
      return respondJson({ ok: true }, 200, args.corsHeaders);
    }

    return respondJson({ error: "not_found" }, 404, args.corsHeaders);
  }

  return respondJson({ error: "not_found" }, 404, args.corsHeaders);
}

/* ============================= SYNC HELPERS ============================= */

function normalizeWorkspaceId(v: string | null | undefined): string {
  const raw = (v ?? "").trim();
  if (!raw) return "default";
  // allow simple workspace tokens; collapse others to safe
  const safe = raw.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  return safe.length ? safe.slice(0, 64) : "default";
}

function workspaceSnapshotKey(workspaceId: string): string {
  return `workspaces/${workspaceId}/snapshot`;
}

function emptySnapshot(workspaceId: string): SyncSnapshot {
  return {
    workspaceId,
    version: 1,
    updatedAt: nowIso(),
    leads: [],
    todos: [],
    appointments: [],
    sections: {},
    tombstones: {},
  };
}

function parseUpdatedAt(v: any): number {
  const s = typeof v === "string" ? v : "";
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : 0;
}

function isObj(v: any): v is Record<string, any> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function getId(v: any): string {
  return typeof v?.id === "string" ? v.id : "";
}

function ensureArray(v: any): any[] {
  return Array.isArray(v) ? v : [];
}

function ensureRecordArray(v: any): Record<string, any[]> {
  if (!isObj(v)) return {};
  const out: Record<string, any[]> = {};
  for (const [k, val] of Object.entries(v)) {
    if (!k) continue;
    out[k] = ensureArray(val);
  }
  return out;
}

function ensureTombstones(v: any): Record<string, Record<string, string>> {
  if (!isObj(v)) return {};
  const out: Record<string, Record<string, string>> = {};
  for (const [section, m] of Object.entries(v)) {
    if (!isObj(m)) continue;
    const sec: Record<string, string> = {};
    for (const [id, ts] of Object.entries(m)) {
      if (typeof id !== "string") continue;
      if (typeof ts !== "string") continue;
      sec[id] = ts;
    }
    out[section] = sec;
  }
  return out;
}

async function getOrInitWorkspaceSnapshot(store: ReturnType<typeof getStore>, workspaceId: string): Promise<SyncSnapshot> {
  const key = workspaceSnapshotKey(workspaceId);
  const existing = (await store.get(key, { type: "json" })) as SyncSnapshot | null;
  if (existing && typeof existing?.version === "number") return normalizeSnapshotShape(existing, workspaceId);

  const snap = emptySnapshot(workspaceId);
  await store.setJSON(key, snap, { onlyIfNew: true });
  const reread = (await store.get(key, { type: "json" })) as SyncSnapshot | null;
  return reread ? normalizeSnapshotShape(reread, workspaceId) : snap;
}

function normalizeSnapshotShape(s: any, workspaceId: string): SyncSnapshot {
  const version = typeof s?.version === "number" && s.version > 0 ? Math.floor(s.version) : 1;
  const updatedAt = typeof s?.updatedAt === "string" && s.updatedAt ? s.updatedAt : nowIso();

  return {
    workspaceId,
    version,
    updatedAt,
    leads: ensureArray(s?.leads),
    todos: ensureArray(s?.todos),
    appointments: ensureArray(s?.appointments),
    sections: ensureRecordArray(s?.sections),
    tombstones: ensureTombstones(s?.tombstones),
  };
}

function mergeSection(
  sectionName: string,
  serverItems: any[],
  incomingItems: any[],
  tombstones: Record<string, Record<string, string>>,
): { items: any[]; tombstones: Record<string, Record<string, string>> } {
  const nextTomb = { ...tombstones, [sectionName]: { ...(tombstones[sectionName] ?? {}) } };

  const map = new Map<string, any>();
  for (const it of serverItems) {
    const id = getId(it);
    if (!id) continue;
    map.set(id, it);
  }

  // Respect existing tombstones against server data too (in case older snapshots existed)
  const secTombs = nextTomb[sectionName] ?? {};
  for (const [id, ts] of Object.entries(secTombs)) {
    const existing = map.get(id);
    if (!existing) continue;
    const existingTs = parseUpdatedAt(existing?.updatedAt);
    const tombTs = parseUpdatedAt(ts);
    if (tombTs >= existingTs) map.delete(id);
  }

  for (const it of incomingItems) {
    const id = getId(it);
    if (!id) continue;

    const inTs = parseUpdatedAt(it?.updatedAt);
    const tombTs = parseUpdatedAt(secTombs[id]);

    // If a tombstone is newer, ignore non-delete updates
    const isDelete = !!it?._deleted;
    if (!isDelete && tombTs && tombTs >= inTs) continue;

    if (isDelete) {
      const cur = map.get(id);
      const curTs = parseUpdatedAt(cur?.updatedAt);
      const bestTs = Math.max(inTs, curTs, tombTs);
      secTombs[id] = new Date(bestTs || Date.now()).toISOString();
      map.delete(id);
      continue;
    }

    const cur = map.get(id);
    if (!cur) {
      map.set(id, it);
      continue;
    }

    const curTs = parseUpdatedAt(cur?.updatedAt);
    if (inTs >= curTs) map.set(id, it);
  }

  nextTomb[sectionName] = secTombs;
  return { items: Array.from(map.values()), tombstones: nextTomb };
}

function mergeSnapshots(server: SyncSnapshot, incomingRaw: any): SyncSnapshot {
  const incoming = normalizeSnapshotShape(
    {
      ...incomingRaw,
      // allow clients to send "sections" or extra top-level arrays
      sections: isObj(incomingRaw?.sections) ? incomingRaw.sections : {},
      tombstones: incomingRaw?.tombstones,
    },
    server.workspaceId,
  );

  // If client sent extra top-level arrays (besides known keys), treat them as sections too
  if (isObj(incomingRaw)) {
    const known = new Set(["workspaceId", "version", "updatedAt", "leads", "todos", "appointments", "sections", "tombstones", "snapshot", "changes"]);
    for (const [k, v] of Object.entries(incomingRaw)) {
      if (known.has(k)) continue;
      if (Array.isArray(v)) incoming.sections[k] = v;
    }
  }

  let tombstones = { ...server.tombstones };

  const mergedLeads = mergeSection("leads", server.leads, incoming.leads, tombstones);
  tombstones = mergedLeads.tombstones;

  const mergedTodos = mergeSection("todos", server.todos, incoming.todos, tombstones);
  tombstones = mergedTodos.tombstones;

  const mergedAppointments = mergeSection("appointments", server.appointments, incoming.appointments, tombstones);
  tombstones = mergedAppointments.tombstones;

  const serverSections = server.sections ?? {};
  const incomingSections = incoming.sections ?? {};
  const mergedSections: Record<string, any[]> = { ...serverSections };

  // union of section keys
  const keys = new Set<string>([...Object.keys(serverSections), ...Object.keys(incomingSections)]);
  for (const k of keys) {
    // prevent weird keys from becoming blob bloat
    const safeName = String(k).trim();
    if (!safeName) continue;
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(safeName)) continue;

    const serverArr = ensureArray(serverSections[safeName]);
    const incomingArr = ensureArray(incomingSections[safeName]);

    const merged = mergeSection(`sections:${safeName}`, serverArr, incomingArr, tombstones);
    tombstones = merged.tombstones;
    mergedSections[safeName] = merged.items;
  }

  return {
    workspaceId: server.workspaceId,
    version: Math.max(1, server.version) + 1,
    updatedAt: nowIso(),
    leads: mergedLeads.items,
    todos: mergedTodos.items,
    appointments: mergedAppointments.items,
    sections: mergedSections,
    tombstones,
  };
}

async function syncUpWorkspace(store: ReturnType<typeof getStore>, workspaceId: string, incoming: any): Promise<SyncSnapshot> {
  const key = workspaceSnapshotKey(workspaceId);

  for (let i = 0; i < 8; i += 1) {
    const existing = (await store.getWithMetadata(key, { type: "json" })) as
      | { data: SyncSnapshot; etag: string }
      | null;

    if (!existing) {
      const base = emptySnapshot(workspaceId);
      const merged = mergeSnapshots(base, incoming);

      const res = await store.setJSON(key, merged, { onlyIfNew: true });
      if (res.modified) return merged;
      continue;
    }

    const serverSnap = normalizeSnapshotShape(existing.data, workspaceId);
    const merged = mergeSnapshots(serverSnap, incoming);

    const res = await store.setJSON(key, merged, { onlyIfMatch: existing.etag });
    if (res.modified) return merged;
  }

  // fallback: last read
  const final = (await store.get(key, { type: "json" })) as SyncSnapshot | null;
  return final ? normalizeSnapshotShape(final, workspaceId) : emptySnapshot(workspaceId);
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

/* ------------------ Pull Leads once + server-side dedupe ------------------ */

function normalizeEmail(email?: string): string {
  return (email ?? "").trim().toLowerCase();
}

function normalizePhone(phone?: string): string {
  // keep digits and + (very light normalization)
  const p = (phone ?? "").trim();
  if (!p) return "";
  const cleaned = p.replace(/[^\d+]/g, "");
  return cleaned;
}

function leadDedupeKeys(email?: string, phone?: string): string[] {
  const e = normalizeEmail(email);
  const p = normalizePhone(phone);
  const keys: string[] = [];

  if (e && p) keys.push(`dedupe/leads/emailphone/${hashShort(`${e}|${p}`)}`);
  if (e) keys.push(`dedupe/leads/email/${hashShort(e)}`);
  if (p) keys.push(`dedupe/leads/phone/${hashShort(p)}`);

  return keys;
}

async function findLeadByDedupe(
  store: ReturnType<typeof getStore>,
  args: { email?: string; phone?: string },
): Promise<string | null> {
  const keys = leadDedupeKeys(args.email, args.phone);
  for (const k of keys) {
    const hit = (await store.get(k, { type: "json" })) as { id?: string } | null;
    const id = typeof hit?.id === "string" ? hit.id : "";
    if (id) return id;
  }
  return null;
}

async function createLeadWithDedupe(
  store: ReturnType<typeof getStore>,
  lead: Lead,
): Promise<{ ok: true } | { ok: false; leadId: string }> {
  // Primary uniqueness is lead.id (handled by onlyIfNew on leads/<id>), but we also enforce fallback by email/phone.
  const keys = leadDedupeKeys(lead.email, lead.phone);

  // If we have dedupe keys, attempt to claim them first.
  for (const k of keys) {
    const res = await store.setJSON(k, { id: lead.id }, { onlyIfNew: true });
    if (!res.modified) {
      const existing = (await store.get(k, { type: "json" })) as { id?: string } | null;
      const existingId = typeof existing?.id === "string" ? existing.id : "";
      if (existingId) return { ok: false, leadId: existingId };
      return { ok: false, leadId: lead.id };
    }
  }

  // Now create the lead itself (if this races, caller can retry safely)
  const created = await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
  if (!created.modified) {
    // lead.id already exists (retry). Use it.
    return { ok: false, leadId: lead.id };
  }

  await store.setJSON(
    `indexes/leads/${lead.createdAt}_${lead.id}`,
    { id: lead.id, createdAt: lead.createdAt },
    { onlyIfNew: true },
  );

  return { ok: true };
}

async function tryAssignLead(
  store: ReturnType<typeof getStore>,
  leadId: string,
  assignee: string,
): Promise<Lead | null> {
  for (let i = 0; i < 6; i += 1) {
    const existing = (await store.getWithMetadata(`leads/${leadId}`, { type: "json" })) as
      | { data: Lead; etag: string }
      | null;

    if (!existing?.data) return null;

    const lead = existing.data;
    if (lead.assignedTo) return null;

    const ts = nowIso();
    const next: Lead = {
      ...lead,
      assignedTo: assignee,
      pulledAt: ts,
      updatedAt: ts,
      timeline: [...(lead.timeline ?? []), { at: ts, type: "pulled", note: assignee }],
    };

    const res = await store.setJSON(`leads/${leadId}`, next, { onlyIfMatch: existing.etag });
    if (res.modified) return next;
  }

  return null;
}

async function pullUnassignedLeadsOnce(
  store: ReturnType<typeof getStore>,
  opts: { limit: number; status?: LeadStatus; assignee: string },
): Promise<Lead[]> {
  // We intentionally scan more than requested and assign with per-lead optimistic locking.
  const scanLimit = Math.min(500, Math.max(opts.limit * 8, opts.limit));
  const candidates = await listLeads(store, { limit: scanLimit, q: undefined, status: undefined });

  const out: Lead[] = [];

  for (const l of candidates) {
    if (out.length >= opts.limit) break;

    if (opts.status && l.status !== opts.status) continue;
    if (l.status === "archived") continue;
    if (l.assignedTo) continue;

    const assigned = await tryAssignLead(store, l.id, opts.assignee);
    if (assigned) out.push(assigned);
  }

  return out;
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

  return { exportedAt: nowIso(), leads, appointments, slots };
}

async function importSnapshot(
  store: ReturnType<typeof getStore>,
  snapshot: { leads?: Lead[]; appointments?: Appointment[]; slots?: Record<string, SlotLock> },
): Promise<void> {
  await deleteByPrefix(store, "leads/");
  await deleteByPrefix(store, "appointments/");
  await deleteByPrefix(store, "slots/");
  await deleteByPrefix(store, "indexes/leads/");
  await deleteByPrefix(store, "dedupe/leads/");

  for (const lead of snapshot.leads ?? []) {
    await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: true },
    );

    // re-establish dedupe keys if possible
    const keys = leadDedupeKeys(lead.email, lead.phone);
    for (const k of keys) await store.setJSON(k, { id: lead.id }, { onlyIfNew: true });
  }

  for (const appt of snapshot.appointments ?? []) {
    await store.setJSON(`appointments/${appt.id}`, appt, { onlyIfNew: true });
  }

  const slots = snapshot.slots ?? {};
  for (const [k, v] of Object.entries(slots)) {
    await store.setJSON(k, v, { onlyIfNew: true });
  }
}

async function deleteByPrefix(store: ReturnType<typeof getStore>, prefix: string): Promise<void> {
  const { blobs } = await store.list({ prefix });
  for (const b of blobs) await store.delete(b.key);
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
  return crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);
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
