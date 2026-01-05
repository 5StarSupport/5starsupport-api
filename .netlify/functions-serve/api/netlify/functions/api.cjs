var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// netlify/functions/api.ts
var api_exports = {};
__export(api_exports, {
  config: () => config,
  default: () => handler
});
module.exports = __toCommonJS(api_exports);
var import_blobs = require("@netlify/blobs");
var import_node_crypto = __toESM(require("node:crypto"));
var config = {
  path: "/api/*"
};
var STORE_NAME = "crm";
var CONSISTENCY = "strong";
async function handler(req, context) {
  const url = new URL(req.url);
  const path = normalizeApiPath(url.pathname);
  const env = readEnvSafe();
  const origin = req.headers.get("origin") ?? "";
  const acrh = req.headers.get("access-control-request-headers") ?? "";
  const corsHeaders = buildCorsHeaders(env, origin, acrh);
  if (path === "/api/health" && req.method === "GET") {
    return respondJson({ ok: true }, 200, corsHeaders);
  }
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  try {
    const store = (0, import_blobs.getStore)({ name: STORE_NAME, consistency: CONSISTENCY });
    return await route({ req, context, env, store, url, path, corsHeaders });
  } catch {
    return respondJson({ error: "internal_error" }, 500, corsHeaders);
  }
}
async function route(args) {
  const { req, env, store, url, path } = args;
  if (path === "/api/health" && req.method === "GET") {
    return respondJson({ ok: true }, 200, args.corsHeaders);
  }
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
      exp: nowSec() + 60 * 60 * 12
    });
    return respondJson({ token, role: user.role }, 200, args.corsHeaders);
  }
  if (path === "/api/public/hot-leads" && req.method === "POST") {
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
    const message = optionalString(body?.message) ?? optionalString(body?.notes);
    const existingId = await findExistingLeadIdByMessage(store, message);
    if (existingId) {
      await safeAppendLeadEvent(store, existingId, { type: "duplicate_submit_inquiry" });
      return respondJson({ ok: true, leadId: existingId, deduped: true }, 200, args.corsHeaders);
    }
    const leadId = import_node_crypto.default.randomUUID();
    const reserved = await reserveMessageIndex(store, { id: leadId, message });
    if (!reserved.ok) {
      await safeAppendLeadEvent(store, reserved.existingId, { type: "duplicate_submit_inquiry" });
      return respondJson({ ok: true, leadId: reserved.existingId, deduped: true }, 200, args.corsHeaders);
    }
    const now = nowIso();
    const lead = {
      id: leadId,
      createdAt: now,
      updatedAt: now,
      updatedBy: "public",
      source: "public",
      status: "hot",
      name,
      phone,
      email,
      service: optionalString(body?.service),
      notes: optionalString(body?.notes),
      preferredDate: optionalString(body?.preferredDate),
      preferredTime: optionalString(body?.preferredTime),
      timeline: [{ at: now, type: "hot_created" }]
    };
    const created = await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
    if (!created.modified) {
      await releaseReservedMessageIndex(store, { id: leadId, message });
      return respondJson({ error: "create_failed" }, 500, args.corsHeaders);
    }
    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: true }
    );
    return respondJson({ ok: true, leadId: lead.id }, 200, args.corsHeaders);
  }
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
    const message = optionalString(body?.message) ?? optionalString(body?.notes);
    const existingId = await findExistingLeadIdByMessage(store, message);
    if (existingId) {
      await safeAppendLeadEvent(store, existingId, { type: "duplicate_submit_inquiry" });
      return respondJson({ ok: true, leadId: existingId, deduped: true }, 200, args.corsHeaders);
    }
    const leadId = import_node_crypto.default.randomUUID();
    const reserved = await reserveMessageIndex(store, { id: leadId, message });
    if (!reserved.ok) {
      await safeAppendLeadEvent(store, reserved.existingId, { type: "duplicate_submit_inquiry" });
      return respondJson({ ok: true, leadId: reserved.existingId, deduped: true }, 200, args.corsHeaders);
    }
    const now = nowIso();
    const lead = {
      id: leadId,
      createdAt: now,
      updatedAt: now,
      updatedBy: "public",
      source: "public",
      status: "new",
      name,
      phone,
      email,
      service: optionalString(body?.service),
      notes: optionalString(body?.notes),
      preferredDate: optionalString(body?.preferredDate),
      preferredTime: optionalString(body?.preferredTime),
      timeline: [{ at: now, type: "created" }]
    };
    const created = await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
    if (!created.modified) {
      await releaseReservedMessageIndex(store, { id: leadId, message });
      return respondJson({ error: "create_failed" }, 500, args.corsHeaders);
    }
    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: true }
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
    const endAt = new Date(new Date(startAt).getTime() + env.slotMinutes * 6e4).toISOString();
    const appointmentId = import_node_crypto.default.randomUUID();
    const slotKey = slotLockKey(date, time, service);
    const reserved = await reserveSlot(store, slotKey, appointmentId, env.capacityPerSlot);
    if (!reserved.ok) return respondJson({ error: "slot_unavailable" }, 409, args.corsHeaders);
    const appt = {
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
        email: optionalString(body?.email)
      },
      notes: optionalString(body?.notes),
      leadId: optionalString(body?.leadId)
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
        updatedBy: "public",
        timeline: [...lead.timeline, { at: nowIso(), type: "appointment_created", note: appt.id }]
      }));
    }
    return respondJson(
      {
        ok: true,
        appointmentId: appt.id,
        startAt: appt.startAt,
        endAt: appt.endAt
      },
      200,
      args.corsHeaders
    );
  }
  if (path === "/api/snapshots" && req.method === "GET") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);
    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);
    const { blobs } = await store.list({ prefix: "snapshots/" });
    const keys = blobs.map((b) => b.key).sort().slice(0, 500);
    const snapshots = [];
    for (const k of keys) {
      const raw = await store.get(k, { type: "json" });
      if (!raw) continue;
      const deviceIdFromKey = k.split("/").pop() ?? "";
      const snap = asDeviceSnapshot(raw, deviceIdFromKey);
      if (snap) snapshots.push(snap);
    }
    return respondJson({ ok: true, snapshots }, 200, args.corsHeaders);
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
      const raw = await store.get(key, { type: "json" });
      if (!raw) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
      const snap = asDeviceSnapshot(raw, deviceId);
      if (!snap) return respondJson({ error: "corrupt_snapshot" }, 500, args.corsHeaders);
      return respondJson({ ok: true, snapshot: snap }, 200, args.corsHeaders);
    }
    if (req.method === "PUT" || req.method === "POST") {
      const body = await safeJson(req);
      if (!body) return respondJson({ error: "missing_json" }, 400, args.corsHeaders);
      const snap = asDeviceSnapshot(body, deviceId);
      if (!snap) return respondJson({ error: "invalid_snapshot" }, 400, args.corsHeaders);
      const toStore = {
        ...snap,
        deviceId,
        at: nowIso()
      };
      await store.setJSON(key, toStore);
      return respondJson({ ok: true }, 200, args.corsHeaders);
    }
    return respondJson({ error: "not_found" }, 404, args.corsHeaders);
  }
  if (path === "/api/sync" && req.method === "GET") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);
    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);
    const workspaceId = safeText(url.searchParams.get("workspaceId")) || "default";
    const meta = await getSyncMeta(store, workspaceId);
    const snapshot = await exportSnapshot(store);
    return respondJson(
      {
        ok: true,
        workspaceId,
        meta,
        snapshot
      },
      200,
      args.corsHeaders
    );
  }
  if (path === "/api/sync" && req.method === "POST") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);
    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);
    const body = await safeJson(req);
    const workspaceId = safeText(body?.workspaceId) || safeText(url.searchParams.get("workspaceId")) || "default";
    const incoming = body?.snapshot;
    if (!incoming) return respondJson({ error: "missing_snapshot" }, 400, args.corsHeaders);
    if (!isFullSnapshotShape(incoming)) {
      return respondJson({ error: "full_snapshot_required" }, 400, args.corsHeaders);
    }
    const server = await exportSnapshot(store);
    const merged = await mergeSnapshots(store, {
      server,
      incoming,
      actor: auth.payload.sub
    });
    await persistMergedSnapshot(store, merged);
    const meta = await bumpSyncMeta(store, workspaceId);
    const latest = await exportSnapshot(store);
    return respondJson(
      {
        ok: true,
        workspaceId,
        meta,
        snapshot: latest
      },
      200,
      args.corsHeaders
    );
  }
  if (path === "/api/leads/pull" && req.method === "POST") {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);
    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);
    const deviceId = requestDeviceId(req);
    const body = await safeJson(req);
    const limit = clampInt(asString(body?.limit) ?? url.searchParams.get("limit"), 1, 200, 50);
    const status = asString(body?.status) ?? url.searchParams.get("status") ?? "hot";
    const pulled = await pullOnceConsumeLeads(store, {
      limit,
      status,
      assignedTo: auth.payload.sub,
      deviceId
    });
    return respondJson({ ok: true, pulled: pulled.length, leads: pulled }, 200, args.corsHeaders);
  }
  if (path.startsWith("/api/crm/")) {
    if (!env.jwtSecret) return respondJson({ error: "misconfigured_jwt_secret" }, 500, args.corsHeaders);
    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);
    const deviceId = requestDeviceId(req);
    if (path === "/api/crm/leads" && req.method === "GET") {
      const status = url.searchParams.get("status");
      const q = url.searchParams.get("q");
      const limit = clampInt(url.searchParams.get("limit"), 1, 200, 50);
      const leads = await listLeads(store, { status: status ?? void 0, q: q ?? void 0, limit });
      return respondJson({ leads }, 200, args.corsHeaders);
    }
    if (path.startsWith("/api/crm/leads/")) {
      const id = path.split("/").pop() ?? "";
      if (!id) return respondJson({ error: "missing_id" }, 400, args.corsHeaders);
      if (req.method === "GET") {
        const lead = await store.get(`leads/${id}`, { type: "json" });
        if (!lead) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ lead }, 200, args.corsHeaders);
      }
      if (req.method === "PUT") {
        const body = await safeJson(req);
        const status = optionalString(body?.status);
        const notes = optionalString(body?.notes);
        const followUpAt = optionalString(body?.followUpAt);
        const assignedTo = optionalString(body?.assignedTo);
        const updated = await patchLead(store, id, (lead) => {
          if (auth.payload.role !== "admin" && typeof assignedTo === "string" && assignedTo !== lead.assignedTo) {
            throw new ForbiddenError("reassign_forbidden");
          }
          return {
            ...lead,
            updatedAt: nowIso(),
            updatedBy: auth.payload.sub,
            updatedDeviceId: deviceId ?? lead.updatedDeviceId,
            status: status ?? lead.status,
            notes: notes ?? lead.notes,
            followUpAt: followUpAt ?? lead.followUpAt,
            assignedTo: auth.payload.role === "admin" ? assignedTo ?? lead.assignedTo : lead.assignedTo,
            timeline: [...lead.timeline, { at: nowIso(), type: "updated" }]
          };
        });
        if (!updated) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ ok: true }, 200, args.corsHeaders);
      }
    }
    if (path === "/api/crm/appointments" && req.method === "GET") {
      const from = url.searchParams.get("from");
      const to = url.searchParams.get("to");
      const limit = clampInt(url.searchParams.get("limit"), 1, 500, 200);
      const appts = await listAppointments(store, { from: from ?? void 0, to: to ?? void 0, limit });
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
      const endAt = new Date(new Date(startAt).getTime() + env.slotMinutes * 6e4).toISOString();
      const appointmentId = import_node_crypto.default.randomUUID();
      const slotKey = slotLockKey(date, time, service);
      const reserved = await reserveSlot(store, slotKey, appointmentId, env.capacityPerSlot);
      if (!reserved.ok) return respondJson({ error: "slot_unavailable" }, 409, args.corsHeaders);
      const appt = {
        id: appointmentId,
        createdAt: nowIso(),
        updatedAt: nowIso(),
        status: "booked",
        service,
        startAt,
        endAt,
        customer: { name, phone: optionalString(body?.phone), email: optionalString(body?.email) },
        notes: optionalString(body?.notes),
        leadId: optionalString(body?.leadId)
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
        const appt = await store.get(`appointments/${id}`, { type: "json" });
        if (!appt) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ appointment: appt }, 200, args.corsHeaders);
      }
      if (req.method === "PUT") {
        const body = await safeJson(req);
        const patch = {
          status: optionalString(body?.status),
          notes: optionalString(body?.notes)
        };
        const updated = await patchAppointment(store, id, (appt) => ({
          ...appt,
          updatedAt: nowIso(),
          status: patch.status ?? appt.status,
          notes: patch.notes ?? appt.notes
        }));
        if (!updated) return respondJson({ error: "not_found" }, 404, args.corsHeaders);
        return respondJson({ ok: true }, 200, args.corsHeaders);
      }
      if (req.method === "DELETE") {
        const appt = await store.get(`appointments/${id}`, { type: "json" });
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
      const snapshot = body?.snapshot;
      if (!snapshot) return respondJson({ error: "missing_snapshot" }, 400, args.corsHeaders);
      if (!isFullSnapshotShape(snapshot)) {
        return respondJson({ error: "full_snapshot_required" }, 400, args.corsHeaders);
      }
      await importSnapshot(store, snapshot);
      return respondJson({ ok: true }, 200, args.corsHeaders);
    }
    return respondJson({ error: "not_found" }, 404, args.corsHeaders);
  }
  return respondJson({ error: "not_found" }, 404, args.corsHeaders);
}
async function computeAvailability(store, env, date, service) {
  const times = buildSlots(env, date);
  const out = [];
  for (const time of times) {
    const lock = await store.get(slotLockKey(date, time, service), { type: "json" });
    const used = lock?.ids?.length ?? 0;
    const remaining = Math.max(0, env.capacityPerSlot - used);
    out.push({ time, available: remaining > 0, remaining });
  }
  return out;
}
function buildSlots(env, _date) {
  const slots = [];
  const startMin = env.openHour * 60;
  const endMin = env.closeHour * 60;
  for (let m = startMin; m + env.slotMinutes <= endMin; m += env.slotMinutes) {
    const hh = String(Math.floor(m / 60)).padStart(2, "0");
    const mm = String(m % 60).padStart(2, "0");
    slots.push(`${hh}:${mm}`);
  }
  return slots;
}
function slotLockKey(date, time, service) {
  const safeService = service.replaceAll("/", "_").slice(0, 80);
  return `slots/${date}/${time}/${safeService}`;
}
async function reserveSlot(store, slotKey, appointmentId, capacity) {
  for (let i = 0; i < 5; i += 1) {
    const existing = await store.getWithMetadata(slotKey, { type: "json" });
    if (!existing) {
      const next2 = { ids: [appointmentId] };
      const res2 = await store.setJSON(slotKey, next2, { onlyIfNew: true });
      if (res2.modified) return { ok: true };
      continue;
    }
    const ids = Array.isArray(existing.data?.ids) ? existing.data.ids : [];
    if (ids.includes(appointmentId)) return { ok: true };
    if (ids.length >= capacity) return { ok: false };
    const next = { ids: [...ids, appointmentId] };
    const res = await store.setJSON(slotKey, next, { onlyIfMatch: existing.etag });
    if (res.modified) return { ok: true };
  }
  return { ok: false };
}
async function releaseSlot(store, slotKey, appointmentId) {
  for (let i = 0; i < 5; i += 1) {
    const existing = await store.getWithMetadata(slotKey, { type: "json" });
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
async function rateLimit(store, ip, dailyLimit) {
  const day = nowIso().slice(0, 10);
  const key = `ratelimit_v2/${day}/${hashShort(ip)}`;
  for (let i = 0; i < 5; i += 1) {
    const existing = await store.getWithMetadata(key, { type: "json" });
    if (!existing) {
      const res2 = await store.setJSON(key, { count: 1 }, { onlyIfNew: true });
      if (res2.modified) return { ok: true };
      continue;
    }
    const count = typeof existing.data?.count === "number" ? existing.data.count : 0;
    if (count >= dailyLimit) return { ok: false };
    const res = await store.setJSON(key, { count: count + 1 }, { onlyIfMatch: existing.etag });
    if (res.modified) return { ok: true };
  }
  return { ok: false };
}
function normalizeMessage(msg) {
  const m = (msg ?? "").trim().toLowerCase();
  const compact = m.replace(/\s+/g, " ");
  return compact.length ? compact : null;
}
function leadByMessageKey(message) {
  return `indexes/leadByMessage/${sha256Hex(message)}`;
}
async function findExistingLeadIdByMessage(store, message) {
  const m = normalizeMessage(message);
  if (!m) return null;
  const idx = await store.get(leadByMessageKey(m), { type: "json" });
  const id = safeText(idx?.id);
  return id || null;
}
async function reserveMessageIndex(store, opts) {
  const m = normalizeMessage(opts.message);
  if (!m) return { ok: true };
  const key = leadByMessageKey(m);
  const res = await store.setJSON(key, { id: opts.id }, { onlyIfNew: true });
  if (res.modified) return { ok: true };
  const idx = await store.get(key, { type: "json" });
  const existingId = safeText(idx?.id) || opts.id;
  return { ok: false, existingId };
}
async function releaseReservedMessageIndex(store, opts) {
  const m = normalizeMessage(opts.message);
  if (!m) return;
  try {
    const key = leadByMessageKey(m);
    const idx = await store.get(key, { type: "json" });
    if (safeText(idx?.id) === opts.id) await store.delete(key);
  } catch {
  }
}
function normalizeEmail(email) {
  const e = (email ?? "").trim().toLowerCase();
  return e.length ? e : null;
}
function normalizePhone(phone) {
  const p = (phone ?? "").trim();
  if (!p) return null;
  const cleaned = p.startsWith("+") ? "+" + p.slice(1).replace(/[^\d]/g, "") : p.replace(/[^\d]/g, "");
  return cleaned.length ? cleaned : null;
}
function leadByEmailKey(email) {
  return `indexes/leadByEmail/${hashShort(email)}`;
}
function leadByPhoneKey(phone) {
  return `indexes/leadByPhone/${hashShort(phone)}`;
}
async function findExistingLeadIdByContact(store, c) {
  const e = normalizeEmail(c.email);
  if (e) {
    const idx = await store.get(leadByEmailKey(e), { type: "json" });
    const id = safeText(idx?.id);
    if (id) return id;
  }
  const p = normalizePhone(c.phone);
  if (p) {
    const idx = await store.get(leadByPhoneKey(p), { type: "json" });
    const id = safeText(idx?.id);
    if (id) return id;
  }
  return null;
}
async function reserveContactIndexes(store, opts) {
  const e = normalizeEmail(opts.email);
  const p = normalizePhone(opts.phone);
  const existing = await findExistingLeadIdByContact(store, { email: e ?? void 0, phone: p ?? void 0 });
  if (existing) return { ok: false, existingId: existing };
  if (e) {
    const key = leadByEmailKey(e);
    const res = await store.setJSON(key, { id: opts.id }, { onlyIfNew: true });
    if (!res.modified) {
      const idx = await store.get(key, { type: "json" });
      const id = safeText(idx?.id) || opts.id;
      return { ok: false, existingId: id };
    }
  }
  if (p) {
    const key = leadByPhoneKey(p);
    const res = await store.setJSON(key, { id: opts.id }, { onlyIfNew: true });
    if (!res.modified) {
      if (e) {
        try {
          await store.delete(leadByEmailKey(e));
        } catch {
        }
      }
      const idx = await store.get(key, { type: "json" });
      const id = safeText(idx?.id) || opts.id;
      return { ok: false, existingId: id };
    }
  }
  return { ok: true };
}
async function safeAppendLeadEvent(store, id, evt) {
  try {
    await patchLead(store, id, (lead) => ({
      ...lead,
      updatedAt: nowIso(),
      timeline: [...lead.timeline ?? [], { at: nowIso(), type: evt.type, note: evt.note }]
    }));
  } catch {
  }
}
var ForbiddenError = class extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
};
async function patchLead(store, id, updater) {
  for (let i = 0; i < 5; i += 1) {
    const existing = await store.getWithMetadata(`leads/${id}`, { type: "json" });
    if (!existing) return false;
    let next;
    try {
      next = updater(existing.data);
    } catch (e) {
      if (e instanceof ForbiddenError) throw e;
      throw e;
    }
    const res = await store.setJSON(`leads/${id}`, next, { onlyIfMatch: existing.etag });
    if (res.modified) return true;
  }
  return false;
}
async function listLeads(store, opts) {
  const { blobs } = await store.list({ prefix: "indexes/leads/" });
  const keys = blobs.map((b) => b.key).sort().reverse();
  const leads = [];
  for (const k of keys) {
    if (leads.length >= opts.limit) break;
    const idx = await store.get(decodeBlobKey(k), { type: "json" });
    if (!idx?.id) continue;
    const lead = await store.get(`leads/${idx.id}`, { type: "json" });
    if (!lead) continue;
    if (lead.deletedAt) continue;
    if (opts.status && lead.status !== opts.status) continue;
    if (opts.q && !matchesQuery(lead, opts.q)) continue;
    leads.push(lead);
  }
  return leads;
}
function matchesQuery(lead, q) {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const hay = [lead.id, lead.name, lead.email ?? "", lead.phone ?? "", lead.service ?? "", lead.notes ?? "", lead.status].join(" ").toLowerCase();
  return hay.includes(needle);
}
async function pullOnceConsumeLeads(store, opts) {
  const { blobs } = await store.list({ prefix: "indexes/leads/" });
  const keys = blobs.map((b) => b.key).sort().reverse();
  const out = [];
  for (const k of keys) {
    if (out.length >= opts.limit) break;
    const idx = await store.get(decodeBlobKey(k), { type: "json" });
    const id = safeText(idx?.id);
    if (!id) continue;
    const claimed = await tryClaimLead(store, id, opts);
    if (!claimed) continue;
    await consumeLead(store, claimed);
    out.push(claimed);
  }
  return out;
}
async function tryClaimLead(store, id, opts) {
  for (let i = 0; i < 5; i += 1) {
    const existing = await store.getWithMetadata(`leads/${id}`, { type: "json" });
    if (!existing) return null;
    const lead = existing.data;
    if (!lead) return null;
    if (lead.deletedAt) return null;
    if (lead.assignedTo) return null;
    if (opts.status && lead.status !== opts.status) return null;
    const ts = nowIso();
    const next = {
      ...lead,
      assignedTo: opts.assignedTo,
      pulledAt: ts,
      updatedAt: ts,
      updatedBy: opts.assignedTo,
      updatedDeviceId: opts.deviceId ?? lead.updatedDeviceId,
      timeline: [...lead.timeline ?? [], { at: ts, type: "pulled", note: opts.assignedTo }]
    };
    const res = await store.setJSON(`leads/${id}`, next, { onlyIfMatch: existing.etag });
    if (res.modified) return next;
  }
  return null;
}
async function consumeLead(store, lead) {
  const ts = nowIso();
  const markerKey = `pulled/${lead.id}`;
  const res = await store.setJSON(markerKey, { id: lead.id, pulledAt: ts }, { onlyIfNew: true });
  if (!res.modified) return;
  await patchLead(store, lead.id, (l) => ({
    ...l,
    status: "archived",
    archivedAt: ts,
    updatedAt: ts,
    updatedBy: lead.updatedBy ?? l.updatedBy,
    updatedDeviceId: lead.updatedDeviceId ?? l.updatedDeviceId,
    timeline: [...l.timeline ?? [], { at: ts, type: "archived" }]
  }));
}
async function patchAppointment(store, id, updater) {
  for (let i = 0; i < 5; i += 1) {
    const existing = await store.getWithMetadata(`appointments/${id}`, { type: "json" });
    if (!existing) return false;
    const next = updater(existing.data);
    const res = await store.setJSON(`appointments/${id}`, next, { onlyIfMatch: existing.etag });
    if (res.modified) return true;
  }
  return false;
}
async function listAppointments(store, opts) {
  const { blobs } = await store.list({ prefix: "appointments/" });
  const keys = blobs.map((b) => b.key).sort().reverse();
  const appts = [];
  for (const k of keys) {
    if (appts.length >= opts.limit) break;
    const appt = await store.get(k, { type: "json" });
    if (!appt) continue;
    if (opts.from && appt.startAt < opts.from) continue;
    if (opts.to && appt.startAt > opts.to) continue;
    appts.push(appt);
  }
  return appts;
}
async function computeMetrics(store) {
  const leads = await listLeads(store, { limit: 200, q: void 0, status: void 0 });
  const { blobs: apptBlobs } = await store.list({ prefix: "appointments/" });
  const appts = [];
  for (const b of apptBlobs) {
    const a = await store.get(b.key, { type: "json" });
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
  const landedByDay = /* @__PURE__ */ new Map();
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
    bestDay
  };
}
async function exportSnapshot(store) {
  const { blobs: leadBlobs } = await store.list({ prefix: "leads/" });
  const { blobs: apptBlobs } = await store.list({ prefix: "appointments/" });
  const { blobs: slotBlobs } = await store.list({ prefix: "slots/" });
  const { blobs: todoBlobs } = await store.list({ prefix: "todos/" });
  const leads = [];
  for (const b of leadBlobs) {
    const l = await store.get(b.key, { type: "json" });
    if (l) leads.push(l);
  }
  const appointments = [];
  for (const b of apptBlobs) {
    const a = await store.get(b.key, { type: "json" });
    if (a) appointments.push(a);
  }
  const slots = {};
  for (const b of slotBlobs) {
    const s = await store.get(b.key, { type: "json" });
    if (s) slots[b.key] = s;
  }
  const todos = [];
  for (const b of todoBlobs) {
    const t = await store.get(b.key, { type: "json" });
    if (t) todos.push(t);
  }
  return { exportedAt: nowIso(), leads, appointments, slots, todos };
}
async function importSnapshot(store, snapshot) {
  const incomingLeads = Array.isArray(snapshot.leads) ? snapshot.leads : [];
  const incomingIds = new Set(incomingLeads.map((l) => safeText(l?.id)).filter(Boolean));
  const { blobs: existingLeadBlobs } = await store.list({ prefix: "leads/" });
  for (const b of existingLeadBlobs) {
    const ex = await store.get(b.key, { type: "json" });
    if (!ex?.id) continue;
    if (incomingIds.has(ex.id)) continue;
    if (ex.deletedAt) continue;
    await patchLead(store, ex.id, (l) => {
      const ts = nowIso();
      return {
        ...l,
        status: "archived",
        deletedAt: ts,
        updatedAt: ts,
        updatedBy: "import",
        timeline: [...l.timeline ?? [], { at: ts, type: "archived", note: "missing_from_import" }]
      };
    });
  }
  for (const lead of incomingLeads) {
    if (!lead?.id || !lead?.createdAt) continue;
    const normalized = {
      ...lead,
      source: "public",
      timeline: mergeTimeline([], lead.timeline)
    };
    await store.setJSON(`leads/${lead.id}`, normalized, { onlyIfNew: false });
    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: false }
    );
    const e = normalizeEmail(lead.email);
    const p = normalizePhone(lead.phone);
    if (e) await store.setJSON(leadByEmailKey(e), { id: lead.id }, { onlyIfNew: false });
    if (p) await store.setJSON(leadByPhoneKey(p), { id: lead.id }, { onlyIfNew: false });
  }
  for (const appt of snapshot.appointments ?? []) {
    if (!appt?.id) continue;
    await store.setJSON(`appointments/${appt.id}`, appt, { onlyIfNew: false });
  }
  const slots = snapshot.slots ?? {};
  for (const [k, v] of Object.entries(slots)) {
    if (!k) continue;
    await store.setJSON(k, v, { onlyIfNew: false });
  }
  for (const todo of snapshot.todos ?? []) {
    if (!todo?.id) continue;
    await store.setJSON(`todos/${todo.id}`, todo, { onlyIfNew: false });
  }
}
function syncMetaKey(workspaceId) {
  return `sync/meta/${workspaceId}`;
}
async function getSyncMeta(store, workspaceId) {
  const meta = await store.get(syncMetaKey(workspaceId), { type: "json" });
  if (meta && typeof meta.version === "number" && typeof meta.updatedAt === "string") return meta;
  return { version: 0, updatedAt: "\u2014" };
}
async function bumpSyncMeta(store, workspaceId) {
  const key = syncMetaKey(workspaceId);
  for (let i = 0; i < 5; i += 1) {
    const existing = await store.getWithMetadata(key, { type: "json" });
    if (!existing) {
      const next2 = { version: 1, updatedAt: nowIso() };
      const res2 = await store.setJSON(key, next2, { onlyIfNew: true });
      if (res2.modified) return next2;
      continue;
    }
    const curV = typeof existing.data?.version === "number" ? existing.data.version : 0;
    const next = { version: curV + 1, updatedAt: nowIso() };
    const res = await store.setJSON(key, next, { onlyIfMatch: existing.etag });
    if (res.modified) return next;
  }
  return await getSyncMeta(store, workspaceId);
}
function isoGt(a, b) {
  if (!a) return false;
  if (!b) return true;
  return a > b;
}
function mergeTimeline(a, b) {
  const x = Array.isArray(a) ? a : [];
  const y = Array.isArray(b) ? b : [];
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const evt of [...x, ...y]) {
    const key = JSON.stringify([evt?.at ?? "", evt?.type ?? "", evt?.note ?? ""]);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ at: String(evt?.at ?? ""), type: String(evt?.type ?? ""), note: evt?.note ? String(evt.note) : void 0 });
  }
  out.sort((m, n) => String(m.at).localeCompare(String(n.at)));
  return out;
}
function mergeLead(ex, inc) {
  if (ex.deletedAt || inc.deletedAt) {
    const winner = ex.deletedAt ? ex : inc;
    return {
      ...winner,
      deletedAt: ex.deletedAt || inc.deletedAt,
      timeline: mergeTimeline(ex.timeline, inc.timeline),
      updatedAt: nowIso()
    };
  }
  const newer = isoGt(inc.updatedAt, ex.updatedAt);
  return newer ? { ...ex, ...inc, timeline: mergeTimeline(ex.timeline, inc.timeline) } : { ...inc, ...ex, timeline: mergeTimeline(ex.timeline, inc.timeline) };
}
async function mergeSnapshots(store, args) {
  const serverLeads = new Map(args.server.leads.map((l) => [l.id, l]));
  const serverAppts = new Map(args.server.appointments.map((a) => [a.id, a]));
  const serverTodos = new Map(args.server.todos.map((t) => [t.id, t]));
  const mergedSlots = { ...args.server.slots ?? {} };
  for (const inc of args.incoming.leads ?? []) {
    if (!inc?.id || !inc?.createdAt) continue;
    const ex = serverLeads.get(inc.id);
    if (ex) {
      serverLeads.set(inc.id, mergeLead(ex, inc));
      continue;
    }
    const byContact = await findExistingLeadIdByContact(store, { email: inc.email, phone: inc.phone });
    if (byContact) {
      const ex2 = serverLeads.get(byContact) || await store.get(`leads/${byContact}`, { type: "json" });
      if (ex2) {
        const incFixed = { ...inc, id: ex2.id, createdAt: ex2.createdAt };
        serverLeads.set(ex2.id, mergeLead(ex2, incFixed));
        continue;
      }
    }
    const reserve = await reserveContactIndexes(store, { id: inc.id, email: inc.email, phone: inc.phone });
    if (!reserve.ok) {
      const ex3 = serverLeads.get(reserve.existingId) || await store.get(`leads/${reserve.existingId}`, { type: "json" });
      if (ex3) {
        const incFixed = { ...inc, id: ex3.id, createdAt: ex3.createdAt };
        serverLeads.set(ex3.id, mergeLead(ex3, incFixed));
      }
      continue;
    }
    const nextNew = {
      ...inc,
      source: "public",
      timeline: mergeTimeline([], inc.timeline)
    };
    serverLeads.set(nextNew.id, nextNew);
  }
  for (const inc of args.incoming.appointments ?? []) {
    if (!inc?.id) continue;
    const ex = serverAppts.get(inc.id);
    if (!ex) {
      serverAppts.set(inc.id, inc);
      continue;
    }
    serverAppts.set(inc.id, isoGt(inc.updatedAt, ex.updatedAt) ? inc : ex);
  }
  for (const inc of args.incoming.todos ?? []) {
    if (!inc?.id) continue;
    const ex = serverTodos.get(inc.id);
    if (!ex) {
      serverTodos.set(inc.id, inc);
      continue;
    }
    serverTodos.set(inc.id, isoGt(inc.updatedAt, ex.updatedAt) ? inc : ex);
  }
  const incomingSlots = args.incoming.slots ?? {};
  for (const [k, v] of Object.entries(incomingSlots)) {
    const a = mergedSlots[k]?.ids ?? [];
    const b = v?.ids ?? [];
    const set = new Set([...a, ...b].filter(Boolean));
    mergedSlots[k] = { ids: Array.from(set) };
  }
  return {
    leads: Array.from(serverLeads.values()),
    appointments: Array.from(serverAppts.values()),
    slots: mergedSlots,
    todos: Array.from(serverTodos.values())
  };
}
async function persistMergedSnapshot(store, merged) {
  for (const lead of merged.leads) {
    if (!lead?.id || !lead?.createdAt) continue;
    await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: false });
    await store.setJSON(
      `indexes/leads/${lead.createdAt}_${lead.id}`,
      { id: lead.id, createdAt: lead.createdAt },
      { onlyIfNew: true }
    );
    const e = normalizeEmail(lead.email);
    const p = normalizePhone(lead.phone);
    if (e) await store.setJSON(leadByEmailKey(e), { id: lead.id }, { onlyIfNew: false });
    if (p) await store.setJSON(leadByPhoneKey(p), { id: lead.id }, { onlyIfNew: false });
  }
  for (const appt of merged.appointments) {
    if (!appt?.id) continue;
    await store.setJSON(`appointments/${appt.id}`, appt, { onlyIfNew: false });
  }
  for (const [k, v] of Object.entries(merged.slots ?? {})) {
    await store.setJSON(k, v, { onlyIfNew: false });
  }
  for (const todo of merged.todos ?? []) {
    if (!todo?.id) continue;
    await store.setJSON(`todos/${todo.id}`, todo, { onlyIfNew: false });
  }
}
function isFullSnapshotShape(v) {
  if (!v || typeof v !== "object") return false;
  if (!Array.isArray(v.leads)) return false;
  if (!Array.isArray(v.appointments)) return false;
  if (!Array.isArray(v.todos)) return false;
  if (!v.slots || typeof v.slots !== "object") return false;
  return true;
}
function requireAuth(env, authHeader) {
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice("Bearer ".length).trim() : "";
  if (!token) return { ok: false };
  const payload = verifyJwt(env.jwtSecret, token);
  if (!payload) return { ok: false };
  return { ok: true, payload };
}
function verifyUser(env, username, password) {
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
function signJwt(secret, payload) {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = b64url(JSON.stringify(header));
  const encPayload = b64url(JSON.stringify(payload));
  const data = `${encHeader}.${encPayload}`;
  const sig = hmacSha256(secret, data);
  return `${data}.${sig}`;
}
function verifyJwt(secret, token) {
  if (!secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const data = `${h}.${p}`;
  const expected = hmacSha256(secret, data);
  if (!timingSafeEqualStr(expected, s)) return null;
  try {
    const payload = JSON.parse(b64urlDecode(p));
    if (typeof payload?.exp !== "number" || nowSec() > payload.exp) return null;
    if (typeof payload?.sub !== "string") return null;
    if (payload.role !== "admin" && payload.role !== "staff") return null;
    return payload;
  } catch {
    return null;
  }
}
function readEnvSafe() {
  const jwtSecret = envGet("JWT_SECRET") ?? "";
  const allowedOriginsRaw = envGet("ALLOWED_ORIGINS") ?? "";
  const allowedOrigins = allowedOriginsRaw.trim().length > 0 ? allowedOriginsRaw.split(",").map((s) => s.trim()).filter(Boolean) : null;
  const crmUsername = envGet("CRM_USERNAME");
  const crmPasswordHash = envGet("CRM_PASSWORD_HASH");
  const crmPassword = envGet("CRM_PASSWORD");
  const slotMinutes = clampInt(envGet("SLOT_MINUTES"), 10, 240, 30);
  const openHour = clampInt(envGet("OPEN_HOUR"), 0, 23, 9);
  const closeHour = clampInt(envGet("CLOSE_HOUR"), 1, 24, 17);
  const capacityPerSlot = clampInt(envGet("CAPACITY_PER_SLOT"), 1, 50, 1);
  const tz = envGet("TZ") ?? "America/Los_Angeles";
  const publicDailyRateLimit = clampInt(envGet("PUBLIC_DAILY_RATE_LIMIT"), 1, 1e4, 5e3);
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
    publicDailyRateLimit
  };
}
function envGet(key) {
  const v1 = process.env[key];
  if (typeof v1 === "string" && v1.length) return v1;
  const n = globalThis?.Netlify?.env?.get?.(key);
  if (typeof n === "string" && n.length) return n;
  return null;
}
function buildCorsHeaders(env, origin, accessControlRequestHeaders) {
  const h = new Headers();
  const allowOrigin = computeAllowedOrigin(env, origin);
  if (allowOrigin) h.set("access-control-allow-origin", allowOrigin);
  h.set("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS");
  const reqHeaders = (accessControlRequestHeaders ?? "").trim();
  if (reqHeaders) {
    h.set("access-control-allow-headers", reqHeaders);
  } else {
    h.set(
      "access-control-allow-headers",
      "content-type,authorization,x-device-id,x-client-name,x-client-version,x-workspace-id"
    );
  }
  h.set("access-control-max-age", "86400");
  if (allowOrigin && allowOrigin !== "*") h.set("vary", "origin");
  return h;
}
function computeAllowedOrigin(env, origin) {
  const o = (origin ?? "").trim();
  if (!o) return null;
  if (env.allowedOrigins === null) return "*";
  const list = env.allowedOrigins.map((x) => (x ?? "").trim()).filter(Boolean);
  if (list.length === 0) return null;
  if (list.includes("*")) return "*";
  if (list.includes(o)) return o;
  let originUrl = null;
  try {
    originUrl = new URL(o);
  } catch {
    return null;
  }
  const originHost = originUrl.host;
  const originProto = originUrl.protocol;
  for (const rawPattern of list) {
    const p = rawPattern.trim();
    if (!p) continue;
    if (p.includes("://")) {
      let patternUrl = null;
      try {
        const tmp = p.replace("://*.", "://placeholder.");
        patternUrl = new URL(tmp);
      } catch {
        patternUrl = null;
      }
      if (patternUrl && patternUrl.protocol !== originProto) continue;
      const hostPattern = p.split("://")[1] ?? "";
      if (hostPattern.startsWith("*.")) {
        const base = hostPattern.slice(2);
        if (originHost === base) continue;
        if (originHost.endsWith("." + base)) return o;
      }
      continue;
    }
    if (p.startsWith("*.")) {
      const base = p.slice(2);
      if (originHost === base) continue;
      if (originHost.endsWith("." + base)) return o;
    }
  }
  return null;
}
function normalizeApiPath(pathname) {
  if (pathname.startsWith("/.netlify/functions/api")) {
    const rest = pathname.slice("/.netlify/functions/api".length);
    return `/api${rest || ""}`.replaceAll("//", "/");
  }
  return pathname.replaceAll("//", "/");
}
function respondJson(data, status, corsHeaders) {
  const headers = new Headers(corsHeaders);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(json(data), { status, headers });
}
function json(v) {
  return JSON.stringify(v);
}
async function safeJson(req) {
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.toLowerCase().includes("application/json")) return null;
  try {
    return await req.json();
  } catch {
    return null;
  }
}
function asString(v) {
  return typeof v === "string" ? v : null;
}
function requiredString(v) {
  const s = asString(v);
  if (!s) return null;
  const t = s.trim();
  return t.length ? t : null;
}
function optionalString(v) {
  const s = asString(v);
  if (!s) return void 0;
  const t = s.trim();
  return t.length ? t : void 0;
}
function safeText(v) {
  return typeof v === "string" ? v.trim() : "";
}
function decodeBlobKey(key) {
  try {
    return decodeURIComponent(key);
  } catch {
    return key;
  }
}
function requestDeviceId(req) {
  const raw = req.headers.get("x-device-id") ?? "";
  const v = raw.trim();
  if (!v) return null;
  return /^[A-Za-z0-9_-]{1,64}$/.test(v) ? v : null;
}
function nowIso() {
  return (/* @__PURE__ */ new Date()).toISOString();
}
function nowSec() {
  return Math.floor(Date.now() / 1e3);
}
function b64url(input) {
  return Buffer.from(input, "utf8").toString("base64").replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}
function b64urlDecode(input) {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - input.length % 4);
  const b64 = input.replaceAll("-", "+").replaceAll("_", "/") + pad;
  return Buffer.from(b64, "base64").toString("utf8");
}
function hmacSha256(secret, data) {
  const sig = import_node_crypto.default.createHmac("sha256", secret).update(data).digest("base64");
  return sig.replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}
function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return import_node_crypto.default.timingSafeEqual(ba, bb);
}
function sha256Hex(s) {
  return import_node_crypto.default.createHash("sha256").update(s, "utf8").digest("hex");
}
function hashShort(s) {
  return import_node_crypto.default.createHash("sha256").update(s, "utf8").digest("hex").slice(0, 16);
}
function isDateYmd(s) {
  return /^\d{4}-\d{2}-\d{2}$/.test(s);
}
function isTimeHm(s) {
  return /^\d{2}:\d{2}$/.test(s);
}
function dateAddDays(ymd, delta) {
  const d = /* @__PURE__ */ new Date(`${ymd}T00:00:00.000Z`);
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
}
function toIsoFromLocal(dateYmd, timeHm) {
  const [hh, mm] = timeHm.split(":").map((x) => Number(x));
  const dt = new Date(dateYmd);
  dt.setHours(hh, mm, 0, 0);
  return dt.toISOString();
}
function splitIsoToDateTime(iso) {
  const d = new Date(iso);
  const yyyy = String(d.getFullYear()).padStart(4, "0");
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return { date: `${yyyy}-${mm}-${dd}`, time: `${hh}:${mi}` };
}
function clampInt(v, min, max, def) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  const i = Math.floor(n);
  return Math.min(max, Math.max(min, i));
}
function clientIp(args) {
  const viaContext = args.context?.ip;
  if (typeof viaContext === "string" && viaContext.trim()) return viaContext.trim();
  const h = args.req.headers;
  const nf = h.get("x-nf-client-connection-ip");
  if (nf) return nf.split(",")[0].trim();
  const xff = h.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return "0.0.0.0";
}
function isSafeDeviceId(s) {
  return /^[A-Za-z0-9_-]{1,64}$/.test(s);
}
function snapshotKey(deviceId) {
  return `snapshots/${deviceId}`;
}
function asDeviceSnapshot(v, fallbackDeviceId) {
  if (!v || typeof v !== "object") return null;
  const deviceId = safeText(v.deviceId) || fallbackDeviceId;
  const at = safeText(v.at) || nowIso();
  const customersRaw = Array.isArray(v.customers) ? v.customers : [];
  const customers = customersRaw.filter((c) => c && typeof c === "object" && typeof c.id === "string").map((c) => ({
    ...c,
    id: String(c.id),
    createdAt: safeText(c.createdAt) || nowIso(),
    updatedAt: safeText(c.updatedAt) || safeText(c.createdAt) || nowIso()
  }));
  const tombstonesRaw = v.tombstones && typeof v.tombstones === "object" ? v.tombstones : {};
  const tombstones = {};
  for (const [k, val] of Object.entries(tombstonesRaw)) {
    const id = safeText(k);
    const deletedAt = safeText(val);
    if (id && deletedAt) tombstones[id] = deletedAt;
  }
  return { deviceId, at, customers, tombstones };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  config
});
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsibmV0bGlmeS9mdW5jdGlvbnMvYXBpLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvKiBGaWxlOiBuZXRsaWZ5L2Z1bmN0aW9ucy9hcGkudHMgKi9cclxuXHJcbmltcG9ydCB0eXBlIHsgQ29uZmlnLCBDb250ZXh0IH0gZnJvbSBcIkBuZXRsaWZ5L2Z1bmN0aW9uc1wiO1xyXG5pbXBvcnQgeyBnZXRTdG9yZSB9IGZyb20gXCJAbmV0bGlmeS9ibG9ic1wiO1xyXG5pbXBvcnQgY3J5cHRvIGZyb20gXCJub2RlOmNyeXB0b1wiO1xyXG5cclxuZXhwb3J0IGNvbnN0IGNvbmZpZzogQ29uZmlnID0ge1xyXG4gIHBhdGg6IFwiL2FwaS8qXCIsXHJcbn07XHJcblxyXG50eXBlIEpzb25WYWx1ZSA9IG51bGwgfCBib29sZWFuIHwgbnVtYmVyIHwgc3RyaW5nIHwgSnNvblZhbHVlW10gfCB7IFtrOiBzdHJpbmddOiBKc29uVmFsdWUgfTtcclxuXHJcbnR5cGUgTGVhZFN0YXR1cyA9IFwiaG90XCIgfCBcIm5ld1wiIHwgXCJmb2xsb3dfdXBcIiB8IFwiYXBwb2ludG1lbnRcIiB8IFwibGFuZGVkXCIgfCBcIm5vXCIgfCBcImFyY2hpdmVkXCI7XHJcbnR5cGUgQXBwb2ludG1lbnRTdGF0dXMgPSBcImJvb2tlZFwiIHwgXCJjYW5jZWxlZFwiIHwgXCJjb21wbGV0ZWRcIjtcclxuXHJcbnR5cGUgTGVhZCA9IHtcclxuICBpZDogc3RyaW5nO1xyXG4gIGNyZWF0ZWRBdDogc3RyaW5nO1xyXG4gIHVwZGF0ZWRBdDogc3RyaW5nO1xyXG5cclxuICBkZWxldGVkQXQ/OiBzdHJpbmc7XHJcbiAgYXJjaGl2ZWRBdD86IHN0cmluZzsgLy8gXHUyNzA1IGFkZCB0aGlzIGlmIHlvdSB3YW50IGl0XHJcblxyXG4gIHVwZGF0ZWRCeT86IHN0cmluZztcclxuICB1cGRhdGVkRGV2aWNlSWQ/OiBzdHJpbmc7XHJcblxyXG4gIHNvdXJjZTogXCJwdWJsaWNcIjtcclxuICBzdGF0dXM6IExlYWRTdGF0dXM7XHJcbiAgbmFtZTogc3RyaW5nO1xyXG4gIHBob25lPzogc3RyaW5nO1xyXG4gIGVtYWlsPzogc3RyaW5nO1xyXG4gIHNlcnZpY2U/OiBzdHJpbmc7XHJcbiAgbm90ZXM/OiBzdHJpbmc7XHJcbiAgcHJlZmVycmVkRGF0ZT86IHN0cmluZztcclxuICBwcmVmZXJyZWRUaW1lPzogc3RyaW5nO1xyXG4gIGZvbGxvd1VwQXQ/OiBzdHJpbmc7XHJcblxyXG4gIGFzc2lnbmVkVG8/OiBzdHJpbmc7XHJcbiAgcHVsbGVkQXQ/OiBzdHJpbmc7XHJcblxyXG4gIHRpbWVsaW5lOiBBcnJheTx7IGF0OiBzdHJpbmc7IHR5cGU6IHN0cmluZzsgbm90ZT86IHN0cmluZyB9PjtcclxufTtcclxuXHJcbnR5cGUgQXBwb2ludG1lbnQgPSB7XHJcbiAgaWQ6IHN0cmluZztcclxuICBjcmVhdGVkQXQ6IHN0cmluZztcclxuICB1cGRhdGVkQXQ6IHN0cmluZztcclxuICBzdGF0dXM6IEFwcG9pbnRtZW50U3RhdHVzO1xyXG4gIHNlcnZpY2U6IHN0cmluZztcclxuICBzdGFydEF0OiBzdHJpbmc7XHJcbiAgZW5kQXQ6IHN0cmluZztcclxuICBjdXN0b21lcjogeyBuYW1lOiBzdHJpbmc7IHBob25lPzogc3RyaW5nOyBlbWFpbD86IHN0cmluZyB9O1xyXG4gIG5vdGVzPzogc3RyaW5nO1xyXG4gIGxlYWRJZD86IHN0cmluZztcclxufTtcclxuXHJcbnR5cGUgVG9kbyA9IHtcclxuICBpZDogc3RyaW5nO1xyXG4gIGNyZWF0ZWRBdDogc3RyaW5nO1xyXG4gIHVwZGF0ZWRBdDogc3RyaW5nO1xyXG4gIHRleHQ6IHN0cmluZztcclxuICBkb25lOiBib29sZWFuO1xyXG4gIGR1ZUF0Pzogc3RyaW5nO1xyXG59O1xyXG5cclxuLyoqXHJcbiAqIERldmljZSBzbmFwc2hvdCBzeW5jIChDUk0gbWVyZ2VzIG9uIGNsaWVudCkuXHJcbiAqIC0gY3VzdG9tZXJzOiBmdWxsIGRldmljZSBzdGF0ZVxyXG4gKiAtIHRvbWJzdG9uZXM6IGRlbGV0aW9ucyBieSBpZCAoZGVsZXRlZEF0IElTTykgc28gZGVsZXRlcyBzeW5jIGFjcm9zcyBkZXZpY2VzXHJcbiAqL1xyXG50eXBlIEN1c3RvbWVyID0ge1xyXG4gIGlkOiBzdHJpbmc7XHJcbiAgY3JlYXRlZEF0OiBzdHJpbmc7XHJcbiAgdXBkYXRlZEF0OiBzdHJpbmc7XHJcbiAgW2s6IHN0cmluZ106IGFueTtcclxufTtcclxuXHJcbnR5cGUgRGV2aWNlU25hcHNob3QgPSB7XHJcbiAgZGV2aWNlSWQ6IHN0cmluZztcclxuICBhdDogc3RyaW5nO1xyXG4gIGN1c3RvbWVyczogQ3VzdG9tZXJbXTtcclxuICB0b21ic3RvbmVzOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+O1xyXG59O1xyXG5cclxudHlwZSBKd3RQYXlsb2FkID0ge1xyXG4gIHN1Yjogc3RyaW5nO1xyXG4gIHJvbGU6IFwiYWRtaW5cIiB8IFwic3RhZmZcIjtcclxuICBpYXQ6IG51bWJlcjtcclxuICBleHA6IG51bWJlcjtcclxufTtcclxuXHJcbnR5cGUgU2xvdExvY2sgPSB7IGlkczogc3RyaW5nW10gfTtcclxuXHJcbnR5cGUgU3luY01ldGEgPSB7IHZlcnNpb246IG51bWJlcjsgdXBkYXRlZEF0OiBzdHJpbmcgfTtcclxuXHJcbnR5cGUgRW52Q29uZmlnID0ge1xyXG4gIGp3dFNlY3JldDogc3RyaW5nOyAvLyBKV1RfU0VDUkVUXHJcbiAgYWxsb3dlZE9yaWdpbnM6IHN0cmluZ1tdIHwgbnVsbDsgLy8gQUxMT1dFRF9PUklHSU5TIChjb21tYS1zZXBhcmF0ZWQpLCBudWxsID0gXCIqXCJcclxuICBjcm1Vc2VybmFtZTogc3RyaW5nIHwgbnVsbDsgLy8gQ1JNX1VTRVJOQU1FXHJcbiAgY3JtUGFzc3dvcmRIYXNoOiBzdHJpbmcgfCBudWxsOyAvLyBDUk1fUEFTU1dPUkRfSEFTSCAoc2hhMjU2IGhleClcclxuICBjcm1QYXNzd29yZDogc3RyaW5nIHwgbnVsbDsgLy8gb3B0aW9uYWw6IENSTV9QQVNTV09SRCAocGxhaW50ZXh0IGZhbGxiYWNrKVxyXG4gIHNsb3RNaW51dGVzOiBudW1iZXI7XHJcbiAgb3BlbkhvdXI6IG51bWJlcjtcclxuICBjbG9zZUhvdXI6IG51bWJlcjtcclxuICBjYXBhY2l0eVBlclNsb3Q6IG51bWJlcjtcclxuICB0ejogc3RyaW5nO1xyXG4gIHB1YmxpY0RhaWx5UmF0ZUxpbWl0OiBudW1iZXI7XHJcbn07XHJcblxyXG5jb25zdCBTVE9SRV9OQU1FID0gXCJjcm1cIjtcclxuY29uc3QgQ09OU0lTVEVOQ1k6IFwic3Ryb25nXCIgPSBcInN0cm9uZ1wiO1xyXG5cclxuZXhwb3J0IGRlZmF1bHQgYXN5bmMgZnVuY3Rpb24gaGFuZGxlcihyZXE6IFJlcXVlc3QsIGNvbnRleHQ6IENvbnRleHQpIHtcclxuICBjb25zdCB1cmwgPSBuZXcgVVJMKHJlcS51cmwpO1xyXG4gIGNvbnN0IHBhdGggPSBub3JtYWxpemVBcGlQYXRoKHVybC5wYXRobmFtZSk7XHJcblxyXG4gIGNvbnN0IGVudiA9IHJlYWRFbnZTYWZlKCk7XHJcbiAgY29uc3Qgb3JpZ2luID0gcmVxLmhlYWRlcnMuZ2V0KFwib3JpZ2luXCIpID8/IFwiXCI7XHJcbiAgY29uc3QgYWNyaCA9IHJlcS5oZWFkZXJzLmdldChcImFjY2Vzcy1jb250cm9sLXJlcXVlc3QtaGVhZGVyc1wiKSA/PyBcIlwiO1xyXG4gIGNvbnN0IGNvcnNIZWFkZXJzID0gYnVpbGRDb3JzSGVhZGVycyhlbnYsIG9yaWdpbiwgYWNyaCk7XHJcblxyXG4gIC8vIEFsd2F5cyByZXNwb25kIHRvIGhlYWx0aCBldmVuIGlmIGVudiB2YXJzIGFyZSBtaXNzaW5nLlxyXG4gIGlmIChwYXRoID09PSBcIi9hcGkvaGVhbHRoXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJHRVRcIikge1xyXG4gICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBjb3JzSGVhZGVycyk7XHJcbiAgfVxyXG5cclxuICBpZiAocmVxLm1ldGhvZCA9PT0gXCJPUFRJT05TXCIpIHtcclxuICAgIHJldHVybiBuZXcgUmVzcG9uc2UobnVsbCwgeyBzdGF0dXM6IDIwNCwgaGVhZGVyczogY29yc0hlYWRlcnMgfSk7XHJcbiAgfVxyXG5cclxuICB0cnkge1xyXG4gICAgY29uc3Qgc3RvcmUgPSBnZXRTdG9yZSh7IG5hbWU6IFNUT1JFX05BTUUsIGNvbnNpc3RlbmN5OiBDT05TSVNURU5DWSB9KTtcclxuICAgIHJldHVybiBhd2FpdCByb3V0ZSh7IHJlcSwgY29udGV4dCwgZW52LCBzdG9yZSwgdXJsLCBwYXRoLCBjb3JzSGVhZGVycyB9KTtcclxuICB9IGNhdGNoIHtcclxuICAgIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcImludGVybmFsX2Vycm9yXCIgfSwgNTAwLCBjb3JzSGVhZGVycyk7XHJcbiAgfVxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiByb3V0ZShhcmdzOiB7XHJcbiAgcmVxOiBSZXF1ZXN0O1xyXG4gIGNvbnRleHQ6IENvbnRleHQ7XHJcbiAgZW52OiBFbnZDb25maWc7XHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPjtcclxuICB1cmw6IFVSTDtcclxuICBwYXRoOiBzdHJpbmc7XHJcbiAgY29yc0hlYWRlcnM6IEhlYWRlcnM7XHJcbn0pOiBQcm9taXNlPFJlc3BvbnNlPiB7XHJcbiAgY29uc3QgeyByZXEsIGVudiwgc3RvcmUsIHVybCwgcGF0aCB9ID0gYXJncztcclxuXHJcbiAgaWYgKHBhdGggPT09IFwiL2FwaS9oZWFsdGhcIiAmJiByZXEubWV0aG9kID09PSBcIkdFVFwiKSB7XHJcbiAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gIH1cclxuXHJcbiAgLy8gLS0tLSBBVVRIIC0tLS1cclxuICBpZiAocGF0aCA9PT0gXCIvYXBpL2F1dGgvbG9naW5cIiAmJiByZXEubWV0aG9kID09PSBcIlBPU1RcIikge1xyXG4gICAgaWYgKCFlbnYuand0U2VjcmV0KSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNjb25maWd1cmVkX2p3dF9zZWNyZXRcIiB9LCA1MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBzYWZlSnNvbihyZXEpO1xyXG4gICAgY29uc3QgdXNlcm5hbWUgPSBhc1N0cmluZyhib2R5Py51c2VybmFtZSk7XHJcbiAgICBjb25zdCBwYXNzd29yZCA9IGFzU3RyaW5nKGJvZHk/LnBhc3N3b3JkKTtcclxuICAgIGlmICghdXNlcm5hbWUgfHwgIXBhc3N3b3JkKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNzaW5nX2NyZWRlbnRpYWxzXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCB1c2VyID0gdmVyaWZ5VXNlcihlbnYsIHVzZXJuYW1lLCBwYXNzd29yZCk7XHJcbiAgICBpZiAoIXVzZXIpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcImludmFsaWRfY3JlZGVudGlhbHNcIiB9LCA0MDEsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IHRva2VuID0gc2lnbkp3dChlbnYuand0U2VjcmV0LCB7XHJcbiAgICAgIHN1YjogdXNlcm5hbWUsXHJcbiAgICAgIHJvbGU6IHVzZXIucm9sZSxcclxuICAgICAgaWF0OiBub3dTZWMoKSxcclxuICAgICAgZXhwOiBub3dTZWMoKSArIDYwICogNjAgKiAxMixcclxuICAgIH0pO1xyXG5cclxuICAgIHJldHVybiByZXNwb25kSnNvbih7IHRva2VuLCByb2xlOiB1c2VyLnJvbGUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICB9XHJcblxyXG4gIC8vIC0tLS0gUHVibGljIGVuZHBvaW50cyAtLS0tXHJcblxyXG4gIC8vIE5FVzogSG90IGxlYWRzIGVuZHBvaW50IChTY2hlZHVsZSBhIENhbGwpIHdpdGggc2VydmVyLXNpZGUgZGVkdXBlXHJcbiAgaWYgKHBhdGggPT09IFwiL2FwaS9wdWJsaWMvaG90LWxlYWRzXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcclxuICAgIGNvbnN0IGlwID0gY2xpZW50SXAoYXJncyk7XHJcbiAgICBjb25zdCBsaW1pdGVkID0gYXdhaXQgcmF0ZUxpbWl0KHN0b3JlLCBpcCwgZW52LnB1YmxpY0RhaWx5UmF0ZUxpbWl0KTtcclxuICAgIGlmICghbGltaXRlZC5vaykgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwicmF0ZV9saW1pdGVkXCIgfSwgNDI5LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuXHJcbiAgICAvLyBIb25leXBvdCAodXNlIFwiaHBcIiBzbyBcIndlYnNpdGVcIiBjYW4gYmUgcmVhbCB1c2VyIGRhdGEpXHJcbiAgICBjb25zdCBob25leXBvdCA9IGFzU3RyaW5nKGJvZHk/LmhwKTtcclxuICAgIGlmIChob25leXBvdCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBuYW1lID0gcmVxdWlyZWRTdHJpbmcoYm9keT8ubmFtZSk7XHJcbiAgICBpZiAoIW5hbWUpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm1pc3NpbmdfbmFtZVwiIH0sIDQwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3QgZW1haWwgPSBvcHRpb25hbFN0cmluZyhib2R5Py5lbWFpbCk7XHJcbiAgICBjb25zdCBwaG9uZSA9IG9wdGlvbmFsU3RyaW5nKGJvZHk/LnBob25lKTtcclxuY29uc3QgbWVzc2FnZSA9IG9wdGlvbmFsU3RyaW5nKGJvZHk/Lm1lc3NhZ2UpID8/IG9wdGlvbmFsU3RyaW5nKGJvZHk/Lm5vdGVzKTtcclxuXHJcblxyXG4gICAgY29uc3QgZXhpc3RpbmdJZCA9IGF3YWl0IGZpbmRFeGlzdGluZ0xlYWRJZEJ5TWVzc2FnZShzdG9yZSwgbWVzc2FnZSk7XHJcbmlmIChleGlzdGluZ0lkKSB7XHJcbiAgYXdhaXQgc2FmZUFwcGVuZExlYWRFdmVudChzdG9yZSwgZXhpc3RpbmdJZCwgeyB0eXBlOiBcImR1cGxpY2F0ZV9zdWJtaXRfaW5xdWlyeVwiIH0pO1xyXG4gIHJldHVybiByZXNwb25kSnNvbih7IG9rOiB0cnVlLCBsZWFkSWQ6IGV4aXN0aW5nSWQsIGRlZHVwZWQ6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxufVxyXG5cclxuY29uc3QgbGVhZElkID0gY3J5cHRvLnJhbmRvbVVVSUQoKTtcclxuXHJcbmNvbnN0IHJlc2VydmVkID0gYXdhaXQgcmVzZXJ2ZU1lc3NhZ2VJbmRleChzdG9yZSwgeyBpZDogbGVhZElkLCBtZXNzYWdlIH0pO1xyXG5pZiAoIXJlc2VydmVkLm9rKSB7XHJcbiAgYXdhaXQgc2FmZUFwcGVuZExlYWRFdmVudChzdG9yZSwgcmVzZXJ2ZWQuZXhpc3RpbmdJZCwgeyB0eXBlOiBcImR1cGxpY2F0ZV9zdWJtaXRfaW5xdWlyeVwiIH0pO1xyXG4gIHJldHVybiByZXNwb25kSnNvbih7IG9rOiB0cnVlLCBsZWFkSWQ6IHJlc2VydmVkLmV4aXN0aW5nSWQsIGRlZHVwZWQ6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxufVxyXG5cclxuXHJcbiAgICBjb25zdCBub3cgPSBub3dJc28oKTtcclxuICAgIGNvbnN0IGxlYWQ6IExlYWQgPSB7XHJcbiAgICAgIGlkOiBsZWFkSWQsXHJcbiAgICAgIGNyZWF0ZWRBdDogbm93LFxyXG4gICAgICB1cGRhdGVkQXQ6IG5vdyxcclxuICAgICAgdXBkYXRlZEJ5OiBcInB1YmxpY1wiLFxyXG4gICAgICBzb3VyY2U6IFwicHVibGljXCIsXHJcbiAgICAgIHN0YXR1czogXCJob3RcIixcclxuICAgICAgbmFtZSxcclxuICAgICAgcGhvbmUsXHJcbiAgICAgIGVtYWlsLFxyXG4gICAgICBzZXJ2aWNlOiBvcHRpb25hbFN0cmluZyhib2R5Py5zZXJ2aWNlKSxcclxuICAgICAgbm90ZXM6IG9wdGlvbmFsU3RyaW5nKGJvZHk/Lm5vdGVzKSxcclxuICAgICAgcHJlZmVycmVkRGF0ZTogb3B0aW9uYWxTdHJpbmcoYm9keT8ucHJlZmVycmVkRGF0ZSksXHJcbiAgICAgIHByZWZlcnJlZFRpbWU6IG9wdGlvbmFsU3RyaW5nKGJvZHk/LnByZWZlcnJlZFRpbWUpLFxyXG4gICAgICB0aW1lbGluZTogW3sgYXQ6IG5vdywgdHlwZTogXCJob3RfY3JlYXRlZFwiIH1dLFxyXG4gICAgfTtcclxuXHJcbiAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgc3RvcmUuc2V0SlNPTihgbGVhZHMvJHtsZWFkLmlkfWAsIGxlYWQsIHsgb25seUlmTmV3OiB0cnVlIH0pO1xyXG4gICAgaWYgKCFjcmVhdGVkLm1vZGlmaWVkKSB7XHJcbiAgYXdhaXQgcmVsZWFzZVJlc2VydmVkTWVzc2FnZUluZGV4KHN0b3JlLCB7IGlkOiBsZWFkSWQsIG1lc3NhZ2UgfSk7XHJcbiAgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiY3JlYXRlX2ZhaWxlZFwiIH0sIDUwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbn1cclxuXHJcbiAgICBhd2FpdCBzdG9yZS5zZXRKU09OKFxyXG4gICAgICBgaW5kZXhlcy9sZWFkcy8ke2xlYWQuY3JlYXRlZEF0fV8ke2xlYWQuaWR9YCxcclxuICAgICAgeyBpZDogbGVhZC5pZCwgY3JlYXRlZEF0OiBsZWFkLmNyZWF0ZWRBdCB9LFxyXG4gICAgICB7IG9ubHlJZk5ldzogdHJ1ZSB9LFxyXG4gICAgKTtcclxuXHJcbiAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSwgbGVhZElkOiBsZWFkLmlkIH0sIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgfVxyXG5cclxuICAvLyBFeGlzdGluZyBpbnF1aXJpZXMgZW5kcG9pbnQgKHVwZGF0ZWQgaG9uZXlwb3QgZnJvbSBcIndlYnNpdGVcIiAtPiBcImhwXCIpIHdpdGggc2VydmVyLXNpZGUgZGVkdXBlXHJcbiAgaWYgKHBhdGggPT09IFwiL2FwaS9wdWJsaWMvaW5xdWlyaWVzXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcclxuICAgIGNvbnN0IGlwID0gY2xpZW50SXAoYXJncyk7XHJcbiAgICBjb25zdCBsaW1pdGVkID0gYXdhaXQgcmF0ZUxpbWl0KHN0b3JlLCBpcCwgZW52LnB1YmxpY0RhaWx5UmF0ZUxpbWl0KTtcclxuICAgIGlmICghbGltaXRlZC5vaykgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwicmF0ZV9saW1pdGVkXCIgfSwgNDI5LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuICAgIGNvbnN0IGhvbmV5cG90ID0gYXNTdHJpbmcoYm9keT8uaHApO1xyXG4gICAgaWYgKGhvbmV5cG90KSByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IG5hbWUgPSByZXF1aXJlZFN0cmluZyhib2R5Py5uYW1lKTtcclxuICAgIGlmICghbmFtZSkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibWlzc2luZ19uYW1lXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBlbWFpbCA9IG9wdGlvbmFsU3RyaW5nKGJvZHk/LmVtYWlsKTtcclxuICAgIGNvbnN0IHBob25lID0gb3B0aW9uYWxTdHJpbmcoYm9keT8ucGhvbmUpO1xyXG5cclxuY29uc3QgbWVzc2FnZSA9IG9wdGlvbmFsU3RyaW5nKGJvZHk/Lm1lc3NhZ2UpID8/IG9wdGlvbmFsU3RyaW5nKGJvZHk/Lm5vdGVzKTtcclxuXHJcblxyXG4gICAgY29uc3QgZXhpc3RpbmdJZCA9IGF3YWl0IGZpbmRFeGlzdGluZ0xlYWRJZEJ5TWVzc2FnZShzdG9yZSwgbWVzc2FnZSk7XHJcbmlmIChleGlzdGluZ0lkKSB7XHJcbiAgYXdhaXQgc2FmZUFwcGVuZExlYWRFdmVudChzdG9yZSwgZXhpc3RpbmdJZCwgeyB0eXBlOiBcImR1cGxpY2F0ZV9zdWJtaXRfaW5xdWlyeVwiIH0pO1xyXG4gIHJldHVybiByZXNwb25kSnNvbih7IG9rOiB0cnVlLCBsZWFkSWQ6IGV4aXN0aW5nSWQsIGRlZHVwZWQ6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxufVxyXG5cclxuY29uc3QgbGVhZElkID0gY3J5cHRvLnJhbmRvbVVVSUQoKTtcclxuXHJcbmNvbnN0IHJlc2VydmVkID0gYXdhaXQgcmVzZXJ2ZU1lc3NhZ2VJbmRleChzdG9yZSwgeyBpZDogbGVhZElkLCBtZXNzYWdlIH0pO1xyXG5pZiAoIXJlc2VydmVkLm9rKSB7XHJcbiAgYXdhaXQgc2FmZUFwcGVuZExlYWRFdmVudChzdG9yZSwgcmVzZXJ2ZWQuZXhpc3RpbmdJZCwgeyB0eXBlOiBcImR1cGxpY2F0ZV9zdWJtaXRfaW5xdWlyeVwiIH0pO1xyXG4gIHJldHVybiByZXNwb25kSnNvbih7IG9rOiB0cnVlLCBsZWFkSWQ6IHJlc2VydmVkLmV4aXN0aW5nSWQsIGRlZHVwZWQ6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxufVxyXG5cclxuXHJcbiAgICBjb25zdCBub3cgPSBub3dJc28oKTtcclxuICAgIGNvbnN0IGxlYWQ6IExlYWQgPSB7XHJcbiAgICAgIGlkOiBsZWFkSWQsXHJcbiAgICAgIGNyZWF0ZWRBdDogbm93LFxyXG4gICAgICB1cGRhdGVkQXQ6IG5vdyxcclxuICAgICAgdXBkYXRlZEJ5OiBcInB1YmxpY1wiLFxyXG4gICAgICBzb3VyY2U6IFwicHVibGljXCIsXHJcbiAgICAgIHN0YXR1czogXCJuZXdcIixcclxuICAgICAgbmFtZSxcclxuICAgICAgcGhvbmUsXHJcbiAgICAgIGVtYWlsLFxyXG4gICAgICBzZXJ2aWNlOiBvcHRpb25hbFN0cmluZyhib2R5Py5zZXJ2aWNlKSxcclxuICAgICAgbm90ZXM6IG9wdGlvbmFsU3RyaW5nKGJvZHk/Lm5vdGVzKSxcclxuICAgICAgcHJlZmVycmVkRGF0ZTogb3B0aW9uYWxTdHJpbmcoYm9keT8ucHJlZmVycmVkRGF0ZSksXHJcbiAgICAgIHByZWZlcnJlZFRpbWU6IG9wdGlvbmFsU3RyaW5nKGJvZHk/LnByZWZlcnJlZFRpbWUpLFxyXG4gICAgICB0aW1lbGluZTogW3sgYXQ6IG5vdywgdHlwZTogXCJjcmVhdGVkXCIgfV0sXHJcbiAgICB9O1xyXG5cclxuICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBzdG9yZS5zZXRKU09OKGBsZWFkcy8ke2xlYWQuaWR9YCwgbGVhZCwgeyBvbmx5SWZOZXc6IHRydWUgfSk7XHJcbiAgICBpZiAoIWNyZWF0ZWQubW9kaWZpZWQpIHtcclxuICBhd2FpdCByZWxlYXNlUmVzZXJ2ZWRNZXNzYWdlSW5kZXgoc3RvcmUsIHsgaWQ6IGxlYWRJZCwgbWVzc2FnZSB9KTtcclxuICByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJjcmVhdGVfZmFpbGVkXCIgfSwgNTAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxufVxyXG5cclxuICAgIGF3YWl0IHN0b3JlLnNldEpTT04oXHJcbiAgICAgIGBpbmRleGVzL2xlYWRzLyR7bGVhZC5jcmVhdGVkQXR9XyR7bGVhZC5pZH1gLFxyXG4gICAgICB7IGlkOiBsZWFkLmlkLCBjcmVhdGVkQXQ6IGxlYWQuY3JlYXRlZEF0IH0sXHJcbiAgICAgIHsgb25seUlmTmV3OiB0cnVlIH0sXHJcbiAgICApO1xyXG5cclxuICAgIHJldHVybiByZXNwb25kSnNvbih7IG9rOiB0cnVlLCBsZWFkSWQ6IGxlYWQuaWQgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICB9XHJcblxyXG4gIGlmIChwYXRoID09PSBcIi9hcGkvcHVibGljL2F2YWlsYWJpbGl0eVwiICYmIHJlcS5tZXRob2QgPT09IFwiR0VUXCIpIHtcclxuICAgIGNvbnN0IGRhdGUgPSB1cmwuc2VhcmNoUGFyYW1zLmdldChcImRhdGVcIikgPz8gXCJcIjtcclxuICAgIGlmICghaXNEYXRlWW1kKGRhdGUpKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJpbnZhbGlkX2RhdGVcIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IHNlcnZpY2UgPSB1cmwuc2VhcmNoUGFyYW1zLmdldChcInNlcnZpY2VcIikgPz8gXCJkZWZhdWx0XCI7XHJcbiAgICBjb25zdCBzbG90cyA9IGF3YWl0IGNvbXB1dGVBdmFpbGFiaWxpdHkoc3RvcmUsIGVudiwgZGF0ZSwgc2VydmljZSk7XHJcblxyXG4gICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgZGF0ZSwgc2VydmljZSwgc2xvdHMgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICB9XHJcblxyXG4gIGlmIChwYXRoID09PSBcIi9hcGkvcHVibGljL2Jvb2tpbmdzXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcclxuICAgIGNvbnN0IGlwID0gY2xpZW50SXAoYXJncyk7XHJcbiAgICBjb25zdCBsaW1pdGVkID0gYXdhaXQgcmF0ZUxpbWl0KHN0b3JlLCBpcCwgZW52LnB1YmxpY0RhaWx5UmF0ZUxpbWl0KTtcclxuICAgIGlmICghbGltaXRlZC5vaykgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwicmF0ZV9saW1pdGVkXCIgfSwgNDI5LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuICAgIGNvbnN0IGhvbmV5cG90ID0gYXNTdHJpbmcoYm9keT8uaHApO1xyXG4gICAgaWYgKGhvbmV5cG90KSByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IG5hbWUgPSByZXF1aXJlZFN0cmluZyhib2R5Py5uYW1lKTtcclxuICAgIGNvbnN0IHNlcnZpY2UgPSByZXF1aXJlZFN0cmluZyhib2R5Py5zZXJ2aWNlKSA/PyBcImRlZmF1bHRcIjtcclxuICAgIGNvbnN0IGRhdGUgPSByZXF1aXJlZFN0cmluZyhib2R5Py5kYXRlKTtcclxuICAgIGNvbnN0IHRpbWUgPSByZXF1aXJlZFN0cmluZyhib2R5Py50aW1lKTtcclxuXHJcbiAgICBpZiAoIW5hbWUpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm1pc3NpbmdfbmFtZVwiIH0sIDQwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICBpZiAoIWlzRGF0ZVltZChkYXRlKSkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiaW52YWxpZF9kYXRlXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgIGlmICghaXNUaW1lSG0odGltZSkpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcImludmFsaWRfdGltZVwiIH0sIDQwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3Qgc3RhcnRBdCA9IHRvSXNvRnJvbUxvY2FsKGRhdGUsIHRpbWUpO1xyXG4gICAgY29uc3QgZW5kQXQgPSBuZXcgRGF0ZShuZXcgRGF0ZShzdGFydEF0KS5nZXRUaW1lKCkgKyBlbnYuc2xvdE1pbnV0ZXMgKiA2MF8wMDApLnRvSVNPU3RyaW5nKCk7XHJcblxyXG4gICAgY29uc3QgYXBwb2ludG1lbnRJZCA9IGNyeXB0by5yYW5kb21VVUlEKCk7XHJcbiAgICBjb25zdCBzbG90S2V5ID0gc2xvdExvY2tLZXkoZGF0ZSwgdGltZSwgc2VydmljZSk7XHJcblxyXG4gICAgY29uc3QgcmVzZXJ2ZWQgPSBhd2FpdCByZXNlcnZlU2xvdChzdG9yZSwgc2xvdEtleSwgYXBwb2ludG1lbnRJZCwgZW52LmNhcGFjaXR5UGVyU2xvdCk7XHJcbiAgICBpZiAoIXJlc2VydmVkLm9rKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJzbG90X3VuYXZhaWxhYmxlXCIgfSwgNDA5LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBhcHB0OiBBcHBvaW50bWVudCA9IHtcclxuICAgICAgaWQ6IGFwcG9pbnRtZW50SWQsXHJcbiAgICAgIGNyZWF0ZWRBdDogbm93SXNvKCksXHJcbiAgICAgIHVwZGF0ZWRBdDogbm93SXNvKCksXHJcbiAgICAgIHN0YXR1czogXCJib29rZWRcIixcclxuICAgICAgc2VydmljZSxcclxuICAgICAgc3RhcnRBdCxcclxuICAgICAgZW5kQXQsXHJcbiAgICAgIGN1c3RvbWVyOiB7XHJcbiAgICAgICAgbmFtZSxcclxuICAgICAgICBwaG9uZTogb3B0aW9uYWxTdHJpbmcoYm9keT8ucGhvbmUpLFxyXG4gICAgICAgIGVtYWlsOiBvcHRpb25hbFN0cmluZyhib2R5Py5lbWFpbCksXHJcbiAgICAgIH0sXHJcbiAgICAgIG5vdGVzOiBvcHRpb25hbFN0cmluZyhib2R5Py5ub3RlcyksXHJcbiAgICAgIGxlYWRJZDogb3B0aW9uYWxTdHJpbmcoYm9keT8ubGVhZElkKSxcclxuICAgIH07XHJcblxyXG4gICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IHN0b3JlLnNldEpTT04oYGFwcG9pbnRtZW50cy8ke2FwcHQuaWR9YCwgYXBwdCwgeyBvbmx5SWZOZXc6IHRydWUgfSk7XHJcbiAgICBpZiAoIWNyZWF0ZWQubW9kaWZpZWQpIHtcclxuICAgICAgYXdhaXQgcmVsZWFzZVNsb3Qoc3RvcmUsIHNsb3RLZXksIGFwcG9pbnRtZW50SWQpO1xyXG4gICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJib29raW5nX2ZhaWxlZFwiIH0sIDUwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKGFwcHQubGVhZElkKSB7XHJcbiAgICAgIGF3YWl0IHBhdGNoTGVhZChzdG9yZSwgYXBwdC5sZWFkSWQsIChsZWFkKSA9PiAoe1xyXG4gICAgICAgIC4uLmxlYWQsXHJcbiAgICAgICAgc3RhdHVzOiBsZWFkLnN0YXR1cyA9PT0gXCJsYW5kZWRcIiA/IGxlYWQuc3RhdHVzIDogXCJhcHBvaW50bWVudFwiLFxyXG4gICAgICAgIHVwZGF0ZWRBdDogbm93SXNvKCksXHJcbiAgICAgICAgdXBkYXRlZEJ5OiBcInB1YmxpY1wiLFxyXG4gICAgICAgIHRpbWVsaW5lOiBbLi4ubGVhZC50aW1lbGluZSwgeyBhdDogbm93SXNvKCksIHR5cGU6IFwiYXBwb2ludG1lbnRfY3JlYXRlZFwiLCBub3RlOiBhcHB0LmlkIH1dLFxyXG4gICAgICB9KSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHJlc3BvbmRKc29uKFxyXG4gICAgICB7XHJcbiAgICAgICAgb2s6IHRydWUsXHJcbiAgICAgICAgYXBwb2ludG1lbnRJZDogYXBwdC5pZCxcclxuICAgICAgICBzdGFydEF0OiBhcHB0LnN0YXJ0QXQsXHJcbiAgICAgICAgZW5kQXQ6IGFwcHQuZW5kQXQsXHJcbiAgICAgIH0sXHJcbiAgICAgIDIwMCxcclxuICAgICAgYXJncy5jb3JzSGVhZGVycyxcclxuICAgICk7XHJcbiAgfVxyXG5cclxuICAvLyAtLS0tIERldmljZSBTbmFwc2hvdCBTeW5jIChKV1QgcmVxdWlyZWQpIC0tLS1cclxuICBpZiAocGF0aCA9PT0gXCIvYXBpL3NuYXBzaG90c1wiICYmIHJlcS5tZXRob2QgPT09IFwiR0VUXCIpIHtcclxuICAgIGlmICghZW52Lmp3dFNlY3JldCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibWlzY29uZmlndXJlZF9qd3Rfc2VjcmV0XCIgfSwgNTAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBhdXRoID0gcmVxdWlyZUF1dGgoZW52LCByZXEuaGVhZGVycy5nZXQoXCJhdXRob3JpemF0aW9uXCIpID8/IFwiXCIpO1xyXG4gICAgaWYgKCFhdXRoLm9rKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJ1bmF1dGhvcml6ZWRcIiB9LCA0MDEsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IHsgYmxvYnMgfSA9IGF3YWl0IHN0b3JlLmxpc3QoeyBwcmVmaXg6IFwic25hcHNob3RzL1wiIH0pO1xyXG4gICAgY29uc3Qga2V5cyA9IGJsb2JzLm1hcCgoYikgPT4gYi5rZXkpLnNvcnQoKS5zbGljZSgwLCA1MDApO1xyXG5cclxuICAgIGNvbnN0IHNuYXBzaG90czogRGV2aWNlU25hcHNob3RbXSA9IFtdO1xyXG4gICAgZm9yIChjb25zdCBrIG9mIGtleXMpIHtcclxuICAgICAgY29uc3QgcmF3ID0gKGF3YWl0IHN0b3JlLmdldChrLCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBhbnkgfCBudWxsO1xyXG4gICAgICBpZiAoIXJhdykgY29udGludWU7XHJcblxyXG4gICAgICBjb25zdCBkZXZpY2VJZEZyb21LZXkgPSBrLnNwbGl0KFwiL1wiKS5wb3AoKSA/PyBcIlwiO1xyXG4gICAgICBjb25zdCBzbmFwID0gYXNEZXZpY2VTbmFwc2hvdChyYXcsIGRldmljZUlkRnJvbUtleSk7XHJcbiAgICAgIGlmIChzbmFwKSBzbmFwc2hvdHMucHVzaChzbmFwKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSwgc25hcHNob3RzIH0gYXMgYW55LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gIH1cclxuXHJcbiAgaWYgKHBhdGguc3RhcnRzV2l0aChcIi9hcGkvc25hcHNob3RzL1wiKSkge1xyXG4gICAgaWYgKCFlbnYuand0U2VjcmV0KSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNjb25maWd1cmVkX2p3dF9zZWNyZXRcIiB9LCA1MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IGF1dGggPSByZXF1aXJlQXV0aChlbnYsIHJlcS5oZWFkZXJzLmdldChcImF1dGhvcml6YXRpb25cIikgPz8gXCJcIik7XHJcbiAgICBpZiAoIWF1dGgub2spIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcInVuYXV0aG9yaXplZFwiIH0sIDQwMSwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3QgZGV2aWNlSWQgPSBkZWNvZGVVUklDb21wb25lbnQocGF0aC5zbGljZShcIi9hcGkvc25hcHNob3RzL1wiLmxlbmd0aCkpO1xyXG4gICAgaWYgKCFkZXZpY2VJZCB8fCAhaXNTYWZlRGV2aWNlSWQoZGV2aWNlSWQpKSB7XHJcbiAgICAgIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcImludmFsaWRfZGV2aWNlSWRcIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGtleSA9IHNuYXBzaG90S2V5KGRldmljZUlkKTtcclxuXHJcbiAgICBpZiAocmVxLm1ldGhvZCA9PT0gXCJHRVRcIikge1xyXG4gICAgICBjb25zdCByYXcgPSAoYXdhaXQgc3RvcmUuZ2V0KGtleSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgYW55IHwgbnVsbDtcclxuICAgICAgaWYgKCFyYXcpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm5vdF9mb3VuZFwiIH0sIDQwNCwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgICBjb25zdCBzbmFwID0gYXNEZXZpY2VTbmFwc2hvdChyYXcsIGRldmljZUlkKTtcclxuICAgICAgaWYgKCFzbmFwKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJjb3JydXB0X3NuYXBzaG90XCIgfSwgNTAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIHJldHVybiByZXNwb25kSnNvbih7IG9rOiB0cnVlLCBzbmFwc2hvdDogc25hcCB9IGFzIGFueSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAocmVxLm1ldGhvZCA9PT0gXCJQVVRcIiB8fCByZXEubWV0aG9kID09PSBcIlBPU1RcIikge1xyXG4gICAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuICAgICAgaWYgKCFib2R5KSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNzaW5nX2pzb25cIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgICAgY29uc3Qgc25hcCA9IGFzRGV2aWNlU25hcHNob3QoYm9keSwgZGV2aWNlSWQpO1xyXG4gICAgICBpZiAoIXNuYXApIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcImludmFsaWRfc25hcHNob3RcIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgICAgY29uc3QgdG9TdG9yZTogRGV2aWNlU25hcHNob3QgPSB7XHJcbiAgICAgICAgLi4uc25hcCxcclxuICAgICAgICBkZXZpY2VJZCxcclxuICAgICAgICBhdDogbm93SXNvKCksXHJcbiAgICAgIH07XHJcblxyXG4gICAgICBhd2FpdCBzdG9yZS5zZXRKU09OKGtleSwgdG9TdG9yZSBhcyBhbnkpO1xyXG4gICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm5vdF9mb3VuZFwiIH0sIDQwNCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgfVxyXG5cclxuICAvLyAtLS0tIFN5bmMgZW5kcG9pbnRzIChKV1QgcmVxdWlyZWQpIC0tLS1cclxuXHJcbiAgLy8gU3luYyBEb3duIChuZXcgZGV2aWNlIGJvb3RzdHJhcHBpbmcpXHJcbiAgaWYgKHBhdGggPT09IFwiL2FwaS9zeW5jXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJHRVRcIikge1xyXG4gICAgaWYgKCFlbnYuand0U2VjcmV0KSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNjb25maWd1cmVkX2p3dF9zZWNyZXRcIiB9LCA1MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IGF1dGggPSByZXF1aXJlQXV0aChlbnYsIHJlcS5oZWFkZXJzLmdldChcImF1dGhvcml6YXRpb25cIikgPz8gXCJcIik7XHJcbiAgICBpZiAoIWF1dGgub2spIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcInVuYXV0aG9yaXplZFwiIH0sIDQwMSwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3Qgd29ya3NwYWNlSWQgPSBzYWZlVGV4dCh1cmwuc2VhcmNoUGFyYW1zLmdldChcIndvcmtzcGFjZUlkXCIpKSB8fCBcImRlZmF1bHRcIjtcclxuXHJcbiAgICBjb25zdCBtZXRhID0gYXdhaXQgZ2V0U3luY01ldGEoc3RvcmUsIHdvcmtzcGFjZUlkKTtcclxuICAgIGNvbnN0IHNuYXBzaG90ID0gYXdhaXQgZXhwb3J0U25hcHNob3Qoc3RvcmUpO1xyXG5cclxuICAgIHJldHVybiByZXNwb25kSnNvbihcclxuICAgICAge1xyXG4gICAgICAgIG9rOiB0cnVlLFxyXG4gICAgICAgIHdvcmtzcGFjZUlkLFxyXG4gICAgICAgIG1ldGEsXHJcbiAgICAgICAgc25hcHNob3QsXHJcbiAgICAgIH0gYXMgYW55LFxyXG4gICAgICAyMDAsXHJcbiAgICAgIGFyZ3MuY29yc0hlYWRlcnMsXHJcbiAgICApO1xyXG4gIH1cclxuXHJcbiAgLy8gU3luYyBVcCAobWVyZ2UgY2xpZW50IGNoYW5nZXMpIFx1MjAxNCBmdWxsIHNuYXBzaG90IHJlcXVpcmVkIChzaW5nbGUgc291cmNlIG9mIHRydXRoKVxyXG4gIGlmIChwYXRoID09PSBcIi9hcGkvc3luY1wiICYmIHJlcS5tZXRob2QgPT09IFwiUE9TVFwiKSB7XHJcbiAgICBpZiAoIWVudi5qd3RTZWNyZXQpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm1pc2NvbmZpZ3VyZWRfand0X3NlY3JldFwiIH0sIDUwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3QgYXV0aCA9IHJlcXVpcmVBdXRoKGVudiwgcmVxLmhlYWRlcnMuZ2V0KFwiYXV0aG9yaXphdGlvblwiKSA/PyBcIlwiKTtcclxuICAgIGlmICghYXV0aC5vaykgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwidW5hdXRob3JpemVkXCIgfSwgNDAxLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuICAgIGNvbnN0IHdvcmtzcGFjZUlkID0gc2FmZVRleHQoYm9keT8ud29ya3NwYWNlSWQpIHx8IHNhZmVUZXh0KHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwid29ya3NwYWNlSWRcIikpIHx8IFwiZGVmYXVsdFwiO1xyXG5cclxuICAgIGNvbnN0IGluY29taW5nID0gYm9keT8uc25hcHNob3QgYXNcclxuICAgICAgfCB7IGxlYWRzPzogTGVhZFtdOyBhcHBvaW50bWVudHM/OiBBcHBvaW50bWVudFtdOyBzbG90cz86IFJlY29yZDxzdHJpbmcsIFNsb3RMb2NrPjsgdG9kb3M/OiBUb2RvW10gfVxyXG4gICAgICB8IHVuZGVmaW5lZDtcclxuICAgIGlmICghaW5jb21pbmcpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm1pc3Npbmdfc25hcHNob3RcIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGlmICghaXNGdWxsU25hcHNob3RTaGFwZShpbmNvbWluZykpIHtcclxuICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiZnVsbF9zbmFwc2hvdF9yZXF1aXJlZFwiIH0sIDQwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3Qgc2VydmVyID0gYXdhaXQgZXhwb3J0U25hcHNob3Qoc3RvcmUpO1xyXG5cclxuICAgIGNvbnN0IG1lcmdlZCA9IGF3YWl0IG1lcmdlU25hcHNob3RzKHN0b3JlLCB7XHJcbiAgICAgIHNlcnZlcixcclxuICAgICAgaW5jb21pbmcsXHJcbiAgICAgIGFjdG9yOiBhdXRoLnBheWxvYWQuc3ViLFxyXG4gICAgfSk7XHJcblxyXG4gICAgYXdhaXQgcGVyc2lzdE1lcmdlZFNuYXBzaG90KHN0b3JlLCBtZXJnZWQpO1xyXG5cclxuICAgIGNvbnN0IG1ldGEgPSBhd2FpdCBidW1wU3luY01ldGEoc3RvcmUsIHdvcmtzcGFjZUlkKTtcclxuICAgIGNvbnN0IGxhdGVzdCA9IGF3YWl0IGV4cG9ydFNuYXBzaG90KHN0b3JlKTtcclxuXHJcbiAgICByZXR1cm4gcmVzcG9uZEpzb24oXHJcbiAgICAgIHtcclxuICAgICAgICBvazogdHJ1ZSxcclxuICAgICAgICB3b3Jrc3BhY2VJZCxcclxuICAgICAgICBtZXRhLFxyXG4gICAgICAgIHNuYXBzaG90OiBsYXRlc3QsXHJcbiAgICAgIH0gYXMgYW55LFxyXG4gICAgICAyMDAsXHJcbiAgICAgIGFyZ3MuY29yc0hlYWRlcnMsXHJcbiAgICApO1xyXG4gIH1cclxuXHJcbiAgLy8gLS0tLSBQdWxsLW9uY2UgbGVhZHMgZW5kcG9pbnQgKEpXVCByZXF1aXJlZCkgLS0tLVxyXG4gIC8vIFBPU1QgL2FwaS9sZWFkcy9wdWxsIC0+IHJldHVybnMgb25seSB1bnB1bGxlZC91bmFzc2lnbmVkLCBjb25zdW1lcyB0aGVtIGltbWVkaWF0ZWx5IChhcmNoaXZlcyArIHRvbWJzdG9uZXMpXHJcbiAgaWYgKHBhdGggPT09IFwiL2FwaS9sZWFkcy9wdWxsXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcclxuICAgIGlmICghZW52Lmp3dFNlY3JldCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibWlzY29uZmlndXJlZF9qd3Rfc2VjcmV0XCIgfSwgNTAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBhdXRoID0gcmVxdWlyZUF1dGgoZW52LCByZXEuaGVhZGVycy5nZXQoXCJhdXRob3JpemF0aW9uXCIpID8/IFwiXCIpO1xyXG4gICAgaWYgKCFhdXRoLm9rKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJ1bmF1dGhvcml6ZWRcIiB9LCA0MDEsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IGRldmljZUlkID0gcmVxdWVzdERldmljZUlkKHJlcSk7XHJcbiAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuICAgIGNvbnN0IGxpbWl0ID0gY2xhbXBJbnQoYXNTdHJpbmcoYm9keT8ubGltaXQpID8/IHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwibGltaXRcIiksIDEsIDIwMCwgNTApO1xyXG4gICAgY29uc3Qgc3RhdHVzID0gKGFzU3RyaW5nKGJvZHk/LnN0YXR1cykgPz8gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJzdGF0dXNcIikgPz8gXCJob3RcIikgYXMgTGVhZFN0YXR1cztcclxuXHJcbiAgICBjb25zdCBwdWxsZWQgPSBhd2FpdCBwdWxsT25jZUNvbnN1bWVMZWFkcyhzdG9yZSwge1xyXG4gICAgICBsaW1pdCxcclxuICAgICAgc3RhdHVzLFxyXG4gICAgICBhc3NpZ25lZFRvOiBhdXRoLnBheWxvYWQuc3ViLFxyXG4gICAgICBkZXZpY2VJZCxcclxuICAgIH0pO1xyXG5cclxuICAgIHJldHVybiByZXNwb25kSnNvbih7IG9rOiB0cnVlLCBwdWxsZWQ6IHB1bGxlZC5sZW5ndGgsIGxlYWRzOiBwdWxsZWQgfSBhcyBhbnksIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgfVxyXG5cclxuICAvLyAtLS0tIENSTSBlbmRwb2ludHMgKEpXVCByZXF1aXJlZCkgLS0tLVxyXG4gIGlmIChwYXRoLnN0YXJ0c1dpdGgoXCIvYXBpL2NybS9cIikpIHtcclxuICAgIGlmICghZW52Lmp3dFNlY3JldCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibWlzY29uZmlndXJlZF9qd3Rfc2VjcmV0XCIgfSwgNTAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBhdXRoID0gcmVxdWlyZUF1dGgoZW52LCByZXEuaGVhZGVycy5nZXQoXCJhdXRob3JpemF0aW9uXCIpID8/IFwiXCIpO1xyXG4gICAgaWYgKCFhdXRoLm9rKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJ1bmF1dGhvcml6ZWRcIiB9LCA0MDEsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IGRldmljZUlkID0gcmVxdWVzdERldmljZUlkKHJlcSk7XHJcblxyXG4gICAgaWYgKHBhdGggPT09IFwiL2FwaS9jcm0vbGVhZHNcIiAmJiByZXEubWV0aG9kID09PSBcIkdFVFwiKSB7XHJcbiAgICAgIGNvbnN0IHN0YXR1cyA9IHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwic3RhdHVzXCIpO1xyXG4gICAgICBjb25zdCBxID0gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJxXCIpO1xyXG4gICAgICBjb25zdCBsaW1pdCA9IGNsYW1wSW50KHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwibGltaXRcIiksIDEsIDIwMCwgNTApO1xyXG5cclxuICAgICAgY29uc3QgbGVhZHMgPSBhd2FpdCBsaXN0TGVhZHMoc3RvcmUsIHsgc3RhdHVzOiBzdGF0dXMgPz8gdW5kZWZpbmVkLCBxOiBxID8/IHVuZGVmaW5lZCwgbGltaXQgfSk7XHJcbiAgICAgIHJldHVybiByZXNwb25kSnNvbih7IGxlYWRzIH0gYXMgYW55LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChwYXRoLnN0YXJ0c1dpdGgoXCIvYXBpL2NybS9sZWFkcy9cIikpIHtcclxuICAgICAgY29uc3QgaWQgPSBwYXRoLnNwbGl0KFwiL1wiKS5wb3AoKSA/PyBcIlwiO1xyXG4gICAgICBpZiAoIWlkKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNzaW5nX2lkXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIGlmIChyZXEubWV0aG9kID09PSBcIkdFVFwiKSB7XHJcbiAgICAgICAgY29uc3QgbGVhZCA9IChhd2FpdCBzdG9yZS5nZXQoYGxlYWRzLyR7aWR9YCwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgTGVhZCB8IG51bGw7XHJcbiAgICAgICAgaWYgKCFsZWFkKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJub3RfZm91bmRcIiB9LCA0MDQsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgICAgIHJldHVybiByZXNwb25kSnNvbih7IGxlYWQgfSBhcyBhbnksIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmIChyZXEubWV0aG9kID09PSBcIlBVVFwiKSB7XHJcbiAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHNhZmVKc29uKHJlcSk7XHJcbiAgICAgICAgY29uc3Qgc3RhdHVzID0gb3B0aW9uYWxTdHJpbmcoYm9keT8uc3RhdHVzKSBhcyBMZWFkU3RhdHVzIHwgdW5kZWZpbmVkO1xyXG4gICAgICAgIGNvbnN0IG5vdGVzID0gb3B0aW9uYWxTdHJpbmcoYm9keT8ubm90ZXMpO1xyXG4gICAgICAgIGNvbnN0IGZvbGxvd1VwQXQgPSBvcHRpb25hbFN0cmluZyhib2R5Py5mb2xsb3dVcEF0KTtcclxuICAgICAgICBjb25zdCBhc3NpZ25lZFRvID0gb3B0aW9uYWxTdHJpbmcoYm9keT8uYXNzaWduZWRUbyk7XHJcblxyXG4gICAgICAgIGNvbnN0IHVwZGF0ZWQgPSBhd2FpdCBwYXRjaExlYWQoc3RvcmUsIGlkLCAobGVhZCkgPT4ge1xyXG4gICAgICAgICAgaWYgKGF1dGgucGF5bG9hZC5yb2xlICE9PSBcImFkbWluXCIgJiYgdHlwZW9mIGFzc2lnbmVkVG8gPT09IFwic3RyaW5nXCIgJiYgYXNzaWduZWRUbyAhPT0gbGVhZC5hc3NpZ25lZFRvKSB7XHJcbiAgICAgICAgICAgIHRocm93IG5ldyBGb3JiaWRkZW5FcnJvcihcInJlYXNzaWduX2ZvcmJpZGRlblwiKTtcclxuICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAuLi5sZWFkLFxyXG4gICAgICAgICAgICB1cGRhdGVkQXQ6IG5vd0lzbygpLFxyXG4gICAgICAgICAgICB1cGRhdGVkQnk6IGF1dGgucGF5bG9hZC5zdWIsXHJcbiAgICAgICAgICAgIHVwZGF0ZWREZXZpY2VJZDogZGV2aWNlSWQgPz8gbGVhZC51cGRhdGVkRGV2aWNlSWQsXHJcbiAgICAgICAgICAgIHN0YXR1czogc3RhdHVzID8/IGxlYWQuc3RhdHVzLFxyXG4gICAgICAgICAgICBub3Rlczogbm90ZXMgPz8gbGVhZC5ub3RlcyxcclxuICAgICAgICAgICAgZm9sbG93VXBBdDogZm9sbG93VXBBdCA/PyBsZWFkLmZvbGxvd1VwQXQsXHJcbiAgICAgICAgICAgIGFzc2lnbmVkVG86IGF1dGgucGF5bG9hZC5yb2xlID09PSBcImFkbWluXCIgPyBhc3NpZ25lZFRvID8/IGxlYWQuYXNzaWduZWRUbyA6IGxlYWQuYXNzaWduZWRUbyxcclxuICAgICAgICAgICAgdGltZWxpbmU6IFsuLi5sZWFkLnRpbWVsaW5lLCB7IGF0OiBub3dJc28oKSwgdHlwZTogXCJ1cGRhdGVkXCIgfV0sXHJcbiAgICAgICAgICB9O1xyXG4gICAgICAgIH0pO1xyXG5cclxuICAgICAgICBpZiAoIXVwZGF0ZWQpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm5vdF9mb3VuZFwiIH0sIDQwNCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmIChwYXRoID09PSBcIi9hcGkvY3JtL2FwcG9pbnRtZW50c1wiICYmIHJlcS5tZXRob2QgPT09IFwiR0VUXCIpIHtcclxuICAgICAgY29uc3QgZnJvbSA9IHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwiZnJvbVwiKTtcclxuICAgICAgY29uc3QgdG8gPSB1cmwuc2VhcmNoUGFyYW1zLmdldChcInRvXCIpO1xyXG4gICAgICBjb25zdCBsaW1pdCA9IGNsYW1wSW50KHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwibGltaXRcIiksIDEsIDUwMCwgMjAwKTtcclxuXHJcbiAgICAgIGNvbnN0IGFwcHRzID0gYXdhaXQgbGlzdEFwcG9pbnRtZW50cyhzdG9yZSwgeyBmcm9tOiBmcm9tID8/IHVuZGVmaW5lZCwgdG86IHRvID8/IHVuZGVmaW5lZCwgbGltaXQgfSk7XHJcbiAgICAgIHJldHVybiByZXNwb25kSnNvbih7IGFwcG9pbnRtZW50czogYXBwdHMgfSBhcyBhbnksIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHBhdGggPT09IFwiL2FwaS9jcm0vYXBwb2ludG1lbnRzXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcclxuICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHNhZmVKc29uKHJlcSk7XHJcbiAgICAgIGNvbnN0IHNlcnZpY2UgPSByZXF1aXJlZFN0cmluZyhib2R5Py5zZXJ2aWNlKSA/PyBcImRlZmF1bHRcIjtcclxuICAgICAgY29uc3QgZGF0ZSA9IHJlcXVpcmVkU3RyaW5nKGJvZHk/LmRhdGUpO1xyXG4gICAgICBjb25zdCB0aW1lID0gcmVxdWlyZWRTdHJpbmcoYm9keT8udGltZSk7XHJcbiAgICAgIGNvbnN0IG5hbWUgPSByZXF1aXJlZFN0cmluZyhib2R5Py5uYW1lKTtcclxuICAgICAgaWYgKCFzZXJ2aWNlIHx8ICFpc0RhdGVZbWQoZGF0ZSkgfHwgIWlzVGltZUhtKHRpbWUpIHx8ICFuYW1lKSB7XHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiaW52YWxpZF9pbnB1dFwiIH0sIDQwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGNvbnN0IHN0YXJ0QXQgPSB0b0lzb0Zyb21Mb2NhbChkYXRlLCB0aW1lKTtcclxuICAgICAgY29uc3QgZW5kQXQgPSBuZXcgRGF0ZShuZXcgRGF0ZShzdGFydEF0KS5nZXRUaW1lKCkgKyBlbnYuc2xvdE1pbnV0ZXMgKiA2MF8wMDApLnRvSVNPU3RyaW5nKCk7XHJcblxyXG4gICAgICBjb25zdCBhcHBvaW50bWVudElkID0gY3J5cHRvLnJhbmRvbVVVSUQoKTtcclxuICAgICAgY29uc3Qgc2xvdEtleSA9IHNsb3RMb2NrS2V5KGRhdGUsIHRpbWUsIHNlcnZpY2UpO1xyXG5cclxuICAgICAgY29uc3QgcmVzZXJ2ZWQgPSBhd2FpdCByZXNlcnZlU2xvdChzdG9yZSwgc2xvdEtleSwgYXBwb2ludG1lbnRJZCwgZW52LmNhcGFjaXR5UGVyU2xvdCk7XHJcbiAgICAgIGlmICghcmVzZXJ2ZWQub2spIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcInNsb3RfdW5hdmFpbGFibGVcIiB9LCA0MDksIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgICAgY29uc3QgYXBwdDogQXBwb2ludG1lbnQgPSB7XHJcbiAgICAgICAgaWQ6IGFwcG9pbnRtZW50SWQsXHJcbiAgICAgICAgY3JlYXRlZEF0OiBub3dJc28oKSxcclxuICAgICAgICB1cGRhdGVkQXQ6IG5vd0lzbygpLFxyXG4gICAgICAgIHN0YXR1czogXCJib29rZWRcIixcclxuICAgICAgICBzZXJ2aWNlLFxyXG4gICAgICAgIHN0YXJ0QXQsXHJcbiAgICAgICAgZW5kQXQsXHJcbiAgICAgICAgY3VzdG9tZXI6IHsgbmFtZSwgcGhvbmU6IG9wdGlvbmFsU3RyaW5nKGJvZHk/LnBob25lKSwgZW1haWw6IG9wdGlvbmFsU3RyaW5nKGJvZHk/LmVtYWlsKSB9LFxyXG4gICAgICAgIG5vdGVzOiBvcHRpb25hbFN0cmluZyhib2R5Py5ub3RlcyksXHJcbiAgICAgICAgbGVhZElkOiBvcHRpb25hbFN0cmluZyhib2R5Py5sZWFkSWQpLFxyXG4gICAgICB9O1xyXG5cclxuICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IHN0b3JlLnNldEpTT04oYGFwcG9pbnRtZW50cy8ke2FwcHQuaWR9YCwgYXBwdCwgeyBvbmx5SWZOZXc6IHRydWUgfSk7XHJcbiAgICAgIGlmICghY3JlYXRlZC5tb2RpZmllZCkge1xyXG4gICAgICAgIGF3YWl0IHJlbGVhc2VTbG90KHN0b3JlLCBzbG90S2V5LCBhcHBvaW50bWVudElkKTtcclxuICAgICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJjcmVhdGVfZmFpbGVkXCIgfSwgNTAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUsIGFwcG9pbnRtZW50SWQ6IGFwcHQuaWQgfSBhcyBhbnksIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHBhdGguc3RhcnRzV2l0aChcIi9hcGkvY3JtL2FwcG9pbnRtZW50cy9cIikpIHtcclxuICAgICAgY29uc3QgaWQgPSBwYXRoLnNwbGl0KFwiL1wiKS5wb3AoKSA/PyBcIlwiO1xyXG4gICAgICBpZiAoIWlkKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNzaW5nX2lkXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIGlmIChyZXEubWV0aG9kID09PSBcIkdFVFwiKSB7XHJcbiAgICAgICAgY29uc3QgYXBwdCA9IChhd2FpdCBzdG9yZS5nZXQoYGFwcG9pbnRtZW50cy8ke2lkfWAsIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIEFwcG9pbnRtZW50IHwgbnVsbDtcclxuICAgICAgICBpZiAoIWFwcHQpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm5vdF9mb3VuZFwiIH0sIDQwNCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgYXBwb2ludG1lbnQ6IGFwcHQgfSBhcyBhbnksIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmIChyZXEubWV0aG9kID09PSBcIlBVVFwiKSB7XHJcbiAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHNhZmVKc29uKHJlcSk7XHJcbiAgICAgICAgY29uc3QgcGF0Y2ggPSB7XHJcbiAgICAgICAgICBzdGF0dXM6IG9wdGlvbmFsU3RyaW5nKGJvZHk/LnN0YXR1cykgYXMgQXBwb2ludG1lbnRTdGF0dXMgfCB1bmRlZmluZWQsXHJcbiAgICAgICAgICBub3Rlczogb3B0aW9uYWxTdHJpbmcoYm9keT8ubm90ZXMpLFxyXG4gICAgICAgIH07XHJcblxyXG4gICAgICAgIGNvbnN0IHVwZGF0ZWQgPSBhd2FpdCBwYXRjaEFwcG9pbnRtZW50KHN0b3JlLCBpZCwgKGFwcHQpID0+ICh7XHJcbiAgICAgICAgICAuLi5hcHB0LFxyXG4gICAgICAgICAgdXBkYXRlZEF0OiBub3dJc28oKSxcclxuICAgICAgICAgIHN0YXR1czogcGF0Y2guc3RhdHVzID8/IGFwcHQuc3RhdHVzLFxyXG4gICAgICAgICAgbm90ZXM6IHBhdGNoLm5vdGVzID8/IGFwcHQubm90ZXMsXHJcbiAgICAgICAgfSkpO1xyXG5cclxuICAgICAgICBpZiAoIXVwZGF0ZWQpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm5vdF9mb3VuZFwiIH0sIDQwNCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKHJlcS5tZXRob2QgPT09IFwiREVMRVRFXCIpIHtcclxuICAgICAgICBjb25zdCBhcHB0ID0gKGF3YWl0IHN0b3JlLmdldChgYXBwb2ludG1lbnRzLyR7aWR9YCwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgQXBwb2ludG1lbnQgfCBudWxsO1xyXG4gICAgICAgIGlmICghYXBwdCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIgfSwgNDA0LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgICAgY29uc3QgeyBkYXRlLCB0aW1lIH0gPSBzcGxpdElzb1RvRGF0ZVRpbWUoYXBwdC5zdGFydEF0KTtcclxuICAgICAgICBjb25zdCBzbG90S2V5ID0gc2xvdExvY2tLZXkoZGF0ZSwgdGltZSwgYXBwdC5zZXJ2aWNlKTtcclxuXHJcbiAgICAgICAgYXdhaXQgcGF0Y2hBcHBvaW50bWVudChzdG9yZSwgaWQsIChhKSA9PiAoeyAuLi5hLCB1cGRhdGVkQXQ6IG5vd0lzbygpLCBzdGF0dXM6IFwiY2FuY2VsZWRcIiB9KSk7XHJcbiAgICAgICAgYXdhaXQgcmVsZWFzZVNsb3Qoc3RvcmUsIHNsb3RLZXksIGlkKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmIChwYXRoID09PSBcIi9hcGkvY3JtL21ldHJpY3NcIiAmJiByZXEubWV0aG9kID09PSBcIkdFVFwiKSB7XHJcbiAgICAgIGNvbnN0IG1ldHJpY3MgPSBhd2FpdCBjb21wdXRlTWV0cmljcyhzdG9yZSk7XHJcbiAgICAgIHJldHVybiByZXNwb25kSnNvbih7IG1ldHJpY3MgfSBhcyBhbnksIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHBhdGggPT09IFwiL2FwaS9jcm0vZXhwb3J0XCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcclxuICAgICAgaWYgKGF1dGgucGF5bG9hZC5yb2xlICE9PSBcImFkbWluXCIpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcImZvcmJpZGRlblwiIH0sIDQwMywgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgIGNvbnN0IHNuYXBzaG90ID0gYXdhaXQgZXhwb3J0U25hcHNob3Qoc3RvcmUpO1xyXG4gICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBzbmFwc2hvdCB9IGFzIGFueSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAocGF0aCA9PT0gXCIvYXBpL2NybS9pbXBvcnRcIiAmJiByZXEubWV0aG9kID09PSBcIlBPU1RcIikge1xyXG4gICAgICBpZiAoYXV0aC5wYXlsb2FkLnJvbGUgIT09IFwiYWRtaW5cIikgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiZm9yYmlkZGVuXCIgfSwgNDAzLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBzYWZlSnNvbihyZXEpO1xyXG4gICAgICBjb25zdCBzbmFwc2hvdCA9IGJvZHk/LnNuYXBzaG90IGFzXHJcbiAgICAgICAgfCB7IGxlYWRzPzogTGVhZFtdOyBhcHBvaW50bWVudHM/OiBBcHBvaW50bWVudFtdOyBzbG90cz86IFJlY29yZDxzdHJpbmcsIFNsb3RMb2NrPjsgdG9kb3M/OiBUb2RvW10gfVxyXG4gICAgICAgIHwgdW5kZWZpbmVkO1xyXG4gICAgICBpZiAoIXNuYXBzaG90KSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNzaW5nX3NuYXBzaG90XCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIGlmICghaXNGdWxsU25hcHNob3RTaGFwZShzbmFwc2hvdCkpIHtcclxuICAgICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJmdWxsX3NuYXBzaG90X3JlcXVpcmVkXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgYXdhaXQgaW1wb3J0U25hcHNob3Qoc3RvcmUsIHNuYXBzaG90KTtcclxuICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJub3RfZm91bmRcIiB9LCA0MDQsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIgfSwgNDA0LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxufVxyXG5cclxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gQXZhaWxhYmlsaXR5IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5hc3luYyBmdW5jdGlvbiBjb21wdXRlQXZhaWxhYmlsaXR5KFxyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sXHJcbiAgZW52OiBFbnZDb25maWcsXHJcbiAgZGF0ZTogc3RyaW5nLFxyXG4gIHNlcnZpY2U6IHN0cmluZyxcclxuKTogUHJvbWlzZTxBcnJheTx7IHRpbWU6IHN0cmluZzsgYXZhaWxhYmxlOiBib29sZWFuOyByZW1haW5pbmc6IG51bWJlciB9Pj4ge1xyXG4gIGNvbnN0IHRpbWVzID0gYnVpbGRTbG90cyhlbnYsIGRhdGUpO1xyXG4gIGNvbnN0IG91dDogQXJyYXk8eyB0aW1lOiBzdHJpbmc7IGF2YWlsYWJsZTogYm9vbGVhbjsgcmVtYWluaW5nOiBudW1iZXIgfT4gPSBbXTtcclxuXHJcbiAgZm9yIChjb25zdCB0aW1lIG9mIHRpbWVzKSB7XHJcbiAgICBjb25zdCBsb2NrID0gKGF3YWl0IHN0b3JlLmdldChzbG90TG9ja0tleShkYXRlLCB0aW1lLCBzZXJ2aWNlKSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgU2xvdExvY2sgfCBudWxsO1xyXG4gICAgY29uc3QgdXNlZCA9IGxvY2s/Lmlkcz8ubGVuZ3RoID8/IDA7XHJcbiAgICBjb25zdCByZW1haW5pbmcgPSBNYXRoLm1heCgwLCBlbnYuY2FwYWNpdHlQZXJTbG90IC0gdXNlZCk7XHJcbiAgICBvdXQucHVzaCh7IHRpbWUsIGF2YWlsYWJsZTogcmVtYWluaW5nID4gMCwgcmVtYWluaW5nIH0pO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIG91dDtcclxufVxyXG5cclxuZnVuY3Rpb24gYnVpbGRTbG90cyhlbnY6IEVudkNvbmZpZywgX2RhdGU6IHN0cmluZyk6IHN0cmluZ1tdIHtcclxuICBjb25zdCBzbG90czogc3RyaW5nW10gPSBbXTtcclxuICBjb25zdCBzdGFydE1pbiA9IGVudi5vcGVuSG91ciAqIDYwO1xyXG4gIGNvbnN0IGVuZE1pbiA9IGVudi5jbG9zZUhvdXIgKiA2MDtcclxuXHJcbiAgZm9yIChsZXQgbSA9IHN0YXJ0TWluOyBtICsgZW52LnNsb3RNaW51dGVzIDw9IGVuZE1pbjsgbSArPSBlbnYuc2xvdE1pbnV0ZXMpIHtcclxuICAgIGNvbnN0IGhoID0gU3RyaW5nKE1hdGguZmxvb3IobSAvIDYwKSkucGFkU3RhcnQoMiwgXCIwXCIpO1xyXG4gICAgY29uc3QgbW0gPSBTdHJpbmcobSAlIDYwKS5wYWRTdGFydCgyLCBcIjBcIik7XHJcbiAgICBzbG90cy5wdXNoKGAke2hofToke21tfWApO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHNsb3RzO1xyXG59XHJcblxyXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gU2xvdCBMb2NrcyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cclxuXHJcbmZ1bmN0aW9uIHNsb3RMb2NrS2V5KGRhdGU6IHN0cmluZywgdGltZTogc3RyaW5nLCBzZXJ2aWNlOiBzdHJpbmcpOiBzdHJpbmcge1xyXG4gIGNvbnN0IHNhZmVTZXJ2aWNlID0gc2VydmljZS5yZXBsYWNlQWxsKFwiL1wiLCBcIl9cIikuc2xpY2UoMCwgODApO1xyXG4gIHJldHVybiBgc2xvdHMvJHtkYXRlfS8ke3RpbWV9LyR7c2FmZVNlcnZpY2V9YDtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gcmVzZXJ2ZVNsb3QoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBzbG90S2V5OiBzdHJpbmcsXHJcbiAgYXBwb2ludG1lbnRJZDogc3RyaW5nLFxyXG4gIGNhcGFjaXR5OiBudW1iZXIsXHJcbik6IFByb21pc2U8eyBvazogdHJ1ZSB9IHwgeyBvazogZmFsc2UgfT4ge1xyXG4gIGZvciAobGV0IGkgPSAwOyBpIDwgNTsgaSArPSAxKSB7XHJcbiAgICBjb25zdCBleGlzdGluZyA9IChhd2FpdCBzdG9yZS5nZXRXaXRoTWV0YWRhdGEoc2xvdEtleSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXNcclxuICAgICAgfCB7IGRhdGE6IFNsb3RMb2NrOyBldGFnOiBzdHJpbmcgfVxyXG4gICAgICB8IG51bGw7XHJcblxyXG4gICAgaWYgKCFleGlzdGluZykge1xyXG4gICAgICBjb25zdCBuZXh0OiBTbG90TG9jayA9IHsgaWRzOiBbYXBwb2ludG1lbnRJZF0gfTtcclxuICAgICAgY29uc3QgcmVzID0gYXdhaXQgc3RvcmUuc2V0SlNPTihzbG90S2V5LCBuZXh0LCB7IG9ubHlJZk5ldzogdHJ1ZSB9KTtcclxuICAgICAgaWYgKHJlcy5tb2RpZmllZCkgcmV0dXJuIHsgb2s6IHRydWUgfTtcclxuICAgICAgY29udGludWU7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgaWRzID0gQXJyYXkuaXNBcnJheShleGlzdGluZy5kYXRhPy5pZHMpID8gZXhpc3RpbmcuZGF0YS5pZHMgOiBbXTtcclxuICAgIGlmIChpZHMuaW5jbHVkZXMoYXBwb2ludG1lbnRJZCkpIHJldHVybiB7IG9rOiB0cnVlIH07XHJcbiAgICBpZiAoaWRzLmxlbmd0aCA+PSBjYXBhY2l0eSkgcmV0dXJuIHsgb2s6IGZhbHNlIH07XHJcblxyXG4gICAgY29uc3QgbmV4dDogU2xvdExvY2sgPSB7IGlkczogWy4uLmlkcywgYXBwb2ludG1lbnRJZF0gfTtcclxuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04oc2xvdEtleSwgbmV4dCwgeyBvbmx5SWZNYXRjaDogZXhpc3RpbmcuZXRhZyB9KTtcclxuICAgIGlmIChyZXMubW9kaWZpZWQpIHJldHVybiB7IG9rOiB0cnVlIH07XHJcbiAgfVxyXG5cclxuICByZXR1cm4geyBvazogZmFsc2UgfTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gcmVsZWFzZVNsb3Qoc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPiwgc2xvdEtleTogc3RyaW5nLCBhcHBvaW50bWVudElkOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcclxuICBmb3IgKGxldCBpID0gMDsgaSA8IDU7IGkgKz0gMSkge1xyXG4gICAgY29uc3QgZXhpc3RpbmcgPSAoYXdhaXQgc3RvcmUuZ2V0V2l0aE1ldGFkYXRhKHNsb3RLZXksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzXHJcbiAgICAgIHwgeyBkYXRhOiBTbG90TG9jazsgZXRhZzogc3RyaW5nIH1cclxuICAgICAgfCBudWxsO1xyXG5cclxuICAgIGlmICghZXhpc3RpbmcpIHJldHVybjtcclxuXHJcbiAgICBjb25zdCBpZHMgPSBBcnJheS5pc0FycmF5KGV4aXN0aW5nLmRhdGE/LmlkcykgPyBleGlzdGluZy5kYXRhLmlkcyA6IFtdO1xyXG4gICAgY29uc3QgbmV4dElkcyA9IGlkcy5maWx0ZXIoKHgpID0+IHggIT09IGFwcG9pbnRtZW50SWQpO1xyXG5cclxuICAgIGlmIChuZXh0SWRzLmxlbmd0aCA9PT0gaWRzLmxlbmd0aCkgcmV0dXJuO1xyXG5cclxuICAgIGlmIChuZXh0SWRzLmxlbmd0aCA9PT0gMCkge1xyXG4gICAgICBhd2FpdCBzdG9yZS5kZWxldGUoc2xvdEtleSk7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCByZXMgPSBhd2FpdCBzdG9yZS5zZXRKU09OKHNsb3RLZXksIHsgaWRzOiBuZXh0SWRzIH0sIHsgb25seUlmTWF0Y2g6IGV4aXN0aW5nLmV0YWcgfSk7XHJcbiAgICBpZiAocmVzLm1vZGlmaWVkKSByZXR1cm47XHJcbiAgfVxyXG59XHJcblxyXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIFJhdGUgTGltaXQgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5hc3luYyBmdW5jdGlvbiByYXRlTGltaXQoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBpcDogc3RyaW5nLFxyXG4gIGRhaWx5TGltaXQ6IG51bWJlcixcclxuKTogUHJvbWlzZTx7IG9rOiB0cnVlIH0gfCB7IG9rOiBmYWxzZSB9PiB7XHJcbiAgY29uc3QgZGF5ID0gbm93SXNvKCkuc2xpY2UoMCwgMTApO1xyXG5cclxuICBjb25zdCBrZXkgPSBgcmF0ZWxpbWl0X3YyLyR7ZGF5fS8ke2hhc2hTaG9ydChpcCl9YDtcclxuXHJcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCA1OyBpICs9IDEpIHtcclxuICAgIGNvbnN0IGV4aXN0aW5nID0gKGF3YWl0IHN0b3JlLmdldFdpdGhNZXRhZGF0YShrZXksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzXHJcbiAgICAgIHwgeyBkYXRhOiB7IGNvdW50OiBudW1iZXIgfTsgZXRhZzogc3RyaW5nIH1cclxuICAgICAgfCBudWxsO1xyXG5cclxuICAgIGlmICghZXhpc3RpbmcpIHtcclxuICAgICAgY29uc3QgcmVzID0gYXdhaXQgc3RvcmUuc2V0SlNPTihrZXksIHsgY291bnQ6IDEgfSwgeyBvbmx5SWZOZXc6IHRydWUgfSk7XHJcbiAgICAgIGlmIChyZXMubW9kaWZpZWQpIHJldHVybiB7IG9rOiB0cnVlIH07XHJcbiAgICAgIGNvbnRpbnVlO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGNvdW50ID0gdHlwZW9mIGV4aXN0aW5nLmRhdGE/LmNvdW50ID09PSBcIm51bWJlclwiID8gZXhpc3RpbmcuZGF0YS5jb3VudCA6IDA7XHJcbiAgICBpZiAoY291bnQgPj0gZGFpbHlMaW1pdCkgcmV0dXJuIHsgb2s6IGZhbHNlIH07XHJcblxyXG4gICAgY29uc3QgcmVzID0gYXdhaXQgc3RvcmUuc2V0SlNPTihrZXksIHsgY291bnQ6IGNvdW50ICsgMSB9LCB7IG9ubHlJZk1hdGNoOiBleGlzdGluZy5ldGFnIH0pO1xyXG4gICAgaWYgKHJlcy5tb2RpZmllZCkgcmV0dXJuIHsgb2s6IHRydWUgfTtcclxuICB9XHJcblxyXG4gIHJldHVybiB7IG9rOiBmYWxzZSB9O1xyXG59XHJcblxyXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gTGVhZHMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cclxuXHJcbmZ1bmN0aW9uIGlzRGVsZXRlZChsZWFkOiBMZWFkKTogYm9vbGVhbiB7XHJcbiAgcmV0dXJuIHR5cGVvZiBsZWFkLmRlbGV0ZWRBdCA9PT0gXCJzdHJpbmdcIiAmJiBsZWFkLmRlbGV0ZWRBdC5sZW5ndGggPiAwO1xyXG59XHJcblxyXG5mdW5jdGlvbiBub3JtYWxpemVNZXNzYWdlKG1zZz86IHN0cmluZyk6IHN0cmluZyB8IG51bGwge1xyXG4gIGNvbnN0IG0gPSAobXNnID8/IFwiXCIpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xyXG4gIGNvbnN0IGNvbXBhY3QgPSBtLnJlcGxhY2UoL1xccysvZywgXCIgXCIpO1xyXG4gIHJldHVybiBjb21wYWN0Lmxlbmd0aCA/IGNvbXBhY3QgOiBudWxsO1xyXG59XHJcblxyXG5mdW5jdGlvbiBsZWFkQnlNZXNzYWdlS2V5KG1lc3NhZ2U6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgcmV0dXJuIGBpbmRleGVzL2xlYWRCeU1lc3NhZ2UvJHtzaGEyNTZIZXgobWVzc2FnZSl9YDtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZmluZEV4aXN0aW5nTGVhZElkQnlNZXNzYWdlKFxyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sXHJcbiAgbWVzc2FnZT86IHN0cmluZyxcclxuKTogUHJvbWlzZTxzdHJpbmcgfCBudWxsPiB7XHJcbiAgY29uc3QgbSA9IG5vcm1hbGl6ZU1lc3NhZ2UobWVzc2FnZSk7XHJcbiAgaWYgKCFtKSByZXR1cm4gbnVsbDtcclxuICBjb25zdCBpZHggPSAoYXdhaXQgc3RvcmUuZ2V0KGxlYWRCeU1lc3NhZ2VLZXkobSksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIHsgaWQ/OiBzdHJpbmcgfSB8IG51bGw7XHJcbiAgY29uc3QgaWQgPSBzYWZlVGV4dChpZHg/LmlkKTtcclxuICByZXR1cm4gaWQgfHwgbnVsbDtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gcmVzZXJ2ZU1lc3NhZ2VJbmRleChcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIG9wdHM6IHsgaWQ6IHN0cmluZzsgbWVzc2FnZT86IHN0cmluZyB9LFxyXG4pOiBQcm9taXNlPHsgb2s6IHRydWUgfSB8IHsgb2s6IGZhbHNlOyBleGlzdGluZ0lkOiBzdHJpbmcgfT4ge1xyXG4gIGNvbnN0IG0gPSBub3JtYWxpemVNZXNzYWdlKG9wdHMubWVzc2FnZSk7XHJcbiAgaWYgKCFtKSByZXR1cm4geyBvazogdHJ1ZSB9OyAvLyBubyBtZXNzYWdlID0+IG5vIGRlZHVwZVxyXG5cclxuICBjb25zdCBrZXkgPSBsZWFkQnlNZXNzYWdlS2V5KG0pO1xyXG4gIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04oa2V5LCB7IGlkOiBvcHRzLmlkIH0sIHsgb25seUlmTmV3OiB0cnVlIH0pO1xyXG5cclxuICBpZiAocmVzLm1vZGlmaWVkKSByZXR1cm4geyBvazogdHJ1ZSB9O1xyXG5cclxuICBjb25zdCBpZHggPSAoYXdhaXQgc3RvcmUuZ2V0KGtleSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgeyBpZD86IHN0cmluZyB9IHwgbnVsbDtcclxuICBjb25zdCBleGlzdGluZ0lkID0gc2FmZVRleHQoaWR4Py5pZCkgfHwgb3B0cy5pZDtcclxuICByZXR1cm4geyBvazogZmFsc2UsIGV4aXN0aW5nSWQgfTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gcmVsZWFzZVJlc2VydmVkTWVzc2FnZUluZGV4KFxyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sXHJcbiAgb3B0czogeyBpZDogc3RyaW5nOyBtZXNzYWdlPzogc3RyaW5nIH0sXHJcbik6IFByb21pc2U8dm9pZD4ge1xyXG4gIGNvbnN0IG0gPSBub3JtYWxpemVNZXNzYWdlKG9wdHMubWVzc2FnZSk7XHJcbiAgaWYgKCFtKSByZXR1cm47XHJcblxyXG4gIHRyeSB7XHJcbiAgICBjb25zdCBrZXkgPSBsZWFkQnlNZXNzYWdlS2V5KG0pO1xyXG4gICAgY29uc3QgaWR4ID0gKGF3YWl0IHN0b3JlLmdldChrZXksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIHsgaWQ/OiBzdHJpbmcgfSB8IG51bGw7XHJcbiAgICBpZiAoc2FmZVRleHQoaWR4Py5pZCkgPT09IG9wdHMuaWQpIGF3YWl0IHN0b3JlLmRlbGV0ZShrZXkpO1xyXG4gIH0gY2F0Y2gge31cclxufVxyXG5cclxuXHJcbmZ1bmN0aW9uIG5vcm1hbGl6ZUVtYWlsKGVtYWlsPzogc3RyaW5nKTogc3RyaW5nIHwgbnVsbCB7XHJcbiAgY29uc3QgZSA9IChlbWFpbCA/PyBcIlwiKS50cmltKCkudG9Mb3dlckNhc2UoKTtcclxuICByZXR1cm4gZS5sZW5ndGggPyBlIDogbnVsbDtcclxufVxyXG5cclxuZnVuY3Rpb24gbm9ybWFsaXplUGhvbmUocGhvbmU/OiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsIHtcclxuICBjb25zdCBwID0gKHBob25lID8/IFwiXCIpLnRyaW0oKTtcclxuICBpZiAoIXApIHJldHVybiBudWxsO1xyXG4gIGNvbnN0IGNsZWFuZWQgPSBwLnN0YXJ0c1dpdGgoXCIrXCIpID8gXCIrXCIgKyBwLnNsaWNlKDEpLnJlcGxhY2UoL1teXFxkXS9nLCBcIlwiKSA6IHAucmVwbGFjZSgvW15cXGRdL2csIFwiXCIpO1xyXG4gIHJldHVybiBjbGVhbmVkLmxlbmd0aCA/IGNsZWFuZWQgOiBudWxsO1xyXG59XHJcblxyXG5mdW5jdGlvbiBsZWFkQnlFbWFpbEtleShlbWFpbDogc3RyaW5nKTogc3RyaW5nIHtcclxuICByZXR1cm4gYGluZGV4ZXMvbGVhZEJ5RW1haWwvJHtoYXNoU2hvcnQoZW1haWwpfWA7XHJcbn1cclxuZnVuY3Rpb24gbGVhZEJ5UGhvbmVLZXkocGhvbmU6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgcmV0dXJuIGBpbmRleGVzL2xlYWRCeVBob25lLyR7aGFzaFNob3J0KHBob25lKX1gO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBmaW5kRXhpc3RpbmdMZWFkSWRCeUNvbnRhY3QoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBjOiB7IGVtYWlsPzogc3RyaW5nOyBwaG9uZT86IHN0cmluZyB9LFxyXG4pOiBQcm9taXNlPHN0cmluZyB8IG51bGw+IHtcclxuICBjb25zdCBlID0gbm9ybWFsaXplRW1haWwoYy5lbWFpbCk7XHJcbiAgaWYgKGUpIHtcclxuICAgIGNvbnN0IGlkeCA9IChhd2FpdCBzdG9yZS5nZXQobGVhZEJ5RW1haWxLZXkoZSksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIHsgaWQ/OiBzdHJpbmcgfSB8IG51bGw7XHJcbiAgICBjb25zdCBpZCA9IHNhZmVUZXh0KGlkeD8uaWQpO1xyXG4gICAgaWYgKGlkKSByZXR1cm4gaWQ7XHJcbiAgfVxyXG5cclxuICBjb25zdCBwID0gbm9ybWFsaXplUGhvbmUoYy5waG9uZSk7XHJcbiAgaWYgKHApIHtcclxuICAgIGNvbnN0IGlkeCA9IChhd2FpdCBzdG9yZS5nZXQobGVhZEJ5UGhvbmVLZXkocCksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIHsgaWQ/OiBzdHJpbmcgfSB8IG51bGw7XHJcbiAgICBjb25zdCBpZCA9IHNhZmVUZXh0KGlkeD8uaWQpO1xyXG4gICAgaWYgKGlkKSByZXR1cm4gaWQ7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gbnVsbDtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gcmVzZXJ2ZUNvbnRhY3RJbmRleGVzKFxyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sXHJcbiAgb3B0czogeyBpZDogc3RyaW5nOyBlbWFpbD86IHN0cmluZzsgcGhvbmU/OiBzdHJpbmcgfSxcclxuKTogUHJvbWlzZTx7IG9rOiB0cnVlIH0gfCB7IG9rOiBmYWxzZTsgZXhpc3RpbmdJZDogc3RyaW5nIH0+IHtcclxuICBjb25zdCBlID0gbm9ybWFsaXplRW1haWwob3B0cy5lbWFpbCk7XHJcbiAgY29uc3QgcCA9IG5vcm1hbGl6ZVBob25lKG9wdHMucGhvbmUpO1xyXG5cclxuICBjb25zdCBleGlzdGluZyA9IGF3YWl0IGZpbmRFeGlzdGluZ0xlYWRJZEJ5Q29udGFjdChzdG9yZSwgeyBlbWFpbDogZSA/PyB1bmRlZmluZWQsIHBob25lOiBwID8/IHVuZGVmaW5lZCB9KTtcclxuICBpZiAoZXhpc3RpbmcpIHJldHVybiB7IG9rOiBmYWxzZSwgZXhpc3RpbmdJZDogZXhpc3RpbmcgfTtcclxuXHJcbiAgaWYgKGUpIHtcclxuICAgIGNvbnN0IGtleSA9IGxlYWRCeUVtYWlsS2V5KGUpO1xyXG4gICAgY29uc3QgcmVzID0gYXdhaXQgc3RvcmUuc2V0SlNPTihrZXksIHsgaWQ6IG9wdHMuaWQgfSwgeyBvbmx5SWZOZXc6IHRydWUgfSk7XHJcbiAgICBpZiAoIXJlcy5tb2RpZmllZCkge1xyXG4gICAgICBjb25zdCBpZHggPSAoYXdhaXQgc3RvcmUuZ2V0KGtleSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgeyBpZD86IHN0cmluZyB9IHwgbnVsbDtcclxuICAgICAgY29uc3QgaWQgPSBzYWZlVGV4dChpZHg/LmlkKSB8fCBvcHRzLmlkO1xyXG4gICAgICByZXR1cm4geyBvazogZmFsc2UsIGV4aXN0aW5nSWQ6IGlkIH07XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBpZiAocCkge1xyXG4gICAgY29uc3Qga2V5ID0gbGVhZEJ5UGhvbmVLZXkocCk7XHJcbiAgICBjb25zdCByZXMgPSBhd2FpdCBzdG9yZS5zZXRKU09OKGtleSwgeyBpZDogb3B0cy5pZCB9LCB7IG9ubHlJZk5ldzogdHJ1ZSB9KTtcclxuICAgIGlmICghcmVzLm1vZGlmaWVkKSB7XHJcbiAgICAgIGlmIChlKSB7XHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgIGF3YWl0IHN0b3JlLmRlbGV0ZShsZWFkQnlFbWFpbEtleShlKSk7XHJcbiAgICAgICAgfSBjYXRjaCB7fVxyXG4gICAgICB9XHJcbiAgICAgIGNvbnN0IGlkeCA9IChhd2FpdCBzdG9yZS5nZXQoa2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyB7IGlkPzogc3RyaW5nIH0gfCBudWxsO1xyXG4gICAgICBjb25zdCBpZCA9IHNhZmVUZXh0KGlkeD8uaWQpIHx8IG9wdHMuaWQ7XHJcbiAgICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXhpc3RpbmdJZDogaWQgfTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHJldHVybiB7IG9rOiB0cnVlIH07XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIHJlbGVhc2VSZXNlcnZlZENvbnRhY3RJbmRleGVzKFxyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sXHJcbiAgb3B0czogeyBpZDogc3RyaW5nOyBlbWFpbD86IHN0cmluZzsgcGhvbmU/OiBzdHJpbmcgfSxcclxuKTogUHJvbWlzZTx2b2lkPiB7XHJcbiAgY29uc3QgZSA9IG5vcm1hbGl6ZUVtYWlsKG9wdHMuZW1haWwpO1xyXG4gIGNvbnN0IHAgPSBub3JtYWxpemVQaG9uZShvcHRzLnBob25lKTtcclxuICBpZiAoZSkge1xyXG4gICAgdHJ5IHtcclxuICAgICAgY29uc3Qga2V5ID0gbGVhZEJ5RW1haWxLZXkoZSk7XHJcbiAgICAgIGNvbnN0IGlkeCA9IChhd2FpdCBzdG9yZS5nZXQoa2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyB7IGlkPzogc3RyaW5nIH0gfCBudWxsO1xyXG4gICAgICBpZiAoc2FmZVRleHQoaWR4Py5pZCkgPT09IG9wdHMuaWQpIGF3YWl0IHN0b3JlLmRlbGV0ZShrZXkpO1xyXG4gICAgfSBjYXRjaCB7fVxyXG4gIH1cclxuICBpZiAocCkge1xyXG4gICAgdHJ5IHtcclxuICAgICAgY29uc3Qga2V5ID0gbGVhZEJ5UGhvbmVLZXkocCk7XHJcbiAgICAgIGNvbnN0IGlkeCA9IChhd2FpdCBzdG9yZS5nZXQoa2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyB7IGlkPzogc3RyaW5nIH0gfCBudWxsO1xyXG4gICAgICBpZiAoc2FmZVRleHQoaWR4Py5pZCkgPT09IG9wdHMuaWQpIGF3YWl0IHN0b3JlLmRlbGV0ZShrZXkpO1xyXG4gICAgfSBjYXRjaCB7fVxyXG4gIH1cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gc2FmZUFwcGVuZExlYWRFdmVudChcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIGlkOiBzdHJpbmcsXHJcbiAgZXZ0OiB7IHR5cGU6IHN0cmluZzsgbm90ZT86IHN0cmluZyB9LFxyXG4pOiBQcm9taXNlPHZvaWQ+IHtcclxuICB0cnkge1xyXG4gICAgYXdhaXQgcGF0Y2hMZWFkKHN0b3JlLCBpZCwgKGxlYWQpID0+ICh7XHJcbiAgICAgIC4uLmxlYWQsXHJcbiAgICAgIHVwZGF0ZWRBdDogbm93SXNvKCksXHJcbiAgICAgIHRpbWVsaW5lOiBbLi4uKGxlYWQudGltZWxpbmUgPz8gW10pLCB7IGF0OiBub3dJc28oKSwgdHlwZTogZXZ0LnR5cGUsIG5vdGU6IGV2dC5ub3RlIH1dLFxyXG4gICAgfSkpO1xyXG4gIH0gY2F0Y2gge31cclxufVxyXG5cclxuY2xhc3MgRm9yYmlkZGVuRXJyb3IgZXh0ZW5kcyBFcnJvciB7XHJcbiAgY29uc3RydWN0b3IocHVibGljIHJlYWRvbmx5IGNvZGU6IHN0cmluZykge1xyXG4gICAgc3VwZXIoY29kZSk7XHJcbiAgfVxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBwYXRjaExlYWQoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBpZDogc3RyaW5nLFxyXG4gIHVwZGF0ZXI6IChsZWFkOiBMZWFkKSA9PiBMZWFkLFxyXG4pOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICBmb3IgKGxldCBpID0gMDsgaSA8IDU7IGkgKz0gMSkge1xyXG4gICAgY29uc3QgZXhpc3RpbmcgPSAoYXdhaXQgc3RvcmUuZ2V0V2l0aE1ldGFkYXRhKGBsZWFkcy8ke2lkfWAsIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzXHJcbiAgICAgIHwgeyBkYXRhOiBMZWFkOyBldGFnOiBzdHJpbmcgfVxyXG4gICAgICB8IG51bGw7XHJcblxyXG4gICAgaWYgKCFleGlzdGluZykgcmV0dXJuIGZhbHNlO1xyXG5cclxuICAgIGxldCBuZXh0OiBMZWFkO1xyXG4gICAgdHJ5IHtcclxuICAgICAgbmV4dCA9IHVwZGF0ZXIoZXhpc3RpbmcuZGF0YSk7XHJcbiAgICB9IGNhdGNoIChlKSB7XHJcbiAgICAgIGlmIChlIGluc3RhbmNlb2YgRm9yYmlkZGVuRXJyb3IpIHRocm93IGU7XHJcbiAgICAgIHRocm93IGU7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgcmVzID0gYXdhaXQgc3RvcmUuc2V0SlNPTihgbGVhZHMvJHtpZH1gLCBuZXh0LCB7IG9ubHlJZk1hdGNoOiBleGlzdGluZy5ldGFnIH0pO1xyXG4gICAgaWYgKHJlcy5tb2RpZmllZCkgcmV0dXJuIHRydWU7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gZmFsc2U7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGxpc3RMZWFkcyhcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIG9wdHM6IHsgc3RhdHVzPzogc3RyaW5nOyBxPzogc3RyaW5nOyBsaW1pdDogbnVtYmVyIH0sXHJcbik6IFByb21pc2U8TGVhZFtdPiB7XHJcbiAgY29uc3QgeyBibG9icyB9ID0gYXdhaXQgc3RvcmUubGlzdCh7IHByZWZpeDogXCJpbmRleGVzL2xlYWRzL1wiIH0pO1xyXG4gIGNvbnN0IGtleXMgPSBibG9icy5tYXAoKGIpID0+IGIua2V5KS5zb3J0KCkucmV2ZXJzZSgpO1xyXG5cclxuICBjb25zdCBsZWFkczogTGVhZFtdID0gW107XHJcbiAgZm9yIChjb25zdCBrIG9mIGtleXMpIHtcclxuICAgIGlmIChsZWFkcy5sZW5ndGggPj0gb3B0cy5saW1pdCkgYnJlYWs7XHJcbiAgICBjb25zdCBpZHggPSAoYXdhaXQgc3RvcmUuZ2V0KGRlY29kZUJsb2JLZXkoayksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIHsgaWQ6IHN0cmluZyB9IHwgbnVsbDtcclxuICAgIGlmICghaWR4Py5pZCkgY29udGludWU7XHJcblxyXG4gICAgY29uc3QgbGVhZCA9IChhd2FpdCBzdG9yZS5nZXQoYGxlYWRzLyR7aWR4LmlkfWAsIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIExlYWQgfCBudWxsO1xyXG4gICAgaWYgKCFsZWFkKSBjb250aW51ZTtcclxuXHJcbiAgICBpZiAobGVhZC5kZWxldGVkQXQpIGNvbnRpbnVlO1xyXG5cclxuICAgIGlmIChvcHRzLnN0YXR1cyAmJiBsZWFkLnN0YXR1cyAhPT0gb3B0cy5zdGF0dXMpIGNvbnRpbnVlO1xyXG4gICAgaWYgKG9wdHMucSAmJiAhbWF0Y2hlc1F1ZXJ5KGxlYWQsIG9wdHMucSkpIGNvbnRpbnVlO1xyXG5cclxuICAgIGxlYWRzLnB1c2gobGVhZCk7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gbGVhZHM7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIG1hdGNoZXNRdWVyeShsZWFkOiBMZWFkLCBxOiBzdHJpbmcpOiBib29sZWFuIHtcclxuICBjb25zdCBuZWVkbGUgPSBxLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xyXG4gIGlmICghbmVlZGxlKSByZXR1cm4gdHJ1ZTtcclxuICBjb25zdCBoYXkgPSBbbGVhZC5pZCwgbGVhZC5uYW1lLCBsZWFkLmVtYWlsID8/IFwiXCIsIGxlYWQucGhvbmUgPz8gXCJcIiwgbGVhZC5zZXJ2aWNlID8/IFwiXCIsIGxlYWQubm90ZXMgPz8gXCJcIiwgbGVhZC5zdGF0dXNdXHJcbiAgICAuam9pbihcIiBcIilcclxuICAgIC50b0xvd2VyQ2FzZSgpO1xyXG4gIHJldHVybiBoYXkuaW5jbHVkZXMobmVlZGxlKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gcHVsbE9uY2VDb25zdW1lTGVhZHMoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBvcHRzOiB7IGxpbWl0OiBudW1iZXI7IHN0YXR1czogTGVhZFN0YXR1czsgYXNzaWduZWRUbzogc3RyaW5nOyBkZXZpY2VJZDogc3RyaW5nIHwgbnVsbCB9LFxyXG4pOiBQcm9taXNlPExlYWRbXT4ge1xyXG4gIGNvbnN0IHsgYmxvYnMgfSA9IGF3YWl0IHN0b3JlLmxpc3QoeyBwcmVmaXg6IFwiaW5kZXhlcy9sZWFkcy9cIiB9KTtcclxuICBjb25zdCBrZXlzID0gYmxvYnMubWFwKChiKSA9PiBiLmtleSkuc29ydCgpLnJldmVyc2UoKTtcclxuXHJcbiAgY29uc3Qgb3V0OiBMZWFkW10gPSBbXTtcclxuXHJcbiAgZm9yIChjb25zdCBrIG9mIGtleXMpIHtcclxuICAgIGlmIChvdXQubGVuZ3RoID49IG9wdHMubGltaXQpIGJyZWFrO1xyXG5cclxuICAgIGNvbnN0IGlkeCA9IChhd2FpdCBzdG9yZS5nZXQoZGVjb2RlQmxvYktleShrKSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgeyBpZD86IHN0cmluZzsgY3JlYXRlZEF0Pzogc3RyaW5nIH0gfCBudWxsO1xyXG4gICAgY29uc3QgaWQgPSBzYWZlVGV4dChpZHg/LmlkKTtcclxuICAgIGlmICghaWQpIGNvbnRpbnVlO1xyXG5cclxuICAgIGNvbnN0IGNsYWltZWQgPSBhd2FpdCB0cnlDbGFpbUxlYWQoc3RvcmUsIGlkLCBvcHRzKTtcclxuICAgIGlmICghY2xhaW1lZCkgY29udGludWU7XHJcblxyXG4gICAgYXdhaXQgY29uc3VtZUxlYWQoc3RvcmUsIGNsYWltZWQpO1xyXG4gICAgb3V0LnB1c2goY2xhaW1lZCk7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gb3V0O1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiB0cnlDbGFpbUxlYWQoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBpZDogc3RyaW5nLFxyXG4gIG9wdHM6IHsgc3RhdHVzOiBMZWFkU3RhdHVzOyBhc3NpZ25lZFRvOiBzdHJpbmc7IGRldmljZUlkOiBzdHJpbmcgfCBudWxsIH0sXHJcbik6IFByb21pc2U8TGVhZCB8IG51bGw+IHtcclxuICBmb3IgKGxldCBpID0gMDsgaSA8IDU7IGkgKz0gMSkge1xyXG4gICAgY29uc3QgZXhpc3RpbmcgPSAoYXdhaXQgc3RvcmUuZ2V0V2l0aE1ldGFkYXRhKGBsZWFkcy8ke2lkfWAsIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzXHJcbiAgICAgIHwgeyBkYXRhOiBMZWFkOyBldGFnOiBzdHJpbmcgfVxyXG4gICAgICB8IG51bGw7XHJcblxyXG4gICAgaWYgKCFleGlzdGluZykgcmV0dXJuIG51bGw7XHJcblxyXG4gICAgY29uc3QgbGVhZCA9IGV4aXN0aW5nLmRhdGE7XHJcbiAgICBpZiAoIWxlYWQpIHJldHVybiBudWxsO1xyXG5cclxuICAgIGlmIChsZWFkLmRlbGV0ZWRBdCkgcmV0dXJuIG51bGw7XHJcbiAgICBpZiAobGVhZC5hc3NpZ25lZFRvKSByZXR1cm4gbnVsbDtcclxuICAgIGlmIChvcHRzLnN0YXR1cyAmJiBsZWFkLnN0YXR1cyAhPT0gb3B0cy5zdGF0dXMpIHJldHVybiBudWxsO1xyXG5cclxuICAgIGNvbnN0IHRzID0gbm93SXNvKCk7XHJcblxyXG4gICAgY29uc3QgbmV4dDogTGVhZCA9IHtcclxuICAgICAgLi4ubGVhZCxcclxuICAgICAgYXNzaWduZWRUbzogb3B0cy5hc3NpZ25lZFRvLFxyXG4gICAgICBwdWxsZWRBdDogdHMsXHJcbiAgICAgIHVwZGF0ZWRBdDogdHMsXHJcbiAgICAgIHVwZGF0ZWRCeTogb3B0cy5hc3NpZ25lZFRvLFxyXG4gICAgICB1cGRhdGVkRGV2aWNlSWQ6IG9wdHMuZGV2aWNlSWQgPz8gbGVhZC51cGRhdGVkRGV2aWNlSWQsXHJcbiAgICAgIHRpbWVsaW5lOiBbLi4uKGxlYWQudGltZWxpbmUgPz8gW10pLCB7IGF0OiB0cywgdHlwZTogXCJwdWxsZWRcIiwgbm90ZTogb3B0cy5hc3NpZ25lZFRvIH1dLFxyXG4gICAgfTtcclxuXHJcbiAgICBjb25zdCByZXMgPSBhd2FpdCBzdG9yZS5zZXRKU09OKGBsZWFkcy8ke2lkfWAsIG5leHQsIHsgb25seUlmTWF0Y2g6IGV4aXN0aW5nLmV0YWcgfSk7XHJcbiAgICBpZiAocmVzLm1vZGlmaWVkKSByZXR1cm4gbmV4dDtcclxuICB9XHJcblxyXG4gIHJldHVybiBudWxsO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBjb25zdW1lTGVhZChzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LCBsZWFkOiBMZWFkKTogUHJvbWlzZTx2b2lkPiB7XHJcbiAgY29uc3QgdHMgPSBub3dJc28oKTtcclxuXHJcbiAgLy8gXHUyNzA1IGdsb2JhbCBtYXJrZXIgKG5vIHdvcmtzcGFjZUlkKVxyXG4gIGNvbnN0IG1hcmtlcktleSA9IGBwdWxsZWQvJHtsZWFkLmlkfWA7XHJcblxyXG4gIC8vIFx1MjcwNSBvbmx5IGNvbnRpbnVlIGlmIHdlIGFjdHVhbGx5IGNyZWF0ZWQgdGhlIG1hcmtlclxyXG4gIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04obWFya2VyS2V5LCB7IGlkOiBsZWFkLmlkLCBwdWxsZWRBdDogdHMgfSwgeyBvbmx5SWZOZXc6IHRydWUgfSk7XHJcbiAgaWYgKCFyZXMubW9kaWZpZWQpIHJldHVybjsgLy8gYWxyZWFkeSBjb25zdW1lZFxyXG5cclxuICAvLyBcdTI3MDUgYXJjaGl2ZSAoTk9UIGRlbGV0ZSlcclxuICBhd2FpdCBwYXRjaExlYWQoc3RvcmUsIGxlYWQuaWQsIChsKSA9PiAoe1xyXG4gICAgLi4ubCxcclxuICAgIHN0YXR1czogXCJhcmNoaXZlZFwiLFxyXG4gICAgYXJjaGl2ZWRBdDogdHMsXHJcbiAgICB1cGRhdGVkQXQ6IHRzLFxyXG4gICAgdXBkYXRlZEJ5OiBsZWFkLnVwZGF0ZWRCeSA/PyBsLnVwZGF0ZWRCeSxcclxuICAgIHVwZGF0ZWREZXZpY2VJZDogbGVhZC51cGRhdGVkRGV2aWNlSWQgPz8gbC51cGRhdGVkRGV2aWNlSWQsXHJcbiAgICB0aW1lbGluZTogWy4uLihsLnRpbWVsaW5lID8/IFtdKSwgeyBhdDogdHMsIHR5cGU6IFwiYXJjaGl2ZWRcIiB9XSxcclxuICB9KSk7XHJcbn1cclxuXHJcblxyXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gQXBwb2ludG1lbnRzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5hc3luYyBmdW5jdGlvbiBwYXRjaEFwcG9pbnRtZW50KFxyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sXHJcbiAgaWQ6IHN0cmluZyxcclxuICB1cGRhdGVyOiAoYXBwdDogQXBwb2ludG1lbnQpID0+IEFwcG9pbnRtZW50LFxyXG4pOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICBmb3IgKGxldCBpID0gMDsgaSA8IDU7IGkgKz0gMSkge1xyXG4gICAgY29uc3QgZXhpc3RpbmcgPSAoYXdhaXQgc3RvcmUuZ2V0V2l0aE1ldGFkYXRhKGBhcHBvaW50bWVudHMvJHtpZH1gLCB7IHR5cGU6IFwianNvblwiIH0pKSBhc1xyXG4gICAgICB8IHsgZGF0YTogQXBwb2ludG1lbnQ7IGV0YWc6IHN0cmluZyB9XHJcbiAgICAgIHwgbnVsbDtcclxuXHJcbiAgICBpZiAoIWV4aXN0aW5nKSByZXR1cm4gZmFsc2U7XHJcblxyXG4gICAgY29uc3QgbmV4dCA9IHVwZGF0ZXIoZXhpc3RpbmcuZGF0YSk7XHJcbiAgICBjb25zdCByZXMgPSBhd2FpdCBzdG9yZS5zZXRKU09OKGBhcHBvaW50bWVudHMvJHtpZH1gLCBuZXh0LCB7IG9ubHlJZk1hdGNoOiBleGlzdGluZy5ldGFnIH0pO1xyXG4gICAgaWYgKHJlcy5tb2RpZmllZCkgcmV0dXJuIHRydWU7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gZmFsc2U7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGxpc3RBcHBvaW50bWVudHMoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBvcHRzOiB7IGZyb20/OiBzdHJpbmc7IHRvPzogc3RyaW5nOyBsaW1pdDogbnVtYmVyIH0sXHJcbik6IFByb21pc2U8QXBwb2ludG1lbnRbXT4ge1xyXG4gIGNvbnN0IHsgYmxvYnMgfSA9IGF3YWl0IHN0b3JlLmxpc3QoeyBwcmVmaXg6IFwiYXBwb2ludG1lbnRzL1wiIH0pO1xyXG4gIGNvbnN0IGtleXMgPSBibG9icy5tYXAoKGIpID0+IGIua2V5KS5zb3J0KCkucmV2ZXJzZSgpO1xyXG5cclxuICBjb25zdCBhcHB0czogQXBwb2ludG1lbnRbXSA9IFtdO1xyXG4gIGZvciAoY29uc3QgayBvZiBrZXlzKSB7XHJcbiAgICBpZiAoYXBwdHMubGVuZ3RoID49IG9wdHMubGltaXQpIGJyZWFrO1xyXG4gICAgY29uc3QgYXBwdCA9IChhd2FpdCBzdG9yZS5nZXQoaywgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgQXBwb2ludG1lbnQgfCBudWxsO1xyXG4gICAgaWYgKCFhcHB0KSBjb250aW51ZTtcclxuXHJcbiAgICBpZiAob3B0cy5mcm9tICYmIGFwcHQuc3RhcnRBdCA8IG9wdHMuZnJvbSkgY29udGludWU7XHJcbiAgICBpZiAob3B0cy50byAmJiBhcHB0LnN0YXJ0QXQgPiBvcHRzLnRvKSBjb250aW51ZTtcclxuXHJcbiAgICBhcHB0cy5wdXNoKGFwcHQpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIGFwcHRzO1xyXG59XHJcblxyXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBNZXRyaWNzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5hc3luYyBmdW5jdGlvbiBjb21wdXRlTWV0cmljcyhzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+KSB7XHJcbiAgY29uc3QgbGVhZHMgPSBhd2FpdCBsaXN0TGVhZHMoc3RvcmUsIHsgbGltaXQ6IDIwMCwgcTogdW5kZWZpbmVkLCBzdGF0dXM6IHVuZGVmaW5lZCB9KTtcclxuICBjb25zdCB7IGJsb2JzOiBhcHB0QmxvYnMgfSA9IGF3YWl0IHN0b3JlLmxpc3QoeyBwcmVmaXg6IFwiYXBwb2ludG1lbnRzL1wiIH0pO1xyXG5cclxuICBjb25zdCBhcHB0czogQXBwb2ludG1lbnRbXSA9IFtdO1xyXG4gIGZvciAoY29uc3QgYiBvZiBhcHB0QmxvYnMpIHtcclxuICAgIGNvbnN0IGEgPSAoYXdhaXQgc3RvcmUuZ2V0KGIua2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBBcHBvaW50bWVudCB8IG51bGw7XHJcbiAgICBpZiAoYSkgYXBwdHMucHVzaChhKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IHRvZGF5ID0gbm93SXNvKCkuc2xpY2UoMCwgMTApO1xyXG4gIGNvbnN0IGxhc3Q3ID0gZGF0ZUFkZERheXModG9kYXksIC02KTtcclxuICBjb25zdCBsYXN0MzAgPSBkYXRlQWRkRGF5cyh0b2RheSwgLTI5KTtcclxuXHJcbiAgY29uc3QgbGVhZHNUb2RheSA9IGxlYWRzLmZpbHRlcigobCkgPT4gbC5jcmVhdGVkQXQuc3RhcnRzV2l0aCh0b2RheSkpLmxlbmd0aDtcclxuICBjb25zdCBsZWFkczcgPSBsZWFkcy5maWx0ZXIoKGwpID0+IGwuY3JlYXRlZEF0LnNsaWNlKDAsIDEwKSA+PSBsYXN0NykubGVuZ3RoO1xyXG4gIGNvbnN0IGxlYWRzMzAgPSBsZWFkcy5maWx0ZXIoKGwpID0+IGwuY3JlYXRlZEF0LnNsaWNlKDAsIDEwKSA+PSBsYXN0MzApLmxlbmd0aDtcclxuXHJcbiAgY29uc3QgYXBwdHNUb2RheSA9IGFwcHRzLmZpbHRlcigoYSkgPT4gYS5jcmVhdGVkQXQuc3RhcnRzV2l0aCh0b2RheSkgJiYgYS5zdGF0dXMgPT09IFwiYm9va2VkXCIpLmxlbmd0aDtcclxuICBjb25zdCBhcHB0czcgPSBhcHB0cy5maWx0ZXIoKGEpID0+IGEuY3JlYXRlZEF0LnNsaWNlKDAsIDEwKSA+PSBsYXN0NyAmJiBhLnN0YXR1cyA9PT0gXCJib29rZWRcIikubGVuZ3RoO1xyXG4gIGNvbnN0IGFwcHRzMzAgPSBhcHB0cy5maWx0ZXIoKGEpID0+IGEuY3JlYXRlZEF0LnNsaWNlKDAsIDEwKSA+PSBsYXN0MzAgJiYgYS5zdGF0dXMgPT09IFwiYm9va2VkXCIpLmxlbmd0aDtcclxuXHJcbiAgY29uc3QgbGFuZGVkQnlEYXkgPSBuZXcgTWFwPHN0cmluZywgbnVtYmVyPigpO1xyXG4gIGZvciAoY29uc3QgbCBvZiBsZWFkcykge1xyXG4gICAgaWYgKGwuc3RhdHVzICE9PSBcImxhbmRlZFwiKSBjb250aW51ZTtcclxuICAgIGNvbnN0IGQgPSBsLnVwZGF0ZWRBdC5zbGljZSgwLCAxMCk7XHJcbiAgICBsYW5kZWRCeURheS5zZXQoZCwgKGxhbmRlZEJ5RGF5LmdldChkKSA/PyAwKSArIDEpO1xyXG4gIH1cclxuXHJcbiAgbGV0IGJlc3REYXkgPSB7IGRhdGU6IFwiXCIsIGxhbmRlZDogMCB9O1xyXG4gIGZvciAoY29uc3QgW2QsIG5dIG9mIGxhbmRlZEJ5RGF5LmVudHJpZXMoKSkge1xyXG4gICAgaWYgKG4gPiBiZXN0RGF5LmxhbmRlZCkgYmVzdERheSA9IHsgZGF0ZTogZCwgbGFuZGVkOiBuIH07XHJcbiAgfVxyXG5cclxuICByZXR1cm4ge1xyXG4gICAgbGVhZHM6IHsgdG9kYXk6IGxlYWRzVG9kYXksIGxhc3Q3OiBsZWFkczcsIGxhc3QzMDogbGVhZHMzMCB9LFxyXG4gICAgYXBwb2ludG1lbnRzOiB7IHRvZGF5OiBhcHB0c1RvZGF5LCBsYXN0NzogYXBwdHM3LCBsYXN0MzA6IGFwcHRzMzAgfSxcclxuICAgIGJlc3REYXksXHJcbiAgfTtcclxufVxyXG5cclxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBFeHBvcnQgLyBJbXBvcnQgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqL1xyXG5cclxuYXN5bmMgZnVuY3Rpb24gZXhwb3J0U25hcHNob3Qoc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPikge1xyXG4gIGNvbnN0IHsgYmxvYnM6IGxlYWRCbG9icyB9ID0gYXdhaXQgc3RvcmUubGlzdCh7IHByZWZpeDogXCJsZWFkcy9cIiB9KTtcclxuICBjb25zdCB7IGJsb2JzOiBhcHB0QmxvYnMgfSA9IGF3YWl0IHN0b3JlLmxpc3QoeyBwcmVmaXg6IFwiYXBwb2ludG1lbnRzL1wiIH0pO1xyXG4gIGNvbnN0IHsgYmxvYnM6IHNsb3RCbG9icyB9ID0gYXdhaXQgc3RvcmUubGlzdCh7IHByZWZpeDogXCJzbG90cy9cIiB9KTtcclxuICBjb25zdCB7IGJsb2JzOiB0b2RvQmxvYnMgfSA9IGF3YWl0IHN0b3JlLmxpc3QoeyBwcmVmaXg6IFwidG9kb3MvXCIgfSk7XHJcblxyXG4gIGNvbnN0IGxlYWRzOiBMZWFkW10gPSBbXTtcclxuICBmb3IgKGNvbnN0IGIgb2YgbGVhZEJsb2JzKSB7XHJcbiAgICBjb25zdCBsID0gKGF3YWl0IHN0b3JlLmdldChiLmtleSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgTGVhZCB8IG51bGw7XHJcbiAgICBpZiAobCkgbGVhZHMucHVzaChsKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IGFwcG9pbnRtZW50czogQXBwb2ludG1lbnRbXSA9IFtdO1xyXG4gIGZvciAoY29uc3QgYiBvZiBhcHB0QmxvYnMpIHtcclxuICAgIGNvbnN0IGEgPSAoYXdhaXQgc3RvcmUuZ2V0KGIua2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBBcHBvaW50bWVudCB8IG51bGw7XHJcbiAgICBpZiAoYSkgYXBwb2ludG1lbnRzLnB1c2goYSk7XHJcbiAgfVxyXG5cclxuICBjb25zdCBzbG90czogUmVjb3JkPHN0cmluZywgU2xvdExvY2s+ID0ge307XHJcbiAgZm9yIChjb25zdCBiIG9mIHNsb3RCbG9icykge1xyXG4gICAgY29uc3QgcyA9IChhd2FpdCBzdG9yZS5nZXQoYi5rZXksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIFNsb3RMb2NrIHwgbnVsbDtcclxuICAgIGlmIChzKSBzbG90c1tiLmtleV0gPSBzO1xyXG4gIH1cclxuXHJcbiAgY29uc3QgdG9kb3M6IFRvZG9bXSA9IFtdO1xyXG4gIGZvciAoY29uc3QgYiBvZiB0b2RvQmxvYnMpIHtcclxuICAgIGNvbnN0IHQgPSAoYXdhaXQgc3RvcmUuZ2V0KGIua2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBUb2RvIHwgbnVsbDtcclxuICAgIGlmICh0KSB0b2Rvcy5wdXNoKHQpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHsgZXhwb3J0ZWRBdDogbm93SXNvKCksIGxlYWRzLCBhcHBvaW50bWVudHMsIHNsb3RzLCB0b2RvcyB9O1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBpbXBvcnRTbmFwc2hvdChcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIHNuYXBzaG90OiB7IGxlYWRzPzogTGVhZFtdOyBhcHBvaW50bWVudHM/OiBBcHBvaW50bWVudFtdOyBzbG90cz86IFJlY29yZDxzdHJpbmcsIFNsb3RMb2NrPjsgdG9kb3M/OiBUb2RvW10gfSxcclxuKTogUHJvbWlzZTx2b2lkPiB7XHJcbiAgLy8gXHUyNzA1IG5vIGhhcmQgZGVsZXRlczsgaW1wb3J0IGlzIGlkZW1wb3RlbnQgdXBzZXJ0ICsgbGVhZCB0b21ic3RvbmUgZm9yIHJlbW92YWxzXHJcbiAgY29uc3QgaW5jb21pbmdMZWFkcyA9IEFycmF5LmlzQXJyYXkoc25hcHNob3QubGVhZHMpID8gc25hcHNob3QubGVhZHMgOiBbXTtcclxuICBjb25zdCBpbmNvbWluZ0lkcyA9IG5ldyBTZXQoaW5jb21pbmdMZWFkcy5tYXAoKGwpID0+IHNhZmVUZXh0KGw/LmlkKSkuZmlsdGVyKEJvb2xlYW4pKTtcclxuXHJcbiAgY29uc3QgeyBibG9iczogZXhpc3RpbmdMZWFkQmxvYnMgfSA9IGF3YWl0IHN0b3JlLmxpc3QoeyBwcmVmaXg6IFwibGVhZHMvXCIgfSk7XHJcbiAgZm9yIChjb25zdCBiIG9mIGV4aXN0aW5nTGVhZEJsb2JzKSB7XHJcbiAgICBjb25zdCBleCA9IChhd2FpdCBzdG9yZS5nZXQoYi5rZXksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIExlYWQgfCBudWxsO1xyXG4gICAgaWYgKCFleD8uaWQpIGNvbnRpbnVlO1xyXG4gICAgaWYgKGluY29taW5nSWRzLmhhcyhleC5pZCkpIGNvbnRpbnVlO1xyXG4gICAgaWYgKGV4LmRlbGV0ZWRBdCkgY29udGludWU7XHJcblxyXG4gICAgYXdhaXQgcGF0Y2hMZWFkKHN0b3JlLCBleC5pZCwgKGwpID0+IHtcclxuICAgICAgY29uc3QgdHMgPSBub3dJc28oKTtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICAuLi5sLFxyXG4gICAgICAgIHN0YXR1czogXCJhcmNoaXZlZFwiLFxyXG4gICAgICAgIGRlbGV0ZWRBdDogdHMsXHJcbiAgICAgICAgdXBkYXRlZEF0OiB0cyxcclxuICAgICAgICB1cGRhdGVkQnk6IFwiaW1wb3J0XCIsXHJcbiAgICAgICAgdGltZWxpbmU6IFsuLi4obC50aW1lbGluZSA/PyBbXSksIHsgYXQ6IHRzLCB0eXBlOiBcImFyY2hpdmVkXCIsIG5vdGU6IFwibWlzc2luZ19mcm9tX2ltcG9ydFwiIH1dLFxyXG4gICAgICB9O1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBmb3IgKGNvbnN0IGxlYWQgb2YgaW5jb21pbmdMZWFkcykge1xyXG4gICAgaWYgKCFsZWFkPy5pZCB8fCAhbGVhZD8uY3JlYXRlZEF0KSBjb250aW51ZTtcclxuICAgIGNvbnN0IG5vcm1hbGl6ZWQ6IExlYWQgPSB7XHJcbiAgICAgIC4uLmxlYWQsXHJcbiAgICAgIHNvdXJjZTogXCJwdWJsaWNcIixcclxuICAgICAgdGltZWxpbmU6IG1lcmdlVGltZWxpbmUoW10sIGxlYWQudGltZWxpbmUpLFxyXG4gICAgfTtcclxuICAgIGF3YWl0IHN0b3JlLnNldEpTT04oYGxlYWRzLyR7bGVhZC5pZH1gLCBub3JtYWxpemVkLCB7IG9ubHlJZk5ldzogZmFsc2UgfSBhcyBhbnkpO1xyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihcclxuICAgICAgYGluZGV4ZXMvbGVhZHMvJHtsZWFkLmNyZWF0ZWRBdH1fJHtsZWFkLmlkfWAsXHJcbiAgICAgIHsgaWQ6IGxlYWQuaWQsIGNyZWF0ZWRBdDogbGVhZC5jcmVhdGVkQXQgfSxcclxuICAgICAgeyBvbmx5SWZOZXc6IGZhbHNlIH0gYXMgYW55LFxyXG4gICAgKTtcclxuXHJcbiAgICBjb25zdCBlID0gbm9ybWFsaXplRW1haWwobGVhZC5lbWFpbCk7XHJcbiAgICBjb25zdCBwID0gbm9ybWFsaXplUGhvbmUobGVhZC5waG9uZSk7XHJcbiAgICBpZiAoZSkgYXdhaXQgc3RvcmUuc2V0SlNPTihsZWFkQnlFbWFpbEtleShlKSwgeyBpZDogbGVhZC5pZCB9LCB7IG9ubHlJZk5ldzogZmFsc2UgfSBhcyBhbnkpO1xyXG4gICAgaWYgKHApIGF3YWl0IHN0b3JlLnNldEpTT04obGVhZEJ5UGhvbmVLZXkocCksIHsgaWQ6IGxlYWQuaWQgfSwgeyBvbmx5SWZOZXc6IGZhbHNlIH0gYXMgYW55KTtcclxuICB9XHJcblxyXG4gIGZvciAoY29uc3QgYXBwdCBvZiBzbmFwc2hvdC5hcHBvaW50bWVudHMgPz8gW10pIHtcclxuICAgIGlmICghYXBwdD8uaWQpIGNvbnRpbnVlO1xyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihgYXBwb2ludG1lbnRzLyR7YXBwdC5pZH1gLCBhcHB0LCB7IG9ubHlJZk5ldzogZmFsc2UgfSBhcyBhbnkpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgc2xvdHMgPSBzbmFwc2hvdC5zbG90cyA/PyB7fTtcclxuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhzbG90cykpIHtcclxuICAgIGlmICghaykgY29udGludWU7XHJcbiAgICBhd2FpdCBzdG9yZS5zZXRKU09OKGssIHYsIHsgb25seUlmTmV3OiBmYWxzZSB9IGFzIGFueSk7XHJcbiAgfVxyXG5cclxuICBmb3IgKGNvbnN0IHRvZG8gb2Ygc25hcHNob3QudG9kb3MgPz8gW10pIHtcclxuICAgIGlmICghdG9kbz8uaWQpIGNvbnRpbnVlO1xyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihgdG9kb3MvJHt0b2RvLmlkfWAsIHRvZG8sIHsgb25seUlmTmV3OiBmYWxzZSB9IGFzIGFueSk7XHJcbiAgfVxyXG59XHJcblxyXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIFN5bmMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5mdW5jdGlvbiBzeW5jTWV0YUtleSh3b3Jrc3BhY2VJZDogc3RyaW5nKTogc3RyaW5nIHtcclxuICByZXR1cm4gYHN5bmMvbWV0YS8ke3dvcmtzcGFjZUlkfWA7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldFN5bmNNZXRhKHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sIHdvcmtzcGFjZUlkOiBzdHJpbmcpOiBQcm9taXNlPFN5bmNNZXRhPiB7XHJcbiAgY29uc3QgbWV0YSA9IChhd2FpdCBzdG9yZS5nZXQoc3luY01ldGFLZXkod29ya3NwYWNlSWQpLCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBTeW5jTWV0YSB8IG51bGw7XHJcbiAgaWYgKG1ldGEgJiYgdHlwZW9mIG1ldGEudmVyc2lvbiA9PT0gXCJudW1iZXJcIiAmJiB0eXBlb2YgbWV0YS51cGRhdGVkQXQgPT09IFwic3RyaW5nXCIpIHJldHVybiBtZXRhO1xyXG4gIHJldHVybiB7IHZlcnNpb246IDAsIHVwZGF0ZWRBdDogXCJcdTIwMTRcIiB9O1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBidW1wU3luY01ldGEoc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPiwgd29ya3NwYWNlSWQ6IHN0cmluZyk6IFByb21pc2U8U3luY01ldGE+IHtcclxuICBjb25zdCBrZXkgPSBzeW5jTWV0YUtleSh3b3Jrc3BhY2VJZCk7XHJcblxyXG4gIGZvciAobGV0IGkgPSAwOyBpIDwgNTsgaSArPSAxKSB7XHJcbiAgICBjb25zdCBleGlzdGluZyA9IChhd2FpdCBzdG9yZS5nZXRXaXRoTWV0YWRhdGEoa2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhc1xyXG4gICAgICB8IHsgZGF0YTogU3luY01ldGE7IGV0YWc6IHN0cmluZyB9XHJcbiAgICAgIHwgbnVsbDtcclxuXHJcbiAgICBpZiAoIWV4aXN0aW5nKSB7XHJcbiAgICAgIGNvbnN0IG5leHQ6IFN5bmNNZXRhID0geyB2ZXJzaW9uOiAxLCB1cGRhdGVkQXQ6IG5vd0lzbygpIH07XHJcbiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04oa2V5LCBuZXh0LCB7IG9ubHlJZk5ldzogdHJ1ZSB9KTtcclxuICAgICAgaWYgKHJlcy5tb2RpZmllZCkgcmV0dXJuIG5leHQ7XHJcbiAgICAgIGNvbnRpbnVlO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGN1clYgPSB0eXBlb2YgZXhpc3RpbmcuZGF0YT8udmVyc2lvbiA9PT0gXCJudW1iZXJcIiA/IGV4aXN0aW5nLmRhdGEudmVyc2lvbiA6IDA7XHJcbiAgICBjb25zdCBuZXh0OiBTeW5jTWV0YSA9IHsgdmVyc2lvbjogY3VyViArIDEsIHVwZGF0ZWRBdDogbm93SXNvKCkgfTtcclxuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04oa2V5LCBuZXh0LCB7IG9ubHlJZk1hdGNoOiBleGlzdGluZy5ldGFnIH0pO1xyXG4gICAgaWYgKHJlcy5tb2RpZmllZCkgcmV0dXJuIG5leHQ7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gYXdhaXQgZ2V0U3luY01ldGEoc3RvcmUsIHdvcmtzcGFjZUlkKTtcclxufVxyXG5cclxuZnVuY3Rpb24gaXNvR3QoYT86IHN0cmluZywgYj86IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gIGlmICghYSkgcmV0dXJuIGZhbHNlO1xyXG4gIGlmICghYikgcmV0dXJuIHRydWU7XHJcbiAgcmV0dXJuIGEgPiBiO1xyXG59XHJcblxyXG5mdW5jdGlvbiBtZXJnZVRpbWVsaW5lKGE6IExlYWRbXCJ0aW1lbGluZVwiXSB8IHVuZGVmaW5lZCwgYjogTGVhZFtcInRpbWVsaW5lXCJdIHwgdW5kZWZpbmVkKTogTGVhZFtcInRpbWVsaW5lXCJdIHtcclxuICBjb25zdCB4ID0gQXJyYXkuaXNBcnJheShhKSA/IGEgOiBbXTtcclxuICBjb25zdCB5ID0gQXJyYXkuaXNBcnJheShiKSA/IGIgOiBbXTtcclxuICBjb25zdCBzZWVuID0gbmV3IFNldDxzdHJpbmc+KCk7XHJcbiAgY29uc3Qgb3V0OiBMZWFkW1widGltZWxpbmVcIl0gPSBbXTtcclxuXHJcbiAgZm9yIChjb25zdCBldnQgb2YgWy4uLngsIC4uLnldKSB7XHJcbiAgICBjb25zdCBrZXkgPSBKU09OLnN0cmluZ2lmeShbZXZ0Py5hdCA/PyBcIlwiLCBldnQ/LnR5cGUgPz8gXCJcIiwgZXZ0Py5ub3RlID8/IFwiXCJdKTtcclxuICAgIGlmIChzZWVuLmhhcyhrZXkpKSBjb250aW51ZTtcclxuICAgIHNlZW4uYWRkKGtleSk7XHJcbiAgICBvdXQucHVzaCh7IGF0OiBTdHJpbmcoZXZ0Py5hdCA/PyBcIlwiKSwgdHlwZTogU3RyaW5nKGV2dD8udHlwZSA/PyBcIlwiKSwgbm90ZTogZXZ0Py5ub3RlID8gU3RyaW5nKGV2dC5ub3RlKSA6IHVuZGVmaW5lZCB9KTtcclxuICB9XHJcblxyXG4gIG91dC5zb3J0KChtLCBuKSA9PiBTdHJpbmcobS5hdCkubG9jYWxlQ29tcGFyZShTdHJpbmcobi5hdCkpKTtcclxuICByZXR1cm4gb3V0O1xyXG59XHJcblxyXG5mdW5jdGlvbiBtZXJnZUxlYWQoZXg6IExlYWQsIGluYzogTGVhZCk6IExlYWQge1xyXG4gIGlmIChleC5kZWxldGVkQXQgfHwgaW5jLmRlbGV0ZWRBdCkge1xyXG4gICAgY29uc3Qgd2lubmVyID0gZXguZGVsZXRlZEF0ID8gZXggOiBpbmM7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICAuLi53aW5uZXIsXHJcbiAgICAgIGRlbGV0ZWRBdDogZXguZGVsZXRlZEF0IHx8IGluYy5kZWxldGVkQXQsXHJcbiAgICAgIHRpbWVsaW5lOiBtZXJnZVRpbWVsaW5lKGV4LnRpbWVsaW5lLCBpbmMudGltZWxpbmUpLFxyXG4gICAgICB1cGRhdGVkQXQ6IG5vd0lzbygpLFxyXG4gICAgfTtcclxuICB9XHJcblxyXG4gIGNvbnN0IG5ld2VyID0gaXNvR3QoaW5jLnVwZGF0ZWRBdCwgZXgudXBkYXRlZEF0KTtcclxuICByZXR1cm4gbmV3ZXJcclxuICAgID8geyAuLi5leCwgLi4uaW5jLCB0aW1lbGluZTogbWVyZ2VUaW1lbGluZShleC50aW1lbGluZSwgaW5jLnRpbWVsaW5lKSB9XHJcbiAgICA6IHsgLi4uaW5jLCAuLi5leCwgdGltZWxpbmU6IG1lcmdlVGltZWxpbmUoZXgudGltZWxpbmUsIGluYy50aW1lbGluZSkgfTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gbWVyZ2VTbmFwc2hvdHMoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBhcmdzOiB7XHJcbiAgICBzZXJ2ZXI6IHsgbGVhZHM6IExlYWRbXTsgYXBwb2ludG1lbnRzOiBBcHBvaW50bWVudFtdOyBzbG90czogUmVjb3JkPHN0cmluZywgU2xvdExvY2s+OyB0b2RvczogVG9kb1tdIH07XHJcbiAgICBpbmNvbWluZzogeyBsZWFkcz86IExlYWRbXTsgYXBwb2ludG1lbnRzPzogQXBwb2ludG1lbnRbXTsgc2xvdHM/OiBSZWNvcmQ8c3RyaW5nLCBTbG90TG9jaz47IHRvZG9zPzogVG9kb1tdIH07XHJcbiAgICBhY3Rvcjogc3RyaW5nO1xyXG4gIH0sXHJcbik6IFByb21pc2U8eyBsZWFkczogTGVhZFtdOyBhcHBvaW50bWVudHM6IEFwcG9pbnRtZW50W107IHNsb3RzOiBSZWNvcmQ8c3RyaW5nLCBTbG90TG9jaz47IHRvZG9zOiBUb2RvW10gfT4ge1xyXG4gIGNvbnN0IHNlcnZlckxlYWRzID0gbmV3IE1hcChhcmdzLnNlcnZlci5sZWFkcy5tYXAoKGwpID0+IFtsLmlkLCBsXSkpO1xyXG4gIGNvbnN0IHNlcnZlckFwcHRzID0gbmV3IE1hcChhcmdzLnNlcnZlci5hcHBvaW50bWVudHMubWFwKChhKSA9PiBbYS5pZCwgYV0pKTtcclxuICBjb25zdCBzZXJ2ZXJUb2RvcyA9IG5ldyBNYXAoYXJncy5zZXJ2ZXIudG9kb3MubWFwKCh0KSA9PiBbdC5pZCwgdF0pKTtcclxuICBjb25zdCBtZXJnZWRTbG90czogUmVjb3JkPHN0cmluZywgU2xvdExvY2s+ID0geyAuLi4oYXJncy5zZXJ2ZXIuc2xvdHMgPz8ge30pIH07XHJcblxyXG4gIGZvciAoY29uc3QgaW5jIG9mIGFyZ3MuaW5jb21pbmcubGVhZHMgPz8gW10pIHtcclxuICAgIGlmICghaW5jPy5pZCB8fCAhaW5jPy5jcmVhdGVkQXQpIGNvbnRpbnVlO1xyXG5cclxuICAgIGNvbnN0IGV4ID0gc2VydmVyTGVhZHMuZ2V0KGluYy5pZCk7XHJcbiAgICBpZiAoZXgpIHtcclxuICAgICAgc2VydmVyTGVhZHMuc2V0KGluYy5pZCwgbWVyZ2VMZWFkKGV4LCBpbmMpKTtcclxuICAgICAgY29udGludWU7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgYnlDb250YWN0ID0gYXdhaXQgZmluZEV4aXN0aW5nTGVhZElkQnlDb250YWN0KHN0b3JlLCB7IGVtYWlsOiBpbmMuZW1haWwsIHBob25lOiBpbmMucGhvbmUgfSk7XHJcbiAgICBpZiAoYnlDb250YWN0KSB7XHJcbiAgICAgIGNvbnN0IGV4MiA9IHNlcnZlckxlYWRzLmdldChieUNvbnRhY3QpIHx8ICgoYXdhaXQgc3RvcmUuZ2V0KGBsZWFkcy8ke2J5Q29udGFjdH1gLCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBMZWFkIHwgbnVsbCk7XHJcbiAgICAgIGlmIChleDIpIHtcclxuICAgICAgICBjb25zdCBpbmNGaXhlZDogTGVhZCA9IHsgLi4uaW5jLCBpZDogZXgyLmlkLCBjcmVhdGVkQXQ6IGV4Mi5jcmVhdGVkQXQgfTtcclxuICAgICAgICBzZXJ2ZXJMZWFkcy5zZXQoZXgyLmlkLCBtZXJnZUxlYWQoZXgyLCBpbmNGaXhlZCkpO1xyXG4gICAgICAgIGNvbnRpbnVlO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgcmVzZXJ2ZSA9IGF3YWl0IHJlc2VydmVDb250YWN0SW5kZXhlcyhzdG9yZSwgeyBpZDogaW5jLmlkLCBlbWFpbDogaW5jLmVtYWlsLCBwaG9uZTogaW5jLnBob25lIH0pO1xyXG4gICAgaWYgKCFyZXNlcnZlLm9rKSB7XHJcbiAgICAgIGNvbnN0IGV4MyA9XHJcbiAgICAgICAgc2VydmVyTGVhZHMuZ2V0KHJlc2VydmUuZXhpc3RpbmdJZCkgfHxcclxuICAgICAgICAoKGF3YWl0IHN0b3JlLmdldChgbGVhZHMvJHtyZXNlcnZlLmV4aXN0aW5nSWR9YCwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgTGVhZCB8IG51bGwpO1xyXG4gICAgICBpZiAoZXgzKSB7XHJcbiAgICAgICAgY29uc3QgaW5jRml4ZWQ6IExlYWQgPSB7IC4uLmluYywgaWQ6IGV4My5pZCwgY3JlYXRlZEF0OiBleDMuY3JlYXRlZEF0IH07XHJcbiAgICAgICAgc2VydmVyTGVhZHMuc2V0KGV4My5pZCwgbWVyZ2VMZWFkKGV4MywgaW5jRml4ZWQpKTtcclxuICAgICAgfVxyXG4gICAgICBjb250aW51ZTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBuZXh0TmV3OiBMZWFkID0ge1xyXG4gICAgICAuLi5pbmMsXHJcbiAgICAgIHNvdXJjZTogXCJwdWJsaWNcIixcclxuICAgICAgdGltZWxpbmU6IG1lcmdlVGltZWxpbmUoW10sIGluYy50aW1lbGluZSksXHJcbiAgICB9O1xyXG4gICAgc2VydmVyTGVhZHMuc2V0KG5leHROZXcuaWQsIG5leHROZXcpO1xyXG4gIH1cclxuXHJcbiAgZm9yIChjb25zdCBpbmMgb2YgYXJncy5pbmNvbWluZy5hcHBvaW50bWVudHMgPz8gW10pIHtcclxuICAgIGlmICghaW5jPy5pZCkgY29udGludWU7XHJcbiAgICBjb25zdCBleCA9IHNlcnZlckFwcHRzLmdldChpbmMuaWQpO1xyXG4gICAgaWYgKCFleCkge1xyXG4gICAgICBzZXJ2ZXJBcHB0cy5zZXQoaW5jLmlkLCBpbmMpO1xyXG4gICAgICBjb250aW51ZTtcclxuICAgIH1cclxuICAgIHNlcnZlckFwcHRzLnNldChpbmMuaWQsIGlzb0d0KGluYy51cGRhdGVkQXQsIGV4LnVwZGF0ZWRBdCkgPyBpbmMgOiBleCk7XHJcbiAgfVxyXG5cclxuICBmb3IgKGNvbnN0IGluYyBvZiBhcmdzLmluY29taW5nLnRvZG9zID8/IFtdKSB7XHJcbiAgICBpZiAoIWluYz8uaWQpIGNvbnRpbnVlO1xyXG4gICAgY29uc3QgZXggPSBzZXJ2ZXJUb2Rvcy5nZXQoaW5jLmlkKTtcclxuICAgIGlmICghZXgpIHtcclxuICAgICAgc2VydmVyVG9kb3Muc2V0KGluYy5pZCwgaW5jKTtcclxuICAgICAgY29udGludWU7XHJcbiAgICB9XHJcbiAgICBzZXJ2ZXJUb2Rvcy5zZXQoaW5jLmlkLCBpc29HdChpbmMudXBkYXRlZEF0LCBleC51cGRhdGVkQXQpID8gaW5jIDogZXgpO1xyXG4gIH1cclxuXHJcbiAgY29uc3QgaW5jb21pbmdTbG90cyA9IGFyZ3MuaW5jb21pbmcuc2xvdHMgPz8ge307XHJcbiAgZm9yIChjb25zdCBbaywgdl0gb2YgT2JqZWN0LmVudHJpZXMoaW5jb21pbmdTbG90cykpIHtcclxuICAgIGNvbnN0IGEgPSBtZXJnZWRTbG90c1trXT8uaWRzID8/IFtdO1xyXG4gICAgY29uc3QgYiA9IHY/LmlkcyA/PyBbXTtcclxuICAgIGNvbnN0IHNldCA9IG5ldyBTZXQ8c3RyaW5nPihbLi4uYSwgLi4uYl0uZmlsdGVyKEJvb2xlYW4pKTtcclxuICAgIG1lcmdlZFNsb3RzW2tdID0geyBpZHM6IEFycmF5LmZyb20oc2V0KSB9O1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHtcclxuICAgIGxlYWRzOiBBcnJheS5mcm9tKHNlcnZlckxlYWRzLnZhbHVlcygpKSxcclxuICAgIGFwcG9pbnRtZW50czogQXJyYXkuZnJvbShzZXJ2ZXJBcHB0cy52YWx1ZXMoKSksXHJcbiAgICBzbG90czogbWVyZ2VkU2xvdHMsXHJcbiAgICB0b2RvczogQXJyYXkuZnJvbShzZXJ2ZXJUb2Rvcy52YWx1ZXMoKSksXHJcbiAgfTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gcGVyc2lzdE1lcmdlZFNuYXBzaG90KFxyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sXHJcbiAgbWVyZ2VkOiB7IGxlYWRzOiBMZWFkW107IGFwcG9pbnRtZW50czogQXBwb2ludG1lbnRbXTsgc2xvdHM6IFJlY29yZDxzdHJpbmcsIFNsb3RMb2NrPjsgdG9kb3M6IFRvZG9bXSB9LFxyXG4pOiBQcm9taXNlPHZvaWQ+IHtcclxuICBmb3IgKGNvbnN0IGxlYWQgb2YgbWVyZ2VkLmxlYWRzKSB7XHJcbiAgICBpZiAoIWxlYWQ/LmlkIHx8ICFsZWFkPy5jcmVhdGVkQXQpIGNvbnRpbnVlO1xyXG5cclxuICAgIGF3YWl0IHN0b3JlLnNldEpTT04oYGxlYWRzLyR7bGVhZC5pZH1gLCBsZWFkLCB7IG9ubHlJZk5ldzogZmFsc2UgfSBhcyBhbnkpO1xyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihcclxuICAgICAgYGluZGV4ZXMvbGVhZHMvJHtsZWFkLmNyZWF0ZWRBdH1fJHtsZWFkLmlkfWAsXHJcbiAgICAgIHsgaWQ6IGxlYWQuaWQsIGNyZWF0ZWRBdDogbGVhZC5jcmVhdGVkQXQgfSxcclxuICAgICAgeyBvbmx5SWZOZXc6IHRydWUgfSxcclxuICAgICk7XHJcblxyXG4gICAgY29uc3QgZSA9IG5vcm1hbGl6ZUVtYWlsKGxlYWQuZW1haWwpO1xyXG4gICAgY29uc3QgcCA9IG5vcm1hbGl6ZVBob25lKGxlYWQucGhvbmUpO1xyXG4gICAgaWYgKGUpIGF3YWl0IHN0b3JlLnNldEpTT04obGVhZEJ5RW1haWxLZXkoZSksIHsgaWQ6IGxlYWQuaWQgfSwgeyBvbmx5SWZOZXc6IGZhbHNlIH0gYXMgYW55KTtcclxuICAgIGlmIChwKSBhd2FpdCBzdG9yZS5zZXRKU09OKGxlYWRCeVBob25lS2V5KHApLCB7IGlkOiBsZWFkLmlkIH0sIHsgb25seUlmTmV3OiBmYWxzZSB9IGFzIGFueSk7XHJcbiAgfVxyXG5cclxuICBmb3IgKGNvbnN0IGFwcHQgb2YgbWVyZ2VkLmFwcG9pbnRtZW50cykge1xyXG4gICAgaWYgKCFhcHB0Py5pZCkgY29udGludWU7XHJcbiAgICBhd2FpdCBzdG9yZS5zZXRKU09OKGBhcHBvaW50bWVudHMvJHthcHB0LmlkfWAsIGFwcHQsIHsgb25seUlmTmV3OiBmYWxzZSB9IGFzIGFueSk7XHJcbiAgfVxyXG5cclxuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhtZXJnZWQuc2xvdHMgPz8ge30pKSB7XHJcbiAgICBhd2FpdCBzdG9yZS5zZXRKU09OKGssIHYsIHsgb25seUlmTmV3OiBmYWxzZSB9IGFzIGFueSk7XHJcbiAgfVxyXG5cclxuICBmb3IgKGNvbnN0IHRvZG8gb2YgbWVyZ2VkLnRvZG9zID8/IFtdKSB7XHJcbiAgICBpZiAoIXRvZG8/LmlkKSBjb250aW51ZTtcclxuICAgIGF3YWl0IHN0b3JlLnNldEpTT04oYHRvZG9zLyR7dG9kby5pZH1gLCB0b2RvLCB7IG9ubHlJZk5ldzogZmFsc2UgfSBhcyBhbnkpO1xyXG4gIH1cclxufVxyXG5cclxuZnVuY3Rpb24gaXNGdWxsU25hcHNob3RTaGFwZSh2OiBhbnkpOiB2IGlzIHtcclxuICBsZWFkczogTGVhZFtdO1xyXG4gIGFwcG9pbnRtZW50czogQXBwb2ludG1lbnRbXTtcclxuICBzbG90czogUmVjb3JkPHN0cmluZywgU2xvdExvY2s+O1xyXG4gIHRvZG9zOiBUb2RvW107XHJcbn0ge1xyXG4gIGlmICghdiB8fCB0eXBlb2YgdiAhPT0gXCJvYmplY3RcIikgcmV0dXJuIGZhbHNlO1xyXG4gIGlmICghQXJyYXkuaXNBcnJheSh2LmxlYWRzKSkgcmV0dXJuIGZhbHNlO1xyXG4gIGlmICghQXJyYXkuaXNBcnJheSh2LmFwcG9pbnRtZW50cykpIHJldHVybiBmYWxzZTtcclxuICBpZiAoIUFycmF5LmlzQXJyYXkodi50b2RvcykpIHJldHVybiBmYWxzZTtcclxuICBpZiAoIXYuc2xvdHMgfHwgdHlwZW9mIHYuc2xvdHMgIT09IFwib2JqZWN0XCIpIHJldHVybiBmYWxzZTtcclxuICByZXR1cm4gdHJ1ZTtcclxufVxyXG5cclxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIEF1dGggLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5mdW5jdGlvbiByZXF1aXJlQXV0aChlbnY6IEVudkNvbmZpZywgYXV0aEhlYWRlcjogc3RyaW5nKTogeyBvazogdHJ1ZTsgcGF5bG9hZDogSnd0UGF5bG9hZCB9IHwgeyBvazogZmFsc2UgfSB7XHJcbiAgY29uc3QgdG9rZW4gPSBhdXRoSGVhZGVyLnN0YXJ0c1dpdGgoXCJCZWFyZXIgXCIpID8gYXV0aEhlYWRlci5zbGljZShcIkJlYXJlciBcIi5sZW5ndGgpLnRyaW0oKSA6IFwiXCI7XHJcbiAgaWYgKCF0b2tlbikgcmV0dXJuIHsgb2s6IGZhbHNlIH07XHJcbiAgY29uc3QgcGF5bG9hZCA9IHZlcmlmeUp3dChlbnYuand0U2VjcmV0LCB0b2tlbik7XHJcbiAgaWYgKCFwYXlsb2FkKSByZXR1cm4geyBvazogZmFsc2UgfTtcclxuICByZXR1cm4geyBvazogdHJ1ZSwgcGF5bG9hZCB9O1xyXG59XHJcblxyXG5mdW5jdGlvbiB2ZXJpZnlVc2VyKGVudjogRW52Q29uZmlnLCB1c2VybmFtZTogc3RyaW5nLCBwYXNzd29yZDogc3RyaW5nKTogeyByb2xlOiBcImFkbWluXCIgfCBcInN0YWZmXCIgfSB8IG51bGwge1xyXG4gIGlmICghZW52LmNybVVzZXJuYW1lKSByZXR1cm4gbnVsbDtcclxuICBpZiAodXNlcm5hbWUgIT09IGVudi5jcm1Vc2VybmFtZSkgcmV0dXJuIG51bGw7XHJcblxyXG4gIGlmIChlbnYuY3JtUGFzc3dvcmRIYXNoKSB7XHJcbiAgICBjb25zdCBpbmNvbWluZ0hhc2ggPSBzaGEyNTZIZXgocGFzc3dvcmQpO1xyXG4gICAgaWYgKCF0aW1pbmdTYWZlRXF1YWxTdHIoaW5jb21pbmdIYXNoLCBlbnYuY3JtUGFzc3dvcmRIYXNoKSkgcmV0dXJuIG51bGw7XHJcbiAgICByZXR1cm4geyByb2xlOiBcImFkbWluXCIgfTtcclxuICB9XHJcblxyXG4gIGlmIChlbnYuY3JtUGFzc3dvcmQpIHtcclxuICAgIGlmICghdGltaW5nU2FmZUVxdWFsU3RyKHBhc3N3b3JkLCBlbnYuY3JtUGFzc3dvcmQpKSByZXR1cm4gbnVsbDtcclxuICAgIHJldHVybiB7IHJvbGU6IFwiYWRtaW5cIiB9O1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIG51bGw7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHNpZ25Kd3Qoc2VjcmV0OiBzdHJpbmcsIHBheWxvYWQ6IEp3dFBheWxvYWQpOiBzdHJpbmcge1xyXG4gIGNvbnN0IGhlYWRlciA9IHsgYWxnOiBcIkhTMjU2XCIsIHR5cDogXCJKV1RcIiB9O1xyXG4gIGNvbnN0IGVuY0hlYWRlciA9IGI2NHVybChKU09OLnN0cmluZ2lmeShoZWFkZXIpKTtcclxuICBjb25zdCBlbmNQYXlsb2FkID0gYjY0dXJsKEpTT04uc3RyaW5naWZ5KHBheWxvYWQpKTtcclxuICBjb25zdCBkYXRhID0gYCR7ZW5jSGVhZGVyfS4ke2VuY1BheWxvYWR9YDtcclxuICBjb25zdCBzaWcgPSBobWFjU2hhMjU2KHNlY3JldCwgZGF0YSk7XHJcbiAgcmV0dXJuIGAke2RhdGF9LiR7c2lnfWA7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHZlcmlmeUp3dChzZWNyZXQ6IHN0cmluZywgdG9rZW46IHN0cmluZyk6IEp3dFBheWxvYWQgfCBudWxsIHtcclxuICBpZiAoIXNlY3JldCkgcmV0dXJuIG51bGw7XHJcbiAgY29uc3QgcGFydHMgPSB0b2tlbi5zcGxpdChcIi5cIik7XHJcbiAgaWYgKHBhcnRzLmxlbmd0aCAhPT0gMykgcmV0dXJuIG51bGw7XHJcblxyXG4gIGNvbnN0IFtoLCBwLCBzXSA9IHBhcnRzO1xyXG4gIGNvbnN0IGRhdGEgPSBgJHtofS4ke3B9YDtcclxuICBjb25zdCBleHBlY3RlZCA9IGhtYWNTaGEyNTYoc2VjcmV0LCBkYXRhKTtcclxuICBpZiAoIXRpbWluZ1NhZmVFcXVhbFN0cihleHBlY3RlZCwgcykpIHJldHVybiBudWxsO1xyXG5cclxuICB0cnkge1xyXG4gICAgY29uc3QgcGF5bG9hZCA9IEpTT04ucGFyc2UoYjY0dXJsRGVjb2RlKHApKSBhcyBKd3RQYXlsb2FkO1xyXG4gICAgaWYgKHR5cGVvZiBwYXlsb2FkPy5leHAgIT09IFwibnVtYmVyXCIgfHwgbm93U2VjKCkgPiBwYXlsb2FkLmV4cCkgcmV0dXJuIG51bGw7XHJcbiAgICBpZiAodHlwZW9mIHBheWxvYWQ/LnN1YiAhPT0gXCJzdHJpbmdcIikgcmV0dXJuIG51bGw7XHJcbiAgICBpZiAocGF5bG9hZC5yb2xlICE9PSBcImFkbWluXCIgJiYgcGF5bG9hZC5yb2xlICE9PSBcInN0YWZmXCIpIHJldHVybiBudWxsO1xyXG4gICAgcmV0dXJuIHBheWxvYWQ7XHJcbiAgfSBjYXRjaCB7XHJcbiAgICByZXR1cm4gbnVsbDtcclxuICB9XHJcbn1cclxuXHJcbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gVXRpbGl0aWVzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cclxuXHJcbmZ1bmN0aW9uIHJlYWRFbnZTYWZlKCk6IEVudkNvbmZpZyB7XHJcbiAgY29uc3Qgand0U2VjcmV0ID0gZW52R2V0KFwiSldUX1NFQ1JFVFwiKSA/PyBcIlwiO1xyXG5cclxuICBjb25zdCBhbGxvd2VkT3JpZ2luc1JhdyA9IGVudkdldChcIkFMTE9XRURfT1JJR0lOU1wiKSA/PyBcIlwiO1xyXG4gIGNvbnN0IGFsbG93ZWRPcmlnaW5zID1cclxuICAgIGFsbG93ZWRPcmlnaW5zUmF3LnRyaW0oKS5sZW5ndGggPiAwXHJcbiAgICAgID8gYWxsb3dlZE9yaWdpbnNSYXdcclxuICAgICAgICAgIC5zcGxpdChcIixcIilcclxuICAgICAgICAgIC5tYXAoKHMpID0+IHMudHJpbSgpKVxyXG4gICAgICAgICAgLmZpbHRlcihCb29sZWFuKVxyXG4gICAgICA6IG51bGw7XHJcblxyXG4gIGNvbnN0IGNybVVzZXJuYW1lID0gZW52R2V0KFwiQ1JNX1VTRVJOQU1FXCIpO1xyXG4gIGNvbnN0IGNybVBhc3N3b3JkSGFzaCA9IGVudkdldChcIkNSTV9QQVNTV09SRF9IQVNIXCIpO1xyXG4gIGNvbnN0IGNybVBhc3N3b3JkID0gZW52R2V0KFwiQ1JNX1BBU1NXT1JEXCIpO1xyXG5cclxuICBjb25zdCBzbG90TWludXRlcyA9IGNsYW1wSW50KGVudkdldChcIlNMT1RfTUlOVVRFU1wiKSwgMTAsIDI0MCwgMzApO1xyXG4gIGNvbnN0IG9wZW5Ib3VyID0gY2xhbXBJbnQoZW52R2V0KFwiT1BFTl9IT1VSXCIpLCAwLCAyMywgOSk7XHJcbiAgY29uc3QgY2xvc2VIb3VyID0gY2xhbXBJbnQoZW52R2V0KFwiQ0xPU0VfSE9VUlwiKSwgMSwgMjQsIDE3KTtcclxuICBjb25zdCBjYXBhY2l0eVBlclNsb3QgPSBjbGFtcEludChlbnZHZXQoXCJDQVBBQ0lUWV9QRVJfU0xPVFwiKSwgMSwgNTAsIDEpO1xyXG5cclxuICBjb25zdCB0eiA9IGVudkdldChcIlRaXCIpID8/IFwiQW1lcmljYS9Mb3NfQW5nZWxlc1wiO1xyXG4gIGNvbnN0IHB1YmxpY0RhaWx5UmF0ZUxpbWl0ID0gY2xhbXBJbnQoZW52R2V0KFwiUFVCTElDX0RBSUxZX1JBVEVfTElNSVRcIiksIDEsIDEwXzAwMCwgNTAwMCk7XHJcblxyXG4gIHJldHVybiB7XHJcbiAgICBqd3RTZWNyZXQsXHJcbiAgICBhbGxvd2VkT3JpZ2lucyxcclxuICAgIGNybVVzZXJuYW1lLFxyXG4gICAgY3JtUGFzc3dvcmRIYXNoLFxyXG4gICAgY3JtUGFzc3dvcmQsXHJcbiAgICBzbG90TWludXRlcyxcclxuICAgIG9wZW5Ib3VyLFxyXG4gICAgY2xvc2VIb3VyLFxyXG4gICAgY2FwYWNpdHlQZXJTbG90LFxyXG4gICAgdHosXHJcbiAgICBwdWJsaWNEYWlseVJhdGVMaW1pdCxcclxuICB9O1xyXG59XHJcblxyXG5mdW5jdGlvbiBlbnZHZXQoa2V5OiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsIHtcclxuICBjb25zdCB2MSA9IHByb2Nlc3MuZW52W2tleV07XHJcbiAgaWYgKHR5cGVvZiB2MSA9PT0gXCJzdHJpbmdcIiAmJiB2MS5sZW5ndGgpIHJldHVybiB2MTtcclxuXHJcbiAgY29uc3QgbiA9IChnbG9iYWxUaGlzIGFzIGFueSk/Lk5ldGxpZnk/LmVudj8uZ2V0Py4oa2V5KTtcclxuICBpZiAodHlwZW9mIG4gPT09IFwic3RyaW5nXCIgJiYgbi5sZW5ndGgpIHJldHVybiBuO1xyXG5cclxuICByZXR1cm4gbnVsbDtcclxufVxyXG5cclxuLyoqXHJcbiAqIENPUlMgKERST1AtSU4gRklYKVxyXG4gKiAtIEFsbG93cyB0aGUgQ1JNIGFwcCdzIGN1c3RvbSBoZWFkZXJzICh4LWNsaWVudC1uYW1lLCB4LWNsaWVudC12ZXJzaW9uLCB4LXdvcmtzcGFjZS1pZCwgZXRjLilcclxuICogLSBFY2hvZXMgQWNjZXNzLUNvbnRyb2wtUmVxdWVzdC1IZWFkZXJzIGR1cmluZyBwcmVmbGlnaHQgd2hlbiBwcm92aWRlZFxyXG4gKiAtIFN1cHBvcnRzIEFMTE9XRURfT1JJR0lOUyBlbnRyaWVzIGxpa2U6XHJcbiAqICAgLSBodHRwczovL2NybS41c3RhcnN1cHBvcnQuY29cclxuICogICAtIGh0dHBzOi8vNXN0YXJzdXBwb3J0LmNvXHJcbiAqICAgLSAqLjVzdGFyc3VwcG9ydC5jb1xyXG4gKiAgIC0gaHR0cHM6Ly8qLjVzdGFyc3VwcG9ydC5jb1xyXG4gKiAgIC0gKlxyXG4gKi9cclxuZnVuY3Rpb24gYnVpbGRDb3JzSGVhZGVycyhlbnY6IEVudkNvbmZpZywgb3JpZ2luOiBzdHJpbmcsIGFjY2Vzc0NvbnRyb2xSZXF1ZXN0SGVhZGVyczogc3RyaW5nKTogSGVhZGVycyB7XHJcbiAgY29uc3QgaCA9IG5ldyBIZWFkZXJzKCk7XHJcblxyXG4gIGNvbnN0IGFsbG93T3JpZ2luID0gY29tcHV0ZUFsbG93ZWRPcmlnaW4oZW52LCBvcmlnaW4pO1xyXG4gIGlmIChhbGxvd09yaWdpbikgaC5zZXQoXCJhY2Nlc3MtY29udHJvbC1hbGxvdy1vcmlnaW5cIiwgYWxsb3dPcmlnaW4pO1xyXG5cclxuICBoLnNldChcImFjY2Vzcy1jb250cm9sLWFsbG93LW1ldGhvZHNcIiwgXCJHRVQsUE9TVCxQVVQsREVMRVRFLE9QVElPTlNcIik7XHJcblxyXG4gIC8vIElmIGJyb3dzZXIgc2VudCByZXF1ZXN0ZWQgaGVhZGVycywgZWNobyB0aGVtIGJhY2sgKGNvdmVycyBhbnkgbmV3IGN1c3RvbSBoZWFkZXJzKVxyXG4gIGNvbnN0IHJlcUhlYWRlcnMgPSAoYWNjZXNzQ29udHJvbFJlcXVlc3RIZWFkZXJzID8/IFwiXCIpLnRyaW0oKTtcclxuICBpZiAocmVxSGVhZGVycykge1xyXG4gICAgaC5zZXQoXCJhY2Nlc3MtY29udHJvbC1hbGxvdy1oZWFkZXJzXCIsIHJlcUhlYWRlcnMpO1xyXG4gIH0gZWxzZSB7XHJcbiAgICAvLyBGYWxsYmFjayBhbGxvdyBsaXN0IChpbmNsdWRlcyB0aGUgQ1JNIGN1c3RvbSBoZWFkZXJzIHRoYXQgdHJpZ2dlcmVkIHByZWZsaWdodClcclxuICAgIGguc2V0KFxyXG4gICAgICBcImFjY2Vzcy1jb250cm9sLWFsbG93LWhlYWRlcnNcIixcclxuICAgICAgXCJjb250ZW50LXR5cGUsYXV0aG9yaXphdGlvbix4LWRldmljZS1pZCx4LWNsaWVudC1uYW1lLHgtY2xpZW50LXZlcnNpb24seC13b3Jrc3BhY2UtaWRcIixcclxuICAgICk7XHJcbiAgfVxyXG5cclxuICBoLnNldChcImFjY2Vzcy1jb250cm9sLW1heC1hZ2VcIiwgXCI4NjQwMFwiKTtcclxuXHJcbiAgLy8gQ2FjaGUgQ09SUyBieSBvcmlnaW4gd2hlbiBub3Qgd2lsZGNhcmRcclxuICBpZiAoYWxsb3dPcmlnaW4gJiYgYWxsb3dPcmlnaW4gIT09IFwiKlwiKSBoLnNldChcInZhcnlcIiwgXCJvcmlnaW5cIik7XHJcblxyXG4gIHJldHVybiBoO1xyXG59XHJcblxyXG5mdW5jdGlvbiBjb21wdXRlQWxsb3dlZE9yaWdpbihlbnY6IEVudkNvbmZpZywgb3JpZ2luOiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsIHtcclxuICBjb25zdCBvID0gKG9yaWdpbiA/PyBcIlwiKS50cmltKCk7XHJcbiAgaWYgKCFvKSByZXR1cm4gbnVsbDtcclxuXHJcbiAgLy8gSWYgZW52LmFsbG93ZWRPcmlnaW5zIGlzIG51bGwgLT4gYWxsb3cgZXZlcnl0aGluZyAoa2VlcHMgeW91ciBjdXJyZW50IGJlaGF2aW9yKVxyXG4gIGlmIChlbnYuYWxsb3dlZE9yaWdpbnMgPT09IG51bGwpIHJldHVybiBcIipcIjtcclxuXHJcbiAgY29uc3QgbGlzdCA9IGVudi5hbGxvd2VkT3JpZ2lucy5tYXAoKHgpID0+ICh4ID8/IFwiXCIpLnRyaW0oKSkuZmlsdGVyKEJvb2xlYW4pO1xyXG4gIGlmIChsaXN0Lmxlbmd0aCA9PT0gMCkgcmV0dXJuIG51bGw7XHJcblxyXG4gIC8vIEV4cGxpY2l0IHdpbGRjYXJkXHJcbiAgaWYgKGxpc3QuaW5jbHVkZXMoXCIqXCIpKSByZXR1cm4gXCIqXCI7XHJcblxyXG4gIC8vIEV4YWN0IG1hdGNoIChtb3N0IGNvbW1vbilcclxuICBpZiAobGlzdC5pbmNsdWRlcyhvKSkgcmV0dXJuIG87XHJcblxyXG4gIC8vIFdpbGRjYXJkIC8gc3ViZG9tYWluIHBhdHRlcm5zXHJcbiAgbGV0IG9yaWdpblVybDogVVJMIHwgbnVsbCA9IG51bGw7XHJcbiAgdHJ5IHtcclxuICAgIG9yaWdpblVybCA9IG5ldyBVUkwobyk7XHJcbiAgfSBjYXRjaCB7XHJcbiAgICByZXR1cm4gbnVsbDtcclxuICB9XHJcblxyXG4gIGNvbnN0IG9yaWdpbkhvc3QgPSBvcmlnaW5VcmwuaG9zdDtcclxuICBjb25zdCBvcmlnaW5Qcm90byA9IG9yaWdpblVybC5wcm90b2NvbDtcclxuXHJcbiAgZm9yIChjb25zdCByYXdQYXR0ZXJuIG9mIGxpc3QpIHtcclxuICAgIGNvbnN0IHAgPSByYXdQYXR0ZXJuLnRyaW0oKTtcclxuICAgIGlmICghcCkgY29udGludWU7XHJcblxyXG4gICAgLy8gSGFuZGxlIHBhdHRlcm5zIHdpdGggc2NoZW1lOiBodHRwczovLyouZXhhbXBsZS5jb21cclxuICAgIGlmIChwLmluY2x1ZGVzKFwiOi8vXCIpKSB7XHJcbiAgICAgIGxldCBwYXR0ZXJuVXJsOiBVUkwgfCBudWxsID0gbnVsbDtcclxuICAgICAgdHJ5IHtcclxuICAgICAgICAvLyBSZXBsYWNlIHdpbGRjYXJkIGhvc3Qgd2l0aCBhIHBsYWNlaG9sZGVyIHRvIHBhcnNlXHJcbiAgICAgICAgY29uc3QgdG1wID0gcC5yZXBsYWNlKFwiOi8vKi5cIiwgXCI6Ly9wbGFjZWhvbGRlci5cIik7XHJcbiAgICAgICAgcGF0dGVyblVybCA9IG5ldyBVUkwodG1wKTtcclxuICAgICAgfSBjYXRjaCB7XHJcbiAgICAgICAgcGF0dGVyblVybCA9IG51bGw7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIC8vIElmIHdlIGNhbiBwYXJzZSBhbmQgdGhlIHByb3RvY29sIGRpZmZlcnMsIHNraXBcclxuICAgICAgaWYgKHBhdHRlcm5VcmwgJiYgcGF0dGVyblVybC5wcm90b2NvbCAhPT0gb3JpZ2luUHJvdG8pIGNvbnRpbnVlO1xyXG5cclxuICAgICAgY29uc3QgaG9zdFBhdHRlcm4gPSBwLnNwbGl0KFwiOi8vXCIpWzFdID8/IFwiXCI7XHJcbiAgICAgIGlmIChob3N0UGF0dGVybi5zdGFydHNXaXRoKFwiKi5cIikpIHtcclxuICAgICAgICBjb25zdCBiYXNlID0gaG9zdFBhdHRlcm4uc2xpY2UoMik7XHJcbiAgICAgICAgaWYgKG9yaWdpbkhvc3QgPT09IGJhc2UpIGNvbnRpbnVlOyAvLyAqLmV4YW1wbGUuY29tIGRvZXMgbm90IG1hdGNoIGFwZXhcclxuICAgICAgICBpZiAob3JpZ2luSG9zdC5lbmRzV2l0aChcIi5cIiArIGJhc2UpKSByZXR1cm4gbztcclxuICAgICAgfVxyXG5cclxuICAgICAgY29udGludWU7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gSGFuZGxlIHBhdHRlcm5zIHdpdGhvdXQgc2NoZW1lOiAqLmV4YW1wbGUuY29tXHJcbiAgICBpZiAocC5zdGFydHNXaXRoKFwiKi5cIikpIHtcclxuICAgICAgY29uc3QgYmFzZSA9IHAuc2xpY2UoMik7XHJcbiAgICAgIGlmIChvcmlnaW5Ib3N0ID09PSBiYXNlKSBjb250aW51ZTtcclxuICAgICAgaWYgKG9yaWdpbkhvc3QuZW5kc1dpdGgoXCIuXCIgKyBiYXNlKSkgcmV0dXJuIG87XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICByZXR1cm4gbnVsbDtcclxufVxyXG5cclxuZnVuY3Rpb24gbm9ybWFsaXplQXBpUGF0aChwYXRobmFtZTogc3RyaW5nKTogc3RyaW5nIHtcclxuICBpZiAocGF0aG5hbWUuc3RhcnRzV2l0aChcIi8ubmV0bGlmeS9mdW5jdGlvbnMvYXBpXCIpKSB7XHJcbiAgICBjb25zdCByZXN0ID0gcGF0aG5hbWUuc2xpY2UoXCIvLm5ldGxpZnkvZnVuY3Rpb25zL2FwaVwiLmxlbmd0aCk7XHJcbiAgICByZXR1cm4gYC9hcGkke3Jlc3QgfHwgXCJcIn1gLnJlcGxhY2VBbGwoXCIvL1wiLCBcIi9cIik7XHJcbiAgfVxyXG4gIHJldHVybiBwYXRobmFtZS5yZXBsYWNlQWxsKFwiLy9cIiwgXCIvXCIpO1xyXG59XHJcblxyXG5mdW5jdGlvbiByZXNwb25kSnNvbihkYXRhOiBKc29uVmFsdWUsIHN0YXR1czogbnVtYmVyLCBjb3JzSGVhZGVyczogSGVhZGVycyk6IFJlc3BvbnNlIHtcclxuICBjb25zdCBoZWFkZXJzID0gbmV3IEhlYWRlcnMoY29yc0hlYWRlcnMpO1xyXG4gIGhlYWRlcnMuc2V0KFwiY29udGVudC10eXBlXCIsIFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOFwiKTtcclxuICByZXR1cm4gbmV3IFJlc3BvbnNlKGpzb24oZGF0YSksIHsgc3RhdHVzLCBoZWFkZXJzIH0pO1xyXG59XHJcblxyXG5mdW5jdGlvbiBqc29uKHY6IEpzb25WYWx1ZSk6IHN0cmluZyB7XHJcbiAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHYpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBzYWZlSnNvbihyZXE6IFJlcXVlc3QpOiBQcm9taXNlPGFueSB8IG51bGw+IHtcclxuICBjb25zdCBjdCA9IHJlcS5oZWFkZXJzLmdldChcImNvbnRlbnQtdHlwZVwiKSA/PyBcIlwiO1xyXG4gIGlmICghY3QudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhcImFwcGxpY2F0aW9uL2pzb25cIikpIHJldHVybiBudWxsO1xyXG4gIHRyeSB7XHJcbiAgICByZXR1cm4gYXdhaXQgcmVxLmpzb24oKTtcclxuICB9IGNhdGNoIHtcclxuICAgIHJldHVybiBudWxsO1xyXG4gIH1cclxufVxyXG5cclxuZnVuY3Rpb24gYXNTdHJpbmcodjogYW55KTogc3RyaW5nIHwgbnVsbCB7XHJcbiAgcmV0dXJuIHR5cGVvZiB2ID09PSBcInN0cmluZ1wiID8gdiA6IG51bGw7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHJlcXVpcmVkU3RyaW5nKHY6IGFueSk6IHN0cmluZyB8IG51bGwge1xyXG4gIGNvbnN0IHMgPSBhc1N0cmluZyh2KTtcclxuICBpZiAoIXMpIHJldHVybiBudWxsO1xyXG4gIGNvbnN0IHQgPSBzLnRyaW0oKTtcclxuICByZXR1cm4gdC5sZW5ndGggPyB0IDogbnVsbDtcclxufVxyXG5cclxuZnVuY3Rpb24gb3B0aW9uYWxTdHJpbmcodjogYW55KTogc3RyaW5nIHwgdW5kZWZpbmVkIHtcclxuICBjb25zdCBzID0gYXNTdHJpbmcodik7XHJcbiAgaWYgKCFzKSByZXR1cm4gdW5kZWZpbmVkO1xyXG4gIGNvbnN0IHQgPSBzLnRyaW0oKTtcclxuICByZXR1cm4gdC5sZW5ndGggPyB0IDogdW5kZWZpbmVkO1xyXG59XHJcblxyXG5mdW5jdGlvbiBzYWZlVGV4dCh2OiBhbnkpOiBzdHJpbmcge1xyXG4gIHJldHVybiB0eXBlb2YgdiA9PT0gXCJzdHJpbmdcIiA/IHYudHJpbSgpIDogXCJcIjtcclxufVxyXG5cclxuZnVuY3Rpb24gZGVjb2RlQmxvYktleShrZXk6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgdHJ5IHtcclxuICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQoa2V5KTtcclxuICB9IGNhdGNoIHtcclxuICAgIHJldHVybiBrZXk7XHJcbiAgfVxyXG59XHJcblxyXG5cclxuZnVuY3Rpb24gcmVxdWVzdERldmljZUlkKHJlcTogUmVxdWVzdCk6IHN0cmluZyB8IG51bGwge1xyXG4gIGNvbnN0IHJhdyA9IHJlcS5oZWFkZXJzLmdldChcIngtZGV2aWNlLWlkXCIpID8/IFwiXCI7XHJcbiAgY29uc3QgdiA9IHJhdy50cmltKCk7XHJcbiAgaWYgKCF2KSByZXR1cm4gbnVsbDtcclxuICByZXR1cm4gL15bQS1aYS16MC05Xy1dezEsNjR9JC8udGVzdCh2KSA/IHYgOiBudWxsO1xyXG59XHJcblxyXG5mdW5jdGlvbiBub3dJc28oKTogc3RyaW5nIHtcclxuICByZXR1cm4gbmV3IERhdGUoKS50b0lTT1N0cmluZygpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBub3dTZWMoKTogbnVtYmVyIHtcclxuICByZXR1cm4gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGI2NHVybChpbnB1dDogc3RyaW5nKTogc3RyaW5nIHtcclxuICByZXR1cm4gQnVmZmVyLmZyb20oaW5wdXQsIFwidXRmOFwiKS50b1N0cmluZyhcImJhc2U2NFwiKS5yZXBsYWNlQWxsKFwiPVwiLCBcIlwiKS5yZXBsYWNlQWxsKFwiK1wiLCBcIi1cIikucmVwbGFjZUFsbChcIi9cIiwgXCJfXCIpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBiNjR1cmxEZWNvZGUoaW5wdXQ6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgY29uc3QgcGFkID0gaW5wdXQubGVuZ3RoICUgNCA9PT0gMCA/IFwiXCIgOiBcIj1cIi5yZXBlYXQoNCAtIChpbnB1dC5sZW5ndGggJSA0KSk7XHJcbiAgY29uc3QgYjY0ID0gaW5wdXQucmVwbGFjZUFsbChcIi1cIiwgXCIrXCIpLnJlcGxhY2VBbGwoXCJfXCIsIFwiL1wiKSArIHBhZDtcclxuICByZXR1cm4gQnVmZmVyLmZyb20oYjY0LCBcImJhc2U2NFwiKS50b1N0cmluZyhcInV0ZjhcIik7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGhtYWNTaGEyNTYoc2VjcmV0OiBzdHJpbmcsIGRhdGE6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgY29uc3Qgc2lnID0gY3J5cHRvLmNyZWF0ZUhtYWMoXCJzaGEyNTZcIiwgc2VjcmV0KS51cGRhdGUoZGF0YSkuZGlnZXN0KFwiYmFzZTY0XCIpO1xyXG4gIHJldHVybiBzaWcucmVwbGFjZUFsbChcIj1cIiwgXCJcIikucmVwbGFjZUFsbChcIitcIiwgXCItXCIpLnJlcGxhY2VBbGwoXCIvXCIsIFwiX1wiKTtcclxufVxyXG5cclxuZnVuY3Rpb24gdGltaW5nU2FmZUVxdWFsU3RyKGE6IHN0cmluZywgYjogc3RyaW5nKTogYm9vbGVhbiB7XHJcbiAgY29uc3QgYmEgPSBCdWZmZXIuZnJvbShhKTtcclxuICBjb25zdCBiYiA9IEJ1ZmZlci5mcm9tKGIpO1xyXG4gIGlmIChiYS5sZW5ndGggIT09IGJiLmxlbmd0aCkgcmV0dXJuIGZhbHNlO1xyXG4gIHJldHVybiBjcnlwdG8udGltaW5nU2FmZUVxdWFsKGJhLCBiYik7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHNoYTI1NkhleChzOiBzdHJpbmcpOiBzdHJpbmcge1xyXG4gIHJldHVybiBjcnlwdG8uY3JlYXRlSGFzaChcInNoYTI1NlwiKS51cGRhdGUocywgXCJ1dGY4XCIpLmRpZ2VzdChcImhleFwiKTtcclxufVxyXG5cclxuZnVuY3Rpb24gaGFzaFNob3J0KHM6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgcmV0dXJuIGNyeXB0by5jcmVhdGVIYXNoKFwic2hhMjU2XCIpLnVwZGF0ZShzLCBcInV0ZjhcIikuZGlnZXN0KFwiaGV4XCIpLnNsaWNlKDAsIDE2KTtcclxufVxyXG5cclxuZnVuY3Rpb24gaXNEYXRlWW1kKHM6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gIHJldHVybiAvXlxcZHs0fS1cXGR7Mn0tXFxkezJ9JC8udGVzdChzKTtcclxufVxyXG5cclxuZnVuY3Rpb24gaXNUaW1lSG0oczogc3RyaW5nKTogYm9vbGVhbiB7XHJcbiAgcmV0dXJuIC9eXFxkezJ9OlxcZHsyfSQvLnRlc3Qocyk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGRhdGVBZGREYXlzKHltZDogc3RyaW5nLCBkZWx0YTogbnVtYmVyKTogc3RyaW5nIHtcclxuICBjb25zdCBkID0gbmV3IERhdGUoYCR7eW1kfVQwMDowMDowMC4wMDBaYCk7XHJcbiAgZC5zZXRVVENEYXRlKGQuZ2V0VVRDRGF0ZSgpICsgZGVsdGEpO1xyXG4gIHJldHVybiBkLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApO1xyXG59XHJcblxyXG5mdW5jdGlvbiB0b0lzb0Zyb21Mb2NhbChkYXRlWW1kOiBzdHJpbmcsIHRpbWVIbTogc3RyaW5nKTogc3RyaW5nIHtcclxuICBjb25zdCBbaGgsIG1tXSA9IHRpbWVIbS5zcGxpdChcIjpcIikubWFwKCh4KSA9PiBOdW1iZXIoeCkpO1xyXG4gIGNvbnN0IGR0ID0gbmV3IERhdGUoZGF0ZVltZCk7XHJcbiAgZHQuc2V0SG91cnMoaGgsIG1tLCAwLCAwKTtcclxuICByZXR1cm4gZHQudG9JU09TdHJpbmcoKTtcclxufVxyXG5cclxuZnVuY3Rpb24gc3BsaXRJc29Ub0RhdGVUaW1lKGlzbzogc3RyaW5nKTogeyBkYXRlOiBzdHJpbmc7IHRpbWU6IHN0cmluZyB9IHtcclxuICBjb25zdCBkID0gbmV3IERhdGUoaXNvKTtcclxuICBjb25zdCB5eXl5ID0gU3RyaW5nKGQuZ2V0RnVsbFllYXIoKSkucGFkU3RhcnQoNCwgXCIwXCIpO1xyXG4gIGNvbnN0IG1tID0gU3RyaW5nKGQuZ2V0TW9udGgoKSArIDEpLnBhZFN0YXJ0KDIsIFwiMFwiKTtcclxuICBjb25zdCBkZCA9IFN0cmluZyhkLmdldERhdGUoKSkucGFkU3RhcnQoMiwgXCIwXCIpO1xyXG4gIGNvbnN0IGhoID0gU3RyaW5nKGQuZ2V0SG91cnMoKSkucGFkU3RhcnQoMiwgXCIwXCIpO1xyXG4gIGNvbnN0IG1pID0gU3RyaW5nKGQuZ2V0TWludXRlcygpKS5wYWRTdGFydCgyLCBcIjBcIik7XHJcbiAgcmV0dXJuIHsgZGF0ZTogYCR7eXl5eX0tJHttbX0tJHtkZH1gLCB0aW1lOiBgJHtoaH06JHttaX1gIH07XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGNsYW1wSW50KHY6IHN0cmluZyB8IG51bGwgfCB1bmRlZmluZWQsIG1pbjogbnVtYmVyLCBtYXg6IG51bWJlciwgZGVmOiBudW1iZXIpOiBudW1iZXIge1xyXG4gIGNvbnN0IG4gPSBOdW1iZXIodik7XHJcbiAgaWYgKCFOdW1iZXIuaXNGaW5pdGUobikpIHJldHVybiBkZWY7XHJcbiAgY29uc3QgaSA9IE1hdGguZmxvb3Iobik7XHJcbiAgcmV0dXJuIE1hdGgubWluKG1heCwgTWF0aC5tYXgobWluLCBpKSk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGNsaWVudElwKGFyZ3M6IHsgcmVxOiBSZXF1ZXN0OyBjb250ZXh0OiBDb250ZXh0IH0pOiBzdHJpbmcge1xyXG4gIGNvbnN0IHZpYUNvbnRleHQgPSAoYXJncy5jb250ZXh0IGFzIGFueSk/LmlwO1xyXG4gIGlmICh0eXBlb2YgdmlhQ29udGV4dCA9PT0gXCJzdHJpbmdcIiAmJiB2aWFDb250ZXh0LnRyaW0oKSkgcmV0dXJuIHZpYUNvbnRleHQudHJpbSgpO1xyXG5cclxuICBjb25zdCBoID0gYXJncy5yZXEuaGVhZGVycztcclxuICBjb25zdCBuZiA9IGguZ2V0KFwieC1uZi1jbGllbnQtY29ubmVjdGlvbi1pcFwiKTtcclxuICBpZiAobmYpIHJldHVybiBuZi5zcGxpdChcIixcIilbMF0udHJpbSgpO1xyXG4gIGNvbnN0IHhmZiA9IGguZ2V0KFwieC1mb3J3YXJkZWQtZm9yXCIpO1xyXG4gIGlmICh4ZmYpIHJldHVybiB4ZmYuc3BsaXQoXCIsXCIpWzBdLnRyaW0oKTtcclxuICByZXR1cm4gXCIwLjAuMC4wXCI7XHJcbn1cclxuXHJcbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gRGV2aWNlIFNuYXBzaG90IFN5bmMgSGVscGVycyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cclxuXHJcbmZ1bmN0aW9uIGlzU2FmZURldmljZUlkKHM6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gIHJldHVybiAvXltBLVphLXowLTlfLV17MSw2NH0kLy50ZXN0KHMpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBzbmFwc2hvdEtleShkZXZpY2VJZDogc3RyaW5nKTogc3RyaW5nIHtcclxuICByZXR1cm4gYHNuYXBzaG90cy8ke2RldmljZUlkfWA7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGFzRGV2aWNlU25hcHNob3QodjogYW55LCBmYWxsYmFja0RldmljZUlkOiBzdHJpbmcpOiBEZXZpY2VTbmFwc2hvdCB8IG51bGwge1xyXG4gIGlmICghdiB8fCB0eXBlb2YgdiAhPT0gXCJvYmplY3RcIikgcmV0dXJuIG51bGw7XHJcblxyXG4gIGNvbnN0IGRldmljZUlkID0gc2FmZVRleHQodi5kZXZpY2VJZCkgfHwgZmFsbGJhY2tEZXZpY2VJZDtcclxuICBjb25zdCBhdCA9IHNhZmVUZXh0KHYuYXQpIHx8IG5vd0lzbygpO1xyXG5cclxuICBjb25zdCBjdXN0b21lcnNSYXcgPSBBcnJheS5pc0FycmF5KHYuY3VzdG9tZXJzKSA/IHYuY3VzdG9tZXJzIDogW107XHJcbiAgY29uc3QgY3VzdG9tZXJzOiBDdXN0b21lcltdID0gY3VzdG9tZXJzUmF3XHJcbiAgICAuZmlsdGVyKChjOiBhbnkpID0+IGMgJiYgdHlwZW9mIGMgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIGMuaWQgPT09IFwic3RyaW5nXCIpXHJcbiAgICAubWFwKChjOiBhbnkpID0+ICh7XHJcbiAgICAgIC4uLmMsXHJcbiAgICAgIGlkOiBTdHJpbmcoYy5pZCksXHJcbiAgICAgIGNyZWF0ZWRBdDogc2FmZVRleHQoYy5jcmVhdGVkQXQpIHx8IG5vd0lzbygpLFxyXG4gICAgICB1cGRhdGVkQXQ6IHNhZmVUZXh0KGMudXBkYXRlZEF0KSB8fCBzYWZlVGV4dChjLmNyZWF0ZWRBdCkgfHwgbm93SXNvKCksXHJcbiAgICB9KSk7XHJcblxyXG4gIGNvbnN0IHRvbWJzdG9uZXNSYXcgPSB2LnRvbWJzdG9uZXMgJiYgdHlwZW9mIHYudG9tYnN0b25lcyA9PT0gXCJvYmplY3RcIiA/IHYudG9tYnN0b25lcyA6IHt9O1xyXG4gIGNvbnN0IHRvbWJzdG9uZXM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fTtcclxuICBmb3IgKGNvbnN0IFtrLCB2YWxdIG9mIE9iamVjdC5lbnRyaWVzKHRvbWJzdG9uZXNSYXcpKSB7XHJcbiAgICBjb25zdCBpZCA9IHNhZmVUZXh0KGspO1xyXG4gICAgY29uc3QgZGVsZXRlZEF0ID0gc2FmZVRleHQodmFsKTtcclxuICAgIGlmIChpZCAmJiBkZWxldGVkQXQpIHRvbWJzdG9uZXNbaWRdID0gZGVsZXRlZEF0O1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHsgZGV2aWNlSWQsIGF0LCBjdXN0b21lcnMsIHRvbWJzdG9uZXMgfTtcclxufVxyXG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUdBLG1CQUF5QjtBQUN6Qix5QkFBbUI7QUFFWixJQUFNLFNBQWlCO0FBQUEsRUFDNUIsTUFBTTtBQUNSO0FBcUdBLElBQU0sYUFBYTtBQUNuQixJQUFNLGNBQXdCO0FBRTlCLGVBQU8sUUFBK0IsS0FBYyxTQUFrQjtBQUNwRSxRQUFNLE1BQU0sSUFBSSxJQUFJLElBQUksR0FBRztBQUMzQixRQUFNLE9BQU8saUJBQWlCLElBQUksUUFBUTtBQUUxQyxRQUFNLE1BQU0sWUFBWTtBQUN4QixRQUFNLFNBQVMsSUFBSSxRQUFRLElBQUksUUFBUSxLQUFLO0FBQzVDLFFBQU0sT0FBTyxJQUFJLFFBQVEsSUFBSSxnQ0FBZ0MsS0FBSztBQUNsRSxRQUFNLGNBQWMsaUJBQWlCLEtBQUssUUFBUSxJQUFJO0FBR3RELE1BQUksU0FBUyxpQkFBaUIsSUFBSSxXQUFXLE9BQU87QUFD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S0FBSztBQUN6QyxRQUFNLEtBQUssU0FBUyxFQUFFLEVBQUUsS0FBSyxPQUFPO0FBRXBDLFFBQU0sZUFBZSxNQUFNLFFBQVEsRUFBRSxTQUFTLElBQUksRUFBRSxZQUFZLENBQUM7QUFDakUsUUFBTSxZQUF3QixhQUMzQixPQUFPLENBQUMsTUFBVyxLQUFLLE9BQU8sTUFBTSxZQUFZLE9BQU8sRUFBRSxPQUFPLFFBQVEsRUFDekUsSUFBSSxDQUFDLE9BQVk7QUFBQSxJQUNoQixHQUFHO0FBQUEsSUFDSCxJQUFJLE9BQU8sRUFBRSxFQUFFO0FBQUEsSUFDZixXQUFXLFNBQVMsRUFBRSxTQUFTLEtBQUssT0FBTztBQUFBLElBQzNDLFdBQVcsU0FBUyxFQUFFLFNBQVMsS0FBSyxTQUFTLEVBQUUsU0FBUyxLQUFLLE9BQU87QUFBQSxFQUN0RSxFQUFFO0FBRUosUUFBTSxnQkFBZ0IsRUFBRSxjQUFjLE9BQU8sRUFBRSxlQUFlLFdBQVcsRUFBRSxhQUFhLENBQUM7QUFDekYsUUFBTSxhQUFxQyxDQUFDO0FBQzVDLGFBQVcsQ0FBQyxHQUFHLEdBQUcsS0FBSyxPQUFPLFFBQVEsYUFBYSxHQUFHO0FBQ3BELFVBQU0sS0FBSyxTQUFTLENBQUM7QUFDckIsVUFBTSxZQUFZLFNBQVMsR0FBRztBQUM5QixRQUFJLE1BQU0sVUFBVyxZQUFXLEVBQUUsSUFBSTtBQUFBLEVBQ3hDO0FBRUEsU0FBTyxFQUFFLFVBQVUsSUFBSSxXQUFXLFdBQVc7QUFDL0M7IiwKICAibmFtZXMiOiBbImNyeXB0byIsICJuZXh0IiwgInJlcyIsICJuZXh0IiwgInJlcyIsICJjcnlwdG8iXQp9Cg==
