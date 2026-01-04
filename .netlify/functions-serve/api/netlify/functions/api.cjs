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
  const env = readEnv();
  const origin = req.headers.get("origin") ?? "";
  const corsHeaders = buildCorsHeaders(env, origin);
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  try {
    const url = new URL(req.url);
    const path = normalizeApiPath(url.pathname);
    const store = (0, import_blobs.getStore)({ name: STORE_NAME, consistency: CONSISTENCY });
    const routeResult = await route({ req, context, env, store, url, path, corsHeaders });
    return routeResult;
  } catch (err) {
    const body = json({ error: "internal_error" });
    return new Response(body, {
      status: 500,
      headers: { "content-type": "application/json; charset=utf-8" }
    });
  }
}
async function route(args) {
  const { req, env, store, url, path } = args;
  if (path === "/api/health" && req.method === "GET") {
    return respondJson({ ok: true }, 200, args.corsHeaders);
  }
  if (path === "/api/auth/login" && req.method === "POST") {
    const body = await safeJson(req);
    const username = asString(body?.username);
    const password = asString(body?.password);
    if (!username || !password) return respondJson({ error: "missing_credentials" }, 400, args.corsHeaders);
    const user = await verifyUser(env, username, password);
    if (!user) return respondJson({ error: "invalid_credentials" }, 401, args.corsHeaders);
    const token = signJwt(env.jwtSecret, {
      sub: username,
      role: user.role,
      iat: nowSec(),
      exp: nowSec() + 60 * 60 * 12
    });
    return respondJson({ token, role: user.role }, 200, args.corsHeaders);
  }
  if (path === "/api/public/inquiries" && req.method === "POST") {
    const ip = clientIp(args);
    const limited = await rateLimit(store, ip, env.publicDailyRateLimit);
    if (!limited.ok) return respondJson({ error: "rate_limited" }, 429, args.corsHeaders);
    const body = await safeJson(req);
    const honeypot = asString(body?.website);
    if (honeypot) return respondJson({ ok: true }, 200, args.corsHeaders);
    const name = requiredString(body?.name);
    if (!name) return respondJson({ error: "missing_name" }, 400, args.corsHeaders);
    const lead = {
      id: import_node_crypto.default.randomUUID(),
      createdAt: nowIso(),
      updatedAt: nowIso(),
      source: "public",
      status: "new",
      name,
      phone: optionalString(body?.phone),
      email: optionalString(body?.email),
      service: optionalString(body?.service),
      notes: optionalString(body?.notes),
      preferredDate: optionalString(body?.preferredDate),
      preferredTime: optionalString(body?.preferredTime),
      timeline: [{ at: nowIso(), type: "created" }]
    };
    await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
    await store.setJSON(`indexes/leads/${lead.createdAt}_${lead.id}`, { id: lead.id, createdAt: lead.createdAt }, { onlyIfNew: true });
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
  if (path.startsWith("/api/crm/")) {
    const auth = requireAuth(env, req.headers.get("authorization") ?? "");
    if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, args.corsHeaders);
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
          const next = {
            ...lead,
            updatedAt: nowIso(),
            status: status ?? lead.status,
            notes: notes ?? lead.notes,
            followUpAt: followUpAt ?? lead.followUpAt,
            assignedTo: assignedTo ?? lead.assignedTo,
            timeline: [...lead.timeline, { at: nowIso(), type: "updated" }]
          };
          return next;
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
function buildSlots(env, date) {
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
  const key = `ratelimit/${day}/${hashShort(ip)}`;
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
async function patchLead(store, id, updater) {
  for (let i = 0; i < 5; i += 1) {
    const existing = await store.getWithMetadata(`leads/${id}`, { type: "json" });
    if (!existing) return false;
    const next = updater(existing.data);
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
    const idx = await store.get(k, { type: "json" });
    if (!idx?.id) continue;
    const lead = await store.get(`leads/${idx.id}`, { type: "json" });
    if (!lead) continue;
    if (opts.status && lead.status !== opts.status) continue;
    if (opts.q && !matchesQuery(lead, opts.q)) continue;
    leads.push(lead);
  }
  return leads;
}
function matchesQuery(lead, q) {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const hay = [
    lead.id,
    lead.name,
    lead.email ?? "",
    lead.phone ?? "",
    lead.service ?? "",
    lead.notes ?? "",
    lead.status
  ].join(" ").toLowerCase();
  return hay.includes(needle);
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
  return { exportedAt: nowIso(), leads, appointments, slots };
}
async function importSnapshot(store, snapshot) {
  await deleteByPrefix(store, "leads/");
  await deleteByPrefix(store, "appointments/");
  await deleteByPrefix(store, "slots/");
  await deleteByPrefix(store, "indexes/leads/");
  for (const lead of snapshot.leads ?? []) {
    await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
    await store.setJSON(`indexes/leads/${lead.createdAt}_${lead.id}`, { id: lead.id, createdAt: lead.createdAt }, { onlyIfNew: true });
  }
  for (const appt of snapshot.appointments ?? []) {
    await store.setJSON(`appointments/${appt.id}`, appt, { onlyIfNew: true });
  }
  const slots = snapshot.slots ?? {};
  for (const [k, v] of Object.entries(slots)) {
    await store.setJSON(k, v, { onlyIfNew: true });
  }
}
async function deleteByPrefix(store, prefix) {
  const { blobs } = await store.list({ prefix });
  for (const b of blobs) await store.delete(b.key);
}
function requireAuth(env, authHeader) {
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice("Bearer ".length).trim() : "";
  if (!token) return { ok: false };
  const payload = verifyJwt(env.jwtSecret, token);
  if (!payload) return { ok: false };
  return { ok: true, payload };
}
async function verifyUser(env, username, password) {
  if (env.crmUsersJson) {
    try {
      const parsed = JSON.parse(env.crmUsersJson);
      const u = parsed.find((x) => x.username === username);
      if (!u) return null;
      if (!verifyScryptPassword(password, u.passwordHash)) return null;
      return { role: u.role ?? "staff" };
    } catch {
      return null;
    }
  }
  if (env.adminUser && username === env.adminUser) {
    if (env.adminPasswordHash) {
      if (!verifyScryptPassword(password, env.adminPasswordHash)) return null;
      return { role: "admin" };
    }
    if (env.adminPassword && password === env.adminPassword) return { role: "admin" };
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
function verifyScryptPassword(password, encoded) {
  const parts = encoded.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4], "base64");
  const dk = Buffer.from(parts[5], "base64");
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;
  const derived = import_node_crypto.default.scryptSync(password, salt, dk.length, { N, r, p });
  return import_node_crypto.default.timingSafeEqual(derived, dk);
}
function readEnv() {
  const jwtSecret = Netlify.env.get("JWT_SECRET") ?? process.env.JWT_SECRET ?? "";
  if (!jwtSecret) {
    throw new Error("Missing JWT_SECRET");
  }
  const allowedOriginsRaw = Netlify.env.get("ALLOWED_ORIGINS") ?? process.env.ALLOWED_ORIGINS ?? "";
  const allowedOrigins = allowedOriginsRaw.trim().length > 0 ? allowedOriginsRaw.split(",").map((s) => s.trim()).filter(Boolean) : null;
  const crmUsersJson = Netlify.env.get("CRM_USERS_JSON") ?? process.env.CRM_USERS_JSON ?? null;
  const adminUser = Netlify.env.get("CRM_ADMIN_USER") ?? process.env.CRM_ADMIN_USER ?? null;
  const adminPassword = Netlify.env.get("CRM_ADMIN_PASSWORD") ?? process.env.CRM_ADMIN_PASSWORD ?? null;
  const adminPasswordHash = Netlify.env.get("CRM_ADMIN_PASSWORD_HASH") ?? process.env.CRM_ADMIN_PASSWORD_HASH ?? null;
  const slotMinutes = clampInt(Netlify.env.get("SLOT_MINUTES") ?? process.env.SLOT_MINUTES, 10, 240, 30);
  const openHour = clampInt(Netlify.env.get("OPEN_HOUR") ?? process.env.OPEN_HOUR, 0, 23, 9);
  const closeHour = clampInt(Netlify.env.get("CLOSE_HOUR") ?? process.env.CLOSE_HOUR, 1, 24, 17);
  const capacityPerSlot = clampInt(Netlify.env.get("CAPACITY_PER_SLOT") ?? process.env.CAPACITY_PER_SLOT, 1, 50, 1);
  const tz = Netlify.env.get("TZ") ?? process.env.TZ ?? "America/Los_Angeles";
  const publicDailyRateLimit = clampInt(Netlify.env.get("PUBLIC_DAILY_RATE_LIMIT") ?? process.env.PUBLIC_DAILY_RATE_LIMIT, 1, 1e4, 200);
  return {
    jwtSecret,
    allowedOrigins,
    crmUsersJson,
    adminUser,
    adminPassword,
    adminPasswordHash,
    slotMinutes,
    openHour,
    closeHour,
    capacityPerSlot,
    tz,
    publicDailyRateLimit
  };
}
function buildCorsHeaders(env, origin) {
  const h = new Headers();
  const allowOrigin = env.allowedOrigins === null ? "*" : env.allowedOrigins.includes(origin) ? origin : "";
  h.set("access-control-allow-origin", allowOrigin);
  h.set("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS");
  h.set("access-control-allow-headers", "content-type,authorization");
  h.set("access-control-max-age", "86400");
  if (allowOrigin && allowOrigin !== "*") h.set("vary", "origin");
  return h;
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
function hashShort(s) {
  return import_node_crypto.default.createHash("sha256").update(s).digest("hex").slice(0, 16);
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  config
});
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsibmV0bGlmeS9mdW5jdGlvbnMvYXBpLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvKiBGaWxlOiBuZXRsaWZ5L2Z1bmN0aW9ucy9hcGkubXRzICovXHJcblxyXG5pbXBvcnQgdHlwZSB7IENvbmZpZywgQ29udGV4dCB9IGZyb20gXCJAbmV0bGlmeS9mdW5jdGlvbnNcIjtcclxuaW1wb3J0IHsgZ2V0U3RvcmUgfSBmcm9tIFwiQG5ldGxpZnkvYmxvYnNcIjtcclxuaW1wb3J0IGNyeXB0byBmcm9tIFwibm9kZTpjcnlwdG9cIjtcclxuXHJcbmV4cG9ydCBjb25zdCBjb25maWc6IENvbmZpZyA9IHtcclxuICBwYXRoOiBcIi9hcGkvKlwiLFxyXG59O1xyXG5cclxudHlwZSBKc29uVmFsdWUgPSBudWxsIHwgYm9vbGVhbiB8IG51bWJlciB8IHN0cmluZyB8IEpzb25WYWx1ZVtdIHwgeyBbazogc3RyaW5nXTogSnNvblZhbHVlIH07XHJcblxyXG50eXBlIExlYWRTdGF0dXMgPSBcIm5ld1wiIHwgXCJmb2xsb3dfdXBcIiB8IFwiYXBwb2ludG1lbnRcIiB8IFwibGFuZGVkXCIgfCBcIm5vXCIgfCBcImFyY2hpdmVkXCI7XHJcbnR5cGUgQXBwb2ludG1lbnRTdGF0dXMgPSBcImJvb2tlZFwiIHwgXCJjYW5jZWxlZFwiIHwgXCJjb21wbGV0ZWRcIjtcclxuXHJcbnR5cGUgTGVhZCA9IHtcclxuICBpZDogc3RyaW5nO1xyXG4gIGNyZWF0ZWRBdDogc3RyaW5nO1xyXG4gIHVwZGF0ZWRBdDogc3RyaW5nO1xyXG4gIHNvdXJjZTogXCJwdWJsaWNcIjtcclxuICBzdGF0dXM6IExlYWRTdGF0dXM7XHJcbiAgbmFtZTogc3RyaW5nO1xyXG4gIHBob25lPzogc3RyaW5nO1xyXG4gIGVtYWlsPzogc3RyaW5nO1xyXG4gIHNlcnZpY2U/OiBzdHJpbmc7XHJcbiAgbm90ZXM/OiBzdHJpbmc7XHJcbiAgcHJlZmVycmVkRGF0ZT86IHN0cmluZztcclxuICBwcmVmZXJyZWRUaW1lPzogc3RyaW5nO1xyXG4gIGZvbGxvd1VwQXQ/OiBzdHJpbmc7XHJcbiAgYXNzaWduZWRUbz86IHN0cmluZztcclxuICB0aW1lbGluZTogQXJyYXk8eyBhdDogc3RyaW5nOyB0eXBlOiBzdHJpbmc7IG5vdGU/OiBzdHJpbmcgfT47XHJcbn07XHJcblxyXG50eXBlIEFwcG9pbnRtZW50ID0ge1xyXG4gIGlkOiBzdHJpbmc7XHJcbiAgY3JlYXRlZEF0OiBzdHJpbmc7XHJcbiAgdXBkYXRlZEF0OiBzdHJpbmc7XHJcbiAgc3RhdHVzOiBBcHBvaW50bWVudFN0YXR1cztcclxuICBzZXJ2aWNlOiBzdHJpbmc7XHJcbiAgc3RhcnRBdDogc3RyaW5nO1xyXG4gIGVuZEF0OiBzdHJpbmc7XHJcbiAgY3VzdG9tZXI6IHsgbmFtZTogc3RyaW5nOyBwaG9uZT86IHN0cmluZzsgZW1haWw/OiBzdHJpbmcgfTtcclxuICBub3Rlcz86IHN0cmluZztcclxuICBsZWFkSWQ/OiBzdHJpbmc7XHJcbn07XHJcblxyXG50eXBlIEp3dFBheWxvYWQgPSB7XHJcbiAgc3ViOiBzdHJpbmc7XHJcbiAgcm9sZTogXCJhZG1pblwiIHwgXCJzdGFmZlwiO1xyXG4gIGlhdDogbnVtYmVyO1xyXG4gIGV4cDogbnVtYmVyO1xyXG59O1xyXG5cclxudHlwZSBTbG90TG9jayA9IHsgaWRzOiBzdHJpbmdbXSB9O1xyXG5cclxudHlwZSBFbnZDb25maWcgPSB7XHJcbiAgand0U2VjcmV0OiBzdHJpbmc7XHJcbiAgYWxsb3dlZE9yaWdpbnM6IHN0cmluZ1tdIHwgbnVsbDtcclxuICBjcm1Vc2Vyc0pzb246IHN0cmluZyB8IG51bGw7XHJcbiAgYWRtaW5Vc2VyOiBzdHJpbmcgfCBudWxsO1xyXG4gIGFkbWluUGFzc3dvcmQ6IHN0cmluZyB8IG51bGw7XHJcbiAgYWRtaW5QYXNzd29yZEhhc2g6IHN0cmluZyB8IG51bGw7XHJcbiAgc2xvdE1pbnV0ZXM6IG51bWJlcjtcclxuICBvcGVuSG91cjogbnVtYmVyO1xyXG4gIGNsb3NlSG91cjogbnVtYmVyO1xyXG4gIGNhcGFjaXR5UGVyU2xvdDogbnVtYmVyO1xyXG4gIHR6OiBzdHJpbmc7XHJcbiAgcHVibGljRGFpbHlSYXRlTGltaXQ6IG51bWJlcjtcclxufTtcclxuXHJcbmNvbnN0IFNUT1JFX05BTUUgPSBcImNybVwiO1xyXG5jb25zdCBDT05TSVNURU5DWTogXCJzdHJvbmdcIiA9IFwic3Ryb25nXCI7XHJcblxyXG5leHBvcnQgZGVmYXVsdCBhc3luYyBmdW5jdGlvbiBoYW5kbGVyKHJlcTogUmVxdWVzdCwgY29udGV4dDogQ29udGV4dCkge1xyXG4gIGNvbnN0IGVudiA9IHJlYWRFbnYoKTtcclxuICBjb25zdCBvcmlnaW4gPSByZXEuaGVhZGVycy5nZXQoXCJvcmlnaW5cIikgPz8gXCJcIjtcclxuICBjb25zdCBjb3JzSGVhZGVycyA9IGJ1aWxkQ29yc0hlYWRlcnMoZW52LCBvcmlnaW4pO1xyXG5cclxuICBpZiAocmVxLm1ldGhvZCA9PT0gXCJPUFRJT05TXCIpIHtcclxuICAgIHJldHVybiBuZXcgUmVzcG9uc2UobnVsbCwgeyBzdGF0dXM6IDIwNCwgaGVhZGVyczogY29yc0hlYWRlcnMgfSk7XHJcbiAgfVxyXG5cclxuICB0cnkge1xyXG4gICAgY29uc3QgdXJsID0gbmV3IFVSTChyZXEudXJsKTtcclxuICAgIGNvbnN0IHBhdGggPSBub3JtYWxpemVBcGlQYXRoKHVybC5wYXRobmFtZSk7XHJcbiAgICBjb25zdCBzdG9yZSA9IGdldFN0b3JlKHsgbmFtZTogU1RPUkVfTkFNRSwgY29uc2lzdGVuY3k6IENPTlNJU1RFTkNZIH0pO1xyXG5cclxuICAgIGNvbnN0IHJvdXRlUmVzdWx0ID0gYXdhaXQgcm91dGUoeyByZXEsIGNvbnRleHQsIGVudiwgc3RvcmUsIHVybCwgcGF0aCwgY29yc0hlYWRlcnMgfSk7XHJcbiAgICByZXR1cm4gcm91dGVSZXN1bHQ7XHJcbiAgfSBjYXRjaCAoZXJyKSB7XHJcbiAgICBjb25zdCBib2R5ID0ganNvbih7IGVycm9yOiBcImludGVybmFsX2Vycm9yXCIgfSk7XHJcbiAgICByZXR1cm4gbmV3IFJlc3BvbnNlKGJvZHksIHtcclxuICAgICAgc3RhdHVzOiA1MDAsXHJcbiAgICAgIGhlYWRlcnM6IHsgXCJjb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PXV0Zi04XCIgfSxcclxuICAgIH0pO1xyXG4gIH1cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gcm91dGUoYXJnczoge1xyXG4gIHJlcTogUmVxdWVzdDtcclxuICBjb250ZXh0OiBDb250ZXh0O1xyXG4gIGVudjogRW52Q29uZmlnO1xyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT47XHJcbiAgdXJsOiBVUkw7XHJcbiAgcGF0aDogc3RyaW5nO1xyXG4gIGNvcnNIZWFkZXJzOiBIZWFkZXJzO1xyXG59KTogUHJvbWlzZTxSZXNwb25zZT4ge1xyXG4gIGNvbnN0IHsgcmVxLCBlbnYsIHN0b3JlLCB1cmwsIHBhdGggfSA9IGFyZ3M7XHJcblxyXG4gIGlmIChwYXRoID09PSBcIi9hcGkvaGVhbHRoXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJHRVRcIikge1xyXG4gICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICB9XHJcblxyXG4gIGlmIChwYXRoID09PSBcIi9hcGkvYXV0aC9sb2dpblwiICYmIHJlcS5tZXRob2QgPT09IFwiUE9TVFwiKSB7XHJcbiAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuICAgIGNvbnN0IHVzZXJuYW1lID0gYXNTdHJpbmcoYm9keT8udXNlcm5hbWUpO1xyXG4gICAgY29uc3QgcGFzc3dvcmQgPSBhc1N0cmluZyhib2R5Py5wYXNzd29yZCk7XHJcbiAgICBpZiAoIXVzZXJuYW1lIHx8ICFwYXNzd29yZCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibWlzc2luZ19jcmVkZW50aWFsc1wiIH0sIDQwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3QgdXNlciA9IGF3YWl0IHZlcmlmeVVzZXIoZW52LCB1c2VybmFtZSwgcGFzc3dvcmQpO1xyXG4gICAgaWYgKCF1c2VyKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJpbnZhbGlkX2NyZWRlbnRpYWxzXCIgfSwgNDAxLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCB0b2tlbiA9IHNpZ25Kd3QoZW52Lmp3dFNlY3JldCwge1xyXG4gICAgICBzdWI6IHVzZXJuYW1lLFxyXG4gICAgICByb2xlOiB1c2VyLnJvbGUsXHJcbiAgICAgIGlhdDogbm93U2VjKCksXHJcbiAgICAgIGV4cDogbm93U2VjKCkgKyA2MCAqIDYwICogMTIsXHJcbiAgICB9KTtcclxuXHJcbiAgICByZXR1cm4gcmVzcG9uZEpzb24oeyB0b2tlbiwgcm9sZTogdXNlci5yb2xlIH0sIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgfVxyXG5cclxuICBpZiAocGF0aCA9PT0gXCIvYXBpL3B1YmxpYy9pbnF1aXJpZXNcIiAmJiByZXEubWV0aG9kID09PSBcIlBPU1RcIikge1xyXG4gICAgY29uc3QgaXAgPSBjbGllbnRJcChhcmdzKTtcclxuICAgIGNvbnN0IGxpbWl0ZWQgPSBhd2FpdCByYXRlTGltaXQoc3RvcmUsIGlwLCBlbnYucHVibGljRGFpbHlSYXRlTGltaXQpO1xyXG4gICAgaWYgKCFsaW1pdGVkLm9rKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJyYXRlX2xpbWl0ZWRcIiB9LCA0MjksIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBzYWZlSnNvbihyZXEpO1xyXG4gICAgY29uc3QgaG9uZXlwb3QgPSBhc1N0cmluZyhib2R5Py53ZWJzaXRlKTtcclxuICAgIGlmIChob25leXBvdCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBuYW1lID0gcmVxdWlyZWRTdHJpbmcoYm9keT8ubmFtZSk7XHJcbiAgICBpZiAoIW5hbWUpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm1pc3NpbmdfbmFtZVwiIH0sIDQwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3QgbGVhZDogTGVhZCA9IHtcclxuICAgICAgaWQ6IGNyeXB0by5yYW5kb21VVUlEKCksXHJcbiAgICAgIGNyZWF0ZWRBdDogbm93SXNvKCksXHJcbiAgICAgIHVwZGF0ZWRBdDogbm93SXNvKCksXHJcbiAgICAgIHNvdXJjZTogXCJwdWJsaWNcIixcclxuICAgICAgc3RhdHVzOiBcIm5ld1wiLFxyXG4gICAgICBuYW1lLFxyXG4gICAgICBwaG9uZTogb3B0aW9uYWxTdHJpbmcoYm9keT8ucGhvbmUpLFxyXG4gICAgICBlbWFpbDogb3B0aW9uYWxTdHJpbmcoYm9keT8uZW1haWwpLFxyXG4gICAgICBzZXJ2aWNlOiBvcHRpb25hbFN0cmluZyhib2R5Py5zZXJ2aWNlKSxcclxuICAgICAgbm90ZXM6IG9wdGlvbmFsU3RyaW5nKGJvZHk/Lm5vdGVzKSxcclxuICAgICAgcHJlZmVycmVkRGF0ZTogb3B0aW9uYWxTdHJpbmcoYm9keT8ucHJlZmVycmVkRGF0ZSksXHJcbiAgICAgIHByZWZlcnJlZFRpbWU6IG9wdGlvbmFsU3RyaW5nKGJvZHk/LnByZWZlcnJlZFRpbWUpLFxyXG4gICAgICB0aW1lbGluZTogW3sgYXQ6IG5vd0lzbygpLCB0eXBlOiBcImNyZWF0ZWRcIiB9XSxcclxuICAgIH07XHJcblxyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihgbGVhZHMvJHtsZWFkLmlkfWAsIGxlYWQsIHsgb25seUlmTmV3OiB0cnVlIH0pO1xyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihgaW5kZXhlcy9sZWFkcy8ke2xlYWQuY3JlYXRlZEF0fV8ke2xlYWQuaWR9YCwgeyBpZDogbGVhZC5pZCwgY3JlYXRlZEF0OiBsZWFkLmNyZWF0ZWRBdCB9LCB7IG9ubHlJZk5ldzogdHJ1ZSB9KTtcclxuXHJcbiAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSwgbGVhZElkOiBsZWFkLmlkIH0sIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgfVxyXG5cclxuICBpZiAocGF0aCA9PT0gXCIvYXBpL3B1YmxpYy9hdmFpbGFiaWxpdHlcIiAmJiByZXEubWV0aG9kID09PSBcIkdFVFwiKSB7XHJcbiAgICBjb25zdCBkYXRlID0gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJkYXRlXCIpID8/IFwiXCI7XHJcbiAgICBpZiAoIWlzRGF0ZVltZChkYXRlKSkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiaW52YWxpZF9kYXRlXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICBjb25zdCBzZXJ2aWNlID0gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJzZXJ2aWNlXCIpID8/IFwiZGVmYXVsdFwiO1xyXG4gICAgY29uc3Qgc2xvdHMgPSBhd2FpdCBjb21wdXRlQXZhaWxhYmlsaXR5KHN0b3JlLCBlbnYsIGRhdGUsIHNlcnZpY2UpO1xyXG5cclxuICAgIHJldHVybiByZXNwb25kSnNvbih7IGRhdGUsIHNlcnZpY2UsIHNsb3RzIH0sIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgfVxyXG5cclxuICBpZiAocGF0aCA9PT0gXCIvYXBpL3B1YmxpYy9ib29raW5nc1wiICYmIHJlcS5tZXRob2QgPT09IFwiUE9TVFwiKSB7XHJcbiAgICBjb25zdCBpcCA9IGNsaWVudElwKGFyZ3MpO1xyXG4gICAgY29uc3QgbGltaXRlZCA9IGF3YWl0IHJhdGVMaW1pdChzdG9yZSwgaXAsIGVudi5wdWJsaWNEYWlseVJhdGVMaW1pdCk7XHJcbiAgICBpZiAoIWxpbWl0ZWQub2spIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcInJhdGVfbGltaXRlZFwiIH0sIDQyOSwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3QgYm9keSA9IGF3YWl0IHNhZmVKc29uKHJlcSk7XHJcbiAgICBjb25zdCBuYW1lID0gcmVxdWlyZWRTdHJpbmcoYm9keT8ubmFtZSk7XHJcbiAgICBjb25zdCBzZXJ2aWNlID0gcmVxdWlyZWRTdHJpbmcoYm9keT8uc2VydmljZSkgPz8gXCJkZWZhdWx0XCI7XHJcbiAgICBjb25zdCBkYXRlID0gcmVxdWlyZWRTdHJpbmcoYm9keT8uZGF0ZSk7XHJcbiAgICBjb25zdCB0aW1lID0gcmVxdWlyZWRTdHJpbmcoYm9keT8udGltZSk7XHJcblxyXG4gICAgaWYgKCFuYW1lKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNzaW5nX25hbWVcIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgaWYgKCFpc0RhdGVZbWQoZGF0ZSkpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcImludmFsaWRfZGF0ZVwiIH0sIDQwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICBpZiAoIWlzVGltZUhtKHRpbWUpKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJpbnZhbGlkX3RpbWVcIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGNvbnN0IHN0YXJ0QXQgPSB0b0lzb0Zyb21Mb2NhbChkYXRlLCB0aW1lKTtcclxuICAgIGNvbnN0IGVuZEF0ID0gbmV3IERhdGUobmV3IERhdGUoc3RhcnRBdCkuZ2V0VGltZSgpICsgZW52LnNsb3RNaW51dGVzICogNjBfMDAwKS50b0lTT1N0cmluZygpO1xyXG5cclxuICAgIGNvbnN0IGFwcG9pbnRtZW50SWQgPSBjcnlwdG8ucmFuZG9tVVVJRCgpO1xyXG4gICAgY29uc3Qgc2xvdEtleSA9IHNsb3RMb2NrS2V5KGRhdGUsIHRpbWUsIHNlcnZpY2UpO1xyXG5cclxuICAgIGNvbnN0IHJlc2VydmVkID0gYXdhaXQgcmVzZXJ2ZVNsb3Qoc3RvcmUsIHNsb3RLZXksIGFwcG9pbnRtZW50SWQsIGVudi5jYXBhY2l0eVBlclNsb3QpO1xyXG4gICAgaWYgKCFyZXNlcnZlZC5vaykgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwic2xvdF91bmF2YWlsYWJsZVwiIH0sIDQwOSwgYXJncy5jb3JzSGVhZGVycyk7XHJcblxyXG4gICAgY29uc3QgYXBwdDogQXBwb2ludG1lbnQgPSB7XHJcbiAgICAgIGlkOiBhcHBvaW50bWVudElkLFxyXG4gICAgICBjcmVhdGVkQXQ6IG5vd0lzbygpLFxyXG4gICAgICB1cGRhdGVkQXQ6IG5vd0lzbygpLFxyXG4gICAgICBzdGF0dXM6IFwiYm9va2VkXCIsXHJcbiAgICAgIHNlcnZpY2UsXHJcbiAgICAgIHN0YXJ0QXQsXHJcbiAgICAgIGVuZEF0LFxyXG4gICAgICBjdXN0b21lcjoge1xyXG4gICAgICAgIG5hbWUsXHJcbiAgICAgICAgcGhvbmU6IG9wdGlvbmFsU3RyaW5nKGJvZHk/LnBob25lKSxcclxuICAgICAgICBlbWFpbDogb3B0aW9uYWxTdHJpbmcoYm9keT8uZW1haWwpLFxyXG4gICAgICB9LFxyXG4gICAgICBub3Rlczogb3B0aW9uYWxTdHJpbmcoYm9keT8ubm90ZXMpLFxyXG4gICAgICBsZWFkSWQ6IG9wdGlvbmFsU3RyaW5nKGJvZHk/LmxlYWRJZCksXHJcbiAgICB9O1xyXG5cclxuICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBzdG9yZS5zZXRKU09OKGBhcHBvaW50bWVudHMvJHthcHB0LmlkfWAsIGFwcHQsIHsgb25seUlmTmV3OiB0cnVlIH0pO1xyXG4gICAgaWYgKCFjcmVhdGVkLm1vZGlmaWVkKSB7XHJcbiAgICAgIGF3YWl0IHJlbGVhc2VTbG90KHN0b3JlLCBzbG90S2V5LCBhcHBvaW50bWVudElkKTtcclxuICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiYm9va2luZ19mYWlsZWRcIiB9LCA1MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChhcHB0LmxlYWRJZCkge1xyXG4gICAgICBhd2FpdCBwYXRjaExlYWQoc3RvcmUsIGFwcHQubGVhZElkLCAobGVhZCkgPT4gKHtcclxuICAgICAgICAuLi5sZWFkLFxyXG4gICAgICAgIHN0YXR1czogbGVhZC5zdGF0dXMgPT09IFwibGFuZGVkXCIgPyBsZWFkLnN0YXR1cyA6IFwiYXBwb2ludG1lbnRcIixcclxuICAgICAgICB1cGRhdGVkQXQ6IG5vd0lzbygpLFxyXG4gICAgICAgIHRpbWVsaW5lOiBbLi4ubGVhZC50aW1lbGluZSwgeyBhdDogbm93SXNvKCksIHR5cGU6IFwiYXBwb2ludG1lbnRfY3JlYXRlZFwiLCBub3RlOiBhcHB0LmlkIH1dLFxyXG4gICAgICB9KSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHJlc3BvbmRKc29uKFxyXG4gICAgICB7XHJcbiAgICAgICAgb2s6IHRydWUsXHJcbiAgICAgICAgYXBwb2ludG1lbnRJZDogYXBwdC5pZCxcclxuICAgICAgICBzdGFydEF0OiBhcHB0LnN0YXJ0QXQsXHJcbiAgICAgICAgZW5kQXQ6IGFwcHQuZW5kQXQsXHJcbiAgICAgIH0sXHJcbiAgICAgIDIwMCxcclxuICAgICAgYXJncy5jb3JzSGVhZGVycyxcclxuICAgICk7XHJcbiAgfVxyXG5cclxuICBpZiAocGF0aC5zdGFydHNXaXRoKFwiL2FwaS9jcm0vXCIpKSB7XHJcbiAgICBjb25zdCBhdXRoID0gcmVxdWlyZUF1dGgoZW52LCByZXEuaGVhZGVycy5nZXQoXCJhdXRob3JpemF0aW9uXCIpID8/IFwiXCIpO1xyXG4gICAgaWYgKCFhdXRoLm9rKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJ1bmF1dGhvcml6ZWRcIiB9LCA0MDEsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgIGlmIChwYXRoID09PSBcIi9hcGkvY3JtL2xlYWRzXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJHRVRcIikge1xyXG4gICAgICBjb25zdCBzdGF0dXMgPSB1cmwuc2VhcmNoUGFyYW1zLmdldChcInN0YXR1c1wiKTtcclxuICAgICAgY29uc3QgcSA9IHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwicVwiKTtcclxuICAgICAgY29uc3QgbGltaXQgPSBjbGFtcEludCh1cmwuc2VhcmNoUGFyYW1zLmdldChcImxpbWl0XCIpLCAxLCAyMDAsIDUwKTtcclxuXHJcbiAgICAgIGNvbnN0IGxlYWRzID0gYXdhaXQgbGlzdExlYWRzKHN0b3JlLCB7IHN0YXR1czogc3RhdHVzID8/IHVuZGVmaW5lZCwgcTogcSA/PyB1bmRlZmluZWQsIGxpbWl0IH0pO1xyXG4gICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBsZWFkcyB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChwYXRoLnN0YXJ0c1dpdGgoXCIvYXBpL2NybS9sZWFkcy9cIikpIHtcclxuICAgICAgY29uc3QgaWQgPSBwYXRoLnNwbGl0KFwiL1wiKS5wb3AoKSA/PyBcIlwiO1xyXG4gICAgICBpZiAoIWlkKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNzaW5nX2lkXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIGlmIChyZXEubWV0aG9kID09PSBcIkdFVFwiKSB7XHJcbiAgICAgICAgY29uc3QgbGVhZCA9IChhd2FpdCBzdG9yZS5nZXQoYGxlYWRzLyR7aWR9YCwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgTGVhZCB8IG51bGw7XHJcbiAgICAgICAgaWYgKCFsZWFkKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJub3RfZm91bmRcIiB9LCA0MDQsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgICAgIHJldHVybiByZXNwb25kSnNvbih7IGxlYWQgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKHJlcS5tZXRob2QgPT09IFwiUFVUXCIpIHtcclxuICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuICAgICAgICBjb25zdCBzdGF0dXMgPSBvcHRpb25hbFN0cmluZyhib2R5Py5zdGF0dXMpIGFzIExlYWRTdGF0dXMgfCB1bmRlZmluZWQ7XHJcbiAgICAgICAgY29uc3Qgbm90ZXMgPSBvcHRpb25hbFN0cmluZyhib2R5Py5ub3Rlcyk7XHJcbiAgICAgICAgY29uc3QgZm9sbG93VXBBdCA9IG9wdGlvbmFsU3RyaW5nKGJvZHk/LmZvbGxvd1VwQXQpO1xyXG4gICAgICAgIGNvbnN0IGFzc2lnbmVkVG8gPSBvcHRpb25hbFN0cmluZyhib2R5Py5hc3NpZ25lZFRvKTtcclxuXHJcbiAgICAgICAgY29uc3QgdXBkYXRlZCA9IGF3YWl0IHBhdGNoTGVhZChzdG9yZSwgaWQsIChsZWFkKSA9PiB7XHJcbiAgICAgICAgICBjb25zdCBuZXh0OiBMZWFkID0ge1xyXG4gICAgICAgICAgICAuLi5sZWFkLFxyXG4gICAgICAgICAgICB1cGRhdGVkQXQ6IG5vd0lzbygpLFxyXG4gICAgICAgICAgICBzdGF0dXM6IHN0YXR1cyA/PyBsZWFkLnN0YXR1cyxcclxuICAgICAgICAgICAgbm90ZXM6IG5vdGVzID8/IGxlYWQubm90ZXMsXHJcbiAgICAgICAgICAgIGZvbGxvd1VwQXQ6IGZvbGxvd1VwQXQgPz8gbGVhZC5mb2xsb3dVcEF0LFxyXG4gICAgICAgICAgICBhc3NpZ25lZFRvOiBhc3NpZ25lZFRvID8/IGxlYWQuYXNzaWduZWRUbyxcclxuICAgICAgICAgICAgdGltZWxpbmU6IFsuLi5sZWFkLnRpbWVsaW5lLCB7IGF0OiBub3dJc28oKSwgdHlwZTogXCJ1cGRhdGVkXCIgfV0sXHJcbiAgICAgICAgICB9O1xyXG4gICAgICAgICAgcmV0dXJuIG5leHQ7XHJcbiAgICAgICAgfSk7XHJcblxyXG4gICAgICAgIGlmICghdXBkYXRlZCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIgfSwgNDA0LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHBhdGggPT09IFwiL2FwaS9jcm0vYXBwb2ludG1lbnRzXCIgJiYgcmVxLm1ldGhvZCA9PT0gXCJHRVRcIikge1xyXG4gICAgICBjb25zdCBmcm9tID0gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJmcm9tXCIpO1xyXG4gICAgICBjb25zdCB0byA9IHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwidG9cIik7XHJcbiAgICAgIGNvbnN0IGxpbWl0ID0gY2xhbXBJbnQodXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJsaW1pdFwiKSwgMSwgNTAwLCAyMDApO1xyXG5cclxuICAgICAgY29uc3QgYXBwdHMgPSBhd2FpdCBsaXN0QXBwb2ludG1lbnRzKHN0b3JlLCB7IGZyb206IGZyb20gPz8gdW5kZWZpbmVkLCB0bzogdG8gPz8gdW5kZWZpbmVkLCBsaW1pdCB9KTtcclxuICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgYXBwb2ludG1lbnRzOiBhcHB0cyB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChwYXRoID09PSBcIi9hcGkvY3JtL2FwcG9pbnRtZW50c1wiICYmIHJlcS5tZXRob2QgPT09IFwiUE9TVFwiKSB7XHJcbiAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBzYWZlSnNvbihyZXEpO1xyXG4gICAgICBjb25zdCBzZXJ2aWNlID0gcmVxdWlyZWRTdHJpbmcoYm9keT8uc2VydmljZSkgPz8gXCJkZWZhdWx0XCI7XHJcbiAgICAgIGNvbnN0IGRhdGUgPSByZXF1aXJlZFN0cmluZyhib2R5Py5kYXRlKTtcclxuICAgICAgY29uc3QgdGltZSA9IHJlcXVpcmVkU3RyaW5nKGJvZHk/LnRpbWUpO1xyXG4gICAgICBjb25zdCBuYW1lID0gcmVxdWlyZWRTdHJpbmcoYm9keT8ubmFtZSk7XHJcbiAgICAgIGlmICghc2VydmljZSB8fCAhaXNEYXRlWW1kKGRhdGUpIHx8ICFpc1RpbWVIbSh0aW1lKSB8fCAhbmFtZSkge1xyXG4gICAgICAgIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcImludmFsaWRfaW5wdXRcIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBjb25zdCBzdGFydEF0ID0gdG9Jc29Gcm9tTG9jYWwoZGF0ZSwgdGltZSk7XHJcbiAgICAgIGNvbnN0IGVuZEF0ID0gbmV3IERhdGUobmV3IERhdGUoc3RhcnRBdCkuZ2V0VGltZSgpICsgZW52LnNsb3RNaW51dGVzICogNjBfMDAwKS50b0lTT1N0cmluZygpO1xyXG5cclxuICAgICAgY29uc3QgYXBwb2ludG1lbnRJZCA9IGNyeXB0by5yYW5kb21VVUlEKCk7XHJcbiAgICAgIGNvbnN0IHNsb3RLZXkgPSBzbG90TG9ja0tleShkYXRlLCB0aW1lLCBzZXJ2aWNlKTtcclxuXHJcbiAgICAgIGNvbnN0IHJlc2VydmVkID0gYXdhaXQgcmVzZXJ2ZVNsb3Qoc3RvcmUsIHNsb3RLZXksIGFwcG9pbnRtZW50SWQsIGVudi5jYXBhY2l0eVBlclNsb3QpO1xyXG4gICAgICBpZiAoIXJlc2VydmVkLm9rKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJzbG90X3VuYXZhaWxhYmxlXCIgfSwgNDA5LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIGNvbnN0IGFwcHQ6IEFwcG9pbnRtZW50ID0ge1xyXG4gICAgICAgIGlkOiBhcHBvaW50bWVudElkLFxyXG4gICAgICAgIGNyZWF0ZWRBdDogbm93SXNvKCksXHJcbiAgICAgICAgdXBkYXRlZEF0OiBub3dJc28oKSxcclxuICAgICAgICBzdGF0dXM6IFwiYm9va2VkXCIsXHJcbiAgICAgICAgc2VydmljZSxcclxuICAgICAgICBzdGFydEF0LFxyXG4gICAgICAgIGVuZEF0LFxyXG4gICAgICAgIGN1c3RvbWVyOiB7IG5hbWUsIHBob25lOiBvcHRpb25hbFN0cmluZyhib2R5Py5waG9uZSksIGVtYWlsOiBvcHRpb25hbFN0cmluZyhib2R5Py5lbWFpbCkgfSxcclxuICAgICAgICBub3Rlczogb3B0aW9uYWxTdHJpbmcoYm9keT8ubm90ZXMpLFxyXG4gICAgICAgIGxlYWRJZDogb3B0aW9uYWxTdHJpbmcoYm9keT8ubGVhZElkKSxcclxuICAgICAgfTtcclxuXHJcbiAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBzdG9yZS5zZXRKU09OKGBhcHBvaW50bWVudHMvJHthcHB0LmlkfWAsIGFwcHQsIHsgb25seUlmTmV3OiB0cnVlIH0pO1xyXG4gICAgICBpZiAoIWNyZWF0ZWQubW9kaWZpZWQpIHtcclxuICAgICAgICBhd2FpdCByZWxlYXNlU2xvdChzdG9yZSwgc2xvdEtleSwgYXBwb2ludG1lbnRJZCk7XHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiY3JlYXRlX2ZhaWxlZFwiIH0sIDUwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHJldHVybiByZXNwb25kSnNvbih7IG9rOiB0cnVlLCBhcHBvaW50bWVudElkOiBhcHB0LmlkIH0sIDIwMCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHBhdGguc3RhcnRzV2l0aChcIi9hcGkvY3JtL2FwcG9pbnRtZW50cy9cIikpIHtcclxuICAgICAgY29uc3QgaWQgPSBwYXRoLnNwbGl0KFwiL1wiKS5wb3AoKSA/PyBcIlwiO1xyXG4gICAgICBpZiAoIWlkKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJtaXNzaW5nX2lkXCIgfSwgNDAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIGlmIChyZXEubWV0aG9kID09PSBcIkdFVFwiKSB7XHJcbiAgICAgICAgY29uc3QgYXBwdCA9IChhd2FpdCBzdG9yZS5nZXQoYGFwcG9pbnRtZW50cy8ke2lkfWAsIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIEFwcG9pbnRtZW50IHwgbnVsbDtcclxuICAgICAgICBpZiAoIWFwcHQpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm5vdF9mb3VuZFwiIH0sIDQwNCwgYXJncy5jb3JzSGVhZGVycyk7XHJcbiAgICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgYXBwb2ludG1lbnQ6IGFwcHQgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKHJlcS5tZXRob2QgPT09IFwiUFVUXCIpIHtcclxuICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgc2FmZUpzb24ocmVxKTtcclxuICAgICAgICBjb25zdCBwYXRjaCA9IHtcclxuICAgICAgICAgIHN0YXR1czogb3B0aW9uYWxTdHJpbmcoYm9keT8uc3RhdHVzKSBhcyBBcHBvaW50bWVudFN0YXR1cyB8IHVuZGVmaW5lZCxcclxuICAgICAgICAgIG5vdGVzOiBvcHRpb25hbFN0cmluZyhib2R5Py5ub3RlcyksXHJcbiAgICAgICAgfTtcclxuXHJcbiAgICAgICAgY29uc3QgdXBkYXRlZCA9IGF3YWl0IHBhdGNoQXBwb2ludG1lbnQoc3RvcmUsIGlkLCAoYXBwdCkgPT4gKHtcclxuICAgICAgICAgIC4uLmFwcHQsXHJcbiAgICAgICAgICB1cGRhdGVkQXQ6IG5vd0lzbygpLFxyXG4gICAgICAgICAgc3RhdHVzOiBwYXRjaC5zdGF0dXMgPz8gYXBwdC5zdGF0dXMsXHJcbiAgICAgICAgICBub3RlczogcGF0Y2gubm90ZXMgPz8gYXBwdC5ub3RlcyxcclxuICAgICAgICB9KSk7XHJcblxyXG4gICAgICAgIGlmICghdXBkYXRlZCkgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIgfSwgNDA0LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAocmVxLm1ldGhvZCA9PT0gXCJERUxFVEVcIikge1xyXG4gICAgICAgIGNvbnN0IGFwcHQgPSAoYXdhaXQgc3RvcmUuZ2V0KGBhcHBvaW50bWVudHMvJHtpZH1gLCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBBcHBvaW50bWVudCB8IG51bGw7XHJcbiAgICAgICAgaWYgKCFhcHB0KSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJub3RfZm91bmRcIiB9LCA0MDQsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgICAgICBjb25zdCB7IGRhdGUsIHRpbWUgfSA9IHNwbGl0SXNvVG9EYXRlVGltZShhcHB0LnN0YXJ0QXQpO1xyXG4gICAgICAgIGNvbnN0IHNsb3RLZXkgPSBzbG90TG9ja0tleShkYXRlLCB0aW1lLCBhcHB0LnNlcnZpY2UpO1xyXG5cclxuICAgICAgICBhd2FpdCBwYXRjaEFwcG9pbnRtZW50KHN0b3JlLCBpZCwgKGEpID0+ICh7IC4uLmEsIHVwZGF0ZWRBdDogbm93SXNvKCksIHN0YXR1czogXCJjYW5jZWxlZFwiIH0pKTtcclxuICAgICAgICBhd2FpdCByZWxlYXNlU2xvdChzdG9yZSwgc2xvdEtleSwgaWQpO1xyXG5cclxuICAgICAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBvazogdHJ1ZSB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHBhdGggPT09IFwiL2FwaS9jcm0vbWV0cmljc1wiICYmIHJlcS5tZXRob2QgPT09IFwiR0VUXCIpIHtcclxuICAgICAgY29uc3QgbWV0cmljcyA9IGF3YWl0IGNvbXB1dGVNZXRyaWNzKHN0b3JlKTtcclxuICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgbWV0cmljcyB9LCAyMDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChwYXRoID09PSBcIi9hcGkvY3JtL2V4cG9ydFwiICYmIHJlcS5tZXRob2QgPT09IFwiUE9TVFwiKSB7XHJcbiAgICAgIGlmIChhdXRoLnBheWxvYWQucm9sZSAhPT0gXCJhZG1pblwiKSByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJmb3JiaWRkZW5cIiB9LCA0MDMsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gICAgICBjb25zdCBzbmFwc2hvdCA9IGF3YWl0IGV4cG9ydFNuYXBzaG90KHN0b3JlKTtcclxuICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgc25hcHNob3QgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAocGF0aCA9PT0gXCIvYXBpL2NybS9pbXBvcnRcIiAmJiByZXEubWV0aG9kID09PSBcIlBPU1RcIikge1xyXG4gICAgICBpZiAoYXV0aC5wYXlsb2FkLnJvbGUgIT09IFwiYWRtaW5cIikgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwiZm9yYmlkZGVuXCIgfSwgNDAzLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuXHJcbiAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBzYWZlSnNvbihyZXEpO1xyXG4gICAgICBjb25zdCBzbmFwc2hvdCA9IGJvZHk/LnNuYXBzaG90IGFzIHsgbGVhZHM/OiBMZWFkW107IGFwcG9pbnRtZW50cz86IEFwcG9pbnRtZW50W107IHNsb3RzPzogUmVjb3JkPHN0cmluZywgU2xvdExvY2s+IH0gfCB1bmRlZmluZWQ7XHJcbiAgICAgIGlmICghc25hcHNob3QpIHJldHVybiByZXNwb25kSnNvbih7IGVycm9yOiBcIm1pc3Npbmdfc25hcHNob3RcIiB9LCA0MDAsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG5cclxuICAgICAgYXdhaXQgaW1wb3J0U25hcHNob3Qoc3RvcmUsIHNuYXBzaG90KTtcclxuICAgICAgcmV0dXJuIHJlc3BvbmRKc29uKHsgb2s6IHRydWUgfSwgMjAwLCBhcmdzLmNvcnNIZWFkZXJzKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gcmVzcG9uZEpzb24oeyBlcnJvcjogXCJub3RfZm91bmRcIiB9LCA0MDQsIGFyZ3MuY29yc0hlYWRlcnMpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIHJlc3BvbmRKc29uKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIgfSwgNDA0LCBhcmdzLmNvcnNIZWFkZXJzKTtcclxufVxyXG5cclxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gQXZhaWxhYmlsaXR5IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5hc3luYyBmdW5jdGlvbiBjb21wdXRlQXZhaWxhYmlsaXR5KFxyXG4gIHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sXHJcbiAgZW52OiBFbnZDb25maWcsXHJcbiAgZGF0ZTogc3RyaW5nLFxyXG4gIHNlcnZpY2U6IHN0cmluZyxcclxuKTogUHJvbWlzZTxBcnJheTx7IHRpbWU6IHN0cmluZzsgYXZhaWxhYmxlOiBib29sZWFuOyByZW1haW5pbmc6IG51bWJlciB9Pj4ge1xyXG4gIGNvbnN0IHRpbWVzID0gYnVpbGRTbG90cyhlbnYsIGRhdGUpO1xyXG4gIGNvbnN0IG91dDogQXJyYXk8eyB0aW1lOiBzdHJpbmc7IGF2YWlsYWJsZTogYm9vbGVhbjsgcmVtYWluaW5nOiBudW1iZXIgfT4gPSBbXTtcclxuXHJcbiAgZm9yIChjb25zdCB0aW1lIG9mIHRpbWVzKSB7XHJcbiAgICBjb25zdCBsb2NrID0gKGF3YWl0IHN0b3JlLmdldChzbG90TG9ja0tleShkYXRlLCB0aW1lLCBzZXJ2aWNlKSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgU2xvdExvY2sgfCBudWxsO1xyXG4gICAgY29uc3QgdXNlZCA9IGxvY2s/Lmlkcz8ubGVuZ3RoID8/IDA7XHJcbiAgICBjb25zdCByZW1haW5pbmcgPSBNYXRoLm1heCgwLCBlbnYuY2FwYWNpdHlQZXJTbG90IC0gdXNlZCk7XHJcbiAgICBvdXQucHVzaCh7IHRpbWUsIGF2YWlsYWJsZTogcmVtYWluaW5nID4gMCwgcmVtYWluaW5nIH0pO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIG91dDtcclxufVxyXG5cclxuZnVuY3Rpb24gYnVpbGRTbG90cyhlbnY6IEVudkNvbmZpZywgZGF0ZTogc3RyaW5nKTogc3RyaW5nW10ge1xyXG4gIGNvbnN0IHNsb3RzOiBzdHJpbmdbXSA9IFtdO1xyXG4gIGNvbnN0IHN0YXJ0TWluID0gZW52Lm9wZW5Ib3VyICogNjA7XHJcbiAgY29uc3QgZW5kTWluID0gZW52LmNsb3NlSG91ciAqIDYwO1xyXG5cclxuICBmb3IgKGxldCBtID0gc3RhcnRNaW47IG0gKyBlbnYuc2xvdE1pbnV0ZXMgPD0gZW5kTWluOyBtICs9IGVudi5zbG90TWludXRlcykge1xyXG4gICAgY29uc3QgaGggPSBTdHJpbmcoTWF0aC5mbG9vcihtIC8gNjApKS5wYWRTdGFydCgyLCBcIjBcIik7XHJcbiAgICBjb25zdCBtbSA9IFN0cmluZyhtICUgNjApLnBhZFN0YXJ0KDIsIFwiMFwiKTtcclxuICAgIHNsb3RzLnB1c2goYCR7aGh9OiR7bW19YCk7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gc2xvdHM7XHJcbn1cclxuXHJcbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBTbG90IExvY2tzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqL1xyXG5cclxuZnVuY3Rpb24gc2xvdExvY2tLZXkoZGF0ZTogc3RyaW5nLCB0aW1lOiBzdHJpbmcsIHNlcnZpY2U6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgY29uc3Qgc2FmZVNlcnZpY2UgPSBzZXJ2aWNlLnJlcGxhY2VBbGwoXCIvXCIsIFwiX1wiKS5zbGljZSgwLCA4MCk7XHJcbiAgcmV0dXJuIGBzbG90cy8ke2RhdGV9LyR7dGltZX0vJHtzYWZlU2VydmljZX1gO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiByZXNlcnZlU2xvdChcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIHNsb3RLZXk6IHN0cmluZyxcclxuICBhcHBvaW50bWVudElkOiBzdHJpbmcsXHJcbiAgY2FwYWNpdHk6IG51bWJlcixcclxuKTogUHJvbWlzZTx7IG9rOiB0cnVlIH0gfCB7IG9rOiBmYWxzZSB9PiB7XHJcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCA1OyBpICs9IDEpIHtcclxuICAgIGNvbnN0IGV4aXN0aW5nID0gKGF3YWl0IHN0b3JlLmdldFdpdGhNZXRhZGF0YShzbG90S2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhc1xyXG4gICAgICB8IHsgZGF0YTogU2xvdExvY2s7IGV0YWc6IHN0cmluZyB9XHJcbiAgICAgIHwgbnVsbDtcclxuXHJcbiAgICBpZiAoIWV4aXN0aW5nKSB7XHJcbiAgICAgIGNvbnN0IG5leHQ6IFNsb3RMb2NrID0geyBpZHM6IFthcHBvaW50bWVudElkXSB9O1xyXG4gICAgICBjb25zdCByZXMgPSBhd2FpdCBzdG9yZS5zZXRKU09OKHNsb3RLZXksIG5leHQsIHsgb25seUlmTmV3OiB0cnVlIH0pO1xyXG4gICAgICBpZiAocmVzLm1vZGlmaWVkKSByZXR1cm4geyBvazogdHJ1ZSB9O1xyXG4gICAgICBjb250aW51ZTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBpZHMgPSBBcnJheS5pc0FycmF5KGV4aXN0aW5nLmRhdGE/LmlkcykgPyBleGlzdGluZy5kYXRhLmlkcyA6IFtdO1xyXG4gICAgaWYgKGlkcy5pbmNsdWRlcyhhcHBvaW50bWVudElkKSkgcmV0dXJuIHsgb2s6IHRydWUgfTtcclxuICAgIGlmIChpZHMubGVuZ3RoID49IGNhcGFjaXR5KSByZXR1cm4geyBvazogZmFsc2UgfTtcclxuXHJcbiAgICBjb25zdCBuZXh0OiBTbG90TG9jayA9IHsgaWRzOiBbLi4uaWRzLCBhcHBvaW50bWVudElkXSB9O1xyXG4gICAgY29uc3QgcmVzID0gYXdhaXQgc3RvcmUuc2V0SlNPTihzbG90S2V5LCBuZXh0LCB7IG9ubHlJZk1hdGNoOiBleGlzdGluZy5ldGFnIH0pO1xyXG4gICAgaWYgKHJlcy5tb2RpZmllZCkgcmV0dXJuIHsgb2s6IHRydWUgfTtcclxuICB9XHJcblxyXG4gIHJldHVybiB7IG9rOiBmYWxzZSB9O1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiByZWxlYXNlU2xvdChzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LCBzbG90S2V5OiBzdHJpbmcsIGFwcG9pbnRtZW50SWQ6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xyXG4gIGZvciAobGV0IGkgPSAwOyBpIDwgNTsgaSArPSAxKSB7XHJcbiAgICBjb25zdCBleGlzdGluZyA9IChhd2FpdCBzdG9yZS5nZXRXaXRoTWV0YWRhdGEoc2xvdEtleSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXNcclxuICAgICAgfCB7IGRhdGE6IFNsb3RMb2NrOyBldGFnOiBzdHJpbmcgfVxyXG4gICAgICB8IG51bGw7XHJcblxyXG4gICAgaWYgKCFleGlzdGluZykgcmV0dXJuO1xyXG5cclxuICAgIGNvbnN0IGlkcyA9IEFycmF5LmlzQXJyYXkoZXhpc3RpbmcuZGF0YT8uaWRzKSA/IGV4aXN0aW5nLmRhdGEuaWRzIDogW107XHJcbiAgICBjb25zdCBuZXh0SWRzID0gaWRzLmZpbHRlcigoeCkgPT4geCAhPT0gYXBwb2ludG1lbnRJZCk7XHJcblxyXG4gICAgaWYgKG5leHRJZHMubGVuZ3RoID09PSBpZHMubGVuZ3RoKSByZXR1cm47XHJcblxyXG4gICAgaWYgKG5leHRJZHMubGVuZ3RoID09PSAwKSB7XHJcbiAgICAgIGF3YWl0IHN0b3JlLmRlbGV0ZShzbG90S2V5KTtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04oc2xvdEtleSwgeyBpZHM6IG5leHRJZHMgfSwgeyBvbmx5SWZNYXRjaDogZXhpc3RpbmcuZXRhZyB9KTtcclxuICAgIGlmIChyZXMubW9kaWZpZWQpIHJldHVybjtcclxuICB9XHJcbn1cclxuXHJcbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gUmF0ZSBMaW1pdCAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIHJhdGVMaW1pdChcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIGlwOiBzdHJpbmcsXHJcbiAgZGFpbHlMaW1pdDogbnVtYmVyLFxyXG4pOiBQcm9taXNlPHsgb2s6IHRydWUgfSB8IHsgb2s6IGZhbHNlIH0+IHtcclxuICBjb25zdCBkYXkgPSBub3dJc28oKS5zbGljZSgwLCAxMCk7XHJcbiAgY29uc3Qga2V5ID0gYHJhdGVsaW1pdC8ke2RheX0vJHtoYXNoU2hvcnQoaXApfWA7XHJcblxyXG4gIGZvciAobGV0IGkgPSAwOyBpIDwgNTsgaSArPSAxKSB7XHJcbiAgICBjb25zdCBleGlzdGluZyA9IChhd2FpdCBzdG9yZS5nZXRXaXRoTWV0YWRhdGEoa2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhc1xyXG4gICAgICB8IHsgZGF0YTogeyBjb3VudDogbnVtYmVyIH07IGV0YWc6IHN0cmluZyB9XHJcbiAgICAgIHwgbnVsbDtcclxuXHJcbiAgICBpZiAoIWV4aXN0aW5nKSB7XHJcbiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04oa2V5LCB7IGNvdW50OiAxIH0sIHsgb25seUlmTmV3OiB0cnVlIH0pO1xyXG4gICAgICBpZiAocmVzLm1vZGlmaWVkKSByZXR1cm4geyBvazogdHJ1ZSB9O1xyXG4gICAgICBjb250aW51ZTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBjb3VudCA9IHR5cGVvZiBleGlzdGluZy5kYXRhPy5jb3VudCA9PT0gXCJudW1iZXJcIiA/IGV4aXN0aW5nLmRhdGEuY291bnQgOiAwO1xyXG4gICAgaWYgKGNvdW50ID49IGRhaWx5TGltaXQpIHJldHVybiB7IG9rOiBmYWxzZSB9O1xyXG5cclxuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04oa2V5LCB7IGNvdW50OiBjb3VudCArIDEgfSwgeyBvbmx5SWZNYXRjaDogZXhpc3RpbmcuZXRhZyB9KTtcclxuICAgIGlmIChyZXMubW9kaWZpZWQpIHJldHVybiB7IG9rOiB0cnVlIH07XHJcbiAgfVxyXG5cclxuICByZXR1cm4geyBvazogZmFsc2UgfTtcclxufVxyXG5cclxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIExlYWRzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5hc3luYyBmdW5jdGlvbiBwYXRjaExlYWQoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBpZDogc3RyaW5nLFxyXG4gIHVwZGF0ZXI6IChsZWFkOiBMZWFkKSA9PiBMZWFkLFxyXG4pOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICBmb3IgKGxldCBpID0gMDsgaSA8IDU7IGkgKz0gMSkge1xyXG4gICAgY29uc3QgZXhpc3RpbmcgPSAoYXdhaXQgc3RvcmUuZ2V0V2l0aE1ldGFkYXRhKGBsZWFkcy8ke2lkfWAsIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzXHJcbiAgICAgIHwgeyBkYXRhOiBMZWFkOyBldGFnOiBzdHJpbmcgfVxyXG4gICAgICB8IG51bGw7XHJcblxyXG4gICAgaWYgKCFleGlzdGluZykgcmV0dXJuIGZhbHNlO1xyXG5cclxuICAgIGNvbnN0IG5leHQgPSB1cGRhdGVyKGV4aXN0aW5nLmRhdGEpO1xyXG4gICAgY29uc3QgcmVzID0gYXdhaXQgc3RvcmUuc2V0SlNPTihgbGVhZHMvJHtpZH1gLCBuZXh0LCB7IG9ubHlJZk1hdGNoOiBleGlzdGluZy5ldGFnIH0pO1xyXG4gICAgaWYgKHJlcy5tb2RpZmllZCkgcmV0dXJuIHRydWU7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gZmFsc2U7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGxpc3RMZWFkcyhcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIG9wdHM6IHsgc3RhdHVzPzogc3RyaW5nOyBxPzogc3RyaW5nOyBsaW1pdDogbnVtYmVyIH0sXHJcbik6IFByb21pc2U8TGVhZFtdPiB7XHJcbiAgY29uc3QgeyBibG9icyB9ID0gYXdhaXQgc3RvcmUubGlzdCh7IHByZWZpeDogXCJpbmRleGVzL2xlYWRzL1wiIH0pO1xyXG4gIGNvbnN0IGtleXMgPSBibG9icy5tYXAoKGIpID0+IGIua2V5KS5zb3J0KCkucmV2ZXJzZSgpO1xyXG5cclxuICBjb25zdCBsZWFkczogTGVhZFtdID0gW107XHJcbiAgZm9yIChjb25zdCBrIG9mIGtleXMpIHtcclxuICAgIGlmIChsZWFkcy5sZW5ndGggPj0gb3B0cy5saW1pdCkgYnJlYWs7XHJcbiAgICBjb25zdCBpZHggPSAoYXdhaXQgc3RvcmUuZ2V0KGssIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIHsgaWQ6IHN0cmluZyB9IHwgbnVsbDtcclxuICAgIGlmICghaWR4Py5pZCkgY29udGludWU7XHJcblxyXG4gICAgY29uc3QgbGVhZCA9IChhd2FpdCBzdG9yZS5nZXQoYGxlYWRzLyR7aWR4LmlkfWAsIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIExlYWQgfCBudWxsO1xyXG4gICAgaWYgKCFsZWFkKSBjb250aW51ZTtcclxuXHJcbiAgICBpZiAob3B0cy5zdGF0dXMgJiYgbGVhZC5zdGF0dXMgIT09IG9wdHMuc3RhdHVzKSBjb250aW51ZTtcclxuICAgIGlmIChvcHRzLnEgJiYgIW1hdGNoZXNRdWVyeShsZWFkLCBvcHRzLnEpKSBjb250aW51ZTtcclxuXHJcbiAgICBsZWFkcy5wdXNoKGxlYWQpO1xyXG4gIH1cclxuXHJcbiAgcmV0dXJuIGxlYWRzO1xyXG59XHJcblxyXG5mdW5jdGlvbiBtYXRjaGVzUXVlcnkobGVhZDogTGVhZCwgcTogc3RyaW5nKTogYm9vbGVhbiB7XHJcbiAgY29uc3QgbmVlZGxlID0gcS50cmltKCkudG9Mb3dlckNhc2UoKTtcclxuICBpZiAoIW5lZWRsZSkgcmV0dXJuIHRydWU7XHJcbiAgY29uc3QgaGF5ID0gW1xyXG4gICAgbGVhZC5pZCxcclxuICAgIGxlYWQubmFtZSxcclxuICAgIGxlYWQuZW1haWwgPz8gXCJcIixcclxuICAgIGxlYWQucGhvbmUgPz8gXCJcIixcclxuICAgIGxlYWQuc2VydmljZSA/PyBcIlwiLFxyXG4gICAgbGVhZC5ub3RlcyA/PyBcIlwiLFxyXG4gICAgbGVhZC5zdGF0dXMsXHJcbiAgXVxyXG4gICAgLmpvaW4oXCIgXCIpXHJcbiAgICAudG9Mb3dlckNhc2UoKTtcclxuICByZXR1cm4gaGF5LmluY2x1ZGVzKG5lZWRsZSk7XHJcbn1cclxuXHJcbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBBcHBvaW50bWVudHMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIHBhdGNoQXBwb2ludG1lbnQoXHJcbiAgc3RvcmU6IFJldHVyblR5cGU8dHlwZW9mIGdldFN0b3JlPixcclxuICBpZDogc3RyaW5nLFxyXG4gIHVwZGF0ZXI6IChhcHB0OiBBcHBvaW50bWVudCkgPT4gQXBwb2ludG1lbnQsXHJcbik6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gIGZvciAobGV0IGkgPSAwOyBpIDwgNTsgaSArPSAxKSB7XHJcbiAgICBjb25zdCBleGlzdGluZyA9IChhd2FpdCBzdG9yZS5nZXRXaXRoTWV0YWRhdGEoYGFwcG9pbnRtZW50cy8ke2lkfWAsIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzXHJcbiAgICAgIHwgeyBkYXRhOiBBcHBvaW50bWVudDsgZXRhZzogc3RyaW5nIH1cclxuICAgICAgfCBudWxsO1xyXG5cclxuICAgIGlmICghZXhpc3RpbmcpIHJldHVybiBmYWxzZTtcclxuXHJcbiAgICBjb25zdCBuZXh0ID0gdXBkYXRlcihleGlzdGluZy5kYXRhKTtcclxuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN0b3JlLnNldEpTT04oYGFwcG9pbnRtZW50cy8ke2lkfWAsIG5leHQsIHsgb25seUlmTWF0Y2g6IGV4aXN0aW5nLmV0YWcgfSk7XHJcbiAgICBpZiAocmVzLm1vZGlmaWVkKSByZXR1cm4gdHJ1ZTtcclxuICB9XHJcblxyXG4gIHJldHVybiBmYWxzZTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gbGlzdEFwcG9pbnRtZW50cyhcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIG9wdHM6IHsgZnJvbT86IHN0cmluZzsgdG8/OiBzdHJpbmc7IGxpbWl0OiBudW1iZXIgfSxcclxuKTogUHJvbWlzZTxBcHBvaW50bWVudFtdPiB7XHJcbiAgY29uc3QgeyBibG9icyB9ID0gYXdhaXQgc3RvcmUubGlzdCh7IHByZWZpeDogXCJhcHBvaW50bWVudHMvXCIgfSk7XHJcbiAgY29uc3Qga2V5cyA9IGJsb2JzLm1hcCgoYikgPT4gYi5rZXkpLnNvcnQoKS5yZXZlcnNlKCk7XHJcblxyXG4gIGNvbnN0IGFwcHRzOiBBcHBvaW50bWVudFtdID0gW107XHJcbiAgZm9yIChjb25zdCBrIG9mIGtleXMpIHtcclxuICAgIGlmIChhcHB0cy5sZW5ndGggPj0gb3B0cy5saW1pdCkgYnJlYWs7XHJcbiAgICBjb25zdCBhcHB0ID0gKGF3YWl0IHN0b3JlLmdldChrLCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBBcHBvaW50bWVudCB8IG51bGw7XHJcbiAgICBpZiAoIWFwcHQpIGNvbnRpbnVlO1xyXG5cclxuICAgIGlmIChvcHRzLmZyb20gJiYgYXBwdC5zdGFydEF0IDwgb3B0cy5mcm9tKSBjb250aW51ZTtcclxuICAgIGlmIChvcHRzLnRvICYmIGFwcHQuc3RhcnRBdCA+IG9wdHMudG8pIGNvbnRpbnVlO1xyXG5cclxuICAgIGFwcHRzLnB1c2goYXBwdCk7XHJcbiAgfVxyXG5cclxuICByZXR1cm4gYXBwdHM7XHJcbn1cclxuXHJcbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIE1ldHJpY3MgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGNvbXB1dGVNZXRyaWNzKHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4pIHtcclxuICBjb25zdCBsZWFkcyA9IGF3YWl0IGxpc3RMZWFkcyhzdG9yZSwgeyBsaW1pdDogMjAwLCBxOiB1bmRlZmluZWQsIHN0YXR1czogdW5kZWZpbmVkIH0pO1xyXG4gIGNvbnN0IHsgYmxvYnM6IGFwcHRCbG9icyB9ID0gYXdhaXQgc3RvcmUubGlzdCh7IHByZWZpeDogXCJhcHBvaW50bWVudHMvXCIgfSk7XHJcblxyXG4gIGNvbnN0IGFwcHRzOiBBcHBvaW50bWVudFtdID0gW107XHJcbiAgZm9yIChjb25zdCBiIG9mIGFwcHRCbG9icykge1xyXG4gICAgY29uc3QgYSA9IChhd2FpdCBzdG9yZS5nZXQoYi5rZXksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIEFwcG9pbnRtZW50IHwgbnVsbDtcclxuICAgIGlmIChhKSBhcHB0cy5wdXNoKGEpO1xyXG4gIH1cclxuXHJcbiAgY29uc3QgdG9kYXkgPSBub3dJc28oKS5zbGljZSgwLCAxMCk7XHJcbiAgY29uc3QgbGFzdDcgPSBkYXRlQWRkRGF5cyh0b2RheSwgLTYpO1xyXG4gIGNvbnN0IGxhc3QzMCA9IGRhdGVBZGREYXlzKHRvZGF5LCAtMjkpO1xyXG5cclxuICBjb25zdCBsZWFkc1RvZGF5ID0gbGVhZHMuZmlsdGVyKChsKSA9PiBsLmNyZWF0ZWRBdC5zdGFydHNXaXRoKHRvZGF5KSkubGVuZ3RoO1xyXG4gIGNvbnN0IGxlYWRzNyA9IGxlYWRzLmZpbHRlcigobCkgPT4gbC5jcmVhdGVkQXQuc2xpY2UoMCwgMTApID49IGxhc3Q3KS5sZW5ndGg7XHJcbiAgY29uc3QgbGVhZHMzMCA9IGxlYWRzLmZpbHRlcigobCkgPT4gbC5jcmVhdGVkQXQuc2xpY2UoMCwgMTApID49IGxhc3QzMCkubGVuZ3RoO1xyXG5cclxuICBjb25zdCBhcHB0c1RvZGF5ID0gYXBwdHMuZmlsdGVyKChhKSA9PiBhLmNyZWF0ZWRBdC5zdGFydHNXaXRoKHRvZGF5KSAmJiBhLnN0YXR1cyA9PT0gXCJib29rZWRcIikubGVuZ3RoO1xyXG4gIGNvbnN0IGFwcHRzNyA9IGFwcHRzLmZpbHRlcigoYSkgPT4gYS5jcmVhdGVkQXQuc2xpY2UoMCwgMTApID49IGxhc3Q3ICYmIGEuc3RhdHVzID09PSBcImJvb2tlZFwiKS5sZW5ndGg7XHJcbiAgY29uc3QgYXBwdHMzMCA9IGFwcHRzLmZpbHRlcigoYSkgPT4gYS5jcmVhdGVkQXQuc2xpY2UoMCwgMTApID49IGxhc3QzMCAmJiBhLnN0YXR1cyA9PT0gXCJib29rZWRcIikubGVuZ3RoO1xyXG5cclxuICBjb25zdCBsYW5kZWRCeURheSA9IG5ldyBNYXA8c3RyaW5nLCBudW1iZXI+KCk7XHJcbiAgZm9yIChjb25zdCBsIG9mIGxlYWRzKSB7XHJcbiAgICBpZiAobC5zdGF0dXMgIT09IFwibGFuZGVkXCIpIGNvbnRpbnVlO1xyXG4gICAgY29uc3QgZCA9IGwudXBkYXRlZEF0LnNsaWNlKDAsIDEwKTtcclxuICAgIGxhbmRlZEJ5RGF5LnNldChkLCAobGFuZGVkQnlEYXkuZ2V0KGQpID8/IDApICsgMSk7XHJcbiAgfVxyXG5cclxuICBsZXQgYmVzdERheSA9IHsgZGF0ZTogXCJcIiwgbGFuZGVkOiAwIH07XHJcbiAgZm9yIChjb25zdCBbZCwgbl0gb2YgbGFuZGVkQnlEYXkuZW50cmllcygpKSB7XHJcbiAgICBpZiAobiA+IGJlc3REYXkubGFuZGVkKSBiZXN0RGF5ID0geyBkYXRlOiBkLCBsYW5kZWQ6IG4gfTtcclxuICB9XHJcblxyXG4gIHJldHVybiB7XHJcbiAgICBsZWFkczogeyB0b2RheTogbGVhZHNUb2RheSwgbGFzdDc6IGxlYWRzNywgbGFzdDMwOiBsZWFkczMwIH0sXHJcbiAgICBhcHBvaW50bWVudHM6IHsgdG9kYXk6IGFwcHRzVG9kYXksIGxhc3Q3OiBhcHB0czcsIGxhc3QzMDogYXBwdHMzMCB9LFxyXG4gICAgYmVzdERheSxcclxuICB9O1xyXG59XHJcblxyXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIEV4cG9ydCAvIEltcG9ydCAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXHJcblxyXG5hc3luYyBmdW5jdGlvbiBleHBvcnRTbmFwc2hvdChzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+KSB7XHJcbiAgY29uc3QgeyBibG9iczogbGVhZEJsb2JzIH0gPSBhd2FpdCBzdG9yZS5saXN0KHsgcHJlZml4OiBcImxlYWRzL1wiIH0pO1xyXG4gIGNvbnN0IHsgYmxvYnM6IGFwcHRCbG9icyB9ID0gYXdhaXQgc3RvcmUubGlzdCh7IHByZWZpeDogXCJhcHBvaW50bWVudHMvXCIgfSk7XHJcbiAgY29uc3QgeyBibG9iczogc2xvdEJsb2JzIH0gPSBhd2FpdCBzdG9yZS5saXN0KHsgcHJlZml4OiBcInNsb3RzL1wiIH0pO1xyXG5cclxuICBjb25zdCBsZWFkczogTGVhZFtdID0gW107XHJcbiAgZm9yIChjb25zdCBiIG9mIGxlYWRCbG9icykge1xyXG4gICAgY29uc3QgbCA9IChhd2FpdCBzdG9yZS5nZXQoYi5rZXksIHsgdHlwZTogXCJqc29uXCIgfSkpIGFzIExlYWQgfCBudWxsO1xyXG4gICAgaWYgKGwpIGxlYWRzLnB1c2gobCk7XHJcbiAgfVxyXG5cclxuICBjb25zdCBhcHBvaW50bWVudHM6IEFwcG9pbnRtZW50W10gPSBbXTtcclxuICBmb3IgKGNvbnN0IGIgb2YgYXBwdEJsb2JzKSB7XHJcbiAgICBjb25zdCBhID0gKGF3YWl0IHN0b3JlLmdldChiLmtleSwgeyB0eXBlOiBcImpzb25cIiB9KSkgYXMgQXBwb2ludG1lbnQgfCBudWxsO1xyXG4gICAgaWYgKGEpIGFwcG9pbnRtZW50cy5wdXNoKGEpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgc2xvdHM6IFJlY29yZDxzdHJpbmcsIFNsb3RMb2NrPiA9IHt9O1xyXG4gIGZvciAoY29uc3QgYiBvZiBzbG90QmxvYnMpIHtcclxuICAgIGNvbnN0IHMgPSAoYXdhaXQgc3RvcmUuZ2V0KGIua2V5LCB7IHR5cGU6IFwianNvblwiIH0pKSBhcyBTbG90TG9jayB8IG51bGw7XHJcbiAgICBpZiAocykgc2xvdHNbYi5rZXldID0gcztcclxuICB9XHJcblxyXG4gIHJldHVybiB7IGV4cG9ydGVkQXQ6IG5vd0lzbygpLCBsZWFkcywgYXBwb2ludG1lbnRzLCBzbG90cyB9O1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBpbXBvcnRTbmFwc2hvdChcclxuICBzdG9yZTogUmV0dXJuVHlwZTx0eXBlb2YgZ2V0U3RvcmU+LFxyXG4gIHNuYXBzaG90OiB7IGxlYWRzPzogTGVhZFtdOyBhcHBvaW50bWVudHM/OiBBcHBvaW50bWVudFtdOyBzbG90cz86IFJlY29yZDxzdHJpbmcsIFNsb3RMb2NrPiB9LFxyXG4pOiBQcm9taXNlPHZvaWQ+IHtcclxuICBhd2FpdCBkZWxldGVCeVByZWZpeChzdG9yZSwgXCJsZWFkcy9cIik7XHJcbiAgYXdhaXQgZGVsZXRlQnlQcmVmaXgoc3RvcmUsIFwiYXBwb2ludG1lbnRzL1wiKTtcclxuICBhd2FpdCBkZWxldGVCeVByZWZpeChzdG9yZSwgXCJzbG90cy9cIik7XHJcbiAgYXdhaXQgZGVsZXRlQnlQcmVmaXgoc3RvcmUsIFwiaW5kZXhlcy9sZWFkcy9cIik7XHJcblxyXG4gIGZvciAoY29uc3QgbGVhZCBvZiBzbmFwc2hvdC5sZWFkcyA/PyBbXSkge1xyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihgbGVhZHMvJHtsZWFkLmlkfWAsIGxlYWQsIHsgb25seUlmTmV3OiB0cnVlIH0pO1xyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihgaW5kZXhlcy9sZWFkcy8ke2xlYWQuY3JlYXRlZEF0fV8ke2xlYWQuaWR9YCwgeyBpZDogbGVhZC5pZCwgY3JlYXRlZEF0OiBsZWFkLmNyZWF0ZWRBdCB9LCB7IG9ubHlJZk5ldzogdHJ1ZSB9KTtcclxuICB9XHJcblxyXG4gIGZvciAoY29uc3QgYXBwdCBvZiBzbmFwc2hvdC5hcHBvaW50bWVudHMgPz8gW10pIHtcclxuICAgIGF3YWl0IHN0b3JlLnNldEpTT04oYGFwcG9pbnRtZW50cy8ke2FwcHQuaWR9YCwgYXBwdCwgeyBvbmx5SWZOZXc6IHRydWUgfSk7XHJcbiAgfVxyXG5cclxuICBjb25zdCBzbG90cyA9IHNuYXBzaG90LnNsb3RzID8/IHt9O1xyXG4gIGZvciAoY29uc3QgW2ssIHZdIG9mIE9iamVjdC5lbnRyaWVzKHNsb3RzKSkge1xyXG4gICAgYXdhaXQgc3RvcmUuc2V0SlNPTihrLCB2LCB7IG9ubHlJZk5ldzogdHJ1ZSB9KTtcclxuICB9XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUJ5UHJlZml4KHN0b3JlOiBSZXR1cm5UeXBlPHR5cGVvZiBnZXRTdG9yZT4sIHByZWZpeDogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XHJcbiAgY29uc3QgeyBibG9icyB9ID0gYXdhaXQgc3RvcmUubGlzdCh7IHByZWZpeCB9KTtcclxuICBmb3IgKGNvbnN0IGIgb2YgYmxvYnMpIGF3YWl0IHN0b3JlLmRlbGV0ZShiLmtleSk7XHJcbn1cclxuXHJcbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBBdXRoIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqL1xyXG5cclxuZnVuY3Rpb24gcmVxdWlyZUF1dGgoZW52OiBFbnZDb25maWcsIGF1dGhIZWFkZXI6IHN0cmluZyk6IHsgb2s6IHRydWU7IHBheWxvYWQ6IEp3dFBheWxvYWQgfSB8IHsgb2s6IGZhbHNlIH0ge1xyXG4gIGNvbnN0IHRva2VuID0gYXV0aEhlYWRlci5zdGFydHNXaXRoKFwiQmVhcmVyIFwiKSA/IGF1dGhIZWFkZXIuc2xpY2UoXCJCZWFyZXIgXCIubGVuZ3RoKS50cmltKCkgOiBcIlwiO1xyXG4gIGlmICghdG9rZW4pIHJldHVybiB7IG9rOiBmYWxzZSB9O1xyXG4gIGNvbnN0IHBheWxvYWQgPSB2ZXJpZnlKd3QoZW52Lmp3dFNlY3JldCwgdG9rZW4pO1xyXG4gIGlmICghcGF5bG9hZCkgcmV0dXJuIHsgb2s6IGZhbHNlIH07XHJcbiAgcmV0dXJuIHsgb2s6IHRydWUsIHBheWxvYWQgfTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gdmVyaWZ5VXNlcihcclxuICBlbnY6IEVudkNvbmZpZyxcclxuICB1c2VybmFtZTogc3RyaW5nLFxyXG4gIHBhc3N3b3JkOiBzdHJpbmcsXHJcbik6IFByb21pc2U8eyByb2xlOiBcImFkbWluXCIgfCBcInN0YWZmXCIgfSB8IG51bGw+IHtcclxuICBpZiAoZW52LmNybVVzZXJzSnNvbikge1xyXG4gICAgdHJ5IHtcclxuICAgICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShlbnYuY3JtVXNlcnNKc29uKSBhcyBBcnJheTx7IHVzZXJuYW1lOiBzdHJpbmc7IHBhc3N3b3JkSGFzaDogc3RyaW5nOyByb2xlPzogXCJhZG1pblwiIHwgXCJzdGFmZlwiIH0+O1xyXG4gICAgICBjb25zdCB1ID0gcGFyc2VkLmZpbmQoKHgpID0+IHgudXNlcm5hbWUgPT09IHVzZXJuYW1lKTtcclxuICAgICAgaWYgKCF1KSByZXR1cm4gbnVsbDtcclxuICAgICAgaWYgKCF2ZXJpZnlTY3J5cHRQYXNzd29yZChwYXNzd29yZCwgdS5wYXNzd29yZEhhc2gpKSByZXR1cm4gbnVsbDtcclxuICAgICAgcmV0dXJuIHsgcm9sZTogdS5yb2xlID8/IFwic3RhZmZcIiB9O1xyXG4gICAgfSBjYXRjaCB7XHJcbiAgICAgIHJldHVybiBudWxsO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgaWYgKGVudi5hZG1pblVzZXIgJiYgdXNlcm5hbWUgPT09IGVudi5hZG1pblVzZXIpIHtcclxuICAgIGlmIChlbnYuYWRtaW5QYXNzd29yZEhhc2gpIHtcclxuICAgICAgaWYgKCF2ZXJpZnlTY3J5cHRQYXNzd29yZChwYXNzd29yZCwgZW52LmFkbWluUGFzc3dvcmRIYXNoKSkgcmV0dXJuIG51bGw7XHJcbiAgICAgIHJldHVybiB7IHJvbGU6IFwiYWRtaW5cIiB9O1xyXG4gICAgfVxyXG4gICAgaWYgKGVudi5hZG1pblBhc3N3b3JkICYmIHBhc3N3b3JkID09PSBlbnYuYWRtaW5QYXNzd29yZCkgcmV0dXJuIHsgcm9sZTogXCJhZG1pblwiIH07XHJcbiAgfVxyXG5cclxuICByZXR1cm4gbnVsbDtcclxufVxyXG5cclxuZnVuY3Rpb24gc2lnbkp3dChzZWNyZXQ6IHN0cmluZywgcGF5bG9hZDogSnd0UGF5bG9hZCk6IHN0cmluZyB7XHJcbiAgY29uc3QgaGVhZGVyID0geyBhbGc6IFwiSFMyNTZcIiwgdHlwOiBcIkpXVFwiIH07XHJcbiAgY29uc3QgZW5jSGVhZGVyID0gYjY0dXJsKEpTT04uc3RyaW5naWZ5KGhlYWRlcikpO1xyXG4gIGNvbnN0IGVuY1BheWxvYWQgPSBiNjR1cmwoSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkpO1xyXG4gIGNvbnN0IGRhdGEgPSBgJHtlbmNIZWFkZXJ9LiR7ZW5jUGF5bG9hZH1gO1xyXG4gIGNvbnN0IHNpZyA9IGhtYWNTaGEyNTYoc2VjcmV0LCBkYXRhKTtcclxuICByZXR1cm4gYCR7ZGF0YX0uJHtzaWd9YDtcclxufVxyXG5cclxuZnVuY3Rpb24gdmVyaWZ5Snd0KHNlY3JldDogc3RyaW5nLCB0b2tlbjogc3RyaW5nKTogSnd0UGF5bG9hZCB8IG51bGwge1xyXG4gIGNvbnN0IHBhcnRzID0gdG9rZW4uc3BsaXQoXCIuXCIpO1xyXG4gIGlmIChwYXJ0cy5sZW5ndGggIT09IDMpIHJldHVybiBudWxsO1xyXG4gIGNvbnN0IFtoLCBwLCBzXSA9IHBhcnRzO1xyXG4gIGNvbnN0IGRhdGEgPSBgJHtofS4ke3B9YDtcclxuICBjb25zdCBleHBlY3RlZCA9IGhtYWNTaGEyNTYoc2VjcmV0LCBkYXRhKTtcclxuICBpZiAoIXRpbWluZ1NhZmVFcXVhbFN0cihleHBlY3RlZCwgcykpIHJldHVybiBudWxsO1xyXG5cclxuICB0cnkge1xyXG4gICAgY29uc3QgcGF5bG9hZCA9IEpTT04ucGFyc2UoYjY0dXJsRGVjb2RlKHApKSBhcyBKd3RQYXlsb2FkO1xyXG4gICAgaWYgKHR5cGVvZiBwYXlsb2FkPy5leHAgIT09IFwibnVtYmVyXCIgfHwgbm93U2VjKCkgPiBwYXlsb2FkLmV4cCkgcmV0dXJuIG51bGw7XHJcbiAgICBpZiAodHlwZW9mIHBheWxvYWQ/LnN1YiAhPT0gXCJzdHJpbmdcIikgcmV0dXJuIG51bGw7XHJcbiAgICBpZiAocGF5bG9hZC5yb2xlICE9PSBcImFkbWluXCIgJiYgcGF5bG9hZC5yb2xlICE9PSBcInN0YWZmXCIpIHJldHVybiBudWxsO1xyXG4gICAgcmV0dXJuIHBheWxvYWQ7XHJcbiAgfSBjYXRjaCB7XHJcbiAgICByZXR1cm4gbnVsbDtcclxuICB9XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHZlcmlmeVNjcnlwdFBhc3N3b3JkKHBhc3N3b3JkOiBzdHJpbmcsIGVuY29kZWQ6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gIC8vIEZvcm1hdDogc2NyeXB0JE4kciRwJHNhbHRCNjQkZGtCNjRcclxuICBjb25zdCBwYXJ0cyA9IGVuY29kZWQuc3BsaXQoXCIkXCIpO1xyXG4gIGlmIChwYXJ0cy5sZW5ndGggIT09IDYgfHwgcGFydHNbMF0gIT09IFwic2NyeXB0XCIpIHJldHVybiBmYWxzZTtcclxuXHJcbiAgY29uc3QgTiA9IE51bWJlcihwYXJ0c1sxXSk7XHJcbiAgY29uc3QgciA9IE51bWJlcihwYXJ0c1syXSk7XHJcbiAgY29uc3QgcCA9IE51bWJlcihwYXJ0c1szXSk7XHJcbiAgY29uc3Qgc2FsdCA9IEJ1ZmZlci5mcm9tKHBhcnRzWzRdLCBcImJhc2U2NFwiKTtcclxuICBjb25zdCBkayA9IEJ1ZmZlci5mcm9tKHBhcnRzWzVdLCBcImJhc2U2NFwiKTtcclxuICBpZiAoIU51bWJlci5pc0Zpbml0ZShOKSB8fCAhTnVtYmVyLmlzRmluaXRlKHIpIHx8ICFOdW1iZXIuaXNGaW5pdGUocCkpIHJldHVybiBmYWxzZTtcclxuXHJcbiAgY29uc3QgZGVyaXZlZCA9IGNyeXB0by5zY3J5cHRTeW5jKHBhc3N3b3JkLCBzYWx0LCBkay5sZW5ndGgsIHsgTiwgciwgcCB9KTtcclxuICByZXR1cm4gY3J5cHRvLnRpbWluZ1NhZmVFcXVhbChkZXJpdmVkLCBkayk7XHJcbn1cclxuXHJcbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gVXRpbGl0aWVzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cclxuXHJcbmZ1bmN0aW9uIHJlYWRFbnYoKTogRW52Q29uZmlnIHtcclxuICBjb25zdCBqd3RTZWNyZXQgPSBOZXRsaWZ5LmVudi5nZXQoXCJKV1RfU0VDUkVUXCIpID8/IHByb2Nlc3MuZW52LkpXVF9TRUNSRVQgPz8gXCJcIjtcclxuICBpZiAoIWp3dFNlY3JldCkge1xyXG4gICAgdGhyb3cgbmV3IEVycm9yKFwiTWlzc2luZyBKV1RfU0VDUkVUXCIpO1xyXG4gIH1cclxuXHJcbiAgY29uc3QgYWxsb3dlZE9yaWdpbnNSYXcgPSBOZXRsaWZ5LmVudi5nZXQoXCJBTExPV0VEX09SSUdJTlNcIikgPz8gcHJvY2Vzcy5lbnYuQUxMT1dFRF9PUklHSU5TID8/IFwiXCI7XHJcbiAgY29uc3QgYWxsb3dlZE9yaWdpbnMgPVxyXG4gICAgYWxsb3dlZE9yaWdpbnNSYXcudHJpbSgpLmxlbmd0aCA+IDBcclxuICAgICAgPyBhbGxvd2VkT3JpZ2luc1Jhd1xyXG4gICAgICAgICAgLnNwbGl0KFwiLFwiKVxyXG4gICAgICAgICAgLm1hcCgocykgPT4gcy50cmltKCkpXHJcbiAgICAgICAgICAuZmlsdGVyKEJvb2xlYW4pXHJcbiAgICAgIDogbnVsbDtcclxuXHJcbiAgY29uc3QgY3JtVXNlcnNKc29uID0gTmV0bGlmeS5lbnYuZ2V0KFwiQ1JNX1VTRVJTX0pTT05cIikgPz8gcHJvY2Vzcy5lbnYuQ1JNX1VTRVJTX0pTT04gPz8gbnVsbDtcclxuICBjb25zdCBhZG1pblVzZXIgPSBOZXRsaWZ5LmVudi5nZXQoXCJDUk1fQURNSU5fVVNFUlwiKSA/PyBwcm9jZXNzLmVudi5DUk1fQURNSU5fVVNFUiA/PyBudWxsO1xyXG4gIGNvbnN0IGFkbWluUGFzc3dvcmQgPSBOZXRsaWZ5LmVudi5nZXQoXCJDUk1fQURNSU5fUEFTU1dPUkRcIikgPz8gcHJvY2Vzcy5lbnYuQ1JNX0FETUlOX1BBU1NXT1JEID8/IG51bGw7XHJcbiAgY29uc3QgYWRtaW5QYXNzd29yZEhhc2ggPSBOZXRsaWZ5LmVudi5nZXQoXCJDUk1fQURNSU5fUEFTU1dPUkRfSEFTSFwiKSA/PyBwcm9jZXNzLmVudi5DUk1fQURNSU5fUEFTU1dPUkRfSEFTSCA/PyBudWxsO1xyXG5cclxuICBjb25zdCBzbG90TWludXRlcyA9IGNsYW1wSW50KE5ldGxpZnkuZW52LmdldChcIlNMT1RfTUlOVVRFU1wiKSA/PyBwcm9jZXNzLmVudi5TTE9UX01JTlVURVMsIDEwLCAyNDAsIDMwKTtcclxuICBjb25zdCBvcGVuSG91ciA9IGNsYW1wSW50KE5ldGxpZnkuZW52LmdldChcIk9QRU5fSE9VUlwiKSA/PyBwcm9jZXNzLmVudi5PUEVOX0hPVVIsIDAsIDIzLCA5KTtcclxuICBjb25zdCBjbG9zZUhvdXIgPSBjbGFtcEludChOZXRsaWZ5LmVudi5nZXQoXCJDTE9TRV9IT1VSXCIpID8/IHByb2Nlc3MuZW52LkNMT1NFX0hPVVIsIDEsIDI0LCAxNyk7XHJcbiAgY29uc3QgY2FwYWNpdHlQZXJTbG90ID0gY2xhbXBJbnQoTmV0bGlmeS5lbnYuZ2V0KFwiQ0FQQUNJVFlfUEVSX1NMT1RcIikgPz8gcHJvY2Vzcy5lbnYuQ0FQQUNJVFlfUEVSX1NMT1QsIDEsIDUwLCAxKTtcclxuXHJcbiAgY29uc3QgdHogPSBOZXRsaWZ5LmVudi5nZXQoXCJUWlwiKSA/PyBwcm9jZXNzLmVudi5UWiA/PyBcIkFtZXJpY2EvTG9zX0FuZ2VsZXNcIjtcclxuICBjb25zdCBwdWJsaWNEYWlseVJhdGVMaW1pdCA9IGNsYW1wSW50KE5ldGxpZnkuZW52LmdldChcIlBVQkxJQ19EQUlMWV9SQVRFX0xJTUlUXCIpID8/IHByb2Nlc3MuZW52LlBVQkxJQ19EQUlMWV9SQVRFX0xJTUlULCAxLCAxMF8wMDAsIDIwMCk7XHJcblxyXG4gIHJldHVybiB7XHJcbiAgICBqd3RTZWNyZXQsXHJcbiAgICBhbGxvd2VkT3JpZ2lucyxcclxuICAgIGNybVVzZXJzSnNvbixcclxuICAgIGFkbWluVXNlcixcclxuICAgIGFkbWluUGFzc3dvcmQsXHJcbiAgICBhZG1pblBhc3N3b3JkSGFzaCxcclxuICAgIHNsb3RNaW51dGVzLFxyXG4gICAgb3BlbkhvdXIsXHJcbiAgICBjbG9zZUhvdXIsXHJcbiAgICBjYXBhY2l0eVBlclNsb3QsXHJcbiAgICB0eixcclxuICAgIHB1YmxpY0RhaWx5UmF0ZUxpbWl0LFxyXG4gIH07XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGJ1aWxkQ29yc0hlYWRlcnMoZW52OiBFbnZDb25maWcsIG9yaWdpbjogc3RyaW5nKTogSGVhZGVycyB7XHJcbiAgY29uc3QgaCA9IG5ldyBIZWFkZXJzKCk7XHJcbiAgY29uc3QgYWxsb3dPcmlnaW4gPVxyXG4gICAgZW52LmFsbG93ZWRPcmlnaW5zID09PSBudWxsID8gXCIqXCIgOiBlbnYuYWxsb3dlZE9yaWdpbnMuaW5jbHVkZXMob3JpZ2luKSA/IG9yaWdpbiA6IFwiXCI7XHJcblxyXG4gIGguc2V0KFwiYWNjZXNzLWNvbnRyb2wtYWxsb3ctb3JpZ2luXCIsIGFsbG93T3JpZ2luKTtcclxuICBoLnNldChcImFjY2Vzcy1jb250cm9sLWFsbG93LW1ldGhvZHNcIiwgXCJHRVQsUE9TVCxQVVQsREVMRVRFLE9QVElPTlNcIik7XHJcbiAgaC5zZXQoXCJhY2Nlc3MtY29udHJvbC1hbGxvdy1oZWFkZXJzXCIsIFwiY29udGVudC10eXBlLGF1dGhvcml6YXRpb25cIik7XHJcbiAgaC5zZXQoXCJhY2Nlc3MtY29udHJvbC1tYXgtYWdlXCIsIFwiODY0MDBcIik7XHJcbiAgaWYgKGFsbG93T3JpZ2luICYmIGFsbG93T3JpZ2luICE9PSBcIipcIikgaC5zZXQoXCJ2YXJ5XCIsIFwib3JpZ2luXCIpO1xyXG4gIHJldHVybiBoO1xyXG59XHJcblxyXG5mdW5jdGlvbiBub3JtYWxpemVBcGlQYXRoKHBhdGhuYW1lOiBzdHJpbmcpOiBzdHJpbmcge1xyXG4gIC8vIEhhbmRsZXMgYm90aDogL2FwaS8uLi4gIGFuZCAvLm5ldGxpZnkvZnVuY3Rpb25zL2FwaS8uLi4gKGRldilcclxuICBpZiAocGF0aG5hbWUuc3RhcnRzV2l0aChcIi8ubmV0bGlmeS9mdW5jdGlvbnMvYXBpXCIpKSB7XHJcbiAgICBjb25zdCByZXN0ID0gcGF0aG5hbWUuc2xpY2UoXCIvLm5ldGxpZnkvZnVuY3Rpb25zL2FwaVwiLmxlbmd0aCk7XHJcbiAgICByZXR1cm4gYC9hcGkke3Jlc3QgfHwgXCJcIn1gLnJlcGxhY2VBbGwoXCIvL1wiLCBcIi9cIik7XHJcbiAgfVxyXG4gIHJldHVybiBwYXRobmFtZS5yZXBsYWNlQWxsKFwiLy9cIiwgXCIvXCIpO1xyXG59XHJcblxyXG5mdW5jdGlvbiByZXNwb25kSnNvbihkYXRhOiBKc29uVmFsdWUsIHN0YXR1czogbnVtYmVyLCBjb3JzSGVhZGVyczogSGVhZGVycyk6IFJlc3BvbnNlIHtcclxuICBjb25zdCBoZWFkZXJzID0gbmV3IEhlYWRlcnMoY29yc0hlYWRlcnMpO1xyXG4gIGhlYWRlcnMuc2V0KFwiY29udGVudC10eXBlXCIsIFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOFwiKTtcclxuICByZXR1cm4gbmV3IFJlc3BvbnNlKGpzb24oZGF0YSksIHsgc3RhdHVzLCBoZWFkZXJzIH0pO1xyXG59XHJcblxyXG5mdW5jdGlvbiBqc29uKHY6IEpzb25WYWx1ZSk6IHN0cmluZyB7XHJcbiAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHYpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBzYWZlSnNvbihyZXE6IFJlcXVlc3QpOiBQcm9taXNlPGFueSB8IG51bGw+IHtcclxuICBjb25zdCBjdCA9IHJlcS5oZWFkZXJzLmdldChcImNvbnRlbnQtdHlwZVwiKSA/PyBcIlwiO1xyXG4gIGlmICghY3QudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhcImFwcGxpY2F0aW9uL2pzb25cIikpIHJldHVybiBudWxsO1xyXG4gIHRyeSB7XHJcbiAgICByZXR1cm4gYXdhaXQgcmVxLmpzb24oKTtcclxuICB9IGNhdGNoIHtcclxuICAgIHJldHVybiBudWxsO1xyXG4gIH1cclxufVxyXG5cclxuZnVuY3Rpb24gYXNTdHJpbmcodjogYW55KTogc3RyaW5nIHwgbnVsbCB7XHJcbiAgcmV0dXJuIHR5cGVvZiB2ID09PSBcInN0cmluZ1wiID8gdiA6IG51bGw7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHJlcXVpcmVkU3RyaW5nKHY6IGFueSk6IHN0cmluZyB8IG51bGwge1xyXG4gIGNvbnN0IHMgPSBhc1N0cmluZyh2KTtcclxuICBpZiAoIXMpIHJldHVybiBudWxsO1xyXG4gIGNvbnN0IHQgPSBzLnRyaW0oKTtcclxuICByZXR1cm4gdC5sZW5ndGggPyB0IDogbnVsbDtcclxufVxyXG5cclxuZnVuY3Rpb24gb3B0aW9uYWxTdHJpbmcodjogYW55KTogc3RyaW5nIHwgdW5kZWZpbmVkIHtcclxuICBjb25zdCBzID0gYXNTdHJpbmcodik7XHJcbiAgaWYgKCFzKSByZXR1cm4gdW5kZWZpbmVkO1xyXG4gIGNvbnN0IHQgPSBzLnRyaW0oKTtcclxuICByZXR1cm4gdC5sZW5ndGggPyB0IDogdW5kZWZpbmVkO1xyXG59XHJcblxyXG5mdW5jdGlvbiBub3dJc28oKTogc3RyaW5nIHtcclxuICByZXR1cm4gbmV3IERhdGUoKS50b0lTT1N0cmluZygpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBub3dTZWMoKTogbnVtYmVyIHtcclxuICByZXR1cm4gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGI2NHVybChpbnB1dDogc3RyaW5nKTogc3RyaW5nIHtcclxuICByZXR1cm4gQnVmZmVyLmZyb20oaW5wdXQsIFwidXRmOFwiKVxyXG4gICAgLnRvU3RyaW5nKFwiYmFzZTY0XCIpXHJcbiAgICAucmVwbGFjZUFsbChcIj1cIiwgXCJcIilcclxuICAgIC5yZXBsYWNlQWxsKFwiK1wiLCBcIi1cIilcclxuICAgIC5yZXBsYWNlQWxsKFwiL1wiLCBcIl9cIik7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGI2NHVybERlY29kZShpbnB1dDogc3RyaW5nKTogc3RyaW5nIHtcclxuICBjb25zdCBwYWQgPSBpbnB1dC5sZW5ndGggJSA0ID09PSAwID8gXCJcIiA6IFwiPVwiLnJlcGVhdCg0IC0gKGlucHV0Lmxlbmd0aCAlIDQpKTtcclxuICBjb25zdCBiNjQgPSBpbnB1dC5yZXBsYWNlQWxsKFwiLVwiLCBcIitcIikucmVwbGFjZUFsbChcIl9cIiwgXCIvXCIpICsgcGFkO1xyXG4gIHJldHVybiBCdWZmZXIuZnJvbShiNjQsIFwiYmFzZTY0XCIpLnRvU3RyaW5nKFwidXRmOFwiKTtcclxufVxyXG5cclxuZnVuY3Rpb24gaG1hY1NoYTI1NihzZWNyZXQ6IHN0cmluZywgZGF0YTogc3RyaW5nKTogc3RyaW5nIHtcclxuICBjb25zdCBzaWcgPSBjcnlwdG8uY3JlYXRlSG1hYyhcInNoYTI1NlwiLCBzZWNyZXQpLnVwZGF0ZShkYXRhKS5kaWdlc3QoXCJiYXNlNjRcIik7XHJcbiAgcmV0dXJuIHNpZy5yZXBsYWNlQWxsKFwiPVwiLCBcIlwiKS5yZXBsYWNlQWxsKFwiK1wiLCBcIi1cIikucmVwbGFjZUFsbChcIi9cIiwgXCJfXCIpO1xyXG59XHJcblxyXG5mdW5jdGlvbiB0aW1pbmdTYWZlRXF1YWxTdHIoYTogc3RyaW5nLCBiOiBzdHJpbmcpOiBib29sZWFuIHtcclxuICBjb25zdCBiYSA9IEJ1ZmZlci5mcm9tKGEpO1xyXG4gIGNvbnN0IGJiID0gQnVmZmVyLmZyb20oYik7XHJcbiAgaWYgKGJhLmxlbmd0aCAhPT0gYmIubGVuZ3RoKSByZXR1cm4gZmFsc2U7XHJcbiAgcmV0dXJuIGNyeXB0by50aW1pbmdTYWZlRXF1YWwoYmEsIGJiKTtcclxufVxyXG5cclxuZnVuY3Rpb24gaGFzaFNob3J0KHM6IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgcmV0dXJuIGNyeXB0by5jcmVhdGVIYXNoKFwic2hhMjU2XCIpLnVwZGF0ZShzKS5kaWdlc3QoXCJoZXhcIikuc2xpY2UoMCwgMTYpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBpc0RhdGVZbWQoczogc3RyaW5nKTogYm9vbGVhbiB7XHJcbiAgcmV0dXJuIC9eXFxkezR9LVxcZHsyfS1cXGR7Mn0kLy50ZXN0KHMpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBpc1RpbWVIbShzOiBzdHJpbmcpOiBib29sZWFuIHtcclxuICByZXR1cm4gL15cXGR7Mn06XFxkezJ9JC8udGVzdChzKTtcclxufVxyXG5cclxuZnVuY3Rpb24gZGF0ZUFkZERheXMoeW1kOiBzdHJpbmcsIGRlbHRhOiBudW1iZXIpOiBzdHJpbmcge1xyXG4gIGNvbnN0IGQgPSBuZXcgRGF0ZShgJHt5bWR9VDAwOjAwOjAwLjAwMFpgKTtcclxuICBkLnNldFVUQ0RhdGUoZC5nZXRVVENEYXRlKCkgKyBkZWx0YSk7XHJcbiAgcmV0dXJuIGQudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHRvSXNvRnJvbUxvY2FsKGRhdGVZbWQ6IHN0cmluZywgdGltZUhtOiBzdHJpbmcpOiBzdHJpbmcge1xyXG4gIC8vIE5PVEU6IEZvciBhIHByb2R1Y3Rpb24gc2NoZWR1bGluZyBzeXN0ZW0sIHVzZSBhIHJlYWwgVFogbGlicmFyeS5cclxuICAvLyBIZXJlIHdlIHRyZWF0IGlucHV0IGFzIHRoZSBzaXRlJ3MgbG9jYWwgdGltZSBhbmQgc2VyaWFsaXplIGFzIElTTyB1c2luZyBzeXN0ZW0gb2Zmc2V0LlxyXG4gIGNvbnN0IFtoaCwgbW1dID0gdGltZUhtLnNwbGl0KFwiOlwiKS5tYXAoKHgpID0+IE51bWJlcih4KSk7XHJcbiAgY29uc3QgZHQgPSBuZXcgRGF0ZShkYXRlWW1kKTtcclxuICBkdC5zZXRIb3VycyhoaCwgbW0sIDAsIDApO1xyXG4gIHJldHVybiBkdC50b0lTT1N0cmluZygpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBzcGxpdElzb1RvRGF0ZVRpbWUoaXNvOiBzdHJpbmcpOiB7IGRhdGU6IHN0cmluZzsgdGltZTogc3RyaW5nIH0ge1xyXG4gIGNvbnN0IGQgPSBuZXcgRGF0ZShpc28pO1xyXG4gIGNvbnN0IHl5eXkgPSBTdHJpbmcoZC5nZXRGdWxsWWVhcigpKS5wYWRTdGFydCg0LCBcIjBcIik7XHJcbiAgY29uc3QgbW0gPSBTdHJpbmcoZC5nZXRNb250aCgpICsgMSkucGFkU3RhcnQoMiwgXCIwXCIpO1xyXG4gIGNvbnN0IGRkID0gU3RyaW5nKGQuZ2V0RGF0ZSgpKS5wYWRTdGFydCgyLCBcIjBcIik7XHJcbiAgY29uc3QgaGggPSBTdHJpbmcoZC5nZXRIb3VycygpKS5wYWRTdGFydCgyLCBcIjBcIik7XHJcbiAgY29uc3QgbWkgPSBTdHJpbmcoZC5nZXRNaW51dGVzKCkpLnBhZFN0YXJ0KDIsIFwiMFwiKTtcclxuICByZXR1cm4geyBkYXRlOiBgJHt5eXl5fS0ke21tfS0ke2RkfWAsIHRpbWU6IGAke2hofToke21pfWAgfTtcclxufVxyXG5cclxuZnVuY3Rpb24gY2xhbXBJbnQodjogc3RyaW5nIHwgbnVsbCB8IHVuZGVmaW5lZCwgbWluOiBudW1iZXIsIG1heDogbnVtYmVyLCBkZWY6IG51bWJlcik6IG51bWJlciB7XHJcbiAgY29uc3QgbiA9IE51bWJlcih2KTtcclxuICBpZiAoIU51bWJlci5pc0Zpbml0ZShuKSkgcmV0dXJuIGRlZjtcclxuICBjb25zdCBpID0gTWF0aC5mbG9vcihuKTtcclxuICByZXR1cm4gTWF0aC5taW4obWF4LCBNYXRoLm1heChtaW4sIGkpKTtcclxufVxyXG5cclxuZnVuY3Rpb24gY2xpZW50SXAoYXJnczogeyByZXE6IFJlcXVlc3Q7IGNvbnRleHQ6IENvbnRleHQgfSk6IHN0cmluZyB7XHJcbiAgLy8gRnVuY3Rpb25zIHYyIHByb3ZpZGVzIGNvbnRleHQuaXAuIDpjb250ZW50UmVmZXJlbmNlW29haWNpdGU6Ml17aW5kZXg9Mn1cclxuICBjb25zdCB2aWFDb250ZXh0ID0gKGFyZ3MuY29udGV4dCBhcyBhbnkpPy5pcDtcclxuICBpZiAodHlwZW9mIHZpYUNvbnRleHQgPT09IFwic3RyaW5nXCIgJiYgdmlhQ29udGV4dC50cmltKCkpIHJldHVybiB2aWFDb250ZXh0LnRyaW0oKTtcclxuXHJcbiAgY29uc3QgaCA9IGFyZ3MucmVxLmhlYWRlcnM7XHJcbiAgY29uc3QgbmYgPSBoLmdldChcIngtbmYtY2xpZW50LWNvbm5lY3Rpb24taXBcIik7XHJcbiAgaWYgKG5mKSByZXR1cm4gbmYuc3BsaXQoXCIsXCIpWzBdLnRyaW0oKTtcclxuICBjb25zdCB4ZmYgPSBoLmdldChcIngtZm9yd2FyZGVkLWZvclwiKTtcclxuICBpZiAoeGZmKSByZXR1cm4geGZmLnNwbGl0KFwiLFwiKVswXS50cmltKCk7XHJcbiAgcmV0dXJuIFwiMC4wLjAuMFwiO1xyXG59XHJcbiJdLAogICJtYXBwaW5ncyI6ICI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBR0EsbUJBQXlCO0FBQ3pCLHlCQUFtQjtBQUVaLElBQU0sU0FBaUI7QUFBQSxFQUM1QixNQUFNO0FBQ1I7QUE4REEsSUFBTSxhQUFhO0FBQ25CLElBQU0sY0FBd0I7QUFFOUIsZUFBTyxRQUErQixLQUFjLFNBQWtCO0FBQ3BFLFFBQU0sTUFBTSxRQUFRO0FBQ3BCLFFBQU0sU0FBUyxJQUFJLFFBQVEsSUFBSSxRQUFRLEtBQUs7QUFDNUMsUUFBTSxjQUFjLGlCQUFpQixLQUFLLE1BQU07QUFFaEQsTUFBSSxJQUFJLFdBQVcsV0FBVztBQUM1QixXQUFPLElBQUksU0FBUyxNQUFNLEVBQUUsUUFBUSxLQUFLLFNBQVMsWUFBWSxDQUFDO0FBQUEsRUFDakU7QUFFQSxNQUFJO0FBQ0YsVUFBTSxNQUFNLElBQUksSUFBSSxJQUFJLEdBQUc7QUFDM0IsVUFBTSxPQUFPLGlCQUFpQixJQUFJLFFBQVE7QUFDMUMsVUFBTSxZQUFRLHVCQUFTLEVBQUUsTUFBTSxZQUFZLGFBQWEsWUFBWSxDQUFDO0FBRXJFLFVBQU0sY0FBYyxNQUFNLE1BQU0sRUFBRSxLQUFLLFNBQVMsS0FBSyxPQUFPLEtBQUssTUFBTSxZQUFZLENBQUM7QUFDcEYsV0FBTztBQUFBLEVBQ1QsU0FBUyxLQUFLO0FBQ1osVUFBTSxPQUFPLEtBQUssRUFBRSxPQUFPLGlCQUFpQixDQUFDO0FBQzdDLFdBQU8sSUFBSSxTQUFTLE1BQU07QUFBQSxNQUN4QixRQUFRO0FB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QUVBLFNBQVMsWUFBWSxLQUFhLE9BQXVCO0FBQ3ZELFFBQU0sSUFBSSxvQkFBSSxLQUFLLEdBQUcsR0FBRyxnQkFBZ0I7QUFDekMsSUFBRSxXQUFXLEVBQUUsV0FBVyxJQUFJLEtBQUs7QUFDbkMsU0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLEdBQUcsRUFBRTtBQUNwQztBQUVBLFNBQVMsZUFBZSxTQUFpQixRQUF3QjtBQUcvRCxRQUFNLENBQUMsSUFBSSxFQUFFLElBQUksT0FBTyxNQUFNLEdBQUcsRUFBRSxJQUFJLENBQUMsTUFBTSxPQUFPLENBQUMsQ0FBQztBQUN2RCxRQUFNLEtBQUssSUFBSSxLQUFLLE9BQU87QUFDM0IsS0FBRyxTQUFTLElBQUksSUFBSSxHQUFHLENBQUM7QUFDeEIsU0FBTyxHQUFHLFlBQVk7QUFDeEI7QUFFQSxTQUFTLG1CQUFtQixLQUE2QztBQUN2RSxRQUFNLElBQUksSUFBSSxLQUFLLEdBQUc7QUFDdEIsUUFBTSxPQUFPLE9BQU8sRUFBRSxZQUFZLENBQUMsRUFBRSxTQUFTLEdBQUcsR0FBRztBQUNwRCxRQUFNLEtBQUssT0FBTyxFQUFFLFNBQVMsSUFBSSxDQUFDLEVBQUUsU0FBUyxHQUFHLEdBQUc7QUFDbkQsUUFBTSxLQUFLLE9BQU8sRUFBRSxRQUFRLENBQUMsRUFBRSxTQUFTLEdBQUcsR0FBRztBQUM5QyxRQUFNLEtBQUssT0FBTyxFQUFFLFNBQVMsQ0FBQyxFQUFFLFNBQVMsR0FBRyxHQUFHO0FBQy9DLFFBQU0sS0FBSyxPQUFPLEVBQUUsV0FBVyxDQUFDLEVBQUUsU0FBUyxHQUFHLEdBQUc7QUFDakQsU0FBTyxFQUFFLE1BQU0sR0FBRyxJQUFJLElBQUksRUFBRSxJQUFJLEVBQUUsSUFBSSxNQUFNLEdBQUcsRUFBRSxJQUFJLEVBQUUsR0FBRztBQUM1RDtBQUVBLFNBQVMsU0FBUyxHQUE4QixLQUFhLEtBQWEsS0FBcUI7QUFDN0YsUUFBTSxJQUFJLE9BQU8sQ0FBQztBQUNsQixNQUFJLENBQUMsT0FBTyxTQUFTLENBQUMsRUFBRyxRQUFPO0FBQ2hDLFFBQU0sSUFBSSxLQUFLLE1BQU0sQ0FBQztBQUN0QixTQUFPLEtBQUssSUFBSSxLQUFLLEtBQUssSUFBSSxLQUFLLENBQUMsQ0FBQztBQUN2QztBQUVBLFNBQVMsU0FBUyxNQUFrRDtBQUVsRSxRQUFNLGFBQWMsS0FBSyxTQUFpQjtBQUMxQyxNQUFJLE9BQU8sZUFBZSxZQUFZLFdBQVcsS0FBSyxFQUFHLFFBQU8sV0FBVyxLQUFLO0FBRWhGLFFBQU0sSUFBSSxLQUFLLElBQUk7QUFDbkIsUUFBTSxLQUFLLEVBQUUsSUFBSSwyQkFBMkI7QUFDNUMsTUFBSSxHQUFJLFFBQU8sR0FBRyxNQUFNLEdBQUcsRUFBRSxDQUFDLEVBQUUsS0FBSztBQUNyQyxRQUFNLE1BQU0sRUFBRSxJQUFJLGlCQUFpQjtBQUNuQyxNQUFJLElBQUssUUFBTyxJQUFJLE1BQU0sR0FBRyxFQUFFLENBQUMsRUFBRSxLQUFLO0FBQ3ZDLFNBQU87QUFDVDsiLAogICJuYW1lcyI6IFsiY3J5cHRvIiwgIm5leHQiLCAicmVzIl0KfQo=
