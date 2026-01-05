/* File: netlify/functions/lead_finder.ts */

import type { Context } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

type JwtPayload = {
  sub: string;
  role: "admin" | "staff";
  iat: number;
  exp: number;
};

type LeadFinderProvider = "google_places";
type GeoType = "city" | "latlng";

type LeadFinderProfile = {
  id: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  updatedBy: string;

  name: string;
  industryId: string;
  subIndustryId: string | null;

  geoType: GeoType;
  city: string | null;
  state: string | null;
  country: string | null;
  centerLat: number | null;
  centerLng: number | null;
  radiusMeters: number;

  requirePhone: boolean;
  requireNoWebsite: boolean;
};

type LeadFinderRunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

type LeadFinderRun = {
  id: string;
  createdAt: string;
  updatedAt: string;
  requestedBy: string;

  profileId: string;
  provider: LeadFinderProvider;
  status: LeadFinderRunStatus;

  statsTotalSeen: number;
  statsQualified: number;
  statsInserted: number;
  statsDuplicates: number;
  statsMissingPhone: number;
  statsHasWebsite: number;

  errorMessage: string | null;
};

type CrmLeadStatus = "hot" | "new" | "follow_up" | "appointment" | "landed" | "no" | "archived";
type CrmLead = {
  id: string;
  createdAt: string;
  updatedAt: string;
  updatedBy?: string;
  updatedDeviceId?: string;
  source: "public";
  status: CrmLeadStatus;
  name: string;
  phone?: string;
  email?: string;
  service?: string;
  notes?: string;
  preferredDate?: string;
  preferredTime?: string;
  followUpAt?: string;
  assignedTo?: string;
  pulledAt?: string;
  timeline: Array<{ at: string; type: string; note?: string }>;
};

const STORE_NAME = "crm";
const CONSISTENCY: "strong" = "strong";

export default async function handler(req: Request, _context: Context) {
  const url = new URL(req.url);
  const path = normalizeFnPath(url.pathname);
  const cors = buildCorsHeaders(req);

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  const auth = requireAuth(req.headers.get("authorization") ?? "");
  if (!auth.ok) return respondJson({ error: "unauthorized" }, 401, cors);

  const store = getStore({ name: STORE_NAME, consistency: CONSISTENCY });

  if (req.method === "GET" && path === "/") {
    return respondJson(
      { ok: true, function: "lead_finder", user: auth.payload.sub, role: auth.payload.role },
      200,
      cors,
    );
  }

  // ---------------- Debug (admin-only) ----------------

  if (req.method === "GET" && path === "/debug/blobs") {
    if (auth.payload.role !== "admin") return respondJson({ error: "forbidden" }, 403, cors);

    const prefix = (url.searchParams.get("prefix") ?? "").trim();
    const limit = clampInt(url.searchParams.get("limit"), 1, 2000, 500);

    const { blobs, directories } = await store.list({ prefix });
    const keys = blobs.map((b) => b.key).sort().slice(0, limit);

    return respondJson(
      { ok: true, prefix, count: keys.length, keys, directories: (directories ?? []).slice(0, 200) },
      200,
      cors,
    );
  }

  if (req.method === "POST" && path === "/debug/backfill-indexes") {
    if (auth.payload.role !== "admin") return respondJson({ error: "forbidden" }, 403, cors);

    const limit = clampInt(url.searchParams.get("limit"), 1, 10_000, 1000);

    const { blobs } = await store.list({ prefix: "leads/" });
    const leadKeys = blobs.map((b) => b.key).sort().reverse().slice(0, limit);

    let scanned = 0;
    let created = 0;
    let skipped = 0;

    for (const k of leadKeys) {
      scanned += 1;

      const lead = (await store.get(k, { type: "json" })) as CrmLead | null;
      if (!lead?.id || !lead.createdAt) {
        skipped += 1;
        continue;
      }

      const idxKey = `indexes/leads/${lead.createdAt}_${lead.id}`;
      const res = await store.setJSON(idxKey, { id: lead.id, createdAt: lead.createdAt }, { onlyIfNew: true });
      if (res.modified) created += 1;
      else skipped += 1;
    }

    return respondJson({ ok: true, scanned, created, skipped }, 200, cors);
  }

  // ---------------- Profiles ----------------

  if (req.method === "POST" && path === "/profiles") {
    const body = await safeJson(req);

    const name = requiredString(body?.name);
    const industryId = requiredString(body?.industryId);
    const subIndustryId = optionalString(body?.subIndustryId);

    const geoType = (requiredString(body?.geoType) ?? "city") as GeoType;
    const city = optionalString(body?.city);
    const state = optionalString(body?.state);
    const country = optionalString(body?.country);
    const centerLat = optionalNumber(body?.centerLat);
    const centerLng = optionalNumber(body?.centerLng);

    const radiusMeters = clampInt(String(body?.radiusMeters ?? ""), 1, 200_000, 5_000);
    const requirePhone = optionalBool(body?.requirePhone) ?? true;
    const requireNoWebsite = optionalBool(body?.requireNoWebsite) ?? true;

    if (!name) return respondJson({ error: "missing_name" }, 400, cors);
    if (!industryId) return respondJson({ error: "missing_industryId" }, 400, cors);

    if (geoType === "city") {
      if (!city) return respondJson({ error: "missing_city" }, 400, cors);
    } else {
      if (centerLat == null || centerLng == null) {
        return respondJson({ error: "missing_centerLat_centerLng" }, 400, cors);
      }
    }

    const profile = await createProfile(store, {
      name,
      industryId,
      subIndustryId,
      geoType,
      city: city ?? null,
      state: state ?? null,
      country: country ?? null,
      centerLat: centerLat ?? null,
      centerLng: centerLng ?? null,
      radiusMeters,
      requirePhone,
      requireNoWebsite,
      actor: auth.payload.sub,
    });

    return respondJson({ ok: true, profile }, 201, cors);
  }

  if (req.method === "GET" && path === "/profiles") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 200, 50);
    const profiles = await listProfiles(store, limit);
    return respondJson({ ok: true, profiles }, 200, cors);
  }

  {
    const m = path.match(/^\/profiles\/([^/]+)$/);
    if (req.method === "GET" && m) {
      const id = decodeURIComponent(m[1]);
      const profile = (await store.get(profileKey(id), { type: "json" })) as LeadFinderProfile | null;
      if (!profile) return respondJson({ error: "not_found" }, 404, cors);
      return respondJson({ ok: true, profile }, 200, cors);
    }
  }

  // ---------------- Runs ----------------

  if (req.method === "POST" && path === "/runs") {
    const body = await safeJson(req);

    const profileId = requiredString(body?.profileId);
    if (!profileId) return respondJson({ error: "profileId_required" }, 400, cors);

    const provider = (optionalString(body?.provider) ?? "google_places") as LeadFinderProvider;

    const profile = (await store.get(profileKey(profileId), { type: "json" })) as LeadFinderProfile | null;
    if (!profile) return respondJson({ error: "profile_not_found" }, 404, cors);

    const run = await createRun(store, {
      profileId,
      provider,
      actor: auth.payload.sub,
    });

    return respondJson({ ok: true, run }, 201, cors);
  }

  if (req.method === "GET" && path === "/runs") {
    const limit = clampInt(url.searchParams.get("limit"), 1, 200, 50);
    const runs = await listRuns(store, limit);
    return respondJson({ ok: true, runs }, 200, cors);
  }

  {
    const m = path.match(/^\/runs\/([^/]+)$/);
    if (req.method === "GET" && m) {
      const id = decodeURIComponent(m[1]);
      const run = (await store.get(runKey(id), { type: "json" })) as LeadFinderRun | null;
      if (!run) return respondJson({ error: "not_found" }, 404, cors);
      return respondJson({ ok: true, run }, 200, cors);
    }
  }

  // POST /runs/:id/cancel
  {
    const m = path.match(/^\/runs\/([^/]+)\/cancel$/);
    if (req.method === "POST" && m) {
      const runId = decodeURIComponent(m[1]);

      const existing = (await store.get(runKey(runId), { type: "json" })) as LeadFinderRun | null;
      if (!existing) return respondJson({ error: "not_found" }, 404, cors);

      if (existing.status === "completed" || existing.status === "failed") {
        return respondJson({ ok: true, run: existing }, 200, cors);
      }

      const cancelled = await patchRun(store, runId, (r) => ({
        ...r,
        status: "cancelled",
        updatedAt: nowIso(),
      }));

      return respondJson({ ok: true, run: cancelled }, 200, cors);
    }
  }

  // POST /runs/:id/execute  (simulation)
  {
    const m = path.match(/^\/runs\/([^/]+)\/execute$/);
    if (req.method === "POST" && m) {
      const runId = decodeURIComponent(m[1]);
      const body = await safeJson(req);

      const requestedInsertCount = clampInt(String(body?.insertCount ?? ""), 0, 500, 10);

      const existing = (await store.get(runKey(runId), { type: "json" })) as LeadFinderRun | null;
      if (!existing) return respondJson({ error: "not_found" }, 404, cors);

      if (existing.status === "cancelled") return respondJson({ ok: true, run: existing }, 200, cors);

      const profile = (await store.get(profileKey(existing.profileId), { type: "json" })) as LeadFinderProfile | null;
      if (!profile) return respondJson({ error: "profile_not_found" }, 404, cors);

      const running = await patchRun(store, runId, (r) => ({
        ...r,
        status: "running",
        updatedAt: nowIso(),
        errorMessage: null,
      }));

      const totalSeen = Math.max(running.statsTotalSeen, requestedInsertCount * 3);
      const qualified = Math.max(running.statsQualified, requestedInsertCount * 2);
      const hasWebsite = Math.floor(requestedInsertCount / 3);
      const missingPhone = Math.floor(requestedInsertCount / 4);

      const insertedIds: string[] = [];
      const indexKeysCreated: string[] = [];

      for (let i = 0; i < requestedInsertCount; i += 1) {
        const leadId = crypto.randomUUID();
        const lead = buildSimulatedLead({
          id: leadId,
          actor: auth.payload.sub,
          profile,
          idx: i,
        });

        const created = await store.setJSON(`leads/${lead.id}`, lead, { onlyIfNew: true });
        if (!created.modified) continue;

        // ✅ MUST match api.ts format exactly
        const crmIndexKey = `indexes/leads/${lead.createdAt}_${lead.id}`;
        const idxRes = await store.setJSON(
          crmIndexKey,
          { id: lead.id, createdAt: lead.createdAt },
          { onlyIfNew: true },
        );

        if (idxRes.modified) indexKeysCreated.push(crmIndexKey);
        insertedIds.push(lead.id);
      }

      const completed = await patchRun(store, runId, (r) => ({
        ...r,
        status: "completed",
        updatedAt: nowIso(),
        statsTotalSeen: totalSeen,
        statsQualified: qualified,
        statsInserted: r.statsInserted + insertedIds.length,
        statsHasWebsite: r.statsHasWebsite + hasWebsite,
        statsMissingPhone: r.statsMissingPhone + missingPhone,
      }));

      return respondJson(
        { ok: true, run: completed, insertedLeadIds: insertedIds, indexKeysCreated },
        200,
        cors,
      );
    }
  }

  return respondJson({ error: "not_found" }, 404, cors);
}

/* ------------------------------- Storage -------------------------------- */

function profileKey(id: string): string {
  return `lead_finder/profiles/${id}`;
}
function profileIndexKey(tsKey: string, id: string): string {
  return `lead_finder/indexes/profiles/${tsKey}_${id}`;
}

function runKey(id: string): string {
  return `lead_finder/runs/${id}`;
}
function runIndexKey(tsKey: string, id: string): string {
  return `lead_finder/indexes/runs/${tsKey}_${id}`;
}

function tsKeyNow(): string {
  return String(Date.now()).padStart(13, "0");
}

async function createProfile(
  store: ReturnType<typeof getStore>,
  input: Omit<LeadFinderProfile, "id" | "createdAt" | "updatedAt" | "createdBy" | "updatedBy"> & { actor: string },
): Promise<LeadFinderProfile> {
  for (let i = 0; i < 5; i += 1) {
    const id = crypto.randomUUID();
    const now = nowIso();
    const tsKey = tsKeyNow();

    const profile: LeadFinderProfile = {
      id,
      createdAt: now,
      updatedAt: now,
      createdBy: input.actor,
      updatedBy: input.actor,

      name: input.name,
      industryId: input.industryId,
      subIndustryId: input.subIndustryId,

      geoType: input.geoType,
      city: input.city,
      state: input.state,
      country: input.country,
      centerLat: input.centerLat,
      centerLng: input.centerLng,
      radiusMeters: input.radiusMeters,

      requirePhone: input.requirePhone,
      requireNoWebsite: input.requireNoWebsite,
    };

    const res = await store.setJSON(profileKey(id), profile, { onlyIfNew: true });
    if (!res.modified) continue;

    await store.setJSON(profileIndexKey(tsKey, id), { id, createdAt: now }, { onlyIfNew: true });
    return profile;
  }

  throw new Error("failed_to_create_profile");
}

async function listProfiles(store: ReturnType<typeof getStore>, limit: number): Promise<LeadFinderProfile[]> {
  const { blobs } = await store.list({ prefix: "lead_finder/indexes/profiles/" });
  const indexKeys = blobs.map((b) => b.key).sort().reverse().slice(0, limit);

  const out: LeadFinderProfile[] = [];
  for (const k of indexKeys) {
    const idx = (await store.get(k, { type: "json" })) as { id?: string } | null;
    const id = safeText(idx?.id);
    if (!id) continue;

    const p = (await store.get(profileKey(id), { type: "json" })) as LeadFinderProfile | null;
    if (p) out.push(p);
  }

  return out;
}

async function createRun(
  store: ReturnType<typeof getStore>,
  input: { profileId: string; provider: LeadFinderProvider; actor: string },
): Promise<LeadFinderRun> {
  for (let i = 0; i < 5; i += 1) {
    const id = crypto.randomUUID();
    const now = nowIso();
    const tsKey = tsKeyNow();

    const run: LeadFinderRun = {
      id,
      createdAt: now,
      updatedAt: now,
      requestedBy: input.actor,

      profileId: input.profileId,
      provider: input.provider,
      status: "queued",

      statsTotalSeen: 0,
      statsQualified: 0,
      statsInserted: 0,
      statsDuplicates: 0,
      statsMissingPhone: 0,
      statsHasWebsite: 0,

      errorMessage: null,
    };

    const res = await store.setJSON(runKey(id), run, { onlyIfNew: true });
    if (!res.modified) continue;

    await store.setJSON(runIndexKey(tsKey, id), { id, createdAt: now }, { onlyIfNew: true });
    return run;
  }

  throw new Error("failed_to_create_run");
}

async function listRuns(store: ReturnType<typeof getStore>, limit: number): Promise<LeadFinderRun[]> {
  const { blobs } = await store.list({ prefix: "lead_finder/indexes/runs/" });
  const indexKeys = blobs.map((b) => b.key).sort().reverse().slice(0, limit);

  const out: LeadFinderRun[] = [];
  for (const k of indexKeys) {
    const idx = (await store.get(k, { type: "json" })) as { id?: string } | null;
    const id = safeText(idx?.id);
    if (!id) continue;

    const r = (await store.get(runKey(id), { type: "json" })) as LeadFinderRun | null;
    if (r) out.push(r);
  }
  return out;
}

async function patchRun(
  store: ReturnType<typeof getStore>,
  id: string,
  updater: (run: LeadFinderRun) => LeadFinderRun,
): Promise<LeadFinderRun> {
  for (let i = 0; i < 5; i += 1) {
    const existing = (await store.getWithMetadata(runKey(id), { type: "json" })) as
      | { data: LeadFinderRun; etag: string }
      | null;

    if (!existing) throw new Error("run_not_found");

    const next = updater(existing.data);
    const res = await store.setJSON(runKey(id), next, { onlyIfMatch: existing.etag });
    if (res.modified) return next;
  }
  throw new Error("run_update_conflict");
}

function buildSimulatedLead(args: { id: string; actor: string; profile: LeadFinderProfile; idx: number }): CrmLead {
  const now = nowIso();
  const city = args.profile.city ? ` (${args.profile.city})` : "";
  return {
    id: args.id,
    createdAt: now,
    updatedAt: now,
    updatedBy: args.actor,
    source: "public",
    status: "new",
    name: `${args.profile.name} Lead #${args.idx + 1}${city}`,
    phone: `+1206555${String(1000 + (args.idx % 9000)).padStart(4, "0")}`,
    service: args.profile.industryId,
    notes: `lead_finder: profile=${args.profile.id}`,
    timeline: [{ at: now, type: "lead_finder_inserted" }],
  };
}

/* --------------------------------- Auth --------------------------------- */

function requireAuth(authHeader: string): { ok: true; payload: JwtPayload } | { ok: false } {
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice("Bearer ".length).trim() : "";
  if (!token) return { ok: false };

  const secret = envGet("JWT_SECRET") ?? "";
  if (!secret) return { ok: false };

  const payload = verifyJwt(secret, token);
  if (!payload) return { ok: false };

  return { ok: true, payload };
}

function verifyJwt(secret: string, token: string): JwtPayload | null {
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

/* ------------------------------ HTTP Helpers ---------------------------- */

function normalizeFnPath(pathname: string): string {
  const prefix = "/.netlify/functions/lead_finder";
  if (pathname.startsWith(prefix)) {
    const rest = pathname.slice(prefix.length);
    return (rest || "/").replaceAll("//", "/");
  }
  return pathname.replaceAll("//", "/");
}

function buildCorsHeaders(req: Request): Headers {
  const h = new Headers();
  h.set("access-control-allow-origin", "*");
  h.set("access-control-allow-methods", "GET,POST,OPTIONS");
  h.set(
    "access-control-allow-headers",
    req.headers.get("access-control-request-headers") ?? "content-type,authorization",
  );
  h.set("access-control-max-age", "86400");
  return h;
}

function respondJson(data: unknown, status: number, corsHeaders: Headers): Response {
  const headers = new Headers(corsHeaders);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
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

/* ------------------------------ Small Utils ----------------------------- */

function envGet(key: string): string | null {
  const v1 = process.env[key];
  if (typeof v1 === "string" && v1.length) return v1;

  const n = (globalThis as any)?.Netlify?.env?.get?.(key);
  if (typeof n === "string" && n.length) return n;

  return null;
}

function nowIso(): string {
  return new Date().toISOString();
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
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

function safeText(v: any): string {
  return typeof v === "string" ? v.trim() : "";
}

function requiredString(v: any): string | null {
  const s = typeof v === "string" ? v.trim() : "";
  return s.length ? s : null;
}

function optionalString(v: any): string | null {
  const s = typeof v === "string" ? v.trim() : "";
  return s.length ? s : null;
}

function optionalNumber(v: any): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim()) {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

function optionalBool(v: any): boolean | null {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s === "true") return true;
    if (s === "false") return false;
  }
  return null;
}

function clampInt(v: string | null | undefined, min: number, max: number, def: number): number {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  const i = Math.floor(n);
  return Math.min(max, Math.max(min, i));
}
