// File: netlify/functions/inventory.js
const { v4: uuidv4 } = require("uuid");
const fs = require("node:fs");
const path = require("node:path");

const { json, getAuthRole, getDataStore, safeParseJson, nowIso } = require("./_utils");

exports.config = { path: "/api/inventory/*" };

const INVENTORY_KEY = "inventory:v1";
const IMAGE_KEY_PREFIX = "inventory:image:";

const ALLOWED_ORIGINS = new Set([
  "https://5starsupport.co",
  "https://www.5starsupport.co",
  "https://crm.5starsupport.co",
  "https://dashboard.5starsupport.co",
]);

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : "null";
  return {
    "Access-Control-Allow-Origin": allowed,
    Vary: "Origin",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Max-Age": "86400",
  };
}

function requireWriteAuth(event) {
  const { role } = getAuthRole(event);
  if (role !== "crm_jwt" && role !== "crm_key") {
    const origin = event.headers.origin || event.headers.Origin || "";
    return json(401, { error: "Unauthorized" }, corsHeaders(origin));
  }
  return null;
}

function parsePath(event) {
  const p = String(event.path || "");
  const base = "/api/inventory";
  if (p === base) return { rest: "" };
  if (p.startsWith(base + "/")) return { rest: p.slice(base.length + 1) };
  return { rest: "" };
}

function readSeedDoc() {
  const seedPath = path.join(__dirname, "_seed", "inventory.json");
  const raw = fs.readFileSync(seedPath, "utf8");
  const doc = safeParseJson(raw);
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.vehicles)) {
    throw new Error("Bad seed inventory.json");
  }
  return doc;
}

async function loadInventoryDoc(store) {
  const existing = await store.get(INVENTORY_KEY, { type: "json" });
  if (existing && typeof existing === "object" && Array.isArray(existing.vehicles)) return existing;

  const seed = readSeedDoc();
  await store.set(INVENTORY_KEY, seed, { type: "json" });
  return seed;
}

async function saveInventoryDoc(store, doc) {
  const next = {
    version: 1,
    updatedAt: nowIso(),
    vehicles: Array.isArray(doc.vehicles) ? doc.vehicles : [],
  };
  await store.set(INVENTORY_KEY, next, { type: "json" });
  return next;
}

function normalizeVehicleInput(input, { isCreate }) {
  const v = input && typeof input === "object" ? input : {};

  const id = String(v.id || "").trim();
  const stockId = isCreate ? (id || String(v.stockId || "").trim()) : id;

  return {
    id: stockId,
    type: String(v.type || "").trim(),
    title: String(v.title || "").trim(),
    price: String(v.price || "").trim(),
    meta: Array.isArray(v.meta) ? v.meta.map(String) : [],
    img: String(v.img || "").trim(),

    year: typeof v.year === "number" ? v.year : Number(v.year || 0) || null,
    make: String(v.make || "").trim(),
    model: String(v.model || "").trim(),
    trim: String(v.trim || "").trim(),

    mileage: typeof v.mileage === "number" ? v.mileage : Number(v.mileage || 0) || null,
    color: String(v.color || "").trim(),
    mpg: typeof v.mpg === "number" ? v.mpg : Number(v.mpg || 0) || null,
    cyl: typeof v.cyl === "number" ? v.cyl : Number(v.cyl || 0) || null,
    transmission: String(v.transmission || "").trim(),
    fuel: String(v.fuel || "").trim(),
    drivetrain: String(v.drivetrain || "").trim(),
    bodyType: String(v.bodyType || v.type || "").trim(),

    vin: String(v.vin || "").trim(),
    modelCode: String(v.modelCode || "").trim(),
    interiorColor: String(v.interiorColor || "").trim(),
    exteriorColor: String(v.exteriorColor || "").trim(),

    featured: Boolean(v.featured),
    features: Array.isArray(v.features) ? v.features.map(String) : [],
    highlightedFeatures: Array.isArray(v.highlightedFeatures) ? v.highlightedFeatures.map(String) : [],

    images: Array.isArray(v.images) ? v.images : [],

    createdAt: String(v.createdAt || "") || null,
    updatedAt: String(v.updatedAt || "") || null,
    deletedAt: String(v.deletedAt || "") || null,
  };
}

function mergeVehicle(existing, patch) {
  const base = { ...existing };
  const p = patch && typeof patch === "object" ? patch : {};
  const allowed = [
    "type","title","price","meta","img","year","make","model","trim","mileage","color","mpg","cyl",
    "transmission","fuel","drivetrain","bodyType","vin","modelCode","interiorColor","exteriorColor",
    "featured","features","highlightedFeatures",
  ];
  for (const k of allowed) if (k in p) base[k] = p[k];
  return base;
}

function base64ToBuffer(b64) {
  const s = String(b64 || "");
  const m = s.match(/^data:([^;]+);base64,(.+)$/);
  if (m) return { contentType: m[1], buffer: Buffer.from(m[2], "base64") };
  return { contentType: null, buffer: Buffer.from(s, "base64") };
}

exports.handler = async (event) => {
  const origin = event.headers.origin || event.headers.Origin || "";
  const cors = corsHeaders(origin);

  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: cors, body: "" };

  const store = getDataStore(event);
  const { rest } = parsePath(event);

  try {
    // GET /api/inventory
    if (event.httpMethod === "GET" && (!rest || rest === "")) {
      const doc = await loadInventoryDoc(store);
      const includeDeleted = String((event.queryStringParameters || {}).includeDeleted || "") === "1";
      const vehicles = doc.vehicles.filter((v) => includeDeleted || !v.deletedAt);
      return json(200, { updatedAt: doc.updatedAt, vehicles }, cors);
    }

    // GET /api/inventory/:id
    if (event.httpMethod === "GET" && rest && !rest.includes("/")) {
      const id = decodeURIComponent(rest);
      const doc = await loadInventoryDoc(store);
      const v = doc.vehicles.find((x) => x.id === id);
      if (!v || v.deletedAt) return json(404, { error: "Not found" }, cors);
      return json(200, { vehicle: v }, cors);
    }

    // POST /api/inventory
    if (event.httpMethod === "POST" && (!rest || rest === "")) {
      const authFail = requireWriteAuth(event);
      if (authFail) return authFail;

      const body = safeParseJson(event.body);
      const input = normalizeVehicleInput(body, { isCreate: true });
      if (!input.id) return json(400, { error: "Missing id (Stock ID)" }, cors);

      const doc = await loadInventoryDoc(store);
      const exists = doc.vehicles.some((x) => x.id === input.id && !x.deletedAt);
      if (exists) return json(409, { error: "Vehicle id already exists" }, cors);

      const now = nowIso();
      const vehicle = { ...input, createdAt: now, updatedAt: now, deletedAt: null, images: [] };

      doc.vehicles.push(vehicle);
      const saved = await saveInventoryDoc(store, doc);

      return json(
        201,
        { ok: true, vehicle, updatedAt: saved.updatedAt, highlightedFeatures: vehicle.highlightedFeatures || [] },
        cors
      );
    }

    // PUT/PATCH /api/inventory/:id
    if ((event.httpMethod === "PUT" || event.httpMethod === "PATCH") && rest && !rest.includes("/")) {
      const authFail = requireWriteAuth(event);
      if (authFail) return authFail;

      const id = decodeURIComponent(rest);
      const body = safeParseJson(event.body);
      const doc = await loadInventoryDoc(store);

      const idx = doc.vehicles.findIndex((x) => x.id === id);
      if (idx === -1 || doc.vehicles[idx].deletedAt) return json(404, { error: "Not found" }, cors);

      const existing = doc.vehicles[idx];
      const patch =
        event.httpMethod === "PUT"
          ? normalizeVehicleInput(body, { isCreate: false })
          : normalizeVehicleInput({ ...existing, ...body }, { isCreate: false });

      const merged = mergeVehicle(existing, patch);
      merged.updatedAt = nowIso();
      merged.images = Array.isArray(existing.images) ? existing.images : [];

      doc.vehicles[idx] = merged;
      const saved = await saveInventoryDoc(store, doc);

      return json(
        200,
        { ok: true, vehicle: merged, updatedAt: saved.updatedAt, highlightedFeatures: merged.highlightedFeatures || [] },
        cors
      );
    }

    // DELETE /api/inventory/:id (soft delete)
    if (event.httpMethod === "DELETE" && rest && !rest.includes("/")) {
      const authFail = requireWriteAuth(event);
      if (authFail) return authFail;

      const id = decodeURIComponent(rest);
      const doc = await loadInventoryDoc(store);
      const idx = doc.vehicles.findIndex((x) => x.id === id);
      if (idx === -1 || doc.vehicles[idx].deletedAt) return json(404, { error: "Not found" }, cors);

      doc.vehicles[idx].deletedAt = nowIso();
      doc.vehicles[idx].updatedAt = nowIso();

      const saved = await saveInventoryDoc(store, doc);
      return json(200, { ok: true, id, updatedAt: saved.updatedAt }, cors);
    }

    // POST /api/inventory/:id/images
    if (event.httpMethod === "POST" && rest && rest.split("/").length === 2 && rest.endsWith("images")) {
      const authFail = requireWriteAuth(event);
      if (authFail) return authFail;

      const [vehicleIdRaw] = rest.split("/");
      const vehicleId = decodeURIComponent(vehicleIdRaw);

      const body = safeParseJson(event.body);
      if (!body) return json(400, { error: "Invalid JSON" }, cors);

      const filename = String(body.filename || "image.jpg");
      const declaredType = String(body.contentType || "").trim() || null;
      const b64 = body.dataBase64;
      if (!b64) return json(400, { error: "Missing dataBase64" }, cors);

      const { contentType, buffer } = base64ToBuffer(b64);
      const finalType = declaredType || contentType || "application/octet-stream";

      const doc = await loadInventoryDoc(store);
      const v = doc.vehicles.find((x) => x.id === vehicleId);
      if (!v || v.deletedAt) return json(404, { error: "Vehicle not found" }, cors);

      const imageId = uuidv4();
      const key = `${IMAGE_KEY_PREFIX}${vehicleId}:${imageId}`;

      await store.set(key, buffer, { metadata: { contentType: finalType, filename } });

      const imgMeta = { id: imageId, filename, contentType: finalType, createdAt: nowIso(), deletedAt: null };
      v.images = Array.isArray(v.images) ? v.images : [];
      v.images.push(imgMeta);

      if (!v.img) v.img = `/api/inventory/${encodeURIComponent(vehicleId)}/images/${encodeURIComponent(imageId)}`;

      v.updatedAt = nowIso();
      const saved = await saveInventoryDoc(store, doc);

      return json(
        201,
        {
          ok: true,
          image: imgMeta,
          vehicleId,
          updatedAt: saved.updatedAt,
          imageUrl: `/api/inventory/${encodeURIComponent(vehicleId)}/images/${encodeURIComponent(imageId)}`,
        },
        cors
      );
    }

    // GET /api/inventory/:id/images/:imageId
    if (event.httpMethod === "GET" && rest && rest.split("/").length === 3 && rest.includes("/images/")) {
      const [vehicleIdRaw, , imageIdRaw] = rest.split("/");
      const vehicleId = decodeURIComponent(vehicleIdRaw);
      const imageId = decodeURIComponent(imageIdRaw);

      const doc = await loadInventoryDoc(store);
      const v = doc.vehicles.find((x) => x.id === vehicleId);
      if (!v || v.deletedAt) return { statusCode: 404, headers: cors, body: "Not found" };

      const meta = Array.isArray(v.images) ? v.images.find((x) => x.id === imageId) : null;
      if (!meta || meta.deletedAt) return { statusCode: 404, headers: cors, body: "Not found" };

      const key = `${IMAGE_KEY_PREFIX}${vehicleId}:${imageId}`;
      const arr = await store.get(key, { type: "arrayBuffer" });
      if (!arr) return { statusCode: 404, headers: cors, body: "Not found" };

      return {
        statusCode: 200,
        headers: { ...cors, "Content-Type": meta.contentType || "application/octet-stream" },
        body: Buffer.from(arr).toString("base64"),
        isBase64Encoded: true,
      };
    }

    // DELETE /api/inventory/:id/images/:imageId (mark deletedAt + delete blob)
    if (event.httpMethod === "DELETE" && rest && rest.split("/").length === 3 && rest.includes("/images/")) {
      const authFail = requireWriteAuth(event);
      if (authFail) return authFail;

      const [vehicleIdRaw, , imageIdRaw] = rest.split("/");
      const vehicleId = decodeURIComponent(vehicleIdRaw);
      const imageId = decodeURIComponent(imageIdRaw);

      const doc = await loadInventoryDoc(store);
      const v = doc.vehicles.find((x) => x.id === vehicleId);
      if (!v || v.deletedAt) return json(404, { error: "Vehicle not found" }, cors);

      const imgs = Array.isArray(v.images) ? v.images : [];
      const img = imgs.find((x) => x.id === imageId);
      if (!img) return json(404, { error: "Image not found" }, cors);

      if (!img.deletedAt) img.deletedAt = nowIso();

      const servedUrl = `/api/inventory/${encodeURIComponent(vehicleId)}/images/${encodeURIComponent(imageId)}`;
      if (v.img === servedUrl) v.img = "";

      v.updatedAt = nowIso();
      await store.delete(`${IMAGE_KEY_PREFIX}${vehicleId}:${imageId}`);

      const saved = await saveInventoryDoc(store, doc);
      return json(200, { ok: true, vehicleId, imageId, deletedAt: img.deletedAt, updatedAt: saved.updatedAt }, cors);
    }

    return json(404, { error: "Not found" }, cors);
  } catch (e) {
    return json(500, { error: "Server error", detail: String(e && e.message ? e.message : e) }, cors);
  }
};
