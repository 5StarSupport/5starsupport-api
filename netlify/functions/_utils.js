const jwt = require("jsonwebtoken");
const { getStore } = require("@netlify/blobs");

/**
 * Allowed CORS origins
 */
const ALLOWED_ORIGINS = new Set([
  "https://5starsupport.co",
  "https://www.5starsupport.co",
  "https://crm.5starsupport.co"
]);

/**
 * JSON response helper
 */
function json(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders
    },
    body: JSON.stringify(body)
  };
}

/**
 * CORS headers
 */
function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : "null";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Vary": "Origin",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Max-Age": "86400"
  };
}

/**
 * Authentication / role resolution
 */
function getAuthRole(event) {
  const header = event.headers.authorization || event.headers.Authorization || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) return { role: "anonymous" };

  const token = match[1].trim();

  const websiteKey = process.env.WEBSITE_API_KEY || "";
  const crmKey = process.env.CRM_API_KEY || "";

  // API key auth
  if (websiteKey && token === websiteKey) return { role: "website" };
  if (crmKey && token === crmKey) return { role: "crm_key" };

  // JWT auth
  const jwtSecret = process.env.JWT_SECRET || "";
  if (!jwtSecret) return { role: "anonymous" };

  try {
    const payload = jwt.verify(token, jwtSecret);
    if (payload?.role === "crm") {
      return { role: "crm_jwt", sub: payload.sub || null };
    }
    return { role: "anonymous" };
  } catch {
    return { role: "anonymous" };
  }
}

/**
 * 🔥 NETLIFY BLOBS — AUTO CONFIG (THIS IS THE FIX)
 * - No siteID
 * - No token
 * - No env vars
 * - Explicit object form avoids esbuild/CJS ambiguity
 */
function getDataStore() {
  return getStore({
    name: "5starsupport-crm",
    consistency: "strong"
  });
}

/**
 * Blob-backed helpers
 */
async function readIndex(store) {
  const idx = await store.get("leads:index", { type: "json" });
  return Array.isArray(idx) ? idx : [];
}

async function writeIndex(store, ids) {
  await store.set("leads:index", ids, { type: "json" });
}

async function readLead(store, id) {
  return await store.get(`lead:${id}`, { type: "json" });
}

async function writeLead(store, id, obj) {
  await store.set(`lead:${id}`, obj, { type: "json" });
}

async function deleteLead(store, id) {
  await store.delete(`lead:${id}`);
}

/**
 * Utilities
 */
function safeParseJson(str) {
  try {
    return JSON.parse(str || "{}");
  } catch {
    return null;
  }
}

function nowIso() {
  return new Date().toISOString();
}

module.exports = {
  json,
  corsHeaders,
  getAuthRole,
  getDataStore,
  readIndex,
  writeIndex,
  readLead,
  writeLead,
  deleteLead,
  safeParseJson,
  nowIso
};
