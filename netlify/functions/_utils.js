// File: netlify/functions/_utils.js
const jwt = require("jsonwebtoken");
const { connectLambda, getStore } = require("@netlify/blobs");

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name}`);
  return v;
}

/**
 * Netlify Blobs store accessor.
 *
 * - Lambda compatibility mode: MUST call connectLambda(event) before getStore()
 * - Manual mode fallback: NETLIFY_SITE_ID + NETLIFY_AUTH_TOKEN
 */
function getDataStore(event) {
  if (event) connectLambda(event);

  const name = "5starsupport-crm";
  const siteID = process.env.NETLIFY_SITE_ID;
  const token = process.env.NETLIFY_AUTH_TOKEN;

  if (siteID && token) return getStore(name, { siteID, token });
  return getStore(name);
}

const ALLOWED_ORIGINS = new Set([
  "https://5starsupport.co",
  "https://www.5starsupport.co",
  "https://crm.5starsupport.co",
]);

function json(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : "null";
  return {
    "Access-Control-Allow-Origin": allowed,
    Vary: "Origin",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Max-Age": "86400",
  };
}

function getAuthRole(event) {
  const header = event.headers.authorization || event.headers.Authorization || "";
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) return { role: "anonymous" };

  const token = m[1].trim();
  const websiteKey = process.env.WEBSITE_API_KEY || "";
  const crmKey = process.env.CRM_API_KEY || "";

  if (websiteKey && token === websiteKey) return { role: "website" };
  if (crmKey && token === crmKey) return { role: "crm_key" };

  const secret = process.env.JWT_SECRET || "";
  if (!secret) return { role: "anonymous" };

  try {
    const payload = jwt.verify(token, secret);
    if (payload?.role === "crm") return { role: "crm_jwt", sub: payload.sub || null };
    return { role: "anonymous" };
  } catch {
    return { role: "anonymous" };
  }
}

async function readIndex(store) {
  const idx = await store.get("leads:index", { type: "json" });
  return Array.isArray(idx) ? idx : [];
}

async function writeIndex(store, ids) {
  await store.set("leads:index", ids, { type: "json" });
}

async function readLead(store, id) {
  return store.get(`lead:${id}`, { type: "json" });
}

async function writeLead(store, id, obj) {
  await store.set(`lead:${id}`, obj, { type: "json" });
}

async function deleteLead(store, id) {
  await store.delete(`lead:${id}`);
}

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
  requireEnv,
  readIndex,
  writeIndex,
  readLead,
  writeLead,
  deleteLead,
  safeParseJson,
  nowIso,
};
