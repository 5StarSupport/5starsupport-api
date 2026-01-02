// netlify/functions/auth-login.js
const crypto = require("node:crypto");

function json(statusCode, data, headers = {}) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
    body: JSON.stringify(data),
  };
}

function buildCorsHeaders(origin) {
  const allowed = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  // If ALLOWED_ORIGINS is empty -> allow all (or lock it down if you prefer)
  const allowOrigin = allowed.length === 0 ? "*" : allowed.includes(origin) ? origin : "";

  return {
    "access-control-allow-origin": allowOrigin,
    "access-control-allow-methods": "POST,OPTIONS",
    "access-control-allow-headers": "content-type,authorization",
    "access-control-max-age": "86400",
    ...(allowOrigin && allowOrigin !== "*" ? { vary: "origin" } : {}),
  };
}

function b64url(str) {
  return Buffer.from(str, "utf8")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function hmacSha256(secret, data) {
  return crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signJwt(secret, payload) {
  const header = { alg: "HS256", typ: "JWT" };
  const data = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = hmacSha256(secret, data);
  return `${data}.${sig}`;
}

function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

exports.handler = async (event) => {
  const origin = event.headers?.origin || "";
  const cors = buildCorsHeaders(origin);

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return json(405, { error: "method_not_allowed" }, cors);
  }

  const jwtSecret = process.env.JWT_SECRET || "";
  if (!jwtSecret) {
    return json(500, { error: "missing_jwt_secret" }, cors);
  }

  let body = null;
  try {
    body = event.body ? JSON.parse(event.body) : null;
  } catch {
    body = null;
  }

  const username = typeof body?.username === "string" ? body.username.trim() : "";
  const password = typeof body?.password === "string" ? body.password : "";

  if (!username || !password) {
    return json(400, { error: "missing_credentials" }, cors);
  }

  const expectedUser = process.env.CRM_USERNAME || "";
  const expectedPass = process.env.CRM_PASSWORD || "";
  const expectedHash = (process.env.CRM_PASSWORD_HASH || "").toLowerCase();

  let ok = false;

  if (expectedUser && username === expectedUser) {
    if (expectedHash) {
      ok = timingSafeEqualStr(sha256Hex(password).toLowerCase(), expectedHash);
    } else if (expectedPass) {
      ok = timingSafeEqualStr(password, expectedPass);
    }
  }

  if (!ok) {
    return json(401, { error: "invalid_credentials" }, cors);
  }

  const now = Math.floor(Date.now() / 1000);
  const token = signJwt(jwtSecret, {
    sub: username,
    role: "admin",
    iat: now,
    exp: now + 60 * 60 * 12,
  });

  return json(200, { token, role: "admin" }, cors);
};
