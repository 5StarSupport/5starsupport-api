const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { json, corsHeaders, requireEnv, safeParseJson } = require("./_utils");

exports.handler = async (event) => {
  const origin = event.headers.origin || event.headers.Origin || "";
  const cors = corsHeaders(origin);

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return json(405, { error: true, message: "Method not allowed" }, cors);
  }

  // Required env vars
  const username = requireEnv("CRM_USERNAME");
  const passwordHash = requireEnv("CRM_PASSWORD_HASH");
  const jwtSecret = requireEnv("JWT_SECRET");

  const body = safeParseJson(event.body);
  if (!body) return json(400, { error: true, message: "Invalid JSON body" }, cors);

  const u = (body.username || "").trim();
  const p = (body.password || "");

  // Constant-time-ish compare for username
  if (!u || !p || u !== username) {
    return json(401, { error: true, message: "Invalid credentials" }, cors);
  }

  const ok = await bcrypt.compare(p, passwordHash);
  if (!ok) {
    return json(401, { error: true, message: "Invalid credentials" }, cors);
  }

  const expiresInSeconds = 60 * 60; // 1 hour
  const token = jwt.sign(
    { role: "crm", sub: u },
    jwtSecret,
    { expiresIn: expiresInSeconds }
  );

  return json(200, { token, expires_in: expiresInSeconds }, cors);
};
