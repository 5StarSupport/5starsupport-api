// File: netlify/functions/leads.js
const { v4: uuidv4 } = require("uuid");
const {
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
  nowIso,
} = require("./_utils");

function normalizeStatus(s) {
  const v = String(s || "").toLowerCase().trim();
  const allowed = new Set(["lead", "follow_up", "appointment", "landed", "no"]);
  return allowed.has(v) ? v : null;
}

function sanitizeString(x, max = 200) {
  return String(x || "")
    .replace(/[^\S\r\n]+/g, " ")
    .trim()
    .slice(0, max);
}

function getPathParts(event) {
  // /.netlify/functions/leads
  // /.netlify/functions/leads/<id>
  // /.netlify/functions/leads/<id>/status
  // /.netlify/functions/leads/<id>/notes
  const p = (event.path || "").split("/").filter(Boolean);
  const i = p.findIndex((s) => s === "leads");
  if (i === -1) return [];
  return p.slice(i + 1);
}

exports.handler = async (event) => {
  const origin = event.headers.origin || event.headers.Origin || "";
  const cors = corsHeaders(origin);

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors, body: "" };
  }

  const auth = getAuthRole(event);
  const parts = getPathParts(event);

  // ✅ FIX: pass event so Netlify Blobs can initialize in Lambda compat mode
  const store = getDataStore(event);

  // Permissions
  const canWebsiteCreate = auth.role === "website";
  const canCrm = auth.role === "crm_key" || auth.role === "crm_jwt";

  const deny = () => json(401, { error: true, message: "Unauthorized" }, cors);

  try {
    // ROUTE: /leads (list or create)
    if (parts.length === 0) {
      if (event.httpMethod === "GET") {
        if (!canCrm) return deny();

        const ids = await readIndex(store);
        const leads = [];
        for (const id of ids) {
          const item = await readLead(store, id);
          if (item) leads.push(item);
        }
        leads.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
        return json(200, { items: leads }, cors);
      }

      if (event.httpMethod === "POST") {
        if (!(canWebsiteCreate || canCrm)) return deny();

        const body = safeParseJson(event.body);
        if (!body) return json(400, { error: true, message: "Invalid JSON body" }, cors);

        const id = uuidv4();
        const createdAt = nowIso();

        const lead = {
          id,
          name: sanitizeString(body.name, 160),
          phone: sanitizeString(body.phone, 60),
          email: sanitizeString(body.email, 120),
          industry: sanitizeString(body.industry, 80),
          subIndustry: sanitizeString(body.subIndustry, 80),
          location: sanitizeString(body.location, 120),
          status: normalizeStatus(body.status) || "lead",
          source: canWebsiteCreate ? "website" : (sanitizeString(body.source, 40) || "crm"),
          notes: [],
          createdAt,
          updatedAt: createdAt,
        };

        if (!lead.name) {
          return json(400, { error: true, message: "Field 'name' is required" }, cors);
        }

        await writeLead(store, id, lead);

        const ids = await readIndex(store);
        ids.push(id);
        await writeIndex(store, ids);

        return json(201, { item: lead }, cors);
      }

      return json(405, { error: true, message: "Method not allowed" }, cors);
    }

    // ROUTE: /leads/<id>[/...]
    const id = parts[0];

    // /leads/<id>/status
    if (parts.length === 2 && parts[1] === "status") {
      if (event.httpMethod !== "PATCH") {
        return json(405, { error: true, message: "Method not allowed" }, cors);
      }
      if (!canCrm) return deny();

      const body = safeParseJson(event.body);
      if (!body) return json(400, { error: true, message: "Invalid JSON body" }, cors);

      const next = normalizeStatus(body.status);
      if (!next) return json(400, { error: true, message: "Invalid status" }, cors);

      const lead = await readLead(store, id);
      if (!lead) return json(404, { error: true, message: "Not found" }, cors);

      lead.status = next;
      lead.updatedAt = nowIso();

      await writeLead(store, id, lead);
      return json(200, { item: lead }, cors);
    }

    // /leads/<id>/notes
    if (parts.length === 2 && parts[1] === "notes") {
      if (event.httpMethod !== "POST") {
        return json(405, { error: true, message: "Method not allowed" }, cors);
      }
      if (!canCrm) return deny();

      const body = safeParseJson(event.body);
      if (!body) return json(400, { error: true, message: "Invalid JSON body" }, cors);

      const text = sanitizeString(body.text, 800);
      if (!text) return json(400, { error: true, message: "Note text required" }, cors);

      const lead = await readLead(store, id);
      if (!lead) return json(404, { error: true, message: "Not found" }, cors);

      lead.notes = Array.isArray(lead.notes) ? lead.notes : [];
      lead.notes.push({ id: uuidv4(), text, at: nowIso() });
      lead.updatedAt = nowIso();

      await writeLead(store, id, lead);
      return json(200, { item: lead }, cors);
    }

    // /leads/<id> (GET, PATCH, DELETE)
    if (parts.length === 1) {
      if (event.httpMethod === "GET") {
        if (!canCrm) return deny();
        const lead = await readLead(store, id);
        if (!lead) return json(404, { error: true, message: "Not found" }, cors);
        return json(200, { item: lead }, cors);
      }

      if (event.httpMethod === "PATCH") {
        if (!canCrm) return deny();
        const body = safeParseJson(event.body);
        if (!body) return json(400, { error: true, message: "Invalid JSON body" }, cors);

        const lead = await readLead(store, id);
        if (!lead) return json(404, { error: true, message: "Not found" }, cors);

        if (body.name !== undefined) lead.name = sanitizeString(body.name, 160);
        if (body.phone !== undefined) lead.phone = sanitizeString(body.phone, 60);
        if (body.email !== undefined) lead.email = sanitizeString(body.email, 120);
        if (body.industry !== undefined) lead.industry = sanitizeString(body.industry, 80);
        if (body.subIndustry !== undefined) lead.subIndustry = sanitizeString(body.subIndustry, 80);
        if (body.location !== undefined) lead.location = sanitizeString(body.location, 120);
        if (body.status !== undefined) {
          const ns = normalizeStatus(body.status);
          if (!ns) return json(400, { error: true, message: "Invalid status" }, cors);
          lead.status = ns;
        }

        if (!lead.name) {
          return json(400, { error: true, message: "Field 'name' is required" }, cors);
        }

        lead.updatedAt = nowIso();
        await writeLead(store, id, lead);
        return json(200, { item: lead }, cors);
      }

      if (event.httpMethod === "DELETE") {
        if (!canCrm) return deny();

        const existing = await readLead(store, id);
        if (!existing) return json(404, { error: true, message: "Not found" }, cors);

        await deleteLead(store, id);

        const ids = await readIndex(store);
        const next = ids.filter((x) => x !== id);
        await writeIndex(store, next);

        return json(200, { success: true }, cors);
      }

      return json(405, { error: true, message: "Method not allowed" }, cors);
    }

    return json(404, { error: true, message: "Not found" }, cors);
  } catch (err) {
    return json(500, { error: true, message: "Server error" }, cors);
  }
};
