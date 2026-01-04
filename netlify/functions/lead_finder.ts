// file: netlify/functions/lead_finder.ts
import type { Handler } from "@netlify/functions";

export const handler: Handler = async (event) => {
  return {
    statusCode: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ok: true,
      function: "lead_finder",
      method: event.httpMethod,
      path: event.path,
      ts: new Date().toISOString(),
    }),
  };
};


//// file: src/lead-finder/types.ts
export type LeadFinderProvider = "google_places";

export type LeadFinderRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type GeoType = "city" | "latlng";

export interface LeadFinderProfile {
  id: string;
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
}

export interface LeadFinderRun {
  id: string;
  profileId: string;
  status: LeadFinderRunStatus;
  provider: LeadFinderProvider;
  requestedByUserId: string;

  startedAt: Date | null;
  finishedAt: Date | null;

  statsTotalSeen: number;
  statsQualified: number;
  statsInserted: number;
  statsDuplicates: number;
  statsMissingPhone: number;
  statsHasWebsite: number;

  errorMessage: string | null;
}

export interface ProviderBusiness {
  provider: LeadFinderProvider;
  providerPlaceId: string;

  businessName: string;
  phoneRaw: string | null;
  websiteUrl: string | null;
  addressFull: string | null;
}

export type RunItemDecision =
  | "inserted"
  | "skipped_missing_phone"
  | "skipped_has_website"
  | "skipped_duplicate"
  | "skipped_invalid";

export interface NormalizedBusiness {
  provider: LeadFinderProvider;
  providerPlaceId: string;

  businessName: string;
  phoneRaw: string | null;
  phoneE164: string | null;
  websiteUrl: string | null;
  addressFull: string | null;
}

//// file: src/lead-finder/db/pool.ts
import { Pool } from "pg";

export function createPgPool() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error("DATABASE_URL is required");
  return new Pool({ connectionString });
}

//// file: src/lead-finder/db/repo.ts
import type { Pool, PoolClient } from "pg";
import type {
  LeadFinderProfile,
  LeadFinderRun,
  LeadFinderRunStatus,
  NormalizedBusiness,
  RunItemDecision,
} from "../types.js";

function toProfile(row: any): LeadFinderProfile {
  return {
    id: row.id,
    name: row.name,
    industryId: row.industry_id,
    subIndustryId: row.sub_industry_id,
    geoType: row.geo_type,
    city: row.city,
    state: row.state,
    country: row.country,
    centerLat: row.center_lat,
    centerLng: row.center_lng,
    radiusMeters: row.radius_meters,
    requirePhone: row.require_phone,
    requireNoWebsite: row.require_no_website,
  };
}

function toRun(row: any): LeadFinderRun {
  return {
    id: row.id,
    profileId: row.profile_id,
    status: row.status,
    provider: row.provider,
    requestedByUserId: row.requested_by_user_id,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    statsTotalSeen: row.stats_total_seen,
    statsQualified: row.stats_qualified,
    statsInserted: row.stats_inserted,
    statsDuplicates: row.stats_duplicates,
    statsMissingPhone: row.stats_missing_phone,
    statsHasWebsite: row.stats_has_website,
    errorMessage: row.error_message,
  };
}

export class LeadFinderRepo {
  constructor(private readonly pool: Pool) {}

  async getProfile(profileId: string): Promise<LeadFinderProfile | null> {
    const { rows } = await this.pool.query(
      `select * from lead_finder_profiles where id = $1`,
      [profileId],
    );
    return rows[0] ? toProfile(rows[0]) : null;
  }

  async createRun(input: {
    profileId: string;
    requestedByUserId: string;
    provider: string;
  }): Promise<LeadFinderRun> {
    const { rows } = await this.pool.query(
      `
      insert into lead_finder_runs (profile_id, status, provider, requested_by_user_id)
      values ($1, 'queued', $2, $3)
      returning *
      `,
      [input.profileId, input.provider, input.requestedByUserId],
    );
    return toRun(rows[0]);
  }

  async getRun(runId: string): Promise<LeadFinderRun | null> {
    const { rows } = await this.pool.query(
      `select * from lead_finder_runs where id = $1`,
      [runId],
    );
    return rows[0] ? toRun(rows[0]) : null;
  }

  async cancelRun(runId: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `
      update lead_finder_runs
      set status = 'cancelled', finished_at = now()
      where id = $1 and status in ('queued','running')
      `,
      [runId],
    );
    return rowCount === 1;
  }

  async claimNextQueuedRun(provider: string): Promise<LeadFinderRun | null> {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      const { rows } = await client.query(
        `
        select *
        from lead_finder_runs
        where status = 'queued' and provider = $1
        order by created_at asc
        for update skip locked
        limit 1
        `,
        [provider],
      );

      if (!rows[0]) {
        await client.query("commit");
        return null;
      }

      const runId = rows[0].id as string;
      const { rows: updated } = await client.query(
        `
        update lead_finder_runs
        set status = 'running', started_at = now()
        where id = $1
        returning *
        `,
        [runId],
      );

      await client.query("commit");
      return toRun(updated[0]);
    } catch (e) {
      await client.query("rollback");
      throw e;
    } finally {
      client.release();
    }
  }

  async setRunStatus(runId: string, status: LeadFinderRunStatus, error?: string) {
    await this.pool.query(
      `
      update lead_finder_runs
      set status = $2,
          error_message = $3,
          finished_at = case when $2 in ('completed','failed','cancelled') then now() else finished_at end
      where id = $1
      `,
      [runId, status, error ?? null],
    );
  }

  async bumpRunStats(runId: string, delta: Partial<Record<
    | "statsTotalSeen"
    | "statsQualified"
    | "statsInserted"
    | "statsDuplicates"
    | "statsMissingPhone"
    | "statsHasWebsite",
    number
  >>) {
    const fields = Object.entries(delta).filter(([, v]) => typeof v === "number");
    if (fields.length === 0) return;

    const sets = fields
      .map(([k], i) => {
        const col = k
          .replace(/[A-Z]/g, (m) => `_${m.toLowerCase()}`)
          .toLowerCase();
        return `${col} = ${col} + $${i + 2}`;
      })
      .join(", ");

    const values = fields.map(([, v]) => v as number);
    await this.pool.query(
      `update lead_finder_runs set ${sets} where id = $1`,
      [runId, ...values],
    );
  }

  async isDuplicate(
    client: PoolClient,
    input: { provider: string; providerPlaceId: string; phoneE164: string | null; name: string; addressFull: string | null },
  ): Promise<boolean> {
    const byProvider = await client.query(
      `
      select 1
      from lead_external_ids
      where provider = $1 and provider_place_id = $2
      limit 1
      `,
      [input.provider, input.providerPlaceId],
    );
    if (byProvider.rowCount) return true;

    if (input.phoneE164) {
      const byPhone = await client.query(
        `select 1 from lead_dedupe_keys where key_type = 'phone' and dedupe_key = $1 limit 1`,
        [input.phoneE164],
      );
      if (byPhone.rowCount) return true;
    }

    if (input.addressFull) {
      const key = `${normalizeKey(input.name)}|${normalizeKey(input.addressFull)}`;
      const byNameAddr = await client.query(
        `select 1 from lead_dedupe_keys where key_type = 'name_address' and dedupe_key = $1 limit 1`,
        [key],
      );
      if (byNameAddr.rowCount) return true;
    }

    return false;
  }

  async insertLeadAndAudit(
    client: PoolClient,
    runId: string,
    profile: LeadFinderProfile,
    b: NormalizedBusiness,
    decision: RunItemDecision,
    leadId?: string,
  ) {
    await client.query(
      `
      insert into lead_finder_run_items (
        run_id, provider, provider_place_id, business_name,
        phone_raw, phone_e164, website_url, address_full,
        decision, lead_id
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      `,
      [
        runId,
        b.provider,
        b.providerPlaceId,
        b.businessName,
        b.phoneRaw,
        b.phoneE164,
        b.websiteUrl,
        b.addressFull,
        decision,
        leadId ?? null,
      ],
    );

    if (decision !== "inserted" || !leadId) return;

    await client.query(
      `insert into lead_external_ids (lead_id, provider, provider_place_id) values ($1,$2,$3) on conflict do nothing`,
      [leadId, b.provider, b.providerPlaceId],
    );

    if (b.phoneE164) {
      await client.query(
        `insert into lead_dedupe_keys (lead_id, key_type, dedupe_key) values ($1,'phone',$2) on conflict do nothing`,
        [leadId, b.phoneE164],
      );
    }

    if (b.addressFull) {
      const key = `${normalizeKey(b.businessName)}|${normalizeKey(b.addressFull)}`;
      await client.query(
        `insert into lead_dedupe_keys (lead_id, key_type, dedupe_key) values ($1,'name_address',$2) on conflict do nothing`,
        [leadId, key],
      );
    }
  }

  async createColdLead(
    client: PoolClient,
    runId: string,
    profile: LeadFinderProfile,
    b: NormalizedBusiness,
  ): Promise<string> {
    const { rows } = await client.query(
      `
      insert into leads (
        status, industry_id, sub_industry_id,
        business_name, phone_e164, website_url, address_full,
        source, source_run_id
      ) values (
        'cold', $1, $2, $3, $4, $5, $6,
        'lead_finder', $7
      )
      returning id
      `,
      [
        profile.industryId,
        profile.subIndustryId,
        b.businessName,
        b.phoneE164,
        b.websiteUrl,
        b.addressFull,
        runId,
      ],
    );
    return rows[0].id as string;
  }
}

function normalizeKey(s: string) {
  return s.trim().toLowerCase().replace(/\s+/g, " ");
}

//// file: src/lead-finder/normalize.ts
import type { ProviderBusiness, NormalizedBusiness } from "./types.js";

export function normalizeBusiness(b: ProviderBusiness): NormalizedBusiness {
  return {
    provider: b.provider,
    providerPlaceId: b.providerPlaceId,
    businessName: b.businessName.trim(),
    phoneRaw: b.phoneRaw,
    phoneE164: normalizePhoneToE164(b.phoneRaw),
    websiteUrl: normalizeWebsite(b.websiteUrl),
    addressFull: b.addressFull?.trim() ?? null,
  };
}

function normalizeWebsite(url: string | null): string | null {
  if (!url) return null;
  const trimmed = url.trim();
  if (!trimmed) return null;
  try {
    const u = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    u.hash = "";
    return u.toString();
  } catch {
    return trimmed;
  }
}

/**
 * Minimal phone normalizer.
 * Replace with libphonenumber if you need full international support.
 */
function normalizePhoneToE164(phoneRaw: string | null): string | null {
  if (!phoneRaw) return null;
  const digits = phoneRaw.replace(/[^\d+]/g, "");
  if (!digits) return null;
  if (digits.startsWith("+")) return digits;
  // Assumes US default if no country code; adjust to your CRM locale rules.
  if (digits.length === 10) return `+1${digits}`;
  return null;
}

//// file: src/lead-finder/provider/googlePlaces.ts
import type { LeadFinderProfile, ProviderBusiness } from "../types.js";

/**
 * Connector boundary.
 * Implement with the official Google Places API in your codebase.
 */
export interface PlacesClient {
  searchBusinesses(input: {
    query: string;
    centerLat: number;
    centerLng: number;
    radiusMeters: number;
    pageToken?: string | null;
  }): Promise<{ results: Array<Omit<ProviderBusiness, "provider">>; nextPageToken: string | null }>;
}

export async function* searchAllBusinesses(
  places: PlacesClient,
  profile: LeadFinderProfile,
  query: string,
): AsyncGenerator<ProviderBusiness> {
  if (profile.centerLat == null || profile.centerLng == null) {
    throw new Error("lat/lng required for provider search");
  }

  let pageToken: string | null = null;
  for (;;) {
    const page = await places.searchBusinesses({
      query,
      centerLat: profile.centerLat,
      centerLng: profile.centerLng,
      radiusMeters: profile.radiusMeters,
      pageToken,
    });

    for (const r of page.results) {
      yield { ...r, provider: "google_places" };
    }

    if (!page.nextPageToken) break;
    pageToken = page.nextPageToken;
  }
}

//// file: src/lead-finder/service.ts
import type { Pool } from "pg";
import type { LeadFinderProfile, LeadFinderRun, PlacesClient, ProviderBusiness, RunItemDecision } from "./types.js";
import { normalizeBusiness } from "./normalize.js";
import { LeadFinderRepo } from "./db/repo.js";
import { searchAllBusinesses } from "./provider/googlePlaces.js";

export class LeadFinderService {
  private readonly repo: LeadFinderRepo;

  constructor(
    private readonly pool: Pool,
    private readonly placesClient: PlacesClient,
  ) {
    this.repo = new LeadFinderRepo(pool);
  }

  async runOnce(run: LeadFinderRun): Promise<void> {
    const profile = await this.repo.getProfile(run.profileId);
    if (!profile) throw new Error(`profile not found: ${run.profileId}`);

    const query = buildQuery(profile);
    for await (const business of searchAllBusinesses(this.placesClient, profile, query)) {
      await this.processBusiness(run.id, profile, business);
      const latest = await this.repo.getRun(run.id);
      if (latest?.status === "cancelled") return;
    }
  }

  private async processBusiness(runId: string, profile: LeadFinderProfile, business: ProviderBusiness) {
    const b = normalizeBusiness(business);
    await this.repo.bumpRunStats(runId, { statsTotalSeen: 1 });

    const decision = qualify(profile, b);
    if (decision !== "inserted") {
      await this.repo.bumpRunStats(runId, bumpForDecision(decision));
      await this.withTx(async (client) => {
        await this.repo.insertLeadAndAudit(client, runId, profile, b, decision);
      });
      return;
    }

    await this.repo.bumpRunStats(runId, { statsQualified: 1 });

    await this.withTx(async (client) => {
      const dup = await this.repo.isDuplicate(client, {
        provider: b.provider,
        providerPlaceId: b.providerPlaceId,
        phoneE164: b.phoneE164,
        name: b.businessName,
        addressFull: b.addressFull,
      });

      if (dup) {
        await this.repo.bumpRunStats(runId, { statsDuplicates: 1 });
        await this.repo.insertLeadAndAudit(client, runId, profile, b, "skipped_duplicate");
        return;
      }

      const leadId = await this.repo.createColdLead(client, runId, profile, b);
      await this.repo.bumpRunStats(runId, { statsInserted: 1 });
      await this.repo.insertLeadAndAudit(client, runId, profile, b, "inserted", leadId);
    });
  }

  private async withTx<T>(fn: (client: import("pg").PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      const out = await fn(client);
      await client.query("commit");
      return out;
    } catch (e) {
      await client.query("rollback");
      throw e;
    } finally {
      client.release();
    }
  }
}

function qualify(profile: LeadFinderProfile, b: ReturnType<typeof normalizeBusiness>): RunItemDecision {
  if (profile.requirePhone && !b.phoneE164) return "skipped_missing_phone";
  if (profile.requireNoWebsite && !!b.websiteUrl) return "skipped_has_website";
  if (!b.businessName || !b.providerPlaceId) return "skipped_invalid";
  return "inserted";
}

function bumpForDecision(decision: RunItemDecision) {
  if (decision === "skipped_missing_phone") return { statsMissingPhone: 1 };
  if (decision === "skipped_has_website") return { statsHasWebsite: 1 };
  return {};
}

function buildQuery(profile: LeadFinderProfile) {
  const base = profile.subIndustryId ? `sub:${profile.subIndustryId}` : `industry:${profile.industryId}`;
  return base;
}

//// file: src/lead-finder/routes.ts
import type { Request, Response } from "express";
import { Router } from "express";
import { LeadFinderRepo } from "./db/repo.js";

export function createLeadFinderRouter(deps: { repo: LeadFinderRepo }) {
  const r = Router();

  r.post("/runs", async (req: Request, res: Response) => {
    const { profileId, provider } = req.body ?? {};
    const requestedByUserId = req.header("x-user-id") ?? "unknown";

    if (!profileId) return res.status(400).json({ error: "profileId required" });
    const run = await deps.repo.createRun({
      profileId,
      requestedByUserId,
      provider: provider ?? "google_places",
    });

    return res.status(201).json({ runId: run.id, status: run.status });
  });

  r.get("/runs/:runId", async (req: Request, res: Response) => {
    const run = await deps.repo.getRun(req.params.runId);
    if (!run) return res.status(404).json({ error: "not found" });
    return res.json(run);
  });

  r.post("/runs/:runId/cancel", async (req: Request, res: Response) => {
    const ok = await deps.repo.cancelRun(req.params.runId);
    return res.status(ok ? 200 : 409).json({ cancelled: ok });
  });

  return r;
}

//// file: src/lead-finder/worker.ts
import { createPgPool } from "./db/pool.js";
import { LeadFinderRepo } from "./db/repo.js";
import { LeadFinderService } from "./service.js";
import type { PlacesClient } from "./provider/googlePlaces.js";

/**
 * Worker entrypoint.
 * Run as: node dist/lead-finder/worker.js
 */
async function main() {
  const provider = (process.env.LEAD_FINDER_PROVIDER ?? "google_places") as const;
  const pollMs = Number(process.env.LEAD_FINDER_POLL_MS ?? "1000");

  const pool = createPgPool();
  const repo = new LeadFinderRepo(pool);

  const placesClient: PlacesClient = {
    async searchBusinesses() {
      throw new Error("Implement PlacesClient.searchBusinesses with your Google Places integration");
    },
  };

  const service = new LeadFinderService(pool, placesClient);

  for (;;) {
    const run = await repo.claimNextQueuedRun(provider);
    if (!run) {
      await sleep(pollMs);
      continue;
    }

    try {
      await service.runOnce(run);
      const latest = await repo.getRun(run.id);
      if (latest?.status !== "cancelled") {
        await repo.setRunStatus(run.id, "completed");
      }
    } catch (e: any) {
      await repo.setRunStatus(run.id, "failed", e?.message ?? "unknown error");
    }
  }
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});

//// file: src/api.ts
import express from "express";
import { createPgPool } from "./lead-finder/db/pool.js";
import { LeadFinderRepo } from "./lead-finder/db/repo.js";
import { createLeadFinderRouter } from "./lead-finder/routes.js";

const app = express();
app.use(express.json());

const pool = createPgPool();
const repo = new LeadFinderRepo(pool);

/**
 * api.ts only wires routes. No Lead Finder logic lives here.
 */
app.use("/lead-finder", createLeadFinderRouter({ repo }));

app.listen(process.env.PORT ?? 3000);

//// file: src/lead-finder/migrations.sql
/**
create table if not exists lead_finder_profiles (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  industry_id uuid not null,
  sub_industry_id uuid null,
  geo_type text not null,
  city text null,
  state text null,
  country text null,
  center_lat double precision null,
  center_lng double precision null,
  radius_meters int not null,
  require_phone boolean not null default true,
  require_no_website boolean not null default true,
  created_by_user_id uuid not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists lead_finder_runs (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references lead_finder_profiles(id),
  status text not null,
  provider text not null,
  requested_by_user_id uuid not null,
  started_at timestamptz null,
  finished_at timestamptz null,
  stats_total_seen int not null default 0,
  stats_qualified int not null default 0,
  stats_inserted int not null default 0,
  stats_duplicates int not null default 0,
  stats_missing_phone int not null default 0,
  stats_has_website int not null default 0,
  error_message text null,
  created_at timestamptz not null default now()
);

create table if not exists lead_finder_run_items (
  id uuid primary key default gen_random_uuid(),
  run_id uuid not null references lead_finder_runs(id),
  provider text not null,
  provider_place_id text not null,
  business_name text not null,
  phone_raw text null,
  phone_e164 text null,
  website_url text null,
  address_full text null,
  decision text not null,
  lead_id uuid null,
  created_at timestamptz not null default now()
);

create table if not exists lead_external_ids (
  id uuid primary key default gen_random_uuid(),
  lead_id uuid not null,
  provider text not null,
  provider_place_id text not null,
  unique (provider, provider_place_id)
);

create table if not exists lead_dedupe_keys (
  id uuid primary key default gen_random_uuid(),
  lead_id uuid not null,
  key_type text not null,
  dedupe_key text not null,
  unique (key_type, dedupe_key)
);
*/
