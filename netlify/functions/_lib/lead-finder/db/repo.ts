// file: netlify/functions/_lib/lead-finder/db/repo.ts
import type { Pool, PoolClient } from "pg";
import type {
  LeadFinderProfile,
  LeadFinderRun,
  LeadFinderRunStatus,
  NormalizedBusiness,
  RunItemDecision,
} from "../types";

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

  async bumpRunStats(
    runId: string,
    delta: Partial<
      Record<
        | "statsTotalSeen"
        | "statsQualified"
        | "statsInserted"
        | "statsDuplicates"
        | "statsMissingPhone"
        | "statsHasWebsite",
        number
      >
    >,
  ) {
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
    input: {
      provider: string;
      providerPlaceId: string;
      phoneE164: string | null;
      name: string;
      addressFull: string | null;
    },
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
