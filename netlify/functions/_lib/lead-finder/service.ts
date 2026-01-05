// file: netlify/functions/_lib/lead-finder/service.ts
import type { Pool } from "pg";
import type { LeadFinderProfile, LeadFinderRun, ProviderBusiness, RunItemDecision } from "./types";
import { normalizeBusiness } from "./normalize";
import { LeadFinderRepo } from "./db/repo";
import type { PlacesClient } from "./provider/googlePlaces";
import { searchAllBusinesses } from "./provider/googlePlaces";

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
