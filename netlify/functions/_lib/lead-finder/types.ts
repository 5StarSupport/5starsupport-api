// file: netlify/functions/_lib/lead-finder/types.ts
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
