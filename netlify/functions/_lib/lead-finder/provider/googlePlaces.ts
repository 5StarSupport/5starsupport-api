// file: netlify/functions/_lib/lead-finder/provider/googlePlaces.ts
import type { LeadFinderProfile, ProviderBusiness } from "../types";

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
