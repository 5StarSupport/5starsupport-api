// file: netlify/functions/_lib/lead-finder/normalize.ts
import type { ProviderBusiness, NormalizedBusiness } from "./types";

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
