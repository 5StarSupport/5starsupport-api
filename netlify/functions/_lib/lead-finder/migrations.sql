-- file: netlify/functions/_lib/lead-finder/migrations.sql
-- Run this in your Postgres DB (adjust UUID defaults if needed)

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
