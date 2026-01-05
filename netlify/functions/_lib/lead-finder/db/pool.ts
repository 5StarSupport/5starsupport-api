// file: netlify/functions/_lib/lead-finder/db/pool.ts
import { Pool } from "pg";

export function createPgPool(): Pool {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error("DATABASE_URL is required");
  return new Pool({ connectionString });
}
