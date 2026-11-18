// The build stamp, read from Cloudflare's version_metadata binding (CF_VERSION_METADATA).
// The deploy passes the short commit as the version's tag (`wrangler deploy --tag <commit>`).
// Anything missing or empty is null; nothing else about the deployment is exposed.
import type { Env } from "./env";

export interface VersionInfo {
  commit: string | null;
  version_id: string | null;
  uploaded_at: string | null;
}

const field = (v: unknown) => (typeof v === "string" && v !== "" ? v : null);

export function versionInfo(env: Env): VersionInfo {
  const m = env.CF_VERSION_METADATA;
  return {
    commit: field(m?.tag),
    version_id: field(m?.id),
    // When the version was uploaded, not when it went live.
    uploaded_at: field(m?.timestamp),
  };
}
