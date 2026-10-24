export interface Env {
  DB: D1Database;
  BLOBS: R2Bucket;

  // https://share.example.com — the viewer shell, dashboard and API (no Access in front).
  APP_ORIGIN: string;
  // https://share-login.example.com — whole hostname behind Cloudflare Access; only /login runs there.
  LOGIN_ORIGIN: string;
  // Each artifact is served from <id>.<CONTENT_DOMAIN>: its own browser origin, on a registrable
  // domain apart from the app, like Claude's <uuid>.frame.claudeusercontent.com.
  CONTENT_DOMAIN: string;
  CONTENT_SCHEME: string; // "https" in production, "http" for wrangler dev on *.localhost

  ACCESS_TEAM_DOMAIN: string; // <team>.cloudflareaccess.com
  ACCESS_AUD: string; // the login host's Access application AUD tag
  // The org's name, shown for sharing mode 'org' ("Example Co").
  ORG_NAME: string;
  // Mode 'org' admits everyone whose email is listed or whose domain is listed.
  ORG_EMAILS: string; // comma-separated
  ORG_DOMAINS: string; // comma-separated, e.g. "example.com"
  // Who may publish at all. Comma-separated emails; empty = members of the org.
  PUBLISHERS: string;
  // Service admins: may mint tokens for another publisher (a tenant's agent identity) and
  // administer every artifact. Comma-separated emails.
  ADMINS: string;

  SESSION_SECRET: string; // wrangler secret
  DEV_LOGIN?: string; // "1" only in .dev.vars: a pick-your-email login for wrangler dev
}

export type Mode = "owner" | "users" | "org" | "public";

export interface ManifestEntry {
  sha256: string;
  size: number;
  type: string;
}
export type Manifest = Record<string, ManifestEntry>;

export interface ArtifactRow {
  id: string;
  owner: string;
  title: string;
  description: string;
  live_version: number;
  read_mode: Mode;
  read_users: string;
  write_users: string;
  pinned_version: number | null;
  created_at: string;
  updated_at: string;
}

export interface Artifact extends Omit<ArtifactRow, "read_users" | "write_users"> {
  read_users: string[];
  write_users: string[];
}

export interface User {
  email: string;
  via: "session" | "token";
}
