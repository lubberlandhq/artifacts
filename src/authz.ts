// Who may do what to an artifact. Pure functions, so the rules are testable without a Worker.
// The model is Claude Artifacts' (observed in Claude Code 2.1.309, docs/claude-artifacts-evidence.md):
// a read grant with a mode (owner | users | org | public), a separate list of editors, and a
// share pin that decides which version viewers see.
import type { Artifact, Env, Mode } from "./env";

export interface OrgPolicy {
  emails: Set<string>;
  domains: Set<string>;
  publishers: Set<string>;
  admins: Set<string>;
}

const list = (s: string | undefined) =>
  new Set(
    (s ?? "")
      .split(",")
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean),
  );

export function orgPolicy(env: Pick<Env, "ORG_EMAILS" | "ORG_DOMAINS" | "PUBLISHERS"> & Partial<Pick<Env, "ADMINS">>): OrgPolicy {
  return { emails: list(env.ORG_EMAILS), domains: list(env.ORG_DOMAINS), publishers: list(env.PUBLISHERS), admins: list(env.ADMINS) };
}

export function isAdmin(policy: OrgPolicy, email: string | null): boolean {
  return !!email && policy.admins.has(email.toLowerCase());
}

export function isOrgMember(policy: OrgPolicy, email: string | null): boolean {
  if (!email) return false;
  const e = email.toLowerCase();
  return policy.emails.has(e) || policy.domains.has(e.split("@")[1] ?? "");
}

export function canPublish(policy: OrgPolicy, email: string | null): boolean {
  if (!email) return false;
  return policy.publishers.size > 0 ? policy.publishers.has(email.toLowerCase()) : isOrgMember(policy, email);
}

export function canWrite(policy: OrgPolicy, a: Artifact, email: string | null): boolean {
  if (!email) return false;
  const e = email.toLowerCase();
  return a.owner === e || a.write_users.includes(e) || isAdmin(policy, e);
}

// Sharing, renaming and deleting stay with the owner, as on claude.ai, plus the service admins
// (a tenant's agents publish as their own identity; the service admins still decide who sees their pages).
export function canAdmin(policy: OrgPolicy, a: Artifact, email: string | null): boolean {
  if (!email) return false;
  return a.owner === email.toLowerCase() || isAdmin(policy, email);
}

export function canRead(policy: OrgPolicy, a: Artifact, email: string | null): boolean {
  if (canWrite(policy, a, email)) return true;
  switch (a.read_mode) {
    case "public":
      return true;
    case "org":
      return isOrgMember(policy, email);
    case "users":
      return !!email && a.read_users.includes(email.toLowerCase());
    default:
      return false;
  }
}

// Editors see whatever version they ask for (default: live). Viewers see the pinned version when
// the share is pinned, otherwise live, and never pick another one.
export function visibleVersion(policy: OrgPolicy, a: Artifact, email: string | null, requested?: number): number {
  if (canWrite(policy, a, email)) return requested && requested <= a.live_version && requested > 0 ? requested : a.live_version;
  return a.pinned_version ?? a.live_version;
}

export function describeMode(mode: Mode, orgName: string): string {
  return {
    owner: "Only you",
    users: "Specific people",
    org: orgName,
    public: "Anyone with the link",
  }[mode];
}

const EMAIL = /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/;
export function parseEmails(input: unknown): string[] | null {
  const raw = Array.isArray(input) ? input : typeof input === "string" ? input.split(/[\s,;]+/) : [];
  const out = [...new Set(raw.map((x) => String(x).trim().toLowerCase()).filter(Boolean))];
  return out.every((e) => EMAIL.test(e)) ? out : null;
}
