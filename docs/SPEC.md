# artifacts: specification

Self-hosted page sharing in the style of Claude Artifacts, on one Cloudflare Worker. A person or
an agent publishes an HTML page (or a folder with an `index.html`) and gets a stable link. The
owner decides who can open it, republishing keeps the link, and viewers either follow the live
version or stay on a pinned one.

This document describes the system as it is. Each roadmap item (`docs/ROADMAP.md`) amends it in
the same change that ships the item, so this file never describes behavior that doesn't exist.

`docs/claude-artifacts-evidence.md` records how Claude Artifacts behave, with sources, and which
parts this copies.

## 1. Hosts and origins

One Worker serves three kinds of host. Their names come from deploy configuration (section 9).

| Host (variable) | Serves | In front of it |
|---|---|---|
| `APP_ORIGIN` | viewer shell `/a/<id>`, gallery `/`, JSON API `/api/*`, `/auth/callback`, `/logout` | nothing: public links need no login; the Worker authorizes every request |
| `LOGIN_ORIGIN` | `/login` only | Cloudflare Access (the deployment's sign-in allowlist) |
| `<id>.<CONTENT_DOMAIN>` | the artifact's files, only under a signed grant `/t/<grant>/<path>` | nothing: the grant is the credential |

Every artifact gets its own browser origin on a registrable domain apart from the app. A page's
scripts therefore cannot read the app's cookies, call the API as the viewer, or reach another
artifact's storage. Claude does the same with `<uuid>.frame.claudeusercontent.com`.

## 2. Identity and sign-in

- **Browser.** `/login` on the app host redirects to `LOGIN_ORIGIN/login`. Access authenticates
  the person (one-time code or an IdP). The Worker verifies the Access JWT (RS256 against
  `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs`, checking `aud = ACCESS_AUD`, issuer and
  expiry), mints a single-use handoff (60 s, table `handoffs`) and redirects to
  `APP_ORIGIN/auth/callback`, which redeems it and sets the session cookie `ls_session` (HMAC
  sealed with `SESSION_SECRET`, 7 days, `HttpOnly`, `Secure`, `SameSite=Lax`).
- **CLI and agents.** `Authorization: Bearer lsh_…`. Tokens are minted on the gallery page by a
  signed-in person; only the SHA-256 is stored (table `tokens`). A token acts as its `owner`.
  Admins may mint a token for another publisher (`as`), which is how a tenant's agents publish
  under their own identity; `created_by` records who minted it.
- **Cookie-authenticated writes** must carry `Origin: APP_ORIGIN`.
- Emails are compared lowercased everywhere.

Who can sign in at all is decided by the Access policy, outside this repo.

## 3. Roles and permissions

Service-wide roles come from deploy configuration:

| Role | Source | Meaning |
|---|---|---|
| org member | `ORG_EMAILS`, `ORG_DOMAINS` | readers of artifacts shared in `org` mode |
| publisher | `PUBLISHERS` (empty = org members) | may create artifacts |
| admin | `ADMINS` | may administer every artifact; may mint tokens `as` a publisher |

Per-artifact roles:

| Role | Who |
|---|---|
| owner | the creator (`artifacts.owner`) |
| editor | `write_users` |
| viewer | everyone the read mode admits: `owner` mode nobody else; `users` mode the emails in `read_users`; `org` mode org members; `public` mode anyone, signed in or not |

| Action | owner | admin | editor | viewer | signed-in non-viewer | anonymous |
|---|---|---|---|---|---|---|
| open the page | ✅ | ✅ | ✅ | ✅ | ❌ | `public` only |
| read comments | ✅ | ✅ | ✅ | ✅ | ❌ | `public` only |
| post a comment | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| resolve a comment | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| list versions, files; open any version | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| publish a new version | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| change sharing, rename, delete | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |

Implemented as pure functions in `src/authz.ts` (`canRead`, `canWrite`, `canAdmin`,
`visibleVersion`) so the rules are unit-tested without a Worker.

**Version visibility.** Editors see the version they ask for (default: live). Everyone else sees
`pinned_version` when set, otherwise live, and cannot choose another.

## 4. Data model

D1 holds metadata; R2 holds file bytes.

- `artifacts(id, owner, title, description, live_version, read_mode, read_users, write_users,
  pinned_version, created_at, updated_at)`. `id` is 20 characters `[a-z0-9]`, also the content
  origin's label. `read_users` and `write_users` are JSON arrays of emails.
- `versions(artifact_id, ver, author, label, manifest, created_at)`, primary key
  `(artifact_id, ver)`. `manifest` is JSON `{path: {sha256, size, type}}`.
- `comments(id, artifact_id, ver, author, body, resolved, created_at)`.
- `tokens(hash, owner, label, created_at, last_used, created_by)`.
- `handoffs(…)`: single-use sign-in handoffs.
- R2: `blob/<sha256>`, content-addressed, so a republish that changes one file copies nothing.

Migrations live in `migrations/` and are applied with `wrangler d1 migrations apply`.

**Publishing.** `addVersion` inserts the version row and then updates `live_version` in one
batch; a concurrent publish of the same version number fails on the primary key and returns 409.
A publish may send `base_version`; a mismatch with `live_version` returns 409.

## 5. API

All under `APP_ORIGIN/api`, JSON in and out.

| Method and path | Who | Notes |
|---|---|---|
| `GET /me` | signed in | `{email, can_publish, admin}` |
| `GET /tokens` | session | rows the caller owns or created |
| `POST /tokens` | session | `{label, as?}`; `as` admin-only and must be a publisher; returns the token once |
| `DELETE /tokens/:id` | session | owner or creator |
| `GET /artifacts` | signed in | owned, editor of, or named in `users` mode |
| `POST /artifacts` | publisher | multipart: `file` parts (name = published path), `title`, `description`, `label` |
| `GET /artifacts/:id` | viewer | public view of the artifact for this caller |
| `PATCH /artifacts/:id` | owner, admin | `{title?, description?}` |
| `DELETE /artifacts/:id` | owner, admin | |
| `GET /artifacts/:id/head` | viewer | `{version, live_version, updated_at}`; the shell polls it every 15 s |
| `GET /artifacts/:id/frame?v=` | viewer | `{version, src}`: a fresh content URL (12 h grant) |
| `GET /artifacts/:id/versions` | editor | |
| `POST /artifacts/:id/versions` | editor | multipart as above, plus `remove`, `base_version` |
| `GET /artifacts/:id/files?v=` | editor | the manifest |
| `PUT /artifacts/:id/sharing` | owner, admin | `{mode?, users?, editors?, pin?: "live" \| "current" \| <ver>}` |
| `GET /artifacts/:id/comments` | viewer | |
| `POST /artifacts/:id/comments` | signed-in viewer | `{body, version?}`; body ≤ 5000 chars |
| `PATCH /artifacts/:id/comments/:cid` | editor | `{resolved}` |

Errors are `{error}` with 400, 401, 403, 404 or 409.

## 6. Content serving

`GET <id>.<CONTENT_DOMAIN>/t/<grant>/<path>`: the grant is `{artifact id, version}` sealed with
`SESSION_SECRET` for 12 hours, and its id must match the host's. It sits in the path rather than a
cookie so it works in a third-party iframe in every browser. Without a valid grant the origin
answers 404. Responses carry an ETag, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and the content CSP:

- scripts from `'self'`, inline, and five CDNs (cdnjs, jsdelivr, unpkg, tailwindcss, jquery);
- stylesheets from `'self'`, inline, Google Fonts and the same CDNs;
- `connect-src 'self'`;
- `frame-ancestors APP_ORIGIN` (a top-level visit still works).

A page written for a Claude artifact works here unchanged. The viewer shell runs under its own
nonce-based CSP (`src/csp.ts`).

## 7. CLI: `lshare`

`cli/lshare` (bun). Environment: `LSHARE_URL` (the deployment's `APP_ORIGIN`), `LSHARE_TOKEN`.
Commands: `publish`, `list`, `get`, `share`, `versions`, `comments`, `rename`, `delete`, `open`.
Prints lines on a terminal and JSON when piped. Exit codes: 2 usage, 4 auth, 5 API.

## 8. Agent skill

`skills/share/SKILL.md` tells an agent when to publish, how to call `lshare`, the page contract
(section 6), and to confirm the audience with the person before sharing beyond them.

## 9. Deploy configuration

`wrangler.example.jsonc` lists every variable with placeholder values. A deployment keeps its
real `wrangler.jsonc` outside this repo (it is gitignored here) and copies it in to deploy.
`wrangler.dev.jsonc` is the local development config used by `bun run dev` and the smoke test.

| Variable | Example |
|---|---|
| `APP_ORIGIN` | `https://share.example.com` |
| `LOGIN_ORIGIN` | `https://share-login.example.com` |
| `CONTENT_DOMAIN` | `exampleusercontent.com` |
| `CONTENT_SCHEME` | `https` |
| `ACCESS_TEAM_DOMAIN` | `example.cloudflareaccess.com` |
| `ACCESS_AUD` | the login host's Access application AUD |
| `ORG_NAME` | label for `org` mode in the UI, e.g. `Example Co` |
| `ORG_EMAILS`, `ORG_DOMAINS`, `PUBLISHERS`, `ADMINS` | comma-separated |
| `SESSION_SECRET` | `wrangler secret put` |
| `DEV_LOGIN` | `"1"` only in `.dev.vars` |

Bindings: D1 `DB`, R2 `BLOBS`. Routes: the app and login hosts as custom domains, and
`*.<CONTENT_DOMAIN>/*` on the content zone (which needs a proxied wildcard DNS record).

## 10. Tests

- `bun test`: unit tests for authz, crypto, paths and the Access JWT check.
- `bun run smoke`: drives `wrangler dev` end to end through the CLI (publish, share in every
  mode, pins, conflicts, comments, tokens, tenants).
- `bun run typecheck`.
