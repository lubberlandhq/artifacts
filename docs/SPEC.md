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
- **CLI and agents.** `Authorization: Bearer tck_…`. Tokens minted before the rename to Tack start with `lsh_` and
  keep working: lookup is by hash, whatever the prefix. Tokens are minted on the gallery page by a
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
- `tokens(hash, owner, label, created_at, last_used, created_by, scope, expires_at)`. `scope`
  NULL is the whole API; `whiteboard` is the share hub only (section 7a). `expires_at` NULL never
  expires; a token past it is refused and deleted.
- `handoffs(…)`: single-use sign-in handoffs.
- R2: `blob/<sha256>`, content-addressed, so a republish that changes one file copies nothing.
- Share hub (section 7a): `wb_device_codes`, `wb_shares`, `wb_revisions`, `wb_requests` and
  `settings` (migration 0003); R2 `wb/<share id>/<revision id>.json`.

Migrations live in `migrations/` and are applied with `wrangler d1 migrations apply`, before the
Worker that needs them is deployed: every token lookup reads `scope` and `expires_at`, so a
Worker deployed ahead of migrations 0004 and 0005 fails every request made with a token.

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

## 7. CLI: `tack`

`cli/tack` (bun). Environment: `TACK_URL` (the deployment's `APP_ORIGIN`), `TACK_TOKEN`.
Commands: `publish`, `board`, `board-viewer`, `list`, `get`, `share`, `versions`, `comments`, `rename`, `delete`,
`open`. Prints lines on a terminal and JSON when piped. Exit codes: 2 usage, 4 auth, 5 API.

`board` publishes a Whiteboard snapshot (a `review-share/2` bundle, from a `.whiteboard` file or
`whiteboard export --review <id>`) as an ordinary artifact; the Worker knows nothing about boards.
The artifact holds `board.whiteboard`, the page in `cli/board-viewer/`, and the viewer:
`@dev.fast/canvas` as published on npm plus React built as ES modules. Their versions, and every
package they depend on, are pinned with integrity hashes in `cli/board-viewer-build/bun.lock`; the
CLI installs from it frozen, so a package that does not match the lock fails the build. The
build is cached under `~/.cache/tack`, one folder per lockfile. The page reads the snapshot from its own origin, so it fits the
content policy in section 6 with no exception. It shows a download link for Whiteboard Desktop
when the snapshot names a repository and quotes no uncommitted changes.

`board-viewer` (admins) publishes that viewer with no board beside it and registers it as the
one the share hub frames (section 7a).

## 7a. Whiteboard share hub

`src/whiteboard.ts` answers the share-service protocol of Whiteboard's client, read from
`@dev.fast/whiteboard` 0.5.2, so stock Whiteboard uses a Tack server after
`whiteboard login --origin <APP_ORIGIN>`. Errors on these routes are `{"error":{"code"}}`.

| Route | Who | What |
|---|---|---|
| `POST /api/auth/device/code` | anyone | starts a device login: device code, user code, `/device?user_code=`. 429 `slow_down` while the caller's address (for IPv6, its /64) holds 5 unexpired codes, or the server 200 |
| `GET, POST /device` | browser session | shows the user code; POST (same-origin) approves it. The page is served with `Referrer-Policy: same-origin`, or a browser would send the form with `Origin: null` |
| `POST /api/auth/device/token` | device code | `authorization_pending` until approved, then `{access_token}` once |
| `GET /api/auth/get-session` | bearer | `{user:{id, name, email}}`, all the person's email |
| `GET /api/auth/token` | — | 404: tells the client to send its token as it is |
| `POST /api/v2/shares` | publisher | `{requestId, bundle}` → `{shareId, url}`. The request id is recorded before anything is stored and counts as answered once its share holds that version: a retry after a failed upload stores the board, and a second board uploaded under an id still in flight gets 409 `request_in_progress` |
| `GET /api/v2/shares` | bearer | `{items:[{shareId, reviewId, title, latestVersion, createdAt, url}], next?}`, 100 a page; `?cursor=<next>` continues, and `next` (`<createdAt>.<shareId>`) still works after that share is revoked; an admin adds `?owner=<email>` or `?owner=*` and gets each item's `owner` |
| `GET /api/v2/shares/:id/link`, `/revisions` | owner | recover the link, list revisions |
| `DELETE /api/v2/shares/:id` | owner or admin | revoke |
| `GET /api/v2/shared/:cap[?rev=]`, `/bundle` | anyone | who shared it and which revision; the snapshot |
| `GET /s/:cap[?rev=]` | anyone | the page: title, sender, "Open in Whiteboard", the board framed |
| `GET, PUT /api/whiteboard/viewer` | signed in; admin | which artifact, at which version, holds the board viewer; PUT takes `{artifact, version}` and registers exactly that version |

Rules:

- The token a device login yields is labelled "Whiteboard login", listed and revoked on the
  gallery page, expires after `WHITEBOARD_LOGIN_DAYS` days, 90 when unset (`tokens.expires_at`,
  migration 0005; Whiteboard then asks the person to sign in again), and is scoped (`tokens.scope = 'whiteboard'`, migration 0004): it works on
  `/api/auth/get-session` and `/api/v2/shares…` and counts as signed out everywhere else, pages
  included (`currentUser` returns nobody for a scoped token unless the caller names its scope).
  Only a browser session approves a code on `/device`; a token never does, so a token cannot
  mint another. Anyone who can sign in may log Whiteboard in (a recipient needs it to open links
  in Desktop); only publishers may share. A person keeps at most 10 Whiteboard logins: one more
  removes their oldest. Expired tokens are deleted when presented and whenever a token is minted,
  and are left out of the token list.
- Reads are anonymous: the client sends them without credentials and refuses redirects, so the
  capability (32 random bytes, 43 base64url characters) is the only read control. Only its
  SHA-256 is stored for look-ups, plus a copy encrypted under `SESSION_SECRET` so the owner can
  recover the link. After `SESSION_SECRET` changes, existing links keep working for whoever holds
  them but the server can no longer show them: lists give `url: null`, `/link` and `/revisions`
  answer 409 `link_unrecoverable`, revoke still works, and sharing that board again replaces the
  link with a new one.
- A link is readable until revoked, so an admin can list and revoke anyone's share. The listing
  gives ids and owners, not links: `url` is null for a share that is not the caller's. That power
  needs a session or a full token; an admin's Whiteboard login token has none of it.
- One link per (owner, board). A bundle is accepted when it is a `review-share/2` object with the
  parts every reader requires, at most 16 MiB; the reader validates the rest. A `requestId`
  sent again answers as the first upload did once that upload's board is stored (see the route
  table for one that is not). A higher `bundle.version` adds a revision and a
  lower one changes nothing. The newest version sent again with different content replaces that
  revision's snapshot in place (same link, same revision id): Whiteboard sends one version for a
  board shared with uncommitted changes and again once committed, and the second must not stay
  view-only. The same content again changes nothing.
- Snapshots are stored in R2 at `wb/<share id>/<revision id>.json`. Revoking deletes those
  objects, then the rows, then sweeps the objects once more; every read route then answers 404,
  the same as for an unknown capability. The content origin serves a snapshot only while its
  revision row exists, so a frame handed out earlier stops at the revoke. If the object delete
  fails the row remains, so the owner can revoke again.
- The browser view gives each share its own content origin (`content_id`). Its grant borrows the
  registered viewer artifact's files and serves that revision's snapshot as `board.whiteboard`,
  so the page is the one `tack board` publishes. The viewer is registered by an admin, must be
  that admin's own artifact, and is pinned at the version it had then: publishing to it later
  changes no share page until `tack board-viewer` registers it again. With no viewer registered, `/s/:cap` shows the
  title and the "Open in Whiteboard" button only. A board that quotes uncommitted changes
  (`frozen`) gets no button.
- The only rate limit is the cap on device codes waiting for approval (migration `0006`); use
  Cloudflare rules in front for the rest if the server is public.

Not covered: Whiteboard's hosted trace store (`/api/trace/v1`), which a login to this server also
points at; it answers 404.

## 8. Agent skill

`skills/tack/SKILL.md` tells an agent when to publish, how to call `tack`, the page contract
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
| `WHITEBOARD_LOGIN_DAYS` | optional; days a Whiteboard login lasts, default `90`; a value outside one second to 3650 days counts as unset |
| `DEV_LOGIN` | `"1"` only in `.dev.vars` |

Bindings: D1 `DB`, R2 `BLOBS`. Routes: the app and login hosts as custom domains, and
`*.<CONTENT_DOMAIN>/*` on the content zone (which needs a proxied wildcard DNS record).

## 10. Tests

- `bun test`: unit tests for authz, crypto, paths, the Access JWT check and the share hub's input checks.
- `bun run smoke`: drives `wrangler dev` end to end through the CLI (publish, share in every
  mode, pins, conflicts, comments, tokens, tenants, boards) and sends the share hub the requests
  Whiteboard's client sends (device login, upload, revisions, anonymous reads, revoke).
- `bun run typecheck`.
