# artifacts: roadmap

Ordered. Each item lists what changes, the decisions already made, acceptance criteria, and
what is out of scope. An item is done when its acceptance criteria pass and `docs/SPEC.md` has
been amended to describe the new behavior in the same change.

```
0 Extract ──> 1 Commenter role ──> 2 Anchored comments
                    │
                    └──> 3 Sign-in for named people (explore, then build)
                                         │
                                         └──> 4 Comment notifications
5 Policy in D1 (after 3: its decision may move the policy lists)
6 Version compare (independent; any time after 0)
```

Why this order: 0 makes everything else land in one public repo. 1 comes before 2 because
anchored comments must already know who may comment. 3 decides how an outside commenter gets in
at all, which is what makes 1 and 2 useful to clients. 4 matters once outside people comment. 5
waits for 3 because 3 may introduce a grants table that the policy lists should join. 6 touches
nothing above.

Status: ☐ not started · ◐ in progress · ☑ done

---

## 0. Extract into this repo ◐

**Goal.** One public repo holds the Worker, the CLI and the agent skill, with no deployment's
private values in it or its history.

**Layout.**

```
src/  migrations/  test/  package.json  tsconfig.json  wrangler.example.jsonc  wrangler.dev.jsonc
cli/lshare
skills/share/SKILL.md
docs/SPEC.md  docs/ROADMAP.md  docs/claude-artifacts-evidence.md
README.md  LICENSE
```

**Decisions.**

- Fresh history: one initial commit. The source tree's history carries a deployment's emails
  and ids.
- `wrangler.jsonc` is gitignored. `wrangler.example.jsonc` has every variable with placeholders.
  A deployment keeps its real file privately and copies it in before `wrangler deploy`.
  `wrangler.dev.jsonc` (committed) is the local dev and smoke config, so a fresh clone runs with
  no Cloudflare account. wrangler is a pinned dev dependency.
- New variable `ORG_NAME` replaces the hard-coded org label in the UI (`src/authz.ts`
  `describeMode`, gallery and share dialog copy).
- The CLI keeps the name `lshare`. `LSHARE_URL` is required (no built-in default host); a
  missing value exits 2 with a message naming the variable.
- The skill is generic: it names `LSHARE_URL` and `LSHARE_TOKEN` and says "confirm the
  audience with the person". How a given machine resolves the token is that deployment's
  business, documented where its agents already look.
- The smoke test runs `cli/lshare` from this repo by default (`LSHARE_BIN` still overrides).

**Acceptance criteria.**

1. `git log --all -p | grep -iE '<each deployment email>|<each deployment domain>|<ACCESS_AUD>|<D1 id>'`
   prints nothing (run against the list of values in the deployment's real config).
2. `bun install && bun test && bun run typecheck && bun run smoke` pass on a fresh clone with
   only a `.dev.vars` from the README (smoke against `bun run dev`).
3. The UI shows `ORG_NAME` wherever it showed the org label; `grep -ri lubberland src cli skills`
   prints nothing.
4. `lshare list` with `LSHARE_URL` unset exits 2 and names the variable.
5. A deployment built from this repo serves the same artifacts as before (same D1, same R2):
   an artifact published before the move opens at the same link, at the same version.

**Out of scope.** Behavior changes of any kind; the deployment's own IaC (DNS, Access).

---

## 1. Commenter role ☐

**Goal.** A share can let people read without commenting, as in Google Docs: viewer, commenter,
editor.

**Behavior.**

- Per-person grants: `read_users` (viewers), new `comment_users` (commenters), `write_users`
  (editors). A person named in any list can open the page, in every mode except `owner`.
- General access: `read_mode` (`owner | users | org | public`) gains a role for the people the
  mode admits, new column `mode_role`: `view | comment`. `users` mode admits nobody beyond the
  named lists, so `mode_role` is ignored there.
- Anonymous visitors to a `public` page never comment (commenting needs an identity), even with
  `mode_role = comment`.
- **Viewers no longer see comments.** Comments are visible to commenters, editors, the owner
  and admins. (Today every reader sees every comment, including anonymous readers of a public
  page.)
- Highest grant wins when a person appears in several places.

| Action | owner, admin | editor | commenter | viewer |
|---|---|---|---|---|
| open the page | ✅ | ✅ | ✅ | ✅ |
| read comments | ✅ | ✅ | ✅ | ❌ |
| post a comment | ✅ | ✅ | ✅ | ❌ |
| delete own comment | ✅ | ✅ | ✅ | — |
| resolve any comment | ✅ | ✅ | ❌ | ❌ |
| versions, publish | ✅ | ✅ | ❌ | ❌ |
| sharing, rename, delete | ✅ | ❌ | ❌ | ❌ |

**Schema** (`migrations/0003_commenter_role.sql`):

```sql
ALTER TABLE artifacts ADD COLUMN comment_users TEXT NOT NULL DEFAULT '[]';
ALTER TABLE artifacts ADD COLUMN mode_role TEXT NOT NULL DEFAULT 'view'
  CHECK (mode_role IN ('view','comment'));
-- Keep what existing shares already allow: their readers could comment.
UPDATE artifacts SET comment_users = read_users, read_users = '[]', mode_role = 'comment';
```

**API.**

- `PUT /artifacts/:id/sharing` accepts `commenters` (emails) and `mode_role`.
- `GET /artifacts/:id` adds `comment_users`, `mode_role`, and the caller's `role`
  (`owner | admin | editor | commenter | viewer`).
- `GET /artifacts/:id/comments` returns 403 to viewers.
- `POST /artifacts/:id/comments` returns 403 to viewers.
- New `DELETE /artifacts/:id/comments/:cid`: the author, editors, owner, admins.
- `lshare share <id> --commenters a@x,b@y --link-role view|comment`.

**UI.** The share dialog lists people with a role picker (Viewer / Commenter / Editor) and the
general-access row gets a role picker for `org` and `public`. The Comments button is hidden for
viewers.

**Acceptance criteria.**

1. `authz` unit tests cover every cell of the table above for each read mode (4 modes × 5 roles
   × 7 actions), plus anonymous on `public`.
2. Smoke: a viewer in `users` mode gets the page, 403 on `GET comments` and 403 on `POST
   comments`; the same person as commenter succeeds at both.
3. Smoke: `public` with `mode_role = view` gives an anonymous visitor the page and 401 on `GET
   comments`; a signed-in non-named person gets 403.
4. After the migration, every pre-existing artifact behaves as before for its readers: each
   former reader can still read and comment.
5. A commenter cannot resolve someone else's comment (403) but can delete their own (200).

**Out of scope.** Anchors (item 2), replies, editing a comment's text, notifications.

---

## 2. Anchored comments ☐

**Goal.** A commenter selects text in the page, clicks Comment, and the comment is attached to
that passage. Highlights show where comments are; clicking one opens its comment.

**How it works.** The page lives in a cross-origin frame, so the shell cannot read the
selection. The content server adds one script to each HTML document it serves; the script reads
the selection inside the page and talks to the shell with `postMessage`.

- **Injection.** For responses with `Content-Type: text/html`, the content server inserts
  `<script src="/t/<grant>/__artifacts/annotate.js" defer></script>` before `</body>` (or at the
  end when there is no `</body>`). The script is same-origin, so the content CSP is unchanged.
  The path prefix `__artifacts/` is reserved: publishing a file under it fails with 400.
  The ETag covers the injected bytes.
- **Anchor format** (W3C Web Annotation `TextQuoteSelector` plus a position hint):
  `{exact, prefix, suffix, start?, end?}`. `exact` ≤ 1000 chars; `prefix` and `suffix` ≤ 32
  chars each; `start`/`end` are offsets into the document's text content.
- **Messages.** Every message is `{v: 1, type, ...}`.

  | Direction | type | payload |
  |---|---|---|
  | page → shell | `artifacts:ready` | none |
  | page → shell | `artifacts:select` | `{anchor}` when the person clicks Comment on a selection |
  | page → shell | `artifacts:open` | `{id}` when a highlight is clicked |
  | shell → page | `artifacts:highlights` | `{items: [{id, anchor, resolved}]}` |
  | shell → page | `artifacts:focus` | `{id}`: scroll to and flash that passage |
  | shell → page | `artifacts:can-comment` | `{value}`: show the Comment button or not |

- **Trust.** The shell accepts a message only when `event.source` is its frame's window and
  `event.origin` is `<scheme>://<id>.<CONTENT_DOMAIN>`. The page accepts only `APP_ORIGIN`. The
  shell treats every string from the page as untrusted text: length-checked, rendered escaped,
  never used as markup or a URL. A page's author can forge any page → shell message; the worst
  outcome is a comment quoting text that isn't on the page.
- **Rendering.** The Comment button lives in a closed shadow root so page CSS cannot restyle
  it. Highlights use the CSS Custom Highlight API (no DOM changes to the page). Where it is
  unsupported, comments still work and appear in the sidebar without highlights.
- **Re-anchoring.** On the version being shown, the script finds `exact`; with several matches
  it picks the one whose prefix and suffix match, then the one closest to `start`. With no match
  the sidebar shows the comment with its quote and "passage not in this version".
- Non-HTML content (images, PDFs, canvas text) has no selection; page-level comments remain.

**Schema** (`migrations/0004_comment_anchor.sql`):

```sql
ALTER TABLE comments ADD COLUMN anchor TEXT; -- JSON TextQuoteSelector, NULL = page-level
```

**API.** `POST /artifacts/:id/comments` accepts `anchor`; `GET` returns it. Validation: object
with string `exact` (1–1000), optional `prefix`/`suffix` (≤ 32), optional non-negative integer
`start` ≤ `end`; anything else is 400. `lshare comments` prints the quote above each anchored
comment.

**Acceptance criteria.**

1. In a real browser (smoke via Playwright or the gstack browser): select a sentence in a
   published page, click Comment, submit; the comment shows the quote and the sentence is
   highlighted after reload.
2. Clicking the highlight opens that comment; clicking the comment scrolls to the passage.
3. Publish a new version that removes the sentence: the comment shows "passage not in this
   version" with its quote. A version that moves the sentence: the highlight follows it.
4. Publishing `__artifacts/x.js` returns 400.
5. A message from any origin other than the artifact's content origin is ignored (unit test on
   the shell's message handler).
6. The injected script is ≤ 4 KB gzipped and the page's own scripts and styles behave as before
   on the pages in `test/fixtures/` (a Claude-style artifact with Tailwind and one with inline
   React).
7. Viewers see no Comment button and no highlights.

**Out of scope.** Comments on images or regions, replies, live presence, editing the page.

---

## 3. Sign-in for named people ☐ (explore, then build)

**Problem.** Naming an outside person on a share does nothing until the deployment's Access
allowlist (IaC) also admits them. Every new client is a pull request and an apply.

**Goal.** Being named on a share, or on a service-wide list, is the permission to sign in.
Nobody else gets in.

**Options to explore.**

- **A. Access External Evaluation.** The login app's Access policy includes an External
  Evaluation rule pointing at the Worker. After the one-time code, Access sends the person's
  identity to `POST /access/evaluate`; the Worker answers allow when the email is an org member,
  publisher, admin, or named on any artifact, and signs the response with a key it publishes at
  `/access/keys`. No Cloudflare API token in the Worker; the IaC change happens once.
- **B. Decouple from Access.** The Worker runs its own email one-time-code sign-in (Cloudflare
  Email Service) and Access leaves the picture. The app owns identity end to end, and the
  sender domain is the one item 4 needs anyway.

**Exploration deliverable.** A short decision record (`docs/decisions/0001-sign-in.md`) with a
working spike of A against a test Access application, covering: plan availability of External
Evaluation on the deployment's Cloudflare plan; latency added to sign-in; behavior when the
Worker errors (Access must fail closed); how revoking someone (removing them from every share)
takes effect against an existing Access session; and the cost of B (email deliverability, rate
limiting, code storage).

**Likely schema need (either option).** "Is this email named anywhere" must be one indexed
query, not a scan of JSON arrays:

```sql
CREATE TABLE grants (
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  role        TEXT NOT NULL CHECK (role IN ('viewer','commenter','editor')),
  PRIMARY KEY (artifact_id, email)
);
CREATE INDEX grants_email ON grants(email);
```

This would replace `read_users`, `comment_users` and `write_users`.

**Acceptance criteria (for the build, after the decision).**

1. A person named on one share, and on no service-wide list, can sign in and open it.
2. A person named nowhere completes the one-time code and is refused.
3. Removing a person from their last share stops new sign-ins immediately and ends access to
   that share on their next request.
4. If the evaluation endpoint errors or times out, sign-in is refused.

**Out of scope.** Self-service sign-up; SSO for client organizations.

---

## 4. Comment notifications ☐

**Goal.** People learn about new comments without polling.

**Behavior.**

- On a new comment, email the owner and editors, minus the author. With anchored comments the
  email quotes the passage.
- At most one email per recipient per artifact per 10 minutes; comments inside the window are
  batched into the next email.
- The email links to `/a/<id>#comment-<cid>`. It never contains a content grant.
- Each person can turn notifications off (per artifact and globally) from the gallery.
- Sending uses Cloudflare Email Service from a sender address in deploy configuration
  (`NOTIFY_FROM`); without it, notifications are off.

**Acceptance criteria.**

1. Three comments within a minute produce one email per recipient containing all three.
2. The author of a comment is never emailed about it.
3. A recipient who turned notifications off for the artifact gets nothing.
4. With `NOTIFY_FROM` unset, posting a comment succeeds and sends nothing.

**Out of scope.** Mentions, replies by email, digests across artifacts, notifying commenters.

---

## 5. Policy in D1 ☐

**Goal.** Changing who is an org member, publisher or admin is an admin page, not a redeploy.

**Behavior.**

- Table `policy(kind, value)` with `kind ∈ {org_email, org_domain, publisher, admin}`.
- On first start with an empty table, the Worker seeds it from the existing variables; after
  that the variables are ignored except `ADMINS`, which stays as a break-glass list that is
  always admin.
- `/admin` (admins only) lists and edits the entries. Every change is recorded in an audit
  table `(at, by, kind, value, action)`.
- If item 3 chose option A, this table feeds the evaluation endpoint too.

**Acceptance criteria.**

1. An admin adds an org domain on `/admin`; a person from that domain can open an `org` share on
   their next request, with no redeploy.
2. A non-admin gets 403 on every `/admin` route and `/api/admin/*` endpoint.
3. Removing the last D1 admin leaves the `ADMINS` variable's people as admins.
4. Every change appears in the audit list with who made it.

**Out of scope.** Groups, per-tenant policy.

---

## 6. Version compare ☐

**Goal.** An editor sees what changed between two versions.

**Behavior.**

- In the viewer, editors pick two versions and get them side by side (two frames, both under
  their own grants), with an option to scroll them together.
- Above the frames, the file list: added, removed, changed (by `sha256`), with sizes.
- For changed text files under 200 KB, a line diff of the source.
- `lshare diff <id> <a> <b>` prints the file list and, with `--source`, the text diffs.

**Acceptance criteria.**

1. Versions that differ in one file list exactly that file as changed.
2. A diff of two versions with identical manifests says "no changes".
3. Viewers and commenters get 403 on the compare endpoint.
4. A binary or > 200 KB file shows as changed without a source diff.

**Out of scope.** Visual (pixel) diff, diffs between artifacts.

---

## 7. Pluggable backends per content type ☐ (future; not designed)

**Idea.** `lshare publish` picks a backend by content type instead of always hosting the page
itself. The motivating case: documents people read and mark up (reports, proposals, memos) go to
Google Drive as a Google Doc or PDF, where commenting, anchoring, notifications and revision
history already exist; interactive pages stay on this Worker.

**What is known (2026-10-23, from Google's docs; nothing tested).**

- Drive converts HTML to a Google Doc on upload; scripts and most CSS are lost. A PDF rendered
  from the page keeps its look, and new uploads become versions of the same file and link.
- Agents can read people's anchored comments (with the quoted text) and reply, but comments an
  agent creates through the API show as unanchored in Google's editors.
- Overwriting a Google Doc with new converted HTML probably orphans existing comment anchors;
  needs a test.
- People without a Google account need Workspace visitor sharing (PIN, re-verified every 7
  days); personal Gmail accounts can't use it.
- Service accounts have no My Drive storage; agents would publish into a Shared Drive, one per
  tenant.

**Open questions for the design.** How a backend is chosen (flag, content sniffing, per-share
default); whether the gallery lists artifacts from every backend; how sharing roles map onto
Drive permissions; where each backend's credentials live per tenant.
