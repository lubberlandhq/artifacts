# artifacts

Self-hosted page sharing in the style of Claude Artifacts, on one Cloudflare Worker.

Publish an HTML page, or a folder with an `index.html`, from a terminal, an AI agent or a
browser. You get a link and decide who can open it: only you, specific people, members of your
org, or anyone with the link. Republishing keeps the same link, and viewers either follow the live
version or stay on a pinned one. Signed-in viewers can comment.

- `docs/SPEC.md`: how it works, roles, API, data model, configuration.
- `docs/ROADMAP.md`: what comes next.
- `docs/claude-artifacts-evidence.md`: how Claude Artifacts behave, with sources, and what this
  copies.

## Pieces

| Path | What |
|---|---|
| `src/` | the Worker: app shell, API, sign-in, content serving |
| `migrations/` | D1 schema |
| `cli/tack` | the CLI (bun) for people and agents |
| `cli/board-viewer/`, `cli/board-viewer-build/` | the page `tack board` publishes, and the locked package list (`bun.lock`) its viewer is built from |
| `skills/tack/SKILL.md` | an agent skill (Claude Code, Codex) for publishing with `tack` |

Each artifact is served from its own origin, `<id>.<CONTENT_DOMAIN>`, on a domain apart from the
app, so a page's scripts can't read the app's cookies, call its API as the viewer, or touch another
artifact's storage. Pages run under the same content contract as Claude Artifacts (scripts from
five CDNs, Google Fonts, everything else inline, `connect-src 'self'`), so a page written for one
works on the other.

## Develop

Needs [bun](https://bun.sh). No Cloudflare account needed.

```bash
bun install
printf 'DEV_LOGIN=1\nSESSION_SECRET=%s\n' "$(openssl rand -hex 32)" > .dev.vars
bun run dev            # local D1 + R2, wrangler dev on :8787 (artifacts on <id>.localhost:8787)
bun run test           # unit: authz, grants, paths, CSP, Access JWT
bun run smoke          # end-to-end against the dev server through cli/tack
bun run typecheck
```

`DEV_LOGIN=1` turns on a pick-your-email login. It only works when `APP_ORIGIN` is plain http, so
it can't switch on in production.

## Deploy

You need a Cloudflare account with:

1. **Two hostnames on a zone you own**, for the app (`share.example.com`) and the sign-in host
   (`share-login.example.com`).
2. **A second registrable domain** for content (`exampleusercontent.com`), as a zone in the same
   account with a proxied wildcard record (`*` → `AAAA 100::`).
3. **A Cloudflare Access application** covering the whole sign-in hostname, with a policy that
   admits the people who may sign in (one-time PIN or any IdP). Note its AUD tag.

Then:

```bash
cp wrangler.example.jsonc wrangler.jsonc      # fill in every value (docs/SPEC.md §9)
wrangler d1 create artifacts                  # paste the id into wrangler.jsonc
wrangler r2 bucket create artifacts
wrangler d1 migrations apply DB --remote
openssl rand -base64 48 | wrangler secret put SESSION_SECRET
rev=$(git rev-parse --short HEAD)
wrangler deploy --tag "$rev" --message "artifacts $rev"
```

`--tag` stamps the version with the commit: `GET /api/version` returns it and the gallery shows it
at the bottom ("tack <commit>"). Leave it out and both just have no commit.

`wrangler.jsonc` is gitignored: keep your deployment's copy wherever you keep infrastructure
config and copy it in before deploying.

When updating a server that is already running, apply the migrations before `wrangler deploy`.
The Whiteboard support adds four (`0003` through `0006`). The Worker reads the token columns
`0004` and `0005` add on every token request, and writes the column `0006` adds on every
`whiteboard login`, so deployed ahead of them those requests fail.

Before rolling back to a Worker from before the Whiteboard support, delete the Whiteboard
logins (`DELETE FROM tokens WHERE scope IS NOT NULL`): the older Worker reads neither a token's
scope nor its expiry, and would treat each one as a full token that never expires.

Sign in at your app host, create a token on the gallery page, and:

```bash
export TACK_URL=https://share.example.com TACK_TOKEN=tck_…
bun cli/tack publish report.html --title "Q3 pipeline"    # new, private → prints the link
bun cli/tack share <id> --mode public --pin current        # anyone with the link, frozen at this version
bun cli/tack board <review-id>                             # a Whiteboard board as a read-only page
```

`tack board` takes a review id from [Whiteboard](https://github.com/devdotfast/whiteboard) (it runs
`whiteboard export`) or a `.whiteboard` file. The page is a snapshot drawn by Whiteboard's own
viewer, `@dev.fast/canvas`, which the first run fetches from npm and publishes with the board. The
viewer's packages are locked in `cli/board-viewer-build/bun.lock`.

### Whiteboard's own share links

Tack also answers the share-service protocol Whiteboard speaks, so `whiteboard share` and the
Share button in Whiteboard Desktop upload to your server and return a link on it. An admin sets
up the browser view once; each person points their Whiteboard at the server:

```bash
bun cli/tack board-viewer                                  # admin, once per server (and to update the viewer)
whiteboard login --origin https://share.example.com       # each computer: approve the code in the browser
whiteboard share --review <review-id>                      # prints https://share.example.com/s/<key>
```

The link opens in a browser with no sign-in, and its "Open in Whiteboard" button opens an
editable copy in Whiteboard Desktop on a computer logged in to the same server. Three things
differ from the rest of Tack: **anyone holding the link can read the board** (the key in the link
is the only control, because Whiteboard fetches links without credentials); a share is a frozen
snapshot, and sharing a newer saved version adds a revision under the same link; and logging
Whiteboard in to your server logs it out of dev.fast's. `whiteboard share revoke <share-id>`
deletes a share and its snapshots.

A Whiteboard login is approved in a signed-in browser, never by a token. Its token works on the
share hub only, not on the rest of Tack, and expires after `WHITEBOARD_LOGIN_DAYS` days (90 when
unset); Whiteboard then asks the person to sign in again. An admin can list and revoke anyone's
share through the API (`docs/SPEC.md` §7a), with a browser session or a gallery token, but gets
no links for other people's shares. `board-viewer` registers the viewer at the version it
publishes, as the admin's own artifact; share pages keep that version until it is run again.

## Agents

Install the skill by linking `skills/tack` into your agent's skills directory (for Claude Code,
`~/.claude/skills/tack`) and putting `cli/tack` on `PATH`. Give agents their own identity: add
an agent email to `PUBLISHERS`, and an admin mints its token on the gallery page with "publish as".
That token sees only the agent's own pages; admins can still open and re-share them.

## License

MIT
