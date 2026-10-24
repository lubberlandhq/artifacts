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
| `cli/lshare` | the CLI (bun) for people and agents |
| `skills/share/SKILL.md` | an agent skill (Claude Code, Codex) for publishing with `lshare` |

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
bun run smoke          # end-to-end against the dev server through cli/lshare
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
wrangler deploy
```

`wrangler.jsonc` is gitignored: keep your deployment's copy wherever you keep infrastructure
config and copy it in before deploying.

Sign in at your app host, create a token on the gallery page, and:

```bash
export LSHARE_URL=https://share.example.com LSHARE_TOKEN=lsh_…
bun cli/lshare publish report.html --title "Q3 pipeline"    # new, private → prints the link
bun cli/lshare share <id> --mode public --pin current        # anyone with the link, frozen at this version
```

## Agents

Install the skill by linking `skills/share` into your agent's skills directory (for Claude Code,
`~/.claude/skills/share`) and putting `cli/lshare` on `PATH`. Give agents their own identity: add
an agent email to `PUBLISHERS`, and an admin mints its token on the gallery page with "publish as".
That token sees only the agent's own pages; admins can still open and re-share them.

## License

MIT
