---
name: share
description: Publish an HTML page to an artifacts server with lshare and share it, a self-hosted Claude-Artifacts-style host. Use when the person asks for a share link or says /share or lshare, when a page (report, mockup, dashboard) must reach someone outside this session, or to update, re-share, list or read comments on an existing share.
---

# /share: pages on an artifacts server

`lshare` publishes a self-contained HTML page (or a folder with `index.html`) and prints a link.
Republishing keeps the link. Who can open it is set per page.

## Run it

`lshare` needs two environment variables: `LSHARE_URL` (the server, e.g.
`https://share.example.com`) and `LSHARE_TOKEN` (a token from the server's gallery page, "Tokens
for the CLI and agents"). If your environment's instructions (AGENTS.md, CLAUDE.md) give a command
that supplies them, such as a secrets wrapper, use that command wherever this skill says `lshare`.
Never put the token on the command line or in a file.

Piped output is JSON; exit 2 = usage (including a missing `LSHARE_URL`), 4 = auth, 5 = API.
`lshare --help` has every flag. On exit 4 the token is missing or revoked: tell the person, who
mints a new one on the gallery page.

## Publish

1. Write the page to the contract below.
2. `lshare publish page.html --title "…"`, or `lshare publish ./dir --title "…"` for several files.
   A new page starts **private**: only its owner (and editors) can open it.
3. To update it: `lshare publish page.html --id <id> --label "what changed"`. Same link, new version.
   Files left out of a folder publish are kept; `--remove path` drops one.
4. Give the person the link from the output, with who can currently see it.

Done when the link opens for its intended audience: check the output's `sharing.mode` matches
what the person asked for.

## Share

```sh
lshare share <id> --mode private|people|org|public [--users a@x,b@y] [--editors c@z] [--pin live|current|N]
```

- `people`: named emails. Each must also be allowed to sign in to the server; if someone can't,
  tell the person rather than working around it.
- `org`: everyone the server counts as a member of its org.
- `public`: anyone with the link, no sign-in.
- `--pin current` freezes what viewers see at this version; `--pin live` follows new publishes.

Sharing reaches people outside this session: confirm the audience with the person before
`people`, `org` or `public`, unless their request already named it.

## The page contract

Pages run on their own origin under a strict CSP, the same contract as Claude Artifacts, so a page
written for one works on the other:

- One `index.html` at the root; other files referenced by relative paths with no leading slash.
- Scripts only from cdnjs.cloudflare.com, cdn.jsdelivr.net, unpkg.com, cdn.tailwindcss.com,
  code.jquery.com, at exact versions; stylesheets only from Google Fonts; everything else inline.
- Network calls only to the page's own files (`connect-src 'self'`): bake the data in.
- Works at phone width; 25 MB per file, 100 MB per version.
- Holds nothing secret. Anyone the page is shared with can save it.

## Other commands

`lshare list` · `lshare get <id>` (sharing details) · `lshare versions <id>` ·
`lshare comments <id>` (viewers' feedback: read these before revising a page) ·
`lshare rename <id> --title …` · `lshare delete <id> --yes` (permanent; only when the person asks).
