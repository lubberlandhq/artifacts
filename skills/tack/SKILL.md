---
name: tack
description: Publish an HTML page or a Whiteboard board to an artifacts server with tack and share it, a self-hosted Claude-Artifacts-style host. Use when the person asks for a share link or says /tack or /share, when a page (report, mockup, dashboard) or a Whiteboard board must reach someone outside this session, or to update, re-share, list or read comments on an existing share.
---

# /tack: pages on an artifacts server

`tack` publishes a self-contained HTML page (or a folder with `index.html`) and prints a link.
Republishing keeps the link. Who can open it is set per page.

## Run it

`tack` needs two environment variables: `TACK_URL` (the server, e.g.
`https://share.example.com`) and `TACK_TOKEN` (a token from the server's gallery page, "Tokens
for the CLI and agents"). If your environment's instructions (AGENTS.md, CLAUDE.md) give a command
that supplies them, such as a secrets wrapper, use that command wherever this skill says `tack`.
Never put the token on the command line or in a file.

Piped output is JSON; exit 2 = usage (including a missing `TACK_URL`), 4 = auth, 5 = API.
`tack --help` has every flag. On exit 4 the token is missing or revoked: tell the person, who
mints a new one on the gallery page.

## Publish

1. Write the page to the contract below.
2. `tack publish page.html --title "…"`, or `tack publish ./dir --title "…"` for several files.
   A new page starts **private**: only its owner (and editors) can open it.
3. To update it: `tack publish page.html --id <id> --label "what changed"`. Same link, new version.
   Files left out of a folder publish are kept; `--remove path` drops one.
4. Give the person the link from the output, with who can currently see it.

Done when the link opens for its intended audience: check the output's `sharing.mode` matches
what the person asked for.

## Share

```sh
tack share <id> --mode private|people|org|public [--users a@x,b@y] [--editors c@z] [--pin live|current|N]
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

## Whiteboard boards

`tack board <review-id>` publishes a Whiteboard board (devdotfast/whiteboard) as a read-only
page: the board as it is now, with a link to download it for Whiteboard Desktop when Desktop can
open it. It takes a review id (exported with the `whiteboard` CLI, which must be on `PATH`) or a
`.whiteboard` file, and the same `--id`, `--title`, `--desc`, `--label` and `--base` as `publish`.
The title defaults to the board's and the label to its version. The page is a snapshot: publish
again with `--id <id>` after the board changes. The first run downloads the viewer from npm.

A board quotes the code it reviews. Treat sharing one like sharing that code.

`tack board` gives a page with Tack's sharing: private until shared, named people or the org.
Whiteboard's own Share button and `whiteboard share --review <id>` are different: once the
computer is logged in to the server (`whiteboard login --origin "$TACK_URL"`, approved by the
person in a browser), they return a `/s/…` link that **anyone holding it can read**, with no
sign-in, and that opens as an editable copy in Whiteboard Desktop. Use that only when the person
asks for a Whiteboard share link, and tell them it is link-readable. `whiteboard share revoke
<share-id>` deletes it.

## Other commands

`tack list` · `tack get <id>` (sharing details) · `tack versions <id>` ·
`tack comments <id>` (viewers' feedback: read these before revising a page) ·
`tack rename <id> --title …` · `tack delete <id> --yes` (permanent; only when the person asks).
