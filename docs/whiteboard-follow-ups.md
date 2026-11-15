# Whiteboard sharing: what is left

Whiteboard sharing merged to `main` on 2026-11-14 in lubberlandhq/artifacts#3 (after the Tack
rename, lubberlandhq/artifacts#2). This is the list of what that merge left undone, untested or
knowingly imperfect. `docs/SPEC.md` §7a describes what was built; the PR body holds the review
record.

Nothing here is deployed yet.

## Before the first deploy

1. Apply migrations `0003` through `0006` before `wrangler deploy`. The Worker reads the token
   columns `0004` and `0005` add on every request made with a token, and writes the column
   `0006` adds on every `whiteboard login`.
2. Run `tack board-viewer` once as an admin, so share pages have a viewer to frame.
3. Update `cli/tack` wherever it is installed, together with the server. A copy from before
   the merge publishes a stray version of the viewer artifact and then gets `invalid_request`
   from `PUT /api/whiteboard/viewer`, which now requires a version.
4. Put a Cloudflare rate-limit rule on `/api/auth/device/*`. The app caps unapproved device
   codes at 5 per caller address (per /64 for IPv6) and 200 on the server, but a caller with 40
   or more addresses or networks can hold all 200 and block new Whiteboard logins for as long
   as it keeps going. Existing logins keep working. No cap inside the app stops that.
5. Optionally set `WHITEBOARD_LOGIN_DAYS` (90 when unset).

Before rolling back to a Worker from before this merge, delete the Whiteboard logins
(`DELETE FROM tokens WHERE scope IS NOT NULL`): the older Worker reads neither a token's scope
nor its expiry.

## Not yet tested

- **Whiteboard's Share button.** Every share in testing was uploaded by `tack board`, the
  `whiteboard` command line, or a test script.
- **Whether Whiteboard Desktop displays a board it opened from a link.** In a hand test over
  https, "Open in Whiteboard" made Desktop fetch the share and its snapshot (seen in the server
  log); what it then showed was not recorded.
- **Production.** `whiteboard login` with a real Cloudflare Access sign-in, and the share page
  framing a board from a per-share content host, have only run against `wrangler dev`.
- **Whiteboard's client paging past 100 shares.** The list cursor is a share id because the
  client refuses anything but a UUID there; the smoke test mirrors that check in a pattern and
  does not run the client itself.
- **Boards that pin code** (commits and sources) through the browser viewer's download link.
- **The server-wide ceiling of 200 device codes**, and taking over a request id left by an
  upload that died more than a minute ago. Neither has a test.
- **The version rule against dev.fast's own service.** Sending the newest version of a board
  again with different content replaces that revision's snapshot in place. That follows what
  Whiteboard sends for a board shared with uncommitted changes and again once committed; how
  dev.fast's service treats the same upload was not checked.

## Merged without a reviewer reading them

Two full review rounds and one fix-check covered the branch up to the request-id fix. Three
later changes went in on tests alone:

- the same-version snapshot replacement and binding token limits (`createApiToken` refuses a
  lifetime under one second and an empty scope);
- the list cursor going back to a share id, with time-ordered share ids (UUID version 7);
- the fix-check itself read only the request-id fix, not the rest of that round.

The upload path (`publish` in `src/whiteboard.ts`) is where two successive fixes each
introduced a defect during review. It is the part most worth a second read.

gstack wrote no ship receipt for this work: its auth reader still had findings when the review
cap was reached. The documentation audit and the final verification gate did not run in the
second pass.

## Known limits

Upload and sharing:

- One request id reused for two different boards: the second waits with 409
  `request_in_progress` for up to 60 seconds, then takes the id over, after which a retry of
  the first upload is answered with the second board's link. Under a further race on that path
  an upload can answer 500, or a share with no board can be left listed. Whiteboard makes a new
  id for every upload.
- A 16 MiB upload is held in about six copies inside one request. An object-dense body may
  exceed the Worker's memory limit. Not measured on Workers.
- No quota on shares or revisions.
- A share stored before the same-version rule has no content hash, so its first same-version
  upload rewrites the snapshot once even when nothing changed.
- Errors from the hub routes can surface as bare 500s without the `{"error":{"code"}}` body
  Whiteboard reads.

Login:

- Whiteboard's command line shows a rate-limited login as the bare word `slow_down`. Someone
  who cancels and retries a login more than five times in ten minutes sees exactly that.
- A server not behind Cloudflare has no caller address, so every caller shares one allowance
  of five pending codes.
- Phishing someone into approving a device code hands over their board sharing until the login
  expires or is pushed out as the oldest of their ten. Nothing tells them a login was made.

CLI and viewer:

- A failed viewer build leaves its build folder in `~/.cache/tack`; nothing removes old ones.
- `tack board-viewer` prints the artifact's live version in its message, which differs from
  the version it registered if someone else published in between.
- The repo states no minimum bun version for the text `bun.lock` the viewer build needs.

Tests and wording:

- The smoke check for two uploads racing with one request id accepts a 409 without retrying
  that upload.
- A smoke run that crashes part-way leaves shares behind that fail the next run. Clear
  `nate@dev.test`'s rows in `wb_shares`, `wb_revisions` and `wb_requests` in the local
  database.
- The comment on `wb_requests` in migration `0003`, and one comment in `publish`, still say a
  repeated request id always answers as the first upload did. `docs/SPEC.md` has the rule as
  it is now.
- Coverage was measured at 73% value-weighted before the expiry, link and request-id tests
  were added, and not measured again.

## Housekeeping

- **Roadmap migration numbers.** `docs/ROADMAP.md` plans `0003_commenter_role.sql` and
  `0004_comment_anchor.sql`. Those numbers are now taken, through `0006`; the next free one is
  `0007`.
- **Repo name.** The service is called Tack and the repository is still `artifacts`. A rename
  touches the GitHub repository, every checkout's remote, and the references in `README.md`,
  `docs/` and `skills/tack/SKILL.md`.
- **The laptop used for the hand test.** Its Whiteboard is still logged in to a local test
  server that has been shut down. Run `whiteboard login --origin <the server it should use>`
  there.
