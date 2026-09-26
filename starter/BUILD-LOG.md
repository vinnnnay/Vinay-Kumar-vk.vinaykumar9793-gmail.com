# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

## 2026-09-26 · Phase 0 — orientation

Expected the stub to fail only the "accepted" rows. It throws, so `null token` and `alg: none`
should already count as rejections.
Observed: `node scripts/check-jwt.js` — 0 passed, 43 failed. Every row, including the rejection
cases, is `Error: TODO: server/auth.js — verifyAccessToken() is yours to write (AUTH-DATA-MODEL.md §10).`
wanted `401 UNAUTHENTICATED`. The harness (`scripts/check-jwt.js` `outcome`) only treats an
`HttpError` as a shaped rejection. A bare throw is not a 401.
Note: `assertFresh` is already implemented and is the only `TOKEN_STALE` path. The verifier has
no database handle, so it cannot see `memberships.perm_version`.

## 2026-09-26 · Phase 1 — token verification

Expected `timingSafeEqual` to return false when the signature is shorter than the digest.
Observed: calling it on an 8-character signature throws `RangeError: Input buffers must have the
same byte length`. Separately, `Buffer.from('!!!not-base64!!!', 'base64url')` does not throw; it
returns a 7-byte buffer. And `NaN <= now` is false, so `typeof exp === 'number' && exp <= now`
would accept `exp: NaN`.
Changed: length-check, then `timingSafeEqual`. HMAC is always SHA-256; `header.alg` is an
allow-list (`HS256` and `typ === 'JWT'`), never a switch. `exp` must be a finite number and
`exp <= now` is expired. Header and payload must be JSON objects, not null or arrays.
Result: `node scripts/check-jwt.js` — 43 passed, 0 failed. Extra probe: `exp: NaN`, `exp:
Infinity`, a `null` header, and an array payload all return `401 UNAUTHENTICATED`. A future
fractional `exp` is accepted; it is a finite number.

## Phase 2 — caller context and the resolution engine

Before writing `resolve()`, ran `npm run db:reset` for the first time and it threw
`ENOENT: no such file or directory, open 'D:\D:\rhino\...\db\schema.sql'` from
`scripts/load-db.js`. A doubled drive letter. `load-db.js:10` does
`new URL(p, import.meta.url).pathname`, and `.pathname` on a `file://` URL is
`/D:/rhino/...` on Windows — a leading slash in front of the drive letter, which
`readFileSync` does not resolve as a real path. Every other script here
(`check-permissions.js:10-11`, `check-personalisation.js:27-28`, `personalise.js:213`)
passes the `URL` object straight to `readFileSync` instead of extracting `.pathname`,
and none of them have this bug. Changed `load-db.js` to do the same. Verified: `npm run
db:reset` now seeds `app.db` and prints the fixture summary. This is a bug in a "given"
file, on this platform only — recorded here rather than silently patched, per the
write-up rules on arguing with the documents instead of quietly working around them.

Expected the org-level (`deviceId: null`) query for a device permission to just be "does
the role baseline contain it, plus any org-wide grant" — i.e. the same code path as a
device-level query with `deviceId` fixed to null. Re-reading PERMISSIONS.md §3 ("org-level
... the union across all devices in the org") and the Globex grant
(`grt_dana_control_one_device` in `seed/orgs.json`: Dana is a `viewer` in Globex, denied
`device:control` by baseline everywhere, but explicitly allowed on
`dev_globex_desk_01`) made the first model visibly wrong: under it, the org-level
question "can Dana control anything in Globex?" would answer deny, when the true answer
is "yes, one device." Moved to computing the per-device answer for every device in the
org and OR-ing them (`resolveDeviceScopedUnion` in `server/permissions.js`), returning on
the first `allow`. D1's deny precedence is per-scope, not global, so this doesn't
conflict with it: an org-wide deny still makes every device resolve to deny (the union
is deny too), but a device-scoped deny on device A must not suppress an allow on device
B. `node scripts/check-permissions.js` — 35 passed, 0 failed, including the existing
device-scoped and org-wide-deny vectors, so this didn't regress D1.

`context.js` initially rejected any non-`active` membership status with 401. Rereading
AUTH-DATA-MODEL.md §10 ("a token for a suspended membership → `403` with an empty
permission set; for a `removed` membership → `401`") caught this before it shipped:
suspended has to reach the permission check and fail there, not be turned away at the
door. Split it: `removed` (and a missing row) throw `unauthenticated()` in
`context.js`; `suspended` is left to flow through, because `permissions.js`'s
`resolve()` already returns a full deny-all set with `reason: "suspended"` for it, and
`assertCan` turns that into a `403` naturally. One engine still decides allow/deny —
context.js does not duplicate the status check.

## Phase 3 — orgs, members, invites

Wrote `assertCanModify` straight from PERMISSIONS.md §6's table: caller's rank must be
strictly greater than the target's, full stop. Then ran `check-api.js`'s D8 block and
hit line 150 -- `PATCH /orgs/org_acme/members/usr_acme_owner` by Dana (owner),
demoting another owner to viewer, expected `200`. Strict-greater-than rejects this: an
owner has equal rank to an owner. But Acme's own fixture has two owners
(`usr_dana`, `usr_acme_owner`), and there is no other endpoint that could ever demote
one of them if owner-vs-owner were refused -- the org would be stuck with two owners
forever. Added one exception: `callerRole === 'owner' && targetRole === 'owner'`
returns immediately, before the rank comparison. `assertNotLastOwner` is the guard that
makes this safe (an owner demoting the *last* owner, including themselves, still hits
`LAST_OWNER`). `node scripts/check-api.js` -- 66/66, including both the "demoting a
non-last owner is allowed" and "admin cannot confer owner" rows, so this didn't loosen
the admin-to-admin case the doc's own example names.

Expected the partial unique index `one_exclusive_session_per_device` to surface with a
message naming the index, so I could match on `'one_exclusive_session_per_device'` to
tell a real conflict apart from an unrelated constraint failure. Observed:
better-sqlite3 throws `SqliteError: UNIQUE constraint failed: sessions.device_id` --
the column, not the index name -- so my first `DEVICE_BUSY` translation
(`server/routes/sessions.js`) never matched and a legitimate second `control` request
came back `500 INTERNAL` instead of `409 DEVICE_BUSY`. Caught by
`check-api.js`'s "2nd control on same device -> 409" row, not by guessing. Changed the
match to `err.code === 'SQLITE_CONSTRAINT_UNIQUE' && err.message.includes('sessions.device_id')`.

`refresh_tokens` has no `org_id` column (by design -- D12, it's an identity credential,
not an authorization one), which means `POST /auth/refresh` has no stored org to
reissue an access token for. The document doesn't say what a bare refresh (no `orgId`
in the body) should scope to. Settled it the same way login settles "no org given
yet": earliest-joined active membership. Recorded as an open decision, not a silent
default -- see DECISIONS.md.

`check-api.js` runs everything end to end -- auth, orgs, members, invites, devices,
grants, sessions, audit -- against real HTTP, so getting any of it green meant getting
most of it built first. Went broad across Phases 3-6 in one pass rather than in
strict phase order; `node scripts/check-api.js` -- 66/66, `check-permissions.js` --
35/35, `check-jwt.js` -- 43/43, `check-personalisation.js` -- 18/18 confirm none of it
regressed the earlier work or leaked the documented 19-permission matrix into a place
that would fail under a different nonce.

## Phase 4 — devices and grants

Covered by the Phase 3 entries above -- devices, grants, and their route-level
validation landed in the same pass as orgs/members/invites, verified together against
`check-api.js`.

## Phase 5 — sessions

The compound check (`assertCanStartSession`) was already built and unit-tested in
Phase 2; this phase was wiring it to a real device lookup, `snapshotAuthority`, and the
database's own exclusivity index rather than a check-then-insert. See the
`SQLITE_CONSTRAINT_UNIQUE` entry above for the one real surprise.

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

Built the device row's session-start buttons expecting to gate each one on BOTH
`session:start` and its mode permission -- that is the literal rule in
PERMISSIONS.md §9, and it's what `assertCanStartSession` on the server actually
enforces. First `npx playwright test` run: 23/25 passed, and the two failures were
both the same shape -- `dev_globex_desk_01`'s `device:control` button missing for
Dana (viewer in Globex, holds `device:control` there only through
`grt_dana_control_one_device`, which grants `device:control` alone, not
`session:start`). The compound rule is real, but it's a rule about what
`POST /sessions` allows, not about what a button's presence means. Rereading
README.md's console contract: "every card, every entry, and **the permission** that
governs it" -- singular, one element to one resolved permission. Removed the
`session:start` half of the presence check; `data-permission="device:control"` now
keys off `permissions['device:control'].effect` alone, same as every other element in
the console. A click on a button that's showing can still 403 if `session:start`
turns out to be the missing half -- that's surfaced as an inline error, not hidden by
making the button disappear for a reason the button doesn't name.
`npx playwright test` -- 25/25 after the fix.

Also found (while getting the production build to serve at all): `server/index.js`'s
`DIST` constant had the exact same `.pathname`-on-a-`file://`-URL bug as
`scripts/load-db.js` (Phase 2) -- `curl` against a built `dist/` returned `404` for
every asset until it was changed to `fileURLToPath`. Same fix, same root cause, two
places in the given code.

## Phase 8 — hardening

Measured, not guessed, against README.md's "Speed" section:

- **Query count per device row.** Seeded 200 devices in one org, monkey-patched
  `db.prepare` to count calls, and ran `resolveDevices` directly: 200 devices, **4**
  prepared statements, 2.06ms total. Confirms the device-row shape does its job --
  membership/baseline/grants load once, the per-device loop is pure JS after that.
- **First screen and first authenticated request.** Against a production build
  (`npm run build`, `NODE_ENV=production`): static `index.html` 8ms, `POST
  /auth/login` (password hashing included) 47ms, `GET /orgs/:org/devices` 2ms. All
  three are the README's "well inside a second" with room to spare.

Went looking for the specific anti-pattern named in the same section --
"resolving permissions more than once inside one request" -- by grepping every route
for a second `resolve(`/`assertCan(` against the same (user, org, device) scope.
Found one real instance: `GET /orgs/:org/devices/:id` called `assertCan(db, ctx,
'device:view', params.id)` (a full `resolve()` internally) and THEN called
`resolve()` again to get the permissions object for the response body -- the exact
double-resolution the doc warns about, on the one route I'd built without noticing
it. Every other route that calls `resolve()` twice does so for a genuinely different
subject (the effective-permissions endpoint resolves the caller once and the target
user once; device transfer resolves the source org and the destination org) --
checked each one by hand rather than assuming grep innocence.

Fixed by splitting `assertCan` in `permissions.js` into `resolve-then-check` and a
new `assertAllowed(permission, alreadyResolvedPermissions)` that just checks, so a
route that needs the full set anyway resolves once and reuses it. `check-api.js`
66/66 and `check-permissions.js` 35/35 held after the change; manually curled the
route directly (not in either public suite) to confirm both the allow and the
explicit-deny case still return the right status and body.

**Left alone, on purpose:** `GET /orgs/:org/devices` still resolves permissions
twice -- once for the `device:list` gate (`assertCan`), once inside `resolveDevices`
for the per-device sets. Both loads are the same fixed handful of queries regardless
of how many devices exist, so it's constant overhead, not the O(n) growth the Speed
section is actually warning against. Merging them would mean either exposing
`permissions.js`'s internal `loadCallerState` or teaching `resolveDevices` to accept
a pre-fetched membership, and I chose not to enlarge that module's surface for a
cost that doesn't scale with the thing the section cares about.

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
