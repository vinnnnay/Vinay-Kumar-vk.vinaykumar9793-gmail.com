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

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
