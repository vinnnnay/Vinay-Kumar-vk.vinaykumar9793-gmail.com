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

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

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
