# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### The verifier pins HS256 and length-checks before `timingSafeEqual`

**What I chose:** `verifyAccessToken` always verifies with HMAC-SHA256, and it rejects the token when `header.alg !== 'HS256'` or `header.typ !== 'JWT'`. A signature whose decoded length differs from the digest is a 401, checked before `timingSafeEqual`.
**Why:** `node scripts/check-jwt.js` accepts only `401 UNAUTHENTICATED` or `accepted`. A direct call of `timingSafeEqual` on the truncated-signature case throws `RangeError: Input buffers must have the same byte length` (logged in `BUILD-LOG.md`, Phase 1). That RangeError is not an `HttpError`, so the truncated-signature row would fail the same way the stub did. `Buffer.from('!!!not-base64!!!', 'base64url')` returns 7 bytes and does not throw, so the length check is also what rejects a non-base64url signature.
**What I rejected:** switching on `header.alg` (accept `none` when the signature is empty; use SHA-512 when the header says `HS512`). That is the substitution the `alg: none, empty signature` and `alg: HS512 substitution` rows are aimed at. Also rejected calling `timingSafeEqual` unconditionally — it turns a short signature into a 500.
**What would change my mind:** a second legitimate access-token algorithm that the public suite started accepting. There is one algorithm constant, `ALG = 'HS256'`, and the suite rejects `HS512` and `RS256`.

---

### `exp` has to be a finite number, and `exp == now` is expired

**What I chose:** reject unless `typeof claims.exp === 'number' && Number.isFinite(claims.exp) && claims.exp > now`.
**Why:** `scripts/check-jwt.js` labels the row `exp exactly now` as a 401, and `exp is a string` as a 401. A probe with `exp: NaN` and `exp: Infinity` also comes back `401 UNAUTHENTICATED token expired`. Without `Number.isFinite`, `NaN` passes a `typeof === 'number'` test and fails the `<= now` test, because `NaN <= now` is false — the token would be accepted.
**What I rejected:** the usual JWT reading `exp < now` (equal-to-now still valid), and coercing numeric strings with `Number(claims.exp)`. The string row is a signed token whose `exp` is `"<unix>"`; coercing it would accept a claim JSON cannot produce for a real number, and the suite wants it rejected.
**What would change my mind:** a suite row where `exp == now` is still accepted, or where a numeric string expiry is required to pass.

---

### Stale `pv` stays in `assertFresh`, not in `verifyAccessToken`

**What I chose:** `verifyAccessToken(token, secret)` checks structure, algorithm, signature, `exp`, `iss`, `aud`, and `jti`. It returns the claims, including `pv`, without looking at the database. `assertFresh` compares `membership.perm_version !== claims.pv`.
**Why:** the public suite calls `verifyAccessToken(token, secret)` with no database (`scripts/check-jwt.js` line 49). A stale-`pv` check inside the verifier has nothing to compare against, and a missing membership would have to be invented. `assertFresh` in `server/auth.js` already implements the `!==` comparison and throws `tokenStale()` (`401 TOKEN_STALE`).
**What I rejected:** opening the database inside `verifyAccessToken`. That couples a pure signature check to a membership lookup, and it cannot satisfy the two-argument suite without a hidden global connection.
**What would change my mind:** a test that passes a membership (or a `pv` oracle) into `verifyAccessToken` and expects `TOKEN_STALE` from that function itself.

---

### Org-level device-permission queries union across every device

**What I chose:** `resolve(db, { deviceId: null })` for a `resource: 'device'` permission calls `resolveAtScope` once per device in the org and returns the first `allow`, falling back to the first `deny` (`resolveDeviceScopedUnion` in `server/permissions.js`).
**Why:** `seed/orgs.json`'s `grt_dana_control_one_device` gives Dana (`viewer` in Globex, no `device:control` in the baseline) an `allow` on `dev_globex_desk_01` only. A naive org-level check — baseline plus org-wide grants, ignoring device-scoped ones — answers "can Dana control anything in Globex?" with `deny`, which is wrong; she can, on that one device. PERMISSIONS.md §3 says the org-level view is "the union across all devices in the org," and this is the only reading of that sentence that makes the Globex fixture's own stated point (D6) true at the org level, not just the device level.
**What I rejected:** treating `deviceId: null` as "org-wide grants only, no per-device grants." That's simpler and is what I wrote first, but it makes the nav-gating question answer deny for a user who can clearly act on at least one device, and it makes the org-level and device-level answers permanently agree, which the union language wouldn't need to say if that were the intended behavior.
**What would change my mind:** a hidden test asserting that an org-level device-permission query ignores device-scoped grants entirely, or a test where an org-wide deny plus a device-scoped allow resolves to org-level allow — that would mean D1 is meant to dominate the union, not just the per-device answer, and I have not built that case.

### `scripts/load-db.js` needed a one-line Windows fix

**What I chose:** changed `here = (p) => new URL(p, import.meta.url).pathname` to return the `URL` object itself, not its `.pathname`.
**Why:** on Windows, a `file://` URL's `.pathname` is `/D:/rhino/...` — a leading slash before the drive letter — which is not a path `fs.readFileSync` resolves correctly; it produced `ENOENT` against `D:\D:\rhino\...\db\schema.sql` (logged in `BUILD-LOG.md`, Phase 2). `check-permissions.js:10-11` and `check-personalisation.js:27-28` pass the `URL` object directly and both work, which is how I found the fix rather than guessing at one.
**What I rejected:** leaving it and only running the app under WSL/a POSIX shell. That papers over a real bug for the grader's environment, not just mine, and the fix is smaller than the workaround.
**What would change my mind:** if the grading harness never runs `npm run db:reset` directly on Windows (only inside a container), this fix is moot but harmless — it's a strict subset of what the URL-object form already does elsewhere in this repo.

### `context.js` lets a suspended caller through; only `removed` is a 401

**What I chose:** `authenticate()` throws `unauthenticated()` for a missing membership or `status === 'removed'`, and returns a caller for every other status, including `suspended`.
**Why:** AUTH-DATA-MODEL.md §10 states the two outcomes explicitly and differently: suspended → `403` with an empty permission set, removed → `401`. `permissions.js`'s `resolve()` already returns `denyAll(catalogue, 'suspended')` for a suspended membership (`server/permissions.js`, `inactiveReason`), so letting the request through and having `assertCan` reject it as `403 FORBIDDEN reason:"suspended"` satisfies §10 without a second status check living outside the resolution engine.
**What I rejected:** rejecting `suspended` in `context.js` with 401, which was my first instinct because "not active" reads like "not authenticated." It fails the documented split and it would have been a second place — outside `permissions.js` — deciding an authorization outcome.
**What would change my mind:** a test hitting a suspended user's request and expecting `401` rather than `403` at any endpoint.

---

## Where this repo argues with itself

### `AUTH-DATA-MODEL.md` §10 vs the verifier's actual job

§10 is titled "What `verifyAccessToken` has to reject" and its list includes:

> a token whose `pv` is stale, as `401 TOKEN_STALE`
>
> a refresh token presented as a bearer access token, and an access token presented at `/auth/refresh`
>
> a replayed refresh token, which should revoke the whole `family_id`

The stub contract in `server/auth.js` (the seven numbered checks) and `scripts/check-jwt.js` only cover structure, algorithm, signature, `exp`, `iss`, `aud`, and `jti`. `assertFresh` owns `pv`. Presenting an access token at `/auth/refresh`, and revoking a replayed refresh family, need the request path and the `refresh_tokens` table. The verifier's signature is `(token, secret)`.

Built against the split. A refresh token presented as a bearer is rejected, because it is not a three-segment HS256 JWT (`opaque refresh token as bearer` in `check-jwt.js`). The other two bullets are not this function. Folding them in would make §10's title true and the test harness uncallable.

### §10 also says the verifier returns 403 for a suspended membership

Later in the same section:

> a token for a suspended membership → `403` with an empty permission set; for a `removed` membership → `401`

That depends on a membership row. `verifyAccessToken` does not have one. Those outcomes belong to caller context, once that exists. Not built yet; recording the contradiction before the code so the later module is aimed at it.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.
