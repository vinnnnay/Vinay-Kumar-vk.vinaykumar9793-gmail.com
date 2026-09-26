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
