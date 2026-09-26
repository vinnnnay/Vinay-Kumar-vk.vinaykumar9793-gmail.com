// JWT and password hashing, hand-rolled on node:crypto.
//
// Nothing here is hidden behind a library on purpose. Signing is done for you;
// `verifyAccessToken` below is a stub you have to implement. The rules it must
// enforce are in AUTH-DATA-MODEL.md §10 and restated in the TODO comment.
//
// The payload is base64, NOT encrypted. Never put a secret in it.

import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

// Issue an access token. Note what is NOT in here: the resolved permission set.
// The token carries the authorization INPUTS (org, role, pv); the server resolves
// the permissions. See AUTH-DATA-MODEL.md §1 (D11).
export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

// Verify an access token and return its claims, or throw `unauthenticated(...)`.
// Structural checks only — permission-version staleness is `assertFresh`, which
// needs the membership row. `node scripts/check-jwt.js` is the public suite.
//
// A header or payload that parses as JSON but is not an object (null, array,
// scalar) must still be a 401. Property access on those values throws, and that
// throw would leave this function as a 500.
function isJsonObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function verifyAccessToken(token, secret) {
  // Every rejection is `unauthenticated(...)` so the suite (and the pipeline) see
  // 401 UNAUTHENTICATED rather than a raw TypeError/RangeError.
  if (typeof token !== 'string') throw unauthenticated('malformed token');

  const parts = token.split('.');
  if (parts.length !== 3) throw unauthenticated('malformed token');
  const [h, p, s] = parts;

  let header;
  try {
    header = JSON.parse(unb64(h).toString('utf8'));
  } catch {
    throw unauthenticated('malformed token header');
  }
  // Read the header, then ignore its algorithm. The HMAC below is always SHA-256.
  // Dispatching on `header.alg` is how `alg: none` and HS512/RS256 substitution get in.
  if (!isJsonObject(header) || header.alg !== ALG || header.typ !== 'JWT') {
    throw unauthenticated('unsupported token algorithm');
  }

  const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  const actual = unb64(s);
  // timingSafeEqual throws when the lengths differ. A truncated or empty signature
  // must be a 401, not that throw leaking out as a 500.
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw unauthenticated('bad signature');
  }

  let claims;
  try {
    claims = JSON.parse(unb64(p).toString('utf8'));
  } catch {
    throw unauthenticated('malformed token payload');
  }
  if (!isJsonObject(claims)) throw unauthenticated('malformed token payload');

  // Half-open, matching D7: exp == now is already expired. A numeric string is not
  // a number — JSON would have kept a real number as a number.
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp <= now) {
    throw unauthenticated('token expired');
  }
  if (claims.iss !== ISS || claims.aud !== AUD) {
    throw unauthenticated('bad token issuer or audience');
  }
  if (typeof claims.jti !== 'string' || claims.jti.length === 0) {
    throw unauthenticated('token has no jti');
  }

  return claims;
}


// The freshness check (AUTH-DATA-MODEL.md §3). Compares the token's pv against the
// membership's current perm_version. Note `!==`, not `<`: a token from the future is
// as suspect as a stale one.
export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

// --- opaque credentials: refresh tokens and invite tokens -------------------
//
// Both are bearer credentials that live in a database, so both are stored hashed —
// never plaintext, and never reversible. But they are DIFFERENT credentials, so they
// get DIFFERENT hash domains: sharing one would let a value from one table be compared
// against the other, which is a pointless and avoidable correlation.
//
// The key is an application secret, not a hardcoded literal. A hardcoded key means the
// hash is brute-forceable offline by anyone who reads this file — which defeats the
// point of hashing a high-entropy token.

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

// --- passwords --------------------------------------------------------------

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
