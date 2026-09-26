// Login, refresh, org-switch, and "who am I". D11/D12/D18 all live here: the token
// carries identity and one org; the server resolves permissions; switching orgs mints
// a new token rather than mutating a shared "current org".

import { issueAccessToken, verifyPassword, newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS } from '../auth.js';
import { newId, nowIso } from '../db.js';
import { send, badRequest, unauthenticated, notFound } from '../http.js';
import { resolve } from '../permissions.js';

const REFRESH_COOKIE = 'rt';

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

// Secure is dropped outside production because `npm run dev` serves plain HTTP on
// localhost; a browser silently refuses to store a Secure cookie over HTTP, which
// would break every login in local dev. See DECISIONS.md.
function setRefreshCookie(res, token, maxAgeSeconds) {
  const secure = process.env.NODE_ENV === 'production' ? ' Secure;' : '';
  res.setHeader('set-cookie', `${REFRESH_COOKIE}=${token}; HttpOnly;${secure} SameSite=Strict; Path=/v1/auth; Max-Age=${maxAgeSeconds}`);
}

function issueRefreshToken(db, res, userId, familyId = newId('fam')) {
  const raw = newRefreshToken();
  db.prepare('INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)').run(
    newId('rt'),
    userId,
    hashRefreshToken(raw),
    familyId,
    new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString()
  );
  setRefreshCookie(res, raw, REFRESH_TTL_SECONDS);
}

function defaultMembership(db, userId) {
  return db
    .prepare(`SELECT * FROM memberships WHERE user_id = ? AND status = 'active' ORDER BY joined_at ASC, created_at ASC LIMIT 1`)
    .get(userId);
}

function membershipFor(db, userId, orgId) {
  return db.prepare(`SELECT * FROM memberships WHERE user_id = ? AND org_id = ? AND status = 'active'`).get(userId, orgId);
}

function activeOrgsFor(db, userId) {
  return db
    .prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY m.joined_at ASC`
    )
    .all(userId);
}

function meBody(db, { userId, orgId, role }) {
  return { userId, orgId, role, orgs: activeOrgsFor(db, userId), permissions: resolve(db, { userId, orgId }).permissions };
}

function mintAccessToken(secret, userId, membership) {
  return issueAccessToken({ userId, orgId: membership.org_id, role: membership.role, permVersion: membership.perm_version }, secret);
}

export function registerAuthRoutes(router, { db, secret }) {
  router.post('/v1/auth/login', async (ctx, params, res) => {
    const { email, password, orgId } = ctx.body;
    if (typeof email !== 'string' || typeof password !== 'string') throw badRequest('email and password are required');

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase());
    // A wrong password and a nonexistent account read the same way -- distinguishing
    // them is an account-enumeration oracle (BRIEF.md §3.2).
    if (!user || !verifyPassword(password, user.password_hash)) throw unauthenticated('invalid email or password');

    const membership = orgId ? membershipFor(db, user.id, orgId) : defaultMembership(db, user.id);
    if (!membership) throw orgId ? notFound() : unauthenticated('no active organization membership');

    const token = mintAccessToken(secret, user.id, membership);
    issueRefreshToken(db, res, user.id);
    send(res, 200, { token, ...meBody(db, { userId: user.id, orgId: membership.org_id, role: membership.role }) });
  });

  router.post('/v1/auth/refresh', async (ctx, params, res) => {
    const raw = parseCookies(ctx.req)[REFRESH_COOKIE];
    if (!raw) throw unauthenticated('missing refresh cookie');

    const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (!row) throw unauthenticated('invalid refresh token');

    if (row.revoked_at) {
      // D12: replaying an already-rotated token revokes the whole rotation family.
      db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`).run(nowIso(), row.family_id);
      throw unauthenticated('refresh token reused; session revoked');
    }
    if (row.expires_at <= nowIso()) throw unauthenticated('refresh token expired');

    db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(nowIso(), row.id);

    // refresh_tokens carries no org_id (it is an identity credential, not an
    // authorization one -- D12), so an explicit orgId in the body re-scopes it;
    // otherwise the same default-org choice login makes. See DECISIONS.md.
    const { orgId } = ctx.body ?? {};
    const membership = orgId ? membershipFor(db, row.user_id, orgId) : defaultMembership(db, row.user_id);
    if (!membership) throw unauthenticated('no active organization membership');

    const token = mintAccessToken(secret, row.user_id, membership);
    issueRefreshToken(db, res, row.user_id, row.family_id);
    send(res, 200, { token, ...meBody(db, { userId: row.user_id, orgId: membership.org_id, role: membership.role }) });
  });

  router.post('/v1/auth/token', async (ctx, params, res) => {
    const { orgId } = ctx.body ?? {};
    if (typeof orgId !== 'string') throw badRequest('orgId is required');

    // Not a member (or not active) here is invisible, same as any other cross-org
    // request -- 404, never 403 (D18, PERMISSIONS.md §5).
    const membership = membershipFor(db, ctx.userId, orgId);
    if (!membership) throw notFound();

    const token = mintAccessToken(secret, ctx.userId, membership);
    send(res, 200, { token, ...meBody(db, { userId: ctx.userId, orgId: membership.org_id, role: membership.role }) });
  });

  router.get('/v1/auth/me', async (ctx, params, res) => {
    send(res, 200, meBody(db, { userId: ctx.userId, orgId: ctx.orgId, role: ctx.role }));
  });
}

export { activeOrgsFor, membershipFor, meBody, mintAccessToken, issueRefreshToken };
