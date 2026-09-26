// Per-request context: turn a bearer token into an authenticated caller.
//
// Structural org isolation lives here, not in individual routes: the token's `org`
// claim is the only org this caller may address. A request naming a different org in
// the path is refused before the database is even asked whether that org exists, so
// the response for "wrong org" and "no such org" are identical -- 404 either way.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const header = req.headers['authorization'] ?? '';
    const match = /^Bearer (.+)$/.exec(header);
    if (!match) throw unauthenticated('missing bearer token');

    const claims = verifyAccessToken(match[1], secret);

    // The caller cannot even ask about another org: not filtered after the fact,
    // refused before the lookup. See AUTH-DATA-MODEL.md §2 (D18) and §10.
    if (params?.org && params.org !== claims.org) throw notFound();

    const membership = db
      .prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
      .get(claims.org, claims.sub);

    // A removed membership no longer exists as far as auth is concerned (D15: users
    // are never deleted, but the membership row's status is). AUTH-DATA-MODEL.md §10:
    // removed -> 401. Suspended is deliberately NOT rejected here -- the caller is
    // still authenticated, and permissions.js resolves an empty set for them, which
    // is what turns every subsequent request into a 403 rather than a 401.
    if (!membership || membership.status === 'removed') {
      throw unauthenticated('membership no longer exists');
    }

    // Compares with !==, not <: a pv from the future is as suspect as a stale one
    // (AUTH-DATA-MODEL.md §3). Throws 401 TOKEN_STALE.
    assertFresh(claims, membership);

    return { userId: claims.sub, orgId: claims.org, role: membership.role, membership, claims };
  };
}
