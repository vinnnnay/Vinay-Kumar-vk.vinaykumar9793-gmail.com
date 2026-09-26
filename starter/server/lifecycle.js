// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can() question --
// that is entirely permissions.js's job. This file only ever answers "who may modify
// whom" (D8) and "what ends a session" (PERMISSIONS.md §7.2).

import { nowIso } from './db.js';
import { badRequest, forbidden, lastOwner } from './http.js';

export function roleRanks(db) {
  return Object.fromEntries(db.prepare('SELECT key, rank FROM roles').all().map((r) => [r.key, r.rank]));
}

export function assertRoleExists(db, role) {
  if (!db.prepare('SELECT 1 FROM roles WHERE key = ?').get(role)) {
    throw badRequest(`unknown role: ${role}`);
  }
}

// D8: owner > admin > operator > auditor > viewer, strictly -- equal rank (admin ->
// admin) is refused, not just lower-modifying-higher. Owner is the one exception: an
// org can have more than one owner (this fixture's Acme does), and an equal-rank
// carve-out is the only way one owner can ever demote a co-owner. assertNotLastOwner
// is the floor that makes this safe -- see DECISIONS.md.
export function assertCanModify(db, callerRole, targetRole) {
  if (callerRole === 'owner' && targetRole === 'owner') return;
  const ranks = roleRanks(db);
  if (!(ranks[callerRole] > ranks[targetRole])) {
    throw forbidden(`${callerRole} may not modify ${targetRole}`, 'rank_too_low');
  }
}

// Assigning a role -- via invite or role-update -- is bounded by the caller's OWN
// rank, non-strictly: an admin may hand out admin, but not owner. Because owner is
// the single highest rank, "caller's rank >= the role being assigned" already implies
// "only an owner may confer owner" -- no separate check needed for that case.
export function assertRoleAssignable(db, callerRole, role) {
  const ranks = roleRanks(db);
  if (ranks[callerRole] < ranks[role]) {
    throw forbidden(`${callerRole} may not assign ${role}`, 'rank_too_low');
  }
}

export function assertNotLastOwner(db, orgId, userId) {
  const owners = db
    .prepare(`SELECT user_id FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'`)
    .all(orgId);
  if (owners.length === 1 && owners[0].user_id === userId) throw lastOwner();
}

// Ends every currently-active session matching the given scope. At least one of
// userId/deviceId is expected; passing neither would end every active session in the
// org, which no caller of this module does on purpose.
export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  const targets = db
    .prepare(
      `SELECT id FROM sessions
        WHERE org_id = @orgId AND state = 'active'
          AND (@userId IS NULL OR user_id = @userId)
          AND (@deviceId IS NULL OR device_id = @deviceId)
          AND (@exceptSessionId IS NULL OR id != @exceptSessionId)`
    )
    .all({ orgId, userId, deviceId, exceptSessionId });

  const end = db.prepare(`UPDATE sessions SET state = 'ended', end_reason = @reason, ended_at = @endedAt WHERE id = @id`);
  const endedAt = nowIso();
  const run = db.transaction((ids) => {
    for (const id of ids) end.run({ reason, endedAt, id });
  });
  run(targets.map((t) => t.id));
  return targets.length;
}

// The authorization snapshot a session is started with (PERMISSIONS.md §7.1). Recorded
// once, at session start, and never recomputed -- that snapshot IS the session's
// authority for its whole life, which is what "grandfathered" means.
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const membership = db.prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  const grantIds = db
    .prepare(
      `SELECT g.id FROM grants g
        WHERE g.org_id = @orgId AND g.user_id = @userId AND g.revoked_at IS NULL
          AND (g.device_id IS NULL OR g.device_id = @deviceId)`
    )
    .all({ orgId, userId, deviceId })
    .map((r) => r.id);

  return JSON.stringify({ role: membership?.role ?? null, grantIds, snapshotAt: nowIso() });
}

export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  const minutes = org?.max_session_minutes ?? 60;
  return new Date(Date.now() + minutes * 60_000).toISOString();
}
