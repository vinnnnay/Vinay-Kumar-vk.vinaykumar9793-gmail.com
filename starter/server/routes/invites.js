// Invites: the only way to add a person (AUTH-DATA-MODEL.md §6). One path, so one set
// of edge cases -- create, list, revoke are org-scoped and permissioned; peek and
// accept are public, because the token holder is not a member yet.

import { newInviteToken, hashInviteToken, hashPassword } from '../auth.js';
import { newId, nowIso } from '../db.js';
import { send, badRequest, notFound, gone, conflict } from '../http.js';
import { assertCan } from '../permissions.js';
import { assertRoleExists, assertRoleAssignable } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { meBody, mintAccessToken, issueRefreshToken } from './auth.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

export function registerInviteRoutes(router, { db, secret }) {
  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'invite.create' }, () => assertCan(db, ctx, 'user:invite'));

    const email = normalizeEmail(ctx.body.email);
    const role = ctx.body.role;
    if (!email) throw badRequest('email is required');
    if (typeof role !== 'string') throw badRequest('role is required');
    assertRoleExists(db, role);
    assertRoleAssignable(db, ctx.role, role);

    const existingMember = db
      .prepare(`SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? AND u.email = ? AND m.status = 'active'`)
      .get(ctx.orgId, email);
    if (existingMember) throw conflict('this email already has an active membership');

    const liveInvite = db
      .prepare(`SELECT 1 FROM invites WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL`)
      .get(ctx.orgId, email);
    if (liveInvite) throw conflict('this email already has a live invite');

    const raw = newInviteToken();
    const id = newId('inv');
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();

    try {
      db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(id, ctx.orgId, email, role, hashInviteToken(raw), ctx.userId, expiresAt);
    } catch {
      // one_live_invite_per_email closing a race the pre-check above cannot.
      throw conflict('this email already has a live invite');
    }

    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.create', targetType: 'invite', targetId: id, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id, email, role, expiresAt, inviteToken: raw });
  });

  router.get('/v1/orgs/:org/invites', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'invite.list' }, () => assertCan(db, ctx, 'user:invite'));

    const invites = db
      .prepare(`SELECT id, email, role, expires_at, accepted_at, revoked_at FROM invites WHERE org_id = ? ORDER BY created_at DESC`)
      .all(ctx.orgId);
    send(res, 200, { invites });
  });

  router.delete('/v1/orgs/:org/invites/:id', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'invite.revoke', targetType: 'invite', targetId: params.id }, () => assertCan(db, ctx, 'user:invite'));

    const invite = db
      .prepare(`SELECT * FROM invites WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`)
      .get(params.id, ctx.orgId);
    if (!invite) throw notFound();

    db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(nowIso(), invite.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.revoke', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: invite.id, status: 'revoked' });
  });

  // Public: the token holder is not a member yet, so only enough to render an
  // acceptance screen -- no org id, no member list, no device counts.
  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const invite = db
      .prepare(`SELECT i.*, o.name AS orgName FROM invites i JOIN organizations o ON o.id = i.org_id WHERE i.token_hash = ?`)
      .get(hashInviteToken(params.token));
    if (!invite) throw notFound();
    if (invite.accepted_at || invite.revoked_at || invite.expires_at <= nowIso()) throw gone();

    send(res, 200, { orgName: invite.orgName, role: invite.role, email: invite.email, expiresAt: invite.expires_at });
  });

  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    const invite = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(hashInviteToken(params.token));
    if (!invite) throw notFound();
    if (invite.accepted_at) throw conflict('invite already accepted');
    if (invite.revoked_at || invite.expires_at <= nowIso()) throw gone();

    const { name, password } = ctx.body;
    if (typeof password !== 'string' || password.length < 8) throw badRequest('password must be at least 8 characters');

    const now = nowIso();
    const accept = db.transaction(() => {
      let user = db.prepare('SELECT * FROM users WHERE email = ?').get(invite.email);
      if (!user) {
        const userId = newId('usr');
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)').run(
          userId,
          invite.email,
          typeof name === 'string' && name.trim() ? name.trim() : invite.email,
          hashPassword(password)
        );
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      }

      const membershipId = newId('mem');
      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?, ?, ?, ?, 'active', ?, ?)`
      ).run(membershipId, invite.org_id, user.id, invite.role, invite.invited_by, now);
      db.prepare('UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?').run(now, user.id, invite.id);

      return { user, membership: db.prepare('SELECT * FROM memberships WHERE id = ?').get(membershipId) };
    });

    let result;
    try {
      result = accept();
    } catch {
      // one_live_invite_per_email again: a concurrent accept of the same token won.
      throw conflict('invite already accepted');
    }

    audit(db, { orgId: invite.org_id, actorId: result.user.id, action: 'invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });

    const token = mintAccessToken(secret, result.user.id, result.membership);
    issueRefreshToken(db, res, result.user.id);
    send(res, 200, { token, ...meBody(db, { userId: result.user.id, orgId: invite.org_id, role: invite.role }) });
  });
}
