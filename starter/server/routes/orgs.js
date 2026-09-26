// Organizations and their membership roster: create/list/update/delete an org, and
// change/suspend/reinstate/remove/leave a member of one.

import { newId, nowIso } from '../db.js';
import { send, badRequest, notFound, selfRoleChange } from '../http.js';
import { assertCan, resolve } from '../permissions.js';
import { assertRoleExists, assertCanModify, assertRoleAssignable, assertNotLastOwner, endActiveSessions } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { activeOrgsFor } from './auth.js';

const THEMES = ['cobalt', 'amber', 'violet', 'emerald', 'rose', 'slate'];
const MAX_AUDIT_LIMIT = 500;

function parsePaging(query) {
  const limit = query.get('limit') === null ? 50 : Number(query.get('limit'));
  const offset = query.get('offset') === null ? 0 : Number(query.get('offset'));
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_AUDIT_LIMIT) {
    throw badRequest(`limit must be an integer between 1 and ${MAX_AUDIT_LIMIT}`);
  }
  if (!Number.isInteger(offset) || offset < 0) throw badRequest('offset must be a non-negative integer');
  return { limit, offset };
}

function bumpPv(db, orgId, userId) {
  db.prepare(`UPDATE memberships SET perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?`).run(orgId, userId);
}

// Any status except 'invited' -- an invite that hasn't been accepted isn't a member yet.
function membershipRow(db, orgId, userId) {
  return db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status != 'invited'`).get(orgId, userId);
}

export function registerOrgRoutes(router, { db }) {
  router.get('/v1/orgs', async (ctx, params, res) => {
    send(res, 200, { orgs: activeOrgsFor(db, ctx.userId) });
  });

  router.post('/v1/orgs', async (ctx, params, res) => {
    const name = typeof ctx.body.name === 'string' ? ctx.body.name.trim() : '';
    if (!name) throw badRequest('name is required');

    const id = newId('org');
    const theme = THEMES[Math.floor(Math.random() * THEMES.length)];
    db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(id, name, theme);
    db.prepare('INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      newId('mem'),
      id,
      ctx.userId,
      'owner',
      'active',
      nowIso()
    );
    audit(db, { orgId: id, actorId: ctx.userId, action: 'org.create', targetType: 'organization', targetId: id, result: 'allow', requestId: ctx.requestId });

    send(res, 201, { id, name, theme, role: 'owner' });
  });

  router.patch('/v1/orgs/:org', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'org.update', targetType: 'organization', targetId: ctx.orgId }, () => assertCan(db, ctx, 'org:update'));

    const fields = [];
    const values = [];
    if (typeof ctx.body.name === 'string' && ctx.body.name.trim()) { fields.push('name = ?'); values.push(ctx.body.name.trim()); }
    if (typeof ctx.body.theme === 'string') { fields.push('theme = ?'); values.push(ctx.body.theme); }
    if (Number.isInteger(ctx.body.maxSessionMinutes) && ctx.body.maxSessionMinutes > 0) {
      fields.push('max_session_minutes = ?');
      values.push(ctx.body.maxSessionMinutes);
    }
    if (fields.length) {
      db.prepare(`UPDATE organizations SET ${fields.join(', ')} WHERE id = ?`).run(...values, ctx.orgId);
    }
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'org.update', targetType: 'organization', targetId: ctx.orgId, result: 'allow', requestId: ctx.requestId });

    const org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(ctx.orgId);
    send(res, 200, org);
  });

  router.delete('/v1/orgs/:org', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'org.delete', targetType: 'organization', targetId: ctx.orgId }, () => assertCan(db, ctx, 'org:delete'));

    db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), ctx.orgId);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'org.delete', targetType: 'organization', targetId: ctx.orgId, result: 'allow', requestId: ctx.requestId });
    send(res, 204);
  });

  router.get('/v1/orgs/:org/members', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'members.list' }, () => assertCan(db, ctx, 'user:read'));

    const members = db
      .prepare(
        `SELECT u.id AS userId, u.email, u.name, m.role, m.status
           FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.org_id = ? AND m.status != 'invited'
          ORDER BY u.name`
      )
      .all(ctx.orgId);
    send(res, 200, { members });
  });

  // Registered before ':userId' so a literal '/members/me' is matched first
  // (router.js: first match wins, and ':userId' would otherwise swallow "me").
  router.delete('/v1/orgs/:org/members/me', async (ctx, params, res) => {
    const membership = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`).get(ctx.orgId, ctx.userId);
    if (!membership) throw notFound();
    if (membership.role === 'owner') assertNotLastOwner(db, ctx.orgId, ctx.userId);

    db.prepare(`UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE id = ?`).run(membership.id);
    endActiveSessions(db, { orgId: ctx.orgId, userId: ctx.userId, reason: 'membership_removed' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.leave', targetType: 'membership', targetId: membership.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { userId: ctx.userId, status: 'removed' });
  });

  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'member.role_update', targetType: 'membership', targetId: params.userId }, () =>
      assertCan(db, ctx, 'user:role:update')
    );

    if (params.userId === ctx.userId) throw selfRoleChange();

    const role = ctx.body.role;
    if (typeof role !== 'string') throw badRequest('role is required');
    assertRoleExists(db, role);

    const target = membershipRow(db, ctx.orgId, params.userId);
    if (!target) throw notFound();

    assertCanModify(db, ctx.role, target.role);
    assertRoleAssignable(db, ctx.role, role);
    if (target.role === 'owner' && role !== 'owner') assertNotLastOwner(db, ctx.orgId, params.userId);

    db.prepare(`UPDATE memberships SET role = ?, perm_version = perm_version + 1 WHERE id = ?`).run(role, target.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.role_update', targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { userId: params.userId, role });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'member.suspend', targetType: 'membership', targetId: params.userId }, () =>
      assertCan(db, ctx, 'user:remove')
    );

    const target = membershipRow(db, ctx.orgId, params.userId);
    if (!target || target.status !== 'active') throw notFound();

    assertCanModify(db, ctx.role, target.role);
    if (target.role === 'owner') assertNotLastOwner(db, ctx.orgId, params.userId);

    db.prepare(`UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1 WHERE id = ?`).run(target.id);
    endActiveSessions(db, { orgId: ctx.orgId, userId: params.userId, reason: 'user_suspended' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.suspend', targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { userId: params.userId, status: 'suspended' });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'member.reinstate', targetType: 'membership', targetId: params.userId }, () =>
      assertCan(db, ctx, 'user:remove')
    );

    const target = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'suspended'`).get(ctx.orgId, params.userId);
    if (!target) throw notFound();

    db.prepare(`UPDATE memberships SET status = 'active', perm_version = perm_version + 1 WHERE id = ?`).run(target.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.reinstate', targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { userId: params.userId, status: 'active' });
  });

  router.delete('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'member.remove', targetType: 'membership', targetId: params.userId }, () =>
      assertCan(db, ctx, 'user:remove')
    );

    const target = membershipRow(db, ctx.orgId, params.userId);
    if (!target || target.status === 'removed') throw notFound();

    assertCanModify(db, ctx.role, target.role);
    if (target.role === 'owner') assertNotLastOwner(db, ctx.orgId, params.userId);

    db.prepare(`UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE id = ?`).run(target.id);
    endActiveSessions(db, { orgId: ctx.orgId, userId: params.userId, reason: 'membership_removed' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.remove', targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { userId: params.userId, status: 'removed' });
  });

  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, params, res) => {
    if (params.userId !== ctx.userId) {
      await auditDenials(db, ctx, { action: 'user.effective', targetType: 'membership', targetId: params.userId }, () => assertCan(db, ctx, 'user:read'));
    }
    const membership = membershipRow(db, ctx.orgId, params.userId);
    if (!membership) throw notFound();

    const { role, permissions } = resolve(db, { userId: params.userId, orgId: ctx.orgId });
    send(res, 200, { role, permissions });
  });

  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'audit.read' }, () => assertCan(db, ctx, 'audit:read'));
    const { limit, offset } = parsePaging(ctx.query);

    const events = db.prepare(`SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`).all(ctx.orgId, limit, offset);
    send(res, 200, { events });
  });
}
