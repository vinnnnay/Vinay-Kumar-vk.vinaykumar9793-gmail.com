// Devices and grants. device:view decides row INCLUSION in the list (§2), never a
// redacted row, and the device row carries the caller's whole resolved permission set
// so the console never issues a follow-up request per row (§8).

import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, forbidden, grantExpired, normalizeTs } from '../http.js';
import { assertCan, assertAllowed, assertMayGrant, resolve, resolveDevices } from '../permissions.js';
import { endActiveSessions } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';

const DEVICE_KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

function deviceRow(db, orgId, deviceId) {
  return db.prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, orgId);
}

export function registerDeviceRoutes(router, { db }) {
  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'devices.list' }, () => assertCan(db, ctx, 'device:list'));

    const rows = db.prepare('SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name').all(ctx.orgId);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: rows.map((d) => d.id) });

    // device:view gates inclusion, not redaction: a denied row is not in the response.
    const devices = rows
      .filter((d) => byDevice[d.id]['device:view'].effect === 'allow')
      .map((d) => ({ id: d.id, name: d.name, kind: d.kind, online: !!d.online, permissions: byDevice[d.id] }));

    send(res, 200, { devices });
  });

  router.get('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    const device = deviceRow(db, ctx.orgId, params.id);
    if (!device) throw notFound();

    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: params.id });
    await auditDenials(db, ctx, { action: 'device.view', targetType: 'device', targetId: params.id }, () => assertAllowed('device:view', permissions));

    send(res, 200, { id: device.id, name: device.name, kind: device.kind, online: !!device.online, permissions });
  });

  router.post('/v1/orgs/:org/devices', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'device.provision' }, () => assertCan(db, ctx, 'device:provision'));

    const name = typeof ctx.body.name === 'string' ? ctx.body.name.trim() : '';
    if (!name) throw badRequest('name is required');
    if (!DEVICE_KINDS.includes(ctx.body.kind)) throw badRequest(`kind must be one of ${DEVICE_KINDS.join(', ')}`);

    const id = newId('dev');
    db.prepare('INSERT INTO devices (id, org_id, name, kind) VALUES (?, ?, ?, ?)').run(id, ctx.orgId, name, ctx.body.kind);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.provision', targetType: 'device', targetId: id, result: 'allow', requestId: ctx.requestId });

    send(res, 201, { id, name, kind: ctx.body.kind, online: false });
  });

  router.patch('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    const device = deviceRow(db, ctx.orgId, params.id);
    if (!device) throw notFound();

    await auditDenials(db, ctx, { action: 'device.update', targetType: 'device', targetId: params.id }, () => assertCan(db, ctx, 'device:update'));

    const fields = [];
    const values = [];
    if (typeof ctx.body.name === 'string' && ctx.body.name.trim()) { fields.push('name = ?'); values.push(ctx.body.name.trim()); }
    if (typeof ctx.body.online === 'boolean') { fields.push('online = ?'); values.push(ctx.body.online ? 1 : 0); }
    if (fields.length) db.prepare(`UPDATE devices SET ${fields.join(', ')} WHERE id = ?`).run(...values, device.id);

    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.update', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });

    const updated = db.prepare('SELECT * FROM devices WHERE id = ?').get(device.id);
    send(res, 200, { id: updated.id, name: updated.name, kind: updated.kind, online: !!updated.online });
  });

  router.delete('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    const device = deviceRow(db, ctx.orgId, params.id);
    if (!device) throw notFound();

    await auditDenials(db, ctx, { action: 'device.decommission', targetType: 'device', targetId: params.id }, () => assertCan(db, ctx, 'device:provision'));

    db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), device.id);
    endActiveSessions(db, { orgId: ctx.orgId, deviceId: device.id, reason: 'device_transferred' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.decommission', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { id: device.id, status: 'decommissioned' });
  });

  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, params, res) => {
    const device = deviceRow(db, ctx.orgId, params.id);
    if (!device) throw notFound();

    await auditDenials(db, ctx, { action: 'device.transfer', targetType: 'device', targetId: params.id }, () => assertCan(db, ctx, 'device:provision'));

    const targetOrgId = ctx.body.targetOrgId;
    if (typeof targetOrgId !== 'string') throw badRequest('targetOrgId is required');
    const targetOrg = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(targetOrgId);
    if (!targetOrg) throw notFound();

    // device:provision is required in BOTH orgs (BRIEF.md §5.1) -- the destination
    // check is a manual resolve() against that org, since ctx is scoped to the source.
    const destination = resolve(db, { userId: ctx.userId, orgId: targetOrgId }).permissions['device:provision'];
    if (destination.effect !== 'allow') throw forbidden('missing device:provision in the destination org', 'missing_permission');

    db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, device.id);
    endActiveSessions(db, { orgId: ctx.orgId, deviceId: device.id, reason: 'device_transferred' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.transfer', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { id: device.id, orgId: targetOrgId, status: 'transferred' });
  });

  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'grant.create' }, () => assertCan(db, ctx, 'grant:create'));

    const { userId, deviceId = null, effect, permissions, startsAt = null, expiresAt = null } = ctx.body;

    if (!Array.isArray(permissions) || permissions.length === 0) throw badRequest('permissions must be a non-empty array');
    const validPatterns = new Set(db.prepare('SELECT pattern FROM permission_patterns').all().map((r) => r.pattern));
    for (const p of permissions) {
      if (!validPatterns.has(p)) throw badRequest(`unknown permission: ${p}`, 'unknown_permission');
    }
    if (effect !== 'allow' && effect !== 'deny') throw badRequest('effect must be allow or deny');
    if (typeof userId !== 'string') throw badRequest('userId is required');
    if (userId === ctx.userId) throw forbidden('cannot grant a permission to yourself', 'no_self_grant');

    if (deviceId !== null && !deviceRow(db, ctx.orgId, deviceId)) throw notFound();
    const target = db.prepare(`SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`).get(ctx.orgId, userId);
    if (!target) throw notFound();

    const startsIso = startsAt === null ? null : normalizeTs(startsAt, 'startsAt');
    const expiresIso = expiresAt === null ? null : normalizeTs(expiresAt, 'expiresAt');
    if (expiresIso !== null && expiresIso <= nowIso()) throw grantExpired();

    // D9: no laundering. The caller must hold every permission being granted, at the
    // same scope (device or org-wide) the grant itself will apply at.
    assertMayGrant(db, ctx, permissions, deviceId);

    const id = newId('grt');
    db.prepare(
      `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, ctx.orgId, userId, deviceId, effect, startsIso, expiresIso, ctx.userId);
    const insertPermission = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
    for (const p of permissions) insertPermission.run(id, p);

    bumpPermVersion(db, { orgId: ctx.orgId, userId });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.create', targetType: 'grant', targetId: id, result: 'allow', requestId: ctx.requestId });

    send(res, 201, { id, userId, deviceId, effect, permissions, startsAt: startsIso, expiresAt: expiresIso });
  });

  router.get('/v1/orgs/:org/grants', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'grants.list' }, () => assertCan(db, ctx, 'user:read'));

    const userId = ctx.query.get('userId');
    const rows = db
      .prepare(
        `SELECT id, user_id AS userId, device_id AS deviceId, effect, starts_at AS startsAt, expires_at AS expiresAt, created_by AS createdBy
           FROM grants
          WHERE org_id = @orgId AND (@userId IS NULL OR user_id = @userId) AND revoked_at IS NULL
          ORDER BY created_at DESC`
      )
      .all({ orgId: ctx.orgId, userId });

    const permissionsFor = db.prepare('SELECT permission FROM grant_permissions WHERE grant_id = ?');
    const grants = rows.map((g) => ({ ...g, permissions: permissionsFor.all(g.id).map((p) => p.permission) }));
    send(res, 200, { grants });
  });

  router.delete('/v1/orgs/:org/grants/:id', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: params.id }, () => assertCan(db, ctx, 'grant:revoke'));

    const grant = db.prepare('SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(params.id, ctx.orgId);
    if (!grant) throw notFound();

    db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), grant.id);
    bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: grant.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { id: grant.id, status: 'revoked' });
  });
}
