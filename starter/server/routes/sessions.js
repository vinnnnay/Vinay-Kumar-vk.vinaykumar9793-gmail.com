// Sessions: the compound start check (D9 in the session sense: session:start AND the
// mode permission), exclusivity via the database's own unique index (D10), and
// grandfathering -- a session's authority is a snapshot, taken once, at start.

import { newId, nowIso } from '../db.js';
import { send, badRequest, notFound, deviceBusy } from '../http.js';
import { assertCan, assertCanStartSession } from '../permissions.js';
import { snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';

export function registerSessionRoutes(router, { db }) {
  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    const { deviceId, mode } = ctx.body;
    if (typeof deviceId !== 'string') throw badRequest('deviceId is required');
    if (!db.prepare('SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId)) {
      throw notFound();
    }

    await auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: deviceId }, () =>
      assertCanStartSession(db, ctx, mode, deviceId)
    );

    const id = newId('ses');
    const startedAt = nowIso();
    const expiresAt = sessionExpiry(db, ctx.orgId);
    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

    try {
      db.prepare(
        `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
      ).run(id, ctx.orgId, ctx.userId, deviceId, mode, authorizedBy, startedAt, expiresAt);
    } catch (err) {
      // D10: one_exclusive_session_per_device is the database refusing a second
      // concurrent control/terminal session -- view is deliberately excluded from it.
      // better-sqlite3 names the column the index is built on, not the index itself.
      if (err.code !== 'SQLITE_CONSTRAINT_UNIQUE' || !String(err.message).includes('sessions.device_id')) throw err;
      const holder = db
        .prepare(`SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')`)
        .get(deviceId);
      throw deviceBusy(holder ? `device already has an exclusive session: ${holder.id}` : undefined);
    }

    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session.start', targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId });

    send(res, 201, {
      id, org_id: ctx.orgId, user_id: ctx.userId, device_id: deviceId, mode, state: 'active',
      end_reason: null, authorized_by: authorizedBy, started_at: startedAt, expires_at: expiresAt, ended_at: null,
    });
  });

  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'sessions.list' }, () => assertCan(db, ctx, 'session:view'));

    const sessions = db.prepare('SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC').all(ctx.orgId);
    send(res, 200, { sessions });
  });

  // No :org segment -- the org isn't in this path, so context.js's structural
  // isolation doesn't apply here. Checked by hand against the session's own org_id.
  router.get('/v1/sessions/:id', async (ctx, params, res) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();

    if (session.user_id !== ctx.userId) {
      await auditDenials(db, ctx, { action: 'session.view', targetType: 'session', targetId: params.id }, () => assertCan(db, ctx, 'session:view'));
    }
    send(res, 200, session);
  });

  router.delete('/v1/sessions/:id', async (ctx, params, res) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(params.id);
    if (!session || session.org_id !== ctx.orgId || session.state !== 'active') throw notFound();

    const isOwner = session.user_id === ctx.userId;
    if (!isOwner) {
      await auditDenials(db, ctx, { action: 'session.terminate', targetType: 'session', targetId: params.id }, () => assertCan(db, ctx, 'session:terminate'));
    }

    db.prepare(`UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ?`).run(
      isOwner ? 'user_stopped' : 'admin_terminated',
      nowIso(),
      session.id
    );
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session.terminate', targetType: 'session', targetId: session.id, result: 'allow', requestId: ctx.requestId });

    send(res, 200, { id: session.id, status: 'ended' });
  });
}
