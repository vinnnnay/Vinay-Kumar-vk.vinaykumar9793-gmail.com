// Append-only audit writes. audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so
// this module only ever INSERTs.

import { newId } from './db.js';
import { HttpError } from './http.js';

export function audit(db, { orgId, actorId = null, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  db.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(newId('aud'), orgId, actorId, action, targetType, targetId, result, reasonCode, requestId);
}

// Run fn(); if it refuses with a 403, record the denial before rethrowing. Only 403s are
// audited here -- a 404 (invisible) or 401 (not authenticated) never confirms the
// resource or the permission question exists, so there is nothing true to log yet.
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason,
        requestId: ctx.requestId,
      });
    }
    throw err;
  }
}
