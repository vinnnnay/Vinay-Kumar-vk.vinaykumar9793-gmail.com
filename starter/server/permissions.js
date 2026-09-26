// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// Reads `permissions`, `role_permissions`, `grants` and `grant_permissions` from the
// database at call time — nothing here hardcodes the documented 5-role / 19-permission
// matrix, so the personalisation overlay (an undocumented role + permission) resolves
// correctly without any special-casing.

import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

function patternMatches(pattern, permission, resource) {
  return pattern === permission || pattern === '*' || pattern === `${resource}:*`;
}

function loadCatalogue(db) {
  return db.prepare('SELECT key, resource FROM permissions').all();
}

// Everything resolve() and resolveDevices() need about the caller, loaded once:
// the membership row, the full permission catalogue, the role's baseline (or null
// when there is no baseline to compute), and the caller's currently-active grants.
function loadCallerState(db, { userId, orgId, now }) {
  const membership = db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  const catalogue = loadCatalogue(db);

  if (!membership || membership.status !== 'active') {
    return { membership, catalogue, baseline: null, grants: null };
  }

  const baseline = new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(membership.role).map((r) => r.permission)
  );

  const nowIso = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  // Half-open window (D7): starts_at <= now < expires_at. expires_at == now is expired.
  const grants = db
    .prepare(
      `SELECT g.id AS grant_id, g.device_id, g.effect, g.starts_at, g.expires_at, gp.permission AS pattern
       FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
       WHERE g.org_id = ? AND g.user_id = ? AND g.revoked_at IS NULL`
    )
    .all(orgId, userId)
    .filter((g) => (g.starts_at === null || g.starts_at <= nowIso) && (g.expires_at === null || nowIso < g.expires_at));

  return { membership, catalogue, baseline, grants };
}

// membership is missing entirely, suspended, invited or removed -> the status IS the
// reason. 'not_a_member' is the one case the docs name explicitly; the others reuse
// the membership's own status string, which is undocumented but self-describing and
// distinct from 'suspended' the way the docs distinguish it (see DECISIONS.md).
function inactiveReason(membership) {
  return membership ? membership.status : 'not_a_member';
}

function denyAll(catalogue, reason) {
  const out = {};
  for (const { key } of catalogue) out[key] = { effect: 'deny', source: null, reason };
  return out;
}

// One permission, one exact scope. deviceId is a concrete device id, or null for "no
// device in play" -- a non-device permission, or an org with no devices at all.
function resolveAtScope({ permission, resource, baseline, role, grants, deviceId }) {
  const applicable = grants.filter(
    (g) => patternMatches(g.pattern, permission, resource) && (g.device_id === null || g.device_id === deviceId)
  );

  // D1: an explicit deny always wins, regardless of scope or specificity -- checked
  // before the baseline and before any allow grant.
  const deny = applicable.find((g) => g.effect === 'deny');
  if (deny) return { effect: 'deny', source: `grant:${deny.grant_id}`, reason: 'explicit_deny' };

  if (baseline.has(permission)) return { effect: 'allow', source: `role:${role}`, reason: null };

  const allow = applicable.find((g) => g.effect === 'allow');
  if (allow) return { effect: 'allow', source: `grant:${allow.grant_id}`, reason: null };

  return { effect: 'deny', source: null, reason: 'implicit' };
}

// A device permission at ORG level is the union across every device in the org
// (PERMISSIONS.md §3). D1's deny precedence is per-scope, not global: an org-wide
// deny makes every device resolve to deny, so the union is deny too -- but a
// device-scoped deny on one device does not drag down a device-scoped (or
// baseline) allow on a different device. The union exists for nav/page gating
// ("can this user control anything at all"), never as a substitute for the
// per-device check that actually gates a row -- see DECISIONS.md.
function resolveDeviceScopedUnion({ permission, resource, baseline, role, grants, deviceIds }) {
  if (deviceIds.length === 0) return resolveAtScope({ permission, resource, baseline, role, grants, deviceId: null });

  let deny = null;
  for (const deviceId of deviceIds) {
    const result = resolveAtScope({ permission, resource, baseline, role, grants, deviceId });
    if (result.effect === 'allow') return result;
    if (!deny) deny = result;
  }
  return deny;
}

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const { membership, catalogue, baseline, grants } = loadCallerState(db, { userId, orgId, now });

  if (!membership || membership.status !== 'active') {
    return { role: membership?.role ?? null, permissions: denyAll(catalogue, inactiveReason(membership)) };
  }

  const deviceIds =
    deviceId === null
      ? db.prepare('SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL').all(orgId).map((r) => r.id)
      : null;

  const permissions = {};
  for (const { key, resource } of catalogue) {
    permissions[key] =
      deviceId !== null
        ? resolveAtScope({ permission: key, resource, baseline, role: membership.role, grants, deviceId })
        : resource === 'device'
          ? resolveDeviceScopedUnion({ permission: key, resource, baseline, role: membership.role, grants, deviceIds })
          : resolveAtScope({ permission: key, resource, baseline, role: membership.role, grants, deviceId: null });
  }
  return { role: membership.role, permissions };
}

// Batched form for list endpoints: one membership/baseline/grants load, then one pass
// per device -- never a follow-up query per row (BRIEF.md §6).
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const { membership, catalogue, baseline, grants } = loadCallerState(db, { userId, orgId, now });

  if (!membership || membership.status !== 'active') {
    const permissions = denyAll(catalogue, inactiveReason(membership));
    return { role: membership?.role ?? null, byDevice: Object.fromEntries(deviceIds.map((id) => [id, permissions])) };
  }

  const byDevice = {};
  for (const deviceId of deviceIds) {
    const permissions = {};
    for (const { key, resource } of catalogue) {
      permissions[key] = resolveAtScope({ permission: key, resource, baseline, role: membership.role, grants, deviceId });
    }
    byDevice[deviceId] = permissions;
  }
  return { role: membership.role, byDevice };
}

export function can(db, ctx, permission, deviceId = null) {
  return resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions[permission]?.effect === 'allow';
}

// resolve()'s internal reasons (implicit/explicit_deny/suspended/...) describe HOW the
// engine got its answer. The error body's `reason` is narrower, by design (PERMISSIONS.md
// §5): 'explicit_deny' and 'suspended' are worth surfacing to the caller as-is; every
// other cause -- implicit, not_a_member, invited, removed -- is just "you don't have it".
const SURFACED_REASON = new Set(['explicit_deny', 'suspended']);

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId = null) {
  const result = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions[permission];
  if (result.effect === 'allow') return result;
  throw forbidden(`missing ${permission}`, SURFACED_REASON.has(result.reason) ? result.reason : 'missing_permission');
}

// No privilege laundering: you may only grant authority you hold at that scope
// (PERMISSIONS.md D9). A wildcard pattern is checked permission-by-permission against
// what it expands to, so 'device:*' requires holding all seven device permissions.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const catalogue = loadCatalogue(db);
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

  for (const pattern of patterns) {
    const covers =
      pattern === '*'
        ? catalogue
        : pattern.endsWith(':*')
          ? catalogue.filter((p) => p.resource === pattern.slice(0, -2))
          : catalogue.filter((p) => p.key === pattern);

    for (const { key } of covers) {
      if (permissions[key]?.effect !== 'allow') {
        throw forbidden(`cannot grant ${pattern}: you do not hold ${key} at this scope`, 'missing_permission');
      }
    }
  }
}

// The compound check: session:start AND the mode permission, both on the same device.
// Checked in this order so a refusal names the actual missing half -- the two shipped
// reason strings the tests read (PERMISSIONS.md §9 / BRIEF.md §5.1).
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw badRequest(`unknown session mode: ${mode}`);

  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  if (permissions['session:start'].effect !== 'allow') {
    throw forbidden('missing session:start', 'missing_permission');
  }
  if (permissions[modePermission].effect !== 'allow') {
    throw forbidden(`missing ${modePermission}`, 'missing_device_permission');
  }
}
