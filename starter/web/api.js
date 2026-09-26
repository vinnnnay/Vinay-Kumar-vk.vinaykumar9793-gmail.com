// A thin fetch wrapper. The access token lives in a module-level variable -- memory
// only, never localStorage/sessionStorage (D13) -- so each tab/page load gets its own,
// and a reload has nothing to read until /auth/refresh re-derives one from the
// httpOnly cookie the server already holds.

const BASE = '/v1';

let accessToken = null;
export const getToken = () => accessToken;
export const setToken = (t) => { accessToken = t; };

async function raw(method, path, body) {
  const headers = {};
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;
  if (body !== undefined) headers['content-type'] = 'application/json';

  const res = await fetch(BASE + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  return { res, json };
}

let refreshInFlight = null;
function refresh() {
  if (!refreshInFlight) {
    refreshInFlight = raw('POST', '/auth/refresh')
      .then(({ res, json }) => {
        if (!res.ok) return null;
        setToken(json.token);
        return json;
      })
      .catch(() => null)
      .finally(() => { refreshInFlight = null; });
  }
  return refreshInFlight;
}

// One retry through /auth/refresh on a stale/missing access token -- covers both a
// role/grant change that just bumped perm_version and an access token that expired
// mid-session. A second failure is a real auth failure, not retried again.
async function request(method, path, body) {
  let { res, json } = await raw(method, path, body);

  if (res.status === 401 && (json?.error?.code === 'TOKEN_STALE' || json?.error?.code === 'UNAUTHENTICATED')) {
    const refreshed = await refresh();
    if (refreshed) ({ res, json } = await raw(method, path, body));
  }

  if (!res.ok) {
    const err = new Error(json?.error?.message ?? 'request failed');
    err.status = res.status;
    err.code = json?.error?.code ?? null;
    err.reason = json?.error?.reason ?? null;
    throw err;
  }
  return json;
}

export const api = {
  refresh,
  login: (email, password) => request('POST', '/auth/login', { email, password }),
  switchOrg: (orgId) => request('POST', '/auth/token', { orgId }),
  me: () => request('GET', '/auth/me'),

  listOrgs: () => request('GET', '/orgs'),
  createOrg: (name) => request('POST', '/orgs', { name }),
  updateOrg: (orgId, patch) => request('PATCH', `/orgs/${orgId}`, patch),
  deleteOrg: (orgId) => request('DELETE', `/orgs/${orgId}`),

  listMembers: (orgId) => request('GET', `/orgs/${orgId}/members`),
  updateMemberRole: (orgId, userId, role) => request('PATCH', `/orgs/${orgId}/members/${userId}`, { role }),
  suspendMember: (orgId, userId) => request('POST', `/orgs/${orgId}/members/${userId}/suspend`),
  reinstateMember: (orgId, userId) => request('DELETE', `/orgs/${orgId}/members/${userId}/suspend`),
  removeMember: (orgId, userId) => request('DELETE', `/orgs/${orgId}/members/${userId}`),
  leaveOrg: (orgId) => request('DELETE', `/orgs/${orgId}/members/me`),
  effectivePermissions: (orgId, userId) => request('GET', `/orgs/${orgId}/users/${userId}/effective`),

  listInvites: (orgId) => request('GET', `/orgs/${orgId}/invites`),
  createInvite: (orgId, email, role) => request('POST', `/orgs/${orgId}/invites`, { email, role }),
  revokeInvite: (orgId, id) => request('DELETE', `/orgs/${orgId}/invites/${id}`),
  peekInvite: (token) => request('GET', `/invites/${token}`),
  acceptInvite: (token, name, password) => request('POST', `/invites/${token}/accept`, { name, password }),

  listDevices: (orgId) => request('GET', `/orgs/${orgId}/devices`),
  createDevice: (orgId, name, kind) => request('POST', `/orgs/${orgId}/devices`, { name, kind }),
  updateDevice: (orgId, id, patch) => request('PATCH', `/orgs/${orgId}/devices/${id}`, patch),
  decommissionDevice: (orgId, id) => request('DELETE', `/orgs/${orgId}/devices/${id}`),
  transferDevice: (orgId, id, targetOrgId) => request('POST', `/orgs/${orgId}/devices/${id}/transfer`, { targetOrgId }),

  listGrants: (orgId) => request('GET', `/orgs/${orgId}/grants`),
  createGrant: (orgId, body) => request('POST', `/orgs/${orgId}/grants`, body),
  revokeGrant: (orgId, id) => request('DELETE', `/orgs/${orgId}/grants/${id}`),

  startSession: (orgId, deviceId, mode) => request('POST', `/orgs/${orgId}/sessions`, { deviceId, mode }),
  listSessions: (orgId) => request('GET', `/orgs/${orgId}/sessions`),
  endSession: (id) => request('DELETE', `/sessions/${id}`),

  listAudit: (orgId, params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request('GET', `/orgs/${orgId}/audit${qs ? `?${qs}` : ''}`);
  },
};
