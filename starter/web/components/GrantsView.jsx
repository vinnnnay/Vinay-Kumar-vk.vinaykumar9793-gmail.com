import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

function GrantForm({ orgId, permissionKeys, onCreated, onCancel }) {
  const [userId, setUserId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [selected, setSelected] = useState(() => new Set());
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.listMembers(orgId).then((r) => setMembers(r.members)).catch(() => {});
    api.listDevices(orgId).then((r) => setDevices(r.devices)).catch(() => {});
  }, [orgId]);

  function toggle(key) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }

  async function submit(e) {
    e.preventDefault();
    if (!userId || selected.size === 0) {
      setError('Choose a user and at least one permission.');
      return;
    }
    try {
      const grant = await api.createGrant(orgId, {
        userId,
        deviceId: deviceId || null,
        effect,
        permissions: [...selected],
      });
      onCreated(grant);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <form className="grant-form" onSubmit={submit}>
      <select data-testid="grant-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
        <option value="">Select user…</option>
        {members.map((m) => (
          <option key={m.userId} value={m.userId}>
            {m.name}
          </option>
        ))}
      </select>
      <select data-testid="grant-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
        <option value="">Org-wide</option>
        {devices.map((d) => (
          <option key={d.id} value={d.id}>
            {d.name}
          </option>
        ))}
      </select>
      <select data-testid="grant-effect" value={effect} onChange={(e) => setEffect(e.target.value)}>
        <option value="allow">allow</option>
        <option value="deny">deny</option>
      </select>
      <fieldset className="grant-permissions">
        {permissionKeys.map((key) => (
          <label key={key}>
            <input type="checkbox" data-permission-key={key} checked={selected.has(key)} onChange={() => toggle(key)} />
            {key}
          </label>
        ))}
      </fieldset>
      <div className="grant-form-actions">
        <button type="submit" data-testid="grant-submit">
          Create grant
        </button>
        <button type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}

export function GrantsView({ orgId, permissions }) {
  const [grants, setGrants] = useState(null);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(false);

  function reload() {
    setGrants(null);
    api.listGrants(orgId).then((r) => setGrants(r.grants)).catch((err) => setError(err.message));
  }

  useEffect(reload, [orgId]);

  const canCreate = permissions['grant:create']?.effect === 'allow';
  const canRevoke = permissions['grant:revoke']?.effect === 'allow';
  const permissionKeys = Object.keys(permissions);

  if (error) return <p role="alert">{error}</p>;

  return (
    <div>
      {canCreate && !showForm && (
        <button type="button" data-testid="new-grant" onClick={() => setShowForm(true)}>
          New grant
        </button>
      )}
      {canCreate && showForm && (
        <GrantForm
          orgId={orgId}
          permissionKeys={permissionKeys}
          onCancel={() => setShowForm(false)}
          onCreated={() => {
            setShowForm(false);
            reload();
          }}
        />
      )}

      {grants === null ? (
        <p>Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Device</th>
              <th>Effect</th>
              <th>Permissions</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-effect={g.effect}>
                <td>{g.userId}</td>
                <td>{g.deviceId ?? 'org-wide'}</td>
                <td>{g.effect}</td>
                <td>{g.permissions.join(', ')}</td>
                <td>
                  {canRevoke && (
                    <button
                      type="button"
                      data-testid="revoke-grant"
                      onClick={() => api.revokeGrant(orgId, g.id).then(reload).catch((err) => setError(err.message))}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
