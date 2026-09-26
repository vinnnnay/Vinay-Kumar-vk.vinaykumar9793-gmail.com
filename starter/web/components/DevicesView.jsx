import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

const SESSION_MODES = [
  { mode: 'view', permission: 'device:view', label: 'View' },
  { mode: 'control', permission: 'device:control', label: 'Control' },
  { mode: 'terminal', permission: 'device:terminal', label: 'Terminal' },
];

// Every device row carries the caller's already-resolved permission set (§8) -- this
// component never asks "am I an operator/owner," only "does this row's permissions
// object say allow." Presence is keyed to exactly the one permission named in
// data-permission, not a compound check: §9's "session:start AND the mode permission"
// is the API's rule for actually STARTING a session, and a click can still 403 on
// session:start even when the button is showing. See DECISIONS.md.
export function DevicesView({ orgId, onStartSession }) {
  const [devices, setDevices] = useState(null);
  const [error, setError] = useState(null);

  function reload() {
    setDevices(null);
    api.listDevices(orgId).then((r) => setDevices(r.devices)).catch((err) => setError(err.message));
  }

  useEffect(reload, [orgId]);

  if (error) return <p role="alert">{error}</p>;
  if (devices === null) return <p>Loading…</p>;
  if (devices.length === 0) return <p data-testid="devices-empty">No devices in this organization yet.</p>;

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Kind</th>
          <th>Status</th>
          <th>Sessions</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => (
          <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
            <td>{d.name}</td>
            <td>{d.kind}</td>
            <td>{d.online ? 'online' : 'offline'}</td>
            <td className="device-actions">
              {SESSION_MODES.filter(({ permission }) => d.permissions[permission]?.effect === 'allow').map(({ mode, permission, label }) => (
                <button
                  key={mode}
                  type="button"
                  data-permission={permission}
                  data-state="unlocked"
                  onClick={async () => {
                    try {
                      await api.startSession(orgId, d.id, mode);
                      onStartSession?.();
                    } catch (err) {
                      // session:start can still be the missing half even though this
                      // button showed -- §9's compound check, surfaced here instead of
                      // hidden as a silently-failed click.
                      setError(err.message);
                    }
                  }}
                >
                  {label}
                </button>
              ))}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
