import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

// PERMISSIONS.md §7: a device row can show `active` in Sessions while its own action
// button is absent -- those are different questions, and this view doesn't try to
// reconcile them. "End" is offered to the session's own owner regardless of
// session:terminate (DELETE /sessions/:id allows the owner OR session:terminate).
export function SessionsView({ orgId, currentUserId, permissions }) {
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState(null);

  function reload() {
    setSessions(null);
    api.listSessions(orgId).then((r) => setSessions(r.sessions)).catch((err) => setError(err.message));
  }

  useEffect(reload, [orgId]);

  if (error) return <p role="alert">{error}</p>;
  if (sessions === null) return <p>Loading…</p>;
  if (sessions.length === 0) return <p data-testid="sessions-empty">No sessions yet.</p>;

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Device</th>
          <th>Mode</th>
          <th>State</th>
          <th>Started</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {sessions.map((s) => (
          <tr key={s.id} data-testid="session-row" data-session-id={s.id} data-state={s.state}>
            <td>{s.device_id}</td>
            <td>{s.mode}</td>
            <td>{s.state}</td>
            <td>{s.started_at}</td>
            <td>
              {s.state === 'active' && (s.user_id === currentUserId || permissions['session:terminate']?.effect === 'allow') && (
                <button
                  type="button"
                  data-testid="end-session"
                  onClick={() => api.endSession(s.id).then(reload).catch((err) => setError(err.message))}
                >
                  {s.user_id === currentUserId ? 'Stop' : 'Terminate'}
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
