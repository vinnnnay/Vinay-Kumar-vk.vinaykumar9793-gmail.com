import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

export function AuditView({ orgId }) {
  const [events, setEvents] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setEvents(null);
    api.listAudit(orgId, { limit: 100 }).then((r) => setEvents(r.events)).catch((err) => setError(err.message));
  }, [orgId]);

  if (error) return <p role="alert">{error}</p>;
  if (events === null) return <p>Loading…</p>;
  if (events.length === 0) return <p data-testid="audit-empty">No audit events yet.</p>;

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>When</th>
          <th>Action</th>
          <th>Target</th>
          <th>Result</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.id} data-testid="audit-row" data-result={e.result}>
            <td>{e.at}</td>
            <td>{e.action}</td>
            <td>{e.target_type ? `${e.target_type}:${e.target_id}` : '—'}</td>
            <td>{e.result}</td>
            <td>{e.reason_code ?? '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
