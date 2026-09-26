import React, { useState } from 'react';
import { api } from '../api.js';

// The Admin card itself is gated (org:update OR org:delete, in Shell.jsx). Inside it,
// each entry is gated on its own permission -- this is the one place an owner and an
// admin render the exact same card with a different entry count (ui.spec.js).
export function AdminView({ orgId, orgName, permissions, onRenamed, onDeleted }) {
  const [name, setName] = useState(orgName);
  const [error, setError] = useState(null);
  const canUpdate = permissions['org:update']?.effect === 'allow';
  const canDelete = permissions['org:delete']?.effect === 'allow';

  return (
    <div className="admin-view">
      {canUpdate && (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await api.updateOrg(orgId, { name });
              onRenamed(name);
            } catch (err) {
              setError(err.message);
            }
          }}
        >
          <label>
            Organization name
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <button type="submit" data-testid="rename-org">
            Rename
          </button>
        </form>
      )}
      {canDelete && (
        <button
          type="button"
          data-testid="delete-org"
          onClick={async () => {
            if (!window.confirm('Delete this organization? This cannot be undone.')) return;
            try {
              await api.deleteOrg(orgId);
              onDeleted();
            } catch (err) {
              setError(err.message);
            }
          }}
        >
          Delete organization
        </button>
      )}
      {error && <p role="alert">{error}</p>}
    </div>
  );
}
