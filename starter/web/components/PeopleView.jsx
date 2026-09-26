import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

const ROLES = ['owner', 'admin', 'operator', 'auditor', 'viewer'];

function InviteForm({ orgId, onCreated }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const [error, setError] = useState(null);
  const [created, setCreated] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    try {
      const invite = await api.createInvite(orgId, email, role);
      setCreated(invite);
      setEmail('');
      onCreated();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <form className="invite-form" onSubmit={submit}>
      <input data-testid="invite-form-email" type="email" placeholder="email@example.test" value={email} onChange={(e) => setEmail(e.target.value)} />
      <select data-testid="invite-form-role" value={role} onChange={(e) => setRole(e.target.value)}>
        {ROLES.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
      <button type="submit" data-testid="invite-form-submit">
        Send invite
      </button>
      {error && <p role="alert">{error}</p>}
      {created && (
        <p data-testid="invite-link-created">
          Invite link: <code>/invite/{created.inviteToken}</code>
        </p>
      )}
    </form>
  );
}

export function PeopleView({ orgId, currentUserId, permissions }) {
  const [members, setMembers] = useState(null);
  const [error, setError] = useState(null);

  function reload() {
    setMembers(null);
    api.listMembers(orgId).then((r) => setMembers(r.members)).catch((err) => setError(err.message));
  }

  useEffect(reload, [orgId]);

  const canInvite = permissions['user:invite']?.effect === 'allow';
  const canUpdateRole = permissions['user:role:update']?.effect === 'allow';
  const canRemove = permissions['user:remove']?.effect === 'allow';

  if (error) return <p role="alert">{error}</p>;

  return (
    <div>
      {canInvite && <InviteForm orgId={orgId} onCreated={reload} />}
      {members === null ? (
        <p>Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {members.map((m) => {
              const isSelf = m.userId === currentUserId;
              return (
                <tr key={m.userId} data-testid="user-row" data-user-id={m.userId}>
                  <td>{m.name}</td>
                  <td>{m.email}</td>
                  <td>
                    {canUpdateRole && !isSelf ? (
                      <select
                        data-testid="member-role"
                        value={m.role}
                        onChange={async (e) => {
                          try {
                            await api.updateMemberRole(orgId, m.userId, e.target.value);
                            reload();
                          } catch (err) {
                            setError(err.message);
                          }
                        }}
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    ) : (
                      m.role
                    )}
                  </td>
                  <td>{m.status}</td>
                  <td>
                    {canRemove && !isSelf && (
                      <>
                        {m.status === 'active' && (
                          <button data-testid="suspend-member" onClick={() => api.suspendMember(orgId, m.userId).then(reload).catch((err) => setError(err.message))}>
                            Suspend
                          </button>
                        )}
                        {m.status === 'suspended' && (
                          <button data-testid="reinstate-member" onClick={() => api.reinstateMember(orgId, m.userId).then(reload).catch((err) => setError(err.message))}>
                            Reinstate
                          </button>
                        )}
                        <button data-testid="remove-member" onClick={() => api.removeMember(orgId, m.userId).then(reload).catch((err) => setError(err.message))}>
                          Remove
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
