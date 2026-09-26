import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

// Public: the token holder is not a member yet. The peek response carries only
// {orgName, role, email, expiresAt} -- no org id, no device or member data -- so
// there is nothing here that could leak even if this component rendered it all.
export function InvitePage({ token, onAccepted }) {
  const [invite, setInvite] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [submitError, setSubmitError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.peekInvite(token).then(setInvite).catch(() => setLoadError('This invite link is invalid or has expired.'));
  }, [token]);

  if (loadError) {
    return (
      <main className="invite-screen">
        <p data-testid="invite-error" role="alert">
          {loadError}
        </p>
      </main>
    );
  }
  if (!invite) return <main className="invite-screen">Loading…</main>;

  async function submit(e) {
    e.preventDefault();
    if (password.length < 8) {
      setSubmitError('Password must be at least 8 characters.');
      return;
    }
    setSubmitError(null);
    setBusy(true);
    try {
      await api.acceptInvite(token, name, password);
      onAccepted();
    } catch (err) {
      setSubmitError(err.message || 'Could not accept this invite.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="invite-screen">
      <form className="login-card" onSubmit={submit}>
        <h1>Join {invite.orgName}</h1>
        <p>
          You have been invited as <strong data-testid="invite-role">{invite.role}</strong>.
        </p>
        <label>
          Email
          <input data-testid="invite-email" value={invite.email} readOnly />
        </label>
        <label>
          Your name
          <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          Choose a password
          <input data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <button data-testid="invite-submit" type="submit" disabled={busy}>
          {busy ? 'Joining…' : 'Accept invite'}
        </button>
        {submitError && (
          <p data-testid="invite-submit-error" role="alert">
            {submitError}
          </p>
        )}
      </form>
    </main>
  );
}
