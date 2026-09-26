import React, { useState } from 'react';
import { api, setToken } from '../api.js';

// Failure feedback is not permission-gated (README.md "The console contract"): a
// refused sign-in has to say why, on screen, and a wrong password must read the same
// as an unknown account -- the server already returns one generic message for both,
// so this component never invents a more specific one.
export function LoginPage({ onLoggedIn }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    if (!email.trim() || !password) {
      setError('Email and password are both required.');
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const session = await api.login(email.trim(), password);
      setToken(session.token);
      onLoggedIn(session);
    } catch (err) {
      setError(err.message || 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-screen">
      <form className="login-card" data-testid="login-form" onSubmit={submit}>
        <h1>RemoteOps</h1>
        <label>
          Email
          <input data-testid="login-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input
            data-testid="login-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        <button data-testid="login-submit" type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        {error && (
          <p data-testid="login-error" role="alert">
            {error}
          </p>
        )}
      </form>
    </main>
  );
}
