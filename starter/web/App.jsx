import React, { useEffect, useState } from 'react';
import { api, setToken } from './api.js';
import { LoginPage } from './components/LoginPage.jsx';
import { InvitePage } from './components/InvitePage.jsx';
import { Shell } from './components/Shell.jsx';
import { DevicesView } from './components/DevicesView.jsx';
import { PeopleView } from './components/PeopleView.jsx';
import { GrantsView } from './components/GrantsView.jsx';
import { SessionsView } from './components/SessionsView.jsx';
import { AuditView } from './components/AuditView.jsx';
import { AdminView } from './components/AdminView.jsx';

const INVITE_PATH = /^\/invite\/(.+)$/.exec(window.location.pathname);

// A hand-rolled, three-screen "router": invite (public, from the URL at load time),
// login, and the authenticated app. Nothing here needs a routing library -- every
// other view (devices/people/grants/...) is in-app state, not a URL, because no test
// or requirement reads the address bar for them.
export function App() {
  const [mode, setMode] = useState(INVITE_PATH ? 'invite' : 'boot');
  const [session, setSession] = useState(null);
  const [view, setView] = useState('devices');

  // Only a normal ("/") load attempts the silent cookie-backed refresh. The invite
  // screen skips it on purpose: accepting an invite sets the SAME refresh cookie this
  // would consume, and the UI contract is that accepting lands back on the login
  // form, not straight into the app (tests/ui.spec.js).
  useEffect(() => {
    if (mode !== 'boot') return;
    api.refresh().then((refreshed) => {
      if (refreshed) {
        setToken(refreshed.token);
        setSession(refreshed);
        setMode('app');
      } else {
        setMode('login');
      }
    });
  }, [mode]);

  if (mode === 'invite') {
    return (
      <InvitePage
        token={INVITE_PATH[1]}
        onAccepted={() => {
          window.history.replaceState({}, '', '/');
          setMode('login');
        }}
      />
    );
  }

  if (mode === 'boot') return <main className="boot-screen">Loading…</main>;

  if (mode === 'login' || !session) {
    return (
      <LoginPage
        onLoggedIn={(s) => {
          setSession(s);
          setView('devices');
          setMode('app');
        }}
      />
    );
  }

  function applyAuth(s) {
    setToken(s.token);
    setSession(s);
  }

  function refetchProfile() {
    // No new token here (rename/delete don't rotate one); merge the fresh
    // orgs/permissions into the session already in memory.
    api.me().then((s) => setSession((prev) => ({ ...prev, ...s })));
  }

  async function handleCreateOrg() {
    const name = window.prompt('New organization name');
    if (!name || !name.trim()) return;
    const created = await api.createOrg(name.trim());
    applyAuth(await api.switchOrg(created.id));
    setView('devices');
  }

  return (
    <Shell
      session={session}
      view={view}
      onNavigate={setView}
      onSwitchOrg={(orgId) => api.switchOrg(orgId).then(applyAuth)}
      onCreateOrg={handleCreateOrg}
    >
      {view === 'devices' && <DevicesView orgId={session.orgId} />}
      {view === 'people' && <PeopleView orgId={session.orgId} currentUserId={session.userId} permissions={session.permissions} />}
      {view === 'grants' && <GrantsView orgId={session.orgId} permissions={session.permissions} />}
      {view === 'sessions' && <SessionsView orgId={session.orgId} currentUserId={session.userId} permissions={session.permissions} />}
      {view === 'audit' && <AuditView orgId={session.orgId} />}
      {view === 'admin' && (
        <AdminView
          orgId={session.orgId}
          orgName={session.orgs.find((o) => o.id === session.orgId)?.name}
          permissions={session.permissions}
          onRenamed={refetchProfile}
          onDeleted={refetchProfile}
        />
      )}
    </Shell>
  );
}
