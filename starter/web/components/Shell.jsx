import React from 'react';

// The nav shape itself is permission-driven (README.md "the console contract"): no
// role-to-permission table lives here, only a fixed list of WHICH resolved permission
// gates WHICH card. The allow/deny decision itself always comes from `permissions`,
// as resolved by the server.
const NAV_ITEMS = [
  { key: 'devices', label: 'Devices', permission: 'device:list' },
  { key: 'people', label: 'People', permission: 'user:read' },
  { key: 'grants', label: 'Grants', permission: 'user:read' },
  { key: 'sessions', label: 'Sessions', permission: 'session:view' },
  { key: 'audit', label: 'Audit', permission: 'audit:read' },
];

function allowed(permissions, key) {
  return permissions[key]?.effect === 'allow';
}

export function Shell({ session, view, onNavigate, onSwitchOrg, onCreateOrg, children }) {
  const activeOrg = session.orgs.find((o) => o.id === session.orgId);
  const showAdmin = allowed(session.permissions, 'org:update') || allowed(session.permissions, 'org:delete');

  return (
    <div
      data-testid="app-shell"
      data-org-id={session.orgId}
      data-org-theme={activeOrg?.theme}
      className={`app-shell theme-${activeOrg?.theme}`}
    >
      <header className="shell-header">
        <div className="org-switcher">
          {session.orgs.map((o) => (
            <button
              key={o.id}
              type="button"
              data-testid="org-option"
              data-org-id={o.id}
              className={o.id === session.orgId ? 'org-option active' : 'org-option'}
              onClick={() => o.id !== session.orgId && onSwitchOrg(o.id)}
            >
              {o.name}
            </button>
          ))}
          <button type="button" data-testid="create-org" onClick={onCreateOrg}>
            + New org
          </button>
        </div>
        <div className="whoami">
          Signed in as <strong data-testid="active-role">{session.role}</strong>
        </div>
      </header>

      <nav className="shell-nav">
        {NAV_ITEMS.filter((item) => allowed(session.permissions, item.permission)).map((item) => (
          <button
            key={item.key}
            type="button"
            data-testid={`nav-${item.key}`}
            className={view === item.key ? 'active' : ''}
            onClick={() => onNavigate(item.key)}
          >
            {item.label}
          </button>
        ))}
        {showAdmin && (
          <button type="button" data-testid="nav-admin" className={view === 'admin' ? 'active' : ''} onClick={() => onNavigate('admin')}>
            Admin
          </button>
        )}
      </nav>

      <main className="shell-main">{children}</main>
    </div>
  );
}
