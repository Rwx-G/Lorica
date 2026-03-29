<script lang="ts">
  import { currentPath, navigate } from '../lib/router';
  import { api } from '../lib/api';
  import { auth } from '../lib/auth';

  const navItems = [
    { path: '/', label: 'Overview', icon: 'grid' },
    { path: '/routes', label: 'Routes', icon: 'route' },
    { path: '/backends', label: 'Backends', icon: 'server' },
    { path: '/certificates', label: 'Certificates', icon: 'lock' },
    { path: '/logs', label: 'Logs', icon: 'list' },
    { path: '/system', label: 'System', icon: 'cpu' },
    { path: '/settings', label: 'Settings', icon: 'settings' },
  ];

  let path = $state('/');

  currentPath.subscribe((v) => {
    path = v;
  });

  async function handleLogout() {
    await api.logout();
    auth.set({ status: 'unauthenticated' });
  }
</script>

<nav class="sidebar">
  <div class="sidebar-header">
    <svg viewBox="0 0 32 32" fill="none" width="28" height="28">
      <path d="M16 2L4 8v8c0 7.2 5.1 13.9 12 16 6.9-2.1 12-8.8 12-16V8L16 2z" fill="#3b82f6" stroke="#2563eb" stroke-width="1"/>
      <path d="M16 6l-8 4v6c0 5.2 3.4 10 8 11.6 4.6-1.6 8-6.4 8-11.6v-6l-8-4z" fill="#60a5fa"/>
      <path d="M14 15l-2-2-1.5 1.5L14 18l6-6-1.5-1.5L14 15z" fill="white"/>
    </svg>
    <span class="sidebar-title">Lorica</span>
  </div>

  <ul class="nav-list">
    {#each navItems as item}
      <li>
        <button
          class="nav-item"
          class:active={path === item.path}
          onclick={() => navigate(item.path)}
        >
          <span class="nav-icon">{@html getIcon(item.icon)}</span>
          <span>{item.label}</span>
        </button>
      </li>
    {/each}
  </ul>

  <div class="sidebar-footer">
    <button class="nav-item logout-btn" onclick={handleLogout}>
      <span class="nav-icon">{@html getIcon('logout')}</span>
      <span>Sign out</span>
    </button>
  </div>
</nav>

<script lang="ts" module>
  function getIcon(name: string): string {
    const icons: Record<string, string> = {
      grid: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>',
      route: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/></svg>',
      server: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
      lock: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
      list: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
      cpu: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>',
      settings: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
      logout: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    };
    return icons[name] ?? '';
  }
</script>

<style>
  .sidebar {
    width: 220px;
    min-height: 100vh;
    background: var(--color-bg-nav);
    border-right: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }

  .sidebar-header {
    display: flex;
    align-items: center;
    gap: 0.625rem;
    padding: 1.25rem 1rem;
    border-bottom: 1px solid var(--color-border);
  }

  .sidebar-title {
    font-size: 1.125rem;
    font-weight: 700;
    color: var(--color-text-heading);
  }

  .nav-list {
    list-style: none;
    margin: 0;
    padding: 0.5rem 0;
    flex: 1;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 0.625rem;
    width: 100%;
    padding: 0.5rem 1rem;
    background: none;
    border: none;
    color: var(--color-text-muted);
    font-size: 0.875rem;
    text-align: left;
    transition: background-color 0.15s, color 0.15s;
    cursor: pointer;
  }

  .nav-item:hover {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  .nav-item.active {
    background: var(--color-bg-hover);
    color: var(--color-primary);
  }

  .nav-icon {
    display: flex;
    align-items: center;
    flex-shrink: 0;
  }

  .sidebar-footer {
    border-top: 1px solid var(--color-border);
    padding: 0.5rem 0;
  }

  .logout-btn:hover {
    color: var(--color-red);
  }
</style>
