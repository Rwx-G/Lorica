<script lang="ts">
  import { currentPath, navigate } from '../lib/router';
  import { api } from '../lib/api';
  import { auth } from '../lib/auth';

  type NavItem = { path: string; label: string; icon: string } | { section: string };

  const navItems: NavItem[] = [
    { path: '/', label: 'Overview', icon: 'grid' },
    { section: 'Infrastructure' },
    { path: '/backends', label: 'Backends', icon: 'server' },
    { path: '/certificates', label: 'Certificates', icon: 'lock' },
    { path: '/routes', label: 'Routes', icon: 'route' },
    { section: 'Security' },
    { path: '/security', label: 'Security', icon: 'shield' },
    { path: '/probes', label: 'Probes', icon: 'radio' },
    { section: 'Monitoring' },
    { path: '/sla', label: 'SLA', icon: 'activity' },
    { path: '/logs', label: 'Logs', icon: 'list' },
    { path: '/loadtest', label: 'Load Test', icon: 'zap' },
    { section: 'System' },
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
    <img src="/logo.png" alt="Lorica" class="sidebar-logo" />
    <span class="sidebar-title">Lorica</span>
  </div>

  <ul class="nav-list">
    {#each navItems as item}
      {#if 'section' in item}
        <li class="nav-section">{item.section}</li>
      {:else}
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
      {/if}
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
      shield: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
      activity: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
      radio: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>',
      zap: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
      settings: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
      logout: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    };
    return icons[name] ?? '';
  }
</script>

<style>
  .sidebar {
    width: 230px;
    height: 100vh;
    position: sticky;
    top: 0;
    background: var(--color-bg-nav);
    border-right: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    overflow-y: auto;
  }

  .sidebar-header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-5) var(--space-4);
    border-bottom: 1px solid var(--color-border);
  }

  .sidebar-logo {
    width: 28px;
    height: 28px;
    object-fit: contain;
  }

  .sidebar-title {
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--color-text-heading);
    letter-spacing: -0.02em;
  }

  .nav-list {
    list-style: none;
    margin: 0;
    padding: var(--space-2) var(--space-2);
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .nav-section {
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--color-text-muted);
    padding: var(--space-4) var(--space-4) var(--space-1);
    margin-top: var(--space-2);
    list-style: none;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    padding: 0.5rem 0.75rem;
    background: none;
    border: none;
    border-left: 3px solid transparent;
    border-radius: var(--radius-md);
    color: var(--color-text-muted);
    font-size: var(--text-md);
    font-weight: 450;
    text-align: left;
    transition: background-color var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
    cursor: pointer;
  }

  .nav-item:hover {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  .nav-item:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: -2px;
  }

  .nav-item.active {
    background: var(--color-primary-subtle);
    color: var(--color-primary);
    border-left-color: var(--color-primary);
    font-weight: 600;
  }

  .nav-icon {
    display: flex;
    align-items: center;
    flex-shrink: 0;
    opacity: 0.7;
  }

  .nav-item.active .nav-icon,
  .nav-item:hover .nav-icon {
    opacity: 1;
  }

  .sidebar-footer {
    border-top: 1px solid var(--color-border);
    padding: var(--space-2);
  }

  .logout-btn:hover {
    color: var(--color-red);
  }
</style>
