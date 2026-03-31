<script lang="ts">
  import { onMount } from 'svelte';
  import { auth, type AuthState } from './lib/auth';
  import { api } from './lib/api';
  import Login from './routes/Login.svelte';
  import PasswordChange from './routes/PasswordChange.svelte';
  import Dashboard from './routes/Dashboard.svelte';

  let state: AuthState = $state({ status: 'unauthenticated' });
  let checking = $state(true);

  auth.subscribe((v) => {
    state = v;
  });

  function applyTheme(t: 'dark' | 'light') {
    document.documentElement.setAttribute('data-theme', t);
  }

  async function loadTheme() {
    const res = await api.listPreferences();
    if (res.data) {
      const themePref = res.data.preferences.find(
        (p) => p.preference_key === 'theme',
      );
      if (themePref) {
        const t = themePref.value === 'always' ? 'light' : 'dark';
        applyTheme(t);
        return;
      }
    }
    // No preference saved yet - ensure light is explicit
    applyTheme('light');
  }

  onMount(async () => {
    // Check if we already have a valid session cookie (survives F5)
    const res = await api.getStatus();
    if (res.data) {
      auth.set({ status: 'authenticated' });
      // Load theme preference immediately after confirming session
      await loadTheme();
    }
    checking = false;
  });
</script>

{#if checking}
  <div class="boot-check"><p class="loading">Loading...</p></div>
{:else if state.status === 'unauthenticated'}
  <Login />
{:else if state.status === 'must_change_password'}
  <PasswordChange />
{:else}
  <Dashboard />
{/if}

<style>
  .boot-check {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
</style>
