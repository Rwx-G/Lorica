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

  onMount(async () => {
    // Check if we already have a valid session cookie (survives F5)
    const res = await api.getStatus();
    if (res.data) {
      auth.set({ status: 'authenticated' });
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
