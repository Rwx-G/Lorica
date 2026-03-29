<script lang="ts">
  import { auth, type AuthState } from './lib/auth';
  import Login from './routes/Login.svelte';
  import PasswordChange from './routes/PasswordChange.svelte';
  import Dashboard from './routes/Dashboard.svelte';

  let state: AuthState = $state({ status: 'unauthenticated' });

  auth.subscribe((v) => {
    state = v;
  });
</script>

{#if state.status === 'unauthenticated'}
  <Login />
{:else if state.status === 'must_change_password'}
  <PasswordChange />
{:else}
  <Dashboard />
{/if}
