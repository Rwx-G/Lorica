<script lang="ts">
  import { api } from '../lib/api';
  import { auth } from '../lib/auth';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let loading = $state(false);

  async function handleSubmit(e: Event) {
    e.preventDefault();
    error = '';
    loading = true;

    const res = await api.login({ username, password });

    if (res.error) {
      error = res.error.message;
      loading = false;
      return;
    }

    if (res.data?.must_change_password) {
      auth.set({ status: 'must_change_password' });
    } else {
      auth.set({ status: 'authenticated' });
    }

    loading = false;
  }
</script>

<div class="login-container">
  <div class="login-card">
    <div class="login-logo">
      <svg viewBox="0 0 32 32" fill="none" width="48" height="48">
        <path d="M16 2L4 8v8c0 7.2 5.1 13.9 12 16 6.9-2.1 12-8.8 12-16V8L16 2z" fill="#3b82f6" stroke="#2563eb" stroke-width="1"/>
        <path d="M16 6l-8 4v6c0 5.2 3.4 10 8 11.6 4.6-1.6 8-6.4 8-11.6v-6l-8-4z" fill="#60a5fa"/>
        <path d="M14 15l-2-2-1.5 1.5L14 18l6-6-1.5-1.5L14 15z" fill="white"/>
      </svg>
      <h1>Lorica</h1>
    </div>
    <p class="login-subtitle">Sign in to your dashboard</p>

    <form onsubmit={handleSubmit}>
      <div class="field">
        <label for="username">Username</label>
        <input
          id="username"
          type="text"
          bind:value={username}
          required
          autocomplete="username"
          placeholder="admin"
        />
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          required
          autocomplete="current-password"
        />
      </div>

      {#if error}
        <div class="error-msg">{error}</div>
      {/if}

      <button type="submit" class="btn btn-primary btn-full" disabled={loading}>
        {loading ? 'Signing in...' : 'Sign in'}
      </button>
    </form>
  </div>
</div>

<style>
  .login-container {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    width: 100%;
    padding: 1rem;
  }

  .login-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 2rem;
    width: 100%;
    max-width: 380px;
  }

  .login-logo {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    justify-content: center;
    margin-bottom: 0.25rem;
  }

  .login-logo h1 {
    margin: 0;
    font-size: 1.75rem;
  }

  .login-subtitle {
    text-align: center;
    color: var(--color-text-muted);
    margin-bottom: 1.5rem;
  }

  .field {
    margin-bottom: 1rem;
  }

  .field label {
    display: block;
    font-size: 0.875rem;
    font-weight: 500;
    margin-bottom: 0.375rem;
    color: var(--color-text);
  }

  .field input {
    width: 100%;
    padding: 0.5rem 0.75rem;
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    color: var(--color-text);
    outline: none;
    transition: border-color 0.15s;
  }

  .field input:focus {
    border-color: var(--color-primary);
  }

  .error-msg {
    color: var(--color-error);
    font-size: 0.875rem;
    margin-bottom: 1rem;
    text-align: center;
  }

  .btn-full {
    width: 100%;
    padding: 0.625rem;
    margin-top: 0.5rem;
  }
</style>
