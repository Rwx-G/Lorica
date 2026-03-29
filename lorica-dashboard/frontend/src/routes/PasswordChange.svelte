<script lang="ts">
  import { api } from '../lib/api';
  import { auth } from '../lib/auth';

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let error = $state('');
  let loading = $state(false);

  async function handleSubmit(e: Event) {
    e.preventDefault();
    error = '';

    if (newPassword !== confirmPassword) {
      error = 'Passwords do not match';
      return;
    }

    if (newPassword.length < 12) {
      error = 'Password must be at least 12 characters';
      return;
    }

    loading = true;

    const res = await api.changePassword(currentPassword, newPassword);

    if (res.error) {
      error = res.error.message;
      loading = false;
      return;
    }

    auth.set({ status: 'authenticated' });
    loading = false;
  }
</script>

<div class="change-container">
  <div class="change-card">
    <div class="change-header">
      <svg viewBox="0 0 32 32" fill="none" width="40" height="40">
        <path d="M16 2L4 8v8c0 7.2 5.1 13.9 12 16 6.9-2.1 12-8.8 12-16V8L16 2z" fill="#3b82f6" stroke="#2563eb" stroke-width="1"/>
        <path d="M16 6l-8 4v6c0 5.2 3.4 10 8 11.6 4.6-1.6 8-6.4 8-11.6v-6l-8-4z" fill="#60a5fa"/>
        <path d="M14 15l-2-2-1.5 1.5L14 18l6-6-1.5-1.5L14 15z" fill="white"/>
      </svg>
      <h1>Change Password</h1>
    </div>
    <p class="change-subtitle">You must change your password before continuing.</p>

    <form onsubmit={handleSubmit}>
      <div class="field">
        <label for="current">Current password</label>
        <input
          id="current"
          type="password"
          bind:value={currentPassword}
          required
          autocomplete="current-password"
        />
      </div>

      <div class="field">
        <label for="new-pw">New password</label>
        <input
          id="new-pw"
          type="password"
          bind:value={newPassword}
          required
          autocomplete="new-password"
          minlength="12"
        />
      </div>

      <div class="field">
        <label for="confirm">Confirm new password</label>
        <input
          id="confirm"
          type="password"
          bind:value={confirmPassword}
          required
          autocomplete="new-password"
        />
      </div>

      {#if error}
        <div class="error-msg">{error}</div>
      {/if}

      <button type="submit" class="btn btn-primary btn-full" disabled={loading}>
        {loading ? 'Updating...' : 'Update password'}
      </button>
    </form>
  </div>
</div>

<style>
  .change-container {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    width: 100%;
    padding: 1rem;
  }

  .change-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 2rem;
    width: 100%;
    max-width: 380px;
  }

  .change-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    justify-content: center;
    margin-bottom: 0.25rem;
  }

  .change-header h1 {
    margin: 0;
    font-size: 1.5rem;
  }

  .change-subtitle {
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
