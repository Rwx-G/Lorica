<script lang="ts">
  import { api } from '../lib/api';
  import { auth } from '../lib/auth';
  import ShieldIcon from '../components/ShieldIcon.svelte';

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let error = $state('');
  let loading = $state(false);
  let showCurrent = $state(false);
  let showNew = $state(false);
  let showConfirm = $state(false);

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
      <ShieldIcon size={40} />
      <h1>Change Password</h1>
    </div>
    <p class="change-subtitle">You must change your password before continuing.</p>

    <form onsubmit={handleSubmit}>
      <div class="field">
        <label for="current">Current password</label>
        <div class="input-with-toggle">
          <input
            id="current"
            type={showCurrent ? 'text' : 'password'}
            bind:value={currentPassword}
            required
            autocomplete="current-password"
          />
          <button type="button" class="toggle-pw" onclick={() => (showCurrent = !showCurrent)} aria-label={showCurrent ? 'Hide password' : 'Show password'}>
            {#if showCurrent}{@html eyeOffIcon}{:else}{@html eyeIcon}{/if}
          </button>
        </div>
      </div>

      <div class="field">
        <label for="new-pw">New password</label>
        <div class="input-with-toggle">
          <input
            id="new-pw"
            type={showNew ? 'text' : 'password'}
            bind:value={newPassword}
            required
            autocomplete="new-password"
            minlength="12"
          />
          <button type="button" class="toggle-pw" onclick={() => (showNew = !showNew)} aria-label={showNew ? 'Hide password' : 'Show password'}>
            {#if showNew}{@html eyeOffIcon}{:else}{@html eyeIcon}{/if}
          </button>
        </div>
      </div>

      <div class="field">
        <label for="confirm">Confirm new password</label>
        <div class="input-with-toggle">
          <input
            id="confirm"
            type={showConfirm ? 'text' : 'password'}
            bind:value={confirmPassword}
            required
            autocomplete="new-password"
          />
          <button type="button" class="toggle-pw" onclick={() => (showConfirm = !showConfirm)} aria-label={showConfirm ? 'Hide password' : 'Show password'}>
            {#if showConfirm}{@html eyeOffIcon}{:else}{@html eyeIcon}{/if}
          </button>
        </div>
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

  .input-with-toggle {
    position: relative;
  }

  .input-with-toggle input {
    width: 100%;
    padding: 0.5rem 2.25rem 0.5rem 0.75rem;
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    color: var(--color-text);
    outline: none;
    transition: border-color 0.15s;
  }

  .input-with-toggle input:focus {
    border-color: var(--color-primary);
  }

  .toggle-pw {
    position: absolute;
    right: 0.5rem;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--color-text-muted);
    cursor: pointer;
    padding: 0.125rem;
    display: flex;
    align-items: center;
  }

  .toggle-pw:hover {
    color: var(--color-text);
  }

  .btn-full {
    width: 100%;
    padding: 0.625rem;
    margin-top: 0.5rem;
  }
</style>

<script lang="ts" module>
  const eyeIcon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const eyeOffIcon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
</script>
