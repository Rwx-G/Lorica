<script lang="ts">
  // Users & access management (Story 8.3 AC #7). Rendered for every
  // role but the API rejects non-SuperAdmin with 403, so the load
  // error doubles as the access notice; the Settings page only
  // mounts it for SuperAdmin anyway.
  import { onMount } from 'svelte';
  import { api, type UserResponse, type Role } from '../../lib/api';
  import { auth } from '../../lib/auth';
  import { showToast } from '../../lib/toast';
  import ConfirmDialog from '../ConfirmDialog.svelte';

  interface Props {
    expanded: boolean;
    toggleSection: () => void;
  }

  let { expanded, toggleSection }: Props = $props();

  let users: UserResponse[] = $state([]);
  let loadError = $state('');
  let loaded = $state(false);

  let ownUsername = $state('');
  auth.subscribe((a) => {
    ownUsername = a.status === 'authenticated' ? a.username : '';
  });

  // Create dialog state
  let creating = $state(false);
  let newUsername = $state('');
  let newPassword = $state('');
  let newRole: Role = $state('viewer');
  let createError = $state('');
  let submitting = $state(false);

  // Password-reset dialog state
  let resetTarget: UserResponse | null = $state(null);
  let resetPassword = $state('');
  let resetError = $state('');

  // Delete confirmation state
  let deleteTarget: UserResponse | null = $state(null);

  const roleLabels: Record<Role, string> = {
    super_admin: 'Super admin',
    operator: 'Operator',
    viewer: 'Viewer',
  };

  async function load() {
    const res = await api.listUsers();
    if (res.error) {
      loadError = res.error.message;
    } else if (res.data) {
      users = res.data;
      loadError = '';
    }
    loaded = true;
  }

  onMount(load);

  function validatePassword(pw: string): string {
    if ([...pw].length < 14) return 'Password must be at least 14 characters';
    if (
      !/[A-Z]/.test(pw) ||
      !/[a-z]/.test(pw) ||
      !/[0-9]/.test(pw) ||
      !/[^a-zA-Z0-9]/.test(pw)
    ) {
      return 'Password must contain an uppercase letter, a lowercase letter, a digit, and a symbol';
    }
    return '';
  }

  async function submitCreate(e: Event) {
    e.preventDefault();
    createError = validatePassword(newPassword);
    if (createError) return;
    submitting = true;
    const res = await api.createUser({
      username: newUsername,
      password: newPassword,
      role: newRole,
    });
    submitting = false;
    if (res.error) {
      createError = res.error.message;
      return;
    }
    showToast(`User ${newUsername} created`);
    creating = false;
    newUsername = '';
    newPassword = '';
    newRole = 'viewer';
    createError = '';
    await load();
  }

  async function changeRole(user: UserResponse, e: Event) {
    const select = e.currentTarget as HTMLSelectElement;
    const role = select.value as Role;
    const res = await api.updateUser(user.id, { role });
    if (res.error) {
      showToast(res.error.message, 'error');
      select.value = user.role;
      return;
    }
    showToast(`${user.username} is now ${roleLabels[role]}`);
    await load();
  }

  async function toggleDisabled(user: UserResponse) {
    const res = await api.updateUser(user.id, { disabled: !user.disabled });
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    showToast(user.disabled ? `${user.username} re-enabled` : `${user.username} disabled`);
    await load();
  }

  async function submitReset(e: Event) {
    e.preventDefault();
    if (resetTarget === null) return;
    resetError = validatePassword(resetPassword);
    if (resetError) return;
    const res = await api.updateUser(resetTarget.id, { password: resetPassword });
    if (res.error) {
      resetError = res.error.message;
      return;
    }
    showToast(`Password reset for ${resetTarget.username}; they must change it on next login`);
    resetTarget = null;
    resetPassword = '';
    resetError = '';
    await load();
  }

  async function confirmDelete() {
    if (deleteTarget === null) return;
    const res = await api.deleteUser(deleteTarget.id);
    if (res.error) {
      showToast(res.error.message, 'error');
    } else {
      showToast(`User ${deleteTarget.username} deleted`);
    }
    deleteTarget = null;
    await load();
  }

  function formatDate(iso: string | null): string {
    if (iso === null) return 'never';
    return new Date(iso).toLocaleString();
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Users &amp; access</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="section-hint">
        Team accounts with role-based access. Super admins manage
        everything including users and settings; operators have full
        control over routes, backends, certificates and protections;
        viewers are read-only with secrets hidden.
      </p>

      {#if loadError}
        <div class="settings-form-error">{loadError}</div>
      {:else if !loaded}
        <p class="hint">Loading...</p>
      {:else}
        <div class="users-table-wrap">
          <table class="users-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Last login</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each users as user (user.id)}
                <tr class:disabled-row={user.disabled}>
                  <td>
                    {user.username}
                    {#if user.username === ownUsername}<span class="you-badge">you</span>{/if}
                  </td>
                  <td>
                    <select
                      value={user.role}
                      onchange={(e) => changeRole(user, e)}
                      aria-label={`Role of ${user.username}`}
                    >
                      <option value="super_admin">Super admin</option>
                      <option value="operator">Operator</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </td>
                  <td>{formatDate(user.last_login_at)}</td>
                  <td>
                    <span class="status-pill" class:pill-disabled={user.disabled}>
                      {user.disabled ? 'Disabled' : 'Active'}
                    </span>
                  </td>
                  <td class="actions-cell">
                    <button class="btn btn-small" onclick={() => { resetTarget = user; resetPassword = ''; resetError = ''; }}>
                      Reset password
                    </button>
                    <button class="btn btn-small" onclick={() => toggleDisabled(user)}>
                      {user.disabled ? 'Enable' : 'Disable'}
                    </button>
                    {#if user.username !== ownUsername}
                      <button class="btn btn-small btn-danger" onclick={() => (deleteTarget = user)}>
                        Delete
                      </button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        {#if creating}
          <form class="create-form" onsubmit={submitCreate}>
            <h3>New user</h3>
            <div class="settings-form-row">
              <label for="new-user-name">Username</label>
              <input
                id="new-user-name"
                type="text"
                bind:value={newUsername}
                required
                minlength="3"
                maxlength="32"
                pattern="[a-z0-9][a-z0-9._\-]*"
                autocomplete="off"
                placeholder="jdoe"
              />
              <span class="hint">3-32 chars, lowercase letters, digits, '.', '_' or '-'.</span>
            </div>
            <div class="settings-form-row">
              <label for="new-user-pass">Initial password</label>
              <input
                id="new-user-pass"
                type="password"
                bind:value={newPassword}
                required
                minlength="14"
                autocomplete="new-password"
              />
              <span class="hint">Min 14 chars with upper, lower, digit and symbol.</span>
            </div>
            <div class="settings-form-row">
              <label for="new-user-role">Role</label>
              <select id="new-user-role" bind:value={newRole}>
                <option value="viewer">Viewer</option>
                <option value="operator">Operator</option>
                <option value="super_admin">Super admin</option>
              </select>
            </div>
            {#if createError}
              <div class="settings-form-error">{createError}</div>
            {/if}
            <div class="form-actions">
              <button type="submit" class="btn btn-primary" disabled={submitting}>
                {submitting ? 'Creating...' : 'Create user'}
              </button>
              <button type="button" class="btn" onclick={() => { creating = false; createError = ''; }}>
                Cancel
              </button>
            </div>
          </form>
        {:else}
          <button class="btn btn-primary" onclick={() => (creating = true)}>Add user</button>
        {/if}
      {/if}
    </div>
  {/if}
</section>

{#if resetTarget !== null}
  <div class="overlay">
    <form class="dialog reset-dialog" onsubmit={submitReset}>
      <h3>Reset password for {resetTarget.username}</h3>
      <p class="hint">
        They will be forced to choose a new password on their next
        login, and every active session of theirs is logged out now.
      </p>
      <div class="settings-form-row">
        <label for="reset-pass">Temporary password</label>
        <input
          id="reset-pass"
          type="password"
          bind:value={resetPassword}
          required
          minlength="14"
          autocomplete="new-password"
        />
      </div>
      {#if resetError}
        <div class="settings-form-error">{resetError}</div>
      {/if}
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">Reset password</button>
        <button type="button" class="btn" onclick={() => (resetTarget = null)}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

{#if deleteTarget !== null}
  <ConfirmDialog
    title={`Delete user ${deleteTarget.username}?`}
    message="The account is removed permanently and every active session of this user is logged out. This cannot be undone."
    confirmLabel="Delete user"
    onconfirm={confirmDelete}
    oncancel={() => (deleteTarget = null)}
  />
{/if}

<style>
  .users-table-wrap {
    overflow-x: auto;
    margin-bottom: 1rem;
  }

  .users-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }

  .users-table th,
  .users-table td {
    text-align: left;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
  }

  .users-table th {
    color: var(--color-text-muted);
    font-weight: 500;
  }

  .disabled-row td {
    opacity: 0.6;
  }

  .you-badge {
    margin-left: 0.375rem;
    font-size: 0.6875rem;
    padding: 0.0625rem 0.375rem;
    border-radius: 999px;
    background: var(--color-primary);
    color: #fff;
  }

  .status-pill {
    font-size: 0.75rem;
    padding: 0.125rem 0.5rem;
    border-radius: 999px;
    background: var(--color-success, #16a34a);
    color: #fff;
  }

  .pill-disabled {
    background: var(--color-text-muted);
  }

  .actions-cell {
    white-space: nowrap;
  }

  .actions-cell .btn {
    margin-right: 0.375rem;
  }

  .btn-small {
    font-size: 0.75rem;
    padding: 0.25rem 0.5rem;
  }

  .create-form {
    margin-top: 0.5rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--color-border);
  }

  .form-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }

  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .reset-dialog {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.5rem;
    width: 100%;
    max-width: 420px;
  }
</style>
