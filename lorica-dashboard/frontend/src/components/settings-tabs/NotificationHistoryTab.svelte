<script lang="ts">
  interface NotifEvent {
    alert_type: string;
    summary: string;
    timestamp: string;
    details: Record<string, string>;
  }

  interface Props {
    notifHistory: NotifEvent[];
    expanded: boolean;
    toggleSection: () => void;
  }

  let { notifHistory, expanded, toggleSection }: Props = $props();
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Notification History</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">Recent alert events dispatched by Lorica (last 100).</p>

      {#if notifHistory.length === 0}
        <p class="settings-empty-text">No notification events yet.</p>
      {:else}
        <div class="notif-history-scroll">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {#each notifHistory as ev, i (i)}
                <tr>
                  <td class="mono">{new Date(ev.timestamp).toLocaleString()}</td>
                  <td><span class="badge badge-{ev.alert_type === 'sla_breached' || ev.alert_type === 'backend_down' ? 'red' : ev.alert_type === 'sla_recovered' ? 'green' : ev.alert_type === 'cert_expiring' ? 'orange' : 'blue'}">{ev.alert_type}</span></td>
                  <td>{ev.summary}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}
</section>

<style>
  .notif-history-scroll {
    max-height: 400px;
    overflow-y: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }

  th {
    text-align: left;
    padding: 0.625rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text-muted);
    font-weight: 500;
    font-size: 0.8125rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  td {
    padding: 0.625rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    vertical-align: middle;
  }
</style>
