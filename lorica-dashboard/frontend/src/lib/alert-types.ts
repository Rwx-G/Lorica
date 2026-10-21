/**
 * The alert types a notification channel subscribes to, as the
 * dashboard offers them, and how an edit is saved.
 *
 * The vocabulary is `AlertType::ALL` in `lorica-notify`. This list is
 * still typed by hand until a generated module replaces it, so saving
 * never trusts it to be complete: a type the channel already holds and
 * no choice covers is kept as it is (`mergeAlertTypes`). Dropping it
 * would silently unsubscribe the channel from an alert the dashboard
 * merely does not display.
 */

export interface AlertTypeChoice {
  label: string;
  /**
   * The types one checkbox stands for: an alert and its recovery
   * travel together. The first one decides whether the box is ticked.
   */
  types: readonly string[];
}

export const ALERT_TYPE_CHOICES: readonly AlertTypeChoice[] = [
  { label: 'Backend down', types: ['backend_down'] },
  { label: 'Certificate expiring', types: ['cert_expiring'] },
  { label: 'WAF alert', types: ['waf_alert'] },
  { label: 'Configuration changed', types: ['config_changed'] },
  { label: 'SLA breached', types: ['sla_breached', 'sla_recovered'] },
  { label: 'IP banned', types: ['ip_banned'] },
  { label: 'Cluster node left', types: ['cluster_node_left'] },
  { label: 'Cluster configuration refused', types: ['cluster_config_refused'] },
  { label: 'Cluster drift', types: ['cluster_drift'] },
  { label: 'Log persistence lost / restored', types: ['log_store_unavailable', 'log_store_recovered'] },
  { label: 'AD CS authority failed', types: ['adcs_authority_failed'] },
  { label: 'Certificate issuance failed', types: ['cert_issuance_failed'] },
];

/** Whether a channel holding `stored` shows `choice` as ticked. */
export function choiceSelected(choice: AlertTypeChoice, stored: readonly string[]): boolean {
  return stored.includes(choice.types[0]);
}

/**
 * The `alert_types` to save, `selected` holding the ticked choices'
 * labels. A choice ticked in the form saves all its types and one
 * unticked saves none, but a choice whose box the operator left as it
 * opened saves exactly the stored types it covers: a channel the API
 * subscribed to `sla_recovered` alone keeps that subscription. Every
 * stored type no choice covers follows, in stored order.
 */
export function mergeAlertTypes(stored: readonly string[], selected: ReadonlySet<string>): string[] {
  const out: string[] = [];
  for (const choice of ALERT_TYPE_CHOICES) {
    const ticked = selected.has(choice.label);
    if (ticked === choiceSelected(choice, stored)) {
      out.push(...choice.types.filter((type) => stored.includes(type)));
    } else if (ticked) {
      out.push(...choice.types);
    }
  }
  const offered = new Set(ALERT_TYPE_CHOICES.flatMap((choice) => choice.types));
  for (const type of stored) {
    if (!offered.has(type) && !out.includes(type)) out.push(type);
  }
  return out;
}

/**
 * The badge colour of an alert type in the notification history: red
 * for a failure, green for a recovery, orange for a warning ahead of
 * one, blue otherwise (including types this module does not know).
 */
export type AlertTone = 'red' | 'green' | 'orange' | 'blue';

const ALERT_TONES: Readonly<Record<string, AlertTone>> = {
  backend_down: 'red',
  sla_breached: 'red',
  log_store_unavailable: 'red',
  adcs_authority_failed: 'red',
  cert_issuance_failed: 'red',
  sla_recovered: 'green',
  log_store_recovered: 'green',
  cert_expiring: 'orange',
};

export function alertTone(type: string): AlertTone {
  return ALERT_TONES[type] ?? 'blue';
}
