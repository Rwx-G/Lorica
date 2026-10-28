/**
 * The alert types a notification channel subscribes to, as the
 * dashboard offers them, and how an edit is saved.
 *
 * The vocabulary is `ALERT_TYPES`, rendered from `AlertType::ALL` in
 * `lorica-notify`. Saving still never trusts it to be complete: a
 * dashboard served next to a newer API meets types it does not know,
 * and a type the channel already holds that no choice covers is kept
 * as it is (`mergeAlertTypes`). Dropping it would silently unsubscribe
 * the channel from an alert the dashboard merely does not display.
 */

import { ALERT_TYPES, type AlertTone, type AlertType } from './adcs.generated';

export interface AlertTypeChoice {
  label: string;
  /**
   * The types one checkbox stands for: an alert and its recovery
   * travel together. The first one decides whether the box is ticked.
   */
  types: readonly AlertType[];
}

/** One checkbox per alert that is not a recovery, carrying the recoveries that close it. */
export const ALERT_TYPE_CHOICES: readonly AlertTypeChoice[] = ALERT_TYPES.filter(
  (definition) => definition.recovers === null,
).map((definition) => ({
  label: definition.label,
  types: [
    definition.value,
    ...ALERT_TYPES.filter((other) => other.recovers === definition.value).map((other) => other.value),
  ],
}));

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
  const offered = new Set<string>(ALERT_TYPE_CHOICES.flatMap((choice) => choice.types));
  for (const type of stored) {
    if (!offered.has(type) && !out.includes(type)) out.push(type);
  }
  return out;
}

/** The badge colour of an alert in the notification history. */
export type AlertBadgeColour = 'red' | 'green' | 'orange' | 'blue';

const BADGE_COLOURS: Readonly<Record<AlertTone, AlertBadgeColour>> = {
  problem: 'red',
  recovery: 'green',
  warning: 'orange',
  info: 'blue',
};

function definitionOf(type: string) {
  return ALERT_TYPES.find((definition) => definition.value === type);
}

/** A type this dashboard does not know reads as information. */
export function alertTone(type: string): AlertBadgeColour {
  return BADGE_COLOURS[definitionOf(type)?.tone ?? 'info'];
}

/** A type this dashboard does not know shows as its raw value. */
export function alertLabel(type: string): string {
  return definitionOf(type)?.label ?? type;
}
