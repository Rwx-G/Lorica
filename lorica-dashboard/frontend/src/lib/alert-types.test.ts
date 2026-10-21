import { describe, it, expect } from 'vitest';

import { ALERT_TYPE_CHOICES, alertTone, choiceSelected, mergeAlertTypes } from './alert-types';

function choice(label: string) {
  const found = ALERT_TYPE_CHOICES.find((candidate) => candidate.label === label);
  if (!found) throw new Error(`no choice ${label}`);
  return found;
}

function ticked(stored: readonly string[]): Set<string> {
  return new Set(ALERT_TYPE_CHOICES.filter((c) => choiceSelected(c, stored)).map((c) => c.label));
}

describe('ALERT_TYPE_CHOICES', () => {
  it('offers each type once', () => {
    const types = ALERT_TYPE_CHOICES.flatMap((c) => c.types);
    expect(new Set(types).size).toBe(types.length);
  });

  it('offers the cluster alerts, whose subscriptions an edit used to drop', () => {
    const types = ALERT_TYPE_CHOICES.flatMap((c) => c.types);
    for (const type of ['cluster_node_left', 'cluster_config_refused', 'cluster_drift']) {
      expect(types).toContain(type);
    }
  });
});

describe('mergeAlertTypes', () => {
  it('saves what was stored when nothing is changed', () => {
    for (const choiceOf of ALERT_TYPE_CHOICES) {
      const stored = [...choiceOf.types];
      expect(mergeAlertTypes(stored, ticked(stored))).toEqual(stored);
    }
  });

  it('keeps a stored type no choice offers, wherever it sits', () => {
    const stored = ['future_alert', 'backend_down', 'another_one'];
    const selected = ticked(stored);
    selected.add(choice('WAF alert').label);
    expect(mergeAlertTypes(stored, selected)).toEqual(['backend_down', 'waf_alert', 'future_alert', 'another_one']);
  });

  it('adds every type of a choice ticked in the form', () => {
    expect(mergeAlertTypes([], new Set([choice('SLA breached').label]))).toEqual(['sla_breached', 'sla_recovered']);
  });

  it('removes every type of a choice unticked in the form', () => {
    const stored = ['sla_breached', 'sla_recovered', 'cluster_drift'];
    const selected = ticked(stored);
    selected.delete(choice('SLA breached').label);
    expect(mergeAlertTypes(stored, selected)).toEqual(['cluster_drift']);
  });

  it('keeps half a pair the API stored when the box was left alone', () => {
    const stored = ['sla_recovered'];
    expect(mergeAlertTypes(stored, ticked(stored))).toEqual(['sla_recovered']);
  });
});

describe('alertTone', () => {
  it('reads failures red, recoveries green, warnings orange, anything else blue', () => {
    expect(alertTone('adcs_authority_failed')).toBe('red');
    expect(alertTone('sla_recovered')).toBe('green');
    expect(alertTone('cert_expiring')).toBe('orange');
    expect(alertTone('config_changed')).toBe('blue');
    expect(alertTone('future_alert')).toBe('blue');
  });
});
