import { describe, it, expect } from 'vitest';

import { ALERT_TYPES } from './adcs.generated';
import { ALERT_TYPE_CHOICES, alertLabel, alertTone, choiceSelected, mergeAlertTypes } from './alert-types';

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

  it('offers every generated type, each recovery beside the alert it closes', () => {
    const offered = ALERT_TYPE_CHOICES.flatMap((c) => c.types);
    expect([...offered].sort()).toEqual(ALERT_TYPES.map((d) => d.value).sort());
    for (const definition of ALERT_TYPES.filter((d) => d.recovers !== null)) {
      const owner = ALERT_TYPE_CHOICES.find((c) => c.types.includes(definition.value));
      expect(owner?.types[0]).toBe(definition.recovers);
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
  it('colours every generated type by its tone', () => {
    const colours = { problem: 'red', recovery: 'green', warning: 'orange', info: 'blue' };
    for (const definition of ALERT_TYPES) {
      expect(alertTone(definition.value)).toBe(colours[definition.tone]);
    }
  });

  it('reads a type it does not know as information', () => {
    expect(alertTone('future_alert')).toBe('blue');
  });
});

describe('alertLabel', () => {
  it('labels a known type and shows an unknown one raw', () => {
    for (const definition of ALERT_TYPES) {
      expect(alertLabel(definition.value)).toBe(definition.label);
    }
    expect(alertLabel('future_alert')).toBe('future_alert');
  });
});
