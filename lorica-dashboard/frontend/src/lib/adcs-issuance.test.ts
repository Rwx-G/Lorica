import { describe, it, expect } from 'vitest';
import type { AdcsAuthorityState } from './api';
import { testAuthority, testCertificate as cert } from '../test-adcs-fixtures';
import {
  ADCS_KEY_TYPE_LABELS,
  ADCS_STILL_FINISHING,
  ADCS_SUBJECT_FIELDS,
  ADCS_SUBJECT_LABELS,
  adcsIssuanceBlocker,
  adcsIssueOutcome,
  adcsRequestSummary,
  adcsSanHints,
  hostnamesWithoutCertificate,
  nameUnderSuffix,
  parseSanList,
  subjectOverrides,
} from './adcs-issuance';

describe('hostnamesWithoutCertificate', () => {
  it('counts a certificate domain as covering, not only its SANs', () => {
    expect(
      hostnamesWithoutCertificate(
        ['app.corp.example.org', 'api.corp.example.org'],
        [cert('app.corp.example.org')],
      ),
    ).toEqual(['api.corp.example.org']);
  });

  it('counts the SANs of every stored certificate, not only one', () => {
    expect(
      hostnamesWithoutCertificate(
        ['a.corp.example.org', 'b.corp.example.org', 'c.corp.example.org'],
        [cert('x.corp.example.org', ['a.corp.example.org']), cert('y.corp.example.org', ['*.corp.example.org'])],
      ),
    ).toEqual([]);
  });

  it('drops wildcard names, which AD CS issuance refuses', () => {
    expect(
      hostnamesWithoutCertificate(['app.corp.example.org', '*.corp.example.org'], []),
    ).toEqual(['app.corp.example.org']);
  });

  it('returns nothing when every name is covered', () => {
    expect(
      hostnamesWithoutCertificate(['app.corp.example.org'], [cert('other.corp.example.org', ['APP.corp.example.org'])]),
    ).toEqual([]);
  });

  it('returns every name when there is no certificate', () => {
    expect(hostnamesWithoutCertificate(['a.corp.example.org', 'b.corp.example.org'], [])).toEqual([
      'a.corp.example.org',
      'b.corp.example.org',
    ]);
  });
});

describe('nameUnderSuffix', () => {
  it('permits the suffix itself and any depth under it', () => {
    expect(nameUnderSuffix('corp.example.org', 'corp.example.org')).toBe(true);
    expect(nameUnderSuffix('a.b.corp.example.org', 'corp.example.org')).toBe(true);
    expect(nameUnderSuffix('App.Corp.Example.Org.', 'corp.example.org')).toBe(true);
  });

  it('matches on labels, never on a string suffix', () => {
    expect(nameUnderSuffix('evilcorp.example.org', 'corp.example.org')).toBe(false);
  });
});

describe('parseSanList and adcsSanHints', () => {
  it('splits lines and commas, trims, and drops duplicates', () => {
    expect(parseSanList('a.corp.example.org\n A.corp.example.org , b.corp.example.org\n\n')).toEqual([
      'a.corp.example.org',
      'b.corp.example.org',
    ]);
  });

  it('flags wildcards and names outside the suffixes separately', () => {
    expect(
      adcsSanHints(['*.corp.example.org', 'evilcorp.example.org', 'ok.corp.example.org'], ['corp.example.org']),
    ).toEqual({ wildcards: ['*.corp.example.org'], outsideSuffixes: ['evilcorp.example.org'] });
  });
});

describe('subjectOverrides', () => {
  const defaults = testAuthority().subject;
  const unchanged = Object.fromEntries(
    ADCS_SUBJECT_FIELDS.map((field) => [field, defaults[field] ?? '']),
  ) as Record<(typeof ADCS_SUBJECT_FIELDS)[number], string>;

  it('sends nothing when the operator changed nothing', () => {
    expect(subjectOverrides(defaults, unchanged)).toBeUndefined();
  });

  it('sends only the changed, non-blank fields', () => {
    expect(
      subjectOverrides(defaults, { ...unchanged, organizational_unit: 'Web', country: '' }),
    ).toEqual({ organizational_unit: 'Web' });
  });
});

describe('adcsRequestSummary', () => {
  it('uses the authority defaults, CN the first SAN, and lists every SAN', () => {
    const authority = testAuthority();
    const summary = adcsRequestSummary(authority, {
      sans: ['app.corp.example.org', 'www.app.corp.example.org'],
    });
    expect(summary.template).toBe('LoricaWebServer');
    expect(summary.keyType).toBe(ADCS_KEY_TYPE_LABELS.rsa2048);
    expect(summary.sans).toEqual(['app.corp.example.org', 'www.app.corp.example.org']);
    expect(summary.autoRenew).toBe(true);
    expect(summary.subject).toEqual([
      { label: 'Common name (CN)', value: 'app.corp.example.org' },
      { label: ADCS_SUBJECT_LABELS.country, value: 'FR' },
      { label: ADCS_SUBJECT_LABELS.locality, value: 'Paris' },
      { label: ADCS_SUBJECT_LABELS.organization, value: 'Example Corp' },
    ]);
  });

  it('puts the overrides on top of the defaults', () => {
    const summary = adcsRequestSummary(testAuthority(), {
      sans: ['app.corp.example.org'],
      template: 'LoricaEcdsa',
      key_type: 'ecdsa_p256',
      subject: { organization: 'Other Corp', organizational_unit: 'Web' },
      auto_renew: false,
    });
    expect(summary.template).toBe('LoricaEcdsa');
    expect(summary.keyType).toBe(ADCS_KEY_TYPE_LABELS.ecdsa_p256);
    expect(summary.autoRenew).toBe(false);
    expect(summary.subject).toContainEqual({ label: ADCS_SUBJECT_LABELS.organization, value: 'Other Corp' });
    expect(summary.subject).toContainEqual({ label: ADCS_SUBJECT_LABELS.organizational_unit, value: 'Web' });
    expect(summary.subject).toContainEqual({ label: ADCS_SUBJECT_LABELS.country, value: 'FR' });
  });
});

describe('adcsIssuanceBlocker', () => {
  const ready: AdcsAuthorityState = { authority: testAuthority(), managed_on_control_plane: false };

  it('offers issuance to an Operator on the control plane with a healthy authority', () => {
    expect(adcsIssuanceBlocker({ canIssue: true, follower: false, state: ready })).toBeNull();
  });

  it('refuses a role below Operator', () => {
    expect(adcsIssuanceBlocker({ canIssue: false, follower: false, state: ready })).toMatch(/Operator role/);
  });

  it('refuses on a follower, by the cluster role or by the API flag', () => {
    expect(adcsIssuanceBlocker({ canIssue: true, follower: true, state: ready })).toMatch(/follower/);
    expect(
      adcsIssuanceBlocker({
        canIssue: true,
        follower: false,
        state: { authority: null, managed_on_control_plane: true },
      }),
    ).toMatch(/follower/);
  });

  it('refuses when no authority is configured', () => {
    expect(
      adcsIssuanceBlocker({ canIssue: true, follower: false, state: { authority: null, managed_on_control_plane: false } }),
    ).toMatch(/No AD CS authority is configured/);
  });

  it('refuses while the authority is in the failed state', () => {
    expect(
      adcsIssuanceBlocker({
        canIssue: true,
        follower: false,
        state: { authority: testAuthority({ failed_since: '2026-10-20T08:00:00Z' }), managed_on_control_plane: false },
      }),
    ).toMatch(/failed state/);
  });
});

describe('adcsIssueOutcome', () => {
  it('reads a certificate as issued', () => {
    const issued = { ...cert('app.corp.example.org'), source: 'adcs' as const };
    expect(adcsIssueOutcome({ data: issued })).toEqual({ kind: 'issued', certificate: issued });
  });

  it('reads the 202 body as pending', () => {
    expect(
      adcsIssueOutcome({ data: { outcome: 'pending', request_id: '4711', message: 'Taken under submission' } }),
    ).toEqual({ kind: 'pending', requestId: '4711', message: 'Taken under submission' });
  });

  it('keeps a refusal message verbatim', () => {
    expect(
      adcsIssueOutcome({ error: { code: 'adcs_denied', message: 'Denied by Policy Module', status: 422 } }),
    ).toEqual({ kind: 'refused', message: 'Denied by Policy Module' });
  });

  it('reads a 504 as still finishing, whatever the body says', () => {
    expect(
      adcsIssueOutcome({ error: { code: 'parse_error', message: 'Server returned invalid response (504)', status: 504 } }),
    ).toEqual({ kind: 'refused', message: ADCS_STILL_FINISHING });
  });
});
