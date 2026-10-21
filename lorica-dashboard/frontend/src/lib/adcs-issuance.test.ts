import { describe, it, expect } from 'vitest';
import type { AdcsAuthorityState } from './api';
import { testAuthority, testAuthorityState, testCertificate as cert } from '../test-adcs-fixtures';
import {
  ADCS_KEY_TYPE_LABELS,
  ADCS_RENEWAL_STILL_FINISHING,
  ADCS_STILL_FINISHING,
  ADCS_SUBJECT_FIELDS,
  ADCS_SUBJECT_LABELS,
  adcsIssuanceBlocker,
  adcsIssueOutcome,
  adcsRenewalOffered,
  adcsRenewOutcome,
  adcsRequestSummary,
  adcsManagedCertificateNotice,
  adcsSanHints,
  adcsTemplateOptions,
  ADCS_KEY_NOT_EXPORTABLE_HINT,
  downloadPartRefusal,
  hostnamesWithoutCertificate,
  isAdcsFollower,
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
  const ready: AdcsAuthorityState = testAuthorityState();

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
        state: testAuthorityState({ follower: true }),
      }),
    ).toMatch(/follower/);
  });

  it('refuses when no authority is configured', () => {
    expect(
      adcsIssuanceBlocker({ canIssue: true, follower: false, state: testAuthorityState({ authority: null }) }),
    ).toMatch(/No AD CS authority is configured/);
  });

  it('refuses while the authority is in the failed state', () => {
    expect(
      adcsIssuanceBlocker({
        canIssue: true,
        follower: false,
        state: testAuthorityState({ authority: testAuthority({ failed_since: '2026-10-20T08:00:00Z' }) }),
      }),
    ).toMatch(/failed state/);
  });

  it('reads configured and failed from the summary, which a Viewer also gets (D18)', () => {
    const failed = testAuthorityState({
      authority: testAuthority({ failed_since: '2026-10-20T08:00:00Z' }),
      viewer: true,
    });
    expect(failed.authority).toBeNull();
    expect(adcsIssuanceBlocker({ canIssue: true, follower: false, state: failed })).toMatch(/failed state/);
    expect(
      adcsIssuanceBlocker({ canIssue: true, follower: false, state: testAuthorityState({ viewer: true }) }),
    ).toBeNull();
  });
});

describe('adcsTemplateOptions', () => {
  it('puts the default first, then the other allowed templates', () => {
    expect(
      adcsTemplateOptions({ default_template: 'LoricaWebServer', allowed_templates: ['LoricaWebServer', 'LoricaEcdsa'] }),
    ).toEqual(['LoricaWebServer', 'LoricaEcdsa']);
  });

  it('offers the default even when the list omits it', () => {
    expect(adcsTemplateOptions({ default_template: 'LoricaWebServer', allowed_templates: [] })).toEqual([
      'LoricaWebServer',
    ]);
  });

  it('lists a name once, ignoring case as the API does', () => {
    expect(
      adcsTemplateOptions({
        default_template: 'LoricaWebServer',
        allowed_templates: ['loricawebserver', 'LoricaEcdsa', 'LORICAECDSA'],
      }),
    ).toEqual(['LoricaWebServer', 'LoricaEcdsa']);
  });
});

describe('isAdcsFollower', () => {
  it('is true by the cluster role before the read lands, or by the API flag', () => {
    expect(isAdcsFollower('follower', null)).toBe(true);
    expect(isAdcsFollower(null, testAuthorityState({ follower: true }))).toBe(true);
    expect(isAdcsFollower('control_plane', testAuthorityState())).toBe(false);
    expect(isAdcsFollower(null, null)).toBe(false);
  });
});

describe('downloadPartRefusal', () => {
  const adcs = cert('app.corp.example.org', [], { source: 'adcs' });

  it('refuses the key and the bundle of an AD CS certificate (D16)', () => {
    expect(downloadPartRefusal(adcs, 'key')).toBe(ADCS_KEY_NOT_EXPORTABLE_HINT);
    expect(downloadPartRefusal(adcs, 'bundle')).toBe(ADCS_KEY_NOT_EXPORTABLE_HINT);
  });

  it('keeps its certificate and chain downloadable', () => {
    expect(downloadPartRefusal(adcs, 'cert')).toBeNull();
    expect(downloadPartRefusal(adcs, 'chain')).toBeNull();
  });

  it('refuses nothing on a manual or ACME certificate', () => {
    for (const source of ['manual', 'acme'] as const) {
      for (const part of ['cert', 'key', 'chain', 'bundle'] as const) {
        expect(downloadPartRefusal(cert('a.example.com', [], { source }), part)).toBeNull();
      }
    }
  });
});

describe('adcsManagedCertificateNotice', () => {
  it('explains the lock on an AD CS certificate only', () => {
    expect(adcsManagedCertificateNotice({ source: 'adcs' })).toMatch(/Revert it to manual first/);
    expect(adcsManagedCertificateNotice({ source: 'manual' })).toBeNull();
    expect(adcsManagedCertificateNotice({ source: 'acme' })).toBeNull();
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

describe('adcsIssueOutcome failing step', () => {
  it('adds the failing step of an adcs_error the message does not name', () => {
    expect(
      adcsIssueOutcome({ error: { code: 'adcs_error', message: 'the CA closed the connection', step: 'enroll', status: 502 } }),
    ).toEqual({ kind: 'refused', message: 'the CA closed the connection (failing step: enroll)' });
  });

  it('does not repeat a step the message already names', () => {
    expect(
      adcsIssueOutcome({ error: { code: 'adcs_error', message: 'kerberos: ticket refused', step: 'kerberos', status: 502 } }),
    ).toEqual({ kind: 'refused', message: 'kerberos: ticket refused' });
  });
});

describe('adcsRenewalOffered', () => {
  const ready: AdcsAuthorityState = testAuthorityState();

  it('follows the issuance rules exactly, case by case', () => {
    const cases: Parameters<typeof adcsIssuanceBlocker>[0][] = [
      { canIssue: true, follower: false, state: ready },
      { canIssue: false, follower: false, state: ready },
      { canIssue: true, follower: true, state: ready },
      { canIssue: true, follower: false, state: testAuthorityState({ follower: true }) },
      { canIssue: true, follower: false, state: testAuthorityState({ authority: null }) },
      { canIssue: true, follower: false, state: null },
      {
        canIssue: true,
        follower: false,
        state: testAuthorityState({ authority: testAuthority({ failed_since: '2026-10-20T08:00:00Z' }) }),
      },
    ];
    for (const input of cases) {
      expect(adcsRenewalOffered(input)).toBe(adcsIssuanceBlocker(input) === null);
    }
    expect(cases.filter(adcsRenewalOffered)).toEqual([cases[0]]);
  });
});

describe('adcsRenewOutcome', () => {
  it('reads the renewed certificate', () => {
    const renewed = cert('app.corp.example.org', [], { source: 'adcs' });
    expect(adcsRenewOutcome({ data: renewed })).toEqual({ kind: 'renewed', certificate: renewed });
  });

  it('reads the ACME shape as renewed with no certificate to show', () => {
    expect(
      adcsRenewOutcome({ data: { renewed: true, old_cert_id: 'c', new_cert_id: 'c', domain: 'app.corp.example.org' } }),
    ).toEqual({ kind: 'renewed', certificate: null });
  });

  it('reads the 202 body as pending', () => {
    expect(
      adcsRenewOutcome({ data: { outcome: 'pending', request_id: '4712', message: 'Taken under submission' } }),
    ).toEqual({ kind: 'pending', requestId: '4712', message: 'Taken under submission' });
  });

  it('keeps every refusal message verbatim and adds the failing step', () => {
    expect(
      adcsRenewOutcome({ error: { code: 'adcs_busy', message: 'an AD CS operation is already running', status: 409 } }),
    ).toEqual({ kind: 'refused', message: 'an AD CS operation is already running' });
    expect(
      adcsRenewOutcome({ error: { code: 'adcs_error', message: 'the CA closed the connection', step: 'enroll', status: 502 } }),
    ).toEqual({ kind: 'refused', message: 'the CA closed the connection (failing step: enroll)' });
  });

  it('reads a 504 as still finishing, whatever the body says', () => {
    expect(
      adcsRenewOutcome({ error: { code: 'parse_error', message: 'Server returned invalid response (504)', status: 504 } }),
    ).toEqual({ kind: 'refused', message: ADCS_RENEWAL_STILL_FINISHING });
  });
});
