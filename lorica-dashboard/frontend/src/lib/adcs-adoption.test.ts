import { describe, it, expect } from 'vitest';

import type { AdcsAdoptionCandidates, ApiResponse, CertificateResponse } from './api';
import { adcsAdoptionBanner, adcsTemplateLabel, adoptInSequence } from './adcs-adoption';
import { testCandidate, testCertificate } from '../test-adcs-fixtures';

const two: AdcsAdoptionCandidates = {
  reason: null,
  candidates: [testCandidate('a.corp.example.org'), testCandidate('b.corp.example.org')],
};

describe('adcsAdoptionBanner', () => {
  it('announces the candidates to an Operator on the control plane', () => {
    expect(adcsAdoptionBanner({ canAdopt: true, follower: false, candidates: two })).toEqual({
      kind: 'candidates',
      count: 2,
    });
  });

  it('says nothing to a Viewer', () => {
    expect(adcsAdoptionBanner({ canAdopt: false, follower: false, candidates: two })).toBeNull();
  });

  it('says nothing on a follower', () => {
    expect(adcsAdoptionBanner({ canAdopt: true, follower: true, candidates: two })).toBeNull();
  });

  it('says nothing when there is no candidate or nothing was read', () => {
    expect(adcsAdoptionBanner({ canAdopt: true, follower: false, candidates: { reason: null, candidates: [] } })).toBeNull();
    expect(adcsAdoptionBanner({ canAdopt: true, follower: false, candidates: null })).toBeNull();
  });

  it('explains how to provide the issuing CA when none is known', () => {
    const candidates: AdcsAdoptionCandidates = { reason: 'no_issuing_ca', candidates: [] };
    expect(adcsAdoptionBanner({ canAdopt: true, follower: false, candidates })).toEqual({ kind: 'no_issuing_ca' });
    expect(adcsAdoptionBanner({ canAdopt: false, follower: false, candidates })).toBeNull();
  });

  it('says nothing on a follower, whose listing names the control plane', () => {
    expect(
      adcsAdoptionBanner({
        canAdopt: true,
        follower: false,
        candidates: { reason: 'managed_on_control_plane', candidates: [] },
      }),
    ).toBeNull();
  });

  it('says nothing when no authority is configured', () => {
    expect(
      adcsAdoptionBanner({ canAdopt: true, follower: false, candidates: { reason: 'not_configured', candidates: [] } }),
    ).toBeNull();
  });
});

describe('adcsTemplateLabel', () => {
  it('reads "unknown" when no template is known', () => {
    expect(adcsTemplateLabel(null)).toBe('unknown');
    expect(adcsTemplateLabel('WebServer')).toBe('WebServer');
  });
});

describe('adoptInSequence', () => {
  it('adopts one certificate at a time, in order, and keeps going after a refusal', async () => {
    const events: string[] = [];
    let inFlight = 0;
    const adopt = async (id: string, body: { auto_renew: boolean }): Promise<ApiResponse<CertificateResponse>> => {
      inFlight += 1;
      expect(inFlight).toBe(1);
      events.push(`${id}:${body.auto_renew}`);
      await new Promise((resolve) => setTimeout(resolve, 0));
      inFlight -= 1;
      if (id === 'cert-a.corp.example.org') {
        return { error: { code: 'adcs_not_candidate', message: 'not signed by the issuing CA', status: 422 } };
      }
      return { data: testCertificate(id, [], { source: 'adcs' }) };
    };
    const results = await adoptInSequence(
      two.candidates,
      (c) => c.domain.startsWith('b'),
      adopt,
    );
    expect(events).toEqual(['cert-a.corp.example.org:false', 'cert-b.corp.example.org:true']);
    expect(results.map((r) => [r.domain, r.ok])).toEqual([
      ['a.corp.example.org', false],
      ['b.corp.example.org', true],
    ]);
    expect(results[0].message).toBe('not signed by the issuing CA');
  });

  it('shows a refusal for an unknown issuing CA as the API words it', async () => {
    const message = 'the AD CS authority does not know its issuing CA certificate';
    const results = await adoptInSequence(two.candidates.slice(0, 1), () => true, async () => ({
      error: { code: 'adcs_no_issuing_ca', message, status: 409 },
    }));
    expect(results).toEqual([expect.objectContaining({ ok: false, message })]);
  });
});
