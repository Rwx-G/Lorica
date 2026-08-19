import { describe, it, expect } from 'vitest';
import {
  buildVerification,
  crawlerToEdit,
  editToBody,
  emptyCrawlerEdit,
  verificationKindLabel,
  verificationSummary,
  type CrawlerEditState,
} from './ai-crawlers';
import type { CustomCrawler } from './api';

describe('buildVerification', () => {
  it('shapes ua_only with no extra fields', () => {
    const state: CrawlerEditState = { ...emptyCrawlerEdit(), kind: 'ua_only' };
    expect(buildVerification(state)).toEqual({ kind: 'ua_only' });
  });

  it('shapes rdns suffixes, splitting on comma and newline', () => {
    const state: CrawlerEditState = {
      ...emptyCrawlerEdit(),
      kind: 'rdns',
      suffixes: 'googlebot.com\n search.msn.com , crawl.yahoo.net ',
    };
    expect(buildVerification(state)).toEqual({
      kind: 'rdns',
      suffixes: ['googlebot.com', 'search.msn.com', 'crawl.yahoo.net'],
    });
  });

  it('shapes ip_ranges cidrs and drops blank entries', () => {
    const state: CrawlerEditState = {
      ...emptyCrawlerEdit(),
      kind: 'ip_ranges',
      cidrs: '10.0.0.0/8\n\n2001:db8::/32\n',
    };
    expect(buildVerification(state)).toEqual({
      kind: 'ip_ranges',
      cidrs: ['10.0.0.0/8', '2001:db8::/32'],
    });
  });

  it('ignores the cidrs textarea when kind is rdns', () => {
    const state: CrawlerEditState = {
      ...emptyCrawlerEdit(),
      kind: 'rdns',
      suffixes: 'googlebot.com',
      cidrs: '10.0.0.0/8',
    };
    expect(buildVerification(state)).toEqual({
      kind: 'rdns',
      suffixes: ['googlebot.com'],
    });
  });
});

describe('editToBody', () => {
  it('trims name and pattern and folds verification in', () => {
    const state: CrawlerEditState = {
      name: '  MyBot  ',
      user_agent_pattern: '  MyBot/1\\.0  ',
      kind: 'ip_ranges',
      suffixes: '',
      cidrs: '203.0.113.0/24',
      enabled: false,
    };
    expect(editToBody(state)).toEqual({
      name: 'MyBot',
      user_agent_pattern: 'MyBot/1\\.0',
      verification: { kind: 'ip_ranges', cidrs: ['203.0.113.0/24'] },
      enabled: false,
    });
  });
});

describe('crawlerToEdit', () => {
  it('round-trips an rdns crawler back through editToBody', () => {
    const crawler: CustomCrawler = {
      id: 7,
      name: 'GoogleOther',
      user_agent_pattern: 'GoogleOther',
      verification: { kind: 'rdns', suffixes: ['googlebot.com', 'google.com'] },
      enabled: true,
      created_at: '2026-06-28T00:00:00Z',
      updated_at: '2026-06-28T00:00:00Z',
    };
    const body = editToBody(crawlerToEdit(crawler));
    expect(body.verification).toEqual({
      kind: 'rdns',
      suffixes: ['googlebot.com', 'google.com'],
    });
    expect(body.name).toBe('GoogleOther');
    expect(body.enabled).toBe(true);
  });
});

describe('verification display helpers', () => {
  it('labels each kind', () => {
    expect(verificationKindLabel('rdns')).toBe('rDNS');
    expect(verificationKindLabel('ip_ranges')).toBe('IP ranges');
    expect(verificationKindLabel('ua_only')).toBe('UA only');
  });

  it('summarises with pluralised counts', () => {
    expect(verificationSummary({ kind: 'rdns', suffixes: ['a'] })).toBe('rDNS (1 suffix)');
    expect(verificationSummary({ kind: 'rdns', suffixes: ['a', 'b'] })).toBe('rDNS (2 suffixes)');
    expect(verificationSummary({ kind: 'ip_ranges', cidrs: ['a'] })).toBe('IP ranges (1 CIDR)');
    expect(verificationSummary({ kind: 'ua_only' })).toBe('UA only');
  });
});
