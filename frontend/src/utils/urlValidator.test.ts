import { describe, it, expect } from 'vitest';
import { validateAndNormalizeUrl } from './urlValidator';

describe('validateAndNormalizeUrl', () => {
  it('validates a standard HTTPS URL correctly', () => {
    const res = validateAndNormalizeUrl('https://github.com/torvalds/linux');
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.hostname).toBe('github.com');
      expect(res.protocol).toBe('https:');
      expect(res.isBareDomainInput).toBe(false);
      expect(res.pathname).toBe('/torvalds/linux');
    }
  });

  it('normalizes a bare domain to HTTPS', () => {
    const res = validateAndNormalizeUrl('github.com');
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.normalizedUrl).toBe('https://github.com/');
      expect(res.hostname).toBe('github.com');
      expect(res.isBareDomainInput).toBe(true);
    }
  });

  it('rejects unsupported javascript: protocol', () => {
    const res = validateAndNormalizeUrl('javascript:alert(1)');
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.reason).toBe('unsupported_protocol');
    }
  });

  it('rejects unsupported file: and data: protocols', () => {
    const res1 = validateAndNormalizeUrl('file:///etc/passwd');
    expect(res1.valid).toBe(false);

    const res2 = validateAndNormalizeUrl('data:text/html,<b>pwn</b>');
    expect(res2.valid).toBe(false);
  });

  it('rejects empty input', () => {
    const res = validateAndNormalizeUrl('   ');
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.reason).toBe('empty');
    }
  });

  it('detects Punycode / IDN homograph domains', () => {
    const res = validateAndNormalizeUrl('https://xn--e1afmkfd.xn--p1ai');
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.isPunycode).toBe(true);
      expect(res.punycodeHostname).toBe('xn--e1afmkfd.xn--p1ai');
    }
  });
});

