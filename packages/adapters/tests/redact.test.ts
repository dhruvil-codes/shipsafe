/** Unit tests for redactSecrets secret-scrubbing heuristics. */
import { describe, expect, it } from 'vitest';
import { redactSecrets } from '../src/index';

describe('redactSecrets', () => {
  it('redacts Bearer tokens and Authorization headers in text', () => {
    expect(redactSecrets('Authorization: Bearer abc.def.ghi')).toBe('Authorization: Bearer [REDACTED]');
    expect(redactSecrets('token was Bearer abc123 here')).toBe('token was Bearer [REDACTED] here');
  });

  it('redacts key=value secret assignments and query strings', () => {
    expect(redactSecrets('api_key=sk-live-1234 ok')).toBe('api_key=[REDACTED] ok');
    expect(redactSecrets('https://x.example/cb?token=abc&next=/')).toBe(
      'https://x.example/cb?token=[REDACTED]&next=/',
    );
  });

  it('redacts Set-Cookie values but keeps cookie names', () => {
    const out = redactSecrets('Set-Cookie: sess=deadbeef; Path=/; HttpOnly') as string;
    expect(out).toContain('sess=[REDACTED]');
    expect(out).not.toContain('deadbeef');
  });

  it('redacts secret-named object keys and recurses into nesting', () => {
    const out = redactSecrets({
      api_key: 'sk-123',
      nested: { password: 'hunter2', safe: 'visible' },
      list: [{ token: 't-1' }],
    });
    expect(out).toEqual({
      api_key: '[REDACTED]',
      nested: { password: '[REDACTED]', safe: 'visible' },
      list: [{ token: '[REDACTED]' }],
    });
  });

  it('redacts Cookie-header values per pair and {name,value} cookie entries', () => {
    expect(redactSecrets({ Cookie: 'a=1; b=2' })).toEqual({ Cookie: 'a=[REDACTED]; b=[REDACTED]' });
    expect(redactSecrets({ name: 'sessionid', value: 'abc' })).toEqual({
      name: 'sessionid',
      value: '[REDACTED]',
    });
    // Non-sensitive pairs survive.
    expect(redactSecrets({ name: 'theme', value: 'dark' })).toEqual({ name: 'theme', value: 'dark' });
  });

  it('passes through non-secret scalars and benign text untouched', () => {
    expect(redactSecrets(42)).toBe(42);
    expect(redactSecrets(null)).toBe(null);
    expect(redactSecrets('plain text without secrets')).toBe('plain text without secrets');
  });
});
