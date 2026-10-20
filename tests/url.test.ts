import { describe, it, expect } from 'vitest';
import { extractHost } from '../src/utils/url.js';

describe('extractHost', () => {
  it('extracts hostname from a well-formed URL', () => {
    expect(extractHost('https://example.com/path?q=1')).toBe('example.com');
  });

  it('strips port and path', () => {
    expect(extractHost('http://example.com:8080/a/b')).toBe('example.com');
  });

  it('handles subdomains', () => {
    expect(extractHost('https://api.v2.example.com/')).toBe('api.v2.example.com');
  });

  it('tolerates the ffuf FUZZ placeholder', () => {
    expect(extractHost('https://example.com/FUZZ')).toBe('example.com');
    expect(extractHost('https://FUZZ.example.com/')).toBe('test.example.com');
  });

  it('falls back to a regex when URL() throws, returning the matched host', () => {
    // The space makes new URL() throw; the regex captures up to the first "/" or ":".
    expect(extractHost('http://exa mple.com/path')).toBe('exa mple.com');
  });

  it('returns the input unchanged when nothing can be parsed', () => {
    expect(extractHost('example.com')).toBe('example.com');
  });
});
