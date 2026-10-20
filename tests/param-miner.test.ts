import { describe, it, expect, afterEach, vi } from 'vitest';
import { setScope } from '../src/config.js';
import { paramMinerSchema, paramMiner } from '../src/tools/web/param-miner.js';

// The scope check runs before any network I/O, so an out-of-scope target must be
// rejected without a single fetch. We spy on fetch to assert it is never called.
describe('paramMiner scope enforcement', () => {
  afterEach(() => {
    setScope([]);
    vi.restoreAllMocks();
  });

  it('rejects a target that is not in scope and makes no network request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    setScope(['example.com']);

    const input = paramMinerSchema.parse({ url: 'https://attacker.test/login' });
    const result = await paramMiner(input);

    expect(result.success).toBe(false);
    expect(result.error).toContain('not in scope');
    expect(result.foundParams).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('allows a target that matches the configured scope (past the scope gate)', async () => {
    // Make fetch fail fast so we never do real I/O; we only assert the scope gate
    // let the call through (error is no longer the scope message).
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('network disabled in test'));
    setScope(['example.com']);

    const input = paramMinerSchema.parse({ url: 'https://example.com/' });
    const result = await paramMiner(input);

    expect(fetchSpy).toHaveBeenCalled();
    expect(result.error ?? '').not.toContain('not in scope');
  });
});
