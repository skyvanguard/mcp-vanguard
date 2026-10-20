import { describe, it, expect, afterEach, vi } from 'vitest';
import { setScope } from '../src/config.js';

import { headersCheckSchema, headersCheck } from '../src/tools/web/headers.js';
import { techDetectSchema, techDetect } from '../src/tools/web/tech-detect.js';
import { corsCheckSchema, corsCheck } from '../src/tools/web/cors-check.js';
import { robotsSitemapSchema, robotsSitemap } from '../src/tools/web/robots-sitemap.js';
import { jsEndpointsSchema, jsEndpoints } from '../src/tools/web/js-endpoints.js';
import { faviconHashSchema, faviconHash } from '../src/tools/osint/favicon-hash.js';
import { metadataExtractSchema, metadataExtract } from '../src/tools/osint/metadata-extract.js';
import { passwordGenSchema, passwordGen } from '../src/tools/crypto/password-gen.js';

// Each entry runs a tool against a target that is NOT in the configured scope.
// The scope gate must short-circuit before any network / subprocess I/O.
const OUT_OF_SCOPE = 'http://attacker.test/path';

const cases: Array<{ name: string; run: () => Promise<{ success: boolean; error?: string }> }> = [
  { name: 'headers_check', run: () => headersCheck(headersCheckSchema.parse({ url: OUT_OF_SCOPE })) },
  { name: 'tech_detect', run: () => techDetect(techDetectSchema.parse({ url: OUT_OF_SCOPE })) },
  { name: 'cors_check', run: () => corsCheck(corsCheckSchema.parse({ url: OUT_OF_SCOPE })) },
  { name: 'robots_sitemap', run: () => robotsSitemap(robotsSitemapSchema.parse({ url: OUT_OF_SCOPE })) },
  { name: 'js_endpoints', run: () => jsEndpoints(jsEndpointsSchema.parse({ url: OUT_OF_SCOPE })) },
  { name: 'favicon_hash', run: () => faviconHash(faviconHashSchema.parse({ url: OUT_OF_SCOPE })) },
  { name: 'metadata_extract', run: () => metadataExtract(metadataExtractSchema.parse({ url: OUT_OF_SCOPE })) },
  { name: 'password_gen (cewl)', run: () => passwordGen(passwordGenSchema.parse({ mode: 'wordlist', url: OUT_OF_SCOPE })) }
];

describe('scope enforcement on target-touching tools', () => {
  afterEach(() => {
    setScope([]);
    vi.restoreAllMocks();
  });

  for (const { name, run } of cases) {
    it(`${name} refuses an out-of-scope target without any network call`, async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      setScope(['example.com']);

      const result = await run();

      expect(result.success).toBe(false);
      expect(result.error ?? '').toContain('not in scope');
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  }

  it('allows an in-scope target through the scope gate', async () => {
    // fetch is stubbed to fail fast: we only assert the gate did not block.
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network disabled in test'));
    setScope(['example.com']);

    const result = await headersCheck(headersCheckSchema.parse({ url: 'https://example.com/' }));

    expect(result.error ?? '').not.toContain('not in scope');
  });
});
