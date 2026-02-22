import { describe, it, expect, beforeEach } from 'vitest';
import {
  getConfig,
  updateConfig,
  setScope,
  getScope,
  isInScope,
  PermissionTier,
  defaultConfig
} from '../src/config.js';
import { registry } from '../src/registry.js';

// Ensure tools are registered for permission tests
import '../src/tools/recon/index.js';
import '../src/tools/web/index.js';
import '../src/tools/osint/index.js';
import '../src/tools/utils/index.js';
import '../src/tools/network/index.js';
import { reconTools } from '../src/tools/recon/index.js';
import { webTools } from '../src/tools/web/index.js';
import { osintTools } from '../src/tools/osint/index.js';
import { utilsTools } from '../src/tools/utils/index.js';
import { networkTools } from '../src/tools/network/index.js';
import { exploitTools } from '../src/tools/exploit/index.js';
import { cryptoTools } from '../src/tools/crypto/index.js';

// Register tools if not already registered
try {
  registry.registerAll([...reconTools, ...webTools, ...osintTools, ...utilsTools, ...networkTools, ...exploitTools, ...cryptoTools]);
} catch {
  // Already registered
}

describe('Config', () => {
  beforeEach(() => {
    updateConfig(defaultConfig);
    setScope([]);
  });

  describe('getConfig', () => {
    it('should return default configuration', () => {
      const config = getConfig();
      expect(config.wslEnabled).toBe(true);
      expect(config.rateLimitMs).toBe(1000);
      expect(config.timeout).toBe(300000);
    });
  });

  describe('updateConfig', () => {
    it('should update configuration', () => {
      updateConfig({ rateLimitMs: 2000 });
      const config = getConfig();
      expect(config.rateLimitMs).toBe(2000);
    });

    it('should preserve other config values', () => {
      updateConfig({ rateLimitMs: 2000 });
      const config = getConfig();
      expect(config.wslEnabled).toBe(true);
    });
  });
});

describe('Scope', () => {
  beforeEach(() => {
    setScope([]);
  });

  describe('setScope / getScope', () => {
    it('should set and get scope', () => {
      setScope(['example.com', 'test.org']);
      expect(getScope()).toEqual(['example.com', 'test.org']);
    });
  });

  describe('isInScope', () => {
    it('should allow all targets when scope is empty', () => {
      expect(isInScope('anything.com')).toBe(true);
    });

    it('should match exact domain', () => {
      setScope(['example.com']);
      expect(isInScope('example.com')).toBe(true);
      expect(isInScope('other.com')).toBe(false);
    });

    it('should match subdomains of scoped domain', () => {
      setScope(['example.com']);
      expect(isInScope('sub.example.com')).toBe(true);
      expect(isInScope('deep.sub.example.com')).toBe(true);
    });

    it('should handle wildcard scope', () => {
      setScope(['*.example.com']);
      expect(isInScope('sub.example.com')).toBe(true);
      expect(isInScope('example.com')).toBe(true);
    });

    it('should be case insensitive', () => {
      setScope(['Example.COM']);
      expect(isInScope('EXAMPLE.com')).toBe(true);
      expect(isInScope('sub.example.com')).toBe(true);
    });
  });
});

describe('Tool Permissions (via Registry)', () => {
  describe('registry.getPermission', () => {
    it('should return SAFE for passive tools', () => {
      expect(registry.getPermission('vanguard_dns_records')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_whois')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_headers_check')).toBe(PermissionTier.SAFE);
    });

    it('should return DANGEROUS for active tools', () => {
      expect(registry.getPermission('vanguard_port_scan')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_ffuf')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_nuclei_scan')).toBe(PermissionTier.DANGEROUS);
    });

    it('should return SAFE for passive network tools', () => {
      expect(registry.getPermission('vanguard_ftp_check')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_ssh_audit')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_reverse_dns')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_network_cidr')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_http_methods')).toBe(PermissionTier.SAFE);
    });

    it('should return DANGEROUS for active network tools', () => {
      expect(registry.getPermission('vanguard_traceroute')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_ping_sweep')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_service_detect')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_os_detect')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_banner_grab')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_snmp_enum')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_smb_enum')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_ldap_enum')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_dns_zone_transfer')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_arp_scan')).toBe(PermissionTier.DANGEROUS);
    });

    it('should return SAFE for passive OSINT extended tools', () => {
      expect(registry.getPermission('vanguard_email_hunter')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_social_media')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_domain_reputation')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_ip_geolocation')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_asn_lookup')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_google_dorks')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_shodan_search')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_breach_check')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_metadata_extract')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_dns_history')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_favicon_hash')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_web_archive_diff')).toBe(PermissionTier.SAFE);
    });

    it('should return DANGEROUS for all exploit tools', () => {
      expect(registry.getPermission('vanguard_exploit_search')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_reverse_shell_gen')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_sqli_test')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_xss_test')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_ssrf_test')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_lfi_test')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_command_inject_test')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_open_redirect_test')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_crlf_inject_test')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_deserialization_check')).toBe(PermissionTier.DANGEROUS);
    });

    it('should return SAFE for passive crypto tools', () => {
      expect(registry.getPermission('vanguard_hash_identify')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_password_policy')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_jwt_decode')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_crypto_audit')).toBe(PermissionTier.SAFE);
      expect(registry.getPermission('vanguard_base_decode')).toBe(PermissionTier.SAFE);
    });

    it('should return DANGEROUS for active crypto tools', () => {
      expect(registry.getPermission('vanguard_hash_crack')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_jwt_attack')).toBe(PermissionTier.DANGEROUS);
      expect(registry.getPermission('vanguard_password_gen')).toBe(PermissionTier.DANGEROUS);
    });

    it('should return BLOCKED for unknown tools', () => {
      expect(registry.getPermission('unknown_tool')).toBe(PermissionTier.BLOCKED);
    });
  });
});
