import { describe, it, expect, beforeEach } from 'vitest';
import {
  getConfig,
  updateConfig,
  setScope,
  getScope,
  isInScope,
  getToolPermission,
  PermissionTier,
  defaultConfig
} from '../src/config.js';

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

describe('Tool Permissions', () => {
  describe('getToolPermission', () => {
    it('should return SAFE for passive tools', () => {
      expect(getToolPermission('vanguard_dns_records')).toBe(PermissionTier.SAFE);
      expect(getToolPermission('vanguard_whois')).toBe(PermissionTier.SAFE);
      expect(getToolPermission('vanguard_headers_check')).toBe(PermissionTier.SAFE);
    });

    it('should return DANGEROUS for active tools', () => {
      expect(getToolPermission('vanguard_port_scan')).toBe(PermissionTier.DANGEROUS);
      expect(getToolPermission('vanguard_ffuf')).toBe(PermissionTier.DANGEROUS);
      expect(getToolPermission('vanguard_nuclei_scan')).toBe(PermissionTier.DANGEROUS);
    });

    it('should return BLOCKED for unknown tools', () => {
      expect(getToolPermission('unknown_tool')).toBe(PermissionTier.BLOCKED);
    });
  });
});
