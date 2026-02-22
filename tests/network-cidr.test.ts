import { describe, it, expect } from 'vitest';
import { networkCidr } from '../src/tools/network/network-cidr.js';

describe('networkCidr', () => {
  describe('info operation', () => {
    it('should return subnet info for /24', async () => {
      const result = await networkCidr({ input: '192.168.1.0/24', operation: 'info' });
      expect(result.success).toBe(true);
      expect(result.subnetInfo).toBeDefined();
      expect(result.subnetInfo!.network).toBe('192.168.1.0');
      expect(result.subnetInfo!.broadcast).toBe('192.168.1.255');
      expect(result.subnetInfo!.firstHost).toBe('192.168.1.1');
      expect(result.subnetInfo!.lastHost).toBe('192.168.1.254');
      expect(result.subnetInfo!.netmask).toBe('255.255.255.0');
      expect(result.subnetInfo!.prefix).toBe(24);
      expect(result.subnetInfo!.totalHosts).toBe(256);
      expect(result.subnetInfo!.usableHosts).toBe(254);
      expect(result.subnetInfo!.ipClass).toBe('C');
      expect(result.subnetInfo!.isPrivate).toBe(true);
    });

    it('should return subnet info for /16', async () => {
      const result = await networkCidr({ input: '10.0.0.0/16', operation: 'info' });
      expect(result.success).toBe(true);
      expect(result.subnetInfo!.network).toBe('10.0.0.0');
      expect(result.subnetInfo!.broadcast).toBe('10.0.255.255');
      expect(result.subnetInfo!.totalHosts).toBe(65536);
      expect(result.subnetInfo!.ipClass).toBe('A');
      expect(result.subnetInfo!.isPrivate).toBe(true);
    });

    it('should detect public IPs', async () => {
      const result = await networkCidr({ input: '8.8.8.0/24', operation: 'info' });
      expect(result.success).toBe(true);
      expect(result.subnetInfo!.isPrivate).toBe(false);
    });

    it('should detect 172.16.0.0/12 as private', async () => {
      const result = await networkCidr({ input: '172.16.0.0/12', operation: 'info' });
      expect(result.success).toBe(true);
      expect(result.subnetInfo!.isPrivate).toBe(true);
    });
  });

  describe('expand operation', () => {
    it('should expand /30 to 4 IPs', async () => {
      const result = await networkCidr({ input: '192.168.1.0/30', operation: 'expand' });
      expect(result.success).toBe(true);
      expect(result.ipList).toHaveLength(4);
      expect(result.ipList).toEqual([
        '192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3'
      ]);
    });

    it('should reject ranges larger than /22', async () => {
      const result = await networkCidr({ input: '10.0.0.0/20', operation: 'expand' });
      expect(result.success).toBe(false);
      expect(result.error).toContain('too large');
    });
  });

  describe('contains operation', () => {
    it('should check if IP is in range', async () => {
      const result = await networkCidr({
        input: '192.168.1.0/24',
        operation: 'contains',
        checkIp: '192.168.1.100'
      });
      expect(result.success).toBe(true);
      expect(result.contains).toBe(true);
    });

    it('should return false for IP outside range', async () => {
      const result = await networkCidr({
        input: '192.168.1.0/24',
        operation: 'contains',
        checkIp: '192.168.2.1'
      });
      expect(result.success).toBe(true);
      expect(result.contains).toBe(false);
    });

    it('should require checkIp parameter', async () => {
      const result = await networkCidr({ input: '192.168.1.0/24', operation: 'contains' });
      expect(result.success).toBe(false);
      expect(result.error).toContain('checkIp');
    });
  });

  describe('error handling', () => {
    it('should reject invalid CIDR', async () => {
      const result = await networkCidr({ input: 'not-a-cidr', operation: 'info' });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid CIDR');
    });

    it('should reject invalid prefix', async () => {
      const result = await networkCidr({ input: '192.168.1.0/33', operation: 'info' });
      expect(result.success).toBe(false);
    });
  });
});
