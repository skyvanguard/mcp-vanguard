import { z } from 'zod';

export const whoisSchema = z.object({
  target: z.string().describe('Domain or IP address to lookup')
});

export type WhoisInput = z.infer<typeof whoisSchema>;

interface WhoisResult {
  domain?: string;
  registrar?: string;
  registrant?: string;
  createdDate?: string;
  updatedDate?: string;
  expiresDate?: string;
  nameServers?: string[];
  status?: string[];
  rawText: string;
}

export async function whoisLookup(input: WhoisInput): Promise<{
  success: boolean;
  target: string;
  data: WhoisResult | null;
  error?: string;
}> {
  const { target } = input;

  try {
    const url = `https://whois.arin.net/rest/ip/${encodeURIComponent(target)}`;

    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target);

    if (isIP) {
      return await queryArinWhois(target);
    } else {
      return await queryDomainWhois(target);
    }
  } catch (err) {
    return {
      success: false,
      target,
      data: null,
      error: err instanceof Error ? err.message : 'WHOIS lookup failed'
    };
  }
}

async function queryArinWhois(ip: string): Promise<{
  success: boolean;
  target: string;
  data: WhoisResult | null;
  error?: string;
}> {
  const url = `https://whois.arin.net/rest/ip/${encodeURIComponent(ip)}.json`;

  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'mcp-vanguard/1.0'
    }
  });

  if (!response.ok) {
    return {
      success: false,
      target: ip,
      data: null,
      error: `ARIN WHOIS returned ${response.status}`
    };
  }

  const data = await response.json() as {
    net?: {
      name?: { $: string };
      orgRef?: { '@name': string };
      registrationDate?: { $: string };
      updateDate?: { $: string };
      netBlocks?: {
        netBlock?: {
          startAddress?: { $: string };
          endAddress?: { $: string };
        };
      };
    };
  };

  const result: WhoisResult = {
    rawText: JSON.stringify(data, null, 2)
  };

  if (data.net) {
    result.registrant = data.net.orgRef?.['@name'];
    result.createdDate = data.net.registrationDate?.$;
    result.updatedDate = data.net.updateDate?.$;
  }

  return {
    success: true,
    target: ip,
    data: result
  };
}

async function queryDomainWhois(domain: string): Promise<{
  success: boolean;
  target: string;
  data: WhoisResult | null;
  error?: string;
}> {
  const rootDomain = extractRootDomain(domain);

  const rdapServers = [
    `https://rdap.verisign.com/com/v1/domain/${rootDomain}`,
    `https://rdap.verisign.com/net/v1/domain/${rootDomain}`,
    `https://rdap.org/domain/${rootDomain}`,
  ];

  let lastError = '';

  for (const url of rdapServers) {
    try {
      const response = await fetch(url, {
        headers: {
          'Accept': 'application/rdap+json',
          'User-Agent': 'mcp-vanguard/1.0'
        }
      });

      if (!response.ok) {
        lastError = `Server returned ${response.status}`;
        continue;
      }

      const data = await response.json() as {
        ldhName?: string;
        handle?: string;
        status?: string[];
        events?: Array<{ eventAction: string; eventDate: string }>;
        nameservers?: Array<{ ldhName: string }>;
        entities?: Array<{
          roles?: string[];
          vcardArray?: [string, Array<[string, unknown, string, string]>];
        }>;
      };

      const result: WhoisResult = {
        domain: data.ldhName || rootDomain,
        status: data.status,
        rawText: JSON.stringify(data, null, 2)
      };

      if (data.events) {
        for (const event of data.events) {
          if (event.eventAction === 'registration') {
            result.createdDate = event.eventDate;
          } else if (event.eventAction === 'last changed' || event.eventAction === 'last update of RDAP database') {
            result.updatedDate = event.eventDate;
          } else if (event.eventAction === 'expiration') {
            result.expiresDate = event.eventDate;
          }
        }
      }

      if (data.nameservers) {
        result.nameServers = data.nameservers.map(ns => ns.ldhName);
      }

      if (data.entities) {
        for (const entity of data.entities) {
          if (entity.roles?.includes('registrar')) {
            if (entity.vcardArray && entity.vcardArray[1]) {
              const fnField = entity.vcardArray[1].find(
                (f: [string, unknown, string, string]) => f[0] === 'fn'
              );
              if (fnField) {
                result.registrar = fnField[3];
              }
            }
          }
        }
      }

      return {
        success: true,
        target: domain,
        data: result
      };
    } catch (err) {
      lastError = err instanceof Error ? err.message : 'Request failed';
      continue;
    }
  }

  return {
    success: false,
    target: domain,
    data: null,
    error: `All RDAP servers failed: ${lastError}`
  };
}

function extractRootDomain(domain: string): string {
  const parts = domain.toLowerCase().split('.');

  if (parts.length >= 2) {
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];

    const ccTldWithSecondLevel = ['co.uk', 'com.br', 'com.au', 'co.nz', 'co.jp'];
    const combined = `${sld}.${tld}`;

    if (ccTldWithSecondLevel.includes(combined) && parts.length >= 3) {
      return `${parts[parts.length - 3]}.${combined}`;
    }

    return `${sld}.${tld}`;
  }

  return domain;
}
