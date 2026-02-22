import { z } from 'zod';

export const ipGeolocationSchema = z.object({
  ip: z.string().describe('IP address to geolocate'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds')
});

export type IpGeolocationInput = z.infer<typeof ipGeolocationSchema>;

interface GeoResult {
  ip: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
  org?: string;
  asn?: string;
  timezone?: string;
}

export async function ipGeolocation(input: IpGeolocationInput): Promise<{
  success: boolean;
  result: GeoResult;
  error?: string;
}> {
  const { ip, timeout } = input;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    // ip-api.com is free, no key required, 45 req/min
    const response = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as`,
      {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal
      }
    );
    clearTimeout(timer);

    if (!response.ok) {
      return { success: false, result: { ip }, error: `API returned ${response.status}` };
    }

    const data = await response.json() as {
      status: string;
      message?: string;
      country?: string;
      countryCode?: string;
      regionName?: string;
      city?: string;
      lat?: number;
      lon?: number;
      timezone?: string;
      isp?: string;
      org?: string;
      as?: string;
    };

    if (data.status === 'fail') {
      return { success: false, result: { ip }, error: data.message || 'Geolocation failed' };
    }

    return {
      success: true,
      result: {
        ip,
        country: data.country,
        countryCode: data.countryCode,
        region: data.regionName,
        city: data.city,
        latitude: data.lat,
        longitude: data.lon,
        isp: data.isp,
        org: data.org,
        asn: data.as,
        timezone: data.timezone
      }
    };
  } catch (err) {
    return {
      success: false,
      result: { ip },
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}
