import { vtIdentifier, vtResourceType } from './detectors.js';

export async function fetchJson(url, options = {}) {
  let response;

  try {
    response = await fetch(url, options);
  } catch (error) {
    throw new Error(`Network/CORS: ${error.message}`);
  }

  const text = await response.text();
  let payload = {};

  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw new Error(`Unexpected non-JSON response from ${new URL(url).hostname}`);
    }
  }

  if (!response.ok) {
    throw new Error(classifyApiError(response.status, payload));
  }

  return payload;
}

export function classifyApiError(status, payload = {}) {
  const message = payload.error?.message || payload.errors?.[0]?.detail || payload.detail || payload.message || 'Request failed';

  if (status === 400) return `Invalid request: ${message}`;
  if (status === 401 || status === 403) return `Invalid key or forbidden: ${message}`;
  if (status === 404) return `Not found: no record for this IOC`;
  if (status === 429) return `Rate limited or quota exceeded: ${message}`;
  if (status >= 500) return `Provider error ${status}: ${message}`;
  return `${status}: ${message}`;
}

export async function lookupVirusTotal(query, type, key, signal) {
  const resource = vtResourceType(type);
  const id = encodeURIComponent(vtIdentifier(query, type));
  return fetchJson(`https://www.virustotal.com/api/v3/${resource}/${id}`, {
    headers: { 'x-apikey': key },
    signal,
  });
}

export async function lookupAbuseIpDb(ip, key, signal) {
  const url = new URL('https://api.abuseipdb.com/api/v2/check');
  url.searchParams.set('ipAddress', ip);
  url.searchParams.set('maxAgeInDays', '90');
  url.searchParams.set('verbose', '');

  return fetchJson(url.toString(), {
    headers: {
      Key: key,
      Accept: 'application/json',
    },
    signal,
  });
}

export async function lookupShodan(ip, key, signal) {
  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`;
  return fetchJson(url, { signal });
}

export async function lookupIpInfo(ip, signal) {
  return fetchJson(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, { signal });
}
