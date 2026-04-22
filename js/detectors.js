export function normalizeQuery(value) {
  const raw = value.trim();
  if (!raw) return '';

  try {
    const parsed = new URL(raw.includes('://') ? raw : `http://${raw}`);
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const path = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : '';
    return raw.includes('/') || raw.includes('://') ? `${host}${path}` : host;
  } catch {
    return raw.replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
  }
}

export function detectType(value) {
  if (!value) return 'unknown';
  if (isIpv4(value) || isIpv6(value)) return 'ip';
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) return 'hash';
  if (isUrlPath(value)) return 'url';
  if (isDomain(value)) return 'domain';
  return 'unknown';
}

export function isIpv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

export function isIpv6(value) {
  if (!value.includes(':')) return false;
  const full = /^([a-f0-9]{1,4}:){7}[a-f0-9]{1,4}$/i;
  const compressed = /^(([a-f0-9]{1,4}:){1,7}|:):(([a-f0-9]{1,4}:){1,7}|:)?[a-f0-9]{0,4}$/i;
  return full.test(value) || (value.includes('::') && compressed.test(value));
}

export function isDomain(value) {
  if (value.length > 253 || value.includes('/')) return false;
  return /^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(value)
    && value.split('.').every((label) => !label.endsWith('-'));
}

export function isUrlPath(value) {
  const slashIndex = value.indexOf('/');
  if (slashIndex === -1) return false;
  return isDomain(value.slice(0, slashIndex));
}

export function vtResourceType(type) {
  if (type === 'ip') return 'ip_addresses';
  if (type === 'domain') return 'domains';
  if (type === 'url') return 'urls';
  return 'files';
}

export function vtIdentifier(query, type) {
  if (type !== 'url') return query;
  return btoa(query).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
