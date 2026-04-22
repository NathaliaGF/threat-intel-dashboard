const STORAGE_KEYS = {
  virustotal: 'tidb_virustotal_key',
  abuseipdb: 'tidb_abuseipdb_key',
  shodan: 'tidb_shodan_key',
};

const state = {
  keys: loadKeys(),
  lastController: null,
};

const els = {
  form: document.querySelector('#search-form'),
  input: document.querySelector('#query-input'),
  searchBtn: document.querySelector('#search-btn'),
  typeBadge: document.querySelector('#type-badge'),
  settingsBtn: document.querySelector('#settings-btn'),
  bannerSettingsBtn: document.querySelector('#banner-settings-btn'),
  noKeysBanner: document.querySelector('#no-keys-banner'),
  apiStatus: document.querySelector('#api-status'),
  results: document.querySelector('#results'),
  resultsQuery: document.querySelector('#results-query'),
  resultsTypeBadge: document.querySelector('#results-type-badge'),
  verdictBadge: document.querySelector('#verdict-badge'),
  cards: document.querySelector('#cards'),
  modal: document.querySelector('#modal-overlay'),
  closeModal: document.querySelector('#close-modal'),
  saveKeysBtn: document.querySelector('#save-keys-btn'),
  clearKeysBtn: document.querySelector('#clear-keys-btn'),
  vtKeyInput: document.querySelector('#vt-key-input'),
  abuseKeyInput: document.querySelector('#abuse-key-input'),
  shodanKeyInput: document.querySelector('#shodan-key-input'),
  toast: document.querySelector('#toast'),
};

document.addEventListener('DOMContentLoaded', init);

function init() {
  renderKeyState();
  updateTypeBadge();

  els.form.addEventListener('submit', handleSearch);
  els.input.addEventListener('input', updateTypeBadge);
  els.settingsBtn.addEventListener('click', openModal);
  els.bannerSettingsBtn.addEventListener('click', openModal);
  els.closeModal.addEventListener('click', closeModal);
  els.modal.addEventListener('click', (event) => {
    if (event.target === els.modal) closeModal();
  });
  els.saveKeysBtn.addEventListener('click', saveKeys);
  els.clearKeysBtn.addEventListener('click', clearKeys);

  document.querySelectorAll('[data-q]').forEach((button) => {
    button.addEventListener('click', () => {
      els.input.value = button.dataset.q;
      updateTypeBadge();
      els.form.requestSubmit();
    });
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeModal();
  });
}

async function handleSearch(event) {
  event.preventDefault();

  const query = normalizeQuery(els.input.value);
  const type = detectType(query);

  if (!query || type === 'unknown') {
    showToast('Enter a valid IP, domain, MD5, SHA-1 or SHA-256.');
    return;
  }

  if (state.lastController) state.lastController.abort();
  state.lastController = new AbortController();

  els.input.value = query;
  setLoading(true);
  renderResultsShell(query, type);

  const jobs = buildLookupJobs(query, type, state.lastController.signal);
  const settled = await Promise.allSettled(jobs.map((job) => job.run()));
  const cards = settled.map((result, index) => {
    const job = jobs[index];
    if (result.status === 'fulfilled') return result.value;
    return errorCard(job.title, readableError(result.reason), job.source);
  });

  els.cards.innerHTML = cards.join('');
  renderVerdict(calculateVerdict(settled));
  setLoading(false);
}

function buildLookupJobs(query, type, signal) {
  const jobs = [];

  if (state.keys.virustotal) {
    jobs.push({
      title: 'VirusTotal',
      source: 'VT',
      run: () => lookupVirusTotal(query, type, signal),
    });
  } else {
    jobs.push({
      title: 'VirusTotal',
      source: 'VT',
      run: async () => missingKeyCard('VirusTotal', 'VT', 'Add a VirusTotal key to scan IPs, domains and hashes.'),
    });
  }

  if (type === 'ip') {
    jobs.push({
      title: 'IPinfo',
      source: 'Geo',
      run: () => lookupIpInfo(query, signal),
    });

    if (state.keys.abuseipdb) {
      jobs.push({
        title: 'AbuseIPDB',
        source: 'Abuse',
        run: () => lookupAbuseIpDb(query, signal),
      });
    } else {
      jobs.push({
        title: 'AbuseIPDB',
        source: 'Abuse',
        run: async () => missingKeyCard('AbuseIPDB', 'Abuse', 'Add an AbuseIPDB key to check IP abuse confidence.'),
      });
    }

    if (state.keys.shodan) {
      jobs.push({
        title: 'Shodan',
        source: 'Shodan',
        run: () => lookupShodan(query, signal),
      });
    } else {
      jobs.push({
        title: 'Shodan',
        source: 'Shodan',
        run: async () => missingKeyCard('Shodan', 'Shodan', 'Add a Shodan key to enumerate exposed services.'),
      });
    }
  }

  return jobs;
}

async function lookupVirusTotal(query, type, signal) {
  const vtType = type === 'ip' ? 'ip_addresses' : type === 'domain' ? 'domains' : 'files';
  const encoded = encodeURIComponent(query);
  const json = await fetchJson(`https://www.virustotal.com/api/v3/${vtType}/${encoded}`, {
    headers: { 'x-apikey': state.keys.virustotal },
    signal,
  });

  const attrs = json.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const results = attrs.last_analysis_results || {};
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const harmless = Number(stats.harmless || 0);
  const undetected = Number(stats.undetected || 0);
  const total = malicious + suspicious + harmless + undetected;
  const risk = total ? Math.round(((malicious + suspicious) / total) * 100) : 0;
  const vendors = Object.entries(results)
    .filter(([, value]) => ['malicious', 'suspicious'].includes(value.category))
    .slice(0, 8);

  return `
    <article class="card" data-severity="${severityFromCounts(malicious, suspicious)}">
      ${cardHeader('VirusTotal', 'VT')}
      <div class="vt-gauge-wrap">
        ${circleGauge(risk, severityColor(risk), 92, 8, true)}
        <div class="gauge-label">${risk}% detection ratio</div>
      </div>
      <div class="vt-stats">
        ${statBox('Malicious', malicious, 'stat-malicious')}
        ${statBox('Suspicious', suspicious, 'stat-suspicious')}
        ${statBox('Harmless', harmless, 'stat-harmless')}
        ${statBox('Undetected', undetected, 'stat-undetected')}
      </div>
      <div class="vt-meta">
        ${metaLine('Reputation', attrs.reputation ?? 'n/a')}
        ${metaLine('Last analysis', formatDate(attrs.last_analysis_date))}
      </div>
      ${vendors.length ? vendorList(vendors) : ''}
    </article>
  `;
}

async function lookupAbuseIpDb(ip, signal) {
  const url = new URL('https://api.abuseipdb.com/api/v2/check');
  url.searchParams.set('ipAddress', ip);
  url.searchParams.set('maxAgeInDays', '90');
  url.searchParams.set('verbose', '');

  const json = await fetchJson(url.toString(), {
    headers: {
      Key: state.keys.abuseipdb,
      Accept: 'application/json',
    },
    signal,
  });

  const data = json.data || {};
  const score = Number(data.abuseConfidenceScore || 0);
  const severity = score >= 70 ? 'malicious' : score >= 20 ? 'suspicious' : 'clean';

  return `
    <article class="card" data-severity="${severity}">
      ${cardHeader('AbuseIPDB', 'Abuse')}
      <div class="abuse-score-wrap">
        <div class="abuse-score-ring ${scoreClass(score)}">
          ${circleGauge(score, severityColor(score), 100, 9, false)}
          <div class="abuse-score-num">${score}</div>
          <div class="abuse-score-pct">score</div>
        </div>
        <div class="abuse-label">Abuse confidence</div>
      </div>
      <div class="abuse-meta">
        ${abuseRow('Reports', data.totalReports ?? 0)}
        ${abuseRow('Country', data.countryCode || 'n/a')}
        ${abuseRow('ISP', data.isp || 'n/a')}
        ${abuseRow('Usage', data.usageType || 'n/a')}
        ${abuseRow('Last report', formatDate(data.lastReportedAt))}
      </div>
    </article>
  `;
}

async function lookupShodan(ip, signal) {
  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(state.keys.shodan)}`;
  const data = await fetchJson(url, { signal });
  const ports = Array.isArray(data.ports) ? data.ports : [];
  const tags = Array.isArray(data.tags) ? data.tags : [];
  const services = Array.isArray(data.data) ? data.data.slice(0, 5) : [];
  const severity = ports.length >= 8 || tags.some((tag) => /malware|compromised|vpn|proxy/i.test(tag)) ? 'suspicious' : 'unknown';

  return `
    <article class="card" data-severity="${severity}">
      ${cardHeader('Shodan', 'Shodan')}
      <div class="abuse-meta">
        ${abuseRow('Organization', data.org || data.isp || 'n/a')}
        ${abuseRow('Open ports', ports.length ? ports.join(', ') : 'None indexed')}
        ${abuseRow('Hostnames', data.hostnames?.length ? data.hostnames.slice(0, 3).join(', ') : 'n/a')}
        ${abuseRow('OS', data.os || 'n/a')}
        ${abuseRow('Updated', data.last_update ? new Date(data.last_update).toLocaleString() : 'n/a')}
      </div>
      ${tags.length ? simpleTags('Tags', tags.slice(0, 8), 'vendor-susp') : ''}
      ${services.length ? simpleTags('Services', services.map((item) => `${item.port}/${item.transport || 'tcp'}`), 'vendor-mal') : ''}
    </article>
  `;
}

async function lookupIpInfo(ip, signal) {
  const data = await fetchJson(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, { signal });
  const country = data.country || 'n/a';

  return `
    <article class="card" data-severity="unknown">
      ${cardHeader('IPinfo', 'Geo')}
      <div class="geo-flag">${countryFlag(country)}</div>
      <div class="geo-country">${escapeHtml([data.city, data.region, country].filter(Boolean).join(', ') || 'Unknown location')}</div>
      <div class="geo-rows">
        ${geoRow('ASN / Org', data.org || 'n/a')}
        ${geoRow('Timezone', data.timezone || 'n/a')}
        ${geoRow('Coordinates', data.loc || 'n/a')}
        ${geoRow('Hostname', data.hostname || 'n/a')}
      </div>
    </article>
  `;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
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
    const message = payload.error?.message || payload.errors?.[0]?.detail || payload.detail || response.statusText;
    throw new Error(`${response.status} ${message}`);
  }

  return payload;
}

function renderResultsShell(query, type) {
  els.results.classList.remove('hidden');
  els.resultsQuery.textContent = query;
  setBadge(els.resultsTypeBadge, type);
  els.verdictBadge.className = 'verdict-badge verdict-unknown';
  els.verdictBadge.textContent = 'Analyzing';
  els.cards.innerHTML = buildLoadingCards(type === 'ip' ? 4 : 1);
}

function buildLoadingCards(count) {
  return Array.from({ length: count }, (_, index) => `
    <article class="card" aria-label="Loading source ${index + 1}">
      <div class="card-header">
        <div class="skeleton skel-line" style="width: 120px"></div>
        <div class="skeleton skel-line" style="width: 46px"></div>
      </div>
      <div class="skeleton skel-circle"></div>
      <div class="skeleton skel-line"></div>
      <div class="skeleton skel-line" style="width: 80%"></div>
      <div class="skeleton skel-line" style="width: 65%"></div>
    </article>
  `).join('');
}

function calculateVerdict(settled) {
  const severities = settled
    .filter((result) => result.status === 'fulfilled')
    .map((result) => {
      const match = String(result.value).match(/data-severity="([^"]+)"/);
      return match ? match[1] : 'unknown';
    });

  if (severities.includes('malicious')) return 'malicious';
  if (severities.includes('suspicious')) return 'suspicious';
  if (severities.includes('clean')) return 'clean';
  return 'unknown';
}

function renderVerdict(verdict) {
  const labels = {
    clean: 'Likely clean',
    suspicious: 'Suspicious',
    malicious: 'Malicious',
    unknown: 'Unknown',
  };

  els.verdictBadge.className = `verdict-badge verdict-${verdict}`;
  els.verdictBadge.textContent = labels[verdict] || labels.unknown;
}

function updateTypeBadge() {
  const type = detectType(normalizeQuery(els.input.value));
  setBadge(els.typeBadge, type);
}

function setBadge(element, type) {
  if (!type || type === 'unknown') {
    element.textContent = '';
    element.removeAttribute('data-type');
    element.classList.add('hidden');
    return;
  }

  element.textContent = type;
  element.dataset.type = type;
  element.classList.remove('hidden');
}

function detectType(value) {
  if (!value) return 'unknown';
  if (isIp(value)) return 'ip';
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) return 'hash';
  if (/^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(value)) return 'domain';
  return 'unknown';
}

function isIp(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function normalizeQuery(value) {
  return value.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
}

function renderKeyState() {
  const active = Object.entries(state.keys).filter(([, value]) => Boolean(value));
  els.noKeysBanner.classList.toggle('hidden', active.length > 0);
  els.apiStatus.innerHTML = [
    statusDot('VT', Boolean(state.keys.virustotal)),
    statusDot('Abuse', Boolean(state.keys.abuseipdb)),
    statusDot('Shodan', Boolean(state.keys.shodan)),
  ].join('');
}

function openModal() {
  els.vtKeyInput.value = state.keys.virustotal;
  els.abuseKeyInput.value = state.keys.abuseipdb;
  els.shodanKeyInput.value = state.keys.shodan;
  els.modal.classList.remove('hidden');
  els.vtKeyInput.focus();
}

function closeModal() {
  els.modal.classList.add('hidden');
}

function saveKeys() {
  state.keys = {
    virustotal: els.vtKeyInput.value.trim(),
    abuseipdb: els.abuseKeyInput.value.trim(),
    shodan: els.shodanKeyInput.value.trim(),
  };

  Object.entries(STORAGE_KEYS).forEach(([name, storageKey]) => {
    if (state.keys[name]) localStorage.setItem(storageKey, state.keys[name]);
    else localStorage.removeItem(storageKey);
  });

  renderKeyState();
  closeModal();
  showToast('API keys saved locally.');
}

function clearKeys() {
  Object.values(STORAGE_KEYS).forEach((key) => localStorage.removeItem(key));
  state.keys = loadKeys();
  renderKeyState();
  closeModal();
  showToast('API keys cleared.');
}

function loadKeys() {
  return {
    virustotal: localStorage.getItem(STORAGE_KEYS.virustotal) || '',
    abuseipdb: localStorage.getItem(STORAGE_KEYS.abuseipdb) || '',
    shodan: localStorage.getItem(STORAGE_KEYS.shodan) || '',
  };
}

function setLoading(isLoading) {
  els.searchBtn.disabled = isLoading;
  els.searchBtn.textContent = isLoading ? 'Analyzing...' : 'Analyze';
}

function showToast(message) {
  els.toast.textContent = message;
  els.toast.classList.add('show');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => els.toast.classList.remove('show'), 2600);
}

function cardHeader(title, source) {
  return `
    <div class="card-header">
      <div class="card-title">${escapeHtml(title)}</div>
      <span class="card-source">${escapeHtml(source)}</span>
    </div>
  `;
}

function missingKeyCard(title, source, message) {
  return `
    <article class="card" data-severity="unknown">
      ${cardHeader(title, source)}
      <div class="card-error">
        <div class="error-icon">!</div>
        <p>${escapeHtml(message)}</p>
      </div>
    </article>
  `;
}

function errorCard(title, message, source = 'API') {
  return `
    <article class="card" data-severity="unknown">
      ${cardHeader(title, source)}
      <div class="card-error">
        <div class="error-icon">!</div>
        <p>Lookup failed. Check the key, quota, network access or browser CORS support for this API.</p>
        <code>${escapeHtml(message)}</code>
      </div>
    </article>
  `;
}

function circleGauge(value, color, size, strokeWidth, showText) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.max(0, Math.min(100, value)) / 100) * circumference;

  return `
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" aria-hidden="true">
      <circle cx="${size / 2}" cy="${size / 2}" r="${radius}" fill="none" stroke="#30363D" stroke-width="${strokeWidth}"/>
      <circle cx="${size / 2}" cy="${size / 2}" r="${radius}" fill="none" stroke="${color}" stroke-width="${strokeWidth}"
        stroke-linecap="round" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"
        transform="rotate(-90 ${size / 2} ${size / 2})"/>
      ${showText ? `<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" fill="${color}" font-size="19" font-weight="800">${value}</text>` : ''}
    </svg>
  `;
}

function statBox(label, value, className) {
  return `
    <div class="vt-stat">
      <span class="vt-stat-label">${escapeHtml(label)}</span>
      <span class="vt-stat-value ${className}">${escapeHtml(String(value))}</span>
    </div>
  `;
}

function vendorList(vendors) {
  return `
    <div class="vendors">
      <div class="vendors-title">Flagged by</div>
      ${vendors.map(([name, value]) => `
        <span class="vendor-tag ${value.category === 'malicious' ? 'vendor-mal' : 'vendor-susp'}">
          ${escapeHtml(name)}
        </span>
      `).join('')}
    </div>
  `;
}

function simpleTags(title, values, className) {
  return `
    <div class="vendors">
      <div class="vendors-title">${escapeHtml(title)}</div>
      ${values.map((value) => `<span class="vendor-tag ${className}">${escapeHtml(String(value))}</span>`).join('')}
    </div>
  `;
}

function metaLine(label, value) {
  return `<span>${escapeHtml(label)} <em>${escapeHtml(String(value ?? 'n/a'))}</em></span>`;
}

function abuseRow(label, value) {
  return `<div class="abuse-meta-row"><span>${escapeHtml(label)}</span><span>${escapeHtml(String(value ?? 'n/a'))}</span></div>`;
}

function geoRow(label, value) {
  return `<div class="geo-row"><span>${escapeHtml(label)}</span><span>${escapeHtml(String(value ?? 'n/a'))}</span></div>`;
}

function statusDot(label, enabled) {
  return `<span class="status-dot ${enabled ? 'active' : ''}">${escapeHtml(label)}</span>`;
}

function severityFromCounts(malicious, suspicious) {
  if (malicious > 0) return 'malicious';
  if (suspicious > 0) return 'suspicious';
  return 'clean';
}

function severityColor(score) {
  if (score >= 70) return '#FF4444';
  if (score >= 20) return '#FFB800';
  return '#00FF7F';
}

function scoreClass(score) {
  if (score >= 70) return 'abuse-score-malicious';
  if (score >= 20) return 'abuse-score-suspicious';
  return 'abuse-score-clean';
}

function formatDate(value) {
  if (!value) return 'n/a';
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return 'n/a';
  return date.toLocaleString();
}

function countryFlag(countryCode) {
  if (!/^[A-Z]{2}$/i.test(countryCode)) return '??';
  return countryCode
    .toUpperCase()
    .replace(/./g, (char) => String.fromCodePoint(127397 + char.charCodeAt(0)));
}

function readableError(error) {
  if (error?.name === 'AbortError') return 'Request canceled.';
  if (error instanceof TypeError && /fetch/i.test(error.message)) {
    return 'Network request blocked or refused. Some public APIs do not allow direct browser calls from static pages.';
  }
  return error?.message || String(error);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
