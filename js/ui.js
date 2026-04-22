export const els = {
  form: document.querySelector('#search-form'),
  input: document.querySelector('#query-input'),
  searchBtn: document.querySelector('#search-btn'),
  typeBadge: document.querySelector('#type-badge'),
  settingsBtn: document.querySelector('#settings-btn'),
  bannerSettingsBtn: document.querySelector('#banner-settings-btn'),
  noKeysBanner: document.querySelector('#no-keys-banner'),
  apiStatus: document.querySelector('#api-status'),
  results: document.querySelector('#results'),
  emptyState: document.querySelector('#empty-state'),
  resultsQuery: document.querySelector('#results-query'),
  resultsTypeBadge: document.querySelector('#results-type-badge'),
  verdictBadge: document.querySelector('#verdict-badge'),
  cards: document.querySelector('#cards'),
  osintLinks: document.querySelector('#osint-links'),
  historyList: document.querySelector('#history-list'),
  clearHistoryBtn: document.querySelector('#clear-history-btn'),
  exportJsonBtn: document.querySelector('#export-json-btn'),
  exportMdBtn: document.querySelector('#export-md-btn'),
  printReportBtn: document.querySelector('#print-report-btn'),
  modal: document.querySelector('#modal-overlay'),
  closeModal: document.querySelector('#close-modal'),
  saveKeysBtn: document.querySelector('#save-keys-btn'),
  clearKeysBtn: document.querySelector('#clear-keys-btn'),
  vtKeyInput: document.querySelector('#vt-key-input'),
  abuseKeyInput: document.querySelector('#abuse-key-input'),
  shodanKeyInput: document.querySelector('#shodan-key-input'),
  toast: document.querySelector('#toast'),
};

export function renderKeyState(keys) {
  const active = Object.values(keys).filter(Boolean);
  els.noKeysBanner.classList.toggle('hidden', active.length > 0);
  els.apiStatus.innerHTML = [
    statusDot('VT', Boolean(keys.virustotal)),
    statusDot('Abuse', Boolean(keys.abuseipdb)),
    statusDot('Shodan', Boolean(keys.shodan)),
  ].join('');
}

export function openModal(keys) {
  els.vtKeyInput.value = keys.virustotal;
  els.abuseKeyInput.value = keys.abuseipdb;
  els.shodanKeyInput.value = keys.shodan;
  els.modal.classList.remove('hidden');
  els.vtKeyInput.focus();
}

export function closeModal() {
  els.modal.classList.add('hidden');
}

export function getModalKeys() {
  return {
    virustotal: els.vtKeyInput.value.trim(),
    abuseipdb: els.abuseKeyInput.value.trim(),
    shodan: els.shodanKeyInput.value.trim(),
  };
}

export function setBadge(element, type) {
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

export function renderResultsShell(query, type, count) {
  els.emptyState.classList.add('hidden');
  els.results.classList.remove('hidden');
  els.resultsQuery.textContent = query;
  setBadge(els.resultsTypeBadge, type);
  els.verdictBadge.className = 'verdict-badge verdict-unknown';
  els.verdictBadge.textContent = 'Analyzing';
  els.cards.innerHTML = buildLoadingCards(count);
}

export function renderVerdict(verdict) {
  const labels = {
    clean: 'Likely clean',
    suspicious: 'Suspicious',
    malicious: 'Malicious',
    unknown: 'Unknown',
  };

  els.verdictBadge.className = `verdict-badge verdict-${verdict}`;
  els.verdictBadge.textContent = labels[verdict] || labels.unknown;
}

export function renderHistory(items) {
  if (!items.length) {
    els.historyList.innerHTML = '<p class="history-empty">No local history yet.</p>';
    return;
  }

  els.historyList.innerHTML = items.map((item) => `
    <button class="history-item" type="button" data-history-query="${escapeHtml(item.query)}">
      <span class="history-query">${escapeHtml(item.query)}</span>
      <span class="history-meta">
        <span>${escapeHtml(item.type)}</span>
        <span class="history-verdict-${escapeHtml(item.verdict)}">${escapeHtml(item.verdict)}</span>
      </span>
      <span class="history-meta">${escapeHtml(formatDate(item.date))}</span>
    </button>
  `).join('');
}

export function renderOsintLinks(query, type) {
  const encoded = encodeURIComponent(query);
  const links = [
    ['VirusTotal', `https://www.virustotal.com/gui/search/${encoded}`, 'Cross-check results'],
    ['AlienVault OTX', `https://otx.alienvault.com/indicator/${type === 'ip' ? 'ip' : type}/${encoded}`, 'Pulses and references'],
    ['GreyNoise', `https://viz.greynoise.io/query/?gnql=${encoded}`, 'Internet noise context'],
    ['Censys', `https://search.censys.io/search?resource=hosts&q=${encoded}`, 'Exposure search'],
    ['URLhaus', `https://urlhaus.abuse.ch/browse.php?search=${encoded}`, 'Malware URL intel'],
    ['MISP/OpenCTI', `https://www.google.com/search?q=${encoded}+MISP+OpenCTI`, 'Future CTI pivot'],
  ];

  els.osintLinks.innerHTML = links.map(([name, href, note]) => `
    <a class="osint-link" href="${href}" target="_blank" rel="noopener">
      <strong>${escapeHtml(name)}</strong>
      <span>${escapeHtml(note)}</span>
    </a>
  `).join('');
}

export function setLoading(isLoading) {
  els.searchBtn.disabled = isLoading;
  els.searchBtn.textContent = isLoading ? 'Analyzing...' : 'Analyze';
}

export function showToast(message) {
  els.toast.textContent = message;
  els.toast.classList.add('show');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => els.toast.classList.remove('show'), 2600);
}

export function cardHeader(title, source) {
  return `
    <div class="card-header">
      <div class="card-title">${escapeHtml(title)}</div>
      <span class="card-source">${escapeHtml(source)}</span>
    </div>
  `;
}

export function missingKeyCard(title, source, message) {
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

export function errorCard(title, message, source = 'API') {
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

export function buildLoadingCards(count) {
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

export function circleGauge(value, color, size, strokeWidth, showText) {
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

export function statBox(label, value, className) {
  return `
    <div class="vt-stat">
      <span class="vt-stat-label">${escapeHtml(label)}</span>
      <span class="vt-stat-value ${className}">${escapeHtml(String(value))}</span>
    </div>
  `;
}

export function vendorList(vendors) {
  return `
    <div class="vendors">
      <div class="vendors-title">Flagged by</div>
      ${vendors.map(([name, value]) => `
        <span class="vendor-tag ${value.category === 'malicious' ? 'vendor-mal' : 'vendor-susp'}">${escapeHtml(name)}</span>
      `).join('')}
    </div>
  `;
}

export function simpleTags(title, values, className) {
  return `
    <div class="vendors">
      <div class="vendors-title">${escapeHtml(title)}</div>
      ${values.map((value) => `<span class="vendor-tag ${className}">${escapeHtml(String(value))}</span>`).join('')}
    </div>
  `;
}

export function metaLine(label, value) {
  return `<span>${escapeHtml(label)} <em>${escapeHtml(String(value ?? 'n/a'))}</em></span>`;
}

export function dataRow(label, value, rowClass = 'abuse-meta-row') {
  return `<div class="${rowClass}"><span>${escapeHtml(label)}</span><span>${escapeHtml(String(value ?? 'n/a'))}</span></div>`;
}

export function severityColor(score) {
  if (score >= 70) return '#FF4444';
  if (score >= 20) return '#FFB800';
  return '#00FF7F';
}

export function formatDate(value) {
  if (!value) return 'n/a';
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return 'n/a';
  return date.toLocaleString();
}

export function countryFlag(countryCode) {
  if (!/^[A-Z]{2}$/i.test(countryCode)) return '??';
  return countryCode.toUpperCase().replace(/./g, (char) => String.fromCodePoint(127397 + char.charCodeAt(0)));
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function statusDot(label, enabled) {
  return `<span class="status-dot ${enabled ? 'active' : ''}">${escapeHtml(label)}</span>`;
}
