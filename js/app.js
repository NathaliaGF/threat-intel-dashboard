import { lookupAbuseIpDb, lookupIpInfo, lookupShodan, lookupVirusTotal } from './api.js';
import { detectType, normalizeQuery } from './detectors.js';
import { addHistoryItem, clearHistory, clearKeys, loadHistory, loadKeys, saveKeys } from './storage.js';
import {
  cardHeader,
  circleGauge,
  closeModal,
  countryFlag,
  dataRow,
  els,
  errorCard,
  escapeHtml,
  formatDate,
  getModalKeys,
  metaLine,
  missingKeyCard,
  openModal,
  renderHistory,
  renderKeyState,
  renderOsintLinks,
  renderResultsShell,
  renderVerdict,
  setBadge,
  setLoading,
  severityColor,
  showToast,
  simpleTags,
  statBox,
  vendorList,
} from './ui.js';

const state = {
  keys: loadKeys(),
  history: loadHistory(),
  lastController: null,
  currentReport: null,
};

document.addEventListener('DOMContentLoaded', init);

function init() {
  renderKeyState(state.keys);
  renderHistory(state.history);
  updateTypeBadge();

  els.form.addEventListener('submit', handleSearch);
  els.input.addEventListener('input', updateTypeBadge);
  els.settingsBtn.addEventListener('click', () => openModal(state.keys));
  els.bannerSettingsBtn.addEventListener('click', () => openModal(state.keys));
  els.closeModal.addEventListener('click', closeModal);
  els.modal.addEventListener('click', (event) => {
    if (event.target === els.modal) closeModal();
  });
  els.saveKeysBtn.addEventListener('click', handleSaveKeys);
  els.clearKeysBtn.addEventListener('click', handleClearKeys);
  els.clearHistoryBtn.addEventListener('click', handleClearHistory);
  els.exportJsonBtn.addEventListener('click', exportJson);
  els.exportMdBtn.addEventListener('click', exportMarkdown);
  els.printReportBtn.addEventListener('click', () => window.print());

  els.historyList.addEventListener('click', (event) => {
    const button = event.target.closest('[data-history-query]');
    if (!button) return;
    els.input.value = button.dataset.historyQuery;
    updateTypeBadge();
    els.form.requestSubmit();
  });

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
    showToast('Enter a valid IP, IPv6, domain, URL, MD5, SHA-1 or SHA-256.');
    return;
  }

  if (state.lastController) state.lastController.abort();
  state.lastController = new AbortController();

  els.input.value = query;
  setLoading(true);
  const jobs = buildLookupJobs(query, type, state.lastController.signal);
  renderResultsShell(query, type, jobs.length);
  renderOsintLinks(query, type);

  const startedAt = new Date().toISOString();
  const settled = await Promise.allSettled(jobs.map((job) => job.run()));
  const results = settled.map((result, index) => normalizeJobResult(result, jobs[index]));

  els.cards.innerHTML = results.map((result) => result.html).join('');
  const verdict = calculateVerdict(results);
  renderVerdict(verdict);
  setLoading(false);

  state.currentReport = {
    query,
    type,
    verdict,
    generatedAt: startedAt,
    sources: results.map(({ html, ...result }) => result),
  };

  state.history = addHistoryItem({ query, type, verdict, date: startedAt });
  renderHistory(state.history);
}

function buildLookupJobs(query, type, signal) {
  const jobs = [];

  if (state.keys.virustotal) {
    jobs.push({
      title: 'VirusTotal',
      source: 'VT',
      run: () => lookupVirusTotal(query, type, state.keys.virustotal, signal).then((data) => renderVirusTotal(data)),
    });
  } else {
    jobs.push({
      title: 'VirusTotal',
      source: 'VT',
      run: async () => sourceResult('VirusTotal', 'VT', 'unknown', { status: 'missing-key' }, missingKeyCard('VirusTotal', 'VT', 'Add a VirusTotal key to scan IPs, domains, URLs and hashes.')),
    });
  }

  if (type === 'ip') {
    jobs.push({
      title: 'IPinfo',
      source: 'Geo',
      run: () => lookupIpInfo(query, signal).then((data) => renderIpInfo(data)),
    });

    if (state.keys.abuseipdb) {
      jobs.push({
        title: 'AbuseIPDB',
        source: 'Abuse',
        run: () => lookupAbuseIpDb(query, state.keys.abuseipdb, signal).then((data) => renderAbuseIpDb(data)),
      });
    } else {
      jobs.push({
        title: 'AbuseIPDB',
        source: 'Abuse',
        run: async () => sourceResult('AbuseIPDB', 'Abuse', 'unknown', { status: 'missing-key' }, missingKeyCard('AbuseIPDB', 'Abuse', 'Add an AbuseIPDB key to check IP abuse confidence.')),
      });
    }

    if (state.keys.shodan) {
      jobs.push({
        title: 'Shodan',
        source: 'Shodan',
        run: () => lookupShodan(query, state.keys.shodan, signal).then((data) => renderShodan(data)),
      });
    } else {
      jobs.push({
        title: 'Shodan',
        source: 'Shodan',
        run: async () => sourceResult('Shodan', 'Shodan', 'unknown', { status: 'missing-key' }, missingKeyCard('Shodan', 'Shodan', 'Add a Shodan key to enumerate exposed services.')),
      });
    }
  }

  return jobs;
}

function renderVirusTotal(json) {
  const attrs = json.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const results = attrs.last_analysis_results || {};
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const harmless = Number(stats.harmless || 0);
  const undetected = Number(stats.undetected || 0);
  const total = malicious + suspicious + harmless + undetected;
  const risk = total ? Math.round(((malicious + suspicious) / total) * 100) : 0;
  const vendors = Object.entries(results).filter(([, value]) => ['malicious', 'suspicious'].includes(value.category)).slice(0, 8);
  const severity = malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean';

  const html = `
    <article class="card" data-severity="${severity}">
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

  return sourceResult('VirusTotal', 'VT', severity, { malicious, suspicious, harmless, undetected, risk }, html);
}

function renderAbuseIpDb(json) {
  const data = json.data || {};
  const score = Number(data.abuseConfidenceScore || 0);
  const severity = score >= 70 ? 'malicious' : score >= 20 ? 'suspicious' : 'clean';
  const scoreClass = score >= 70 ? 'abuse-score-malicious' : score >= 20 ? 'abuse-score-suspicious' : 'abuse-score-clean';

  const html = `
    <article class="card" data-severity="${severity}">
      ${cardHeader('AbuseIPDB', 'Abuse')}
      <div class="abuse-score-wrap">
        <div class="abuse-score-ring ${scoreClass}">
          ${circleGauge(score, severityColor(score), 100, 9, false)}
          <div class="abuse-score-num">${score}</div>
          <div class="abuse-score-pct">score</div>
        </div>
        <div class="abuse-label">Abuse confidence</div>
      </div>
      <div class="abuse-meta">
        ${dataRow('Reports', data.totalReports ?? 0)}
        ${dataRow('Country', data.countryCode || 'n/a')}
        ${dataRow('ISP', data.isp || 'n/a')}
        ${dataRow('Usage', data.usageType || 'n/a')}
        ${dataRow('Last report', formatDate(data.lastReportedAt))}
      </div>
    </article>
  `;

  return sourceResult('AbuseIPDB', 'Abuse', severity, data, html);
}

function renderShodan(data) {
  const ports = Array.isArray(data.ports) ? data.ports : [];
  const tags = Array.isArray(data.tags) ? data.tags : [];
  const services = Array.isArray(data.data) ? data.data.slice(0, 5) : [];
  const severity = ports.length >= 8 || tags.some((tag) => /malware|compromised|vpn|proxy/i.test(tag)) ? 'suspicious' : 'unknown';

  const html = `
    <article class="card" data-severity="${severity}">
      ${cardHeader('Shodan', 'Shodan')}
      <div class="abuse-meta">
        ${dataRow('Organization', data.org || data.isp || 'n/a')}
        ${dataRow('Open ports', ports.length ? ports.join(', ') : 'None indexed')}
        ${dataRow('Hostnames', data.hostnames?.length ? data.hostnames.slice(0, 3).join(', ') : 'n/a')}
        ${dataRow('OS', data.os || 'n/a')}
        ${dataRow('Updated', data.last_update ? new Date(data.last_update).toLocaleString() : 'n/a')}
      </div>
      ${tags.length ? simpleTags('Tags', tags.slice(0, 8), 'vendor-susp') : ''}
      ${services.length ? simpleTags('Services', services.map((item) => `${item.port}/${item.transport || 'tcp'}`), 'vendor-mal') : ''}
    </article>
  `;

  return sourceResult('Shodan', 'Shodan', severity, { ports, tags, org: data.org || data.isp }, html);
}

function renderIpInfo(data) {
  const country = data.country || 'n/a';
  const html = `
    <article class="card" data-severity="unknown">
      ${cardHeader('IPinfo', 'Geo')}
      <div class="geo-flag">${countryFlag(country)}</div>
      <div class="geo-country">${escapeHtml([data.city, data.region, country].filter(Boolean).join(', ') || 'Unknown location')}</div>
      <div class="geo-rows">
        ${dataRow('ASN / Org', data.org || 'n/a', 'geo-row')}
        ${dataRow('Timezone', data.timezone || 'n/a', 'geo-row')}
        ${dataRow('Coordinates', data.loc || 'n/a', 'geo-row')}
        ${dataRow('Hostname', data.hostname || 'n/a', 'geo-row')}
      </div>
    </article>
  `;

  return sourceResult('IPinfo', 'Geo', 'unknown', data, html);
}

function normalizeJobResult(result, job) {
  if (result.status === 'fulfilled') return result.value;
  const error = readableError(result.reason);
  return sourceResult(job.title, job.source, 'unknown', { status: 'error', error }, errorCard(job.title, error, job.source));
}

function sourceResult(name, source, severity, summary, html) {
  return { name, source, severity, summary, html };
}

function calculateVerdict(results) {
  const severities = results.map((result) => result.severity);
  if (severities.includes('malicious')) return 'malicious';
  if (severities.includes('suspicious')) return 'suspicious';
  if (severities.includes('clean')) return 'clean';
  return 'unknown';
}

function updateTypeBadge() {
  setBadge(els.typeBadge, detectType(normalizeQuery(els.input.value)));
}

function handleSaveKeys() {
  state.keys = getModalKeys();
  saveKeys(state.keys);
  renderKeyState(state.keys);
  closeModal();
  showToast('API keys saved locally.');
}

function handleClearKeys() {
  clearKeys();
  state.keys = loadKeys();
  renderKeyState(state.keys);
  closeModal();
  showToast('API keys cleared.');
}

function handleClearHistory() {
  clearHistory();
  state.history = [];
  renderHistory(state.history);
}

function exportJson() {
  if (!state.currentReport) return showToast('Run a lookup before exporting.');
  downloadFile(`threat-report-${state.currentReport.query}.json`, JSON.stringify(state.currentReport, null, 2), 'application/json');
}

function exportMarkdown() {
  if (!state.currentReport) return showToast('Run a lookup before exporting.');
  const report = state.currentReport;
  const body = [
    `# Threat Intelligence Report`,
    ``,
    `- IOC: \`${report.query}\``,
    `- Type: ${report.type}`,
    `- Verdict: ${report.verdict}`,
    `- Generated: ${report.generatedAt}`,
    ``,
    `## Sources`,
    ...report.sources.map((source) => [
      ``,
      `### ${source.name}`,
      `- Severity: ${source.severity}`,
      `- Status: ${source.summary.status || 'ok'}`,
      `- Summary:`,
      '```json',
      JSON.stringify(source.summary, null, 2),
      '```',
    ].join('\n')),
  ].join('\n');

  downloadFile(`threat-report-${report.query}.md`, body, 'text/markdown');
}

function downloadFile(filename, content, type) {
  const safeName = filename.replace(/[^a-z0-9_.-]+/gi, '_');
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = safeName;
  link.click();
  URL.revokeObjectURL(url);
}

function readableError(error) {
  if (error?.name === 'AbortError') return 'Request canceled.';
  if (error instanceof TypeError && /fetch/i.test(error.message)) {
    return 'Network request blocked or refused. Some public APIs do not allow direct browser calls from static pages.';
  }
  return error?.message || String(error);
}
