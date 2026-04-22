const STORAGE_KEYS = {
  virustotal: 'tidb_virustotal_key',
  abuseipdb: 'tidb_abuseipdb_key',
  shodan: 'tidb_shodan_key',
  history: 'tidb_lookup_history',
};

export function loadKeys() {
  return {
    virustotal: localStorage.getItem(STORAGE_KEYS.virustotal) || '',
    abuseipdb: localStorage.getItem(STORAGE_KEYS.abuseipdb) || '',
    shodan: localStorage.getItem(STORAGE_KEYS.shodan) || '',
  };
}

export function saveKeys(keys) {
  ['virustotal', 'abuseipdb', 'shodan'].forEach((name) => {
    if (keys[name]) localStorage.setItem(STORAGE_KEYS[name], keys[name]);
    else localStorage.removeItem(STORAGE_KEYS[name]);
  });
}

export function clearKeys() {
  ['virustotal', 'abuseipdb', 'shodan'].forEach((name) => localStorage.removeItem(STORAGE_KEYS[name]));
}

export function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.history)) || [];
  } catch {
    return [];
  }
}

export function saveHistory(items) {
  localStorage.setItem(STORAGE_KEYS.history, JSON.stringify(items.slice(0, 12)));
}

export function addHistoryItem(item) {
  const next = [
    item,
    ...loadHistory().filter((entry) => entry.query !== item.query),
  ].slice(0, 12);
  saveHistory(next);
  return next;
}

export function clearHistory() {
  localStorage.removeItem(STORAGE_KEYS.history);
}
