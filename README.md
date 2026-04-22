# Threat Intelligence Dashboard

Static threat intelligence dashboard for IP, domain and hash lookups using public security APIs directly from the browser.

## Features

- Detects IPs, domains, MD5, SHA-1 and SHA-256 hashes.
- VirusTotal lookup for IPs, domains and file hashes.
- AbuseIPDB lookup for IP abuse confidence.
- Shodan lookup for indexed IP services and open ports.
- IPinfo geolocation lookup for IPs without requiring an API key.
- API keys are stored only in browser `localStorage`.
- Works as a static site on GitHub Pages.

## Run locally

```bash
python3 -m http.server 8080
```

Open `http://localhost:8080`.

## GitHub Pages

1. Push this folder to a GitHub repository.
2. In the repository, go to `Settings > Pages`.
3. Set source to `Deploy from a branch`.
4. Select branch `main` and folder `/root`.
5. Save and wait for GitHub to publish the site.

## API keys

Open the gear button in the dashboard and paste your API keys:

- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- Shodan: https://account.shodan.io/register

Some APIs may enforce CORS, quota or plan restrictions for direct browser requests. When that happens, the dashboard shows a source-specific error card instead of failing the whole lookup.
