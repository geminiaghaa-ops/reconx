# ReconX

A bug bounty **recon orchestrator** with a live **target-health monitor** and a
**web dashboard**. ReconX glues together best-in-class community tools and adds
its own JavaScript analysis, scope enforcement, result storage, diffing, and
notifications. When a preferred external tool isn't installed, a built-in
pure-Python fallback keeps the stage working.

> Only run ReconX against assets you are **authorized** to test (your own
> systems, or targets explicitly in scope for a bug bounty program). Scope rules
> are enforced on every host/URL before it is touched.

## Features

- **Scope enforcement** — in/out-of-scope rules (with wildcards) gate every stage.
- **Subdomain enumeration** — `subfinder` / `assetfinder` / `amass`, always merged with Certificate Transparency (crt.sh).
- **DNS resolution + wildcard detection** — `dnsx`, or built-in resolver (A + CNAME); flags wildcard zones so fake hosts aren't trusted.
- **Port scanning** — `naabu`, or a built-in async TCP connect scan over a curated top-ports list (not just 80/443); open ports feed extra probe URLs.
- **HTTP probing + WAF/CDN detection** — `httpx`, or built-in async probe (status, title, tech, server, IP) with Cloudflare/Akamai/Fastly/Incapsula/Sucuri/… fingerprinting.
- **Subdomain takeover** — built-in fingerprint engine (GitHub Pages, S3, Heroku, Shopify, Azure, …) flagging dangling CNAMEs.
- **Screenshots** — `gowitness`, or headless Chrome/Chromium, for fast visual triage.
- **Crawling & URL discovery** — `katana` + `gau`/`waybackurls`, or built-in crawler; extracts JS files.
- **JavaScript analysis** (built-in):
  - secrets (AWS/GCP/Stripe/Slack/GitHub/JWT/private keys, …) with entropy + placeholder filtering
  - endpoint/URL extraction (new attack surface)
  - DOM-XSS source→sink detection
  - exposed `sourceMappingURL` detection
  - known-vulnerable libraries via **retire.js** (if installed)
- **Vulnerability scanning** — `nuclei` (optional), rate-limited and scope-gated.
- **Target-health monitor** — continuously samples availability/latency during a
  scan. A circuit-breaker flips a target to `degraded`/`down`, and heavy stages
  **auto-pause and wait to recover** so your scanning never knocks a target over.
- **Storage & diffing** — SQLite; re-scans flag newly discovered assets.
- **Notifications** — Discord / Slack / Telegram on new assets, high-severity findings, or health alerts.
- **Web dashboard** — add targets, launch scans, watch the live log, browse
  findings, and view the health timeline.

## Install

```bash
pip install -r requirements.txt
```

Optional (recommended) external tools — install any you want; ReconX detects them:
`subfinder`, `httpx`, `naabu`, `katana`, `gau`, `nuclei` (ProjectDiscovery),
`assetfinder`, `amass`, and `retire` (retire.js, via `npm i -g retire`).

## Usage

```bash
# Launch the dashboard
python cli.py web            # http://127.0.0.1:8000

# Or drive it from the CLI
python cli.py tools                     # what's installed vs. built-in fallback
python cli.py scan example.com          # add + full scan
python cli.py scan example.com --no-nuclei --in "*.example.com" --out "shop.example.com"
python cli.py list
```

### Input & troubleshooting

- The target is a **domain/host**, not a full URL. You may paste a URL
  (`https://site.tld/some/path`) — ReconX extracts the host (`site.tld`)
  automatically. Subdomain enumeration then runs against that host.
- If a scan ends with **"No live HTTP services found"**, the host wasn't
  reachable/in-scope from the machine running ReconX (DNS, firewall, geo-block,
  or a WAF challenge). It finishes cleanly instead of hanging.
- The **health monitor** only pauses heavy stages when a target was reachable
  and then degraded under load (so your scan doesn't take it down). A target
  that was never reachable does not block the pipeline.

## Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `RECONX_DATA_DIR` | where the DB + artifacts live (default `~/.reconx`) |
| `RECONX_HTTP_CONCURRENCY`, `RECONX_HTTP_TIMEOUT`, `RECONX_REQUEST_DELAY_MS` | politeness |
| `RECONX_HEALTH_INTERVAL_S`, `RECONX_HEALTH_FAIL_THRESHOLD`, `RECONX_HEALTH_SLOW_MS` | health monitor tuning |
| `SECURITYTRAILS_API_KEY`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY` | optional passive sources |
| `RECONX_DISCORD_WEBHOOK`, `RECONX_SLACK_WEBHOOK`, `RECONX_TELEGRAM_BOT_TOKEN`, `RECONX_TELEGRAM_CHAT_ID` | notifications |

## Architecture

```
cli.py                      CLI entry
reconx/
  config.py                 settings (env-driven, no hard-coded secrets)
  db.py                     SQLite storage + diffing
  scope.py                  scope enforcement (the main guardrail)
  tools.py                  external-tool detection + subprocess runner
  notify.py                 Discord/Slack/Telegram
  pipeline.py               orchestrator (health-gated stages)
  util.py                   target input normalization (URL/host:port -> host)
  modules/
    subdomains.py  dns_resolve.py  ports.py  http_probe.py  crawl.py
    waf_cdn.py              WAF/CDN fingerprinting
    takeover.py             subdomain-takeover fingerprint engine
    screenshot.py           gowitness / headless-Chrome screenshots
    jsanalysis.py           JS secrets/endpoints/sinks/sourcemaps + retire.js
    nuclei_scan.py          nuclei wrapper
    uptime.py               target-health monitor + circuit-breaker
  web/                      FastAPI backend + single-page dashboard
```
