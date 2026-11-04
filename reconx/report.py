"""Report generation — turn raw recon data into something you can actually act on.

Produces a self-contained HTML report (and JSON export) for a target: a summary,
findings prioritized by severity (nuclei + takeover + content/exposure + checks +
JS secrets, highest first), live services with tech/WAF/screenshots, and the
subdomain list.
"""
from __future__ import annotations

import html
import json

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "#ff3860", "high": "#ff7849", "medium": "#f5a623",
             "low": "#4fd1c5", "info": "#6b7a90"}


def collect(db, target_id: int) -> dict:
    t = db.get_target(target_id)
    counts = db.counts(target_id)
    findings = db.query(
        "SELECT engine, name, template, severity, matched_at FROM findings WHERE target_id=?", (target_id,))
    # JS high-value findings (secrets, vulnerable libs) as findings too
    jsf = db.query(
        "SELECT kind, name, value, severity, source_url FROM js_findings WHERE target_id=? "
        "AND (severity IN ('high','critical','medium') OR kind IN ('secret','library'))", (target_id,))
    for j in jsf:
        findings.append({"engine": "js", "name": f"{j['kind']}: {j['name'] or j['value'][:40]}",
                         "template": j["value"][:60], "severity": j["severity"],
                         "matched_at": j["source_url"]})
    findings.sort(key=lambda f: SEV_RANK.get((f.get("severity") or "info").lower(), 9))
    services = db.query(
        "SELECT url, status, title, tech, webserver, ip, cdn, waf, screenshot FROM http_services "
        "WHERE target_id=? ORDER BY status", (target_id,))
    subs = [r["value"] for r in db.query(
        "SELECT value FROM assets WHERE target_id=? AND kind='subdomain' ORDER BY value", (target_id,))]
    run = db.latest_run(target_id)
    stats = {}
    try:
        stats = json.loads((run or {}).get("stats") or "{}")
    except Exception:
        pass
    return {"target": t, "counts": counts, "findings": findings,
            "services": services, "subdomains": subs, "stats": stats}


def build_json(db, target_id: int) -> dict:
    return collect(db, target_id)


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def build_html(db, target_id: int) -> str:
    d = collect(db, target_id)
    t, c = d["target"], d["counts"]
    sev_counts: dict[str, int] = {}
    for f in d["findings"]:
        s = (f.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    def badge(sev):
        sev = (sev or "info").lower()
        return f'<span style="background:{SEV_COLOR.get(sev,"#6b7a90")}22;color:{SEV_COLOR.get(sev,"#6b7a90")};' \
               f'padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600">{_esc(sev)}</span>'

    frows = "".join(
        f'<tr><td>{badge(f.get("severity"))}</td><td>{_esc(f.get("engine"))}</td>'
        f'<td>{_esc(f.get("name"))}</td><td class="mono">{_esc(f.get("template"))}</td>'
        f'<td class="mono">{_esc(f.get("matched_at"))}</td></tr>'
        for f in d["findings"]) or '<tr><td colspan="5" class="muted">No findings.</td></tr>'

    srows = "".join(
        f'<tr><td class="mono">{_esc(s["url"])}</td><td>{_esc(s["status"])}</td>'
        f'<td>{_esc(s["title"])}</td><td>{_esc(s["tech"])}</td>'
        f'<td>{_esc((s["waf"] or "") + (("/" + s["cdn"]) if s["cdn"] else "")) or "—"}</td>'
        f'<td class="mono">{_esc(s["ip"])}</td></tr>'
        for s in d["services"]) or '<tr><td colspan="6" class="muted">No live services.</td></tr>'

    sev_summary = " ".join(
        f'<span style="color:{SEV_COLOR[s]}">{sev_counts.get(s,0)} {s}</span>'
        for s in ("critical", "high", "medium", "low", "info") if sev_counts.get(s))

    subs_html = "".join(f"<li class='mono'>{_esc(x)}</li>" for x in d["subdomains"][:1000])

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>ReconX report — {_esc(t['domain'])}</title>
<style>
body{{font-family:system-ui,Segoe UI,sans-serif;background:#0b0f14;color:#dfe7f0;margin:0;padding:24px;font-size:14px}}
h1{{margin:0 0 4px}} h2{{margin:28px 0 10px;font-size:15px;border-bottom:1px solid #1f2a37;padding-bottom:6px}}
.sub{{color:#8a9bb4}} .muted{{color:#8a9bb4}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.card{{background:#121823;border:1px solid #1f2a37;border-radius:10px;padding:14px 18px;min-width:110px}}
.card .n{{font-size:26px;font-weight:700}} .card .l{{font-size:11px;color:#8a9bb4;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #1f2a37;vertical-align:top;word-break:break-all}}
th{{color:#8a9bb4;font-size:10.5px;text-transform:uppercase}}
.mono{{font-family:ui-monospace,monospace;font-size:12px}}
ul{{columns:3;font-size:12px}} @media(max-width:700px){{ul{{columns:1}}}}
</style></head><body>
<h1>ReconX report <span class="sub">— {_esc(t['domain'])}</span></h1>
<div class="sub">health: {_esc(t.get('health'))} · findings by severity: {sev_summary or 'none'}</div>
<div class="cards">
  <div class="card"><div class="n">{c['subdomains']}</div><div class="l">Subdomains</div></div>
  <div class="card"><div class="n">{c['http_services']}</div><div class="l">Live HTTP</div></div>
  <div class="card"><div class="n">{c['js_findings']}</div><div class="l">JS findings</div></div>
  <div class="card"><div class="n">{len(d['findings'])}</div><div class="l">Prioritized findings</div></div>
</div>
<h2>Findings (most severe first)</h2>
<table><thead><tr><th>sev</th><th>source</th><th>name</th><th>detail</th><th>location</th></tr></thead>
<tbody>{frows}</tbody></table>
<h2>Live services</h2>
<table><thead><tr><th>url</th><th>status</th><th>title</th><th>tech</th><th>waf/cdn</th><th>ip</th></tr></thead>
<tbody>{srows}</tbody></table>
<h2>Subdomains ({len(d['subdomains'])})</h2>
<ul>{subs_html}</ul>
</body></html>"""
