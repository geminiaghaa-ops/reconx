#!/usr/bin/env python3
"""ReconX command-line interface.

Examples:
  python cli.py web                         # launch the dashboard
  python cli.py scan example.com            # add + scan a target (CLI)
  python cli.py scan example.com --no-nuclei
  python cli.py add example.com --in "*.example.com" --out "blog.example.com"
  python cli.py tools                       # show which external tools are installed
  python cli.py list                        # list targets
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from reconx.db import get_db
from reconx.tools import availability
from reconx.pipeline import run_target
from reconx.web.app import run_server
from reconx.util import normalize_target


def cmd_tools(_):
    import asyncio
    from reconx.tools import plan
    rows = asyncio.run(plan())
    print("Engine that will run each stage (external tool if installed, else built-in fallback):\n")
    print(f"  {'STAGE':12s} {'MODE':10s} ENGINE")
    print("  " + "-" * 60)
    for r in rows:
        mode = "tool" if r["using_tool"] else ("built-in" if "DISABLED" not in r["engine"] else "OFF")
        print(f"  {r['stage']:12s} {mode:10s} {r['engine']}")
        if r["note"]:
            print(f"  {'':12s} {'':10s} ! {r['note']}")
    missing = sorted({t for r in rows for t in r["missing"]})
    if missing:
        from reconx.tools import INSTALL
        print("\nNot installed (fallbacks are used instead). To get the real tools:\n")
        for t in missing:
            print(f"  {t:12s} {INSTALL.get(t, '')}")
        print("\nTip: install Go (golang) + Node, then run the commands above. "
              "Nuclei has NO fallback — install it to get vuln scanning.")
    else:
        print("\nAll optional tools installed. 🎉")


def _apply_auth(tid, args):
    import json as _j
    cookie = getattr(args, "cookie", None) or ""
    hdrs = {}
    for h in (getattr(args, "header", None) or []):
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()
    if cookie or hdrs:
        get_db().set_auth(tid, cookie, _j.dumps(hdrs) if hdrs else "")
        bits = (["cookie"] if cookie else []) + ([f"{len(hdrs)} header(s)"] if hdrs else [])
        print("  auth set: " + ", ".join(bits) + " (sent only to in-scope hosts)")


def cmd_add(args):
    domain = normalize_target(args.domain)
    if not domain:
        print("error: provide a valid domain or URL"); return 1
    tid = get_db().add_target(domain, args.in_scope or "", args.out_scope or "")
    note = f" (from {args.domain})" if args.domain.strip() != domain else ""
    print(f"target {tid}: {domain}{note}")
    _apply_auth(tid, args)


def cmd_list(_):
    for t in get_db().list_targets():
        c = get_db().counts(t["id"])
        print(f"[{t['id']}] {t['domain']:40s} health={t['health']:9s} "
              f"sub={c['subdomains']} http={c['http_services']} js={c['js_findings']} vuln={c['findings']}")


def cmd_scan(args):
    domain = normalize_target(args.domain)
    if not domain:
        print("error: provide a valid domain or URL"); return 1
    tid = get_db().add_target(domain, args.in_scope or "", args.out_scope or "")
    _apply_auth(tid, args)
    note = f" (from {args.domain})" if args.domain.strip() != domain else ""
    print(f"scanning target {tid}: {domain}{note} (nuclei={not args.no_nuclei}) ...")
    run_id = asyncio.run(run_target(tid, run_nuclei=not args.no_nuclei))
    run = get_db().get_run(run_id)
    print("\n--- log ---")
    print(run["log"])
    print("--- stats ---")
    print(run.get("stats", "{}"))


def cmd_report(args):
    import json as _j
    from reconx.report import build_html, build_json
    db = get_db()
    dom = normalize_target(args.target)
    tid = None
    if args.target.isdigit():
        tid = int(args.target)
    else:
        for t in db.list_targets():
            if t["domain"] == dom:
                tid = t["id"]; break
    if not tid or not db.get_target(tid):
        print(f"error: target not found: {args.target}"); return 1
    if args.json:
        out = args.out or f"reconx-{dom}.json"
        open(out, "w").write(_j.dumps(build_json(db, tid), indent=2, default=str))
    else:
        out = args.out or f"reconx-{dom}.html"
        open(out, "w").write(build_html(db, tid))
    print(f"report written: {out}")


def cmd_web(args):
    print(f"ReconX dashboard: http://{args.host}:{args.port}")
    run_server(host=args.host, port=args.port)


def main(argv=None):
    p = argparse.ArgumentParser(prog="reconx", description="Bug bounty recon orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("tools", help="show external tool availability"); sp.set_defaults(fn=cmd_tools)

    sp = sub.add_parser("add", help="add a target")
    sp.add_argument("domain"); sp.add_argument("--in", dest="in_scope"); sp.add_argument("--out", dest="out_scope")
    sp.add_argument("--cookie", help="session cookie string, e.g. 'sid=abc; csrf=xyz'")
    sp.add_argument("--header", action="append", help="extra header 'Name: value' (repeatable)")
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser("list", help="list targets"); sp.set_defaults(fn=cmd_list)

    sp = sub.add_parser("scan", help="add (if needed) and scan a target")
    sp.add_argument("domain"); sp.add_argument("--in", dest="in_scope"); sp.add_argument("--out", dest="out_scope")
    sp.add_argument("--no-nuclei", action="store_true")
    sp.add_argument("--cookie", help="session cookie string, e.g. 'sid=abc; csrf=xyz'")
    sp.add_argument("--header", action="append", help="extra header 'Name: value' (repeatable)")
    sp.set_defaults(fn=cmd_scan)

    sp = sub.add_parser("report", help="export an HTML (or JSON) report for a target")
    sp.add_argument("target", help="target domain or id")
    sp.add_argument("--out"); sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_report)

    sp = sub.add_parser("web", help="launch the web dashboard")
    sp.add_argument("--host", default="127.0.0.1"); sp.add_argument("--port", type=int, default=8000)
    sp.set_defaults(fn=cmd_web)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
