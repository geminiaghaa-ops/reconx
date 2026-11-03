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


def cmd_tools(_):
    av = availability()
    print(json.dumps(av, indent=2))
    missing = [t for d in av.values() for t, on in d.items() if not on]
    if missing:
        print("\nOptional tools not installed (built-in fallbacks will be used):")
        print("  " + ", ".join(sorted(set(missing))))


def cmd_add(args):
    tid = get_db().add_target(args.domain, args.in_scope or "", args.out_scope or "")
    print(f"target {tid}: {args.domain}")


def cmd_list(_):
    for t in get_db().list_targets():
        c = get_db().counts(t["id"])
        print(f"[{t['id']}] {t['domain']:40s} health={t['health']:9s} "
              f"sub={c['subdomains']} http={c['http_services']} js={c['js_findings']} vuln={c['findings']}")


def cmd_scan(args):
    tid = get_db().add_target(args.domain, args.in_scope or "", args.out_scope or "")
    print(f"scanning target {tid}: {args.domain} (nuclei={not args.no_nuclei}) ...")
    run_id = asyncio.run(run_target(tid, run_nuclei=not args.no_nuclei))
    run = get_db().get_run(run_id)
    print("\n--- log ---")
    print(run["log"])
    print("--- stats ---")
    print(run.get("stats", "{}"))


def cmd_web(args):
    print(f"ReconX dashboard: http://{args.host}:{args.port}")
    run_server(host=args.host, port=args.port)


def main(argv=None):
    p = argparse.ArgumentParser(prog="reconx", description="Bug bounty recon orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("tools", help="show external tool availability"); sp.set_defaults(fn=cmd_tools)

    sp = sub.add_parser("add", help="add a target")
    sp.add_argument("domain"); sp.add_argument("--in", dest="in_scope"); sp.add_argument("--out", dest="out_scope")
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser("list", help="list targets"); sp.set_defaults(fn=cmd_list)

    sp = sub.add_parser("scan", help="add (if needed) and scan a target")
    sp.add_argument("domain"); sp.add_argument("--in", dest="in_scope"); sp.add_argument("--out", dest="out_scope")
    sp.add_argument("--no-nuclei", action="store_true")
    sp.set_defaults(fn=cmd_scan)

    sp = sub.add_parser("web", help="launch the web dashboard")
    sp.add_argument("--host", default="127.0.0.1"); sp.add_argument("--port", type=int, default=8000)
    sp.set_defaults(fn=cmd_web)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
