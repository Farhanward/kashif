from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .datasets import download_nvd
from .reports import nvd_markdown, scan_markdown
from .scanner import scan_path


def scan_command(args: argparse.Namespace) -> int:
    report = scan_path(args.path)
    payload = json.dumps(report.to_dict(), ensure_ascii=False, indent=2) if args.format == "json" else scan_markdown(report)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print(str(out.resolve()))
    else:
        print(payload)
    return 1 if any(item.severity == "critical" for item in report.findings) and args.fail_on_critical else 0


def nvd_command(args: argparse.Namespace) -> int:
    summary = download_nvd(args.out, limit=args.limit, page_size=args.page_size, sleep_seconds=args.sleep)
    md_path = Path(args.report)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(nvd_markdown(summary), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def serve_command(args: argparse.Namespace) -> int:
    from .service import run_server

    run_server(host=args.host, port=args.port)
    return 0


def version_command(args: argparse.Namespace) -> int:
    from .version import __version__

    print(json.dumps({"service": "kashif", "version": __version__}, ensure_ascii=False))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="kashif", description="Local Arabic code/binary security mapper.")
    sub = root.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--path", required=True)
    scan.add_argument("--out")
    scan.add_argument("--format", choices=["json", "md"], default="md")
    scan.add_argument("--fail-on-critical", action="store_true")
    scan.set_defaults(func=scan_command)

    nvd = sub.add_parser("download-nvd")
    nvd.add_argument("--out", default="data/external/nvd_cves_12000.jsonl")
    nvd.add_argument("--report", default="reports/nvd_summary.md")
    nvd.add_argument("--limit", type=int, default=12000)
    nvd.add_argument("--page-size", type=int, default=1000)
    nvd.add_argument("--sleep", type=float, default=6.2)
    nvd.set_defaults(func=nvd_command)

    serve = sub.add_parser("serve", help="Run the local HTTP scan service.")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.set_defaults(func=serve_command)

    version = sub.add_parser("version", help="Print service version.")
    version.set_defaults(func=version_command)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
