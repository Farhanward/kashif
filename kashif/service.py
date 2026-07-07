"""Kashif scan gateway as a local HTTP service.

``POST /api/scan`` scans a directory or file and returns the findings map.
Security: the service only scans paths under the allowed roots
(``KASHIF_SCAN_ROOTS``, semicolon-separated; default ``C:\\Projects``) so a
network client cannot walk arbitrary disks.
"""

from __future__ import annotations

import os
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .http_base import BaseServiceHandler, build_server
from .scanner import scan_path


def allowed_scan_roots() -> list[Path]:
    raw = os.environ.get("KASHIF_SCAN_ROOTS", "").strip() or r"C:\Projects"
    return [Path(part).resolve(strict=False) for part in raw.split(";") if part.strip()]


def _path_allowed(target: Path, roots: list[Path]) -> bool:
    for root in roots:
        try:
            target.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _scan_route(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    raw_path = str(data.get("path") or "").strip()
    if not raw_path:
        return 400, {"ok": False, "error": "missing 'path'"}
    target = Path(raw_path).resolve(strict=False)
    roots = allowed_scan_roots()
    if not _path_allowed(target, roots):
        return 403, {
            "ok": False,
            "error": "path outside allowed scan roots",
            "allowed_roots": [str(root) for root in roots],
        }
    if not target.exists():
        return 404, {"ok": False, "error": f"path not found: {target}"}
    report = scan_path(target)
    severities: dict[str, int] = {}
    for finding in report.findings:
        severities[finding.severity] = severities.get(finding.severity, 0) + 1
    return 200, {
        "ok": True,
        "root": report.root,
        "stats": report.stats,
        "severities": severities,
        "findings": [finding.to_dict() for finding in report.findings],
    }


class Handler(BaseServiceHandler):
    post_routes = {"/api/scan": staticmethod(_scan_route)}


def create_server(host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    return build_server(Handler, host=host, port=port)


def run_server(host: str | None = None, port: int | None = None) -> None:
    from .version import __version__

    server = create_server(host=host, port=port)
    print(f"kashif service v{__version__}: http://{server.server_address[0]}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
