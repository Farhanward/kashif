from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _get_json(url: str, retries: int = 5) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "kashif-local-security-mapper/0.1"})
    for attempt in range(retries):
        try:
            with urlopen(request, timeout=90) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == retries - 1:
                raise
            retry_after = exc.headers.get("Retry-After")
            delay = float(retry_after) if retry_after and retry_after.isdigit() else min(45, 6 * (attempt + 1))
            time.sleep(delay)
    raise RuntimeError("unreachable retry state")


def _severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData") or {}
            return str(data.get("baseSeverity") or metrics[key][0].get("baseSeverity") or "UNKNOWN").upper()
    return "UNKNOWN"


def _cwes(cve: dict[str, Any]) -> list[str]:
    values = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = str(desc.get("value") or "")
            if value:
                values.append(value)
    return values or ["UNKNOWN"]


def _description(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en":
            return str(desc.get("value") or "")
    return ""


def download_nvd(out: str | Path, limit: int = 12000, page_size: int = 1000, sleep_seconds: float = 6.2) -> dict[str, Any]:
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    start = 0
    severity_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()
    with out_path.open("w", encoding="utf-8") as handle:
        while total < limit:
            length = min(page_size, limit - total)
            url = f"{NVD_URL}?{urlencode({'startIndex': start, 'resultsPerPage': length})}"
            payload = _get_json(url)
            vulns = payload.get("vulnerabilities") or []
            if not vulns:
                break
            for item in vulns:
                cve = item.get("cve") or {}
                severity = _severity(cve)
                cwes = _cwes(cve)
                record = {
                    "id": cve.get("id"),
                    "published": cve.get("published"),
                    "lastModified": cve.get("lastModified"),
                    "severity": severity,
                    "cwe": cwes,
                    "description": _description(cve),
                }
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                severity_counts[severity] += 1
                cwe_counts.update(cwes)
                total += 1
                if total >= limit:
                    break
            start += len(vulns)
            time.sleep(sleep_seconds)
    return {
        "out": str(out_path.resolve()),
        "records": total,
        "critical_high": severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0),
        "severity_counts": dict(severity_counts),
        "top_cwe": dict(cwe_counts.most_common(20)),
    }
