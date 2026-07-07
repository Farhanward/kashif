from __future__ import annotations

from .models import ScanReport


def scan_markdown(report: ScanReport) -> str:
    lines = [
        "# تقرير كاشف",
        "",
        f"- الجذر: `{report.root}`",
        f"- الملفات: `{report.stats.get('file_count')}`",
        f"- الملاحظات: `{report.stats.get('finding_count')}`",
        f"- الشدّات: `{report.stats.get('severity_counts')}`",
        "",
        "## أعلى المخاطر",
        "",
    ]
    if not report.findings:
        lines.append("لا توجد مؤشرات خطرة ضمن القواعد الحالية.")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for finding in sorted(report.findings, key=lambda item: (order.get(item.severity, 9), item.file, item.line))[:80]:
        loc = f"{finding.file}:{finding.line}" if finding.line else finding.file
        lines.append(f"- **{finding.severity} / {finding.title}** `{loc}` `{finding.cwe}` — `{finding.evidence}`")
    lines.extend(["", "## خريطة الملفات", ""])
    for item in report.files[:120]:
        symbols = f" symbols={len(item.symbols)}" if item.symbols else ""
        extra = f" entropy={item.entropy} magic={item.magic}" if item.kind == "binary" else ""
        lines.append(f"- `{item.path}` {item.kind} size={item.size} lines={item.lines}{symbols}{extra}")
    lines.append("")
    return "\n".join(lines)


def nvd_markdown(summary: dict) -> str:
    lines = [
        "# تقرير بيانات NVD",
        "",
        f"- السجلات: `{summary.get('records')}`",
        f"- الملف: `{summary.get('out')}`",
        f"- Critical/High: `{summary.get('critical_high')}`",
        "",
        "## الشدات",
        "",
    ]
    for key, value in (summary.get("severity_counts") or {}).items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## أكثر CWE", ""])
    for key, value in (summary.get("top_cwe") or {}).items():
        lines.append(f"- `{key}`: `{value}`")
    lines.append("")
    return "\n".join(lines)
