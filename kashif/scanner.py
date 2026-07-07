from __future__ import annotations

import ast
import math
import re
from collections import Counter
from pathlib import Path

from .models import FileSummary, Finding, ScanReport


TEXT_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".go", ".java", ".cs", ".php", ".rb", ".sh", ".ps1", ".env", ".txt", ".md", ".json", ".yml", ".yaml", ".toml"}
SKIP_DIRS = {".git", "node_modules", "target", "__pycache__", ".venv", "venv", "dist", "build", "reports", "data"}
RULES: list[tuple[str, str, str, str, str, re.Pattern[str]]] = [
    ("PY_EVAL", "critical", "تنفيذ eval/exec", "CWE-94", "استخدم parser آمن أو mapping صريح بدل eval/exec.", re.compile(r"\b(eval|exec)\s*\(")),
    ("PY_SHELL_TRUE", "critical", "subprocess مع shell=True", "CWE-78", "استخدم قائمة arguments وshell=False.", re.compile(r"subprocess\.[a-zA-Z_]+\(.{0,160}shell\s*=\s*True", re.S)),
    ("OS_SYSTEM", "high", "تنفيذ نظام مباشر", "CWE-78", "استخدم subprocess بقائمة arguments بعد تحقق allowlist.", re.compile(r"\bos\.system\s*\(")),
    ("PICKLE_LOAD", "high", "تحميل pickle غير آمن", "CWE-502", "لا تفك pickle من مصدر غير موثوق.", re.compile(r"\bpickle\.loads?\s*\(")),
    ("YAML_LOAD", "high", "YAML load غير آمن", "CWE-502", "استخدم safe_load.", re.compile(r"\byaml\.load\s*\(")),
    ("SQL_CONCAT", "high", "SQL مبني بسلاسل", "CWE-89", "استخدم prepared statements.", re.compile(r"(SELECT|INSERT|UPDATE|DELETE).{0,120}(\+|%|format\(|f['\"])", re.I | re.S)),
    ("VERIFY_FALSE", "medium", "تعطيل تحقق TLS", "CWE-295", "لا تستخدم verify=False إلا في بيئة اختبار معزولة.", re.compile(r"verify\s*=\s*False")),
    ("WEAK_HASH", "medium", "خوارزمية hash ضعيفة", "CWE-327", "استخدم SHA-256 أو BLAKE2 حسب الحاجة.", re.compile(r"\b(md5|sha1)\s*\(")),
    ("HARDCODED_SECRET", "critical", "سر مضمّن في الكود", "CWE-798", "انقل السر إلى خزنة أسرار ودوّره.", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("DOCKER_SOCKET", "critical", "وصول Docker socket", "CWE-269", "لا تمنح الوكيل وصولاً مباشراً إلى docker.sock.", re.compile(r"docker\.sock|/var/run/docker\.sock", re.I)),
]
PY_AST_RULE_CODES = {"PY_EVAL", "PY_SHELL_TRUE", "OS_SYSTEM", "PICKLE_LOAD", "YAML_LOAD", "VERIFY_FALSE", "WEAK_HASH"}


def _is_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXT


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _magic(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE/Windows executable"
    if data.startswith(b"\x7fELF"):
        return "ELF/Linux binary"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP/JAR/APK"
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return "Java class"
    return data[:8].hex()


def _python_symbols(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    symbols: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.append(f"{type(node).__name__}:{node.name}:{node.lineno}")
    return symbols


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _source_segment(text: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(text, node) or _call_name(getattr(node, "func", node))
    return re.sub(r"\s+", " ", segment).strip()[:180]


def _keyword_is_true(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
            return True
    return False


def _keyword_is_false(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
            return True
    return False


def _scan_python_ast(rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        evidence = _source_segment(text, node)
        line = int(getattr(node, "lineno", 0) or 0)
        if name in {"eval", "exec"}:
            findings.append(Finding("PY_EVAL", "critical", "تنفيذ eval/exec", rel, line, evidence, "CWE-94"))
        elif name.startswith("subprocess.") and _keyword_is_true(node, "shell"):
            findings.append(Finding("PY_SHELL_TRUE", "critical", "subprocess مع shell=True", rel, line, evidence, "CWE-78"))
        elif name == "os.system":
            findings.append(Finding("OS_SYSTEM", "high", "تنفيذ نظام مباشر", rel, line, evidence, "CWE-78"))
        elif name in {"pickle.load", "pickle.loads"}:
            findings.append(Finding("PICKLE_LOAD", "high", "تحميل pickle غير آمن", rel, line, evidence, "CWE-502"))
        elif name == "yaml.load":
            findings.append(Finding("YAML_LOAD", "high", "YAML load غير آمن", rel, line, evidence, "CWE-502"))
        elif _keyword_is_false(node, "verify"):
            findings.append(Finding("VERIFY_FALSE", "medium", "تعطيل تحقق TLS", rel, line, evidence, "CWE-295"))
        elif name in {"md5", "sha1", "hashlib.md5", "hashlib.sha1"}:
            findings.append(Finding("WEAK_HASH", "medium", "خوارزمية hash ضعيفة", rel, line, evidence, "CWE-327"))
    return findings


def _scan_text(path: Path, rel: str, text: str) -> tuple[FileSummary, list[Finding]]:
    lines = text.splitlines()
    summary = FileSummary(path=rel, kind=path.suffix.lower().lstrip(".") or "text", size=path.stat().st_size, lines=len(lines))
    if path.suffix.lower() == ".py":
        summary.symbols = _python_symbols(text)
    findings: list[Finding] = []
    skip_regex_codes: set[str] = set()
    if path.suffix.lower() == ".py":
        ast_findings = _scan_python_ast(rel, text)
        findings.extend(ast_findings)
        skip_regex_codes = PY_AST_RULE_CODES
    for code, severity, title, cwe, _fix, pattern in RULES:
        if code in skip_regex_codes:
            continue
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            evidence = re.sub(r"\s+", " ", match.group(0)).strip()[:180]
            findings.append(Finding(code, severity, title, rel, line, evidence, cwe))
    return summary, findings


def _scan_binary(path: Path, rel: str, data: bytes) -> tuple[FileSummary, list[Finding]]:
    entropy = _entropy(data)
    summary = FileSummary(path=rel, kind="binary", size=len(data), entropy=round(entropy, 3), magic=_magic(data))
    findings: list[Finding] = []
    ascii_text = re.sub(rb"[^\x20-\x7e]+", b" ", data[:2_000_000]).decode("ascii", "ignore")
    if entropy > 7.4 and len(data) > 1024:
        findings.append(Finding("HIGH_ENTROPY_BINARY", "medium", "ثنائي عالي العشوائية", rel, evidence=f"entropy={entropy:.2f}", cwe="CWE-506"))
    for needle in ("cmd.exe", "powershell", "mimikatz", "password", "api_key", "docker.sock"):
        if needle.lower() in ascii_text.lower():
            findings.append(Finding("SUSPICIOUS_STRING", "high", "سلسلة مشبوهة داخل ثنائي", rel, evidence=needle, cwe="CWE-200"))
    return summary, findings


def scan_path(root: str | Path, max_file_size: int = 2_000_000) -> ScanReport:
    root_path = Path(root).resolve(strict=False)
    files: list[FileSummary] = []
    findings: list[Finding] = []
    for path in root_path.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(root_path).as_posix()
        try:
            size = path.stat().st_size
            if size > max_file_size:
                files.append(FileSummary(path=rel, kind="skipped_large", size=size))
                continue
            data = path.read_bytes()
            if _is_text(path):
                text = data.decode("utf-8", "replace")
                summary, file_findings = _scan_text(path, rel, text)
            else:
                summary, file_findings = _scan_binary(path, rel, data)
            files.append(summary)
            findings.extend(file_findings)
        except OSError as exc:
            findings.append(Finding("READ_ERROR", "low", "تعذر قراءة الملف", rel, evidence=repr(exc)))
    severity_counts = Counter(f.severity for f in findings)
    kind_counts = Counter(item.kind for item in files)
    return ScanReport(
        root=str(root_path),
        files=files,
        findings=findings,
        stats={
            "file_count": len(files),
            "finding_count": len(findings),
            "severity_counts": dict(severity_counts),
            "kind_counts": dict(kind_counts),
        },
    )
