from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    file: str
    line: int = 0
    evidence: str = ""
    cwe: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class FileSummary:
    path: str
    kind: str
    size: int
    lines: int = 0
    symbols: list[str] = field(default_factory=list)
    entropy: float = 0.0
    magic: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ScanReport:
    root: str
    files: list[FileSummary]
    findings: list[Finding]
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files": [item.to_dict() for item in self.files],
            "findings": [item.to_dict() for item in self.findings],
            "stats": self.stats,
        }
