from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    pattern: str
    severity: str
    description: str
    remediation: str


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: str
    evidence: str
    code_snippet: str
    verification_note: str
    remediation: str
    rule_id: str

    def to_dict(self) -> dict:
        return asdict(self)
