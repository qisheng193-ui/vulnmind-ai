from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding, Rule
from .rules import DEFAULT_RULES


class ReconAgent:
    """Parse source files and identify candidate risky patterns."""

    def __init__(self, rules: list[Rule] | None = None, extensions: tuple[str, ...] = (".php", ".py", ".js")):
        self.rules = rules or DEFAULT_RULES
        self.extensions = tuple(ext.lower() for ext in extensions)
        self._compiled = [(rule, re.compile(rule.pattern)) for rule in self.rules]

    def scan_directory(self, path: str | Path) -> list[dict]:
        base_path = Path(path)
        findings: list[dict] = []

        for file_path in base_path.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in self.extensions:
                findings.extend(self.scan_file(file_path))

        return findings

    def scan_file(self, filepath: str | Path) -> list[dict]:
        file_path = Path(filepath)
        raw_findings: list[dict] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return [{
                "file": str(file_path),
                "line": 0,
                "rule": Rule(
                    rule_id="SCAN-ERROR-001",
                    title="File read error",
                    pattern="",
                    severity="LOW",
                    description=f"File could not be read: {exc}",
                    remediation="Check file permissions and text encoding before rerunning the scan.",
                ),
                "evidence": "read_text failure",
                "code_snippet": "",
            }]

        lines = content.splitlines()

        for line_number, line in enumerate(lines, start=1):
            for rule, pattern in self._compiled:
                if pattern.search(line):
                    start = max(0, line_number - 3)
                    end = line_number
                    context_lines = lines[start:end]
                    raw_findings.append(
                        {
                            "file": str(file_path),
                            "line": line_number,
                            "rule": rule,
                            "evidence": rule.pattern,
                            "code_snippet": line.strip(),
                            "context": "\n".join(context_lines),
                        }
                    )

        return raw_findings


class TriageAgent:
    """Classify severity and confidence using lightweight heuristics."""

    user_input_markers = ("$_GET", "$_POST", "$_REQUEST", "input(", "request.", "req.", "argv", "sys.argv")

    def assess(self, finding: dict) -> Finding:
        rule: Rule = finding["rule"]
        snippet = finding["code_snippet"]
        context = finding.get("context", snippet)
        analysis_text = f"{context}\n{snippet}"
        severity = rule.severity
        confidence = "MEDIUM"

        if any(marker in analysis_text for marker in self.user_input_markers):
            confidence = "HIGH"
            if severity == "MEDIUM":
                severity = "HIGH"
        elif rule.severity == "LOW":
            confidence = "LOW"

        return Finding(
            file=finding["file"],
            line=finding["line"],
            vulnerability=rule.title,
            severity=severity,
            confidence=confidence,
            evidence=finding["evidence"],
            code_snippet=snippet,
            verification_note="Confirm whether untrusted input can reach this sink and whether allowlisting, escaping, or fixed dispatch prevents abuse.",
            remediation=rule.remediation,
            rule_id=rule.rule_id,
        )


class GuidanceAgent:
    """Generate a clearer verification note for the final report."""

    def enrich(self, finding: Finding) -> Finding:
        note = finding.verification_note

        if finding.severity == "HIGH":
            note = "Review this sink first. Trace the input source, confirm exploitability in a non-production environment, and add guardrails before release."
        elif "include" in finding.vulnerability.lower() or "require" in finding.vulnerability.lower():
            note = "Check whether file paths are mapped from fixed identifiers instead of being assembled directly from request parameters."

        return Finding(
            file=finding.file,
            line=finding.line,
            vulnerability=finding.vulnerability,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence=finding.evidence,
            code_snippet=finding.code_snippet,
            verification_note=note,
            remediation=finding.remediation,
            rule_id=finding.rule_id,
        )


class ReportAgent:
    """Render reports in multiple formats."""

    def build_text(self, results: list[Finding], target: str) -> str:
        lines = [
            "=" * 72,
            " VulnMind AI - Secure Code Review Report",
            "=" * 72,
            f"Target: {target}",
            f"Total findings: {len(results)}",
            "",
        ]

        if not results:
            lines.append("No risky patterns were detected in the selected files.")
            return "\n".join(lines)

        for index, result in enumerate(results, start=1):
            lines.extend(
                [
                    f"[{index}] {result.vulnerability}",
                    f"Rule ID: {result.rule_id}",
                    f"Location: {result.file}:{result.line}",
                    f"Severity: {result.severity}",
                    f"Confidence: {result.confidence}",
                    f"Evidence: {result.evidence}",
                    f"Code Snippet: {result.code_snippet}",
                    f"Verification Note: {result.verification_note}",
                    f"Remediation: {result.remediation}",
                    "-" * 72,
                ]
            )

        return "\n".join(lines)

    def build_markdown(self, results: list[Finding], target: str) -> str:
        lines = [
            "# VulnMind AI Report",
            "",
            f"- Target: `{target}`",
            f"- Total findings: `{len(results)}`",
            "",
        ]

        if not results:
            lines.append("No risky patterns were detected in the selected files.")
            return "\n".join(lines)

        for index, result in enumerate(results, start=1):
            lines.extend(
                [
                    f"## {index}. {result.vulnerability}",
                    "",
                    f"- Rule ID: `{result.rule_id}`",
                    f"- File: `{result.file}`",
                    f"- Line: `{result.line}`",
                    f"- Severity: `{result.severity}`",
                    f"- Confidence: `{result.confidence}`",
                    f"- Evidence: `{result.evidence}`",
                    f"- Verification: {result.verification_note}",
                    f"- Remediation: {result.remediation}",
                    "",
                    "```text",
                    result.code_snippet or "(empty line)",
                    "```",
                    "",
                ]
            )

        return "\n".join(lines)

    def build_json(self, results: list[Finding], target: str) -> str:
        payload = {
            "target": target,
            "total_findings": len(results),
            "findings": [result.to_dict() for result in results],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)


class VulnMindAI:
    """Main orchestrator for the secure code review workflow."""

    def __init__(self, extensions: tuple[str, ...] = (".php", ".py", ".js")):
        self.recon = ReconAgent(extensions=extensions)
        self.triage = TriageAgent()
        self.guidance = GuidanceAgent()
        self.reporter = ReportAgent()

    def run(self, target_path: str | Path) -> list[Finding]:
        raw_findings = self.recon.scan_directory(target_path)
        triaged = [self.triage.assess(finding) for finding in raw_findings]
        return [self.guidance.enrich(finding) for finding in triaged]
