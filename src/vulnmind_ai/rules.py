from __future__ import annotations

from .models import Rule


DEFAULT_RULES = [
    Rule(
        rule_id="PHP-EVAL-001",
        title="PHP eval() usage",
        pattern=r"eval\s*\(",
        severity="HIGH",
        description="Dynamic evaluation in PHP can lead to remote code execution when user input reaches the sink.",
        remediation="Replace eval with explicit parsing logic and ensure untrusted input never reaches dynamic execution APIs.",
    ),
    Rule(
        rule_id="CMD-EXEC-001",
        title="Command execution API usage",
        pattern=r"\b(system|exec|passthru|shell_exec)\s*\(",
        severity="HIGH",
        description="Command execution APIs often become injection sinks when input is concatenated into shell commands.",
        remediation="Use parameterized process APIs, strict allowlists, and avoid shell invocation when possible.",
    ),
    Rule(
        rule_id="PY-SUBPROC-001",
        title="Python subprocess shell usage",
        pattern=r"subprocess\.(run|Popen|call)\s*\(",
        severity="MEDIUM",
        description="Process execution in Python becomes risky when shell=True or untrusted arguments are introduced.",
        remediation="Pass argument lists instead of shell strings and avoid shell=True for untrusted input.",
    ),
    Rule(
        rule_id="NODE-CHILDPROC-001",
        title="Node.js child_process usage",
        pattern=r"child_process\.(exec|execSync|spawn|spawnSync)\s*\(",
        severity="MEDIUM",
        description="Node.js child_process APIs can become command injection sinks when user input is passed directly.",
        remediation="Use argument arrays, allowlist inputs, and avoid shell-backed execution for untrusted values.",
    ),
    Rule(
        rule_id="PHP-UNSERIALIZE-001",
        title="PHP unserialize() usage",
        pattern=r"unserialize\s*\(",
        severity="HIGH",
        description="Unsafe deserialization in PHP may enable object injection and gadget-based code execution.",
        remediation="Prefer JSON formats, validate structure strictly, and never deserialize untrusted content.",
    ),
    Rule(
        rule_id="PHP-INCLUDE-001",
        title="Dynamic include/require usage",
        pattern=r"\b(include|require)(_once)?\s*\(",
        severity="MEDIUM",
        description="Dynamic file inclusion can lead to local or remote file inclusion if path inputs are attacker-controlled.",
        remediation="Map input values to fixed files, validate paths strictly, and avoid direct inclusion from request parameters.",
    ),
    Rule(
        rule_id="PHP-BASE64-001",
        title="base64_decode() usage",
        pattern=r"base64_decode\s*\(",
        severity="LOW",
        description="base64_decode is not inherently vulnerable, but frequent use may indicate obfuscated or layered execution flow.",
        remediation="Review the decoded data flow and confirm it is not combined with dynamic execution or file writes.",
    ),
]
