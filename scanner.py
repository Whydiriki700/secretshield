"""SecretShield scanner: deterministic credential detection, no LLM, no network.

Detectors are anchored to well-known vendor credential formats plus
key = value assignment contexts, so ordinary prose and code identifiers do
not trip the shield. A finding never carries the secret itself into logs:
only its kind, its length, and a masked preview (first 4 characters).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

REDACTION = "[REDACTED by SecretShield]"

# (kind, pattern, group whose span is the secret: 0 = whole match)
_DETECTORS: List[Tuple[str, "re.Pattern[str]", int]] = [
    (
        "private_key_pem",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        0,
    ),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), 0),
    ("openai_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), 0),
    ("github_token", re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"), 0),
    ("aws_access_key", re.compile(r"\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA|A3T[A-Z0-9])[A-Z0-9]{16}\b"), 0),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), 0),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), 0),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"), 0),
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), 0),
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{36}"), 0),
    ("pypi_token", re.compile(r"pypi-[A-Za-z0-9_\-]{16,}"), 0),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"), 0),
    (
        "discord_token",
        re.compile(r"\b[MN][A-Za-z0-9_\-]{23,28}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,40}\b"),
        0,
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,2048}\.eyJ[A-Za-z0-9_\-]{8,2048}\.[A-Za-z0-9_\-]{8,2048}\b"),
        0,
    ),
    (
        "bearer_credential",
        re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=\-]{16,})"),
        1,
    ),
    (
        "basic_auth_url",
        re.compile(r"(?i)\bhttps?://[^/\s:@]{2,}:([^/\s:@]{4,})@"),
        1,
    ),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|secret|passwd|password|pwd|"
            r"access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key)\b"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=\-]{12,})[\"']?"
        ),
        1,
    ),
]


def _masked(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:4] + "****"


def scan_text(text: str, disabled_kinds: Any = None) -> List[Dict[str, Any]]:
    """Return findings: {kind, start, end, length, preview}. Spans never overlap."""
    if not text:
        return []
    disabled = set(disabled_kinds or [])
    spans: List[Tuple[int, int]] = []
    findings: List[Dict[str, Any]] = []
    for kind, pattern, group in _DETECTORS:
        if kind in disabled:
            continue
        for match in pattern.finditer(text):
            start, end = match.span(group)
            if start < 0 or any(start < e and end > s for s, e in spans):
                continue
            value = match.group(group)
            spans.append((start, end))
            findings.append(
                {
                    "kind": kind,
                    "start": start,
                    "end": end,
                    "length": len(value),
                    "preview": _masked(value),
                }
            )
    findings.sort(key=lambda f: f["start"])
    return findings


def redact_text(text: str, disabled_kinds: Any = None) -> Tuple[str, List[Dict[str, Any]]]:
    findings = scan_text(text, disabled_kinds)
    if not findings:
        return text, findings
    out: List[str] = []
    cursor = 0
    for finding in findings:
        out.append(text[cursor : finding["start"]])
        out.append(REDACTION)
        cursor = finding["end"]
    out.append(text[cursor:])
    return "".join(out), findings


def _scan_value(value: Any, disabled: Any, path: str, out: List[Dict[str, Any]]) -> None:
    if isinstance(value, str):
        for finding in scan_text(value, disabled):
            out.append({**finding, "path": path})
    elif isinstance(value, dict):
        for key, item in value.items():
            _scan_value(item, disabled, f"{path}.{key}" if path else str(key), out)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _scan_value(item, disabled, f"{path}[{index}]", out)


def scan_args(args: Any, disabled_kinds: Any = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    _scan_value(args, disabled_kinds, "", findings)
    return findings


def _redact_value(value: Any, disabled: Any) -> Any:
    if isinstance(value, str):
        new_text, _ = redact_text(value, disabled)
        return new_text
    if isinstance(value, dict):
        return {key: _redact_value(item, disabled) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, disabled) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, disabled) for item in value)
    return value


def redact_args(args: Any, disabled_kinds: Any = None) -> Any:
    return _redact_value(args, disabled_kinds)


def public_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """A finding stripped of span data, safe for ledgers and messages."""
    return {
        "kind": finding["kind"],
        "length": finding["length"],
        "preview": finding["preview"],
        **({"path": finding["path"]} if finding.get("path") else {}),
    }
