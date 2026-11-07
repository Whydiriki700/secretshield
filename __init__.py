"""SecretShield - credentials stop at the tool boundary.

Hermes already masks known credential formats in logs and transcripts.
SecretShield is the enforcement layer on top of that masking:

  1. `pre_tool_call` scans every tool call's arguments BEFORE dispatch.
     A credential found there never leaves the machine inside a shell
     command, an HTTP request, a message send, or a file write: the call
     is blocked (or its arguments are rewritten with the credential
     redacted), and the attempt is recorded.
  2. `transform_llm_output` scans the finished reply before the user
     sees it; credentials in the text are redacted and a notice is
     appended, so a secret the model decides to quote never reaches
     the chat surface.
  3. `post_tool_call` scans tool results and records detections, so a
     tool that printed a secret into the session is visible in the
     incident ledger even before the reply is checked.

Detection is deterministic (vendor-format patterns plus assignment
contexts), no LLM, no network. Incidents are append-only JSONL under
<HERMES_HOME>/secretshield/ and contain only metadata: kind, length,
masked preview, surface, action. Secret values are never stored.

Modes (config: plugins.entries.secretshield.settings.mode):
  - enforce (default): tool calls carrying credentials are blocked;
    replies are redacted with a notice
  - redact: tool arguments are rewritten with credentials replaced,
    calls proceed; replies are redacted with a notice
  - warn: detections are recorded, nothing is blocked or changed
  - off: plugin observes nothing and changes nothing

Optional setting: disabled_kinds, a list of detector kinds to skip.
Scanner errors fail closed in enforce mode for replies (the reply is
withheld rather than shipped unchecked) and are recorded in the ledger.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

try:
    from . import ledger, scanner
except ImportError:  # loaded as a top-level module in tests
    import ledger  # type: ignore
    import scanner  # type: ignore

logger = logging.getLogger(__name__)

_CTX: Any = None
_MODES = {"enforce", "redact", "warn", "off"}


def _mode() -> str:
    if _CTX is not None:
        try:
            mode = _CTX.get_config("mode", "enforce")
            if isinstance(mode, str) and mode.lower() in _MODES:
                return mode.lower()
        except Exception:
            pass
    return "enforce"


def _disabled_kinds() -> List[str]:
    if _CTX is not None:
        try:
            kinds = _CTX.get_config("disabled_kinds", [])
            if isinstance(kinds, list):
                return [str(k) for k in kinds]
        except Exception:
            pass
    return []


def _record(surface: str, action: str, findings: List[Dict[str, Any]], **extra: Any) -> None:
    try:
        ledger.append_incident(
            {
                "ts": time.time(),
                "surface": surface,
                "action": action,
                "findings": [scanner.public_finding(f) for f in findings],
                **extra,
            }
        )
    except Exception:
        logger.debug("SecretShield: incident append failed", exc_info=True)


def _describe(findings: List[Dict[str, Any]]) -> str:
    parts = []
    for finding in findings[:6]:
        where = f" at {finding['path']}" if finding.get("path") else ""
        parts.append(f"{finding['kind']} ({finding['preview']}, {finding['length']} chars){where}")
    suffix = f" and {len(findings) - 6} more" if len(findings) > 6 else ""
    return "; ".join(parts) + suffix


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


def on_pre_tool_call(tool_name: str, args: Any = None, **kwargs: Any) -> Optional[Dict[str, Any]]:
    mode = _mode()
    if mode == "off":
        return None
    try:
        findings = scanner.scan_args(args if isinstance(args, dict) else {}, _disabled_kinds())
    except Exception:
        logger.warning("SecretShield: scanner failed on pre_tool_call", exc_info=True)
        if mode == "enforce":
            _record("tool_call", "blocked_scanner_error", [], tool=tool_name,
                    session_id=str(kwargs.get("session_id") or ""))
            return {
                "action": "block",
                "message": (
                    "SecretShield could not scan this tool call (internal scanner "
                    "error), so the call was blocked rather than shipped unchecked."
                ),
            }
        return None
    if not findings:
        return None
    session_id = str(kwargs.get("session_id") or "")
    if mode == "warn":
        _record("tool_call", "warned", findings, tool=tool_name, session_id=session_id)
        return None
    if mode == "redact":
        _record("tool_call", "redacted_args", findings, tool=tool_name, session_id=session_id)
        return {"action": "modify", "args": scanner.redact_args(args, _disabled_kinds())}
    _record("tool_call", "blocked", findings, tool=tool_name, session_id=session_id)
    return {
        "action": "block",
        "message": (
            "SecretShield blocked this tool call: its arguments contain "
            f"credential material ({_describe(findings)}). Credentials must not "
            "be sent through tool calls. Remove the credential, use the tool's "
            "own authenticated configuration instead, and retry. This attempt "
            "was recorded in the SecretShield incident ledger."
        ),
    }


def on_post_tool_call(tool_name: str, args: Any = None, result: Any = None, **kwargs: Any) -> None:
    if _mode() == "off":
        return
    text = result if isinstance(result, str) else ""
    if not text:
        return
    try:
        findings = scanner.scan_text(text, _disabled_kinds())
    except Exception:
        logger.debug("SecretShield: scanner failed on post_tool_call", exc_info=True)
        return
    if findings:
        _record("tool_result", "detected", findings, tool=tool_name,
                session_id=str(kwargs.get("session_id") or ""))


def on_pre_llm_call(is_first_turn: bool = False, **kwargs: Any) -> Optional[Dict[str, str]]:
    if not is_first_turn or _mode() == "off":
        return None
    return {
        "context": (
            "SecretShield is active in this profile. Never place credentials "
            "(API keys, tokens, passwords, private keys) inside tool call "
            "arguments or in your replies: tool calls carrying them are "
            "blocked or redacted, replies are redacted before delivery, and "
            "every attempt is written to a local incident ledger. Use each "
            "tool's own authenticated configuration instead of passing secrets "
            "around as text."
        )
    }


def on_transform_llm_output(response_text: str = "", **kwargs: Any) -> Optional[str]:
    mode = _mode()
    if mode == "off" or not response_text:
        return None
    session_id = str(kwargs.get("session_id") or "")
    try:
        redacted, findings = scanner.redact_text(response_text, _disabled_kinds())
    except Exception:
        logger.warning("SecretShield: scanner failed on transform_llm_output", exc_info=True)
        if mode == "enforce":
            _record("reply", "withheld_scanner_error", [], session_id=session_id)
            return (
                "[SecretShield: this reply was withheld because the credential "
                "scanner failed internally. The original text was not shipped "
                "unchecked.]"
            )
        return None
    if not findings:
        return None
    if mode == "warn":
        _record("reply", "warned", findings, session_id=session_id)
        return None
    _record("reply", "redacted", findings, session_id=session_id)
    kinds = ", ".join(sorted({f["kind"] for f in findings}))
    return (
        redacted
        + f"\n\n[SecretShield: {len(findings)} credential(s) redacted from this "
        f"reply before delivery ({kinds}). See /shield for the incident ledger.]"
    )


# ---------------------------------------------------------------------------
# User surfaces: /shield command, shield_status tool, hermes secretshield CLI
# ---------------------------------------------------------------------------


def _format_incidents(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "SecretShield incident ledger is empty. No credential has been detected yet."
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row.get("action", "?")] = counts.get(row.get("action", "?"), 0) + 1
    lines = ["SecretShield incidents (most recent last):"]
    lines.append("Counts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for row in rows[-5:]:
        kinds = ", ".join(f.get("kind", "?") for f in (row.get("findings") or [])) or "-"
        lines.append(
            f"- {row.get('action')} on {row.get('surface')} | {kinds} "
            f"| tool={row.get('tool') or '-'} | session={row.get('session_id') or '-'}"
        )
    return "\n".join(lines)


def shield_command(raw_args: str = "", **kwargs: Any) -> str:
    return _format_incidents(ledger.read_recent(limit=100))


def shield_status_tool(params: Dict[str, Any] | None = None, **kwargs: Any) -> str:
    rows = ledger.read_recent(limit=100)
    return json.dumps(
        {
            "success": True,
            "mode": _mode(),
            "incidents_recent": len(rows),
            "latest": rows[-5:],
            "note": "Full history lives in <HERMES_HOME>/secretshield/incidents.jsonl",
        }
    )


def _cli_setup(subparser: Any) -> None:
    sub = subparser.add_subparsers(dest="secretshield_action")
    sub.add_parser("incidents", help="Show recent SecretShield incidents")
    sub.add_parser("stats", help="Show SecretShield incident counts")


def _cli_handler(args: Any) -> int:
    print(_format_incidents(ledger.read_recent(limit=100)))
    return 0


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(ctx: Any) -> None:
    global _CTX
    _CTX = ctx

    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    try:
        ctx.register_hook("transform_llm_output", on_transform_llm_output, hold_stream=True)
    except TypeError:
        ctx.register_hook("transform_llm_output", on_transform_llm_output)

    ctx.register_command(
        "shield",
        shield_command,
        description="Show recent SecretShield credential incidents",
    )
    ctx.register_tool(
        name="shield_status",
        toolset="secretshield",
        schema={
            "name": "shield_status",
            "description": (
                "Return SecretShield's recent incident ledger: credentials "
                "blocked or redacted in tool calls and replies."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
        handler=shield_status_tool,
    )
    ctx.register_cli_command(
        "secretshield",
        "Inspect the SecretShield incident ledger",
        _cli_setup,
        _cli_handler,
        description="Show SecretShield incidents recorded on this machine",
    )
