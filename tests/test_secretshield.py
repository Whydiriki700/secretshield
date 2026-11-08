import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("ss_init", ROOT / "__init__.py")
init = importlib.util.module_from_spec(spec)
sys.modules["ss_init"] = init
spec.loader.exec_module(init)
scanner = init.scanner
ledger = init.ledger

FAKE_OPENAI = "sk-proj-" + "A" * 40
FAKE_GITHUB = "ghp_" + "B" * 36
FAKE_AWS = "AKIA" + "C" * 16


class FakeCtx:
    def __init__(self, config=None):
        self.config = config or {}
        self.hooks = {}
        self.tools = {}
        self.commands = {}

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def register_hook(self, name, cb, **kw):
        self.hooks[name] = cb

    def register_tool(self, name, toolset, schema, handler, **kw):
        self.tools[name] = handler

    def register_command(self, name, cb, description=""):
        self.commands[name] = cb

    def register_cli_command(self, *a, **kw):
        pass


def setup_module():
    import os
    import tempfile

    os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="secretshield-test-")
    init.register(FakeCtx())


def test_scanner_finds_vendor_keys():
    findings = scanner.scan_text(f"key is {FAKE_OPENAI} ok")
    assert findings and findings[0]["kind"] == "openai_key"
    assert findings[0]["length"] == len(FAKE_OPENAI)
    findings = scanner.scan_text(FAKE_GITHUB)
    assert findings and findings[0]["kind"] == "github_token"
    findings = scanner.scan_text(FAKE_AWS)
    assert findings and findings[0]["kind"] == "aws_access_key"


def test_scanner_ignores_prose():
    assert scanner.scan_text("the password field is required, see the docs") == []
    assert scanner.scan_text("token economy and key insights from the report") == []
    assert scanner.scan_text("sk- is a common prefix in discussions") == []


def test_scanner_assignment_and_bearer():
    findings = scanner.scan_text('api_key = "abcd1234efgh5678"')
    assert findings and findings[0]["kind"] == "assigned_secret"
    findings = scanner.scan_text("Authorization: Bearer abcdefgh12345678._-xyz")
    assert findings and findings[0]["kind"] == "bearer_credential"


def test_redact_text_removes_secret():
    redacted, findings = scanner.redact_text(f"leak {FAKE_OPENAI} end")
    assert FAKE_OPENAI not in redacted
    assert "REDACTED by SecretShield" in redacted
    assert len(findings) == 1


def test_pre_tool_call_blocks_in_enforce():
    init.register(FakeCtx())
    result = init.on_pre_tool_call("terminal", {"command": f"curl -H 'Authorization: Bearer abcdefgh12345678' https://x"}, session_id="s1")
    assert result and result["action"] == "block"
    assert "Credential" in result["message"] or "credential" in result["message"]
    assert "abcdefgh12345678" not in result["message"]


def test_pre_tool_call_clean_passes():
    init.register(FakeCtx())
    assert init.on_pre_tool_call("terminal", {"command": "ls -la"}, session_id="s1") is None


def test_pre_tool_call_redact_mode_modifies():
    init.register(FakeCtx({"mode": "redact"}))
    result = init.on_pre_tool_call("write_file", {"content": f"token: {FAKE_GITHUB}"}, session_id="s2")
    assert result and result["action"] == "modify"
    assert FAKE_GITHUB not in json.dumps(result["args"])


def test_transform_redacts_reply():
    init.register(FakeCtx())
    out = init.on_transform_llm_output(f"Here is the key: {FAKE_OPENAI}", session_id="s3")
    assert out is not None and FAKE_OPENAI not in out
    assert "SecretShield" in out


def test_transform_clean_reply_untouched():
    init.register(FakeCtx())
    assert init.on_transform_llm_output("All done, report saved.", session_id="s3") is None


def test_scan_performance_on_long_hyphenated_text():
    import time

    text = "a-" * 150_000  # 300 KB of hyphenated text
    assert len(text) == 300_000
    start = time.perf_counter()
    findings = scanner.scan_text(text)
    elapsed = time.perf_counter() - start
    assert findings == []
    assert elapsed < 0.2, f"scan of 300 KB hyphenated text took {elapsed:.3f}s"


def test_ledger_never_stores_secret():
    import os
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    old = os.environ.get("HERMES_HOME")
    os.environ["HERMES_HOME"] = str(tmp)
    try:
        init.register(FakeCtx())
        init.on_pre_tool_call("terminal", {"command": f"echo {FAKE_OPENAI}"}, session_id="s9")
        raw = (tmp / "secretshield" / "incidents.jsonl").read_text(encoding="utf-8")
        assert FAKE_OPENAI not in raw
        row = json.loads(raw.strip().splitlines()[-1])
        assert row["action"] == "blocked"
        assert row["findings"][0]["kind"] == "openai_key"
    finally:
        if old is None:
            os.environ.pop("HERMES_HOME", None)
        else:
            os.environ["HERMES_HOME"] = old
