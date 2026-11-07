# SecretShield

**Credentials stop at the tool boundary.**

Hermes already masks known credential formats in logs and transcripts.
SecretShield is the enforcement layer on top of that masking: it decides
whether credential material is allowed to *move*.

## What it does

1. **`pre_tool_call` (before dispatch)** scans every tool call's arguments.
   A credential found there never leaves the machine inside a shell command,
   an HTTP request, a message send, or a file write:
   - `enforce` mode (default): the call is **blocked** with an explanation.
   - `redact` mode: the arguments are rewritten with the credential replaced
     and the call proceeds.
   - `warn` mode: the detection is recorded, nothing is changed.
2. **`transform_llm_output`** scans the finished reply before delivery.
   Credentials in the text are redacted and a notice is appended, so a
   secret the model decides to quote never reaches the chat surface.
3. **`post_tool_call`** scans tool results and records detections, so a
   tool that printed a secret into the session is visible in the ledger.

Detection is deterministic: vendor credential formats (OpenAI, Anthropic,
GitHub, AWS, Google, Slack, Stripe, SendGrid, npm, PyPI, Telegram, Discord,
JWTs, PEM private keys, bearer credentials, basic-auth URLs) plus
`key = value` assignment contexts. No LLM, no network.

## Incident ledger

Every detection is appended to `<HERMES_HOME>/secretshield/incidents.jsonl`
with only metadata: timestamp, surface, action, credential kind, length,
and a masked preview (first 4 characters). **The secret value is never
stored anywhere.** Inspect it with `/shield`, the `shield_status` tool,
or `hermes secretshield incidents`.

## Configuration

```yaml
plugins:
  entries:
    secretshield:
      settings:
        mode: enforce        # enforce | redact | warn | off
        disabled_kinds: []   # detector kinds to skip, e.g. ["jwt"]
```

## Failure behavior

The scanner fails closed where it matters: if scanning itself errors in
`enforce` mode, a tool call is blocked rather than shipped unchecked and
a reply is withheld rather than delivered unscanned. Every such event is
recorded in the ledger as a scanner-error action.

## Disclosure

SecretShield observes all tool call arguments, tool results, and final
replies in sessions of profiles where it is enabled, in order to scan
them locally. It makes no network calls, starts no processes, and writes
only its incident ledger under `<HERMES_HOME>/secretshield/`. Declared
capabilities in `plugin.yaml` match the registered hooks and tool exactly.

## Verification

- `hermes plugins validate`: passed, security scan safe.
- `hermes plugins doctor`: OK, 1 tool and 4 hooks registered under the
  real runtime contracts.
- Unit tests cover every detector family, all four modes, and a proof
  that the ledger never contains a secret value.
- Live session test: a terminal call carrying a fake OpenAI key was
  blocked before dispatch and recorded in the ledger with a masked
  preview only.
