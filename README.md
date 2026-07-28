# Canarytokens incident normalizer

`@mgreten/canarytokens` is a deterministic, read-only Swamp model that turns caller-supplied Canarytoken observations into a persisted, bounded incident report. It is designed as the safe analysis layer between a private alert collector and an operator-facing response workflow.

The model does **not** create, deploy, read, modify, or delete Canarytokens. It makes no network request, does not inspect host files or Swamp vaults, does not access credentials, and does not send Discord, email, ntfy, or Home Assistant notifications. A separate explicitly authorized private collector should perform any provider/webhook integration and pass only normalized, redacted observations to `ingest`.

## Methods

- `ingest(events, policy?)` validates up to 100 observations, persistently deduplicates matching token/source/action signals inside a configurable 1–1,440 minute window, and emits containment-oriented response guidance.
- `acknowledge(keys)` marks existing persisted incident keys as reviewed. It cannot resolve an upstream provider event or change a deployed token.

## Input boundary

Provide only already-authorized, normalized data. Do not send token bodies, credentials, secret values, raw vault/file paths, user identifiers, private chat text, or broad provider payloads. Use a non-secret token label and, when needed, a redacted source identifier.

```json
{
  "observedAt": "2026-07-28T14:00:00.000Z",
  "tokenLabel": "retired-mcp-fixture",
  "tokenType": "mcp_configuration",
  "action": "attempted_use",
  "sourceIp": "redacted-source-1",
  "severity": "critical"
}
```

## Example method call

```text
swamp model method run canarytokens ingest --input '<normalized event JSON>'
swamp model method run canarytokens acknowledge --input '{"keys":["provider-event-id"]}'
```

A hit is a tripwire, not proof of compromise. Preserve the provider-side timestamp/reference, verify whether a documented reader could explain it, then compare the source against authorized activity before containment or credential rotation.
