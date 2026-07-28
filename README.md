# Canarytokens incident normalizer

`@mgreten/canarytokens` is a read-only Swamp model with deterministic keying and state-transition decisions that turns caller-supplied Canarytoken observations into a persisted, bounded incident report. Processing and acknowledgement timestamps come from the execution clock. It is designed as the safe analysis layer between a private alert collector and an operator-facing response workflow.

The model does **not** create, deploy, read, modify, or delete Canarytokens. It makes no network request, does not inspect host files or Swamp vaults, does not access credentials, and does not send Discord, email, ntfy, or Home Assistant notifications. A separate explicitly authorized private collector should perform any provider/webhook integration and pass only normalized, redacted observations to `ingest`.

## Methods

- `ingest(events, policy?)` validates and processes every supplied observation (up to the schema limit of 100), persistently deduplicates matching signals, and emits containment-oriented response guidance.
- `acknowledge(keys)` marks existing persisted incident keys as reviewed. Repeating an acknowledgement preserves its original acknowledgement time. It cannot resolve an upstream provider event or change a deployed token.

Event IDs are represented only by deterministic SHA-256 keys and are replay-idempotent while their incident remains retained. Without an event ID, identity is derived from the token label, token type, action, and optional source. Duplicate or out-of-order observations at or before the current `lastSeenAt` are replay-idempotent. Later observations inside `dedupeMinutes` increment the occurrence count but are suppressed, unless they occurred after acknowledgement; such an observation reopens and is accepted. Observations outside the window are accepted.

`policy.maxIncidents` defaults to 500 (allowed range 1–5,000). The persisted incident list and event replay index retain the newest `lastSeenAt` values deterministically. Every retention eviction is disclosed through `evictedKeys`, `evictedCount`, and the report summary; accepted/suppressed decisions are also recorded as hashed keys. Once an incident is evicted, replay history for its event ID is intentionally evicted with it.

## Input boundary

Provide only already-authorized, normalized data. The strict input schema rejects unknown fields. Do not send token bodies, credentials, secret values, URLs, raw references, vault/file paths, user identifiers, private chat text, or broad provider payloads. Use a non-secret token label and, when needed, a redacted source identifier. The model makes no network calls and persists no raw event ID; nevertheless, callers remain responsible for redacting every accepted input field.

```json
{
  "events": [
    {
      "observedAt": "2026-07-28T14:00:00.000Z",
      "tokenLabel": "retired-mcp-fixture",
      "tokenType": "mcp_configuration",
      "action": "attempted_use",
      "sourceIp": "redacted-source-1",
      "severity": "critical"
    }
  ],
  "policy": { "dedupeMinutes": 60, "maxIncidents": 500 }
}
```

## Example method call

```text
swamp model method run canarytokens ingest --input '{"events":[{"observedAt":"2026-07-28T14:00:00.000Z","tokenLabel":"retired-mcp-fixture","tokenType":"mcp_configuration","action":"attempted_use","sourceIp":"redacted-source-1","severity":"critical"}]}'
swamp model method run canarytokens acknowledge --input '{"keys":["<sha256-incident-key>"]}'
```

A hit is a tripwire, not proof of compromise. Preserve the provider-side timestamp/reference, verify whether a documented reader could explain it, then compare the source against authorized activity before containment or credential rotation.

## Operational limitations

- "Read-only" means provider-read-only, not persistence-free: both methods write the declared report through Swamp's configured datastore. A filesystem-backed datastore therefore writes files even though this model makes no direct filesystem calls.
- The logical report has infinite lifetime and asks Swamp GC to retain 52 versions. That is a retention target, not a hard physical-storage bound when datastore GC is disabled or has not run.
- Decision arrays and `summary` describe only the latest operation. Use retained resource versions or an external audit sink when a cumulative history is required.
- SHA-256 keys are pseudonyms, not encryption. Predictable provider IDs may be guessable, so never supply a sensitive ID or treat its hash as secret protection.
- With `eventId`, that provider ID alone defines incident identity. Without it, identity excludes country, ASN, and severity. Caller-controlled timestamps determine deduplication, reopening, and recency retention; the model does not reject future clock skew.
- Recency retention can evict unacknowledged incidents. Eviction also removes retained event-ID replay history, so a later replay can be accepted again.
- This is the first registry release. Reports produced by pre-release Git revisions used a different schema and must be reset rather than reused.
