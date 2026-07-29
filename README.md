# Canarytokens incident normalizer and web-token creator

This package provides two deliberately separate Swamp model types:

- `@mgreten/canarytokens` is the original provider-read-only incident normalizer. It has deterministic keying and state-transition decisions that turn caller-supplied observations into a persisted, bounded incident report. It still makes no network requests and cannot create or modify provider tokens.
- `@mgreten/canarytokens/creator` is an explicitly mutating sibling that creates one web token at a time against one operator-configured self-hosted Canarytokens endpoint. It requires a preview-bound confirmation, refuses redirects, blocks ambiguous retries, and stores generated token material through Swamp's sensitive-resource vault boundary.

Neither model sends Discord, email, ntfy, or Home Assistant notifications. A separate explicitly authorized private collector should perform webhook ingestion and pass only normalized, redacted observations to the incident model's `ingest` method.

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
- Reports produced by pre-release Git revisions used a different schema and must be reset rather than reused.

## Web-token creator

The creator intentionally supports only `web` tokens. Configure an exact HTTPS `/generate` endpoint and one HTTPS alert webhook globally. The endpoint cannot be overridden per call. Treat the webhook as sensitive and wire it from a Swamp vault expression.

```text
swamp model create @mgreten/canarytokens/creator canarytoken-creator \
  --global-arg 'apiEndpoint=https://canary.example.internal/<api-prefix>/generate' \
  --global-arg 'webhookUrl=${{ vault.get(canarytokens, alert-webhook-url) }}'

swamp model method run canarytoken-creator preview \
  --input '{"requestId":"operator-20260729-001","label":"decoy-admin-document"}'

# Read the preview artifact, inspect it, then pass its exact confirmation:
swamp model method run canarytoken-creator create \
  --input '{"requestId":"operator-20260729-001","label":"decoy-admin-document","confirmation":"create-web:<sha256>"}'

swamp model method run canarytoken-creator inventory
```

The `requestId` is a non-secret operator-supplied idempotency key. Once its pending receipt is durable, Swamp's per-model execution lock prevents concurrent and sequential calls for the same request. A completed request is safe to repeat and does not contact the provider again. A pending request represents an ambiguous crash/network window and is deliberately blocked from retry: reconcile it on the Canarytokens server and use a new request ID rather than risk silently creating duplicates. The provider's documented HTTP 400 validation response is recorded as failed and also requires a new request ID; every other unexpected status remains pending. This is not provider-backed exactly-once delivery: a cached remote datastore that loses its final state sync can lose the receipt after the provider has acted. Use a directly durable datastore when that failure boundary matters.

Generated token IDs, trigger URLs, hostnames, and management credentials are declared sensitive. Swamp moves them to its configured vault and persists only vault references. The ordinary inventory contains only the request ID, non-secret label, status, timestamps, and confirmation fingerprint. A separate durable safe receipt preserves idempotency after an item leaves the bounded 100-item inventory. Do not put locations, credentials, URLs, or other secrets in `requestId` or `label`.

The open-source Canarytokens `/generate` route is an implementation contract, not a documented stable public API. Pin and test the exact endpoint for your deployment before use. In the deployment used to validate this model, successful responses returned an empty `webhook_url` even though the requested webhook was retained, so the creator validates the required generated fields rather than trusting that response field as an echo. The creator accepts operator-configured private/tailnet endpoints because self-hosting is its purpose; HTTPS and redirect refusal reduce destination drift, but DNS and certificate trust still belong to the host runtime. The model does not authorize Tailscale Funnel or make token callbacks publicly reachable. Only place generated tokens where both the trigger and alert callback can reach the configured infrastructure.
