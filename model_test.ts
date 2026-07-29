import { model } from "./model.ts";

type Report = {
  incidents: Array<{
    key: string;
    tokenLabel: string;
    occurrences: number;
    status: "new" | "acknowledged";
    acknowledgedAt?: string;
  }>;
  acceptedKeys: string[];
  suppressedKeys: string[];
  evictedKeys: string[];
  evictedCount: number;
  replayEventKeys: string[];
  summary: string;
};

function harness() {
  let stored: unknown = null;
  const logs: Array<{ message: string; properties?: Record<string, unknown> }> =
    [];
  const reads: string[] = [];
  const writes: Array<{ resource: string; name: string }> = [];
  return {
    get stored() {
      return stored as Report;
    },
    logs,
    reads,
    writes,
    context: {
      logger: {
        info: (message: string, properties?: Record<string, unknown>) =>
          logs.push({ message, properties }),
      },
      readResource: (name: string) => {
        reads.push(name);
        return Promise.resolve(stored);
      },
      writeResource: (resource: string, name: string, value: unknown) => {
        writes.push({ resource, name });
        stored = model.resources.canaryIncidentReport.schema.parse(value);
        return Promise.resolve({ id: "test-handle" });
      },
    },
  };
}

const policy = { dedupeMinutes: 60, maxIncidents: 500 };
const event = (overrides: Record<string, unknown> = {}) => ({
  observedAt: "2026-07-28T14:00:00.000Z",
  tokenLabel: "fixture",
  tokenType: "dns",
  action: "lookup",
  severity: "high" as const,
  ...overrides,
});
const assert = (condition: unknown, message: string) => {
  if (!condition) throw new Error(message);
};

Deno.test("hashed tuple keys isolate delimiter collisions", async () => {
  const h = harness();
  await model.methods.ingest.execute({
    events: [
      event({ tokenLabel: "a|b", tokenType: "c" }),
      event({ tokenLabel: "a", tokenType: "b|c" }),
    ],
    policy,
  }, h.context);
  assert(h.stored.incidents.length === 2, "composite values must not collide");
  assert(
    h.stored.incidents.every((incident) => /^[0-9a-f]{64}$/.test(incident.key)),
    "keys must be SHA-256 hex",
  );
});

Deno.test("exact event ID replay is idempotent while retained", async () => {
  const h = harness();
  await model.methods.ingest.execute({
    events: [event({ eventId: "provider-1" })],
    policy,
  }, h.context);
  await model.methods.ingest.execute({
    events: [
      event({ eventId: "provider-1", observedAt: "2030-01-01T00:00:00.000Z" }),
    ],
    policy,
  }, h.context);
  assert(h.stored.acceptedKeys.length === 0, "replay must not be accepted");
  assert(h.stored.suppressedKeys.length === 1, "replay must be suppressed");
  assert(h.stored.incidents[0].occurrences === 1, "replay must not increment");
  assert(
    !JSON.stringify(h.stored).includes("provider-1"),
    "raw provider event ID must not be persisted",
  );
});

Deno.test("public argument schemas reject unknown and malformed fields", () => {
  assert(
    !model.globalArguments.safeParse({ unexpected: true }).success,
    "global arguments must be strict",
  );
  assert(
    !model.methods.ingest.arguments.safeParse({
      events: [event()],
      unexpected: true,
    }).success,
    "ingest arguments must be strict",
  );
  assert(
    !model.methods.ingest.arguments.safeParse({
      events: [event()],
      policy: { ...policy, unexpected: true },
    }).success,
    "policy must be strict",
  );
  assert(
    !model.methods.ingest.arguments.safeParse({
      events: [event({ rawReference: "must-not-pass" })],
    }).success,
    "event fields must be strict",
  );
  assert(
    !model.methods.ingest.arguments.safeParse({
      events: [event({ observedAt: "2026-07-28T14:00:00.0001Z" })],
    }).success,
    "timestamps beyond millisecond precision must be rejected",
  );
  assert(
    !model.methods.acknowledge.arguments.safeParse({ keys: ["not-a-hash"] })
      .success,
    "acknowledgement keys must be SHA-256 hex",
  );
  assert(
    !model.methods.acknowledge.arguments.safeParse({
      keys: ["a".repeat(64)],
      unexpected: true,
    }).success,
    "acknowledgement arguments must be strict",
  );
});

Deno.test("published incident model has a no-op upgrade to the package version", () => {
  assert(model.version === "2026.07.29.1", "model version must match package");
  const upgrade = model.upgrades.find((candidate) =>
    candidate.toVersion === model.version
  );
  assert(upgrade, "current model version must have an upgrade entry");
  const attributes = { retained: "unchanged" };
  assert(
    upgrade!.upgradeAttributes(attributes) === attributes,
    "creator release must not mutate incident-model attributes",
  );
});

Deno.test("all 100 schema-accepted events are processed", async () => {
  const h = harness();
  const events = Array.from(
    { length: 100 },
    (_, index) => event({ eventId: `event-${index}` }),
  );
  await model.methods.ingest.execute({ events, policy }, h.context);
  assert(h.stored.acceptedKeys.length === 100, "all events must be accepted");
  assert(h.stored.incidents.length === 100, "all events must be persisted");
});

Deno.test("incident retention is bounded and eviction is explicit", async () => {
  const h = harness();
  await model.methods.ingest.execute({
    events: [
      event({ eventId: "old", observedAt: "2026-07-28T14:00:00.000Z" }),
      event({ eventId: "new", observedAt: "2026-07-28T15:00:00.000Z" }),
    ],
    policy: { dedupeMinutes: 60, maxIncidents: 1 },
  }, h.context);
  assert(h.stored.incidents.length === 1, "retention limit must be enforced");
  assert(h.stored.evictedCount === 1, "eviction count must be explicit");
  assert(h.stored.evictedKeys.length === 1, "evicted key must be recorded");
  assert(
    h.stored.replayEventKeys.length === 1,
    "event replay index must be bounded with retained incidents",
  );
  assert(
    h.stored.summary.includes("1 incident(s) evicted"),
    "summary must disclose eviction",
  );
});

Deno.test("stale out-of-order observations do not regress incident state", async () => {
  const h = harness();
  await model.methods.ingest.execute({
    events: [event({ observedAt: "2026-07-28T15:00:00.000Z" })],
    policy,
  }, h.context);
  await model.methods.ingest.execute({
    events: [event({ observedAt: "2026-07-28T14:00:00.000Z" })],
    policy,
  }, h.context);
  assert(
    h.stored.acceptedKeys.length === 0,
    "stale event must not be accepted",
  );
  assert(
    h.stored.suppressedKeys.length === 1,
    "stale event must be suppressed",
  );
  assert(
    h.stored.incidents[0].occurrences === 1,
    "stale event must not increment",
  );
});

Deno.test("delayed pre-acknowledgement observation does not reopen", async () => {
  const h = harness();
  await model.methods.ingest.execute({
    events: [event({ observedAt: "2020-01-01T10:00:00Z" })],
    policy,
  }, h.context);
  const key = h.stored.incidents[0].key;
  await model.methods.acknowledge.execute({ keys: [key] }, h.context);
  await model.methods.ingest.execute({
    events: [event({ observedAt: "2020-01-01T12:00:00.000Z" })],
    policy,
  }, h.context);
  assert(
    h.stored.incidents[0].status === "acknowledged",
    "pre-acknowledgement observation must stay acknowledged",
  );
  assert(
    h.stored.acceptedKeys.length === 0,
    "delayed event must be suppressed",
  );
  assert(
    h.stored.incidents[0].occurrences === 1,
    "delayed event must not count",
  );
});

Deno.test("retention ranks timestamps chronologically across ISO precision", async () => {
  const h = harness();
  await model.methods.ingest.execute({
    events: [
      event({
        eventId: "whole-second",
        observedAt: "2026-07-28T14:00:00Z",
        tokenLabel: "older",
      }),
      event({
        eventId: "fractional-second",
        observedAt: "2026-07-28T14:00:00.999Z",
        tokenLabel: "newer",
      }),
    ],
    policy: { dedupeMinutes: 60, maxIncidents: 1 },
  }, h.context);
  assert(
    h.stored.incidents[0].tokenLabel === "newer",
    "newest event must remain",
  );
});

Deno.test("acknowledgement is successful, repeat-safe, and later signal reopens", async () => {
  const h = harness();
  await model.methods.ingest.execute({
    events: [event({ observedAt: "2030-07-28T14:00:00.000Z" })],
    policy,
  }, h.context);
  const key = h.stored.incidents[0].key;
  await model.methods.acknowledge.execute({ keys: [key] }, h.context);
  const acknowledgedAt = h.stored.incidents[0].acknowledgedAt;
  assert(h.stored.incidents[0].status === "acknowledged", "must acknowledge");
  await model.methods.acknowledge.execute({ keys: [key] }, h.context);
  assert(
    h.stored.incidents[0].acknowledgedAt === acknowledgedAt,
    "repeat must preserve time",
  );
  await model.methods.ingest.execute({
    events: [event({ observedAt: "2030-07-28T16:01:00.000Z" })],
    policy: { dedupeMinutes: 60, maxIncidents: 500 },
  }, h.context);
  assert(h.stored.incidents[0].status === "new", "post-ack signal must reopen");
  assert(
    h.stored.acceptedKeys.length === 1,
    "reopened signal must be accepted",
  );
});

Deno.test("logs contain counts only and persistence uses fixed local names", async () => {
  const h = harness();
  await model.methods.ingest.execute({
    events: [event({ eventId: "sensitive-provider-reference" })],
    policy,
  }, h.context);
  await model.methods.acknowledge.execute({
    keys: [h.stored.incidents[0].key],
  }, h.context);
  const logs = JSON.stringify(h.logs);
  assert(
    !logs.includes("sensitive-provider-reference"),
    "logs must omit event data",
  );
  assert(h.reads.every((name) => name === "canary-current"), "read name fixed");
  assert(
    h.writes.every((write) =>
      write.resource === "canaryIncidentReport" &&
      write.name === "canary-current"
    ),
    "write resource and instance names fixed",
  );
});

Deno.test("acknowledge rejects unknown keys", async () => {
  const h = harness();
  await model.methods.ingest.execute({ events: [event()], policy }, h.context);
  try {
    await model.methods.acknowledge.execute(
      { keys: ["f".repeat(64)] },
      h.context,
    );
    throw new Error("acknowledge unexpectedly accepted unknown key");
  } catch (error) {
    if (
      !(error instanceof Error) || !error.message.includes("unknown incident")
    ) throw error;
  }
});
