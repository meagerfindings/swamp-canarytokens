import { model } from "./model.ts";

Deno.test("ingest accepts a material signal and suppresses its repeat", async () => {
  let stored: unknown = null;
  const context = {
    logger: { info: () => undefined },
    readResource: () => Promise.resolve(stored),
    writeResource: (_resource: string, _name: string, value: unknown) => {
      stored = value;
      return Promise.resolve({ id: "test-handle" });
    },
  };
  const event = {
    observedAt: "2026-07-28T14:00:00.000Z",
    tokenLabel: "test-retired-mcp-fixture",
    tokenType: "mcp_configuration",
    action: "attempted_use",
    sourceIp: "test-source-1",
    severity: "critical" as const,
  };
  await model.methods.ingest.execute(
    { events: [event], policy: { dedupeMinutes: 1440, maxEvents: 10 } },
    context,
  );
  const first = stored as {
    acceptedKeys: string[];
    incidents: Array<{ status: string; responseSteps: string[] }>;
  };
  if (first.acceptedKeys.length !== 1) {
    throw new Error("expected material signal to be accepted");
  }
  if (first.incidents[0].status !== "new") {
    throw new Error("expected new incident");
  }
  if (
    !first.incidents[0].responseSteps.some((step) => step.includes("disable"))
  ) throw new Error("expected MCP containment guidance");
  await model.methods.ingest.execute(
    { events: [event], policy: { dedupeMinutes: 1440, maxEvents: 10 } },
    context,
  );
  const second = stored as { acceptedKeys: string[]; suppressedKeys: string[] };
  if (second.acceptedKeys.length !== 0 || second.suppressedKeys.length !== 1) {
    throw new Error("expected duplicate signal to be suppressed");
  }
});

Deno.test("acknowledge rejects unknown keys", async () => {
  const context = {
    logger: { info: () => undefined },
    readResource: () =>
      Promise.resolve({
        generatedAt: "2026-07-28T14:00:00.000Z",
        policy: { dedupeMinutes: 60, maxEvents: 10 },
        incidents: [],
        acceptedKeys: [],
        suppressedKeys: [],
        summary: "empty",
      }),
    writeResource: () => Promise.resolve({ id: "test-handle" }),
  };
  try {
    await model.methods.acknowledge.execute({ keys: ["missing"] }, context);
    throw new Error("acknowledge unexpectedly accepted unknown key");
  } catch (error) {
    if (
      !(error instanceof Error) || !error.message.includes("unknown incident")
    ) throw error;
  }
});
