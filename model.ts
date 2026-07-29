/** Read-only Canarytoken incident normalization model. */
import { z } from "npm:zod@4";

const Severity = z.enum(["critical", "high", "medium", "low"]);
const IncidentKeySchema = z.string().regex(/^[0-9a-f]{64}$/);
const TimestampSchema = z.string().datetime().max(24);
const AlertSchema = z.object({
  eventId: z.string().min(1).max(200).optional().describe(
    "Provider event identifier when available",
  ),
  observedAt: TimestampSchema.describe("ISO-8601 token interaction time"),
  tokenLabel: z.string().min(1).max(200).describe(
    "Non-secret operator token label",
  ),
  tokenType: z.string().min(1).max(100).describe(
    "Token class such as dns or mcp_configuration",
  ),
  action: z.string().min(1).max(200).describe("Observed interaction"),
  sourceIp: z.string().min(1).max(64).optional().describe(
    "Source IP or redacted source identifier",
  ),
  sourceCountry: z.string().length(2).optional(),
  sourceAsn: z.string().min(1).max(32).optional(),
  severity: Severity.default("high"),
}).strict();
const PolicySchema = z.object({
  dedupeMinutes: z.number().int().min(1).max(1440).default(60),
  maxIncidents: z.number().int().min(1).max(5000).default(500),
}).strict();
const StoredSchema = AlertSchema.omit({ eventId: true }).extend({
  key: IncidentKeySchema,
  firstSeenAt: TimestampSchema,
  lastSeenAt: TimestampSchema,
  occurrences: z.number().int().positive(),
  status: z.enum(["new", "acknowledged"]),
  acknowledgedAt: TimestampSchema.optional(),
  responseSteps: z.array(z.string().max(300)).max(5),
});
const ReportSchema = z.object({
  generatedAt: TimestampSchema,
  policy: PolicySchema,
  incidents: z.array(StoredSchema).max(5000),
  replayEventKeys: z.array(IncidentKeySchema).max(5000),
  acceptedKeys: z.array(IncidentKeySchema).max(100),
  suppressedKeys: z.array(IncidentKeySchema).max(100),
  evictedKeys: z.array(IncidentKeySchema).max(5100),
  evictedCount: z.number().int().min(0).max(5100),
  summary: z.string().max(500),
}).strict();
type Alert = z.infer<typeof AlertSchema>;
type Incident = z.infer<typeof StoredSchema>;
type Report = z.infer<typeof ReportSchema>;
type Context = {
  logger: {
    info: (message: string, properties?: Record<string, unknown>) => void;
  };
  readResource: (name: string) => Promise<unknown>;
  writeResource: (
    resourceName: string,
    instanceName: string,
    value: Report,
  ) => Promise<unknown>;
};
async function hashTuple(tuple: unknown[]): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(tuple));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}
const keyFor = (event: Alert) =>
  event.eventId ? hashTuple(["event", event.eventId]) : hashTuple([
    "signal",
    event.tokenLabel,
    event.tokenType,
    event.action,
    event.sourceIp ?? null,
  ]);
function withoutEventId(event: Alert): Omit<Alert, "eventId"> {
  const { eventId: _eventId, ...persistable } = event;
  return persistable;
}
function steps(event: Alert): string[] {
  const result = [
    "Preserve the provider-side incident reference and timestamp.",
    "Verify whether the token placement has an expected authorized reader.",
    "Review the source identifier against recent authorized activity before containment.",
  ];
  if (
    event.severity === "critical" || event.tokenType === "mcp_configuration"
  ) {
    result.push(
      "Temporarily disable the affected integration or agent path pending review.",
    );
  }
  if (["aws_keys", "kubeconfig", "wireguard_vpn"].includes(event.tokenType)) {
    result.push(
      "Treat this as credential-like exposure: review access logs and rotate adjacent real credentials only if evidence warrants it.",
    );
  }
  return result;
}
function inWindow(previous: string, now: string, minutes: number) {
  const elapsed = new Date(now).getTime() - new Date(previous).getTime();
  return elapsed >= 0 && elapsed < minutes * 60000;
}
function isNotLater(candidate: string, previous: string) {
  return new Date(candidate).getTime() <= new Date(previous).getTime();
}
function isLater(candidate: string, previous: string) {
  return new Date(candidate).getTime() > new Date(previous).getTime();
}
const IngestArgs = z.object({
  events: z.array(AlertSchema).min(1).max(100).describe(
    "Caller-supplied authorized Canarytoken observations",
  ),
  policy: PolicySchema.default({ dedupeMinutes: 60, maxIncidents: 500 }),
}).strict();
const AcknowledgeArgs = z.object({
  keys: z.array(IncidentKeySchema).min(1).max(100),
}).strict();

/**
 * Normalizes caller-supplied Canarytoken observations without network, token,
 * vault, filesystem, credential, or notification side effects.
 */
export const model = {
  type: "@mgreten/canarytokens",
  version: "2026.07.29.1",
  upgrades: [{
    toVersion: "2026.07.29.1",
    description:
      "Publish the separate creator model; no incident-model argument or stored-data changes",
    upgradeAttributes: (old: Record<string, unknown>) => old,
  }],
  globalArguments: z.object({}).strict(),
  resources: {
    canaryIncidentReport: {
      description:
        "Current normalized Canarytoken incidents, deduplication decisions, acknowledgements, and response guidance",
      schema: ReportSchema,
      lifetime: "infinite",
      garbageCollection: 52,
    },
  },
  methods: {
    ingest: {
      description:
        "Normalize supplied Canarytoken events, deduplicate bounded repeats, and persist response guidance. No network or notification side effects.",
      arguments: IngestArgs,
      execute: async (args: z.infer<typeof IngestArgs>, ctx: Context) => {
        ctx.logger.info("Canarytoken event ingestion started", {
          received: args.events.length,
        });
        const prior = ReportSchema.nullable().parse(
          await ctx.readResource("canary-current"),
        );
        const now = new Date().toISOString();
        const byKey = new Map((prior?.incidents ?? []).map((i) => [i.key, i]));
        const replayEventKeys = new Set(prior?.replayEventKeys ?? []);
        const acceptedKeys: string[] = [];
        const suppressedKeys: string[] = [];
        for (const event of args.events) {
          const key = await keyFor(event);
          if (event.eventId && replayEventKeys.has(key)) {
            suppressedKeys.push(key);
            continue;
          }
          const old = byKey.get(key);
          if (
            old && !event.eventId &&
            isNotLater(event.observedAt, old.lastSeenAt)
          ) {
            suppressedKeys.push(key);
            continue;
          }
          if (
            old && !event.eventId && old.status === "acknowledged" &&
            old.acknowledgedAt !== undefined
          ) {
            if (!isLater(event.observedAt, old.acknowledgedAt)) {
              suppressedKeys.push(key);
              continue;
            }
            byKey.set(key, {
              ...old,
              ...withoutEventId(event),
              lastSeenAt: event.observedAt,
              occurrences: old.occurrences + 1,
              status: "new",
              acknowledgedAt: undefined,
              responseSteps: steps(event),
            });
            acceptedKeys.push(key);
            continue;
          }
          if (
            old && !event.eventId &&
            inWindow(
              old.lastSeenAt,
              event.observedAt,
              args.policy.dedupeMinutes,
            )
          ) {
            byKey.set(key, {
              ...old,
              ...withoutEventId(event),
              lastSeenAt: event.observedAt,
              occurrences: old.occurrences + 1,
              responseSteps: steps(event),
            });
            suppressedKeys.push(key);
            continue;
          }
          const incident: Incident = old
            ? {
              ...old,
              ...withoutEventId(event),
              key,
              lastSeenAt: event.observedAt,
              occurrences: old.occurrences + 1,
              status: "new",
              acknowledgedAt: undefined,
              responseSteps: steps(event),
            }
            : {
              ...withoutEventId(event),
              key,
              firstSeenAt: event.observedAt,
              lastSeenAt: event.observedAt,
              occurrences: 1,
              status: "new",
              responseSteps: steps(event),
            };
          byKey.set(key, incident);
          if (event.eventId) replayEventKeys.add(key);
          acceptedKeys.push(key);
        }
        const rankedIncidents = [...byKey.values()].sort((a, b) => {
          const newestFirst = new Date(b.lastSeenAt).getTime() -
            new Date(a.lastSeenAt).getTime();
          return newestFirst || a.key.localeCompare(b.key);
        });
        const incidents = rankedIncidents.slice(0, args.policy.maxIncidents);
        const evictedKeys = rankedIncidents.slice(args.policy.maxIncidents).map(
          (incident) => incident.key,
        );
        const evictedCount = evictedKeys.length;
        const retainedKeys = new Set(incidents.map((incident) => incident.key));
        const retainedReplayEventKeys = [...replayEventKeys].filter((key) =>
          retainedKeys.has(key)
        ).sort();
        const summary = acceptedKeys.length === 0
          ? `No material new Canarytoken signals; ${suppressedKeys.length} duplicate signal(s) suppressed; ${evictedCount} incident(s) evicted by retention policy.`
          : `${acceptedKeys.length} material Canarytoken signal(s) accepted; ${suppressedKeys.length} duplicate signal(s) suppressed; ${evictedCount} incident(s) evicted by retention policy.`;
        const report: Report = {
          generatedAt: now,
          policy: args.policy,
          incidents,
          replayEventKeys: retainedReplayEventKeys,
          acceptedKeys,
          suppressedKeys,
          evictedKeys,
          evictedCount,
          summary,
        };
        const handle = await ctx.writeResource(
          "canaryIncidentReport",
          "canary-current",
          report,
        );
        ctx.logger.info("Canarytoken event ingestion completed", {
          accepted: acceptedKeys.length,
          suppressed: suppressedKeys.length,
        });
        return { dataHandles: [handle] };
      },
    },
    acknowledge: {
      description:
        "Mark persisted incidents as operator-acknowledged; does not notify, close provider incidents, or change token deployment.",
      arguments: AcknowledgeArgs,
      execute: async (args: z.infer<typeof AcknowledgeArgs>, ctx: Context) => {
        ctx.logger.info("Canarytoken acknowledgement started", {
          requested: args.keys.length,
        });
        const prior = ReportSchema.nullable().parse(
          await ctx.readResource("canary-current"),
        );
        if (!prior) {
          throw new Error(
            "No Canarytoken incident report exists to acknowledge",
          );
        }
        const requested = new Set(args.keys);
        const existing = new Set(prior.incidents.map((i) => i.key));
        const missing = args.keys.filter((key) => !existing.has(key));
        if (missing.length) {
          throw new Error(
            `Cannot acknowledge unknown incident key(s): ${missing.join(", ")}`,
          );
        }
        const now = new Date().toISOString();
        const incidents = prior.incidents.map((i) =>
          requested.has(i.key)
            ? {
              ...i,
              status: "acknowledged" as const,
              acknowledgedAt: i.acknowledgedAt ?? now,
            }
            : i
        );
        const report: Report = {
          ...prior,
          generatedAt: now,
          incidents,
          acceptedKeys: [],
          suppressedKeys: [],
          evictedKeys: [],
          evictedCount: 0,
          summary: `${requested.size} Canarytoken incident(s) acknowledged.`,
        };
        const handle = await ctx.writeResource(
          "canaryIncidentReport",
          "canary-current",
          report,
        );
        ctx.logger.info("Canarytoken acknowledgement completed", {
          acknowledged: requested.size,
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
