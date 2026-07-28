/** Read-only Canarytoken incident normalization model. */
import { z } from "npm:zod@4";

const Severity = z.enum(["critical", "high", "medium", "low"]);
const AlertSchema = z.object({
  eventId: z.string().min(1).max(200).optional().describe(
    "Provider event identifier when available",
  ),
  observedAt: z.string().datetime().describe("ISO-8601 token interaction time"),
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
  rawReference: z.string().url().optional().describe(
    "Authorized provider incident reference; never credentials",
  ),
});
const PolicySchema = z.object({
  dedupeMinutes: z.number().int().min(1).max(1440).default(60),
  maxEvents: z.number().int().min(1).max(100).default(50),
});
const StoredSchema = AlertSchema.extend({
  key: z.string(),
  firstSeenAt: z.string().datetime(),
  lastSeenAt: z.string().datetime(),
  occurrences: z.number().int().positive(),
  status: z.enum(["new", "acknowledged"]),
  acknowledgedAt: z.string().datetime().optional(),
  responseSteps: z.array(z.string()),
});
const ReportSchema = z.object({
  generatedAt: z.string().datetime(),
  policy: PolicySchema,
  incidents: z.array(StoredSchema),
  acceptedKeys: z.array(z.string()),
  suppressedKeys: z.array(z.string()),
  summary: z.string(),
});
type Alert = z.infer<typeof AlertSchema>;
type Incident = z.infer<typeof StoredSchema>;
type Report = z.infer<typeof ReportSchema>;
type Context = {
  logger: {
    info: (message: string, properties?: Record<string, unknown>) => void;
  };
  readResource?: (name: string) => Promise<unknown>;
  writeResource: (
    resourceName: string,
    instanceName: string,
    value: Report,
  ) => Promise<unknown>;
};
const keyFor = (event: Alert) =>
  event.eventId ??
    [
      event.tokenLabel,
      event.tokenType,
      event.action,
      event.sourceIp ?? "unknown-source",
    ].join("|");
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
const IngestArgs = z.object({
  events: z.array(AlertSchema).min(1).max(100).describe(
    "Caller-supplied authorized Canarytoken observations",
  ),
  policy: PolicySchema.default({ dedupeMinutes: 60, maxEvents: 50 }),
});
const AcknowledgeArgs = z.object({
  keys: z.array(z.string().min(1)).min(1).max(100),
});

/**
 * Normalizes caller-supplied Canarytoken observations without network, token,
 * vault, filesystem, credential, or notification side effects.
 */
export const model = {
  type: "@mgreten/canarytokens",
  version: "2026.07.28.1",
  globalArguments: z.object({}),
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
        const prior = ReportSchema.nullable().parse(
          await ctx.readResource?.("canary-current"),
        );
        const now = new Date().toISOString();
        const byKey = new Map((prior?.incidents ?? []).map((i) => [i.key, i]));
        const acceptedKeys: string[] = [];
        const suppressedKeys: string[] = [];
        for (const event of args.events.slice(0, args.policy.maxEvents)) {
          const key = keyFor(event);
          const old = byKey.get(key);
          if (old && inWindow(old.lastSeenAt, now, args.policy.dedupeMinutes)) {
            byKey.set(key, {
              ...old,
              lastSeenAt: now,
              occurrences: old.occurrences + 1,
            });
            suppressedKeys.push(key);
            continue;
          }
          const incident: Incident = old
            ? {
              ...old,
              ...event,
              key,
              lastSeenAt: now,
              occurrences: old.occurrences + 1,
              status: "new",
              acknowledgedAt: undefined,
              responseSteps: steps(event),
            }
            : {
              ...event,
              key,
              firstSeenAt: now,
              lastSeenAt: now,
              occurrences: 1,
              status: "new",
              responseSteps: steps(event),
            };
          byKey.set(key, incident);
          acceptedKeys.push(key);
        }
        const incidents = [...byKey.values()].sort((a, b) =>
          b.lastSeenAt.localeCompare(a.lastSeenAt) || a.key.localeCompare(b.key)
        );
        const summary = acceptedKeys.length === 0
          ? "No material new Canarytoken signals; all received events were deduplicated."
          : `${acceptedKeys.length} material Canarytoken signal(s) accepted; ${suppressedKeys.length} duplicate signal(s) suppressed.`;
        const report: Report = {
          generatedAt: now,
          policy: args.policy,
          incidents,
          acceptedKeys,
          suppressedKeys,
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
        const prior = ReportSchema.nullable().parse(
          await ctx.readResource?.("canary-current"),
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
            ? { ...i, status: "acknowledged" as const, acknowledgedAt: now }
            : i
        );
        const report: Report = {
          ...prior,
          generatedAt: now,
          incidents,
          acceptedKeys: [],
          suppressedKeys: [],
          summary: `${requested.size} Canarytoken incident(s) acknowledged.`,
        };
        const handle = await ctx.writeResource(
          "canaryIncidentReport",
          "canary-current",
          report,
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
