/**
 * Create web Canarytokens against one operator-configured self-hosted server.
 *
 * This model is intentionally separate from @mgreten/canarytokens so the
 * incident normalizer keeps its no-network, provider-read-only contract.
 *
 * @module
 */

import { z } from "npm:zod@4";

const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_INVENTORY_ITEMS = 100;

const GlobalArgsSchema = z.object({
  apiEndpoint: z.string().url()
    .refine((value) => new URL(value).protocol === "https:", {
      message: "apiEndpoint must use HTTPS",
    })
    .refine((value) => {
      const url = new URL(value);
      return !url.username && !url.password && !url.search && !url.hash;
    }, {
      message:
        "apiEndpoint must not contain credentials, a query string, or a fragment",
    })
    .refine((value) => new URL(value).pathname.endsWith("/generate"), {
      message: "apiEndpoint must be the exact Canarytokens /generate endpoint",
    }).describe(
      "Exact HTTPS URL of the self-hosted Canarytokens /generate endpoint. The method never accepts a per-call override.",
    ),
  webhookUrl: z.string().url().refine(
    (value) => new URL(value).protocol === "https:",
    "webhookUrl must use HTTPS",
  ).meta({ sensitive: true }).describe(
    "Alert webhook attached to every created token. Wire this from a Swamp vault; it may contain an ingestion secret.",
  ),
  timeoutSeconds: z.number().int().min(2).max(30).default(10).describe(
    "Provider request timeout in seconds",
  ),
}).strict();

const RequestSchema = z.object({
  requestId: z.string().min(8).max(64).regex(/^[A-Za-z0-9._-]+$/).describe(
    "Unique non-secret idempotency key chosen by the operator",
  ),
  label: z.string().trim().min(1).max(128).describe(
    "Non-secret token label sent to Canarytokens as its memo",
  ),
});

const ConfirmationSchema = z.string().regex(/^create-web:[0-9a-f]{64}$/);

const PreviewSchema = z.object({
  requestId: RequestSchema.shape.requestId,
  label: RequestSchema.shape.label,
  tokenType: z.literal("web"),
  serverOrigin: z.string().url(),
  confirmation: ConfirmationSchema,
  warning: z.string(),
});

const InventoryItemSchema = z.object({
  requestId: RequestSchema.shape.requestId,
  label: RequestSchema.shape.label,
  tokenType: z.literal("web"),
  requestFingerprint: ConfirmationSchema,
  status: z.enum(["pending", "created", "failed"]),
  updatedAt: z.string().datetime({ offset: true }),
  createdAt: z.string().datetime({ offset: true }).optional(),
});

const InventorySchema = z.object({
  items: z.array(InventoryItemSchema).max(MAX_INVENTORY_ITEMS),
  summary: z.string(),
});
type Inventory = z.infer<typeof InventorySchema>;
type InventoryItem = z.infer<typeof InventoryItemSchema>;

const SecretTokenSchema = z.object({
  tokenType: z.literal("web"),
  token: z.string().min(1).meta({ sensitive: true }),
  tokenUrl: z.string().url().meta({ sensitive: true }),
  authToken: z.string().min(1).meta({ sensitive: true }),
  hostname: z.string().min(1).meta({ sensitive: true }),
});

const ProviderResponseSchema = z.object({
  token_type: z.literal("web"),
  token: z.string().min(1).meta({ sensitive: true }),
  token_url: z.string().url().meta({ sensitive: true }),
  auth_token: z.string().min(1).meta({ sensitive: true }),
  hostname: z.string().min(1).meta({ sensitive: true }),
  error: z.null(),
  error_message: z.null(),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;
type RequestArgs = z.infer<typeof RequestSchema>;
type FetchLike = (input: string, init: RequestInit) => Promise<Response>;
type MethodContext = {
  globalArgs: GlobalArgs;
  signal?: AbortSignal;
  logger: {
    info: (message: string, properties?: Record<string, unknown>) => void;
    warning: (message: string, properties?: Record<string, unknown>) => void;
  };
  readResource: (instanceName: string) => Promise<unknown>;
  writeResource: (
    specName: string,
    instanceName: string,
    data: unknown,
  ) => Promise<unknown>;
};

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function confirmationFor(
  args: RequestArgs,
  globalArgs: GlobalArgs,
): Promise<string> {
  const webhookFingerprint = await sha256(globalArgs.webhookUrl);
  const digest = await sha256(JSON.stringify({
    version: 1,
    apiEndpoint: globalArgs.apiEndpoint,
    webhookFingerprint,
    requestId: args.requestId,
    label: args.label,
    tokenType: "web",
  }));
  return `create-web:${digest}`;
}

async function readBoundedBody(response: Response): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null && Number(declaredLength) > MAX_RESPONSE_BYTES) {
    throw new Error("Canarytokens response exceeded the 64 KiB limit");
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Canarytokens response exceeded the 64 KiB limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

function inventoryWith(
  inventory: Inventory,
  item: InventoryItem,
): Inventory {
  const items = inventory.items.filter((candidate) =>
    candidate.requestId !== item.requestId
  );
  items.push(item);
  items.sort((left, right) => left.updatedAt.localeCompare(right.updatedAt));
  const bounded = items.slice(-MAX_INVENTORY_ITEMS);
  return {
    items: bounded,
    summary: `${bounded.length} retained web-token creation request(s)`,
  };
}

async function readInventory(context: MethodContext): Promise<Inventory> {
  const stored = await context.readResource("creator-inventory");
  return stored
    ? InventorySchema.parse(stored)
    : { items: [], summary: "Empty" };
}

async function writeInventory(
  context: MethodContext,
  inventory: Inventory,
): Promise<unknown> {
  return await context.writeResource(
    "creatorInventory",
    "creator-inventory",
    inventory,
  );
}

async function readReceipt(
  context: MethodContext,
  requestId: string,
): Promise<InventoryItem | null> {
  const stored = await context.readResource(`creator-receipt-${requestId}`);
  return stored ? InventoryItemSchema.parse(stored) : null;
}

async function requirePreview(
  context: MethodContext,
  args: RequestArgs,
  confirmation: string,
): Promise<void> {
  const stored = await context.readResource(
    `creator-preview-${args.requestId}`,
  );
  if (!stored) {
    throw new Error(
      `No persisted preview exists for request ${args.requestId}; run preview first`,
    );
  }
  const preview = PreviewSchema.parse(stored);
  if (
    preview.requestId !== args.requestId || preview.label !== args.label ||
    preview.tokenType !== "web" || preview.confirmation !== confirmation
  ) {
    throw new Error(
      `Persisted preview does not match request ${args.requestId}; run preview again`,
    );
  }
}

async function writeReceipt(
  context: MethodContext,
  receipt: InventoryItem,
): Promise<unknown> {
  return await context.writeResource(
    "creatorReceipt",
    `creator-receipt-${receipt.requestId}`,
    receipt,
  );
}

/** Execute the provider mutation. Exported so tests can inject fetch safely. */
export async function createWebToken(
  args: RequestArgs & { confirmation: string },
  context: MethodContext,
  fetcher: FetchLike = fetch,
): Promise<{ dataHandles: unknown[] }> {
  const globals = GlobalArgsSchema.parse(context.globalArgs);
  const expected = await confirmationFor(args, globals);
  if (args.confirmation !== expected) {
    throw new Error(
      "Confirmation does not match this request and configured destination; run preview again",
    );
  }
  await requirePreview(context, args, args.confirmation);

  const inventory = await readInventory(context);
  const existing = await readReceipt(context, args.requestId);
  if (existing && existing.requestFingerprint !== args.confirmation) {
    throw new Error(
      `Creation request ${args.requestId} is already bound to different configuration`,
    );
  }
  if (existing?.status === "created") {
    context.logger.info(
      "Creation request {requestId} is already complete; no provider call made",
      { requestId: args.requestId },
    );
    return {
      dataHandles: [
        await writeInventory(context, inventoryWith(inventory, existing)),
      ],
    };
  }
  if (existing) {
    throw new Error(
      `Creation request ${args.requestId} is ${existing.status}; use a new requestId after operator reconciliation`,
    );
  }

  const pendingAt = new Date().toISOString();
  const pending: InventoryItem = {
    requestId: args.requestId,
    label: args.label,
    tokenType: "web",
    requestFingerprint: args.confirmation,
    status: "pending",
    updatedAt: pendingAt,
  };
  await writeReceipt(context, pending);
  await writeInventory(context, inventoryWith(inventory, pending));

  context.logger.info(
    "Creating one web Canarytoken for request {requestId}",
    { requestId: args.requestId },
  );
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error("Canarytokens request timed out")),
    globals.timeoutSeconds * 1_000,
  );
  const abort = () => controller.abort(context.signal?.reason);
  context.signal?.addEventListener("abort", abort, { once: true });

  let response: Response;
  let body: string;
  try {
    response = await fetcher(globals.apiEndpoint, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        token_type: "web",
        memo: args.label,
        webhook_url: globals.webhookUrl,
      }),
    });
    body = await readBoundedBody(response);
  } catch (error) {
    throw new Error(
      `Canarytokens creation outcome is unknown for request ${args.requestId}; reconcile before retrying (${
        error instanceof Error ? error.name : "network error"
      })`,
    );
  } finally {
    clearTimeout(timeout);
    context.signal?.removeEventListener("abort", abort);
  }

  if (response.status !== 200) {
    if (response.status === 400) {
      const failed: InventoryItem = {
        requestId: args.requestId,
        label: args.label,
        tokenType: "web",
        requestFingerprint: args.confirmation,
        status: "failed",
        updatedAt: new Date().toISOString(),
      };
      await writeReceipt(context, failed);
      await writeInventory(context, inventoryWith(inventory, failed));
    }
    throw new Error(
      `Canarytokens creation failed with HTTP ${response.status}; response details were redacted and the request ${
        response.status === 400 ? "failed" : "remains pending"
      }`,
    );
  }

  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]
    .trim().toLowerCase();
  if (mediaType !== "application/json") {
    throw new Error(
      `Canarytokens returned a non-JSON success response; request ${args.requestId} remains pending for reconciliation`,
    );
  }

  let providerData: z.infer<typeof ProviderResponseSchema>;
  try {
    providerData = ProviderResponseSchema.parse(JSON.parse(body));
  } catch {
    throw new Error(
      `Canarytokens returned an invalid success response; request ${args.requestId} remains pending for reconciliation`,
    );
  }
  const createdAt = new Date().toISOString();
  const secretHandle = await context.writeResource(
    "createdToken",
    `creator-token-${args.requestId}`,
    {
      tokenType: "web",
      token: providerData.token,
      tokenUrl: providerData.token_url,
      authToken: providerData.auth_token,
      hostname: providerData.hostname,
    },
  );
  const completed: InventoryItem = {
    requestId: args.requestId,
    label: args.label,
    tokenType: "web",
    requestFingerprint: args.confirmation,
    status: "created",
    updatedAt: createdAt,
    createdAt,
  };
  const receiptHandle = await writeReceipt(context, completed);
  const inventoryHandle = await writeInventory(
    context,
    inventoryWith(inventory, completed),
  );
  context.logger.info(
    "Created one web Canarytoken for request {requestId}; secret fields were vaulted",
    { requestId: args.requestId },
  );
  return { dataHandles: [secretHandle, receiptHandle, inventoryHandle] };
}

/** Swamp model for previewed, idempotency-guarded web-token creation. */
export const model = {
  type: "@mgreten/canarytokens/creator",
  version: "2026.07.29.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    creatorPreview: {
      description: "Safe preview and confirmation value for one proposed token",
      schema: PreviewSchema,
      lifetime: "1d" as const,
      garbageCollection: 5,
    },
    creatorInventory: {
      description: "Bounded non-secret token-creation receipts",
      schema: InventorySchema,
      lifetime: "infinite" as const,
      garbageCollection: 52,
    },
    creatorReceipt: {
      description:
        "Durable non-secret receipt preserving one request's idempotency decision even after bounded inventory eviction",
      schema: InventoryItemSchema,
      lifetime: "infinite" as const,
      garbageCollection: 1,
    },
    createdToken: {
      description:
        "Generated token material; Swamp stores every field in its configured vault",
      schema: SecretTokenSchema,
      sensitiveOutput: true,
      lifetime: "infinite" as const,
      garbageCollection: 1,
    },
  },
  checks: {
    "secure-api-endpoint": {
      description:
        "Require the pinned creation endpoint and callback to use HTTPS",
      labels: ["policy"],
      appliesTo: ["create"],
      execute: (context: { globalArgs: unknown }) => {
        const result = GlobalArgsSchema.safeParse(context.globalArgs);
        return result.success ? { pass: true } : {
          pass: false,
          errors: result.error.issues.map((issue) => issue.message),
        };
      },
    },
  },
  methods: {
    preview: {
      description:
        "Validate and persist a safe preview. Makes no provider request and returns the confirmation required by create.",
      arguments: RequestSchema,
      execute: async (args: RequestArgs, context: MethodContext) => {
        const globals = GlobalArgsSchema.parse(context.globalArgs);
        context.logger.info(
          "Previewing one web Canarytoken for request {requestId}",
          { requestId: args.requestId },
        );
        const preview = {
          requestId: args.requestId,
          label: args.label,
          tokenType: "web" as const,
          serverOrigin: new URL(globals.apiEndpoint).origin,
          confirmation: await confirmationFor(args, globals),
          warning:
            "Creation calls the configured server once and stores generated values in the Swamp vault. A pending request must be reconciled, not retried.",
        };
        const handle = await context.writeResource(
          "creatorPreview",
          `creator-preview-${args.requestId}`,
          preview,
        );
        context.logger.info(
          "Preview ready for request {requestId}; no provider call made",
          { requestId: args.requestId },
        );
        return { dataHandles: [handle] };
      },
    },
    create: {
      description:
        "Create exactly one web Canarytoken after exact preview confirmation. Redirects are refused and ambiguous retries are blocked.",
      arguments: RequestSchema.extend({ confirmation: ConfirmationSchema }),
      execute: async (
        args: RequestArgs & { confirmation: string },
        context: MethodContext,
      ) => await createWebToken(args, context),
    },
    inventory: {
      description: "Return bounded, non-secret creation receipts",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: MethodContext) => {
        context.logger.info("Reading Canarytoken creator inventory");
        const inventory = await readInventory(context);
        const handle = await writeInventory(context, inventory);
        context.logger.info("Returned {count} creator inventory item(s)", {
          count: inventory.items.length,
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
