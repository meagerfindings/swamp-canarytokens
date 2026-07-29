import { createWebToken, model } from "./creator.ts";

const assert = (condition: unknown, message: string) => {
  if (!condition) throw new Error(message);
};

const globals = {
  apiEndpoint: "https://canary.example.test/private-api/generate",
  webhookUrl: "https://ingest.example.test/hooks/secret-value",
  timeoutSeconds: 10,
};

type Write = { spec: string; instance: string; data: unknown };

function harness(seed?: unknown) {
  let inventory = seed;
  const receipts = new Map<string, unknown>();
  const previews = new Map<string, unknown>();
  const writes: Write[] = [];
  const logs: Array<{ message: string; properties?: Record<string, unknown> }> =
    [];
  const context = {
    globalArgs: globals,
    signal: undefined as AbortSignal | undefined,
    logger: {
      info: (message: string, properties?: Record<string, unknown>) =>
        logs.push({ message, properties }),
      warning: (message: string, properties?: Record<string, unknown>) =>
        logs.push({ message, properties }),
    },
    readResource: (instance: string) =>
      Promise.resolve(
        instance === "creator-inventory"
          ? inventory
          : receipts.get(instance) ?? previews.get(instance),
      ),
    writeResource: (spec: string, instance: string, data: unknown) => {
      writes.push({ spec, instance, data });
      if (spec === "creatorInventory") inventory = data;
      if (spec === "creatorReceipt") receipts.set(instance, data);
      if (spec === "creatorPreview") previews.set(instance, data);
      return Promise.resolve({ specName: spec, name: instance });
    },
  };
  return {
    context,
    writes,
    logs,
    get inventory() {
      return inventory as {
        items: Array<{ requestId: string; status: string }>;
      };
    },
  };
}

async function previewConfirmation(
  h: ReturnType<typeof harness>,
  requestId = "operator-request-001",
  label = "decoy-admin-document",
): Promise<string> {
  await model.methods.preview.execute({ requestId, label }, h.context);
  const preview = h.writes.find((write) => write.spec === "creatorPreview")
    ?.data as { confirmation?: string } | undefined;
  assert(preview?.confirmation, "preview must return a confirmation");
  return preview!.confirmation!;
}

function successResponse() {
  return new Response(
    JSON.stringify({
      token_type: "web",
      token: "provider-token-secret",
      token_url: "https://trigger.example.test/provider-token-secret",
      auth_token: "management-secret",
      hostname: "provider-token-secret.trigger.example.test",
      email: "",
      webhook_url: globals.webhookUrl,
      error: null,
      error_message: null,
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    },
  );
}

Deno.test("creator schemas pin HTTPS destinations and reject unknown input", () => {
  assert(
    model.globalArguments.safeParse(globals).success,
    "valid pinned configuration must parse",
  );
  for (
    const apiEndpoint of [
      "http://canary.example.test/private-api/generate",
      "https://canary.example.test/private-api/generate?next=elsewhere",
      "https://canary.example.test/private-api/not-generate",
    ]
  ) {
    assert(
      !model.globalArguments.safeParse({ ...globals, apiEndpoint }).success,
      `unsafe endpoint must fail: ${apiEndpoint}`,
    );
  }
  assert(
    !("endpoint" in model.methods.preview.arguments.parse({
      requestId: "operator-request-001",
      label: "safe",
      endpoint: "https://attacker.example/generate",
    })),
    "method schema must strip a destination override before execution",
  );
  assert(
    model.resources.createdToken.sensitiveOutput === true,
    "generated token resource must be wholly sensitive",
  );
});

Deno.test("preview performs no provider call and binds all creation inputs", async () => {
  const h = harness();
  const confirmation = await previewConfirmation(h);
  assert(
    /^create-web:[0-9a-f]{64}$/.test(confirmation),
    "confirmation must be a deterministic digest",
  );
  assert(h.writes.length === 1, "preview should write only its safe artifact");
  const other = harness();
  const changed = await previewConfirmation(
    other,
    "operator-request-001",
    "different-label",
  );
  assert(changed !== confirmation, "confirmation must bind the label");
  assert(
    !JSON.stringify(h.writes).includes(globals.webhookUrl),
    "preview must not persist the sensitive webhook",
  );
});

Deno.test("create refuses mismatched confirmation before state or network", async () => {
  const h = harness();
  let calls = 0;
  let error = "";
  try {
    await createWebToken(
      {
        requestId: "operator-request-001",
        label: "decoy-admin-document",
        confirmation: `create-web:${"0".repeat(64)}`,
      },
      h.context,
      () => {
        calls++;
        return Promise.resolve(successResponse());
      },
    );
  } catch (cause) {
    error = String(cause);
  }
  assert(error.includes("Confirmation does not match"), "must reject mismatch");
  assert(calls === 0, "mismatch must not call provider");
  assert(h.writes.length === 0, "mismatch must not write state");
});

Deno.test("create requires the matching persisted preview", async () => {
  const previewHarness = harness();
  const confirmation = await previewConfirmation(previewHarness);
  const createHarness = harness();
  let calls = 0;
  let error = "";
  try {
    await createWebToken(
      {
        requestId: "operator-request-001",
        label: "decoy-admin-document",
        confirmation,
      },
      createHarness.context,
      () => {
        calls++;
        return Promise.resolve(successResponse());
      },
    );
  } catch (cause) {
    error = String(cause);
  }
  assert(error.includes("No persisted preview"), "missing preview must fail");
  assert(calls === 0, "missing preview must not reach provider");
  assert(
    createHarness.writes.length === 0,
    "missing preview must not write state",
  );
});

Deno.test("create stores secrets separately and only safe receipt metadata", async () => {
  const h = harness();
  const confirmation = await previewConfirmation(h);
  let requestUrl = "";
  let requestInit: RequestInit | undefined;
  await createWebToken(
    {
      requestId: "operator-request-001",
      label: "decoy-admin-document",
      confirmation,
    },
    h.context,
    (url, init) => {
      requestUrl = url;
      requestInit = init;
      return Promise.resolve(successResponse());
    },
  );

  assert(requestUrl === globals.apiEndpoint, "must call only pinned endpoint");
  assert(requestInit?.redirect === "manual", "redirects must be disabled");
  assert(
    requestInit?.headers &&
      (requestInit.headers as Record<string, string>)["Content-Type"] ===
        "application/json",
    "must use Thinkst's exact JSON content type",
  );
  const secret = h.writes.find((write) => write.spec === "createdToken");
  assert(secret, "must write generated fields to sensitive resource");
  const serializedInventory = JSON.stringify(h.inventory);
  for (
    const value of [
      "provider-token-secret",
      "management-secret",
      globals.webhookUrl,
    ]
  ) {
    assert(
      !serializedInventory.includes(value),
      "safe inventory must contain no token or webhook values",
    );
    assert(
      !JSON.stringify(h.logs).includes(value),
      "logs must contain no token or webhook values",
    );
  }
  assert(
    h.inventory.items[0].status === "created",
    "receipt must become created",
  );
});

Deno.test("completed request is idempotent and never calls provider twice", async () => {
  const h = harness();
  const confirmation = await previewConfirmation(h);
  const args = {
    requestId: "operator-request-001",
    label: "decoy-admin-document",
    confirmation,
  };
  let calls = 0;
  const fetcher = () => {
    calls++;
    return Promise.resolve(successResponse());
  };
  await createWebToken(args, h.context, fetcher);
  await createWebToken(args, h.context, fetcher);
  assert(calls === 1, "completed request must not be recreated");
});

Deno.test("request id cannot be rebound after creation", async () => {
  const h = harness();
  const confirmation = await previewConfirmation(h);
  await createWebToken(
    {
      requestId: "operator-request-001",
      label: "decoy-admin-document",
      confirmation,
    },
    h.context,
    () => Promise.resolve(successResponse()),
  );

  const changedConfirmation = await previewConfirmation(
    h,
    "operator-request-001",
    "different-label",
  );
  let calls = 0;
  try {
    await createWebToken(
      {
        requestId: "operator-request-001",
        label: "different-label",
        confirmation: changedConfirmation,
      },
      h.context,
      () => {
        calls++;
        return Promise.resolve(successResponse());
      },
    );
  } catch {
    // Expected: a request ID permanently binds its original request.
  }
  assert(calls === 0, "rebound request must not reach provider");
});

Deno.test("request id cannot be rebound after destination configuration changes", async () => {
  const h = harness();
  const confirmation = await previewConfirmation(h);
  await createWebToken(
    {
      requestId: "operator-request-001",
      label: "decoy-admin-document",
      confirmation,
    },
    h.context,
    () => Promise.resolve(successResponse()),
  );

  h.context.globalArgs.webhookUrl =
    "https://ingest.example.test/hooks/rotated-secret";
  const changedConfirmation = await previewConfirmation(h);
  let calls = 0;
  let rejected = false;
  try {
    await createWebToken(
      {
        requestId: "operator-request-001",
        label: "decoy-admin-document",
        confirmation: changedConfirmation,
      },
      h.context,
      () => {
        calls++;
        return Promise.resolve(successResponse());
      },
    );
  } catch {
    rejected = true;
  }
  assert(rejected, "destination rebind must be rejected");
  assert(calls === 0, "destination rebind must not reach provider");
});

Deno.test("network ambiguity and redirects stay pending and cannot retry", async () => {
  for (
    const fetcher of [
      () => Promise.reject(new TypeError("private network detail")),
      () =>
        Promise.resolve(
          new Response("", {
            status: 302,
            headers: { Location: "https://attacker.example/generate" },
          }),
        ),
    ]
  ) {
    const h = harness();
    const confirmation = await previewConfirmation(h);
    const args = {
      requestId: "operator-request-001",
      label: "decoy-admin-document",
      confirmation,
    };
    try {
      await createWebToken(args, h.context, fetcher);
    } catch {
      // Expected: provider outcome is deliberately not guessed.
    }
    assert(h.inventory.items[0].status === "pending", "must remain pending");
    let retryCalls = 0;
    try {
      await createWebToken(args, h.context, () => {
        retryCalls++;
        return Promise.resolve(successResponse());
      });
    } catch {
      // Expected: operator reconciliation is required.
    }
    assert(retryCalls === 0, "ambiguous request must not call provider again");
  }
});

Deno.test("definite 4xx is safely redacted and recorded failed", async () => {
  const h = harness();
  const confirmation = await previewConfirmation(h);
  let error = "";
  try {
    await createWebToken(
      {
        requestId: "operator-request-001",
        label: "decoy-admin-document",
        confirmation,
      },
      h.context,
      () =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              error_message: `provider echoed ${globals.webhookUrl}`,
            }),
            { status: 400 },
          ),
        ),
    );
  } catch (cause) {
    error = String(cause);
  }
  assert(error.includes("HTTP 400"), "must report safe status");
  assert(!error.includes(globals.webhookUrl), "must redact provider body");
  assert(
    h.inventory.items[0].status === "failed",
    "must record definite failure",
  );
});

Deno.test("unexpected success contract remains pending", async () => {
  const responses = [
    new Response(JSON.stringify({}), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    }),
    new Response(JSON.stringify({}), {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    }),
    new Response(
      JSON.stringify({
        token_type: "web",
        token: "provider-token-secret",
        token_url: "https://trigger.example.test/provider-token-secret",
        hostname: "provider-token-secret.trigger.example.test",
        error: null,
        error_message: null,
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    ),
  ];
  for (const response of responses) {
    const h = harness();
    const confirmation = await previewConfirmation(h);
    try {
      await createWebToken(
        {
          requestId: "operator-request-001",
          label: "decoy-admin-document",
          confirmation,
        },
        h.context,
        () => Promise.resolve(response),
      );
    } catch {
      // Expected.
    }
    assert(h.inventory.items[0].status === "pending", "must remain pending");
    assert(
      !h.writes.some((write) => write.spec === "createdToken"),
      "invalid provider contract must not persist generated material",
    );
  }
});

Deno.test("parent abort interrupts response body consumption", async () => {
  const h = harness();
  const confirmation = await previewConfirmation(h);
  const parent = new AbortController();
  h.context.signal = parent.signal;
  const abortTimer = setTimeout(() => parent.abort(), 5);
  let error = "";
  try {
    await createWebToken(
      {
        requestId: "operator-request-001",
        label: "decoy-admin-document",
        confirmation,
      },
      h.context,
      (_url, init) => {
        const signal = init.signal!;
        return Promise.resolve(
          new Response(
            new ReadableStream({
              start(controller) {
                signal.addEventListener(
                  "abort",
                  () =>
                    controller.error(new DOMException("aborted", "AbortError")),
                );
                controller.enqueue(new TextEncoder().encode("{"));
              },
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" },
            },
          ),
        );
      },
    );
  } catch (cause) {
    error = String(cause);
  } finally {
    clearTimeout(abortTimer);
    parent.abort();
  }
  assert(error.includes("outcome is unknown"), "abort must fail safely");
  assert(h.inventory.items[0].status === "pending", "abort must stay pending");
});

Deno.test("oversized and malformed success bodies remain pending", async () => {
  for (
    const response of [
      new Response("x".repeat(64 * 1024 + 1), { status: 200 }),
      new Response("not-json", { status: 200 }),
    ]
  ) {
    const h = harness();
    const confirmation = await previewConfirmation(h);
    try {
      await createWebToken(
        {
          requestId: "operator-request-001",
          label: "decoy-admin-document",
          confirmation,
        },
        h.context,
        () => Promise.resolve(response),
      );
    } catch {
      // Expected.
    }
    assert(
      h.inventory.items[0].status === "pending",
      "untrusted success response must not complete receipt",
    );
    assert(
      !h.writes.some((write) => write.spec === "createdToken"),
      "untrusted response must not persist token material",
    );
  }
});
