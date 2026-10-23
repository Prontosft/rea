import { describe, expect, it, onTestFinished } from "vitest";
import { CdpWebRuntimeProvider } from "../../../src/browser/execution/CdpWebRuntimeProvider.js";
import { observeWebExecutionInputSchema } from "../../../src/domain/webExecution.js";
import { WEB_RUNTIME_LIMITS } from "../../../src/domain/webRuntime.js";
import { startRuntimeBrowser } from "../../fixtures/webRuntime.js";

describe("runtime initiator URL representation", () => {
  it.each(["before", "after"])(
    "omits proven transport userinfo and preserves declared names with metadata %s the request",
    async (ordering) => {
      const browser = await startRuntimeBrowser();
      onTestFinished(() => browser.close());
      const resourceUrl =
        browser.endpoint.replace("http://", "http://transport:credential@") +
        "/resource.js?caller=value#fragment";
      const declaredUrl =
        browser.endpoint.replace("http://", "http://declared:label@") +
        "/declaration.js?caller=value#fragment";
      const metadata = (
        scriptId: string,
        url: string,
        hasSourceURL: boolean,
      ) => ({
        scriptId,
        url,
        hasSourceURL,
        executionContextId: 999,
        startLine: 0,
        startColumn: 0,
        endLine: 1,
        endColumn: 0,
      });
      const frames = [
        {
          scriptId: "resource-script",
          url: resourceUrl,
          functionName: "resource",
          lineNumber: 0,
          columnNumber: 0,
        },
        {
          scriptId: "declared-script",
          url: declaredUrl,
          functionName: "declared",
          lineNumber: 0,
          columnNumber: 0,
        },
      ];
      const initiator = {
        type: "script",
        url: resourceUrl,
        lineNumber: 0,
        producerExtension: { url: declaredUrl, opaque: "keep caller data" },
        stack: {
          description: "producer sync",
          callFrames: [frames[0]],
          parent: {
            description: "producer async",
            callFrames: [frames[1]],
            parentId: { id: "retained-parent" },
          },
        },
      };
      const result = await new CdpWebRuntimeProvider().observeExecution(
        observeWebExecutionInputSchema.parse({
          cdp_endpoint: browser.endpoint,
          target_id: "allowed-page",
          observation_ms: 30,
        }),
        {
          progress: {
            report: async (update) => {
              if (update.completed !== 1) return;
              const scripts = () => {
                for (const params of [
                  metadata("resource-script", resourceUrl, false),
                  metadata("declared-script", declaredUrl, true),
                ])
                  browser.emitEvent({
                    method: "Debugger.scriptParsed",
                    params,
                    sessionId: "session-1",
                  });
              };
              if (ordering === "before") scripts();
              browser.emitEvent({
                method: "Network.requestWillBeSent",
                sessionId: "session-1",
                params: {
                  requestId: "request",
                  frameId: "runtime-main",
                  timestamp: 12,
                  request: {
                    url: `${browser.endpoint}/selected`,
                    method: "GET",
                  },
                  initiator,
                },
              });
              if (ordering === "after") scripts();
            },
          },
        },
      );
      if (!result.ok) throw result.error;
      const sanitized = `${browser.endpoint}/resource.js?caller=value#fragment`;
      expect(result.value.requests[0]?.reported_initiator).toEqual({
        ...initiator,
        url: sanitized,
        stack: {
          ...initiator.stack,
          callFrames: [{ ...frames[0], url: sanitized }],
        },
      });
      expect(result.value.requests[0]?.callsites.map(({ url }) => url)).toEqual(
        [sanitized, declaredUrl, sanitized],
      );
      expect(
        result.value.sources.find(
          ({ script_id }) => script_id === "resource-script",
        )?.url,
      ).toBe(sanitized);
      expect(
        result.value.sources.find(
          ({ script_id }) => script_id === "declared-script",
        )?.url,
      ).toBe(declaredUrl);
      expect(JSON.stringify(result.value)).not.toContain(
        "transport:credential@",
      );
      expect(JSON.stringify(result.value)).toContain("declared:label@");
    },
  );
});

describe("discarded POST body accounting", () => {
  it("admits a POST whose discarded body exceeds the retained metadata budget", async () => {
    const browser = await startRuntimeBrowser();
    onTestFinished(() => browser.close());
    const body = `POSTBODY${"b".repeat(WEB_RUNTIME_LIMITS.retainedEventBytes)}`;
    const params = {
      requestId: "large-post",
      frameId: "runtime-main",
      timestamp: 12,
      request: {
        url: `${browser.endpoint}/selected`,
        method: "POST",
        postData: body,
      },
      initiator: { type: "script" },
    };
    expect(Buffer.byteLength(JSON.stringify(params))).toBeGreaterThan(
      WEB_RUNTIME_LIMITS.retainedEventBytes,
    );
    const result = await new CdpWebRuntimeProvider().observeExecution(
      observeWebExecutionInputSchema.parse({
        cdp_endpoint: browser.endpoint,
        target_id: "allowed-page",
        observation_ms: 2_000,
      }),
      {
        progress: {
          report: async (update) => {
            if (update.completed !== 1) return;
            browser.emitEvent({
              method: "Network.requestWillBeSent",
              sessionId: "session-1",
              params,
            });
          },
        },
      },
    );
    if (!result.ok) throw result.error;
    expect(result.value.requests).toMatchObject([
      {
        request_id: "large-post",
        method: "POST",
        url: `${browser.endpoint}/selected`,
      },
    ]);
    expect(JSON.stringify(result.value)).not.toContain("POSTBODY");
  });
});

describe("retained request metadata accounting", () => {
  const observeRequests = async (
    paddings: readonly number[],
  ): Promise<
    Awaited<ReturnType<CdpWebRuntimeProvider["observeExecution"]>>
  > => {
    const browser = await startRuntimeBrowser();
    onTestFinished(() => browser.close());
    return new CdpWebRuntimeProvider().observeExecution(
      observeWebExecutionInputSchema.parse({
        cdp_endpoint: browser.endpoint,
        target_id: "allowed-page",
        observation_ms: 2_000,
      }),
      {
        progress: {
          report: async (update) => {
            if (update.completed !== 1) return;
            paddings.forEach((padding, index) =>
              browser.emitEvent({
                method: "Network.requestWillBeSent",
                sessionId: "session-1",
                params: {
                  requestId: `retained-${String(index)}`,
                  frameId: "runtime-main",
                  timestamp: 12,
                  request: {
                    url: `${browser.endpoint}/selected`,
                    method: "GET",
                  },
                  initiator: { type: "script", padding: "i".repeat(padding) },
                },
              }),
            );
          },
        },
      },
    );
  };
  const budgetError = expect.objectContaining({
    message: expect.stringContaining(
      "Request initiator evidence exceeds its complete 8 MiB event budget.",
    ),
  });

  it("rejects one request whose retained initiator exceeds the budget", async () => {
    const result = await observeRequests([
      WEB_RUNTIME_LIMITS.retainedEventBytes,
    ]);
    expect(result).toMatchObject({ ok: false, error: budgetError });
  });

  it("rejects requests whose retained initiators together exceed the budget", async () => {
    const padding = Math.floor(WEB_RUNTIME_LIMITS.retainedEventBytes / 3);
    const result = await observeRequests([padding, padding, padding, padding]);
    expect(result).toMatchObject({ ok: false, error: budgetError });
  });
});
