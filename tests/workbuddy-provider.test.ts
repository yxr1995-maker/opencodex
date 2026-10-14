import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildOpenAIChatPassthroughRequest } from "../src/adapters/openai-chat";
import { OAUTH_PROVIDERS } from "../src/oauth";
import {
  WORKBUDDY_AI_BASE_URL,
  WORKBUDDY_AI_MODEL_IDS,
  WORKBUDDY_BASE_URL,
  WORKBUDDY_MODEL_IDS,
  WORKBUDDY_NOT_LOGGED_IN_ERROR,
  WORKBUDDY_UA_VERSION,
  buildWorkBuddyHeaders,
  loginWorkBuddy,
  readWorkBuddyDesktopAuth,
  refreshWorkBuddyToken,
  resetWorkBuddyMemoryForTests,
  workBuddyAuthPath,
  type WorkBuddyCreds,
  type WorkBuddySiteId,
} from "../src/oauth/workbuddy";
import { PROVIDER_REGISTRY } from "../src/providers/registry";

const AUTH_DIR = join(import.meta.dir, ".tmp-workbuddy-provider");
const originalFetch = globalThis.fetch;
let previousAuthDir: string | undefined;

function session(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    account: { uid: "uid-1", nickname: "desk" },
    auth: {
      accessToken: "fake-access-token",
      refreshToken: "fake-refresh-token",
      expiresAt: 1_893_456_000_000,
      domain: "copilot.tencent.com",
      ...overrides,
    },
  });
}

function writeSession(site: WorkBuddySiteId, body: string): string {
  const path = workBuddyAuthPath(site);
  writeFileSync(path, body);
  return path;
}

describe("WorkBuddy providers", () => {
  beforeEach(() => {
    previousAuthDir = process.env.OCX_WORKBUDDY_AUTH_DIR;
    rmSync(AUTH_DIR, { recursive: true, force: true });
    mkdirSync(AUTH_DIR, { recursive: true });
    process.env.OCX_WORKBUDDY_AUTH_DIR = AUTH_DIR;
    resetWorkBuddyMemoryForTests();
    globalThis.fetch = originalFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    resetWorkBuddyMemoryForTests();
    if (previousAuthDir === undefined) delete process.env.OCX_WORKBUDDY_AUTH_DIR;
    else process.env.OCX_WORKBUDDY_AUTH_DIR = previousAuthDir;
    rmSync(AUTH_DIR, { recursive: true, force: true });
  });

  test("reads a desktop auth file and does not call the network", async () => {
    const path = writeSession("workbuddy", session());
    const before = readFileSync(path, "utf8");
    const beforeStat = statSync(path);
    let fetched = false;
    globalThis.fetch = (() => {
      fetched = true;
      throw new Error("login must not call the network");
    }) as typeof fetch;

    const creds = readWorkBuddyDesktopAuth("workbuddy");
    expect(creds).toMatchObject({
      uid: "uid-1",
      accessToken: "fake-access-token",
      refreshToken: "fake-refresh-token",
      expiresAt: 1_893_456_000_000,
      domain: "copilot.tencent.com",
    });
    const imported = await loginWorkBuddy({}, "workbuddy");
    expect(imported).toMatchObject({
      access: "fake-access-token",
      refresh: "fake-refresh-token",
      accountId: "uid-1",
      expires: 1_893_456_000_000,
      source: "credential-file",
    });
    expect(fetched).toBe(false);
    expect(readFileSync(path, "utf8")).toBe(before);
    expect(statSync(path).mtimeMs).toBe(beforeStat.mtimeMs);
    expect(workBuddyAuthPath("workbuddy")).toBe(join(AUTH_DIR, "workbuddy-desktop.info"));
    expect(workBuddyAuthPath("workbuddy-ai")).toBe(join(AUTH_DIR, "workbuddy-desktop-ai.info"));
  });

  test("encrypted token fields and a missing file are not-logged-in", async () => {
    writeSession("workbuddy", session({ accessToken: { cipher: "sealed" } }));
    expect(() => readWorkBuddyDesktopAuth("workbuddy")).toThrow(WORKBUDDY_NOT_LOGGED_IN_ERROR);

    writeSession("workbuddy", session({ refreshToken: { encrypted: true } }));
    await expect(loginWorkBuddy({}, "workbuddy")).rejects.toThrow(WORKBUDDY_NOT_LOGGED_IN_ERROR);

    rmSync(workBuddyAuthPath("workbuddy-ai"), { force: true });
    expect(() => readWorkBuddyDesktopAuth("workbuddy-ai")).toThrow(WORKBUDDY_NOT_LOGGED_IN_ERROR);
  });

  test("request headers match the WorkBuddy desktop client", () => {
    const creds: WorkBuddyCreds = {
      uid: "uid-1",
      accessToken: "fake-access-token",
      refreshToken: "fake-refresh-token",
      expiresAt: 1_893_456_000_000,
      domain: "copilot.tencent.com",
    };
    const first = buildWorkBuddyHeaders(creds, "workbuddy");
    const second = buildWorkBuddyHeaders({ ...creds, domain: "" }, "workbuddy-ai");
    expect(first).toMatchObject({
      Authorization: "Bearer fake-access-token",
      "X-User-Id": "uid-1",
      "X-Domain": "copilot.tencent.com",
      "X-Product": "SaaS",
      "X-IDE-Type": "WorkBuddy",
      "X-IDE-Name": "WorkBuddy",
      "X-IDE-Version": WORKBUDDY_UA_VERSION,
      "User-Agent": `WorkBuddy/${WORKBUDDY_UA_VERSION}`,
      "X-Requested-With": "XMLHttpRequest",
      "X-Agent-Intent": "craft",
      "X-Agent-Type": "main",
    });
    expect(first["X-Request-ID"]).toMatch(/^[0-9a-f]{32}$/);
    expect(second["X-Request-ID"]).toMatch(/^[0-9a-f]{32}$/);
    expect(second["X-Request-ID"]).not.toBe(first["X-Request-ID"]);
    expect(second["X-Domain"]).toBe("www.workbuddy.ai");

    writeSession("workbuddy", session());
    const request = buildOpenAIChatPassthroughRequest(
      {
        adapter: "openai-chat",
        baseUrl: WORKBUDDY_BASE_URL,
        authMode: "oauth",
        apiKey: "live-access-token",
      },
      { messages: [{ role: "user", content: "hi" }] },
      "auto",
      false,
    );
    expect(request.headers.Authorization).toBe("Bearer live-access-token");
    expect(request.headers["X-User-Id"]).toBe("uid-1");
    expect(request.headers["X-Domain"]).toBe("copilot.tencent.com");
    expect(request.headers["User-Agent"]).toBe(`WorkBuddy/${WORKBUDDY_UA_VERSION}`);
    expect(request.headers["X-Product"]).toBe("SaaS");
    expect(request.headers["X-Agent-Intent"]).toBe("craft");
    expect(request.url).toBe(`${WORKBUDDY_BASE_URL}/chat/completions`);
  });

  test("refresh posts to the plan token URL and does not write the auth file", async () => {
    for (const site of ["workbuddy", "workbuddy-ai"] as const) {
      resetWorkBuddyMemoryForTests();
      const path = writeSession(site, session({ domain: site === "workbuddy" ? "copilot.tencent.com" : "www.workbuddy.ai" }));
      const before = readFileSync(path, "utf8");
      const beforeMtime = statSync(path).mtimeMs;
      const calls: Array<{ url: string; init?: RequestInit }> = [];
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({ url: String(input), init });
        return Response.json({
          code: 0,
          data: {
            accessToken: "refreshed-access",
            refreshToken: "refreshed-refresh",
            expiresAt: 1_900_000_000_000,
            domain: site === "workbuddy" ? "copilot.tencent.com" : "www.workbuddy.ai",
          },
        });
      }) as typeof fetch;

      const refreshed = await refreshWorkBuddyToken("fake-refresh-token", undefined, { access: "fake-access-token", refresh: "fake-refresh-token", expires: 1, accountId: "uid-1" }, site);
      expect(calls).toHaveLength(1);
      expect(calls[0]!.url).toBe(`${site === "workbuddy" ? "https://copilot.tencent.com" : "https://www.workbuddy.ai"}/v2/plugin/auth/token/refresh`);
      expect(calls[0]!.init?.method).toBe("POST");
      expect(calls[0]!.init?.body).toBe("{}");
      const headers = calls[0]!.init?.headers as Record<string, string>;
      expect(headers["X-Refresh-Token"]).toBe("fake-refresh-token");
      expect(headers["X-Auth-Refresh-Source"]).toBe("plugin");
      expect(headers["User-Agent"]).toBe(`WorkBuddy/${WORKBUDDY_UA_VERSION}`);
      expect(headers["X-Domain"]).toBe(site === "workbuddy" ? "copilot.tencent.com" : "www.workbuddy.ai");
      expect(refreshed.access).toBe("refreshed-access");
      expect(refreshed.refresh).toBe("refreshed-refresh");
      expect(readFileSync(path, "utf8")).toBe(before);
      expect(statSync(path).mtimeMs).toBe(beforeMtime);
      expect(readWorkBuddyDesktopAuth(site).accessToken).toBe("fake-access-token");
    }
  });

  test("registry entries use the magpie model seeds and /v2 base URLs", () => {
    const cn = PROVIDER_REGISTRY.find(entry => entry.id === "workbuddy");
    const ai = PROVIDER_REGISTRY.find(entry => entry.id === "workbuddy-ai");
    expect(cn).toMatchObject({
      adapter: "openai-chat",
      baseUrl: WORKBUDDY_BASE_URL,
      authKind: "oauth",
      defaultModel: "auto",
      models: WORKBUDDY_MODEL_IDS,
    });
    expect(ai).toMatchObject({
      adapter: "openai-chat",
      baseUrl: WORKBUDDY_AI_BASE_URL,
      authKind: "oauth",
      defaultModel: "default-model",
      models: WORKBUDDY_AI_MODEL_IDS,
    });
    expect(cn?.baseUrl).toBe("https://copilot.tencent.com/v2");
    expect(ai?.baseUrl).toBe("https://www.workbuddy.ai/v2");
    expect(cn?.note).toContain("腾讯风控");
    expect(ai?.note).toContain("腾讯风控");
    expect(cn?.models).toContain("hy4-preview-f");
    expect(cn?.models).toContain("deepseek-v4-pro");
    expect(ai?.models).toContain("default-model");
    expect(ai?.models).toContain("gpt-5.5");
    expect(ai?.models).not.toContain("auto");
    expect(OAUTH_PROVIDERS.workbuddy?.defaultRefreshPolicy).toBe("lazy-only");
    expect(OAUTH_PROVIDERS["workbuddy-ai"]?.defaultRefreshPolicy).toBe("lazy-only");
    expect(OAUTH_PROVIDERS.workbuddy?.providerConfig.baseUrl).toBe(WORKBUDDY_BASE_URL);
    expect(OAUTH_PROVIDERS.workbuddy?.providerConfig.models).toEqual(WORKBUDDY_MODEL_IDS);
    expect(OAUTH_PROVIDERS["workbuddy-ai"]?.providerConfig.baseUrl).toBe(WORKBUDDY_AI_BASE_URL);
    expect(OAUTH_PROVIDERS["workbuddy-ai"]?.providerConfig.models).toEqual(WORKBUDDY_AI_MODEL_IDS);
    expect(OAUTH_PROVIDERS.workbuddy?.providerConfig.adapter).toBe("openai-chat");
  });
});
