/**
 * WorkBuddy desktop subscription credentials (read-only).
 *
 * Ported from yetone/magpie internal/provider/workbuddy.go
 * (https://github.com/yetone/magpie).
 * Copyright (c) 2026 yetone
 * SPDX-License-Identifier: MIT
 *
 * The desktop auth file is only ever read. Refreshed tokens stay in memory
 * and in opencodex's own credential store — this module never writes
 * workbuddy-desktop.info or workbuddy-desktop-ai.info.
 */
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import type { OAuthController, OAuthCredentials } from "./types";

export const WORKBUDDY_UA_VERSION = "5.5.6";
export const WORKBUDDY_NOT_LOGGED_IN_ERROR = "WorkBuddy 未登录或凭证已加密";

/** Chinese CodeBuddy plan (copilot.tencent.com). */
export const WORKBUDDY_CN_API = "https://copilot.tencent.com";
/** International WorkBuddy AI plan (www.workbuddy.ai). */
export const WORKBUDDY_AI_API = "https://www.workbuddy.ai";
export const WORKBUDDY_BASE_URL = `${WORKBUDDY_CN_API}/v2`;
export const WORKBUDDY_AI_BASE_URL = `${WORKBUDDY_AI_API}/v2`;

/**
 * Unofficial desktop-shaped client. Tencent's gateway checks the User-Agent
 * (code 10085) and has restricted accounts for unusual activity.
 */
export const WORKBUDDY_RISK_NOTE =
  "腾讯风控风险：模仿 WorkBuddy 桌面端（User-Agent 与 IDE 请求头）调用订阅接口，可能被限流、限制或封号。Tencent risk control may throttle or ban this unofficial client. Use one local account at low frequency and stop on error 10085.";

export type WorkBuddySiteId = "workbuddy" | "workbuddy-ai";

export interface WorkBuddyCreds {
  uid: string;
  accessToken: string;
  refreshToken: string;
  /** Unix milliseconds, or 0 when the desktop file did not say. */
  expiresAt: number;
  domain: string;
  refreshExpiresAt?: number;
}

interface ModelSeed {
  id: string;
  context: number;
  efforts?: readonly string[];
}

/** magpie wbModels — static seed until a live /v3/config read exists. */
const WORKBUDDY_SEEDS: readonly ModelSeed[] = [
  { id: "auto", context: 168_000 },
  { id: "hy4-preview-f", context: 1_000_000, efforts: ["high"] },
  { id: "hy3", context: 192_000, efforts: ["low", "high"] },
  { id: "hy3-x", context: 192_000, efforts: ["low", "high"] },
  { id: "deepseek-v4.1-flash", context: 1_000_000 },
  { id: "glm-5.3", context: 1_000_000, efforts: ["low", "high", "max"] },
  { id: "glm-5.3-flash", context: 1_000_000, efforts: ["low", "high", "max"] },
  { id: "glm-5.2", context: 1_000_000, efforts: ["high", "xhigh"] },
  { id: "glm-5.1", context: 200_000 },
  { id: "glm-5v-turbo", context: 200_000 },
  { id: "minimax-m3", context: 512_000 },
  { id: "kimi-k3-1", context: 1_000_000, efforts: ["low", "high", "xhigh"] },
  { id: "kimi-k2.7", context: 256_000 },
  { id: "kimi-k2.6", context: 256_000 },
  { id: "deepseek-v4-pro", context: 1_000_000, efforts: ["none", "high", "xhigh"] },
];

/** magpie wbAIModels. */
const WORKBUDDY_AI_SEEDS: readonly ModelSeed[] = [
  { id: "default-model", context: 176_000 },
  { id: "fast-model", context: 200_000 },
  { id: "balanced-model", context: 256_000 },
  { id: "primary-model", context: 272_000 },
  { id: "deep-model", context: 176_000 },
  { id: "gpt-5.5", context: 1_000_000 },
  { id: "gpt-5.4", context: 272_000 },
  { id: "gpt-5.3-codex", context: 272_000 },
  { id: "gemini-3.1-pro", context: 400_000 },
  { id: "gemini-3.5-flash", context: 1_000_000 },
  { id: "glm-5.3", context: 1_000_000, efforts: ["low", "high", "max"] },
  { id: "glm-5.2", context: 1_000_000, efforts: ["high", "xhigh"] },
  { id: "hy3", context: 192_000, efforts: ["low", "high"] },
  { id: "kimi-k3", context: 1_000_000 },
  { id: "kimi-k2.6", context: 256_000 },
  { id: "minimax-m3", context: 512_000 },
];

function modelIds(seeds: readonly ModelSeed[]): string[] {
  return seeds.map(row => row.id);
}

function contextWindows(seeds: readonly ModelSeed[]): Record<string, number> {
  return Object.fromEntries(seeds.map(row => [row.id, row.context]));
}

function reasoningEfforts(seeds: readonly ModelSeed[]): Record<string, string[]> {
  return Object.fromEntries(
    seeds.filter(row => row.efforts && row.efforts.length > 0).map(row => [row.id, [...row.efforts!]]),
  );
}

export const WORKBUDDY_MODEL_IDS = modelIds(WORKBUDDY_SEEDS);
export const WORKBUDDY_AI_MODEL_IDS = modelIds(WORKBUDDY_AI_SEEDS);
export const WORKBUDDY_MODEL_CONTEXT_WINDOWS = contextWindows(WORKBUDDY_SEEDS);
export const WORKBUDDY_AI_MODEL_CONTEXT_WINDOWS = contextWindows(WORKBUDDY_AI_SEEDS);
export const WORKBUDDY_MODEL_REASONING_EFFORTS = reasoningEfforts(WORKBUDDY_SEEDS);
export const WORKBUDDY_AI_MODEL_REASONING_EFFORTS = reasoningEfforts(WORKBUDDY_AI_SEEDS);

const SITE_API: Record<WorkBuddySiteId, string> = {
  workbuddy: WORKBUDDY_CN_API,
  "workbuddy-ai": WORKBUDDY_AI_API,
};

const AUTH_FILE: Record<WorkBuddySiteId, string> = {
  workbuddy: "workbuddy-desktop.info",
  "workbuddy-ai": "workbuddy-desktop-ai.info",
};

/** In-memory refreshed sessions, keyed by site and uid. The desktop file is never updated. */
const memory = new Map<string, WorkBuddyCreds>();

export class WorkBuddyAuthError extends Error {
  constructor(message = WORKBUDDY_NOT_LOGGED_IN_ERROR) {
    super(message);
    this.name = "WorkBuddyAuthError";
  }
}

function cacheKey(site: WorkBuddySiteId, uid: string): string {
  return `${site}|${uid}`;
}

function remember(site: WorkBuddySiteId, creds: WorkBuddyCreds): void {
  memory.set(cacheKey(site, creds.uid), creds);
}

/** Drop cached sessions. Tests use this so a file read is not masked by an earlier refresh. */
export function resetWorkBuddyMemoryForTests(): void {
  memory.clear();
}

function recall(site: WorkBuddySiteId, accessToken?: string): WorkBuddyCreds | undefined {
  const prefix = `${site}|`;
  const rows: WorkBuddyCreds[] = [];
  for (const [key, creds] of memory) {
    if (!key.startsWith(prefix)) continue;
    if (accessToken && creds.accessToken === accessToken) return creds;
    rows.push(creds);
  }
  return rows.length === 1 ? rows[0] : undefined;
}

/**
 * Directory of the desktop auth files. `OCX_WORKBUDDY_AUTH_DIR` replaces the
 * platform directory (the folder that contains `workbuddy-desktop.info`).
 * Same relative layout as magpie `wbAuthPath`.
 */
function authDir(): string {
  const override = process.env.OCX_WORKBUDDY_AUTH_DIR?.trim();
  if (override) return override;
  const home = homedir();
  const os = platform();
  const base = os === "darwin"
    ? join(home, "Library", "Application Support", "CodeBuddyExtension")
    : os === "win32"
      ? join(home, "AppData", "Local", "CodeBuddyExtension")
      : join(home, ".local", "share", "CodeBuddyExtension");
  return join(base, "Data", "Public", "auth");
}

export function workBuddyAuthPath(site: WorkBuddySiteId): string {
  return join(authDir(), AUTH_FILE[site]);
}

function siteApi(site: WorkBuddySiteId): string {
  return SITE_API[site];
}

function siteHost(site: WorkBuddySiteId): string {
  return new URL(siteApi(site)).host;
}

export function workBuddySiteFromBaseUrl(baseUrl: string): WorkBuddySiteId | undefined {
  try {
    const host = new URL(baseUrl).host.toLowerCase();
    if (host === "copilot.tencent.com") return "workbuddy";
    if (host === "www.workbuddy.ai") return "workbuddy-ai";
  } catch {
    return undefined;
  }
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function finiteNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

function notLoggedIn(): never {
  throw new WorkBuddyAuthError();
}

/**
 * Read one desktop session. A missing file, a non-string token (credential
 * protection stores an object), or a missing uid/token is "not signed in".
 * This function does not create, truncate, or rewrite the file.
 */
export function readWorkBuddyDesktopAuth(site: WorkBuddySiteId): WorkBuddyCreds {
  let text: string;
  try {
    text = readFileSync(workBuddyAuthPath(site), { encoding: "utf8", flag: "r" });
  } catch {
    notLoggedIn();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    notLoggedIn();
  }
  const root = asRecord(parsed);
  const account = asRecord(root?.account);
  const auth = asRecord(root?.auth);
  if (!account || !auth) notLoggedIn();
  const uid = account.uid;
  const accessToken = auth.accessToken;
  const refreshToken = auth.refreshToken;
  if (typeof uid !== "string" || uid.length === 0) notLoggedIn();
  if (typeof accessToken !== "string" || accessToken.length === 0) notLoggedIn();
  if (typeof refreshToken !== "string" || refreshToken.length === 0) notLoggedIn();
  const now = Date.now();
  let expiresAt = finiteNumber(auth.expiresAt);
  if (expiresAt === 0) {
    const expiresIn = finiteNumber(auth.expiresIn);
    if (expiresIn > 0) expiresAt = now + expiresIn * 1000;
  }
  let refreshExpiresAt = finiteNumber(auth.refreshExpiresAt);
  if (refreshExpiresAt === 0) {
    const refreshExpiresIn = finiteNumber(auth.refreshExpiresIn);
    if (refreshExpiresIn > 0) refreshExpiresAt = now + refreshExpiresIn * 1000;
  }
  const domain = typeof auth.domain === "string" ? auth.domain.trim() : "";
  return {
    uid,
    accessToken,
    refreshToken,
    expiresAt,
    domain,
    ...(refreshExpiresAt > 0 ? { refreshExpiresAt } : {}),
  };
}

function toOAuth(creds: WorkBuddyCreds): OAuthCredentials {
  // A missing expiry means "trust it until the gateway refuses" (magpie
  // wbNearExpiry). The shared refresh gate treats a past timestamp as due,
  // so an unknown expiry must not be 0 or every request would refresh.
  const expires = creds.expiresAt > 0 ? creds.expiresAt : Date.now() + 24 * 60 * 60 * 1000;
  return {
    access: creds.accessToken,
    refresh: creds.refreshToken,
    expires,
    accountId: creds.uid,
    source: "credential-file",
  };
}

function adopt(site: WorkBuddySiteId, fromFile: WorkBuddyCreds): WorkBuddyCreds {
  const cached = memory.get(cacheKey(site, fromFile.uid));
  if (cached && cached.expiresAt >= fromFile.expiresAt && cached.accessToken) return cached;
  remember(site, fromFile);
  return fromFile;
}

/**
 * Local import only. There is no browser or device login — a missing or
 * encrypted desktop session fails here instead of opening a network flow.
 */
export async function loginWorkBuddy(ctrl: OAuthController, site: WorkBuddySiteId): Promise<OAuthCredentials> {
  const creds = adopt(site, readWorkBuddyDesktopAuth(site));
  ctrl.onProgress?.("Using the WorkBuddy desktop session");
  return toOAuth(creds);
}

interface RefreshedTokens {
  accessToken?: unknown;
  refreshToken?: unknown;
  expiresAt?: unknown;
  expiresIn?: unknown;
  refreshExpiresAt?: unknown;
  refreshExpiresIn?: unknown;
  domain?: unknown;
}

function mergeRefreshed(previous: WorkBuddyCreds, got: RefreshedTokens): WorkBuddyCreds {
  const accessToken = typeof got.accessToken === "string" ? got.accessToken : "";
  if (!accessToken) throw new Error("WorkBuddy gave no refreshed token");
  const now = Date.now();
  let expiresAt = finiteNumber(got.expiresAt);
  if (expiresAt === 0) {
    const expiresIn = finiteNumber(got.expiresIn);
    if (expiresIn > 0) expiresAt = now + expiresIn * 1000;
  }
  let refreshExpiresAt = finiteNumber(got.refreshExpiresAt);
  if (refreshExpiresAt === 0) {
    const refreshExpiresIn = finiteNumber(got.refreshExpiresIn);
    if (refreshExpiresIn > 0) refreshExpiresAt = now + refreshExpiresIn * 1000;
  }
  const refreshToken = typeof got.refreshToken === "string" && got.refreshToken.length > 0
    ? got.refreshToken
    : previous.refreshToken;
  const domain = typeof got.domain === "string" && got.domain.trim().length > 0
    ? got.domain.trim()
    : previous.domain;
  return {
    uid: previous.uid,
    accessToken,
    refreshToken,
    expiresAt: expiresAt > 0 ? expiresAt : previous.expiresAt,
    domain,
    ...((refreshExpiresAt > 0 || previous.refreshExpiresAt) ? { refreshExpiresAt: refreshExpiresAt || previous.refreshExpiresAt } : {}),
  };
}

function previousCreds(
  site: WorkBuddySiteId,
  refreshToken: string,
  credential: OAuthCredentials | undefined,
): WorkBuddyCreds {
  const uid = credential?.accountId;
  const cached = (uid ? memory.get(cacheKey(site, uid)) : undefined) ?? recall(site, credential?.access);
  if (cached) return { ...cached, refreshToken: refreshToken || cached.refreshToken };
  try {
    const fromFile = readWorkBuddyDesktopAuth(site);
    if (!uid || fromFile.uid === uid) return { ...fromFile, refreshToken: refreshToken || fromFile.refreshToken };
  } catch {
    // The desktop file is optional once a session is already stored.
  }
  if (!uid) throw new WorkBuddyAuthError();
  return {
    uid,
    accessToken: credential?.access ?? "",
    refreshToken,
    expiresAt: credential?.expires && credential.expires > 0 ? credential.expires : 0,
    domain: "",
  };
}

/**
 * POST `{api}/v2/plugin/auth/token/refresh`, matching magpie `wbRefresh`
 * (refresh token in `X-Refresh-Token`, empty JSON body). The new tokens are
 * remembered in memory only — the desktop auth file is not opened for write.
 */
export async function refreshWorkBuddyToken(
  refreshToken: string,
  signal: AbortSignal | undefined,
  credential: OAuthCredentials | undefined,
  site: WorkBuddySiteId,
): Promise<OAuthCredentials> {
  if (!refreshToken) throw new WorkBuddyAuthError();
  const previous = previousCreds(site, refreshToken, credential);
  const url = `${siteApi(site)}/v2/plugin/auth/token/refresh`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": `WorkBuddy/${WORKBUDDY_UA_VERSION}`,
      "X-Refresh-Token": refreshToken,
      "X-Auth-Refresh-Source": "plugin",
      "X-Domain": previous.domain || siteHost(site),
    },
    body: "{}",
    signal,
  });
  const body = await response.text();
  let parsed: Record<string, unknown> = {};
  try {
    const value = JSON.parse(body) as unknown;
    parsed = asRecord(value) ?? {};
  } catch {
    parsed = {};
  }
  const code = parsed.code;
  const okCode = code === undefined || code === 0 || code === "0";
  if (!response.ok || !okCode) {
    throw new Error(`WorkBuddy token refresh: HTTP ${response.status}`);
  }
  const data = asRecord(parsed.data) ?? (typeof parsed.accessToken === "string" ? parsed : undefined);
  if (!data) throw new Error("WorkBuddy gave no refreshed token");
  const next = mergeRefreshed(previous, data);
  remember(site, next);
  return toOAuth(next);
}

/** Headers the WorkBuddy desktop client sends on chat requests. `X-Request-ID` is new every call. */
export function buildWorkBuddyHeaders(creds: WorkBuddyCreds, site: WorkBuddySiteId): Record<string, string> {
  return {
    Authorization: `Bearer ${creds.accessToken}`,
    "X-User-Id": creds.uid,
    "X-Domain": creds.domain || siteHost(site),
    "X-Product": "SaaS",
    "X-IDE-Type": "WorkBuddy",
    "X-IDE-Name": "WorkBuddy",
    "X-IDE-Version": WORKBUDDY_UA_VERSION,
    "User-Agent": `WorkBuddy/${WORKBUDDY_UA_VERSION}`,
    "X-Requested-With": "XMLHttpRequest",
    "X-Agent-Intent": "craft",
    "X-Agent-Type": "main",
    "X-Request-ID": randomBytes(16).toString("hex"),
  };
}

function chooseChatCreds(site: WorkBuddySiteId, access: string): WorkBuddyCreds | undefined {
  const cached = recall(site, access);
  let fromFile: WorkBuddyCreds | undefined;
  try {
    fromFile = readWorkBuddyDesktopAuth(site);
  } catch {
    fromFile = undefined;
  }
  if (cached && fromFile) {
    if (cached.uid === fromFile.uid) return cached.expiresAt >= fromFile.expiresAt ? cached : fromFile;
    if (access && cached.accessToken === access) return cached;
    return fromFile;
  }
  return cached ?? fromFile;
}

/**
 * Per-request WorkBuddy headers for an openai-chat call whose base URL is one
 * of the two plan hosts. Returns undefined for every other provider so the
 * shared chat transport stays unchanged. A live `apiKey` wins over the
 * desktop file's access token (a refresh lives in memory / the oauth store).
 */
export function workBuddyChatHeaders(provider: { baseUrl?: string; apiKey?: string }): Record<string, string> | undefined {
  const site = workBuddySiteFromBaseUrl(provider.baseUrl ?? "");
  if (!site) return undefined;
  const access = typeof provider.apiKey === "string" ? provider.apiKey.trim() : "";
  const chosen = chooseChatCreds(site, access);
  if (!chosen) return undefined;
  const creds = access ? { ...chosen, accessToken: access } : chosen;
  return buildWorkBuddyHeaders(creds, site);
}
