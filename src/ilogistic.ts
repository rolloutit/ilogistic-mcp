import type { Env } from "./types";

const MAX_RESPONSE_CHARS = 100_000;
const UPSTREAM_TIMEOUT_MS = 20_000;
const KV_TOKEN = "ilogistic:token";
const KV_BACKOFF = "ilogistic:refresh-backoff";
const TOKEN_LIFETIME_S = 604_800; // 7 days, per the iLogistic docs
// After a failed refresh (cron or 401 path) no new attempt for this long; short so a missed window is retried soon.
const REFRESH_BACKOFF_S = 300;
const EXPIRY_WARN_S = 24 * 3600;

export class IlogisticError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

interface StoredToken {
  token: string;
  iat: number;
}

/** iat (seconds) from the JWT payload; 0 when it cannot be read. */
export function jwtIat(token: string): number {
  try {
    const part = token.split(".")[1];
    if (!part) return 0;
    const json = atob(part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "="));
    const iat = (JSON.parse(json) as { iat?: unknown }).iat;
    return typeof iat === "number" ? iat : 0;
  } catch {
    return 0;
  }
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  headers?: Record<string, string>;
}

export class IlogisticClient {
  constructor(private env: Env) {}

  private get base(): string {
    return this.env.ILOGISTIC_BASE_URL.replace(/\/+$/, "");
  }

  /** Newest of: the secret bootstrap token and the last refreshed token kept in KV. */
  private async currentToken(): Promise<StoredToken> {
    const boot: StoredToken = { token: this.env.ILOGISTIC_TOKEN, iat: jwtIat(this.env.ILOGISTIC_TOKEN) };
    const stored = await this.env.STATE.get<StoredToken>(KV_TOKEN, "json");
    return stored && stored.iat > boot.iat ? stored : boot;
  }

  /**
   * Exchange the current token for a fresh one (GET /authentication/auth).
   * The API refuses tokens that are "too fresh", so this is only attempted when the token is old
   * enough (or `force`, on an upstream 401). Every failure, forced or not, backs off for
   * REFRESH_BACKOFF_S, so a dead token cannot turn each tool call into extra upstream calls.
   * Returns true when a new token was stored.
   */
  async refreshIfNeeded(force = false): Promise<boolean> {
    if (!this.env.ILOGISTIC_TOKEN) return false;
    const cur = await this.currentToken();
    const ageS = Math.floor(Date.now() / 1000) - cur.iat;
    const thresholdS = Number(this.env.TOKEN_REFRESH_AFTER_HOURS ?? "144") * 3600;
    if (!force && cur.iat > 0 && ageS < thresholdS) return false;
    if (await this.env.STATE.get(KV_BACKOFF)) return false;

    try {
      const res = await fetch(`${this.base}/authentication/auth`, {
        headers: { Authorization: `Bearer ${cur.token}`, Accept: "application/json" },
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      });
      const data = (await res.json().catch(() => ({}))) as { token?: unknown; error?: unknown };
      if (res.ok && typeof data.token === "string") {
        const iat = jwtIat(data.token);
        // A concurrent refresh may already have stored a newer token: never replace it with an older one.
        const latest = await this.currentToken();
        if (iat >= latest.iat) await this.env.STATE.put(KV_TOKEN, JSON.stringify({ token: data.token, iat }));
        console.log(JSON.stringify({ evt: "token_refreshed", forced: force }));
        return true;
      }
      console.warn(
        JSON.stringify({ evt: "token_refresh_failed", forced: force, status: res.status, error: String(data.error ?? "") }),
      );
    } catch (e) {
      console.warn(JSON.stringify({ evt: "token_refresh_error", forced: force, error: (e as Error).message }));
    }
    await this.env.STATE.put(KV_BACKOFF, "1", { expirationTtl: REFRESH_BACKOFF_S });
    return false;
  }

  /** Cron entry point: refresh when due, then log the remaining lifetime (alert on token_expiring / token_expired). */
  async scheduledMaintenance(): Promise<void> {
    await this.refreshIfNeeded();
    const ttl = await this.tokenTtl();
    if (ttl === null) {
      console.error(JSON.stringify({ evt: "token_unreadable", detail: "no iat in the iLogistic token" }));
    } else if (ttl <= 0) {
      console.error(JSON.stringify({ evt: "token_expired", secondsAgo: -ttl }));
    } else if (ttl < EXPIRY_WARN_S) {
      console.error(JSON.stringify({ evt: "token_expiring", hoursLeft: Math.round((ttl / 3600) * 10) / 10 }));
    } else {
      console.log(JSON.stringify({ evt: "token_status", hoursLeft: Math.round(ttl / 3600) }));
    }
  }

  /** Seconds until the current token expires (negative = already expired). */
  async tokenTtl(): Promise<number | null> {
    const { iat } = await this.currentToken();
    return iat > 0 ? iat + TOKEN_LIFETIME_S - Math.floor(Date.now() / 1000) : null;
  }

  async request(method: "GET" | "POST" | "PATCH" | "DELETE", path: string, opts: RequestOptions = {}): Promise<unknown> {
    if (!this.env.ILOGISTIC_TOKEN) {
      throw new IlogisticError(503, "ILOGISTIC_TOKEN is not configured on the server yet.");
    }
    const send = async (token: string) => {
      const url = new URL(this.base + path);
      for (const [k, v] of Object.entries(opts.query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));
      return fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
          ...opts.headers,
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        redirect: "manual", // never follow redirects with the bearer token attached
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      });
    };

    const used = (await this.currentToken()).token;
    let res = await send(used);
    if (res.status === 401) {
      // Another request may have refreshed meanwhile: try the newest stored token before refreshing ourselves.
      const latest = (await this.currentToken()).token;
      if (latest !== used) res = await send(latest);
      else if (await this.refreshIfNeeded(true)) res = await send((await this.currentToken()).token);
    }

    const text = await res.text();
    let data: unknown = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      /* non-JSON body, keep text */
    }

    if (!res.ok) {
      const apiMsg =
        data && typeof data === "object" && "error" in data ? String((data as { error: unknown }).error) : String(text);
      const extra = data && typeof data === "object" && "id" in data ? ` (id: ${(data as { id: unknown }).id})` : "";
      throw new IlogisticError(res.status, `${apiMsg.slice(0, 400)}${extra}`);
    }
    return data;
  }
}

export function toToolText(data: unknown): string {
  const text = JSON.stringify(data);
  if (text.length <= MAX_RESPONSE_CHARS) return text;
  return `${text.slice(0, MAX_RESPONSE_CHARS)}\n…[truncated: response exceeded ${MAX_RESPONSE_CHARS} characters; use limit/offset or filters to narrow it]`;
}
