import { decrypt, encrypt } from "./crypto";
import type { Env } from "./types";

const MAX_RESPONSE_CHARS = 100_000;
const UPSTREAM_TIMEOUT_MS = 20_000;
const KV_TOKEN = "ilogistic:token";
const KV_BACKOFF = "ilogistic:refresh-backoff";
const TOKEN_LIFETIME_S = 604_800; // 7 days, per the iLogistic docs
// After a failed refresh (cron or 401 path) no new attempt for this long; short so a missed window is retried soon.
const REFRESH_BACKOFF_S = 300;
const EXPIRY_WARN_S = 24 * 3600;
// Per-request ("tenant") tokens: a shop that stops calling the MCP for this long is forgotten, so the cron stops refreshing it.
const TENANT_IDLE_S = 90 * 24 * 3600;
const TENANT_PREFIX = "ten:";
// Refresh leeway after expiry is 120 s; past this a token is unrecoverable and its record is dropped.
const EXPIRED_GRACE_S = 300;
// Free-plan Workers allow 50 subrequests per invocation (KV calls included): cap the hourly cron's refreshes.
const MAX_TENANT_REFRESH_PER_RUN = 8;

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

/** A shop identified by the iLogistic token its client sends; `seed` is empty when the cron maintains it. */
export interface Tenant {
  id: string;
  seed: string;
}

interface TenantMeta {
  iat: number;
  seen: number;
}

const nowS = () => Math.floor(Date.now() / 1000);

export class IlogisticClient {
  private seen = 0;

  constructor(
    private env: Env,
    private tenant?: Tenant,
  ) {}

  private get backoffKey(): string {
    return this.tenant ? `bo:${this.tenant.id}` : KV_BACKOFF;
  }

  private get tenantKey(): string {
    return `${TENANT_PREFIX}${this.tenant!.id}`;
  }

  private async readTenant(): Promise<StoredToken | null> {
    const { value, metadata } = await this.env.STATE.getWithMetadata<TenantMeta>(this.tenantKey);
    if (!value) return null;
    const plain = await decrypt(this.env.TOKEN_ENC_KEY ?? "", value, this.tenantKey);
    if (!plain) return null;
    try {
      const t = JSON.parse(plain) as StoredToken;
      this.seen = metadata?.seen ?? 0;
      return typeof t.token === "string" ? t : null;
    } catch {
      return null;
    }
  }

  private async writeTenant(t: StoredToken, seen: number): Promise<void> {
    if (!this.env.TOKEN_ENC_KEY) throw new IlogisticError(503, "TOKEN_ENC_KEY is not configured on the server.");
    this.seen = seen;
    await this.env.STATE.put(this.tenantKey, await encrypt(this.env.TOKEN_ENC_KEY, JSON.stringify(t), this.tenantKey), {
      expiration: seen + TENANT_IDLE_S,
      metadata: { iat: t.iat, seen } satisfies TenantMeta,
    });
  }

  private get base(): string {
    return this.env.ILOGISTIC_BASE_URL.replace(/\/+$/, "");
  }

  /**
   * Tenant mode: the token record kept (encrypted) in KV, seeded from the client's header on first sight.
   * The record is the newest token the server has refreshed to, so a client that keeps sending its original
   * (by now expired) token still reaches the API.
   * Legacy mode: newest of the ILOGISTIC_TOKEN secret and the last refreshed token kept in KV.
   */
  private async currentToken(): Promise<StoredToken> {
    if (this.tenant) {
      const seed: StoredToken = { token: this.tenant.seed, iat: jwtIat(this.tenant.seed) };
      const stored = await this.readTenant();
      if (!stored) {
        if (seed.token) await this.writeTenant(seed, nowS());
        return seed;
      }
      // A live request (seed present) refreshes the idle clock, at most once a day to spare KV writes.
      if (seed.token && nowS() - this.seen > 86_400) await this.writeTenant(stored, nowS());
      return stored;
    }
    const secret = this.env.ILOGISTIC_TOKEN ?? "";
    const boot: StoredToken = { token: secret, iat: jwtIat(secret) };
    const stored = await this.env.STATE.get<StoredToken>(KV_TOKEN, "json");
    return stored && stored.iat > boot.iat ? stored : boot;
  }

  private async storeRefreshed(token: string, iat: number): Promise<void> {
    if (this.tenant) {
      await this.writeTenant({ token, iat }, this.seen || nowS());
    } else {
      await this.env.STATE.put(KV_TOKEN, JSON.stringify({ token, iat }));
    }
  }

  /**
   * Exchange the current token for a fresh one (GET /authentication/auth).
   * The API refuses tokens that are "too fresh", so this is only attempted when the token is old
   * enough (or `force`, on an upstream 401). Every failure, forced or not, backs off for
   * REFRESH_BACKOFF_S, so a dead token cannot turn each tool call into extra upstream calls.
   * Returns true when a new token was stored.
   */
  async refreshIfNeeded(force = false): Promise<boolean> {
    const cur = await this.currentToken();
    if (!cur.token) return false;
    const ageS = nowS() - cur.iat;
    const thresholdS = Number(this.env.TOKEN_REFRESH_AFTER_HOURS ?? "144") * 3600;
    if (!force && cur.iat > 0 && ageS < thresholdS) return false;
    if (await this.env.STATE.get(this.backoffKey)) return false;

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
        if (iat >= latest.iat) await this.storeRefreshed(data.token, iat);
        console.log(JSON.stringify({ evt: "token_refreshed", forced: force }));
        return true;
      }
      console.warn(
        JSON.stringify({ evt: "token_refresh_failed", forced: force, status: res.status, error: String(data.error ?? "") }),
      );
    } catch (e) {
      console.warn(JSON.stringify({ evt: "token_refresh_error", forced: force, error: (e as Error).message }));
    }
    await this.env.STATE.put(this.backoffKey, "1", { expirationTtl: REFRESH_BACKOFF_S });
    return false;
  }

  /** Cron entry point: refresh when due, then log the remaining lifetime (alert on token_expiring / token_expired). */
  async scheduledMaintenance(): Promise<void> {
    if (!this.tenant && !this.env.ILOGISTIC_TOKEN) return; // no single-shop fallback configured
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
    return iat > 0 ? iat + TOKEN_LIFETIME_S - nowS() : null;
  }

  async request(method: "GET" | "POST" | "PATCH" | "DELETE", path: string, opts: RequestOptions = {}): Promise<unknown> {
    const first = await this.currentToken();
    if (!first.token) {
      throw new IlogisticError(503, "No iLogistic token: send it in the X-iLogistic-Token request header.");
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

    const used = first.token;
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

    if (res.status === 401) {
      // Still unauthorized after the refresh attempt: the token is expired (or revoked) and cannot be recovered.
      throw new IlogisticError(
        401,
        this.tenant
          ? "The iLogistic token has expired or is invalid and could not be refreshed. Get a new token from iLogistic and send it in the X-iLogistic-Token request header."
          : "The iLogistic token has expired or is invalid and could not be refreshed. Replace the ILOGISTIC_TOKEN secret with a new token.",
      );
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

/**
 * Cron: refresh every stored shop token that is old enough and forget the ones that can no longer be recovered.
 * Ages come from the KV key metadata, so only tokens that are actually due cost a KV read and an upstream call.
 */
export async function maintainTenants(env: Env): Promise<void> {
  if (!env.TOKEN_ENC_KEY) return;
  const thresholdS = Number(env.TOKEN_REFRESH_AFTER_HOURS ?? "144") * 3600;
  let refreshed = 0;
  let cursor: string | undefined;
  do {
    const page = await env.STATE.list<TenantMeta>({ prefix: TENANT_PREFIX, cursor });
    for (const { name, metadata } of page.keys) {
      const id = name.slice(TENANT_PREFIX.length);
      const iat = metadata?.iat ?? 0;
      let ttl = iat > 0 ? iat + TOKEN_LIFETIME_S - nowS() : null;
      if (ttl !== null && ttl < -EXPIRED_GRACE_S) {
        await env.STATE.delete(name);
        console.error(JSON.stringify({ evt: "tenant_token_expired", tenant: id.slice(0, 8), secondsAgo: -ttl }));
        continue;
      }
      if ((iat === 0 || nowS() - iat >= thresholdS) && refreshed < MAX_TENANT_REFRESH_PER_RUN) {
        refreshed++;
        const client = new IlogisticClient(env, { id, seed: "" });
        await client.refreshIfNeeded();
        ttl = await client.tokenTtl();
      }
      if (ttl !== null && ttl < EXPIRY_WARN_S) {
        console.error(JSON.stringify({ evt: "tenant_token_expiring", tenant: id.slice(0, 8), hoursLeft: Math.round((ttl / 3600) * 10) / 10 }));
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}
