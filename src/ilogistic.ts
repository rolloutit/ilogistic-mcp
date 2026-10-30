import { parseKeys, sha256Hex } from "./auth";
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
// Refresh leeway after expiry is 120 s; past this a token is unrecoverable and its record is dropped.
const EXPIRED_GRACE_S = 300;

// ---- per-request ("tenant") tokens ----
// ten:<id>  encrypted token record, metadata { iat, born, sub }, expires born + TENANT_MAX_AGE_DAYS
// seen:<id> last live use (written at most daily, expires after TENANT_IDLE_S): kept apart so a "seen" update never
//           rewrites, and so can never roll back, the token record
// bo:<id>   refresh backoff
// <id> = <first 16 hex of the MCP key hash>.<32 hex of sha256(key hash + original token)>
const TENANT_PREFIX = "ten:";
const SEEN_PREFIX = "seen:";
const BACKOFF_PREFIX = "bo:";
// A shop that stops calling the MCP for this long is forgotten, so the cron stops refreshing it.
const TENANT_IDLE_S = 90 * 24 * 3600;
const SEEN_WRITE_EVERY_S = 86_400;
// KV list() may lag behind writes: a record younger than this is never treated as idle.
const NEW_RECORD_GRACE_S = 86_400;
// Free-plan Workers allow 50 subrequests per invocation and KV calls count. The tenant cron gets this many,
// the rest is left for the single-shop fallback refresh running in the same invocation.
const CRON_KV_BUDGET = 40;
const REFRESH_COST = 5; // backoff get, record read, auth fetch, record re-read, record put (or backoff put)
const DROP_COST = 2; // record + seen delete

const EXPIRED_TENANT_MSG =
  "The iLogistic token has expired or is invalid and could not be refreshed. Get a new token from iLogistic and send it in the X-iLogistic-Token request header.";

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

function jwtPayload(token: string): Record<string, unknown> {
  try {
    const part = token.split(".")[1];
    if (!part) return {};
    const json = atob(part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "="));
    const payload = JSON.parse(json) as unknown;
    return payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** iat (seconds) from the JWT payload; 0 when it cannot be read. */
export function jwtIat(token: string): number {
  const iat = jwtPayload(token).iat;
  return typeof iat === "number" ? iat : 0;
}

/** Hash of the iLogistic user (the token's email claim): records of one shop under one MCP key share it. */
async function tokenSubject(token: string): Promise<string | undefined> {
  const email = jwtPayload(token).email;
  return typeof email === "string" && email ? (await sha256Hex(email.trim().toLowerCase())).slice(0, 16) : undefined;
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
  born: number;
  sub?: string;
}

const nowS = () => Math.floor(Date.now() / 1000);
const maxAgeS = (env: Env) => Number(env.TENANT_MAX_AGE_DAYS ?? "30") * 86_400;

export async function tenantId(keyId: string, token: string): Promise<string> {
  return `${keyId.slice(0, 16)}.${(await sha256Hex(`${keyId}:${token}`)).slice(0, 32)}`;
}

async function dropTenant(env: Env, id: string): Promise<void> {
  await Promise.all([env.STATE.delete(TENANT_PREFIX + id), env.STATE.delete(SEEN_PREFIX + id)]);
}

export class IlogisticClient {
  /** Metadata of the stored record; null while this tenant has no (readable) record yet. */
  private meta: TenantMeta | null = null;
  private touched = false;

  constructor(
    private env: Env,
    private tenant?: Tenant,
    /** Without a tenant: may use the server-wide ILOGISTIC_TOKEN (the cron always may). */
    private useFallback = true,
  ) {}

  private key(prefix: string): string {
    return prefix + this.tenant!.id;
  }

  private get backoffKey(): string {
    return this.tenant ? this.key(BACKOFF_PREFIX) : KV_BACKOFF;
  }

  private async readTenant(): Promise<StoredToken | null> {
    const name = this.key(TENANT_PREFIX);
    const { value, metadata } = await this.env.STATE.getWithMetadata<TenantMeta>(name);
    if (!value || !metadata) return null;
    if (nowS() - metadata.born > maxAgeS(this.env)) {
      // The chain is retired: only a token the client got from iLogistic recently can start a new one.
      await dropTenant(this.env, this.tenant!.id);
      console.log(JSON.stringify({ evt: "tenant_dropped", reason: "max_age", tenant: this.tenant!.id.slice(0, 8) }));
      return null;
    }
    const plain = await decrypt(this.env.TOKEN_ENC_KEY ?? "", value, name);
    if (!plain) return null;
    try {
      const t = JSON.parse(plain) as StoredToken;
      if (typeof t.token !== "string") return null;
      this.meta = metadata;
      return t;
    } catch {
      return null;
    }
  }

  /**
   * Stores the token record. The first write for a tenant is only made once iLogistic accepted the token
   * (a 2xx answer or a successful refresh), so made-up tokens never reach KV.
   */
  private async writeTenant(t: StoredToken): Promise<void> {
    if (!this.env.TOKEN_ENC_KEY) throw new IlogisticError(503, "TOKEN_ENC_KEY is not configured on the server.");
    const name = this.key(TENANT_PREFIX);
    const first = !this.meta;
    const meta: TenantMeta = this.meta
      ? { ...this.meta, iat: t.iat }
      : { iat: t.iat, born: nowS(), sub: await tokenSubject(this.tenant!.seed) };
    await this.env.STATE.put(name, await encrypt(this.env.TOKEN_ENC_KEY, JSON.stringify(t), name), {
      expiration: meta.born + maxAgeS(this.env),
      metadata: meta,
    });
    this.meta = meta;
    if (first) {
      await this.env.STATE.put(this.key(SEEN_PREFIX), String(nowS()), { expirationTtl: TENANT_IDLE_S });
      this.touched = true;
      if (meta.sub) await this.retireSiblings(meta.sub);
    }
  }

  /**
   * The shop started a new chain under the same MCP key (it sent a new token, e.g. after a leak):
   * its older chains are dropped, so the old token stops working here.
   */
  private async retireSiblings(sub: string): Promise<void> {
    const [keyPart] = this.tenant!.id.split(".");
    const page = await this.env.STATE.list<TenantMeta>({ prefix: `${TENANT_PREFIX}${keyPart}.` });
    for (const { name, metadata } of page.keys) {
      const id = name.slice(TENANT_PREFIX.length);
      if (id === this.tenant!.id || metadata?.sub !== sub) continue;
      await dropTenant(this.env, id);
      console.log(JSON.stringify({ evt: "tenant_dropped", reason: "rotated", tenant: id.slice(0, 8) }));
    }
  }

  /** Live request: keeps the record from being forgotten as idle (one KV write a day at most). */
  private async touch(): Promise<void> {
    if (this.touched || !this.tenant?.seed) return;
    this.touched = true;
    const last = Number((await this.env.STATE.get(this.key(SEEN_PREFIX))) ?? "0");
    if (nowS() - last > SEEN_WRITE_EVERY_S) {
      await this.env.STATE.put(this.key(SEEN_PREFIX), String(nowS()), { expirationTtl: TENANT_IDLE_S });
    }
  }

  private get base(): string {
    return this.env.ILOGISTIC_BASE_URL.replace(/\/+$/, "");
  }

  /**
   * Tenant mode: the token record kept (encrypted) in KV, which is the newest token the server has refreshed to,
   * so a client that keeps sending its original (by now expired) token still reaches the API. Without a record:
   * the client's header token.
   * Fallback mode: newest of the ILOGISTIC_TOKEN secret and the last refreshed token kept in KV.
   */
  private async currentToken(): Promise<StoredToken> {
    if (this.tenant) {
      const stored = await this.readTenant();
      if (stored) {
        await this.touch();
        return stored;
      }
      return { token: this.tenant.seed, iat: jwtIat(this.tenant.seed) };
    }
    if (!this.useFallback) return { token: "", iat: 0 };
    const secret = this.env.ILOGISTIC_TOKEN ?? "";
    const boot: StoredToken = { token: secret, iat: jwtIat(secret) };
    const stored = await this.env.STATE.get<StoredToken>(KV_TOKEN, "json");
    return stored && stored.iat > boot.iat ? stored : boot;
  }

  private async storeRefreshed(token: string, iat: number): Promise<void> {
    if (this.tenant) {
      await this.writeTenant({ token, iat });
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
    // An unknown header token has nothing stored to protect: no KV write for it (made-up tokens cost no KV writes).
    if (!this.tenant || this.meta) await this.env.STATE.put(this.backoffKey, "1", { expirationTtl: REFRESH_BACKOFF_S });
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
    // An expired header token can no longer start a chain (also stops long-expired leaked tokens costing upstream calls).
    if (this.tenant && !this.meta && first.iat + TOKEN_LIFETIME_S + EXPIRED_GRACE_S < nowS()) {
      throw new IlogisticError(401, EXPIRED_TENANT_MSG);
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
    } else if (res.ok && this.tenant && !this.meta) {
      await this.writeTenant(first); // iLogistic accepted the header token: start this shop's record
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
          ? EXPIRED_TENANT_MSG
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

async function listAll<M>(env: Env, prefix: string): Promise<{ keys: KVNamespaceListKey<M>[]; calls: number }> {
  const keys: KVNamespaceListKey<M>[] = [];
  let calls = 0;
  let cursor: string | undefined;
  do {
    const page = await env.STATE.list<M>({ prefix, cursor });
    calls++;
    keys.push(...page.keys);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return { keys, calls };
}

/**
 * Cron: refresh the shop tokens that are due, oldest first, then drop the records that must go
 * (revoked MCP key, expired, past max age, idle, unreadable). Works within CRON_KV_BUDGET; what does not fit
 * is picked up by the next hourly run.
 */
export async function maintainTenants(env: Env): Promise<void> {
  if (!env.TOKEN_ENC_KEY) return;
  const records = await listAll<TenantMeta>(env, TENANT_PREFIX);
  const seen = await listAll(env, SEEN_PREFIX);
  let budget = CRON_KV_BUDGET - records.calls - seen.calls;
  const seenIds = new Set(seen.keys.map((k) => k.name.slice(SEEN_PREFIX.length)));
  // null when MCP_API_KEYS cannot be read: then nothing is dropped as "key_revoked"
  const liveKeys = (() => {
    const keys = parseKeys(env);
    return keys ? new Set(keys.map((k) => k.sha256.slice(0, 16))) : null;
  })();

  const now = nowS();
  const thresholdS = Number(env.TOKEN_REFRESH_AFTER_HOURS ?? "144") * 3600;
  const drop: { id: string; reason: string }[] = [];
  const due: { id: string; iat: number }[] = [];
  for (const { name, metadata } of records.keys) {
    const id = name.slice(TENANT_PREFIX.length);
    const iat = metadata?.iat ?? 0;
    const born = metadata?.born ?? 0;
    const reason =
      liveKeys && !liveKeys.has(id.split(".")[0]!)
        ? "key_revoked"
        : iat <= 0 || born <= 0
          ? "unreadable"
          : iat + TOKEN_LIFETIME_S + EXPIRED_GRACE_S < now
            ? "expired"
            : now - born > maxAgeS(env)
              ? "max_age"
              : !seenIds.has(id) && now - born > NEW_RECORD_GRACE_S
                ? "idle"
                : null;
    if (reason) drop.push({ id, reason });
    else if (now - iat >= thresholdS) due.push({ id, iat });
  }

  // Oldest first: the tokens closest to expiry are refreshed before the others.
  due.sort((a, b) => a.iat - b.iat);
  let refreshed = 0;
  for (const { id, iat } of due) {
    if (budget < REFRESH_COST) break;
    budget -= REFRESH_COST;
    refreshed++;
    const ok = await new IlogisticClient(env, { id, seed: "" }).refreshIfNeeded();
    const ttl = iat + TOKEN_LIFETIME_S - now;
    if (!ok && ttl < EXPIRY_WARN_S) {
      console.error(JSON.stringify({ evt: "tenant_token_expiring", tenant: id.slice(0, 8), hoursLeft: Math.round((ttl / 3600) * 10) / 10 }));
    }
  }
  if (refreshed < due.length) {
    console.warn(JSON.stringify({ evt: "tenant_refresh_backlog", waiting: due.length - refreshed }));
  }

  for (const { id, reason } of drop) {
    if (budget < DROP_COST) break;
    budget -= DROP_COST;
    await dropTenant(env, id);
    const evt = reason === "expired" ? "tenant_token_expired" : "tenant_dropped";
    (reason === "expired" ? console.error : console.log)(JSON.stringify({ evt, reason, tenant: id.slice(0, 8) }));
  }
}
