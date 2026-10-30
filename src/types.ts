export interface Env {
  // secrets
  MCP_API_KEYS: string;
  /** base64, 32 bytes. Enables per-request iLogistic tokens (X-iLogistic-Token): they are stored encrypted with this key. */
  TOKEN_ENC_KEY?: string;
  /** Optional single-shop fallback used when a request carries no X-iLogistic-Token header. */
  ILOGISTIC_TOKEN?: string;
  // vars
  ILOGISTIC_BASE_URL: string;
  WRITES_ENABLED?: string;
  ALLOWED_ORIGINS?: string;
  TOKEN_REFRESH_AFTER_HOURS?: string;
  /** A shop's refreshed token chain is retired this many days after its first token (default 30); then a new token is needed. */
  TENANT_MAX_AGE_DAYS?: string;
  // bindings
  STATE: KVNamespace;
  RL_AUTH_FAIL: RateLimit;
  RL_KEY: RateLimit;
  RL_WRITE: RateLimit;
}

export type Scope = "read" | "write" | "delete";

export interface Principal {
  name: string;
  scopes: Scope[];
  /** SHA-256 of the presented key: shop records are bound to it, so a re-issued key (even with the same name) starts clean. */
  keyId: string;
  /** May fall back to the server-wide ILOGISTIC_TOKEN. */
  fallback: boolean;
}
