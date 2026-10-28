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
}
