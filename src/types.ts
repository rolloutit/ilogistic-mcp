export interface Env {
  // secrets
  MCP_API_KEYS: string;
  ILOGISTIC_TOKEN: string;
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
