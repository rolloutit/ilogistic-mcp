import { z } from "zod";
import type { Env, Principal } from "./types";

const KeyEntry = z.object({
  name: z.string().min(1).max(64),
  /** hex SHA-256 of the raw API key; the raw key is never stored server-side */
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  scopes: z.array(z.enum(["read", "write", "delete"])).min(1),
});
const KeyList = z.array(KeyEntry).min(1);

export async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function extractBearer(request: Request): string | null {
  const m = /^Bearer ([A-Za-z0-9._~+/=-]{32,256})$/.exec(request.headers.get("Authorization") ?? "");
  return m?.[1] ?? null;
}

/** Returns the matching principal, or null. Misconfigured key list fails closed. */
export async function authenticate(request: Request, env: Env): Promise<Principal | null> {
  const presented = extractBearer(request);
  if (!presented) return null;

  let entries: z.infer<typeof KeyList>;
  try {
    entries = KeyList.parse(JSON.parse(env.MCP_API_KEYS));
  } catch {
    console.error(JSON.stringify({ evt: "config_error", detail: "MCP_API_KEYS missing or invalid" }));
    return null;
  }

  const hash = await sha256Hex(presented);
  let found: Principal | null = null;
  for (const e of entries) {
    // no early exit: constant work regardless of which entry matches
    if (timingSafeEqualHex(hash, e.sha256) && !found) found = { name: e.name, scopes: e.scopes };
  }
  return found;
}
