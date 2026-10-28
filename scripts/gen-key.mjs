// Usage: node scripts/gen-key.mjs <name> <scopes comma separated, e.g. read or read,write,delete>
// Prints the raw API key ONCE (give it to the MCP client) and the JSON entry to put into MCP_API_KEYS.
import { randomBytes, createHash } from "node:crypto";

const [name = "default", scopes = "read"] = process.argv.slice(2);
const list = scopes.split(",").map((s) => s.trim());
if (!list.every((s) => ["read", "write", "delete"].includes(s))) {
  console.error("scopes must be a comma separated subset of: read, write, delete");
  process.exit(1);
}
const key = "ilmcp_" + randomBytes(32).toString("base64url");
const sha256 = createHash("sha256").update(key).digest("hex");
console.log("API key (store in the client, shown only now):\n  " + key + "\n");
console.log("Entry for MCP_API_KEYS (merge into the JSON array):\n  " + JSON.stringify({ name, sha256, scopes: list }));
