// Manages the MCP API keys. The list of key hashes lives in ./mcp-keys.local (gitignored, hashes only),
// and `--push` uploads the complete list as the MCP_API_KEYS secret, so nobody has to rebuild the array by hand.
//
//   node scripts/gen-key.mjs <name> <scopes> [--push]   add a key (or replace the one with this name); scopes: read,write,delete
//   node scripts/gen-key.mjs revoke <name> [--push]     remove a key
//   node scripts/gen-key.mjs list                       show names and scopes
//
// The raw key is printed ONCE (give it to the client); only its SHA-256 hash is stored.
import { randomBytes, createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const FILE = process.env.MCP_KEYS_FILE ?? "mcp-keys.local";
const SCOPES = ["read", "write", "delete"];
const sha = (s) => createHash("sha256").update(s).digest("hex");

const args = process.argv.slice(2);
const push = args.includes("--push");
const [cmd = "", ...rest] = args.filter((a) => a !== "--push");

function load() {
  if (existsSync(FILE)) return JSON.parse(readFileSync(FILE, "utf8"));
  // First run: adopt the key created earlier by hand (mcp-api-key.local), which is already live in Cloudflare.
  if (existsSync("mcp-api-key.local")) {
    const raw = readFileSync("mcp-api-key.local", "utf8").trim();
    console.error("Adopting the existing key from mcp-api-key.local as 'claude-code' (read,write,delete).");
    return [{ name: "claude-code", sha256: sha(raw), scopes: SCOPES }];
  }
  return [];
}

function save(keys) {
  writeFileSync(FILE, JSON.stringify(keys, null, 2) + "\n", { mode: 0o600 });
  console.log(`Saved ${keys.length} key(s) to ${FILE}: ${keys.map((k) => k.name).join(", ") || "(none)"}`);
  if (push) {
    const r = spawnSync("npx", ["wrangler", "secret", "put", "MCP_API_KEYS"], { input: JSON.stringify(keys), stdio: ["pipe", "inherit", "inherit"] });
    if (r.status !== 0) process.exit(r.status ?? 1);
    console.log("MCP_API_KEYS uploaded; it is live immediately.");
  } else {
    console.log("Not uploaded yet: rerun with --push (or: npx wrangler secret put MCP_API_KEYS < mcp-keys.local).");
  }
}

const keys = load();

if (cmd === "list") {
  for (const k of keys) console.log(`${k.name}\t${k.scopes.join(",")}`);
} else if (cmd === "revoke") {
  const [name] = rest;
  if (!keys.some((k) => k.name === name)) {
    console.error(`No key named '${name}'.`);
    process.exit(1);
  }
  save(keys.filter((k) => k.name !== name));
} else {
  const [name = "", scopes = "read"] = [cmd, ...rest];
  const list = scopes.split(",").map((s) => s.trim());
  if (!name || !list.every((s) => SCOPES.includes(s))) {
    console.error("usage: gen-key.mjs <name> <read|write|delete, comma separated> [--push] | revoke <name> [--push] | list");
    process.exit(1);
  }
  const key = "ilmcp_" + randomBytes(32).toString("base64url");
  save([...keys.filter((k) => k.name !== name), { name, sha256: sha(key), scopes: list }]);
  console.log("\nAPI key for '" + name + "' (give it to the client; shown only now):\n  " + key);
}
