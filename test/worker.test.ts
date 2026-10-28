import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { sha256Hex } from "../src/auth";
import type { Env } from "../src/types";

const READ_KEY = "ilmcp_" + "r".repeat(43);
const WRITE_KEY = "ilmcp_" + "w".repeat(43);
const ADMIN_KEY = "ilmcp_" + "a".repeat(43);

// JWT whose payload is {"iat":1700000000}
const jwt = (iat: number) => `h.${btoa(JSON.stringify({ iat })).replace(/=+$/, "")}.s`;

function makeEnv(over: Partial<Env> = {}, limiterOk = true): Env {
  const kv = new Map<string, string>();
  const limiter = { limit: vi.fn(async () => ({ success: limiterOk })) };
  return {
    MCP_API_KEYS: "[]",
    ILOGISTIC_TOKEN: jwt(Math.floor(Date.now() / 1000)),
    ILOGISTIC_BASE_URL: "https://upstream.test",
    WRITES_ENABLED: "true",
    STATE: {
      get: async (k: string, t?: string) => (kv.has(k) ? (t === "json" ? JSON.parse(kv.get(k)!) : kv.get(k)) : null),
      put: async (k: string, v: string) => void kv.set(k, v),
    } as unknown as KVNamespace,
    RL_AUTH_FAIL: limiter,
    RL_KEY: limiter,
    RL_WRITE: limiter,
    ...over,
  } as Env;
}

async function withKeys(env: Env): Promise<Env> {
  env.MCP_API_KEYS = JSON.stringify([
    { name: "reader", sha256: await sha256Hex(READ_KEY), scopes: ["read"] },
    { name: "writer", sha256: await sha256Hex(WRITE_KEY), scopes: ["read", "write"] },
    { name: "admin", sha256: await sha256Hex(ADMIN_KEY), scopes: ["read", "write", "delete"] },
  ]);
  return env;
}

function rpc(env: Env, key: string | null, body: unknown, headers: Record<string, string> = {}) {
  return worker.fetch(
    new Request("https://w.test/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        ...(key ? { Authorization: `Bearer ${key}` } : {}),
        ...headers,
      },
      body: JSON.stringify(body),
    }),
    env,
  );
}

const listTools = { jsonrpc: "2.0", id: 1, method: "tools/list" };
const call = (name: string, args: unknown) => ({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: args } });
const toolNames = async (res: Response) => ((await res.json()) as any).result.tools.map((t: any) => t.name) as string[];

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn(async () => new Response(JSON.stringify([{ id: 1 }]), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("authentication & request hygiene", () => {
  it("rejects missing and wrong keys with 401", async () => {
    const env = await withKeys(makeEnv());
    expect((await rpc(env, null, listTools)).status).toBe(401);
    expect((await rpc(env, "ilmcp_" + "x".repeat(43), listTools)).status).toBe(401);
  });

  it("throttles repeated failed auth attempts", async () => {
    const env = await withKeys(makeEnv({}, false));
    expect((await rpc(env, "ilmcp_" + "x".repeat(43), listTools)).status).toBe(429);
  });

  it("fails closed on a broken MCP_API_KEYS", async () => {
    const env = makeEnv({ MCP_API_KEYS: "not json" });
    expect((await rpc(env, READ_KEY, listTools)).status).toBe(401);
  });

  it("rate limits authenticated callers per key", async () => {
    const env = await withKeys(makeEnv({}, false));
    // limiter denies everything: valid key is rejected with 429 (auth ok, quota exceeded)
    expect((await rpc(env, READ_KEY, listTools)).status).toBe(429);
  });

  it("blocks unlisted browser origins", async () => {
    const env = await withKeys(makeEnv());
    expect((await rpc(env, READ_KEY, listTools, { Origin: "https://evil.example" })).status).toBe(403);
  });

  it("only accepts POST on /mcp", async () => {
    const env = await withKeys(makeEnv());
    const res = await worker.fetch(new Request("https://w.test/mcp", { method: "GET" }), env);
    expect(res.status).toBe(405);
    expect((await worker.fetch(new Request("https://w.test/other"), env)).status).toBe(404);
  });

  it("rejects oversized bodies", async () => {
    const env = await withKeys(makeEnv());
    const res = await rpc(env, READ_KEY, { jsonrpc: "2.0", id: 1, method: "x", params: { pad: "a".repeat(300_000) } });
    expect(res.status).toBe(413);
  });

  it("measures the body limit in bytes, not characters", async () => {
    const env = await withKeys(makeEnv());
    // 200k chars < 256 KiB, but 400k bytes in UTF-8
    const res = await rpc(env, READ_KEY, { jsonrpc: "2.0", id: 1, method: "x", params: { pad: "é".repeat(200_000) } });
    expect(res.status).toBe(413);
  });
});

describe("PII redaction", () => {
  const person = {
    name: "Kovács Béla",
    email: "bela.kovacs8@gmail.com",
    phoneNumber: "+36701234567",
    country: "HU",
    postCode: "1234",
    city: "Budapest",
    address: "Petőfi Sándor u. 4.",
  };
  const order = {
    id: 62,
    foreignId: "I-1",
    state: "Jóváhagyva",
    delivery: { ...person, company: "GLS", aptNumber: null, taxNumber: "12345678" },
    billing: person,
    content: [{ productName: "Teszt Sajt", itemNumber: "SKU-1", quantity: 2 }],
  };

  for (const [tool, args, payload] of [
    ["ilogistic_list_orders", {}, [order]],
    ["ilogistic_get_order", { id: 62 }, order],
  ] as const) {
    it(`${tool} drops name/phone/address and masks email`, async () => {
      const env = await withKeys(makeEnv());
      fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(payload), { status: 200 }));
      const res = (await (await rpc(env, READ_KEY, call(tool, args))).json()) as any;
      const text: string = res.result.content[0].text;
      for (const secret of ["Kovács", "+3670", "Petőfi", "bela.kovacs8", "12345678"]) expect(text).not.toContain(secret);
      const out = JSON.parse(text);
      const o = Array.isArray(out) ? out[0] : out;
      expect(o.delivery).toEqual({ email: "b*****8@gmail.com", country: "HU", postCode: "1234", city: "Budapest", company: "GLS", aptNumber: null });
      expect(o.billing).toEqual({ email: "b*****8@gmail.com", country: "HU", postCode: "1234", city: "Budapest" });
      expect(o.content[0].productName).toBe("Teszt Sajt"); // non-customer names stay
    });
  }
});

describe("scope based tool exposure", () => {
  it("read key sees only read tools", async () => {
    const names = await toolNames(await rpc(await withKeys(makeEnv()), READ_KEY, listTools));
    expect(names).toContain("ilogistic_list_orders");
    expect(names.some((n) => /create|update|delete/.test(n))).toBe(false);
  });

  it("write key sees create/update but not delete", async () => {
    const names = await toolNames(await rpc(await withKeys(makeEnv()), WRITE_KEY, listTools));
    expect(names).toContain("ilogistic_create_order");
    expect(names).not.toContain("ilogistic_delete_order");
  });

  it("admin key sees delete tools", async () => {
    const names = await toolNames(await rpc(await withKeys(makeEnv()), ADMIN_KEY, listTools));
    expect(names).toContain("ilogistic_delete_order");
  });

  it("WRITES_ENABLED=false hides all write tools even for admin", async () => {
    const names = await toolNames(await rpc(await withKeys(makeEnv({ WRITES_ENABLED: "false" })), ADMIN_KEY, listTools));
    expect(names.some((n) => /create|update|delete/.test(n))).toBe(false);
  });
});

describe("tool calls", () => {
  it("list_orders hits the right upstream URL with bearer token and 0/1 booleans", async () => {
    const env = await withKeys(makeEnv());
    const res = await rpc(env, READ_KEY, call("ilogistic_list_orders", { limit: 5, state: "Jóváhagyva", isCompletable: true }));
    const body = (await res.json()) as any;
    expect(body.result.isError).toBeFalsy();
    const [url, init] = fetchMock.mock.calls[0]!;
    const u = new URL(String(url));
    expect(u.origin + u.pathname).toBe("https://upstream.test/orders/orders");
    expect(u.searchParams.get("limit")).toBe("5");
    expect(u.searchParams.get("offset")).toBe("0");
    expect(u.searchParams.get("isCompletable")).toBe("1");
    expect(u.searchParams.get("state")).toBe("Jóváhagyva");
    expect((init as RequestInit).redirect).toBe("manual");
    expect(((init as RequestInit).headers as Record<string, string>).Authorization).toBe(`Bearer ${env.ILOGISTIC_TOKEN}`);
  });

  it("validates input (bad id, limit too high)", async () => {
    const env = await withKeys(makeEnv());
    const a = (await (await rpc(env, READ_KEY, call("ilogistic_get_order", { id: "../../etc" }))).json()) as any;
    const b = (await (await rpc(env, READ_KEY, call("ilogistic_list_orders", { limit: 5000 }))).json()) as any;
    expect(a.result?.isError ?? !!a.error).toBeTruthy();
    expect(b.result?.isError ?? !!b.error).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("delete requires confirm: true", async () => {
    const env = await withKeys(makeEnv());
    const res = (await (await rpc(env, ADMIN_KEY, call("ilogistic_delete_order", { id: 7 }))).json()) as any;
    expect(res.result?.isError ?? !!res.error).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
    await rpc(env, ADMIN_KEY, call("ilogistic_delete_order", { id: 7, confirm: true }));
    expect((fetchMock.mock.calls[0]![1] as RequestInit).method).toBe("DELETE");
  });

  it("create_order moves webShopAlias into the X-WebShop-Alias header", async () => {
    const env = await withKeys(makeEnv());
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ id: 62 }), { status: 201 }));
    const person = { name: "T E", email: "t@e.hu", phoneNumber: "+36701234567", country: "HU", postCode: "1234", city: "Budapest", address: "Utca 1." };
    await rpc(
      env,
      WRITE_KEY,
      call("ilogistic_create_order", {
        webShopAlias: "shop.hu",
        delivery: { ...person, company: "GLS" },
        billing: person,
        payment: { type: "Utánvétes fizetés", cost: 1000 },
        content: [{ itemNumber: "SKU-1", quantity: 2 }],
      }),
    );
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>)["X-WebShop-Alias"]).toBe("shop.hu");
    expect(JSON.parse(init.body as string).webShopAlias).toBeUndefined();
  });

  it("maps upstream errors to a sanitized tool error", async () => {
    const env = await withKeys(makeEnv());
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: "Order 9 doesn't exist." }), { status: 404 }));
    const res = (await (await rpc(env, READ_KEY, call("ilogistic_get_order", { id: 9 }))).json()) as any;
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toBe("iLogistic API error 404: Order 9 doesn't exist.");
  });

  it("refreshes the iLogistic token once on 401 and retries", async () => {
    const env = await withKeys(makeEnv());
    const fresh = jwt(Math.floor(Date.now() / 1000) + 5);
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: "Bad authentication token were provided" }), { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: fresh }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }));
    const res = (await (await rpc(env, READ_KEY, call("ilogistic_list_products", {}))).json()) as any;
    expect(res.result.isError).toBeFalsy();
    expect(String(fetchMock.mock.calls[1]![0])).toBe("https://upstream.test/authentication/auth");
    expect(((fetchMock.mock.calls[2]![1] as RequestInit).headers as Record<string, string>).Authorization).toBe(`Bearer ${fresh}`);
  });
});

describe("token refresh robustness", () => {
  const unauthorized = () => new Response(JSON.stringify({ error: "Bad authentication token were provided" }), { status: 401 });
  const authCalls = () => fetchMock.mock.calls.filter(([u]) => String(u).endsWith("/authentication/auth")).length;

  it("a dead token triggers at most one refresh attempt per backoff window", async () => {
    const env = await withKeys(makeEnv());
    fetchMock.mockImplementation(async () => unauthorized());
    for (let i = 0; i < 3; i++) await rpc(env, READ_KEY, call("ilogistic_list_products", {}));
    expect(authCalls()).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(4); // 3 tool calls + 1 refresh, no retry storm
  });

  it("on 401 retries with a newer token another request already stored, without refreshing", async () => {
    const env = await withKeys(makeEnv());
    const newer = jwt(Math.floor(Date.now() / 1000) + 5);
    fetchMock
      .mockImplementationOnce(async () => {
        await env.STATE.put("ilogistic:token", JSON.stringify({ token: newer, iat: Math.floor(Date.now() / 1000) + 5 }));
        return unauthorized();
      })
      .mockResolvedValueOnce(new Response("[]", { status: 200 }));
    const res = (await (await rpc(env, READ_KEY, call("ilogistic_list_products", {}))).json()) as any;
    expect(res.result.isError).toBeFalsy();
    expect(authCalls()).toBe(0);
    expect(((fetchMock.mock.calls[1]![1] as RequestInit).headers as Record<string, string>).Authorization).toBe(`Bearer ${newer}`);
  });

  it("cron logs token_expiring under 24h and token_expired after expiry", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    fetchMock.mockImplementation(async () => unauthorized()); // refresh attempts fail
    const now = Math.floor(Date.now() / 1000);
    const run = async (iat: number) => {
      const pending: Promise<unknown>[] = [];
      await worker.scheduled({} as ScheduledController, makeEnv({ ILOGISTIC_TOKEN: jwt(iat) }), {
        waitUntil: (p: Promise<unknown>) => void pending.push(p),
      } as unknown as ExecutionContext);
      await Promise.all(pending);
    };
    const lastEvt = () => JSON.parse(String(error.mock.calls.at(-1)![0])).evt;

    await run(now - 7 * 86400 + 3600); // 1h left
    expect(lastEvt()).toBe("token_expiring");
    await run(now - 8 * 86400);
    expect(lastEvt()).toBe("token_expired");
    vi.restoreAllMocks();
  });
});
