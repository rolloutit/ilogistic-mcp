import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { IlogisticClient, IlogisticError, toToolText } from "./ilogistic";
import { redactPii } from "./pii";
import {
  DELIVERY_COMPANIES,
  INWARD_STATES,
  ORDER_STATES,
  PAYMENT_TYPES,
  PRODUCT_CATEGORIES,
  REFERENCE,
} from "./reference";
import type { Env, Principal, Scope } from "./types";

// ---------- shared schema pieces ----------
const id = z.number().int().positive().describe("iLogistic numeric ID");
const limit = z.number().int().min(1).max(100).default(25).describe("Page size (1-100, default 25)");
const offset = z.number().int().min(0).max(1_000_000).default(0).describe("Items to skip");
const isoDateTime = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?$/, "Use ISO-8601, e.g. 2026-01-12T12:45:57")
  .describe("ISO-8601 date-time, e.g. 2026-01-12T12:45:57");
const itemNumber = z.string().min(1).max(255).describe("Product itemNumber (SKU) as registered in iLogistic");
const bool01 = z.boolean().describe("true = 1, false = 0");

const confirm = z
  .literal(true)
  .describe("Must be exactly true. Set it only after the user explicitly confirmed this irreversible action.");

const personFields = {
  name: z.string().min(1).max(50),
  email: z.string().min(3).max(50),
  phoneNumber: z.string().min(1).max(50).describe("Must start with +36"),
  country: z.string().min(2).max(50).describe("Hungarian name, ISO alpha-2 (HU) or alpha-3 (HUN)"),
  postCode: z.string().min(1).max(50),
  city: z.string().min(1).max(50),
  address: z.string().min(1).max(255),
};
const delivery = z.object({
  ...personFields,
  company: z.enum(DELIVERY_COMPANIES).describe("Shipping method"),
  aptNumber: z.string().max(50).nullable().optional().describe("Parcel locker / pickup point ID, if any"),
});
const billing = z.object(personFields);
const payment = z.object({
  type: z.enum(PAYMENT_TYPES),
  cost: z.number().min(0).max(1e9).describe("Amount, rounded to 2 decimals"),
});
const orderContent = z
  .array(z.object({ itemNumber, quantity: z.number().int().min(1).max(100_000) }))
  .min(1)
  .max(500);

const contents = z
  .array(z.object({ itemNumber, quantity: z.number().int().min(1).max(100_000) }))
  .min(1)
  .max(200);

const productFields = {
  name: z.string().min(1).max(255),
  type: z.string().min(1).max(255).describe("Free-form label, e.g. a product group"),
  weight: z.number().int().min(0).describe("Grams"),
  width: z.number().int().min(0).describe("cm"),
  depth: z.number().int().min(0).describe("cm"),
  height: z.number().int().min(0).describe("cm"),
  price: z.number().int().min(0).describe("Net selling price in HUF"),
  tax: z.number().int().min(0).max(100).describe("Tax rate in percent, e.g. 27"),
  fragile: z.union([z.literal(0), z.literal(1)]),
  critical: z.number().int().min(0).describe("Critical stock level that triggers a notification"),
  barCode: z.array(z.string().min(1).max(64)).max(4).describe("Up to 4 barcodes; can only be added, not modified"),
  hasSerial: bool01.describe("Serial-number tracking in the warehouse"),
  hasExpirationDate: bool01.describe("Expiration-date tracking in the warehouse"),
  defaultNetPurchasePrice: z.number().min(0).describe("Default net purchase price, 2 decimals"),
  bundleDescription: z.string().max(1000).describe("Package products only: instructions for the warehouse"),
  needsPackage: z.boolean().describe("Package products only: needs separate wrapping"),
  contents: contents.describe("Package products only: the components"),
};

const inwardContents = z
  .array(
    z.object({
      itemNumber,
      estimated: z.number().int().min(1).max(10_000_000).describe("Quantity expected to arrive"),
      netPurchasePrice: z.number().min(0).optional().describe("Net purchase price in HUF"),
    }),
  )
  .min(1)
  .max(500);

// ---------- tool plumbing ----------
type Result = { content: { type: "text"; text: string }[]; isError?: boolean };
// every tool output goes through redactPii, so no read path can bypass it
const ok = (data: unknown): Result => ({ content: [{ type: "text", text: toToolText(redactPii(data)) }] });

const PII_NOTE =
  " Customer PII is redacted (GDPR): delivery/billing name, phoneNumber and street address are removed, email is masked; only country, postCode, city, company and aptNumber remain.";
const fail = (msg: string): Result => ({ content: [{ type: "text", text: msg }], isError: true });

interface Ctx {
  server: McpServer;
  client: IlogisticClient;
  env: Env;
  principal: Principal;
}

export function registerTools({ server, client, env, principal }: Ctx): void {
  const writesEnabled = env.WRITES_ENABLED === "true";

  function define<S extends z.ZodRawShape>(
    name: string,
    scope: Scope,
    title: string,
    description: string,
    shape: S,
    run: (args: z.infer<z.ZodObject<S>>) => Promise<unknown>,
  ): void {
    // Least privilege: tools the caller may not use are not even listed.
    if (!principal.scopes.includes(scope)) return;
    if (scope !== "read" && !writesEnabled) return;

    server.registerTool(
      name,
      {
        title,
        description,
        inputSchema: shape,
        annotations: {
          readOnlyHint: scope === "read",
          destructiveHint: scope === "delete",
          idempotentHint: scope === "read" || scope === "delete",
          openWorldHint: true,
        },
      },
      (async (rawArgs: unknown): Promise<Result> => {
        const args = rawArgs as z.infer<z.ZodObject<S>>;
        const started = Date.now();
        let outcome = "ok";
        try {
          if (scope !== "read") {
            const { success } = await env.RL_WRITE.limit({ key: principal.name });
            if (!success) {
              outcome = "rate_limited";
              return fail("Write rate limit exceeded (20/min). Wait a minute and retry.");
            }
          }
          return ok(await run(args));
        } catch (e) {
          if (e instanceof IlogisticError) {
            outcome = `upstream_${e.status}`;
            return fail(`iLogistic API error ${e.status}: ${e.message}`);
          }
          outcome = "error";
          console.error(JSON.stringify({ evt: "tool_exception", tool: name, error: (e as Error).message }));
          return fail("Internal error while calling the iLogistic API.");
        } finally {
          // audit trail: who, what, outcome. Never the arguments (they may hold customer PII).
          console.log(
            JSON.stringify({ evt: "tool_call", key: principal.name, tool: name, scope, outcome, ms: Date.now() - started }),
          );
        }
      }) as never, // args are validated by the SDK against `shape` before this runs
    );
  }

  // ---------- meta ----------
  define(
    "ilogistic_reference",
    "read",
    "iLogistic reference data",
    "Static reference: order/inward states, delivery companies, payment types, product categories and API conventions. Call this to find valid enum values.",
    {},
    async () => REFERENCE,
  );

  define(
    "ilogistic_check_connection",
    "read",
    "Check iLogistic connection",
    "Validates the server's iLogistic token and reports how long it remains valid.",
    {},
    async () => {
      const valid = await client.request("GET", "/authentication/validate");
      return { ...(valid as object), tokenSecondsRemaining: await client.tokenTtl() };
    },
  );

  // ---------- orders ----------
  define(
    "ilogistic_list_orders",
    "read",
    "List orders",
    "List orders with optional filters and limit/offset pagination." + PII_NOTE,
    {
      limit,
      offset,
      state: z.enum(ORDER_STATES).optional(),
      paymentMethod: z.enum(PAYMENT_TYPES).optional(),
      deliveryCompany: z.enum(DELIVERY_COMPANIES).optional(),
      source: z.string().max(100).optional().describe("Order source, e.g. 'Internal API'"),
      changedSince: isoDateTime.optional().describe("Orders whose last state change is after this time"),
      isCompletable: z.boolean().optional().describe("Only orders that have enough stock to be prepared"),
    },
    ({ isCompletable, ...rest }) =>
      client.request("GET", "/orders/orders", {
        // boolean filters are 0/1 in the iLogistic API
        query: { ...rest, isCompletable: isCompletable === undefined ? undefined : isCompletable ? 1 : 0 },
      }),
  );

  define(
    "ilogistic_get_order",
    "read",
    "Get order",
    "Get one order by its iLogistic ID." + PII_NOTE,
    { id },
    (a) => client.request("GET", `/orders/order/${a.id}`),
  );

  define(
    "ilogistic_get_order_status_history",
    "read",
    "Order status history",
    "Chronological list of state changes of an order.",
    { id },
    (a) => client.request("GET", `/orders/order/${a.id}/status-history`),
  );

  define(
    "ilogistic_get_resent_order",
    "read",
    "Get resent order",
    "For a returned order, get the iLogistic ID and status (wait/store/resend) of the order created for its resend.",
    { id },
    (a) => client.request("GET", `/orders/orders/resent-order/${a.id}`),
  );

  define(
    "ilogistic_create_order",
    "write",
    "Create order",
    "Create a new order. Products must already exist and be active. foreignId must be unique (a duplicate returns the existing order id).",
    {
      foreignId: z.string().max(100).nullable().optional().describe("Your own order reference"),
      webShopAlias: z.string().max(100).optional().describe("Alias of the originating webshop"),
      delivery,
      billing,
      payment,
      content: orderContent,
    },
    ({ webShopAlias, ...body }) =>
      client.request("POST", "/orders/orders", {
        body,
        headers: webShopAlias ? { "X-WebShop-Alias": webShopAlias } : undefined,
      }),
  );

  define(
    "ilogistic_update_order",
    "write",
    "Update order",
    "Partially update an order. Send only the fields to change. Not possible once the order reached 'Összekészítés alatt'.",
    {
      id,
      foreignId: z.string().max(100).nullable().optional(),
      delivery: delivery.partial().optional(),
      billing: billing.partial().optional(),
      payment: payment.partial().optional(),
      content: orderContent.optional(),
    },
    ({ id: orderId, ...body }) => client.request("PATCH", `/orders/order/${orderId}`, { body }),
  );

  define(
    "ilogistic_delete_order",
    "delete",
    "Delete order",
    "Permanently delete an order. IRREVERSIBLE. Only possible before the warehouse starts picking. Ask the user to confirm first.",
    { id, confirm },
    (a) => client.request("DELETE", `/orders/order/${a.id}`),
  );

  // ---------- products ----------
  define(
    "ilogistic_list_products",
    "read",
    "List products",
    "List products with stock levels, optional filters and limit/offset pagination.",
    {
      limit,
      offset,
      hasSerial: z.boolean().optional(),
      hasExpirationDate: z.boolean().optional(),
      isVirtual: z.boolean().optional(),
      isPackage: z.boolean().optional(),
      changedSince: isoDateTime.optional().describe("Products whose stock changed after this time"),
    },
    (a) => {
      const q: Record<string, string | number | undefined> = { limit: a.limit, offset: a.offset, changedSince: a.changedSince };
      // the API expects 0/1 for boolean filters
      for (const k of ["hasSerial", "hasExpirationDate", "isVirtual", "isPackage"] as const) {
        if (a[k] !== undefined) q[k] = a[k] ? 1 : 0;
      }
      return client.request("GET", "/products/products", { query: q });
    },
  );

  define(
    "ilogistic_get_product",
    "read",
    "Get product",
    "Get one product by iLogistic ID (the API returns an array whose first element is the product).",
    { id },
    (a) => client.request("GET", `/products/product/${a.id}`),
  );

  define(
    "ilogistic_create_product",
    "write",
    "Create product",
    "Create a product. For category 'csomag' (bundle) also pass contents, needsPackage and bundleDescription; bundles cannot have serial/expiration tracking.",
    {
      itemNumber: z.string().min(1).max(255).describe("Unique SKU; cannot be changed later"),
      category: z.enum(PRODUCT_CATEGORIES).default("termek"),
      name: productFields.name,
      type: productFields.type,
      weight: productFields.weight,
      width: productFields.width,
      depth: productFields.depth,
      height: productFields.height,
      price: productFields.price,
      tax: productFields.tax,
      fragile: productFields.fragile,
      critical: productFields.critical,
      barCode: productFields.barCode.optional(),
      hasSerial: productFields.hasSerial.optional(),
      hasExpirationDate: productFields.hasExpirationDate.optional(),
      defaultNetPurchasePrice: productFields.defaultNetPurchasePrice.optional(),
      bundleDescription: productFields.bundleDescription.optional(),
      needsPackage: productFields.needsPackage.optional(),
      contents: productFields.contents.optional(),
    },
    (body) => client.request("POST", "/products/products", { body }),
  );

  define(
    "ilogistic_update_product",
    "write",
    "Update product",
    "Partially update a product. Send only fields to change. itemNumber and category cannot be changed; barcodes can only be added.",
    {
      id,
      name: productFields.name.optional(),
      type: productFields.type.optional(),
      weight: productFields.weight.optional(),
      width: productFields.width.optional(),
      depth: productFields.depth.optional(),
      height: productFields.height.optional(),
      price: productFields.price.optional(),
      tax: productFields.tax.optional(),
      fragile: productFields.fragile.optional(),
      critical: productFields.critical.optional(),
      barCode: productFields.barCode.optional(),
      hasSerial: productFields.hasSerial.optional(),
      hasExpirationDate: productFields.hasExpirationDate.optional(),
      defaultNetPurchasePrice: productFields.defaultNetPurchasePrice.optional(),
      bundleDescription: productFields.bundleDescription.optional(),
      needsPackage: productFields.needsPackage.optional(),
      contents: productFields.contents.optional(),
    },
    ({ id: productId, ...body }) => client.request("PATCH", `/products/product/${productId}`, { body }),
  );

  // ---------- inward handling ----------
  define(
    "ilogistic_list_inward_handlings",
    "read",
    "List inward handlings",
    "List incoming shipments (bevételezés), newest first.",
    {
      limit,
      offset,
      state: z.enum(INWARD_STATES).optional(),
      hasArrived: z.boolean().optional(),
      arrivedSince: isoDateTime.optional(),
    },
    (a) =>
      client.request("GET", "/inward-handling", {
        query: {
          limit: a.limit,
          offset: a.offset,
          state: a.state,
          arrivedSince: a.arrivedSince,
          hasArrived: a.hasArrived === undefined ? undefined : a.hasArrived ? 1 : 0,
        },
      }),
  );

  define(
    "ilogistic_get_inward_handling",
    "read",
    "Get inward handling",
    "Get one incoming shipment by ID.",
    { id },
    (a) => client.request("GET", `/inward-handling/${a.id}`),
  );

  define(
    "ilogistic_create_inward_handling",
    "write",
    "Create inward handling",
    "Announce an incoming shipment of existing products.",
    {
      name: z.string().min(3).max(50),
      estimatedArrival: isoDateTime.nullable().describe("Expected arrival, or null if unknown"),
      urgent: z.boolean(),
      express: z.boolean().optional(),
      description: z.string().max(255).optional(),
      contents: inwardContents,
    },
    (body) => client.request("POST", "/inward-handling", { body }),
  );

  define(
    "ilogistic_update_inward_handling",
    "write",
    "Update inward handling",
    "Partially update an incoming shipment. Only possible while its status is 'Várható'.",
    {
      id,
      name: z.string().min(3).max(50).optional(),
      estimatedArrival: isoDateTime.nullable().optional(),
      urgent: z.boolean().optional(),
      express: z.boolean().optional(),
      description: z.string().max(255).optional(),
      contents: inwardContents.optional(),
    },
    ({ id: ihId, ...body }) => client.request("PATCH", `/inward-handling/${ihId}`, { body }),
  );

  define(
    "ilogistic_delete_inward_handling",
    "delete",
    "Delete inward handling",
    "Permanently delete an incoming shipment. IRREVERSIBLE. Only while status is 'Várható' and not a returned order. Ask the user to confirm first.",
    { id, confirm },
    (a) => client.request("DELETE", `/inward-handling/${a.id}`),
  );
}
