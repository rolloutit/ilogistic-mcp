// Customer PII must not reach the LLM provider (GDPR): order delivery/billing blocks are reduced to an allowlist.
const PERSON_BLOCKS = new Set(["delivery", "billing"]);
/** Everything else (name, phoneNumber, address, unknown future fields) is dropped. */
const KEEP = new Set(["country", "postCode", "city", "company", "aptNumber"]);

/** "bela.kovacs8@gmail.com" -> "b*****8@gmail.com"; fixed star count so the length does not leak. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  if (at < 1) return "*****";
  const local = email.slice(0, at);
  return `${local[0]}*****${local.length > 1 ? local[local.length - 1] : ""}${email.slice(at)}`;
}

function redactPerson(person: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(person)) {
    if (k === "email") out.email = typeof v === "string" ? maskEmail(v) : null;
    else if (KEEP.has(k)) out[k] = v;
  }
  return out;
}

/** Recursively redacts every delivery/billing object, whatever the surrounding shape (object, array, wrapper). */
export function redactPii(data: unknown): unknown {
  if (Array.isArray(data)) return data.map(redactPii);
  if (!data || typeof data !== "object") return data;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    const isPerson = PERSON_BLOCKS.has(k) && v !== null && typeof v === "object" && !Array.isArray(v);
    out[k] = isPerson ? redactPerson(v as Record<string, unknown>) : redactPii(v);
  }
  return out;
}
