// AES-256-GCM for iLogistic tokens at rest in KV. The key is the TOKEN_ENC_KEY secret (base64, 32 bytes).

const b64 = {
  enc: (b: Uint8Array) => btoa(String.fromCharCode(...b)),
  dec: (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

async function importKey(secret: string): Promise<CryptoKey> {
  const raw = b64.dec(secret);
  if (raw.byteLength !== 32) throw new Error("TOKEN_ENC_KEY must be 32 bytes, base64 encoded");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Returns `iv.ciphertext` (both base64). `aad` binds the ciphertext to its KV key so records cannot be swapped. */
export async function encrypt(secret: string, plaintext: string, aad: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
    await importKey(secret),
    new TextEncoder().encode(plaintext),
  );
  return `${b64.enc(iv)}.${b64.enc(new Uint8Array(ct))}`;
}

/** Null when the value is malformed, tampered with, or was encrypted with another key. */
export async function decrypt(secret: string, value: string, aad: string): Promise<string | null> {
  try {
    const [iv, ct] = value.split(".");
    if (!iv || !ct) return null;
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64.dec(iv), additionalData: new TextEncoder().encode(aad) },
      await importKey(secret),
      b64.dec(ct),
    );
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}
