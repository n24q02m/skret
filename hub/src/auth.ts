// Constant-time string compare. Length is compared first (a token-length
// oracle is not meaningfully exploitable for fixed-length secrets), then
// bytes via the runtime's timing-safe primitive.
export function timingSafeEqualStr(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.byteLength !== bb.byteLength) return false;
  return crypto.subtle.timingSafeEqual(ab, bb);
}

export function checkBearer(req: Request, token: string): boolean {
  const header = req.headers.get("Authorization") ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) return false;
  return timingSafeEqualStr(header.slice(prefix.length), token);
}

export const SESSION_TTL = 43200; // 12 hours in seconds

export function checkPassword(password: string, expected: string): boolean {
  return timingSafeEqualStr(password, expected);
}

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = norm.length % 4 ? 4 - (norm.length % 4) : 0;
  const bin = atob(norm + "=".repeat(pad));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function sign(secret: string, payloadB64: string): Promise<Uint8Array> {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  return new Uint8Array(sig);
}

export async function mintSession(secret: string, ttlSeconds: number): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payloadB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify({ exp })));
  const sigB64 = b64urlEncode(await sign(secret, payloadB64));
  return `${payloadB64}.${sigB64}`;
}

export async function verifySession(secret: string, cookie: string): Promise<boolean> {
  const dot = cookie.indexOf(".");
  if (dot < 0) return false;
  const payloadB64 = cookie.slice(0, dot);
  const sigB64 = cookie.slice(dot + 1);
  let got: Uint8Array;
  try {
    got = b64urlDecode(sigB64);
  } catch {
    return false;
  }
  const expected = await sign(secret, payloadB64);
  if (got.byteLength !== expected.byteLength) return false;
  if (!crypto.subtle.timingSafeEqual(got, expected)) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64))) as { exp?: unknown };
    return typeof payload.exp === "number" && payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}
