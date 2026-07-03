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
