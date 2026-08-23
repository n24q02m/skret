import {
  ExecutorEnvelopeInvalidError,
  ExecutorEnvelopeReplayRejectedError,
  ExecutorEnvelopeReplayUnavailableError,
  type ExecutorEnvelope,
  verifyAndConsumeExecutorEnvelope,
} from "./executor-envelope-verifier";
import type { DurableExecutorReplayStore } from "./executor-replay-store";

export const PRIVATE_EXECUTOR_PATH = "/operator/executor-envelope";
export const PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER = "X-Skret-Caller-Context";
export const MAX_PRIVATE_EXECUTOR_BYTES = 1 << 20;

const CALLER_CONTEXT_PATTERN = /^sha256:[a-f0-9]{64}$/u;

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; base-uri 'none'",
};

type ReplayStore = Pick<DurableExecutorReplayStore, "consume">;
type OperationResult = Uint8Array | ArrayBuffer | ArrayBufferView;

export interface PrivateExecutorHandlerOptions {
  readonly expectedAudience: string;
  readonly expectedRole: string;
  readonly publicKey: Uint8Array;
  readonly replayStore: ReplayStore;
  readonly execute: (
    body: Uint8Array,
    envelope: ExecutorEnvelope,
  ) => OperationResult | Promise<OperationResult>;
  readonly now?: number;
}

export type PrivateExecutorReplayStore = ReplayStore;

/**
 * Source-only private executor binding boundary. Ordinary Hub routes do not
 * import this module; deployment/wiring stays explicit outside this slice.
 */
export async function handlePrivateExecutorEnvelope(
  req: Request,
  options: PrivateExecutorHandlerOptions,
): Promise<Response> {
  if (req.method !== "POST") {
    return emptyResponse(405, { Allow: "POST" });
  }
  if (!hasPrivateExecutorPath(req)) {
    return emptyResponse(404);
  }
  if (!hasValidDependencies(options)) {
    return emptyResponse(503);
  }

  const callerContext = req.headers.get(PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER);
  if (!callerContext || !CALLER_CONTEXT_PATTERN.test(callerContext)) {
    return emptyResponse(400);
  }

  let body: Uint8Array;
  try {
    const bounded = await readBoundedBody(req);
    if (bounded === null) return emptyResponse(413);
    body = bounded;
  } catch {
    return emptyResponse(400);
  }

  let parsed: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
    parsed = JSON.parse(text);
  } catch {
    return emptyResponse(400);
  }

  if (!isEnvelopeRecord(parsed)) {
    return emptyResponse(400);
  }
  if (typeof parsed.audience !== "string" || typeof parsed.role !== "string") {
    return emptyResponse(400);
  }
  if (parsed.audience !== options.expectedAudience || parsed.role !== options.expectedRole) {
    return emptyResponse(403);
  }

  let verifiedBody: Uint8Array;
  try {
    verifiedBody = await verifyAndConsumeExecutorEnvelope(
      parsed,
      options.publicKey,
      options.replayStore,
      options.now,
    );
  } catch (error) {
    return verifierFailureResponse(error);
  }

  let operationResult: OperationResult;
  try {
    operationResult = await options.execute(verifiedBody, parsed as unknown as ExecutorEnvelope);
  } catch {
    return emptyResponse(502);
  }

  let result: Uint8Array | null;
  try {
    result = copyBoundedResult(operationResult);
  } catch {
    result = null;
  }
  if (result === null) {
    return emptyResponse(502);
  }

  const headers = new Headers(SECURITY_HEADERS);
  headers.set("Content-Type", "application/octet-stream");
  return new Response(result as BodyInit, { status: 200, headers });
}

function hasValidDependencies(options: PrivateExecutorHandlerOptions | undefined): options is PrivateExecutorHandlerOptions {
  return Boolean(
    options &&
      typeof options === "object" &&
      typeof options.expectedAudience === "string" &&
      options.expectedAudience.length > 0 &&
      typeof options.expectedRole === "string" &&
      options.expectedRole.length > 0 &&
      options.publicKey instanceof Uint8Array &&
      options.publicKey.byteLength === 32 &&
      options.replayStore &&
      typeof options.replayStore.consume === "function" &&
      typeof options.execute === "function",
  );
}

function hasPrivateExecutorPath(req: Request): boolean {
  try {
    return new URL(req.url).pathname === PRIVATE_EXECUTOR_PATH;
  } catch {
    return false;
  }
}

function isEnvelopeRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readBoundedBody(req: Request): Promise<Uint8Array | null> {
  const declaredLength = req.headers.get("Content-Length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0) throw new Error("invalid content length");
    if (length > MAX_PRIVATE_EXECUTOR_BYTES) return null;
  }

  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      if (value.byteLength > MAX_PRIVATE_EXECUTOR_BYTES - size) {
        try {
          await reader.cancel();
        } catch {
          // Oversized input remains rejected even if cancellation fails.
        }
        return null;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // Preserve the generic bad-request response for the original failure.
    }
    throw error;
  }

  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function copyBoundedResult(value: OperationResult): Uint8Array | null {
  if (value instanceof Uint8Array) {
    if (value.byteLength > MAX_PRIVATE_EXECUTOR_BYTES) return null;
    return value.slice();
  }
  if (value instanceof ArrayBuffer) {
    if (value.byteLength > MAX_PRIVATE_EXECUTOR_BYTES) return null;
    return new Uint8Array(value.slice(0));
  }
  if (ArrayBuffer.isView(value)) {
    if (value.byteLength > MAX_PRIVATE_EXECUTOR_BYTES) return null;
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  }
  return null;
}

function verifierFailureResponse(error: unknown): Response {
  if (error instanceof ExecutorEnvelopeReplayRejectedError) return emptyResponse(409);
  if (error instanceof ExecutorEnvelopeReplayUnavailableError) return emptyResponse(503);
  if (error instanceof ExecutorEnvelopeInvalidError) return emptyResponse(400);
  return emptyResponse(503);
}

function emptyResponse(status: number, extraHeaders?: Record<string, string>): Response {
  const headers = new Headers(SECURITY_HEADERS);
  for (const [name, value] of Object.entries(extraHeaders ?? {})) headers.set(name, value);
  return new Response(null, { status, headers });
}
