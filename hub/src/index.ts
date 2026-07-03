import type { Env } from "./types";
import { handleRequest } from "./router";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch {
      // Durable boundary: never leak a stack/exception to the client.
      return new Response("internal error", { status: 500 });
    }
  },
};
