import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // Deterministic test secrets — never the real values.
        bindings: {
          SKRET_HUB_TOKEN: "test-hub-token",
          RELAY_PASSWORD: "test-relay-password",
        },
        // The committed service binding points at a separate Worker. Keep
        // local tests hermetic by replacing that remote target with a
        // fail-closed source-only stub.
        serviceBindings: {
          EXECUTOR: () => new Response(null, { status: 503 }),
        },
      },
    }),
  ],
});
