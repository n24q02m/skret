import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          // Deterministic test secrets — never the real values.
          bindings: {
            SKRET_HUB_TOKEN: "test-hub-token",
            RELAY_PASSWORD: "test-relay-password",
          },
        },
      },
    },
  },
});
