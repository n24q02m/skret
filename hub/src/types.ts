import type { SyncContainer } from "./container";

export interface Env {
  VAULT_KV: KVNamespace;
  SKRET_HUB_TOKEN: string;
  RELAY_PASSWORD: string;
  // B2 cron sync worker: the SyncContainer Durable Object namespace plus the
  // secrets forwarded into the container process (see index.ts SYNC_ENV_KEYS).
  // The sync creds are optional because the dashboard/ingest request paths
  // never read them — only scheduled() does, when it boots the container.
  SYNC: DurableObjectNamespace<SyncContainer>;
  GITHUB_TOKEN?: string;
  CLOUDFLARE_API_TOKEN?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  AWS_REGION?: string;
  SKRET_HUB_URL?: string;
}

export interface Manifest {
  namespace: string;
  env: string;
  generated_at: string;
  keys: ManifestKey[];
}

export interface ManifestKey {
  name: string;
  fingerprint: string;
  updated_at: string;
  targets: Record<string, ManifestTarget>;
}

export interface ManifestTarget {
  present: boolean;
  status: "in-sync" | "drift" | "missing";
}
