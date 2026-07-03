export interface Env {
  VAULT_KV: KVNamespace;
  SKRET_HUB_TOKEN: string;
  RELAY_PASSWORD: string;
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
