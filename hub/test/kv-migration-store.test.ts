import { describe, expect, it } from "vitest";
import {
  KVMigrationStore,
  type KVMigrationRow,
  type KVMigrationStorage,
} from "../src/kv-migration-store";

const NOW = 1_700_000_000_000;
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const DIGEST_C = `sha256:${"c".repeat(64)}`;

class MemoryStorage implements KVMigrationStorage {
  private readonly values = new Map<string, unknown>();
  private tail = Promise.resolve();

  async get<T>(key: string): Promise<T | undefined> {
    return this.values.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  transaction<T>(closure: (transaction: KVMigrationStorage) => Promise<T>): Promise<T> {
    const run = this.tail.then(() => closure(this));
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

function rows(): readonly KVMigrationRow[] {
  return [
    { v1_key: "manifest:a", v1_content_digest: DIGEST_A, v2_key: "v2/manifest:a" },
    { v1_key: "manifest:b", v1_content_digest: DIGEST_B, v2_key: "v2/manifest:b" },
  ];
}

async function preparedStore() {
  const store = new KVMigrationStore(new MemoryStorage());
  const result = await store.prepare({ migration_id: "migration-1", fencing_epoch: 1, rows: rows(), now: NOW });
  expect(result.status).toBe("prepared");
  return store;
}

describe("KVMigrationStore", () => {
  it("binds exact v1 rows and resumes a prepared migration after a crash", async () => {
    const storage = new MemoryStorage();
    const first = new KVMigrationStore(storage);
    const prepared = await first.prepare({ migration_id: "migration-1", fencing_epoch: 1, rows: rows(), now: NOW });
    expect(prepared.status).toBe("prepared");

    const resumed = new KVMigrationStore(storage);
    const duplicate = await resumed.prepare({ migration_id: "migration-1", fencing_epoch: 1, rows: rows(), now: NOW + 1 });
    expect(duplicate.status).toBe("existing");

    expect((await resumed.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:a", observed_v2_digest: DIGEST_A })).status).toBe("applied");
    expect((await resumed.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:a", observed_v2_digest: DIGEST_A })).status).toBe("duplicate");
    expect((await resumed.commit({ migration_id: "migration-1", fencing_epoch: 1 })).status).toBe("pending");

    expect((await resumed.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:b", observed_v2_digest: DIGEST_B })).status).toBe("applied");
    expect((await resumed.commit({ migration_id: "migration-1", fencing_epoch: 1 })).status).toBe("committed");
  });

  it("rejects stale KV reads and mismatched row acknowledgements", async () => {
    const store = await preparedStore();
    expect(
      (
        await store.readDecision({
          migration_id: "migration-1",
          fencing_epoch: 1,
          key: "manifest:a",
          source: "v1",
          observed_content_digest: DIGEST_C,
        })
      ).status,
    ).toBe("stale_read_rejected");
    expect(
      (await store.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:a", observed_v2_digest: DIGEST_C })).status,
    ).toBe("digest_mismatch");
    expect(
      (await store.observeFullScan({ migration_id: "migration-1", fencing_epoch: 1, scan_id: "scan-1", observed_at: NOW, v1_rows: [{ v1_key: "manifest:a", v1_content_digest: DIGEST_C }] })).status,
    ).toBe("scan_mismatch");
  });

  it("does not promote a head on partial apply and rejects old epochs after promotion", async () => {
    const storage = new MemoryStorage();
    const store = new KVMigrationStore(storage);
    await store.prepare({ migration_id: "migration-1", fencing_epoch: 1, rows: rows(), now: NOW });
    await store.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:a", observed_v2_digest: DIGEST_A });
    expect((await store.commit({ migration_id: "migration-1", fencing_epoch: 1 })).status).toBe("pending");
    expect((await store.readDecision({ migration_id: "migration-1", fencing_epoch: 1, key: "manifest:a", source: "v1" })).status).toBe("v1_allowed");

    await store.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:b", observed_v2_digest: DIGEST_B });
    expect((await store.commit({ migration_id: "migration-1", fencing_epoch: 1 })).status).toBe("committed");
    await store.prepare({ migration_id: "migration-2", fencing_epoch: 2, rows: [{ v1_key: "manifest:c", v1_content_digest: DIGEST_C, v2_key: "v2/manifest:c" }], now: NOW + 1 });
    await store.acknowledgeApplied({ migration_id: "migration-2", fencing_epoch: 2, v1_key: "manifest:c", observed_v2_digest: DIGEST_C });
    expect((await store.commit({ migration_id: "migration-2", fencing_epoch: 2 })).status).toBe("committed");

    expect((await store.readDecision({ migration_id: "migration-1", fencing_epoch: 1, key: "manifest:a", source: "v1" })).status).toBe("old_epoch_rejected");
    expect((await store.readDecision({ migration_id: "migration-2", fencing_epoch: 2, key: "v2/manifest:c", source: "v2" })).status).toBe("v2_allowed");
  });

  it("resets zero-v1 scan counts when a later scan is nonempty", async () => {
    const store = await preparedStore();
    await store.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:a", observed_v2_digest: DIGEST_A });
    await store.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:b", observed_v2_digest: DIGEST_B });
    expect((await store.commit({ migration_id: "migration-1", fencing_epoch: 1 })).status).toBe("committed");

    const firstScan = await store.observeFullScan({ migration_id: "migration-1", fencing_epoch: 1, scan_id: "scan-1", observed_at: NOW + 1_000, v1_rows: [] });
    expect(firstScan.status).toBe("observed");
    if (firstScan.status === "observed") expect(firstScan.zero_v1_scans).toBe(1);
    const secondScan = await store.observeFullScan({
      migration_id: "migration-1",
      fencing_epoch: 1,
      scan_id: "scan-2",
      observed_at: NOW + 2_000,
      v1_rows: rows().map(({ v1_key, v1_content_digest }) => ({ v1_key, v1_content_digest })),
    });
    expect(secondScan.status).toBe("observed");
    if (secondScan.status === "observed") expect(secondScan.zero_v1_scans).toBe(0);
    const thirdScan = await store.observeFullScan({ migration_id: "migration-1", fencing_epoch: 1, scan_id: "scan-3", observed_at: NOW + 3_000, v1_rows: [] });
    expect(thirdScan.status).toBe("observed");
    if (thirdScan.status === "observed") expect(thirdScan.zero_v1_scans).toBe(1);
  });

  it("requires a caller safety window and consecutive zero-v1 scans before tombstone authorization", async () => {
    const store = await preparedStore();
    await store.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:a", observed_v2_digest: DIGEST_A });
    await store.acknowledgeApplied({ migration_id: "migration-1", fencing_epoch: 1, v1_key: "manifest:b", observed_v2_digest: DIGEST_B });
    await store.commit({ migration_id: "migration-1", fencing_epoch: 1 });

    const safetyWindow = NOW + 10_000;
    expect((await store.authorizeTombstone({ migration_id: "migration-1", fencing_epoch: 1, minimum_safety_window_at: safetyWindow, required_zero_v1_scans: 2, now: NOW })).status).toBe("safety_window");
    await store.observeFullScan({ migration_id: "migration-1", fencing_epoch: 1, scan_id: "scan-1", observed_at: safetyWindow, v1_rows: [] });
    expect((await store.authorizeTombstone({ migration_id: "migration-1", fencing_epoch: 1, minimum_safety_window_at: safetyWindow, required_zero_v1_scans: 2, now: safetyWindow })).status).toBe("zero_scan_gate");
    await store.observeFullScan({ migration_id: "migration-1", fencing_epoch: 1, scan_id: "scan-2", observed_at: safetyWindow + 1, v1_rows: [] });
    expect((await store.authorizeTombstone({ migration_id: "migration-1", fencing_epoch: 1, minimum_safety_window_at: safetyWindow, required_zero_v1_scans: 2, now: safetyWindow + 1 })).status).toBe("authorized");
  });

  it("serializes concurrent duplicate prepare calls and rejects stale epochs", async () => {
    const storage = new MemoryStorage();
    const store = new KVMigrationStore(storage);
    const results = await Promise.all([
      store.prepare({ migration_id: "migration-1", fencing_epoch: 1, rows: rows(), now: NOW }),
      store.prepare({ migration_id: "migration-1", fencing_epoch: 1, rows: rows(), now: NOW }),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual(["existing", "prepared"]);
    expect((await store.prepare({ migration_id: "migration-2", fencing_epoch: 1, rows: rows(), now: NOW })).status).toBe("stale_epoch");
    const pending = await store.prepare({
      migration_id: "migration-3",
      fencing_epoch: 2,
      rows: rows(),
      now: NOW + 1,
    });
    expect(pending.status).toBe("conflict");
  });
});
