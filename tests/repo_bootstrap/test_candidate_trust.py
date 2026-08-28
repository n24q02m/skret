from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "candidate_trust.py"


def load_module():
    spec = importlib.util.spec_from_file_location("candidate_trust", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load candidate trust module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trust = load_module()


class CandidateTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key, self.public_key = trust.generate_keypair(b"candidate-fixture-seed-00000000001"[:32])
        self.now = "2026-08-24T00:00:00Z"

    def artifact_rows(self) -> list[dict[str, str]]:
        return [
            {
                "name": "skret-cli",
                "digest": "sha256:" + "1" * 64,
                "sbom_digest": "sha256:" + "2" * 64,
                "provenance_digest": "sha256:" + "3" * 64,
            },
            {
                "name": "skret-sync",
                "digest": "sha256:" + "4" * 64,
                "sbom_digest": "sha256:" + "5" * 64,
                "provenance_digest": "sha256:" + "6" * 64,
            },
        ]

    def surface_rows(self) -> list[dict[str, str]]:
        return [
            {"surface": "arm64", "result_digest": "sha256:" + "a" * 64, "status": "passed"},
            {"surface": "cloudflare", "result_digest": "sha256:" + "b" * 64, "status": "passed"},
            {"surface": "github", "result_digest": "sha256:" + "c" * 64, "status": "passed"},
            {"surface": "windows", "result_digest": "sha256:" + "d" * 64, "status": "passed"},
        ]

    def payload(self, *, purpose: str = "SK-CANDIDATE-PASS", generation: int = 1, previous: str | None = None) -> dict[str, object]:
        return {
            "schema": "skret-candidate-trust/v1",
            "purpose": purpose,
            "generation": generation,
            "previous_result_hash": previous,
            "source_sha": "a" * 40,
            "source_manifest_digest": "sha256:" + "9" * 64,
            "workflow_sha": "sha256:" + "e" * 64,
            "action_sha": "sha256:" + "f" * 64,
            "publisher_identity": "release-publisher-1",
            "artifacts": self.artifact_rows(),
            "stable_pointer_before": [{"surface": "github", "name": "stable", "digest": "sha256:" + "7" * 64}],
            "stable_pointer_after": [{"surface": "github", "name": "stable", "digest": "sha256:" + "7" * 64}],
            "surfaces": self.surface_rows(),
            "teardown": {
                "resources": [{"name": "candidate-worker", "remaining": 0}],
                "identities": [{"name": "candidate-publisher", "remaining": 0}],
                "schedules": [{"name": "candidate-cron", "remaining": 0}],
                "cost_zero": True,
            },
            "owner": "release-security-owner",
            "issued_at": self.now,
            "expires_at": "2026-08-24T01:00:00Z",
        }

    def sign(self, payload: dict[str, object] | None = None) -> dict[str, object]:
        return trust.create_result(payload or self.payload(), self.private_key)

    def test_rfc8032_vector_and_small_order_rejection(self) -> None:
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        public = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertEqual(trust.public_key_from_private(seed), public)
        self.assertEqual(trust.sign_bytes(b"", seed), signature)
        self.assertTrue(trust.verify_bytes(b"", signature, public))

        identity = b"\x01" + b"\x00" * 31
        forged = identity + b"\x00" * 32
        self.assertFalse(trust.verify_bytes(b"forged", forged, identity))

    def test_create_verify_binds_identities_artifacts_and_teardown(self) -> None:
        signed = self.sign()
        verified = trust.verify_result(signed, self.public_key, now=self.now)
        self.assertEqual(verified["purpose"], "SK-CANDIDATE-PASS")
        self.assertEqual(verified["source_sha"], "a" * 40)
        self.assertEqual(verified["source_manifest_digest"], "sha256:" + "9" * 64)
        self.assertEqual(verified["workflow_sha"], "sha256:" + "e" * 64)
        self.assertEqual(verified["action_sha"], "sha256:" + "f" * 64)
        self.assertEqual(verified["publisher_identity"], "release-publisher-1")
        self.assertEqual(verified["teardown"]["cost_zero"], True)
        self.assertIn("result_hash", verified)
        self.assertNotIn("private_key", json.dumps(verified))

    def test_signature_tamper_expiry_and_wrong_purpose_or_key_fail(self) -> None:
        signed = self.sign()
        tampered = dict(signed)
        tampered["owner"] = "other-owner"
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(tampered, self.public_key, now=self.now)
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(signed, b"z" * 32, now=self.now)
        expired = dict(signed)
        expired["expires_at"] = "2026-08-23T23:59:59Z"
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(expired, self.public_key, now=self.now)
        wrong_purpose = self.payload(purpose="SK-CANDIDATE-PUBLISHED")
        wrong_signed = self.sign(wrong_purpose)
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(wrong_signed, self.public_key, purpose="SK-CANDIDATE-EXECUTOR-READY", now=self.now)

    def test_replay_and_downgrade_are_rejected_against_prior(self) -> None:
        first = self.sign(self.payload(generation=1))
        prior_hash = trust.result_hash(first)
        second = self.sign(self.payload(generation=2, previous=prior_hash))
        trust.verify_result(second, self.public_key, prior=first, now=self.now)
        trust.verify_result(
            second,
            self.public_key,
            trusted_generation=1,
            trusted_result_hash=prior_hash,
            now=self.now,
        )
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(
                second,
                self.public_key,
                trusted_generation=1,
                now=self.now,
            )
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(first, self.public_key, prior=second, now=self.now)
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(second, self.public_key, prior=first, trusted_generation=2, now=self.now)
        bad_previous = self.sign(self.payload(generation=2, previous="sha256:" + "0" * 64))
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(bad_previous, self.public_key, prior=first, now=self.now)

    def test_pass_rejects_pointer_drift_missing_surface_and_nonzero_teardown(self) -> None:
        drifted = self.payload()
        drifted["stable_pointer_after"] = [{"surface": "github", "name": "stable", "digest": "sha256:" + "8" * 64}]
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(self.sign(drifted), self.public_key, now=self.now)
        missing = self.payload()
        missing["surfaces"] = self.surface_rows()[:-1]
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(self.sign(missing), self.public_key, now=self.now)
        nonzero = self.payload()
        nonzero["teardown"]["resources"][0]["remaining"] = 1
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(self.sign(nonzero), self.public_key, now=self.now)
        absent = self.payload()
        absent["teardown"] = None
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(self.sign(absent), self.public_key, now=self.now)
    def test_source_manifest_binding_is_required(self) -> None:
        missing = self.payload()
        missing.pop("source_manifest_digest")
        with self.assertRaises(trust.CandidateTrustError):
            self.sign(missing)


    def test_duplicate_unsorted_and_sensitive_fields_are_rejected(self) -> None:
        unsorted = self.payload()
        unsorted["surfaces"] = list(reversed(self.surface_rows()))
        with self.assertRaises(trust.CandidateTrustError):
            self.sign(unsorted)
        signed = self.sign()
        encoded = trust.canonical_json_bytes(signed)
        duplicate = encoded[:-1] + b',"owner":"duplicate"}'
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(duplicate, self.public_key, now=self.now)
        noncanonical = json.dumps(signed, ensure_ascii=False, indent=2).encode("utf-8")
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(noncanonical, self.public_key, now=self.now)
        sensitive = self.payload()
        sensitive["raw_token"] = "must-never-be-accepted"
        with self.assertRaises(trust.CandidateTrustError):
            self.sign(sensitive)

    def test_foreign_output_lock_is_never_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "candidate.json"
            lock = Path(str(output) + ".lock")
            lock.write_bytes(b"foreign-owner")
            with self.assertRaises(trust.CandidateTrustError):
                trust._atomic_write(output, b"candidate")
            self.assertEqual(lock.read_bytes(), b"foreign-owner")
            self.assertFalse(output.exists())

    def test_published_and_executor_ready_are_distinct_purposes(self) -> None:
        for purpose in ("SK-CANDIDATE-PUBLISHED", "SK-CANDIDATE-EXECUTOR-READY"):
            signed = self.sign(self.payload(purpose=purpose))
            verified = trust.verify_result(signed, self.public_key, purpose=purpose, now=self.now)
            self.assertEqual(verified["purpose"], purpose)
        required_surfaces = {
            "SK-CANDIDATE-PUBLISHED": "github",
            "SK-CANDIDATE-EXECUTOR-READY": "cloudflare",
        }
        for purpose, required_surface in required_surfaces.items():
            incomplete = self.payload(purpose=purpose)
            incomplete["surfaces"] = [
                row for row in self.surface_rows() if row["surface"] != required_surface
            ]
            with self.assertRaises(trust.CandidateTrustError):
                trust.verify_result(self.sign(incomplete), self.public_key, purpose=purpose, now=self.now)

        drifted = self.payload(purpose="SK-CANDIDATE-PUBLISHED")
        drifted["stable_pointer_after"] = [
            {"surface": "github", "name": "stable", "digest": "sha256:" + "8" * 64}
        ]
        with self.assertRaises(trust.CandidateTrustError):
            trust.verify_result(
                self.sign(drifted),
                self.public_key,
                purpose="SK-CANDIDATE-PUBLISHED",
                now=self.now,
            )


if __name__ == "__main__":
    unittest.main()
