from __future__ import annotations

import copy
import hashlib
import json
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA = REPO_ROOT / "deploy" / "sync-target-manifest.schema.json"
TEMPLATE = REPO_ROOT / "deploy" / "sync" / "candidate.skret.yaml.tmpl"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def target_set_digest(targets: list[dict[str, object]]) -> str:
    encoded = bytearray()
    for target in targets:
        value = str(target["canonical"]).encode("utf-8")
        encoded.extend(len(value).to_bytes(4, "big"))
        encoded.extend(value)
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def render_fixture() -> dict[str, object]:
    source = TEMPLATE.read_text(encoding="utf-8")
    replacements = {
        "{{EXPIRES_AT}}": "2026-08-24T01:00:00Z",
        "{{SOURCE_FINGERPRINT}}": "sha256:" + "1" * 64,
        "{{SOURCE_DIGEST}}": "sha256:" + "2" * 64,
        "{{TARGET_SET_DIGEST}}": "TARGET_SET_DIGEST",
        "{{PRODUCTION_DENIAL_DIGEST}}": "sha256:" + "3" * 64,
    }
    for key, value in replacements.items():
        source = source.replace(key, value)
    parsed = json.loads(source)
    parsed["target_set_digest"] = target_set_digest(parsed["targets"])
    return parsed


def validate_fixture(manifest: dict[str, object]) -> None:
    expected_root = {
        "schema",
        "purpose",
        "generation",
        "owner",
        "expires_at",
        "source",
        "targets",
        "target_set_digest",
        "egress_allowlist",
        "operation_budget",
        "production_denial_digest",
    }
    if set(manifest) != expected_root:
        raise ValueError("invalid target manifest")
    if manifest["schema"] != "skret-target-manifest/v1" or manifest["purpose"] != "SK-CANDIDATE-TARGETS":
        raise ValueError("invalid target manifest")
    if type(manifest["generation"]) is not int or manifest["generation"] < 1:
        raise ValueError("invalid target manifest")
    if manifest["owner"] != "release-security-owner":
        raise ValueError("invalid target manifest")
    if not DIGEST.fullmatch(str(manifest["production_denial_digest"])):
        raise ValueError("invalid target manifest")
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {"identity", "version", "fingerprint", "digest"}:
        raise ValueError("invalid target manifest")
    if source["identity"] != "aws|000000000000|ap-southeast-1|/skret-candidate/fixture|101|candidate-generation-1":
        raise ValueError("invalid target manifest")
    if source["version"] != 101 or not DIGEST.fullmatch(str(source["fingerprint"])) or not DIGEST.fullmatch(str(source["digest"])):
        raise ValueError("invalid target manifest")
    targets = manifest["targets"]
    if not isinstance(targets, list) or not targets or len(targets) > 64:
        raise ValueError("invalid target manifest")
    previous = ""
    seen: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("invalid target manifest")
        common = {"provider", "environment", "secret_name", "capability", "operation", "synthetic", "before_state_oid", "canonical"}
        if target.get("provider") == "github":
            if set(target) != common | {"owner", "repository"}:
                raise ValueError("invalid target manifest")
            if target["owner"] != "skret-candidate-fixture" or target["repository"] != "projection-canary":
                raise ValueError("invalid target manifest")
            canonical = f"github|{target['owner']}/{target['repository']}|{target['environment']}|{target['secret_name']}"
        elif target.get("provider") == "cloudflare":
            if set(target) != common | {"account_id", "resource_kind", "resource_name"}:
                raise ValueError("invalid target manifest")
            if target["account_id"] != "c" * 32 or not str(target["resource_name"]).startswith("skret-candidate-"):
                raise ValueError("invalid target manifest")
            canonical = f"cloudflare|{target['account_id']}|{target['resource_kind']}|{target['resource_name']}|{target['environment']}|{target['secret_name']}"
        else:
            raise ValueError("invalid target manifest")
        if (
            target["canonical"] != canonical
            or target["environment"] != "candidate"
            or target["capability"] != "owner_risk_gate"
            or target["operation"] != "upsert"
            or target["synthetic"] is not True
            or target["before_state_oid"] is not None
            or canonical <= previous
            or canonical in seen
        ):
            raise ValueError("invalid target manifest")
        previous = canonical
        seen.add(canonical)
    if manifest["target_set_digest"] != target_set_digest(targets):
        raise ValueError("invalid target manifest")
    if manifest["egress_allowlist"] != ["api.cloudflare.com", "api.github.com"]:
        raise ValueError("invalid target manifest")
    if manifest["operation_budget"] != len(targets):
        raise ValueError("invalid target manifest")


class ProjectionPolicyTests(unittest.TestCase):
    def test_schema_and_candidate_template_are_closed_and_value_free(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["purpose"]["const"], "SK-CANDIDATE-TARGETS")
        self.assertEqual(schema["properties"]["targets"]["maxItems"], 64)
        source = TEMPLATE.read_text(encoding="utf-8")
        for forbidden in (
            "${{ secrets.",
            "n24q02m/KnowledgePrism",
            "skret-hub",
            "CLOUDFLARE_API_TOKEN",
            "GITHUB_TOKEN",
            "plaintext",
            "password",
        ):
            self.assertNotIn(forbidden, source)
        fixture = render_fixture()
        validate_fixture(fixture)
        self.assertNotIn("value", json.dumps(fixture).lower())

    def test_collision_substitution_and_production_targets_fail_closed(self) -> None:
        fixture = render_fixture()
        duplicate = copy.deepcopy(fixture)
        duplicate["targets"] = [duplicate["targets"][0], copy.deepcopy(duplicate["targets"][0])]
        duplicate["operation_budget"] = 2
        duplicate["target_set_digest"] = target_set_digest(duplicate["targets"])
        with self.assertRaises(ValueError):
            validate_fixture(duplicate)

        substituted = copy.deepcopy(fixture)
        substituted["targets"][0]["repository"] = "production-repo"
        with self.assertRaises(ValueError):
            validate_fixture(substituted)

        digest_drift = copy.deepcopy(fixture)
        digest_drift["target_set_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            validate_fixture(digest_drift)

    def test_prepare_workflow_has_zero_projection_authority(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "cd.yml").read_text(encoding="utf-8")
        for forbidden in (
            "sync-secrets:",
            "aws-actions/configure-aws-credentials",
            "wrangler secret",
            "skret sync --to=github",
            "CLOUDFLARE_API_TOKEN",
            "HUB_CF_DEPLOY_TOKEN",
        ):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
