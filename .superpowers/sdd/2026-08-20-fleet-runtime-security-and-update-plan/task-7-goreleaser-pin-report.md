# Task 7 GoReleaser version pin report

## Status

Implemented the bounded GoReleaser binary-version pin in `.github/workflows/cd.yml`. The existing `goreleaser/goreleaser-action` SHA (`f06c13b6b1a9625abc9e6e439d9c05a8f2190e94`, action v7.2.3), publish arguments, environment, and release/publish semantics were unchanged. Only the action's `version` field changed from `latest` to `v2.17.1`.

## Source and version evidence

- Official source: https://github.com/goreleaser/goreleaser/releases/tag/v2.17.1
- Official release page identifies the immutable release tag as `v2.17.1` and marks it as the latest release at verification time.
- Workflow pin: `.github/workflows/cd.yml:156` → `version: v2.17.1`.

## TDD evidence

1. Extended `tests/repo_bootstrap/test_workflow_policy.py` with an assertion that the GoReleaser action block contains `version: v2.17.1` and does not contain `version: latest`.
2. Red run against the original `version: latest` workflow:

   ```text
   python -m unittest tests/repo_bootstrap/test_workflow_policy.py
   .F.
   FAIL: test_goreleaser_uses_pinned_binary_version (...)
   AssertionError: 'version: v2.17.1' not found in ... version: latest ...
   Ran 3 tests in 0.092s
   FAILED (failures=1)
   ```

3. Changed only the GoReleaser version field to `v2.17.1`.
4. Green focused run:

   ```text
   python -m unittest tests/repo_bootstrap/test_workflow_policy.py
   ...
   ----------------------------------------------------------------------
   Ran 3 tests in 0.117s

   OK
   ```

The focused suite retained and passed the existing docs-build, deploy-hub, sync-secrets removal, and OpenCode removal policy assertions.

## Commit

- `12aa99e fix: pin goreleaser binary version`

## Concerns and scope boundaries

No publish/deploy/provider API call, credential/settings mutation, push, formatter, linter, or project-wide test suite was run. The focused test verifies the workflow-policy contract; it does not execute a real release.
