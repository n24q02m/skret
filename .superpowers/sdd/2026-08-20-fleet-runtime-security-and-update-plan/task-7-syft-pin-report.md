# Task 7 Syft version pin report

## Change

Pinned the Syft binary consumed by the existing `anchore/sbom-action/download-syft` action in `.github/workflows/cd.yml`:

```yaml
with:
  syft-version: v1.51.0
```

The existing action SHA, job ordering, SBOM artifacts, and release semantics were left unchanged. The focused policy test now asserts that the download action block contains `syft-version: v1.51.0`.

## Source/version evidence

- Official Syft release: https://github.com/anchore/syft/releases/tag/v1.51.0
- Action retained: `anchore/sbom-action/download-syft@e22c389904149dbc22b58101806040fa8d37a610` (`v0.24.0` comment)
- Pinned input: `syft-version: v1.51.0`

## TDD evidence

1. **Red before workflow change** — after adding the focused assertion, before changing `cd.yml`:
   - Command: `python -m unittest tests/repo_bootstrap/test_workflow_policy.py`
   - Result: `Ran 4 tests ... FAILED (failures=1)`
   - Failure: expected `syft-version: v1.51.0` was absent from the Syft action block.
2. **Green after workflow change** — after adding only the `syft-version` input:
   - Command: `python -m unittest tests/repo_bootstrap/test_workflow_policy.py`
   - Result: `Ran 4 tests ... OK`

## Commit

Recorded in the task commit: `fix: pin syft binary version`.

## Concerns / residuals

No concerns identified within this bounded slice. No publish, deploy, provider API call, credential/settings mutation, push, formatter, linter, or project-wide suite was run.
