# Task 7 workflow policy report

## Status

Implemented the source-only workflow policy slice. The direct-mutating `sync-secrets` job and its job-only documentation were removed from `.github/workflows/cd.yml`.

The release job still contains `actions/create-github-app-token`, and the `docs` and `deploy-hub` jobs remain present. The release-used `CI_APP_KEY` documentation was retained with release-specific wording. The `SYNC_SECRETS_ENABLED` and job-only `AWS_ROLE_ARN` documentation were removed.

## TDD evidence

1. Added `tests/repo_bootstrap/test_workflow_policy.py` before changing the workflow.
2. Red run (expected failure against the original workflow):

   ```text
   python -m unittest tests/repo_bootstrap/test_workflow_policy.py
   F
   FAIL: test_cd_removes_direct_sync_job_and_preserves_deploy_jobs (...)
   AssertionError: 'sync-secrets:' unexpectedly found in ...
   Ran 1 test in 0.002s
   FAILED (failures=1)
   ```

3. Removed the sync job and job-only references.
4. Green run:

   ```text
   python -m unittest tests/repo_bootstrap/test_workflow_policy.py
   .
   ----------------------------------------------------------------------
   Ran 1 test in 0.001s

   OK
   ```

## Commits

- `f2ec9c7 fix: remove direct sync secrets workflow job`

## Concerns

No focused-test concerns. Per the brief, no formatter, linter, project-wide test suite, external mutation, deployment, or provider API operation was run.
