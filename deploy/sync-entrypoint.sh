#!/bin/sh
set -eu
# One-shot sync: SSM -> declared targets, then refresh the vault dashboard.
# The provider/target creds and SKRET_HUB_URL / SKRET_HUB_TOKEN are injected as
# env vars by the hub Worker's scheduled() handler. `skret hub push` reads the
# hub URL from SKRET_HUB_URL (falling back to sync.hub.url in .skret.yaml), so
# no flag is needed and an unset var never aborts the run under `set -u`.
skret sync --skip-unchanged
skret hub push
echo "sync-run: complete"
