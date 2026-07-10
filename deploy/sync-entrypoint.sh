#!/bin/sh
set -eu
# One-shot sync: for each baked config, push SSM -> its declared targets,
# then refresh that namespace's card on the vault dashboard. Creds and
# SKRET_HUB_URL / SKRET_HUB_TOKEN are injected by the hub Worker's
# scheduled() handler. A failing config aborts the run (set -e) so the
# container exits non-zero and the failure is visible in observability.
for f in /app/configs/*.skret.yaml; do
    echo "sync-run: ${f}"
    skret sync --config "${f}" --skip-unchanged
    skret hub push --config "${f}"
done
echo "sync-run: complete"
