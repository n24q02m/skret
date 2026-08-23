#!/bin/sh
set -eu
# One-shot sync: for each committed config, push SSM -> its declared targets,
# then refresh that namespace's card on the vault dashboard. Creds and
# SKRET_HUB_URL / SKRET_HUB_TOKEN are injected by the hub Worker's
# scheduled() handler. Missing Hub configuration fails before any provider
# sync so a direct container invocation cannot write and then fail at push.
case "${SKRET_HUB_TOKEN:-}" in
    *[![:space:]]*) ;;
    *) echo "sync-run: missing required SKRET_HUB_TOKEN" >&2; exit 78 ;;
esac
case "${SKRET_HUB_URL:-}" in
    *[![:space:]]*) ;;
    *) echo "sync-run: missing required SKRET_HUB_URL" >&2; exit 78 ;;
esac

set -- /app/configs/*.skret.yaml
if [ ! -f "$1" ]; then
    echo "sync-run: no sync config found" >&2
    exit 78
fi
for f do
    echo "sync-run: ${f}"
    skret sync --config "${f}" --skip-unchanged
    skret hub push --config "${f}"
done
echo "sync-run: complete"
