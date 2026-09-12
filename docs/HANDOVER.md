# HANDOVER

## Status: maintenance mode — planned archival

This project is in maintenance mode and is planned for archival once consumers have migrated to maintained, official alternatives. **No new features will be added. Dependency updates are frozen.** Only a critical security fix would trigger a further release before archival.

**Guidance: prefer official, first-party tools over configuring this project.** For secret management and vault workflows, use [HashiCorp Vault](https://developer.hashicorp.com/vault) or the [OpenBao](https://openbao.org/) CLI/API directly. For object-storage and drive synchronization, use [rclone](https://rclone.org/). Wrapping day-to-day workflows in this repository's own configuration is no longer the recommended path.

## Current release

The latest release is published on the [GitHub Releases page](https://github.com/n24q02m/skret/releases). If a package-manager manifest still points at an older version, install directly from GitHub Releases instead.

## What remains operational until archival

- The scheduled sync pipeline continues to run on its daily schedule (03:00 UTC).
- The dashboard/manifest surface stays available.
- Client executor credentials rotate on a weekly cycle by design; operators on record have the rotation runbook.

## Migration notes

1. Inventory any scheduled jobs or scripts that invoke this tool.
2. Replace each job with the equivalent direct CLI/API call of the successor tool (OpenBao for vault/secret reads; rclone for storage sync).
3. Verify with a dry run first, then one live cycle, comparing counts and checksums before removing the old job.
4. Keep the last installed version until every replacement job has completed at least one verified cycle.

## After archival

The repository will become read-only. Existing releases remain downloadable, but no further builds, releases, or support responses should be expected.
