# ProNet custom accounting — test release

## v3.10.2-pronet.15

- Web updates allow up to two minutes for graceful panel shutdown/re-exec, rather than rolling a busy master back after 30 seconds. Per-update logs are retained with the database backup.
- Docker web updates persist a checksummed runtime in the existing database volume. The custom Docker entrypoint restores a newer verified runtime after container recreation; newer image versions are never downgraded to an older saved runtime.
- Docker bootstrap files are included in custom release packages. Existing images need the new bootstrap once; recreating an old image without that bootstrap cannot preserve an in-container application update. A read-only application root must be updated by recreating its image; web updates refuse before changing binaries.

## v3.10.2-pronet.12

- Subscription traffic cards hide entries charged less than 10 MiB in the selected range. All byte counters and accounting APIs retain those entries unchanged.
- Persist the last inbound remark across edits, deletion, and node synchronization; resolve dated rows from the retained lifetime label. Upgrade backfills labels for existing inbounds without changing counters.
- Existing entries whose inbound was deleted before any label was stored require recovery from a backup; the page no longer exposes raw transport tags as a substitute name.

## v3.10.2-pronet.11

- Reset network counters no longer wrap into enormous transfer rates or block node heartbeat updates. Masters also discard invalid rates reported by older nodes while retaining node version, latency and health.
- Includes the installer, management menu, custom Docker core and verified-update improvements below.

## v3.10.2-pronet.10

- Installation and web updates use the newest complete published release from this repository, including custom prereleases. Drafts and incomplete packages are ignored.
- Web updates verify that the running executable actually changed before reporting success, and restore the previous binaries on failure.
- Installation validates the package version before stopping the service, preserves existing service configuration, and restarts the previous program if replacement fails. Concurrent installs and updates are blocked.
- The management menu no longer installs the pinned pronet.7 package. Docker source builds include the pinned custom core as well as the custom panel.
- Includes dated raw/billed traffic reports, inbound remark labels, coefficient accounting, and node-host synchronization from previous releases.

## v3.10.2-pronet.9

- Fix the embedded panel version so installed panels report the matching custom release and stop offering the same update repeatedly.
- Includes the node-host synchronization and node-name-free subscription remarks from v3.10.2-pronet.8.

- Node host overrides are synchronized on every successful traffic snapshot, so changes to an already-adopted inbound update the ProNet subscription links. A successful empty host list clears stale overrides; a failed host fetch keeps the last known configuration.
- No host rows are rewritten when their settings are unchanged.

Based on Sanaei 3x-ui v3.10.2 and its pinned Xray revision. Both master and execution nodes must use this package for detailed accounting. This is a custom distribution, not an official Sanaei release.

- One shared client identity, with independent raw upload/download counters per inbound and user.
- Inbound coefficients affect the shared client quota inside Sanaei. Raw counters remain independent.
- Lifetime reports retain separate rows for each coefficient used. Resetting a quota does not erase reporting history.
- The subscription page shows raw usage, coefficient, and billed usage; the client's name is the heading, followed by the subscription identifier. The configured subscription title appears above the announcement. Traffic history can be filtered by date from the upgrade onward; older lifetime totals remain under “All time”. Node history is timed when the master receives its periodic traffic snapshot.
- Inbound usage cards display the panel's inbound remark, falling back to the Xray tag only when the inbound has no remark.
- Authenticated capability discovery includes a check of the running custom core. ProNet edits use a narrow compare-and-set API.
- The panel checks this fork's complete, checksum-verified releases and can update its panel, bundled Xray core, and management menu together. Updates create a database and binary backup first. The official Sanaei release feed is not used for custom update checks.

## Installation

Use a clean test node first. Linux with systemd, amd64 or arm64; requires curl, tar, sha256sum and openssl. The installer verifies release checksums and retains existing configuration and program backups under `/var/backups/pronet`.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MaMMaD1999/pronet-3x-ui/main/pronet-install.sh)
```

The command resolves the latest complete published package each time it runs. Linux requires Python 3 and flock in addition to curl, tar, sha256sum and openssl. On a fresh install, random login credentials and the panel path are printed. Configure HTTPS and firewall access before using the panel remotely. Existing credentials and settings are preserved.

Existing PostgreSQL installations also require Python 3 and `pg_dump`; the database and service environment are backed up before the service is stopped. If backup fails, installation stops before replacing files. Backups are retained for manual rollback.

Non-unit coefficients are supported for VLESS, VMess, Trojan and Shadowsocks. Changing a coefficient applies it to the next traffic collection interval; historical rows are not recalculated. Like upstream, quota enforcement is periodic and can have a small polling overshoot. This initial release does not change that behavior.

Old usage before custom accounting was enabled cannot be reconstructed into per-inbound detail. ProNet establishes a cutover baseline to avoid charging old cumulative usage again. Existing usage remains recorded separately.

## Maintenance

Running `x-ui` without arguments opens the full upstream management menu, adapted for ProNet releases. SSL, firewall, service, database and credential-management tools are retained. Official/dev upgrades are blocked; custom package updates and menu updates use this fork. The installer prints a complete login URL and fresh-install credentials after the service starts. Existing passwords are retained and cannot be recovered from their hashes; option 7 resets them when needed.

`x-ui start`, `x-ui stop`, `x-ui restart`, `x-ui status`, `x-ui log`, and `x-ui setting ...` are available. Use the versioned installer for updates. Do not replace only the core or downgrade a live database; restore the matching program/configuration backup instead.

Docker installations can use the authenticated web updater. The container needs `flock` (util-linux), GNU tar, Bash and curl; new source images include these tools. A web update persists across `docker restart`, but recreating a container must use the matching custom image and the existing database/certificate volumes. The host systemd installer is not run inside containers.

Source and build workflow are included. Upstream licenses and attribution remain intact. ProNet's runtime integration uses authenticated HTTP APIs only; SSH credentials are not part of this package or the application runtime.
