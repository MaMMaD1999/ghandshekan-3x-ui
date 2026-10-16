# ProNet custom accounting — test release

Based on Sanaei 3x-ui v3.10.2 and its pinned Xray revision. Both master and execution nodes must use this package for detailed accounting. This is a custom distribution, not an official Sanaei release.

- One shared client identity, with independent raw upload/download counters per inbound and user.
- Inbound coefficients affect the shared client quota inside Sanaei. Raw counters remain independent.
- Lifetime reports retain separate rows for each coefficient used. Resetting a quota does not erase reporting history.
- The subscription page shows raw usage, coefficient, and billed usage; the client's name is the heading, followed by the subscription identifier. The configured subscription title appears above the announcement.
- Authenticated capability discovery includes a check of the running custom core. ProNet edits use a narrow compare-and-set API.
- Official panel/core self-updaters are blocked. Update the complete custom package to preserve accounting support.

## Installation

Use a clean test node first. Linux with systemd, amd64 or arm64; requires curl, tar, sha256sum and openssl. The installer verifies release checksums and retains existing configuration and program backups under `/var/backups/pronet`.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MaMMaD1999/pronet-3x-ui/v3.10.2-pronet.6/pronet-install.sh) v3.10.2-pronet.6
```

The command is usable only after the corresponding release assets are published. On a fresh install, random login credentials and the panel path are printed. Configure HTTPS and firewall access before using the panel remotely. Existing credentials and settings are preserved.

Existing PostgreSQL installations also require Python 3 and `pg_dump`; the database and service environment are backed up before the service is stopped. If backup fails, installation stops before replacing files. Backups are retained for manual rollback.

Non-unit coefficients are supported for VLESS, VMess, Trojan and Shadowsocks. Changing a coefficient applies it to the next traffic collection interval; historical rows are not recalculated. Like upstream, quota enforcement is periodic and can have a small polling overshoot. This initial release does not change that behavior.

Old usage before custom accounting was enabled cannot be reconstructed into per-inbound detail. ProNet establishes a cutover baseline to avoid charging old cumulative usage again. Existing usage remains recorded separately.

## Maintenance

Running `x-ui` without arguments opens the full upstream management menu, adapted for ProNet releases. SSL, firewall, service, database and credential-management tools are retained. Official/dev upgrades are blocked; custom package updates and menu updates use this fork. The installer prints a complete login URL and fresh-install credentials after the service starts. Existing passwords are retained and cannot be recovered from their hashes; option 7 resets them when needed.

`x-ui start`, `x-ui stop`, `x-ui restart`, `x-ui status`, `x-ui log`, and `x-ui setting ...` are available. Use the versioned installer for updates. Do not replace only the core or downgrade a live database; restore the matching program/configuration backup instead.

Source and build workflow are included. Upstream licenses and attribution remain intact. ProNet's runtime integration uses authenticated HTTP APIs only; SSH credentials are not part of this package or the application runtime.
