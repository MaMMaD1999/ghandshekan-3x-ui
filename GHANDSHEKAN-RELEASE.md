# GhandShekan Pro — v3.10.2-ghandshekan.33

- Rebuild the panel and the existing custom Xray core with the Go 1.27.3 security toolchain.
- Update the custom core's golang.org/x/net to the minimum fixed v0.60.0 for the HTTP/2 security advisories; preserve all custom accounting and protocol code.
- Backport the four upstream security advisories fixed in 3x-ui 3.11.0 while retaining the 3.10.2 custom feature baseline and accounting implementation.
- Fresh Docker/archive databases generate a random first administrator on server startup. Existing administrator accounts, credentials and database contents are preserved; the custom installer continues setting its own random credentials before startup (GHSA-766p-2p4j-3mfm).
- Reject control characters throughout generated WireGuard/AmneziaWG client configuration lines and refuse imported wg-quick hook directives, including external subscription links (GHSA-r59q-h589-mcjq, GHSA-vg5r-p8fc-gffw).
- Resolve login limiter identities from the trusted end of forwarded proxy headers. Conflicting headers cannot supply a fresh brute-force identity; nginx's overwritten client-IP header remains supported (GHSA-73xj-vvj7-fp4p).
- No schema, quota, host-selection or inbound-membership changes. Retain the checksummed native/Docker update and backup flow; this release supersedes .32 without rewriting its published tag.
- Remove only seven unused sponsor/development-channel translation keys from all 13 locales; no remaining labels or UI behavior change.
