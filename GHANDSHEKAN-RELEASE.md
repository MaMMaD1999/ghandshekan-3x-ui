# GhandShekan Pro — v3.10.2-ghandshekan.32

- Rebuild the panel and the existing custom Xray core with the Go 1.27.3 security toolchain.
- Update the custom core's golang.org/x/net to the minimum fixed v0.60.0 for the HTTP/2 security advisories; preserve all custom accounting and protocol code.
- Preserve the v3.10.2-ghandshekan.31 application code, embedded interface assets and custom per-inbound accounting implementation.
- No traffic, quota, subscription, host, inbound, API or database schema changes; retain the existing checksummed native/Docker update and backup flow.
