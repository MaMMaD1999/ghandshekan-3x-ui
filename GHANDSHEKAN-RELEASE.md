# GhandShekan Pro — v3.10.2-ghandshekan.28

- Move the custom distribution to the GhandShekan brand, including transparent logo, login/sidebar, installer and update feed. Old release version formats remain supported.
- Explicit traffic resets clear subscription usage cards and dated history. Lifetime accounting checkpoints remain intact to avoid duplicate billing and stale node reimports. Renewal alone preserves history.
- Subscription history uses separate start/end date inputs with a single-month Persian calendar, responsive to mobile widths. Entries below 10 MiB billed usage remain hidden.
- Preserve Docker runtime restoration and checksummed updates across the brand/version migration.
- Existing client identities, inbound/host settings, coefficients and quotas are retained during installation/update. Databases and binaries are backed up before replacement.
