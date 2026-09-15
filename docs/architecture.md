# Architecture and trust boundaries

## Collection

Windows Sysmon events are collected by the local Wazuh agent. The Wazuh manager applies local rules and stores the complete alert record in the local indexer.

SIAS, Supabase, and Vercel collectors use outbound HTTPS and read-only credentials supplied at runtime. They select a small set of fields, remove credential-shaped values, and write a stable JSON event envelope to the local SOC event directory.

## Handoff

The high-severity watcher queries the local Wazuh index, de-duplicates alerts, and writes a small handoff file. Splunk monitors that file through a read-only mount. This keeps Splunk useful for SPL, dashboards, and reporting while Wazuh retains the full endpoint evidence and response context.

## Security boundaries

- Provider credentials stay in a protected local directory and never enter Git.
- Generated event files, cursors, certificates, and Docker volumes stay local.
- Splunk and Wazuh bind to localhost during learning.
- Public examples use synthetic identifiers and sanitized case notes.
- Least-privilege provider tokens and a disposable Windows host are preferred.
