# SIAS path-traversal and file-disclosure simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise tested SIAS's local prompt-security pattern matcher with bounded strings. It evaluated two file-disclosure patterns and one normal label in memory. No path was opened, no file was read, and no request was sent to SIAS or Cloudflare.

## Guard validation

The detector matched `path_traversal` for `../../etc/passwd` and `C:\Windows\System32\drivers\etc\hosts`, while a normal asset label passed without a match. The matcher is a heuristic; it should be paired with canonical path handling and an allowlist wherever the application accesses files.

## SIEM evidence

A summarized blocked event was written to the local SIAS audit stream:

- Event ID: `sias-path-traversal-sim-20260916-2a20adb5`
- Event type: `security.path_traversal_block`
- Action: `request.path_traversal`
- Route: `/copilot`
- Matched pattern: `path_traversal`
- Response: HTTP `400`
- Fingerprint: `198.51.100.155` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with the route, matched pattern, status, fingerprint, and simulation flag.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-path-traversal-sim-20260916-2a20adb5"
| table _time event_id event_type action outcome severity fingerprint route matched_pattern http_status simulation rule_id rule_level reason payload_sample
```

## Analyst decision

Disposition: expected test activity. The pattern was blocked before any file operation. In a real incident, preserve the request, identify the caller, review adjacent successful file or export actions, verify path canonicalization, and rotate any data-access credentials if a disclosure occurred.
