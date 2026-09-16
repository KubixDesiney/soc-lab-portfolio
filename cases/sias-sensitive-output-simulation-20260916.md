# SIAS sensitive-output guard simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise tested the local output guard against requests that would reveal credentials or embed Firebase authentication URLs in a response. The detector evaluated synthetic strings only; no secret, token, or live prompt was used.

## Guard validation

The matcher identified the `cred_exfil` pattern for a request to reveal an API key and service-account material, and the `firebase_url` pattern for an authentication-bearing Firebase URL. The guard is a heuristic and should be paired with secret storage controls and response review.

## SIEM evidence

- Event ID: `sias-sensitive-output-sim-20260916-677a93a2`
- Event type: `security.sensitive_output_block`
- Action: `prompt.response_blocked`
- Route: `/copilot`
- Matched patterns: `cred_exfil`, `firebase_url`
- Response: HTTP `400`
- Fingerprint: `198.51.100.181` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with route, matched patterns, status, fingerprint, and simulation fields. No credential value was recorded.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-sensitive-output-sim-20260916-677a93a2"
| table _time event_id event_type action outcome severity fingerprint route matched_pattern http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The output guard blocked both sensitive patterns before a response was sent. In a real incident, preserve the request metadata, review the caller and model context, rotate any exposed secret, and confirm that logs and error messages do not contain the value.
