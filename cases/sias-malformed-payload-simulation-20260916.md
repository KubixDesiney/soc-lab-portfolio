# SIAS malformed-payload simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise modeled malformed alert inputs in memory: one description contained a control character and another exceeded the 4,000-character description cap. No payload was sent to SIAS and no database write occurred.

## Guard validation

The anomaly scan counts records with control characters, oversized descriptions, or oversized type fields. The local canary found two malformed records and classified the pattern as `control_char_or_oversize`.

## SIEM evidence

- Event ID: `sias-malformed-alert-sim-20260916-16318875`
- Event type: `security.malformed_alerts`
- Action: `alert.payload_rejected`
- Route: `/alerts`
- Count: `2`
- Matched pattern: `control_char_or_oversize`
- Response: HTTP `400`
- Fingerprint: `198.51.100.171` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with count, matched pattern, route, status, and simulation fields.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-malformed-alert-sim-20260916-16318875"
| table _time event_id event_type action outcome severity fingerprint route count matched_pattern http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The malformed inputs were identified before persistence. In a real incident, preserve the raw request safely, identify the caller, check for parser or injection attempts, and confirm that rejected records did not reach notification or downstream exports.
