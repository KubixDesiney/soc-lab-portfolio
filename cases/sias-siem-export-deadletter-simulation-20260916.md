# SIAS SIEM export dead-letter simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise modeled a SIEM export destination failing repeatedly. It evaluated the retry policy in memory and did not contact an external SIEM or send real telemetry.

## Guard validation

The SIAS export policy allows five attempts before moving an outbox record to `dead_letter`. The local canary reached attempt five and selected the dead-letter state, preserving the failure for operator review instead of retrying indefinitely.

## SIEM evidence

- Event ID: `sias-siem-deadletter-sim-20260916-16318875`
- Event type: `security.siem_export_failure`
- Action: `siem.export_dead_letter`
- Target: `security/siem_outbox/synthetic-record`
- Attempts: `5`; retry limit: `5`
- Response: HTTP `503` (simulated destination failure)
- Fingerprint: `198.51.100.172` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with attempts, retry limit, route, status, and simulation fields.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-siem-deadletter-sim-20260916-16318875"
| table _time event_id event_type action outcome severity fingerprint route target_id attempts limit http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The bounded retry policy prevented an endless export loop and retained a dead-letter record for review. In a real incident, verify destination health and credentials, measure the backlog, replay only after the destination is healthy, and ensure retention alerts do not hide an export outage.
