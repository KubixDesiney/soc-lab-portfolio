# SIAS webhook authentication simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise tested connector webhook authentication with a synthetic key. The local `keyMatches` and `authenticate` helpers rejected the wrong key, and no connector endpoint or production secret was contacted.

## Guard validation

The canary supplied `wrong-key` where the connector expected a different key. Constant-time comparison returned `false`, and adapter resolution returned `null`. This confirms the request is denied before telemetry parsing or database writes.

## SIEM evidence

A summarized blocked event was written to the local SIAS audit stream:

- Event ID: `sias-webhook-auth-sim-20260916-2a20adb5`
- Event type: `security.webhook_auth_failure`
- Action: `ingest.signature_rejected`
- Method: `POST`; route: `/ingest/sensorA`
- Expected scheme: `x-api-key`
- Response: HTTP `401`
- Fingerprint: `198.51.100.157` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with the connector, method, expected scheme, status, fingerprint, and simulation flag. No key value was recorded.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-webhook-auth-sim-20260916-2a20adb5"
| table _time event_id event_type action outcome severity fingerprint route target_id request_method expected_scheme http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The invalid key was rejected before ingestion. In a real incident, identify the source, rotate the connector key if compromise is suspected, review successful events from the same fingerprint, and keep connector keys scoped to one adapter.
