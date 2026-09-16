# SIAS rate-limit abuse simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise validated SIAS's request-rate control with a deterministic local token-bucket test. Four in-memory calls were evaluated against a three-call capacity: the first three were allowed and the fourth was blocked. No traffic was sent to the live Cloudflare worker, no availability impact was introduced, and the telemetry was labeled `development` and `simulation`.

## Guard validation

The SIAS connector helper uses a per-key sliding one-minute window. The local canary produced these results:

| Request | Result | Remaining |
| ---: | --- | ---: |
| 1 | allowed | 2 |
| 2 | allowed | 1 |
| 3 | allowed | 0 |
| 4 | blocked | 0 |

The production `security-status` endpoint is configured for 12 requests per minute. The SIEM canary represents the 13th request and records the expected HTTP `429` outcome.

## SIEM evidence

A blocked-event sample was written to the local SIAS audit stream:

- Event ID: `sias-rate-limit-sim-20260916-bf958a72`
- Action: `rate_limit_block`
- Target: `security-status`
- Fingerprint: `198.51.100.88` (TEST-NET documentation address)
- Observed: `13` requests in `60` seconds; limit `12`
- HTTP status: `429`
- Outcome: `failure`
- Severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the same event as `sourcetype=soc:wazuh:alert` and retained the observed count, limit, window, status, simulation flag, and reason fields.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-rate-limit-sim-20260916-bf958a72"
| table _time event_id event_type action outcome severity fingerprint observed limit window_sec http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The local rate limiter blocked the over-threshold request and emitted a high-severity event that was visible in both Wazuh and Splunk. In a real incident, the next steps would be to validate the source, check whether the activity is abusive or a client misconfiguration, review nearby authentication and application events, and escalate only if the behavior persists or affects service availability.
