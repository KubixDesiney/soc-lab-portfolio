# SIAS buffer-overflow safety simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise tested SIAS request-size defenses without sending a giant request to the live Cloudflare/Firebase deployment and without executing native overflow code. The test used bounded in-memory strings and a clearly labeled `development` telemetry event. No production data or service state changed.

## Guard validation

The SIAS edge-gateway guard sets `MAX_PAYLOAD_BYTES` to `32,768` bytes. Local checks produced these results:

| Test | Size | Result |
| --- | ---: | --- |
| Under limit | 1,024 bytes | accepted |
| Exact boundary | 32,768 bytes | accepted |
| One byte over | 32,769 bytes | rejected |
| Larger canary | 65,537 bytes | rejected |

## SIEM evidence

A blocked-event sample was sent through the local SIAS audit stream:

- Event ID: `sias-buffer-sim-20260916-0c0840ce`
- Action: `payload_too_large`
- Payload: `32,769` bytes against a `32,768` byte limit
- Outcome: `failure`
- Severity: `high`
- Target: `soc-buffer-canary-2`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the same event as `sourcetype=soc:wazuh:alert` and retained the payload size, limit, matched pattern, simulation flag, and reason fields.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-buffer-sim-20260916-0c0840ce"
| table _time timestamp source event_id event_type action outcome severity rule_id rule_level payload_bytes payload_limit matched_pattern simulation reason alert_key
```

## Analyst decision

Disposition: expected test activity. The size guard rejected the over-limit input before parsing or forwarding, and the alert was visible in both Wazuh and Splunk. The watcher now extracts the size and reason fields so an analyst can validate the control directly from the SIEM.
