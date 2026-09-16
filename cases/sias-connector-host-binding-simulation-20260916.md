# SIAS connector credential host-binding simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise validated the connector guard that decides whether stored credentials may accompany an outbound request. It compared a configured endpoint host with a same-host URL and a different-host URL in memory. No credential or outbound request was used.

## Guard validation

The local helper allowed credentials for `sensor.example` when the target host matched, and withheld credentials when a tag URL pointed to `attacker.example`. The request could still be evaluated without secrets, preventing a compromised connector configuration from turning the worker into a credential-forwarding proxy.

## SIEM evidence

A summarized blocked event was written to the local SIAS audit stream:

- Event ID: `sias-credential-host-sim-20260916-2a20adb5`
- Event type: `security.credential_host_guard`
- Action: `credential_forward_block`
- Route: `/connectors/connector-read`
- Configured host: `sensor.example`; target host: `attacker.example`
- Expected scheme: `bearer`
- Response: HTTP `403`
- Fingerprint: `198.51.100.158` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with both hosts, route, status, fingerprint, and simulation flag. No token or credential value was recorded.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-credential-host-sim-20260916-2a20adb5"
| table _time event_id event_type action outcome severity fingerprint route target_id configured_host target_host expected_scheme http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The host-binding guard prevented credential forwarding to a different destination. In a real incident, disable the connector, review configuration changes and audit logs, rotate the affected secret, and allowlist only the intended endpoint host.
