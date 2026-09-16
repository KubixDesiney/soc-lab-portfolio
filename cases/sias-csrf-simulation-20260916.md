# SIAS CSRF-style state-change simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise modeled a cross-site `POST` to the SIAS connector control route. The local authorization helper received an attacker origin and no authorization header, so it rejected the state-changing request. No browser session, cookie, or live request was used.

## Guard validation

`adminAuthorized` returned `false` when `/control` was called without the configured worker secret. SIAS protected control operations require an explicit authorization header; the test did not attempt to bypass that boundary.

Because the current API uses an authorization header rather than ambient cookies, classic browser CSRF exposure is limited. If cookie-based administration is introduced later, add an origin check and a CSRF token before enabling state changes.

## SIEM evidence

A summarized blocked event was written to the local SIAS audit stream:

- Event ID: `sias-csrf-sim-20260916-2a20adb5`
- Event type: `security.csrf_block`
- Action: `state_change_without_auth`
- Method: `POST`; route: `/control`
- Origin: `https://attacker.example` (documentation-only canary)
- Response: HTTP `401`
- Fingerprint: `198.51.100.156` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with the method, origin, route, status, fingerprint, and simulation flag.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-csrf-sim-20260916-2a20adb5"
| table _time event_id event_type action outcome severity fingerprint route request_method origin http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The unauthorized state change was rejected before control handling. In a real incident, confirm whether any session was authenticated, review same-origin and session telemetry, revoke suspicious sessions, and require a CSRF token if the product ever accepts cookie-authenticated state changes.
