# SIAS token replay simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise tested bearer-token claim validation and replay triage in a local harness. It used synthetic claims and an opaque token fingerprint only; no real token was generated, stored, or sent to SIAS. Six repeated invalid-token attempts were modeled against `/security-status`, and no live endpoint was contacted.

## Claim validation

The SIAS validator rejected each malformed claim for the expected reason:

| Claim canary | Result |
| --- | --- |
| Expired token | `expired` |
| Wrong audience | `bad_aud` |
| Wrong issuer | `bad_iss` |
| Missing subject/UID | `no_uid` |

A replay heuristic then observed six attempts with one token fingerprint inside a one-minute window. This is a training signal; production tuning should combine token subject, source fingerprint, endpoint, and normal session behavior before taking action.

## SIEM evidence

A summarized event was written to the local SIAS audit stream:

- Event ID: `sias-token-replay-sim-20260916-4c6895cb`
- Event type: `security.token_replay`
- Action: `invalid_token_replay`
- Route: `/security-status`
- Fingerprint: `198.51.100.144` (TEST-NET documentation address)
- Attempts: `6`; unique token fingerprints: `1`; window: `1` minute
- Response: HTTP `401`
- Claim errors: `expired`, `bad_aud`, `bad_iss`, `no_uid`
- Outcome: `failure`
- Severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the same event as `sourcetype=soc:wazuh:alert` and retained the attempt count, token-fingerprint count, claim errors, route, status, and simulation flag. No credential or token value was forwarded.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-token-replay-sim-20260916-4c6895cb"
| table _time event_id event_type action outcome severity fingerprint route attempts unique_token_fingerprints window_min http_status simulation rule_id rule_level reason claim_errors
```

## Analyst decision

Disposition: expected test activity. The invalid claims were rejected before authorization, and the repeated fingerprint was visible in both SIEMs. In a real incident, revoke the affected session or token, identify the user and source, inspect successful requests made with the same identity, check for impossible-travel or device changes, and escalate if unauthorized access occurred.
