# SIAS privilege-escalation and IDOR simulations

Status: closed - authorized development simulations

## Scope and safety

These were negative authorization tests against a protected SIAS worker and a dummy Firebase path. No valid credential was used, no role was changed, and no customer record was read or modified.

## Tests

### Privilege escalation

An invalid Firebase bearer token was sent to the protected SIAS `/security-status` worker endpoint while modeling a supervisor attempting an admin-only action. SIAS returned HTTP `401` with `{"error":"unauthorized"}`.

The corresponding development telemetry was:

- Event ID: `sias-priv-esc-sim-20260916-cd3287cb`
- Action: `account.role_change`
- Actor role: `supervisor`
- Requested role: `superadmin`
- HTTP status: `401`
- Outcome: `failure`
- Wazuh: rule `100503`, level `12`

### IDOR read

An anonymous `GET` for the dummy path `users/soc-idor-canary-20260916.json` was sent to the Firebase Realtime Database. Firebase returned HTTP `401` with `Permission denied`; no record was returned.

The corresponding development telemetry was:

- Event ID: `sias-idor-sim-20260916-cd3287cb`
- Action: `read.user_record`
- Target: `soc-idor-canary-2`
- HTTP status: `401`
- Outcome: `failure`
- Wazuh: rule `100503`, level `12`

## SIEM validation

Splunk indexed both events as `sourcetype=soc:wazuh:alert` with the actor, target, requested role, HTTP status, reason, and Wazuh rule fields.

```spl
index=main sourcetype=soc:wazuh:alert
(event_id="sias-priv-esc-sim-20260916-cd3287cb" OR event_id="sias-idor-sim-20260916-cd3287cb")
| table _time timestamp source event_id event_type action outcome severity actor_role target_type target_id requested_role http_status rule_id rule_level reason alert_key
```

## Analyst decision

Disposition: expected test activity. Both access paths failed closed before data or authorization state could be changed. The correct response is to preserve the evidence, confirm the actor and tenant context, and close the alert when the activity is an approved test.
