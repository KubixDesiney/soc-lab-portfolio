# SIAS SQL-injection and password-spraying simulations

Status: closed - authorized development simulations

## Scope and safety

These exercises tested SIAS detection logic and the SIAS-to-SOC pipeline without attacking a live account or changing production data. The SIAS application uses Firebase/Cloudflare in this deployment; there is no SQL query path in the tested worker. No live SQL payload was sent to SIAS, and no password was guessed. All telemetry below is explicitly marked `development` and `simulation`.

## SQL-injection canary

The SIAS AI worker's `_securityDetectPromptInjection` helper was exercised locally with three canonical SQL-injection canaries. `OR 1=1`, `UNION SELECT`, and `DROP TABLE` were each flagged with the `sql_injection` signature. A normal maintenance note was not flagged.

The bridge then received a blocked-event sample:

- Event ID: `sias-sqli-sim-20260916-ffc57cf6`
- Action: `prompt_injection_block`
- Outcome: `failure`
- Severity: `high`
- Target: `soc-sqli-canary`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

## Password-spraying threshold

Ten synthetic authentication failures were generated for ten dummy users using the TEST-NET fingerprint `198.51.100.77`. They were local samples only; no request was sent to Firebase Auth. This matches SIAS's documented anomaly threshold of 10 failures from one fingerprint within five minutes.

The resulting surge event was:

- Event ID: `sias-spray-surge-20260916-ffc57cf6`
- Action: `auth_failure_surge`
- Count: `10`
- Window: `5` minutes
- Outcome: `failure`
- Severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Wazuh confirmed all 10 underlying authentication-failure samples and the surge summary. Splunk indexed both high-severity events as `sourcetype=soc:wazuh:alert`.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert
(event_id="sias-sqli-sim-20260916-ffc57cf6" OR event_id="sias-spray-surge-20260916-ffc57cf6")
| table _time timestamp source event_id event_type action outcome severity rule_id rule_level alert_key
```

## Analyst decision

Disposition: expected test activity. The SQL signature and authentication-surge threshold both produced SIEM-visible alerts. The next production-safe improvement is a dedicated tenant/test marker so analysts can filter training events from real incidents without relying on free-text reasons.
