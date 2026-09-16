# SIAS alert-flood simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise modeled the SIAS cron anomaly scan seeing 45 new alerts in one minute. The records existed only in memory and were not written to Firebase or a production alert store.

## Guard validation

The SIAS policy sets `FLOOD_ALERTS_PER_MIN` to 40. The local canary produced `45 >= 40`, so the flood condition was detected and a blocked-event summary was emitted.

## SIEM evidence

- Event ID: `sias-alert-flood-sim-20260916-16318875`
- Event type: `security.alert_flood_detected`
- Action: `alert.create_burst`
- Count: `45`; threshold: `40`; window: `60` seconds
- Response: HTTP `429`
- Fingerprint: `198.51.100.170` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with count, threshold, window, status, and simulation fields.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-alert-flood-sim-20260916-16318875"
| table _time event_id event_type action outcome severity fingerprint route count limit window_sec http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The alert-volume threshold fired without creating live records. In a real incident, identify the creating principal, stop the write path or isolate the account, preserve representative records, and verify that downstream notifications and storage are healthy.
