# SIAS notification-backlog simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise modeled the SIAS cron scan seeing 801 queued notifications. The queue existed only in memory; no notifications were created, delivered, or written to Firebase.

## Guard validation

The SIAS policy sets `FLOOD_NOTIF_BACKLOG` to 800. The local canary produced `801 >= 800`, so the backlog condition was detected and a blocked-event summary was emitted.

## SIEM evidence

- Event ID: `sias-notification-backlog-sim-20260916-677a93a2`
- Event type: `security.notifications_backlog`
- Action: `notifications.queue_growth`
- Count: `801`; threshold: `800`
- Route: `/notifications`; simulated status: HTTP `503`
- Fingerprint: `198.51.100.180` (TEST-NET documentation address)
- Outcome: `failure`; severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the event as `sourcetype=soc:wazuh:alert` with count, threshold, route, status, and simulation fields.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-notification-backlog-sim-20260916-677a93a2"
| table _time event_id event_type action outcome severity fingerprint route count limit http_status simulation rule_id rule_level reason
```

## Analyst decision

Disposition: expected test activity. The queue threshold fired without producing live notifications. In a real incident, identify the writer, pause the fan-out path if necessary, inspect duplicate or malicious messages, verify delivery-provider health, and replay only after the backlog is understood.
