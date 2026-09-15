# SIAS purple-team role-change simulation

Status: closed - authorized development simulation

## Scenario

The SOC operator simulated a failed attempt to change a user role in SIAS development telemetry. The event was deliberately marked as a simulation and did not authenticate to SIAS, change a user, access data, or touch production.

Event ID: `sias-purple-20260915-2d885c26`
Producer time: `2026-09-15T20:41:18.6411761Z`
Source: `sias`
Environment: `development`
Action: `account.role_change`
Outcome: `failure`
Severity: `high`
Actor: `soc-purple-team`
Target: `soc-sim-target`

## Detection path

1. The event was appended to the existing local SIAS audit stream at `C:\SOC-Lab\events\sias.ndjson`.
2. Wazuh ingested it from `/sias-events/sias.ndjson`.
3. Wazuh generated rule `100503`, level `12`: `SIAS application telemetry reported a high-severity event.`
4. The high-severity watcher forwarded the alert to Splunk with sourcetype `soc:wazuh:alert`.
5. Splunk search confirmed the same event ID and rule metadata.

Wazuh evidence:

- Rule: `100503`
- Level: `12`
- Agent: `wazuh.manager`
- Location: `/sias-events/sias.ndjson`

Splunk validation:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-purple-20260915-2d885c26"
| table _time timestamp source event_id event_type action outcome severity actor_id target_id rule_id rule_level rule_description alert_key
```

## Analyst decision

Disposition: expected test activity. No containment or eradication action was required. The detection chain is working end to end; the next improvement is to add a dedicated simulation tag or tenant field so training events are easy to separate from real SIAS incidents.
