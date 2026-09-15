# SIAS and Vercel correlation exercise

Status: closed - expected synthetic correlation exercise

## Trigger

At 2026-09-15T13:12:58.482Z, two synthetic application events were emitted for the same lab exercise:

- SIAS reported a failed `account.role_change` in the development environment (`event_id=sias-correlation-20260915-131258`).
- Vercel reported a failed production `runtime.error` on `/api/demo` (`event_id=vercel-correlation-20260915-131258`).

The events used generic actors, targets, and deployment names. They contained no credentials, real users, production telemetry, or network activity.

## Detection and correlation

Wazuh ingested both events through the local NDJSON bridge and raised the focused high-severity rules:

- Rule `100503`, level 12: SIAS application telemetry reported a high-severity event.
- Rule `100508`, level 12: Vercel runtime reported a high-severity application error.

The producer timestamp was 13:12:58.482Z and Wazuh recorded ingestion at about 13:14:36Z. Comparing those timestamps prevents the analyst from confusing event time with collection time.

The high-severity handoff was then searchable in Splunk Free as `sourcetype=soc:wazuh:alert`. An SPL correlation query returned both event IDs and grouped them by source, event type, outcome, severity, and Wazuh rule. This verified the full path: application event -> Wazuh detection -> de-duplicated handoff -> Splunk search.

## Analyst assessment

The shared producer time and synthetic exercise marker explain the relationship between the two alerts. The SIAS event shows a failed action, and the Vercel event shows an application error; neither demonstrates a successful privilege change, account compromise, or data access. No endpoint process, persistence, or network evidence was associated with the exercise.

## Disposition

Closed as an expected test. Keep rules `100503` and `100508` enabled. For a real investigation, pivot from the producer time and deployment or route into authentication, authorization, data-access, process, network, and change-management records before containment.

## Analyst lesson

Correlate producer time, ingestion time, source, outcome, and environment before escalating separate high-severity application alerts into an incident.
