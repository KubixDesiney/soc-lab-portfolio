# SIAS API enumeration simulation

Status: closed - authorized development simulation

## Scope and safety

This exercise modeled route discovery entirely in memory. Eight nonexistent paths were evaluated as HTTP `404` results inside a local harness. The detector marked the sequence when at least five distinct `404` paths appeared in one minute. No request was sent to SIAS, Cloudflare, Firebase, or any third-party service.

## Detection decision

The local sequence contained eight `404` responses and eight unique paths, so it crossed the practice threshold. The paths were representative canaries only:

`/api/admin`, `/api/debug`, `/api/users`, `/api/config`, `/api/metrics`, `/api/internal`, `/api/graphql`, `/.env`

A real implementation should tune this signal with authenticated identity, source reputation, route sensitivity, and baseline traffic. A small number of `404`s from a normal client is not enough to call an incident.

## SIEM evidence

A summarized event was written to the local SIAS audit stream:

- Event ID: `sias-api-enum-sim-20260916-3cfe632a`
- Event type: `security.api_enumeration`
- Action: `route_probe_burst`
- Target: `public-api`
- Fingerprint: `198.51.100.101` (TEST-NET documentation address)
- Eight unique paths in one minute; representative response `404`
- Outcome: `failure`
- Severity: `high`
- Wazuh: rule `100503`, level `12`
- Location: `/sias-events/sias.ndjson`

Splunk indexed the same event as `sourcetype=soc:wazuh:alert` and retained the route family, count, unique-path count, window, response status, sample paths, and simulation flag.

Validation search:

```spl
index=main sourcetype=soc:wazuh:alert event_id="sias-api-enum-sim-20260916-3cfe632a"
| table _time event_id event_type action outcome severity fingerprint route count unique_paths window_min http_status simulation rule_id rule_level reason sample_paths
```

## Analyst decision

Disposition: expected test activity. The route-probe burst crossed the lab threshold and generated a correlated high-severity alert in both SIEMs. In a real incident, preserve the request and authentication logs, determine whether the source is an approved scanner, review successful requests and sensitive routes, apply a narrow block or challenge if abuse is confirmed, and escalate if discovery precedes unauthorized access.
