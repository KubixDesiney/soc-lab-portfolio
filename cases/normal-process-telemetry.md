# Normal endpoint telemetry scope check

Status: closed - expected telemetry scope test

## Activity

A harmless `whoami.exe /user` command was run on the Windows lab endpoint to verify the normal Sysmon process path. Wazuh matched the process-create event with rule `100516` at level 3. The event was associated with a generic lab user and produced no download, persistence, credential access, or external communication.

## Handoff behavior

The event remained in Wazuh's full alert stream and did not appear in Splunk's `sourcetype=soc:wazuh:alert` search because the local handoff intentionally forwards only level-12-or-higher alerts. A zero-result Splunk search therefore did not mean that Wazuh missed the process; it demonstrated the designed severity boundary.

## Disposition

Closed as expected lab activity. Keep Wazuh as the source for full-fidelity endpoint hunting and use Splunk for the focused high-severity queue and reporting view.

## Analyst lesson

Always check the collector's scope and severity filter before treating an empty downstream search as a collection failure.
