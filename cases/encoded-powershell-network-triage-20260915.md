# Encoded PowerShell network triage

Status: closed - benign controlled test

## Trigger

A controlled lab command generated two Wazuh level-12 alerts on `KUBIX-WIN11` (agent `003`) at `2026-09-15T15:29:22Z`:

- rule `100521`: encoded or commonly obfuscated PowerShell command;
- rule `100522`: high-risk PowerShell script-block pattern.

The process was the built-in Windows PowerShell executable, launched by the authorized local lab automation user. Its parent was the local PowerShell host used to run the exercise.

## Payload and network pivot

The encoded content was recovered from the Sysmon process event and matching PowerShell script-block event. It attempted one HTTP request to `127.0.0.1:8000` (the local Splunk dashboard), caught any error, and printed the marker `SOC-LAB-SAFE-LOOPBACK-NETWORK-TEST`. No public or external destination was contacted by the test.

A one-minute Wazuh window around the alert contained the two level-12 detections, the related Sysmon process-create event, and routine integrity telemetry. No Sysmon event 3 network connection, file-create, registry, or DNS event was associated with the test process. Other command-prompt activity in the window was separate local automation and was excluded by process lineage.

## Handoff and disposition

The high-severity watcher forwarded both alerts to `C:\SOC-Lab\live\high-severity.ndjson`. Splunk indexed both as `sourcetype=soc:wazuh:alert`, and the non-synthetic triage queue displayed them with the decoded script-block text.

Closed as authorized training activity. No isolation, process termination, blocking, or remediation was required. Rules `100521` and `100522` remain enabled because the same combination would require escalation when the parent, user, destination, or payload is unknown or when file, persistence, credential, or external-network evidence appears.

## Analyst lesson

Correlate detections by process ID, parent lineage, user, and time window. An encoded command plus a network-capable PowerShell pattern is high priority, but containment depends on the recovered destination, execution context, and corroborating telemetry.
