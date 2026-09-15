# Encoded PowerShell triage drill

Status: closed - benign controlled test

## Trigger

A harmless PowerShell command was encoded and executed on the Windows lab endpoint to validate the detection path. It only printed the marker `SOC-LAB-SAFE-ENCODED-TEST`; it did not download, modify, persist, or access credentials.

At `2026-09-15T15:24:01Z`, Wazuh raised rule `100521` at level 12 for Sysmon event 1. The image was the built-in Windows PowerShell executable on agent `KUBIX-WIN11` (agent `003`). The encoded payload itself is intentionally omitted from this public case note.

## Evidence review

The high-severity watcher forwarded the alert to `C:\SOC-Lab\live\high-severity.ndjson`, and Splunk indexed it as `sourcetype=soc:wazuh:alert` with rule ID `100521` and level 12. The new Splunk triage queue displayed the event after the watcher refresh.

A one-minute Wazuh window around the alert contained:

- one rule `100521` level-12 encoded-command alert;
- two rule `100516` level-3 Sysmon process-create events; and
- five rule `550` level-7 integrity-checksum events.

No Sysmon network, file-create, registry, or DNS events were present in that window. The parent process and user were local lab automation context, and the command completed successfully with the expected marker.

## Disposition

Closed as authorized training activity. No containment or remediation was required. Rule `100521` remains enabled because an encoded command paired with an unknown parent, untrusted user, download, persistence, credential access, or related network activity would require escalation.

## Analyst lesson

An encoded-command alert is a lead, not a verdict. Recover or decode the content, establish process lineage and user context, then correlate network, file, registry, and DNS telemetry before deciding on containment.
