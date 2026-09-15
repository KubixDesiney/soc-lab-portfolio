# Executable-drop alert triage: temporary Claude cache

Status: benign-likely, pending signer and hash confirmation

## Alert

The Wazuh and Splunk urgent queues contained repeated rule `92213` alerts at level `15` for Sysmon Event ID `11` (FileCreate). The selected alert was recorded at `2026-09-15T17:40:10.084Z` with alert key `UJcnpqAB04pqzx8SpftW`.

Sanitized event details:

- Agent: `KUBIX-WIN11` (`003`)
- Image: `C:\Users\<profile>\AppData\Roaming\Claude\claude-code\2.1.270\claude.exe`
- Target: `C:\Users\<profile>\AppData\Local\Temp\claude\cache-break-state-<uuid>.json.tmp.<suffix>`
- User: local interactive user
- Rule: `92213` - executable file dropped in a folder commonly used by malware

The same alert was found in Splunk with:

```spl
index=main sourcetype=soc:wazuh:alert rule_id=92213 "cache-break-state-adb68068" 
| sort - _time 
| head 5 
| table _time agent agent_id rule_id rule_level rule_description image alert_key
```

Splunk returned the alert key and rule metadata. The target path was searchable in the raw event but was not extracted into the `targetFilename` field, which is a data-model improvement to address.

## Assessment

The alert is benign-likely because the image is a known local Claude installation and the target is a short-lived JSON cache file with a temporary suffix. This is an assessment, not proof of safety. The current Sysmon process filter does not collect `claude.exe` process creation, so a parent-process correlation was unavailable for this event.

## Analyst decisions

1. Confirm that the user expected Claude Code to be installed and active at the alert time.
2. Validate the executable's Authenticode signature, SHA-256, file version, and install provenance.
3. Check for process, PowerShell, network, and authentication activity from the same user and time window.
4. Inspect the target file only in an isolated workflow; preserve it if signer or provenance is unexpected.
5. Suppress only an exact, signed, trusted path after validation. Keep rule `92213` enabled for other temporary executable drops.

## Disposition

Close as `benign-likely / monitor` pending signer and hash checks. Track the missing `targetFilename` extraction and missing `claude.exe` process correlation as telemetry improvements rather than weakening the detection rule.
