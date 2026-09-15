# Executable-drop alert triage: temporary Claude cache

Status: benign-likely, pending signer and hash confirmation; telemetry improvements applied

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

Splunk returned the alert key, rule metadata, and—after the extraction update—the full `targetFilename` value. The field is populated from the collector's normalized `target` value so existing events remain searchable.

## Assessment

The alert is benign-likely because the image is a known local Claude installation and the target is a short-lived JSON cache file with a temporary suffix. This is an assessment, not proof of safety. Parent-process correlation was unavailable for this historical event because the filter was not yet collecting `claude.exe` process creation.

## Remediation applied

- Splunk search-time extraction now exposes `targetFilename` while retaining `target` for compatibility.
- The high-severity watcher emits both fields for new alerts.
- Sysmon now collects process creation for `claude.exe` so future alerts can be correlated with the creating process.

## Analyst decisions

1. Confirm that the user expected Claude Code to be installed and active at the alert time.
2. Validate the executable's Authenticode signature, SHA-256, file version, and install provenance.
3. Check for process, PowerShell, network, and authentication activity from the same user and time window.
4. Inspect the target file only in an isolated workflow; preserve it if signer or provenance is unexpected.
5. Suppress only an exact, signed, trusted path after validation. Keep rule `92213` enabled for other temporary executable drops.

## Disposition

Close as `benign-likely / monitor` pending signer and hash checks. Keep rule `92213` enabled and reassess only after the new process correlation is observed on a future event.
