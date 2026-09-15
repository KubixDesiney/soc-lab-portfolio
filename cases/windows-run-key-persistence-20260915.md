# Windows Run key persistence validation

Status: verified - registry persistence telemetry is visible in Wazuh

## Scenario

The lab simulated a per-user persistence change by writing the value `SOC-Lab-Validation-ad4c1d6a` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. The value pointed to `cmd.exe /c exit 0`; it was never allowed to run and was deleted immediately after telemetry verification.

## Evidence

Wazuh received the Sysmon registry event at `2026-09-15T17:47:32.143Z`:

- Sysmon Event ID: `13` (`SetValue`)
- Wazuh rule: `92302`, level `6`
- Agent: `KUBIX-WIN11` (`003`)
- Image: `C:\Windows\System32\reg.exe`
- Target: `HKU\\S-1-5-21-3770122780-2884150006-4120301897-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SOC-Lab-Validation-ad4c1d6a`
- Details: `cmd.exe /c exit 0`

The corresponding delete operation was performed after verification. The value is no longer present. The high-severity watcher did not forward this event because its handoff threshold is level 12; this is expected and keeps routine persistence auditing separate from the urgent queue.

## Analyst decisions

1. Treat a new `Run` or `RunOnce` value as a persistence lead, not as proof of compromise.
2. Capture the account, value data, parent process, signer, hash, and first-seen time.
3. Check whether the referenced file exists and whether it was created or downloaded near the registry change.
4. Review process, network, and authentication events for the same user and time window.
5. Preserve the value and referenced file for evidence in a real incident; remove or disable only under the approved response plan.

## Lab lesson

Registry coverage is useful only when the value-write event is collected and normalized. The lab now covers common per-user `Run` and `RunOnce` paths, verifies the source event in Wazuh, and reserves Splunk's urgent queue for level-12-or-higher activity.
