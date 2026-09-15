# Sysmon file-create coverage check

Status: verified - collection working; high-severity path tuning remains intentional

## Test

After reloading the active Sysmon configuration with elevation, a harmless text marker with an `.exe` suffix was created at `C:\SOC-Lab\filecreate-validation-3ef09ebf.exe` and left in place long enough for ingestion. It was never executed. SHA-256: `46C9EB93CF7181E74DCB38F364B4DF2C1EFD6EB6CB4E872A14B151B86FEB70CF`. The marker was removed after verification.

## Expected path

Sysmon event 11 should record the create, Wazuh should normalize it, and the normal FileCreate rule should provide a low-severity audit event. Rule `92213` is reserved for executable drops in paths commonly used by malware, so a file in the controlled `C:\SOC-Lab` workspace is not expected to trigger it.

## Observed result

Wazuh received the exact event at `2026-09-15T17:40:22.018Z`:

- Sysmon Event ID: `11` (FileCreate)
- Wazuh rule: `100518`, level `3`
- Agent: `KUBIX-WIN11` (`003`)
- Image: `pwsh.exe`
- Target: `C:\SOC-Lab\filecreate-validation-3ef09ebf.exe`

The high-severity watcher ran successfully and reported no new level-12-or-higher alert. Splunk therefore did not receive this level-3 validation record through the high-severity handoff. Existing Splunk results continue to show rule `92213` for executable files created in higher-risk user and runtime paths.

## Assessment

The earlier apparent gap was caused by testing before the active configuration was restored and by delayed index ingestion. FileCreate collection and Wazuh normalization are working for the SOC-Lab path and `.exe` suffix. The high-severity rule remains intentionally scoped and should be exercised with a separate controlled test in a malware-like temporary path only when we are ready to study that alert path.

## Remediation applied

The active Sysmon configuration now includes:

```xml
<FileCreate onmatch="include">
  <TargetFilename condition="end with">.exe</TargetFilename>
  <TargetFilename condition="contains">C:\SOC-Lab\</TargetFilename>
</FileCreate>
```

Sysmon was reloaded with exit code `0` and the `Sysmon64` service is running.

## Analyst lesson

A detection rule is only useful when the underlying event is collected. Validate the full chain—source event, Wazuh normalization, rule match, watcher handoff, and Splunk visibility—and distinguish a collection problem from an intentionally narrow severity rule.
