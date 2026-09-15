# Sysmon file-create coverage check

Status: open - telemetry gap identified

## Test

A harmless marker file was created and never executed at `%TEMP%\soc-lab-training\payload.exe`. The file contained training text only and was removed after verification. Its SHA-256 was recorded locally during the test and is not needed for remediation.

## Expected path

Sysmon event 11 should have recorded the file creation, Wazuh should have normalized the event, and rule `92213` should have evaluated the temporary executable path. The high-severity watcher would then have forwarded a level-12-or-higher alert to Splunk if the rule fired.

## Observed result

No matching Sysmon event 11 was present in the Windows event channel, and no Wazuh event matched the target path or rule `92213` after the indexer became healthy. The marker was not executed, so this test produced no process, network, registry, or DNS activity. A temporary Docker restart caused an initial connection refusal during checking, but a later authenticated lookup still found no file-create event.

## Assessment

This is a telemetry coverage gap, not evidence that the file was safe in a production scenario. Until FileCreate coverage is confirmed, the lab cannot rely on the dropped-file detector for complete endpoint triage.

## Remediation plan

Inspect the active Sysmon configuration from an elevated console, confirm that FileCreate event 11 includes the temporary and SOC-Lab paths, reload Sysmon if needed, and repeat the marker test. Do not lower or disable rule `92213`; validate the collection path first.

## Analyst lesson

A detection rule is only useful when the underlying event is collected. Test the full chain—source event, Wazuh normalization, rule match, watcher handoff, and Splunk visibility—and record gaps as findings.
