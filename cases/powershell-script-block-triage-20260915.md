# PowerShell script-block triage drill

Status: closed - expected local automation

## Trigger

Wazuh rule `100522` raised a level-12 alert for a PowerShell script block containing the `Invoke-Expression` pattern. The newest event was recorded on 2026-09-15 at about 14:32:38 local time on the Windows lab endpoint.

## Process and content review

The block matched a known shell-launcher pattern that reads a launcher value from an environment variable and evaluates it. A nearby Sysmon process event showed `pwsh.exe` running under the lab operator with `svchost.exe` as its parent. The reviewed process command line had no encoded-command, download, persistence, or credential-access indicators.

The script block was treated as a lead for investigation, not proof of compromise. The command was not executed or modified during triage.

## Correlation

A ten-minute Wazuh window around the alert contained four related PowerShell script-block alerts and no Sysmon network, file-create, registry, or DNS events. No evidence of external communication, persistence, payload staging, or impact was found.

## Disposition

Closed as authorized local tooling activity. No containment or remediation was required. Keep rule `100522` enabled because the same pattern would require escalation when paired with an unknown parent, an untrusted user, encoded content, downloads, persistence, credential access, or related network activity.

## Analyst lesson

For a high-severity PowerShell alert, recover the block, identify the process lineage and user, then pivot across network, file, registry, and DNS telemetry before deciding whether to contain.
