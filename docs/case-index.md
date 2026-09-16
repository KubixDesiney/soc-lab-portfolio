# SOC lab case index

These sanitized cases record the exercise scope, evidence, analyst decision, and validation search. All SIAS exercises use development telemetry and local-only canaries.

## SIAS application and API controls

- [SIAS role-change authorization](../cases/sias-purple-team-role-change-20260915.md)
- [SIAS SQL and authentication-spray simulation](../cases/sias-sqli-auth-spray-simulation-20260916.md)
- [SIAS buffer-overflow safety simulation](../cases/sias-buffer-overflow-simulation-20260916.md)
- [SIAS privilege-escalation and IDOR simulation](../cases/sias-privilege-escalation-idor-20260916.md)
- [SIAS rate-limit simulation](../cases/sias-rate-limit-simulation-20260916.md)
- [SIAS API-enumeration simulation](../cases/sias-api-enumeration-simulation-20260916.md)
- [SIAS session-replay simulation](../cases/sias-session-replay-simulation-20260916.md)
- [SIAS file-disclosure simulation](../cases/sias-file-disclosure-simulation-20260916.md)
- [SIAS CSRF-style state-change simulation](../cases/sias-csrf-simulation-20260916.md)
- [SIAS webhook-authentication simulation](../cases/sias-webhook-auth-simulation-20260916.md)
- [SIAS connector host-binding simulation](../cases/sias-connector-host-binding-simulation-20260916.md)

## Windows and cloud detections

- [Encoded PowerShell](../cases/encoded-powershell.md)
- [Encoded PowerShell triage](../cases/encoded-powershell-triage-20260915.md)
- [PowerShell script-block triage](../cases/powershell-script-block-triage-20260915.md)
- [Sysmon dropped-file detection](../cases/sysmon-dropped-file.md)
- [Sysmon file-create coverage gap](../cases/sysmon-file-create-coverage-gap-20260915.md)
- [Windows Run-key persistence](../cases/windows-run-key-persistence-20260915.md)
- [Windows scheduled-task persistence](../cases/windows-scheduled-task-persistence-20260915.md)
- [Vercel runtime error](../cases/vercel-runtime-error.md)
- [SIAS/Vercel correlation](../cases/sias-vercel-correlation.md)

## How to use the cases

1. Reproduce the local canary or replay the sample event.
2. Validate the Wazuh rule, producer time, source, and outcome.
3. Pivot in Splunk using the validation search in the case.
4. State the disposition and the next containment or monitoring action.
