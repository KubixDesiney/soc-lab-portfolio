# Windows scheduled-task persistence validation

Status: verified - Task Scheduler telemetry is visible in Wazuh

## Scenario

The lab created a one-time `ONLOGON` task named `\\SOC-Lab\\SOC-Lab-Validation-8e4a27d0` with the inert action `cmd.exe /c exit 0`. The task was created only for telemetry validation, was never triggered, and was deleted immediately after the event was confirmed.

## Evidence

Wazuh received the Task Scheduler event at `2026-09-15T18:06:55.708Z`:

- Windows channel: `Microsoft-Windows-TaskScheduler/Operational`
- Event ID: `106` (task registered)
- Wazuh rule: `67014`, level `3`
- Agent: `KUBIX-WIN11` (`003`)
- Message: user `DREAMKEEPER\\21652` registered the task

The Task Scheduler Operational channel was previously disabled. It was enabled, added to the Wazuh agent's event-channel inputs, and the Wazuh service was restarted. After verification, the task query returned “file not found,” confirming cleanup.

## Analyst decisions

1. Treat a new task registration as a persistence lead and record the task path, author, trigger, action, run level, and creation time.
2. Inspect the referenced executable or script, signer, hash, parent process, and user context.
3. Check whether the trigger is `ONLOGON`, `ONSTART`, a time schedule, or an event subscription, and identify affected accounts.
4. Correlate task creation with process, file, PowerShell, network, and authentication events.
5. Preserve task XML and referenced files in a real incident; disable or remove only under the approved response plan.

## Lab lesson

Persistence coverage depends on both the event source and the collector configuration. Enabling the Windows channel and adding it to Wazuh produced a source event, normalized alert, and repeatable cleanup workflow without executing the payload.
