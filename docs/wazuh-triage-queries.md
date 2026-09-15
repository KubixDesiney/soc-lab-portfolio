# Wazuh SOC triage queries

Use these in Wazuh Discover against `wazuh-alerts-*`. Set the time window first, then paste one query into the search bar.

## High severity queue

```text
rule.level >= 12 AND NOT data.message:"synthetic SOC training event"
```

## Encoded or obfuscated PowerShell

```text
rule.id:100521
```

Review `data.win.eventdata.image`, `data.win.eventdata.commandLine`, `data.win.eventdata.parentImage`, `data.win.eventdata.user`, and the timestamp.

## SIAS failed high-severity events

```text
rule.id:100503 OR rule.id:100505
```

## Vercel high-severity runtime errors

```text
rule.id:100508 OR rule.id:100510
```

## Supabase high-severity backend events

```text
rule.id:100513 OR rule.id:100515
```

For Supabase alerts, keep both `timestamp` (Wazuh ingestion time) and `data.event_time` (producer time) visible. A large batch with old `data.event_time` values is likely backfill or replay and needs separate data-quality triage.

## Normal Sysmon process telemetry

```text
rule.id:100516
```

This is a hunting view. It is expected to include routine PowerShell, Codex, Git, and Windows activity; use it to compare a suspicious event with its parent process, user, path, and command line.
