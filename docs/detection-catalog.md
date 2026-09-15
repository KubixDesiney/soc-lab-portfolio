# Detection catalog

| Rule | Level | Signal | MITRE mapping |
| --- | ---: | --- | --- |
| 100516 | 3 | Sysmon process creation telemetry | |
| 100517 | 3 | Sysmon network connection telemetry | |
| 100518 | 3 | Sysmon file creation telemetry | |
| 100519 | 3 | Sysmon registry telemetry | |
| 100520 | 3 | Sysmon DNS telemetry | |
| 100521 | 12 | Encoded or obfuscated PowerShell process | T1059.001 |
| 100522 | 12 | High-risk PowerShell script block | T1059.001, T1105 |
| 100503 | 12 | SIAS high-severity application event | |
| 100513 | 12 | Supabase high-severity operational event | |
| 100508 | 12 | Vercel high-severity runtime error | |
| 100523 | 3 | Narrow known Git JSON-copy false-positive child rule | |

## Tuning standard

A rule should identify a behavior with enough context to investigate. A tuning change should document the original signal, the exact benign combination, the replacement severity, and the test that proves materially different targets still alert.

Do not lower an alert solely because it is noisy. First add process, user, path, outcome, environment, or correlation conditions that make the benign workflow specific.
