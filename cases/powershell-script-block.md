# PowerShell script-block false positive

Status: closed - detection-quality review

A level-12 script-block alert matched the text of a harmless test comment. The analyst verified the PowerShell Operational event, inspected the script block, and checked the nearby Sysmon window for process, network, file, registry, and DNS activity.

No action was executed and no impact was observed. The event was closed as an authorized lab test. The rule remains active, with future escalation based on behavior and correlation rather than a phrase alone.

Lesson: string matches inside a script or search expression can create false positives. Preserve the signal and improve context before suppressing it.
