# Sysmon dropped-file false positive

Status: closed - narrowly tuned

A malware-oriented file-create rule matched Git copying a JSON documentation template into a temporary development workspace. The analyst verified the process, target extension, path, and authorized workflow. No executable was created and no follow-on execution or network activity appeared.

A narrow child rule preserves low-severity telemetry for this exact combination while leaving the original detection active for executable or script targets.

Lesson: tune on the smallest reliable behavior set. Keep the broad detection available for materially different targets.
