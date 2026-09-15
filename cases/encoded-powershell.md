# Encoded PowerShell detection

Status: closed - benign lab test

A controlled PowerShell process used an encoded command that only printed a lab marker. Wazuh rule 100521 fired at level 12 on the Windows lab endpoint and the high-severity watcher forwarded the alert to Splunk.

The analyst validated the image and endpoint, checked the surrounding telemetry, confirmed there was no download, persistence, credential access, or external communication, and closed the event as authorized training activity. The rule stayed enabled because the detection and forwarding path worked correctly.

Lesson: an encoded command is a strong lead, not a final verdict. Decode or recover the command, inspect the parent and user, and correlate network and file activity before containment.
