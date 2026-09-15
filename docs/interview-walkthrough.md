# Interview walkthrough

Use this as a five-to-ten-minute demonstration of the lab.

## 1. Explain the architecture

Start with the README diagram. Explain that Wazuh is the primary collector and detector, while Splunk receives only a de-duplicated high-severity handoff for search and reporting.

## 2. Show a detection

Open the PowerShell case in cases/encoded-powershell.md. Point out the rule ID, severity, endpoint, process image, and the fact that the event was a controlled lab test.

## 3. Show the analyst reasoning

Describe the validation sequence:

- confirm the source and endpoint;
- inspect the command, parent, user, and timestamp;
- correlate nearby process, network, file, registry, and DNS events;
- assess impact;
- record a disposition.

## 4. Show the dashboard

Open the local SOC - Wazuh Overview dashboard. Show alert counts by rule, the trend panel, and the recent evidence table. Explain that the dashboard is backed by a read-only handoff file and does not replace Wazuh's full event record.

## 5. Show detection quality work

Open cases/sysmon-dropped-file.md. Explain why the original file-drop rule was noisy and how the child rule narrowed the known Git documentation workflow while preserving coverage for executable targets.

## 6. State the security boundaries

Credentials, certificates, raw alerts, generated state, and production telemetry remain on the local host. The public repository contains examples and synthetic data only. The public-safety workflow and GitHub secret scanning protect future changes.

## Questions to expect

- Why use both Wazuh and Splunk? Wazuh handles endpoint collection and detection; Splunk provides a familiar search and reporting workflow over a deliberately small stream.
- How would you escalate the PowerShell alert? Recover the full command, inspect process lineage and user context, check network and persistence activity, then contain only when evidence supports it.
- How do you avoid false positives? Use narrow behavioral conditions and correlation, then document the tuning decision.
- How are cloud credentials protected? Read-only tokens are supplied at runtime from protected local files and never written to Git or event output.
