# SOC Lab Portfolio

[![Public safety scan](https://github.com/KubixDesiney/soc-lab-portfolio/actions/workflows/public-safety.yml/badge.svg)](https://github.com/KubixDesiney/soc-lab-portfolio/actions/workflows/public-safety.yml)  [![Collector self-tests](https://github.com/KubixDesiney/soc-lab-portfolio/actions/workflows/collector-self-test.yml/badge.svg)](https://github.com/KubixDesiney/soc-lab-portfolio/actions/workflows/collector-self-test.yml)

A small, reproducible security operations lab built for hands-on detection, triage, and incident response practice.

The lab uses Wazuh as the primary collector and detection engine. Sysmon supplies Windows process, network, file, registry, and DNS telemetry. Small pull-only collectors normalize SIAS, Supabase, and Vercel telemetry into a stable JSON event envelope. Splunk consumes only the de-duplicated high-severity handoff so it can be used for SPL searches, dashboards, and reporting without duplicating the complete Wazuh stream.

## Architecture

~~~mermaid
flowchart LR
  S[Windows + Sysmon] --> W[Wazuh manager and indexer]
  A[SIAS audit API] --> C[Local redacting collectors]
  B[Supabase operational API] --> C
  V[Vercel deployment events API] --> C
  C --> E[C:/SOC-Lab/events]
  E --> W
  W --> H[High-severity watcher]
  H --> F[high-severity.ndjson]
  F --> P[Splunk Free]
  P --> D[SOC - Wazuh Overview dashboard]
~~~

## What this demonstrates

- Writing focused Wazuh rules for PowerShell and Sysmon behavior.
- Collecting cloud application telemetry without putting provider credentials in the repository.
- Redacting and de-duplicating events before forwarding them.
- Using Splunk for SPL searches, trend views, and analyst reporting.
- Recording triage decisions with evidence and an explicit disposition.
- Tuning a false positive narrowly instead of suppressing an entire detection family.

## Repository map

- detections/ contains local Wazuh rules and safe agent configuration examples.
- collectors/ contains read-only SIAS, Supabase, and Vercel bridges.
- deploy/ contains credential-free Splunk and Wazuh examples.
- cases/ contains sanitized incident and detection-quality writeups.
- sample-data/ contains synthetic events for demonstrations.
- docs/ contains the analyst workflow, architecture notes, and the [case index](docs/case-index.md).

## Quick start

1. Install Wazuh and Sysmon on a disposable Windows host or VM using the vendors' current instructions.
2. Copy the example Wazuh rules and agent configuration into the local installation. Keep production configuration and certificates outside this repository.
3. Create local secret files under a protected directory such as C:/SOC-Secrets. Point the collectors at those files through environment variables or wrapper parameters.
4. Run each collector's self-test before supplying a real credential.
5. Start Splunk with deploy/splunk/docker-compose.free.yml and set SPLUNK_PASSWORD in a local environment file that is never committed.
6. Copy the example Splunk inputs and props files into Splunk's local configuration, then import deploy/splunk/soc_wazuh_overview.xml.
7. Use the queries in docs/analyst-workflow.md to validate collection, detection, triage, and disposition.

## Security boundaries

This repository is intentionally sanitized. It excludes passwords, API keys, service-account JSON, private keys, certificates, Docker volumes, generated state, raw alert exports, installer binaries, and live production telemetry.

The collectors are read-only toward provider APIs and write only a bounded, redacted event envelope to the local SOC event directory. Use least-privilege provider tokens, rotate them if exposure is suspected, and keep the Wazuh and Splunk interfaces bound to localhost while learning.

Do not expose a live Wazuh or Splunk console to the public internet. Screenshots should be redacted and synthetic data should be used in public examples.

## Portfolio note

This is a learning lab, not a production SOC. The case notes show the reasoning an analyst uses: validate the alert, identify the process or application context, correlate nearby telemetry, assess impact, and record a disposition.


## Interview materials

- docs/interview-walkthrough.md is a short live-demo script.
- docs/resume-ready-bullets.md contains project bullets that match the implementation.
- docs/portfolio-checklist.md covers the evidence to show in a review.


## Operational maturity

- docs/detection-catalog.md maps the local rule set to behaviors and MITRE techniques.
- docs/incident-response-playbook.md describes identification, containment, recovery, and closure.
- tests/test_collectors.py verifies normalization and credential redaction without network access.
- .github/workflows/collector-self-test.yml runs the same checks on every change.
