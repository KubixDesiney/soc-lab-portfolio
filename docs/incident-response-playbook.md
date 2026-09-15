# Incident-response playbook

This playbook is for the local learning lab. Use it to practice the reasoning and evidence collection that precede a containment decision.

## Preparation

- Keep Wazuh and Splunk bound to localhost.
- Confirm the affected agent, application, and environment.
- Keep credentials in protected local files.
- Record the UTC time window before searching.

## Identification and triage

1. Validate the rule, severity, source, and ingestion time.
2. Inspect the rule-specific evidence: command line and parent for PowerShell; route and deployment for Vercel; actor, target, and outcome for SIAS; table and status for Supabase.
3. Correlate a narrow window of process, network, file, registry, DNS, and application events.
4. Separate synthetic lab activity, reliability failures, false positives, and suspicious behavior.
5. Record the evidence, impact assessment, and current confidence.

## Containment

Contain only when the evidence supports an active compromise or material risk. In the lab, containment can mean stopping a disposable test process, disconnecting a disposable endpoint, or disabling a test integration. Do not delete evidence before recording it.

## Eradication and recovery

For a confirmed lab compromise, preserve the case note, rotate any test credentials, rebuild the disposable host from a known-good image, restore the collectors, and validate the detection path again.

## Closure

Every case should end with:

- a disposition and reason;
- the evidence that supports it;
- the detection or tuning change, if any;
- a follow-up action;
- a short lesson learned.

Do not label a synthetic event as a production incident. The value of the exercise is the repeatable decision process.
