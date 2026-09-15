# Analyst workflow

Use the same sequence for every alert:

1. Validate the rule, severity, timestamp, agent, and source.
2. Read the full event fields that explain what happened: process image, command line, parent, user, route, deployment, or actor.
3. Correlate nearby process, network, file, registry, DNS, and application events.
4. Decide whether the behavior is expected, suspicious, or confirmed malicious.
5. Assess impact and choose a disposition: close, monitor, contain, or escalate.
6. Record the evidence and the next action in a case note.

## Practice searches

~~~text
index=main sourcetype=soc:wazuh:alert
| stats count by rule_id, rule_level, rule_description
| sort - count
~~~

~~~text
index=main sourcetype=soc:wazuh:alert rule_id=100521
| table _time timestamp agent agent_id rule_id rule_level rule_description image script_block
~~~

~~~text
index=main sourcetype=soc:wazuh:alert (source=sias OR source=vercel OR source=supabase)
| stats count by source, event_type, outcome, severity
~~~

For Wazuh Discover, start with rule level 12 or higher and then pivot on the rule-specific fields. Treat producer time and ingestion time separately when reviewing cloud telemetry.
