# Splunk handoff

Wazuh is the primary collector and detection engine. Splunk is used as a secondary search and dashboard layer over the local, de-duplicated high-severity handoff.

The compose example binds Splunk to localhost and expects a local SPLUNK_PASSWORD environment variable. Do not place that value in this repository.

The dashboard file is deploy/splunk/soc_wazuh_overview.xml. The example input and field extraction files are in deploy/splunk/config.

Example SPL:

~~~text
index=main sourcetype=soc:wazuh:alert
| stats count by rule_id, rule_level, rule_description
| sort - count
~~~

Focused PowerShell review:

~~~text
index=main sourcetype=soc:wazuh:alert rule_id=100521
| table _time timestamp agent agent_id rule_id rule_level rule_description image script_block
~~~

Executable-drop review with the normalized file path:

~~~text
index=main sourcetype=soc:wazuh:alert rule_id=92213
| table _time timestamp agent agent_id rule_id rule_level rule_description image targetFilename target alert_key
~~~

The local `props.conf` example maps the watcher's legacy `target` field into `targetFilename` at search time, so existing alerts remain usable while new events carry both names.

Keep the high-severity handoff file read-only and small. Do not send the full Wazuh index or production telemetry to a public Splunk instance.
