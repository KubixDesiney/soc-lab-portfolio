# Wazuh deployment notes

Install Wazuh and Sysmon on a disposable Windows host or VM using the current vendor instructions. Copy detections/local_rules.xml into the manager rules directory and validate the manager configuration before reloading it.

The example agent configuration watches a local SOC event directory:

~~~xml
<localfile>
  <location>C:/SOC-Lab/events/*.json</location>
  <log_format>json</log_format>
  <only-future-events>no</only-future-events>
</localfile>
~~~

For Windows persistence practice, enable the Task Scheduler Operational channel and add it to the agent configuration:

~~~xml
<localfile>
  <location>Microsoft-Windows-TaskScheduler/Operational</location>
  <log_format>eventchannel</log_format>
  <only-future-events>yes</only-future-events>
</localfile>
~~~

The channel is disabled by default on some Windows installations. Enable it before testing scheduled-task detections, then restart the Wazuh agent so the new input is active.

Keep Wazuh certificates, passwords, API credentials, index data, and generated alerts on the host. They are intentionally absent from this repository.

The rule set includes low-noise Sysmon telemetry, focused PowerShell detections, and application rules for SIAS, Supabase, and Vercel. Review and adapt rule IDs to the Wazuh version running in your lab.
