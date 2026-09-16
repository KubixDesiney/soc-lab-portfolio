# Cross-source application incident drill

Status: closed - authorized development simulation with one local endpoint canary

## Scenario

An analyst sees an authentication-failure burst from one source, a Vercel runtime error on an administrative route, and a Windows Sysmon executable drop minutes apart. The exercise tests whether the signals can be joined before deciding whether to contain the account or the host.

The SIAS and Vercel records carry the shared incident ID `IR-20260916-APP-01`. The Windows signal is correlated by agent, rule, timestamp, and target path.

## Safety

The SIAS and Vercel records are synthetic development telemetry. The Windows signal came from writing an inert text file with an `.exe` suffix in a disposable temporary directory; the file was removed after Wazuh recorded the event. No code was executed, no deployment changed, and no production request was sent.

## Timeline and evidence

| Time (local) | Source | Evidence | Detection |
| --- | --- | --- | --- |
| 10:33:22 | Windows `KUBIX-WIN11` | Sysmon Event ID `11`; PowerShell created a temporary `stage.exe` canary | Rule `92213`, level `15` |
| 10:34:35 | Vercel | Runtime error on `/api/admin`, synthetic deployment `deployment-ir-app01` | Rule `100508`, level `12` |
| 10:35:37 | SIAS | 12 authentication failures for one fingerprint in 5 minutes on `/login` | Rule `100503`, level `12` |

The SIAS event ID is `sias-ir-app01-auth-surge-b0f5d9a3`. The Vercel event ID is `vercel-ir-app01-runtime-860727d4`. The endpoint alert retained the target path, image, user, process ID, and Sysmon channel in Wazuh and Splunk.

## Correlation search

```spl
index=main sourcetype=soc:wazuh:alert earliest=-30m
(incident_id="IR-20260916-APP-01" OR (rule_id=92213 AND agent="KUBIX-WIN11"))
| eval drill=if(incident_id="IR-20260916-APP-01","IR-20260916-APP-01","endpoint-correlated-by-time")
| table _time drill event_id event_type action outcome severity incident_id route fingerprint count window_min rule_id rule_level rule_description image targetFilename process_id user
| sort _time
```

The SIAS and Vercel rows share the incident ID. The Windows row is joined by its high-confidence endpoint detection, host identity, and time proximity; it has no synthetic incident ID because it came from the operating system event channel.

## Analyst decision

Disposition: escalate for investigation in a real environment. The combination is more concerning than any single signal: authentication abuse, an administrative-route failure, and an executable drop on the monitored host. The next actions would be to preserve endpoint and application timelines, disable or challenge the source account, isolate the host if the executable is unknown, inspect process ancestry and network connections, and confirm whether the Vercel error was an unrelated deployment issue. In this lab the disposition is closed as expected test activity.
