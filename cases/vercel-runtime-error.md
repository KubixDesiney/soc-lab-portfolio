# Vercel runtime error

Status: open - application investigation example

A production deployment emitted a runtime error on the root route. The Vercel collector normalized the error, Wazuh raised the high-severity application rule, and Splunk grouped it with other application events.

The next analyst actions are to compare occurrences across deployments, check whether the route is still failing, review the deployment diff, and correlate authentication or data-access anomalies. This is an application reliability signal until evidence shows abuse or compromise.

Lesson: application errors need scope and impact analysis before they become security incidents.
