# SIAS role-change telemetry

Status: closed - expected development test

A SIAS development event reported a failed user role-change action and triggered the high-severity application rule. A separate successful alert-claim event was unrelated to the role change.

The analyst compared producer time with Wazuh ingestion time, validated the development environment, and found no successful role change or confirmed impact. The event was closed as an expected bridge test.

Lesson: compare event type, outcome, environment, and timing before treating a high-severity application event as a compromise.
