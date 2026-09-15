# Security policy

## Credential handling

Never commit passwords, API tokens, service-account JSON, private keys, certificates, raw provider logs, or generated Wazuh/Splunk state. Store them in a protected local directory and pass only the file path or environment variable name to a collector.

If a credential may have been exposed:

1. Revoke or rotate it at the provider.
2. Check Git history and repository visibility.
3. Remove the material from every reachable commit if necessary.
4. Review provider and Wazuh audit logs for use.

## Safe demonstrations

Use synthetic events and disposable hosts for public demonstrations. Keep Wazuh and Splunk bound to localhost unless access is protected by a properly configured private network and authentication layer.

## Reporting

This repository is a training project. For a suspected issue in the repository, open a private security report with the maintainer rather than publishing credentials or sensitive telemetry in an issue.
