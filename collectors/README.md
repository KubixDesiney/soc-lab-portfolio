# Read-only telemetry collectors

Each Python collector accepts provider credentials through the process environment or a file path outside the repository. It emits a bounded, redacted JSON-lines event envelope for the local Wazuh agent.

Run the offline self-tests first:

~~~text
python collectors/sias_collector.py --self-test
python collectors/supabase_collector.py --self-test
python collectors/vercel_collector.py --self-test
~~~

Examples for real polling:

~~~text
powershell -ExecutionPolicy Bypass -File collectors/run-sias-collector.example.ps1 -ServiceAccountFile C:/SOC-Secrets/sias-reader.json
powershell -ExecutionPolicy Bypass -File collectors/run-supabase-collector.example.ps1 -KeyFile C:/SOC-Secrets/supabase-reader.txt -ProjectUrl https://your-project.supabase.co
powershell -ExecutionPolicy Bypass -File collectors/run-vercel-collector.example.ps1 -TokenFile C:/SOC-Secrets/vercel-readonly.txt -ProjectId prj_example
~~~

Use provider tokens with read-only scope. Keep cursor files, event files, and credentials under the local SOC directory, outside the Git repository. Do not paste live event output into public issues or pull requests.
