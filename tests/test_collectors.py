import unittest

from collectors import sias_collector
from collectors import supabase_collector
from collectors import vercel_collector


class CollectorNormalizationTests(unittest.TestCase):
    def test_sias_failure_is_high(self):
        event = sias_collector.normalize_record(
            "demo-key",
            {
                "at": "2026-01-15T12:00:00Z",
                "action": "account.role_change",
                "actorId": "demo-operator",
                "targetId": "demo-user",
                "outcome": "failure",
            },
            "development",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["source"], "sias")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["event_id"], "sias-audit-demo-key")

    def test_supabase_rejected_action_is_high(self):
        event = supabase_collector.normalize_record(
            "agent_actions",
            {
                "id": "demo-action",
                "agent_id": "demo-agent",
                "status": "rejected",
                "risk": "high",
                "title": "Synthetic action",
                "created_at": "2026-01-15T12:00:00Z",
            },
            "production",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["source"], "supabase")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["record_id"], "demo-action")

    def test_vercel_error_is_high(self):
        event = vercel_collector.normalize_event(
            "deployment-demo",
            "example.vercel.app",
            {
                "timestamp": "2026-01-15T12:00:00Z",
                "level": "error",
                "text": "Synthetic application error",
                "route": "/",
            },
            "production",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["source"], "vercel")
        self.assertEqual(event["event_type"], "runtime.error")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["outcome"], "failure")
        self.assertEqual(event["deployment_id"], "deployment-demo")

    def test_provider_credential_values_are_redacted(self):
        self.assertIn("[redacted]", supabase_collector.clean("Bearer secret-value"))
        self.assertIn("[redacted]", vercel_collector.clean("VERCEL_TOKEN" + "=secret-value"))


if __name__ == "__main__":
    unittest.main()

