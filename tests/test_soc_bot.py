import unittest

import soc_bot


class ExtractFieldsTests(unittest.TestCase):
    def test_missing_nested_fields_are_safe(self):
        fields = soc_bot.extract_fields({"timestamp": "2026-10-01T10:00:00Z"})
        self.assertEqual(fields["agent"], "?")
        self.assertEqual(fields["rule_id"], "?")
        self.assertEqual(fields["srcip"], "-")
        self.assertEqual(fields["url"], "-")


class GroupAlertsTests(unittest.TestCase):
    def _alert(self, host, rule_id, srcip, url, timestamp):
        return {
            "timestamp": timestamp,
            "agent": {"name": host},
            "rule": {"id": rule_id, "level": 10, "description": "test"},
            "data": {"srcip": srcip, "url": url},
        }

    def test_same_rule_and_ip_on_different_hosts_do_not_merge(self):
        alerts = [
            self._alert("host-a", "100", "10.0.0.1", "/x", "2026-10-01T10:00:00Z"),
            self._alert("host-b", "100", "10.0.0.1", "/x", "2026-10-01T10:01:00Z"),
        ]
        groups = soc_bot.group_alerts(alerts)
        self.assertEqual(len(groups), 2)

    def test_same_host_rule_ip_and_url_merge_and_keep_latest(self):
        alerts = [
            self._alert("host-a", "100", "10.0.0.1", "/x", "2026-10-01T10:00:00Z"),
            self._alert("host-a", "100", "10.0.0.1", "/x", "2026-10-01T10:05:00Z"),
        ]
        groups = soc_bot.group_alerts(alerts)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 2)
        self.assertEqual(groups[0]["fields"]["time"], "2026-10-01T10:05:00Z")

    def test_different_urls_do_not_merge(self):
        alerts = [
            self._alert("host-a", "100", "10.0.0.1", "/a", "2026-10-01T10:00:00Z"),
            self._alert("host-a", "100", "10.0.0.1", "/b", "2026-10-01T10:01:00Z"),
        ]
        self.assertEqual(len(soc_bot.group_alerts(alerts)), 2)


class StructuredTriageTests(unittest.TestCase):
    VALID = (
        '{"summary":"test alert","severity":"Medium",'
        '"false_positive":"Unlikely","false_positive_reason":"matches the rule",'
        '"next_step":"review the source"}'
    )

    def test_valid_triage_json_is_accepted(self):
        result = soc_bot.parse_triage(self.VALID)
        self.assertEqual(result["severity"], "Medium")
        self.assertEqual(result["false_positive"], "Unlikely")

    def test_invalid_severity_is_rejected(self):
        raw = self.VALID.replace('"Medium"', '"Severe"')
        with self.assertRaises(ValueError):
            soc_bot.parse_triage(raw)

    def test_missing_field_is_rejected(self):
        raw = (
            '{"summary":"test alert","severity":"Medium",'
            '"false_positive":"Unlikely","next_step":"review"}'
        )
        with self.assertRaises(ValueError):
            soc_bot.parse_triage(raw)

    def test_formatter_preserves_existing_human_readable_shape(self):
        text = soc_bot.format_triage(soc_bot.parse_triage(self.VALID))
        self.assertIn("SUMMARY: test alert", text)
        self.assertIn("SEVERITY: Medium", text)
        self.assertIn("FALSE POSITIVE?: Unlikely", text)
        self.assertIn("NEXT STEP: review the source", text)


if __name__ == "__main__":
    unittest.main()
