"""Tests for digest/windows_digest.py with Loki and Ollama replaced by fakes.

Run: python3 -m unittest discover -s tests
"""
import importlib.util
import json
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCENARIOS = json.loads((ROOT / "tests/scenarios.json").read_text())

spec = importlib.util.spec_from_file_location("windows_digest", ROOT / "digest/windows_digest.py")
digest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(digest)


def fake_counts(case):
    tables = {"24h": case["c24"], "7d": case["c7"]}
    return lambda window: {(eid, ch): float(n) for eid, ch, n in tables[window]}


class FactsAndSeverityFloor(unittest.TestCase):
    def test_scenarios(self):
        for case in SCENARIOS["facts"]:
            with self.subTest(case["name"]), \
                    mock.patch.object(digest, "counts", fake_counts(case)), \
                    mock.patch.object(digest, "history_days", return_value=case["history_days"]), \
                    mock.patch.object(digest, "loki_range", return_value=[]):
                facts = digest.build_facts()
                floor, reasons, checks = digest.severity_floor(facts)
                exp = case["expected"]
                self.assertEqual(floor, exp["floor"])
                self.assertEqual(reasons, exp["reasons"])
                self.assertEqual(checks, exp["checks"])
                self.assertEqual([r["event_id"] for r in facts["event_counts"] if r["spike"]], exp["spikes"])
                self.assertEqual(facts["baseline_days"], exp["baseline_days"])

    def test_unknown_event_is_named_other(self):
        case = next(c for c in SCENARIOS["facts"] if c["name"] == "unknown event IDs are named other")
        with mock.patch.object(digest, "counts", fake_counts(case)), \
                mock.patch.object(digest, "history_days", return_value=7), \
                mock.patch.object(digest, "loki_range", return_value=[]):
            self.assertEqual(digest.build_facts()["event_counts"][0]["name"], "other")

    def test_notable_events_are_newest_first_and_capped(self):
        values = [[str(i), json.dumps({"timeCreated": f"2026-09-25T10:{i:02d}:00Z", "message": "m" * 300})]
                  for i in range(30)]
        streams = [{"stream": {"event_id": "4720"}, "values": values},
                   {"stream": {"event_id": "7045"}, "values": [["1", "not json"]]}]
        with mock.patch.object(digest, "counts", return_value={}), \
                mock.patch.object(digest, "history_days", return_value=7), \
                mock.patch.object(digest, "loki_range", return_value=streams):
            notable = digest.build_facts()["notable_events"]
        self.assertEqual(len(notable), 25)
        self.assertEqual(notable[0]["time"], "2026-09-25T10:29:00Z")
        self.assertEqual(len(notable[0]["summary"]), 200)


class Finalize(unittest.TestCase):
    def run_main(self, case):
        pushed = []

        def fake_http(url, payload=None, timeout=60):
            if url.endswith("/api/generate"):
                return {"response": case["llm"]}
            if url.endswith("/loki/api/v1/push"):
                pushed.append(payload)
                return {}
            raise AssertionError(f"unexpected call: {url}")

        facts = {"event_counts": [], "notable_events": []}
        floor = (case["floor"], case["reasons"], case["rule_checks"])
        with mock.patch.object(digest, "build_facts", return_value=facts), \
                mock.patch.object(digest, "severity_floor", return_value=floor), \
                mock.patch.object(digest, "http", side_effect=fake_http), \
                mock.patch("builtins.print"):
            digest.main()
        self.assertEqual(len(pushed), 1)
        stream = pushed[0]["streams"][0]
        return stream["stream"], json.loads(stream["values"][0][1])

    def test_scenarios(self):
        for case in SCENARIOS["finalize"]:
            with self.subTest(case["name"]):
                labels, d = self.run_main(case)
                exp = case["expected"]
                self.assertEqual(d["severity"], exp["severity"])
                self.assertEqual(labels, {"job": "ai_digest", "source": "script", "severity": exp["severity"]})
                self.assertEqual(d["headline"], exp["headline"])
                self.assertEqual(d["recommended_checks"], exp["checks"])
                self.assertIsInstance(d["findings"], list)

    def test_ollama_down_still_publishes_facts(self):
        pushed = []

        def fake_http(url, payload=None, timeout=60):
            if url.endswith("/api/generate"):
                raise OSError("connection refused")
            pushed.append(payload)
            return {}

        floor = ("investigate", ["Security log cleared (1x in 24h)"], ["Check A"])
        with mock.patch.object(digest, "build_facts", return_value={"event_counts": [], "notable_events": []}), \
                mock.patch.object(digest, "severity_floor", return_value=floor), \
                mock.patch.object(digest, "http", side_effect=fake_http), \
                mock.patch("builtins.print"):
            digest.main()
        d = json.loads(pushed[0]["streams"][0]["values"][0][1])
        self.assertEqual(d["severity"], "investigate")
        self.assertEqual(d["headline"], "Security log cleared (1x in 24h)")


if __name__ == "__main__":
    unittest.main()
