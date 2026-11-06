from __future__ import annotations

import asyncio
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pipeline
from test_pipeline import FakeResponse, FakeSession, PatchedDataDirs, T0, rdap_body

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import rdap_followup  # noqa: E402


class FakeClientSession(FakeSession):
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class AnalysisTests(unittest.TestCase):
    def test_age_bucket_boundaries(self):
        cases = {0: "<30d", 29: "<30d", 30: "30-180d", 180: "30-180d", 181: ">180d"}
        for age, bucket in cases.items():
            self.assertEqual(rdap_followup.age_bucket(age), bucket)

    def test_hold_statuses_in_either_spelling(self):
        for status in ("server hold", "client hold", "serverHold", "clientHold"):
            self.assertTrue(rdap_followup.on_hold({"epp": [status]}), status)
        self.assertFalse(rdap_followup.on_hold({"epp": ["active", "client transfer prohibited"]}))
        self.assertFalse(rdap_followup.on_hold({}))

    def test_analysis_counts_holds_by_age_and_failures_by_tld(self):
        rows = [
            {"domain": "new.com", "tld": "com", "in_bootstrap": True, "status": 200, "age_at_snapshot_days": 2, "epp": ["server hold"]},
            {"domain": "mid.com", "tld": "com", "in_bootstrap": True, "status": 200, "age_at_snapshot_days": 100, "epp": ["active"]},
            {"domain": "old.org", "tld": "org", "in_bootstrap": True, "status": 200, "age_at_snapshot_days": 900, "epp": ["client hold"]},
            {"domain": "gone.io", "tld": "io", "in_bootstrap": False, "status": 404, "epp": []},
            {"domain": "down.nl", "tld": "nl", "in_bootstrap": False, "status": "ERR:URLError"},
        ]
        result = rdap_followup.analyse(rows)
        self.assertEqual(result["domains"], 5)
        self.assertEqual(result["tld_in_iana_bootstrap"], 3)
        self.assertEqual(result["answered"], 3)
        self.assertEqual(result["answered_with_registration_date"], 3)
        self.assertEqual(result["on_hold"], 2)
        self.assertEqual(result["by_age_at_snapshot"], {
            "<30d": {"domains": 1, "on_hold": 1},
            "30-180d": {"domains": 1, "on_hold": 0},
            ">180d": {"domains": 1, "on_hold": 1},
        })
        self.assertEqual(result["failures_by_tld"], {"io": 1, "nl": 1})
        self.assertEqual([entry["domain"] for entry in result["domains_on_hold"]], ["new.com", "old.org"])


class SavedRunTests(PatchedDataDirs):
    def test_saved_runs_load_in_both_formats(self):
        rows = [{"domain": "a.com"}]
        bare = self.root / "bare.json"
        bare.write_text(json.dumps(rows), encoding="utf-8")
        wrapped = self.root / "wrapped.json"
        wrapped.write_text(json.dumps({"domains": rows}), encoding="utf-8")
        self.assertEqual(rdap_followup.load_saved_rows(bare), rows)
        self.assertEqual(rdap_followup.load_saved_rows(wrapped), rows)


class CollectionTests(PatchedDataDirs):
    def setUp(self):
        super().setUp()
        self.openphish = pipeline.save_raw_snapshot(
            "openphish",
            b"https://abc.vercel.app/phish\nhttps://shop.example.com/login\nhttps://shop.example.com/other\n",
            ".txt", retrieved_at=T0,
        )
        urlhaus = {"query_status": "ok", "urls": [
            {"id": 1, "url": "http://192.0.2.1/x", "date_added": "2026-10-24 12:00:00 UTC"},
            {"id": 2, "url": "https://shop.example.com/payload", "date_added": "2026-10-24 12:00:00 UTC"},
        ]}
        self.urlhaus = pipeline.save_raw_snapshot(
            "urlhaus", json.dumps(urlhaus).encode("utf-8"), ".json", retrieved_at=T0
        )

    def test_domains_are_the_registered_names_with_their_feeds(self):
        self.assertEqual(
            rdap_followup.registrable_domains([self.urlhaus, self.openphish]),
            {"example.com": ["OpenPhish", "URLhaus"], "vercel.app": ["OpenPhish"]},
        )

    def test_run_contacts_rdap_services_only_and_saves_its_results(self):
        session = FakeClientSession({
            pipeline.IANA_RDAP_BOOTSTRAP_URL: FakeResponse(200, json.dumps({
                "services": [[["com"], ["https://rdap.example/"]]]
            }).encode("utf-8")),
            "https://rdap.example/domain/example.com": FakeResponse(
                200, rdap_body(created="2026-10-22T00:00:00Z", statuses=["server hold"])
            ),
            "https://rdap.org/domain/vercel.app": FakeResponse(404, b""),
        })
        output_dir = self.root / "out"
        with patch.object(rdap_followup.aiohttp, "ClientSession", lambda **kwargs: session):
            rdap_followup.main(["--output-dir", str(output_dir)])

        requested = {url for url, _ in session.requests}
        self.assertEqual(requested, {
            pipeline.IANA_RDAP_BOOTSTRAP_URL,
            "https://rdap.example/domain/example.com",
            "https://rdap.org/domain/vercel.app",
        })
        self.assertFalse(any(flagged in url for url in requested for flagged in ("abc.vercel.app", "shop.example.com", "192.0.2.1")))

        saved = json.loads(next(output_dir.glob("rdap_followup_*.json")).read_text(encoding="utf-8"))
        self.assertEqual(saved["reference_time"], T0.isoformat())
        rows = {row["domain"]: row for row in saved["domains"]}
        self.assertEqual(rows["example.com"]["status"], 200)
        self.assertEqual(rows["example.com"]["age_at_snapshot_days"], 2)
        self.assertEqual(rows["example.com"]["epp"], ["server hold"])
        self.assertTrue(rows["example.com"]["in_bootstrap"])
        self.assertEqual(rows["vercel.app"]["status"], 404)
        self.assertEqual(rows["vercel.app"]["lookup_status"], "not_found")
        self.assertIsNone(rows["vercel.app"]["age_at_snapshot_days"])
        self.assertEqual(rdap_followup.analyse(saved["domains"])["on_hold"], 1)
        self.assertTrue(list((self.raw_dir / "rdap").glob("example.com_*.json")))

    def test_earliest_snapshot_sets_the_reference_time(self):
        later = pipeline.save_raw_snapshot("openphish", b"", ".txt", retrieved_at=datetime(2026, 11, 1, tzinfo=timezone.utc))
        self.assertEqual(rdap_followup.reference_time_of([later, self.openphish]), T0)

    def test_no_network_needed_to_re_report_a_saved_run(self):
        saved = self.root / "saved.json"
        saved.write_text(json.dumps([
            {"domain": "a.com", "tld": "com", "in_bootstrap": True, "status": 200, "age_at_snapshot_days": 1, "epp": []}
        ]), encoding="utf-8")
        with patch.object(rdap_followup.aiohttp, "ClientSession", side_effect=AssertionError("network used")), \
                patch("builtins.print") as printed:
            rdap_followup.main(["--analyze", str(saved)])
        self.assertEqual(json.loads(printed.call_args.args[0])["answered"], 1)


if __name__ == "__main__":
    unittest.main()
