"""Checks the paper's reported figures against the 24 October 2026 snapshots.

The snapshots are not in the public repository, because the feed terms restrict redistribution and flagged
URLs can carry personal data. These tests are skipped wherever the author's local data directory is absent.
"""
from __future__ import annotations

import csv
import json
import sys
import unittest
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

import pipeline

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import rdap_followup  # noqa: E402

RAW = Path(pipeline.RAW_DATA_DIR)
URLHAUS = RAW / "urlhaus_20261024T151744.643288Z.json"
OPENPHISH = RAW / "openphish_20261024T151744.852386Z.txt"
PUBLISHED_EXPORT = Path(pipeline.PROCESSED_DATA_DIR) / "abuse_flags_20261024T151746Z.csv"
RDAP_FOLLOWUP = Path(pipeline.PROCESSED_DATA_DIR) / "rdap_followup_20261105.json"
RDAP_BACKFILLED = any((RAW / "rdap").glob("*_20261024T*.json"))


@unittest.skipUnless(URLHAUS.exists() and OPENPHISH.exists(), "24 October 2026 snapshots are not present")
class PublishedSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.result = pipeline.replay_from_snapshots(
            [URLHAUS, OPENPHISH],
            raw_row_limit=25,
            rule_version=pipeline.RULE_SET_EVENT_TIME_ONLY,
            output_dir=Path(temp.name),
        )
        cls.counts = cls.result["counts"]
        cls.rows = cls.result["rows"]

    def test_table_3_counts(self):
        self.assertEqual(self.counts["flagged_urls"], 26)
        self.assertEqual(self.counts["distinct_names"], 19)
        self.assertEqual(self.counts["by_feed"], {"OpenPhish": 25, "URLhaus": 1})
        self.assertEqual(self.counts["by_label"], {"Unverified": 17, "Possible_Maliciously_Registered": 9})
        self.assertEqual(self.counts["by_registrant_category"], {"Unknown": 25, "NonCommercial_Candidate": 1})
        self.assertEqual(self.counts["age_at_flag_known"], 0)
        self.assertEqual(self.counts["platform_tenant_rows"], 17)
        self.assertEqual(self.counts["registered_name_rows"], 9)

    def test_sampling_as_described(self):
        self.assertEqual(self.result["selection"][URLHAUS.name], {
            "feed_rows": 1000, "rows_considered": 25, "dropped_no_registrable_name": 24, "rows_selected": 1,
        })
        self.assertEqual(self.result["selection"][OPENPHISH.name], {
            "feed_rows": 300, "rows_considered": 25, "dropped_no_registrable_name": 0, "rows_selected": 25,
        })

    def test_labels_on_platform_tenants(self):
        tenant_labels = Counter(
            row["classification_label"] for row in self.rows if row["is_platform_tenant"]
        )
        self.assertEqual(tenant_labels["Possible_Maliciously_Registered"], 7)
        hosts = Counter(
            row["domain_name"] for row in self.rows
            if row["classification_label"] == "Possible_Maliciously_Registered"
        )
        self.assertEqual(hosts.most_common(1)[0][1], 5)

    @unittest.skipUnless(PUBLISHED_EXPORT.exists(), "the October export is not present")
    def test_replay_matches_the_published_export(self):
        with PUBLISHED_EXPORT.open(encoding="utf-8", newline="") as handle:
            published = {
                (row["source_feed"], pipeline.redact_email_addresses(row["flagged_url"])): row
                for row in csv.DictReader(handle)
            }
        replayed = {(row["source_feed"], row["flagged_url"]): row for row in self.rows}
        self.assertEqual(set(published), set(replayed))
        for key, row in published.items():
            for column in ("classification_label", "domain_name", "registrant_category", "classification_rule_version"):
                self.assertEqual(row[column], replayed[key][column], column)
            self.assertEqual(json.loads(row["triage_features"]), json.loads(replayed[key]["triage_features"]))

    @unittest.skipUnless(RDAP_BACKFILLED, "RDAP responses have not been backfilled")
    def test_rdap_figures(self):
        self.assertEqual(self.counts["creation_date_known"], 5)
        ages = sorted(
            row["domain_age_at_observation_days"] for row in self.rows
            if row["domain_age_at_observation_days"] is not None
        )
        self.assertEqual(ages[0], 2)
        self.assertEqual(ages[-1], 6918)
        statuses = {
            row["domain_name"]: json.loads(row["rdap_epp_statuses"]) for row in self.rows if row["creation_date"]
        }
        self.assertFalse(any("hold" in status for values in statuses.values() for status in values))
        add_period = [name for name, values in statuses.items() if "add period" in values]
        self.assertEqual(len(add_period), 2)

    @unittest.skipUnless(RDAP_BACKFILLED and RDAP_FOLLOWUP.exists(), "RDAP responses or follow-up results are not present")
    def test_three_of_the_five_dated_domains_were_on_hold_by_5_november(self):
        dated = {row["domain_name"] for row in self.rows if row["creation_date"]}
        result = rdap_followup.analyse(rdap_followup.load_saved_rows(RDAP_FOLLOWUP))
        on_hold = {entry["domain"] for entry in result["domains_on_hold"]}
        self.assertEqual(len(dated), 5)
        self.assertEqual(len(dated & on_hold), 3)


@unittest.skipUnless(URLHAUS.exists() and OPENPHISH.exists(), "24 October 2026 snapshots are not present")
class FullSnapshotTests(unittest.TestCase):
    def test_share_of_openphish_urls_under_a_private_suffix(self):
        items = pipeline.load_feed_items(OPENPHISH)
        hosts = [pipeline.parse_flagged_host(item["flagged_url"]) for item in items]
        self.assertEqual(len(items), 300)
        self.assertEqual(sum(1 for host in hosts if host.platform_basis == "psl_private"), 176)

    def test_urlhaus_composition(self):
        items = pipeline.load_feed_items(URLHAUS)
        hosts = [pipeline.parse_flagged_host(item["flagged_url"]) for item in items]
        registered = [host for host in hosts if host is not None]
        self.assertEqual(len(items), 1000)
        self.assertEqual(len(items) - len(registered), 36)
        self.assertEqual(sum(1 for host in registered if host.registrable_domain == "githubusercontent.com"), 962)

    def test_classifier_on_the_full_openphish_snapshot(self):
        labels = []
        tenant_labels = []
        for item in pipeline.load_feed_items(OPENPHISH):
            host = pipeline.parse_flagged_host(item["flagged_url"])
            label = pipeline.build_flag_record(item, host, None, pipeline.RULE_SET_EVENT_TIME_ONLY)["classification_label"]
            labels.append(label)
            if host.platform_basis == "psl_private":
                tenant_labels.append(label)
        self.assertEqual(labels.count("Possible_Maliciously_Registered"), 140)
        self.assertEqual(tenant_labels.count("Possible_Maliciously_Registered"), 133)

    def test_registrable_domains_queried_in_the_follow_up(self):
        self.assertEqual(len(rdap_followup.registrable_domains([URLHAUS, OPENPHISH])), 88)


@unittest.skipUnless(RDAP_FOLLOWUP.exists(), "the 5 November 2026 follow-up results are not present")
class FollowUpResultTests(unittest.TestCase):
    def test_figures_in_section_4(self):
        result = rdap_followup.analyse(rdap_followup.load_saved_rows(RDAP_FOLLOWUP))
        self.assertEqual(result["domains"], 88)
        self.assertEqual(result["answered"], 63)
        self.assertEqual(result["answered_with_registration_date"], 63)
        self.assertEqual(result["on_hold"], 14)
        self.assertEqual(result["by_age_at_snapshot"], {
            "<30d": {"domains": 21, "on_hold": 9},
            "30-180d": {"domains": 8, "on_hold": 3},
            ">180d": {"domains": 34, "on_hold": 2},
        })


if __name__ == "__main__":
    unittest.main()
