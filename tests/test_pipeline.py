from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import re
import tomllib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pipeline

T0 = datetime(2026, 10, 24, 15, 0, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, status: int = 200, body: bytes = b"{}"):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def raise_for_status(self):
        return None

    async def read(self):
        return self._body

    async def json(self, **kwargs):
        return json.loads(self._body)


class FakeSession:
    """Answers from a URL map and records what was requested. Exceptions in the map are raised."""

    def __init__(self, responses: dict | None = None):
        self.responses = responses or {}
        self.requests: list[tuple[str, float]] = []

    def get(self, url, **kwargs):
        self.requests.append((url, asyncio.get_running_loop().time()))
        response = self.responses.get(url, FakeResponse(404, b""))
        if isinstance(response, Exception):
            raise response
        return response


def rdap_body(created: str = "2020-01-01T00:00:00Z", statuses: list[str] | None = None) -> bytes:
    return json.dumps({
        "status": statuses if statuses is not None else ["active"],
        "events": [{"eventAction": "registration", "eventDate": created}],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
        }],
    }).encode("utf-8")


def feed_item(url: str, flagged_at=None, observed_at=T0, snapshot="openphish_a.txt") -> dict:
    return {
        "source_feed": "OpenPhish",
        "threat_type": "Phishing",
        "flagged_url": url,
        "flagged_at": flagged_at,
        "observed_at": observed_at,
        "source_record_id": None,
        "raw_snapshot": snapshot,
        "source_url": "https://example.test/feed.txt",
        "timestamp_basis": "collection_time_no_feed_timestamp",
    }


class PatchedDataDirs(unittest.TestCase):
    """Runs each test against temporary data directories."""

    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.raw_dir = self.root / "raw"
        self.processed_dir = self.root / "processed"
        for name, value in (
            ("RAW_DATA_DIR", self.raw_dir),
            ("PROCESSED_DATA_DIR", self.processed_dir),
            ("PROJECT_ROOT", self.root),
        ):
            patcher = patch.object(pipeline, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)


class PipelineResearchTests(PatchedDataDirs):
    def test_openphish_timestamp_not_fabricated_as_event_time(self):
        with patch.object(pipeline, "OPENPHISH_FEED_URL", "https://example.test/feed.txt"):
            session = FakeSession({"https://example.test/feed.txt": FakeResponse(200, b"https://malware.example/path\n")})
            items = asyncio.run(pipeline.fetch_openphish_feed(session))
        self.assertEqual(len(items), 1)
        self.assertIsNone(items[0]["flagged_at"])
        self.assertIsNotNone(items[0]["observed_at"])
        self.assertEqual(items[0]["timestamp_basis"], "collection_time_no_feed_timestamp")

    def test_observation_key_is_deterministic_and_feed_specific(self):
        url = "https://example.test/path"
        key = pipeline.make_observation_key("OpenPhish", url)
        self.assertEqual(key, pipeline.make_observation_key("OpenPhish", url))
        self.assertNotEqual(key, pipeline.make_observation_key("URLhaus", url))

    def test_url_repeated_within_a_snapshot_is_one_row(self):
        openphish = pipeline.parse_openphish_body(
            b"https://a.example/x\nhttps://a.example/x\nhttps://b.example/y\nnot-a-url\n", "s.txt", T0
        )
        self.assertEqual([item["flagged_url"] for item in openphish], ["https://a.example/x", "https://b.example/y"])

        urlhaus = pipeline.parse_urlhaus_body(
            json.dumps({"query_status": "ok", "urls": [
                {"id": 1, "url": "https://a.example/x", "date_added": "2026-10-24 12:00:00 UTC"},
                {"id": 2, "url": "https://a.example/x", "date_added": "2026-10-24 12:00:00 UTC"},
            ]}).encode("utf-8"),
            "s.json", T0,
        )
        self.assertEqual(len(urlhaus), 1)

    def test_all_rows_of_a_snapshot_share_its_retrieval_time(self):
        items = pipeline.parse_urlhaus_body(
            json.dumps({"query_status": "ok", "urls": [
                {"id": 1, "url": "https://a.example/x", "date_added": "2026-10-24 12:00:00 UTC"},
                {"id": 2, "url": "https://b.example/y", "date_added": "not a date"},
            ]}).encode("utf-8"),
            "s.json", T0,
        )
        self.assertEqual({item["observed_at"] for item in items}, {T0})
        self.assertEqual(items[0]["flagged_at"], datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc))
        self.assertIsNone(items[1]["flagged_at"])

    def test_old_domain_and_deep_path_is_only_a_candidate(self):
        flagged = datetime(2026, 1, 1, tzinfo=timezone.utc)
        created = flagged - timedelta(days=400)
        label, age, probability = pipeline.classify_abuse_flag(
            "https://example.com/a/b", "example.com", "example", "com", flagged, created
        )
        self.assertEqual(label, "Possible_Compromised_Legitimate")
        self.assertEqual(age, 400)
        self.assertIsNone(probability)

    def test_missing_registration_date_keeps_age_unknown(self):
        label, age, probability = pipeline.classify_abuse_flag(
            "https://example.com/path", "example.com", "example", "com",
            datetime(2026, 1, 1, tzinfo=timezone.utc), None
        )
        self.assertEqual(label, "Unverified")
        self.assertIsNone(age)
        self.assertIsNone(probability)

    def test_noncommercial_category_is_only_a_candidate(self):
        self.assertEqual(
            pipeline.infer_registrant_category("example.org", "example", "org"),
            "NonCommercial_Candidate",
        )

    def test_triage_features_are_explainable(self):
        cues = pipeline.extract_triage_features(
            "https://example.com/wp-content/a/b", "example", 400
        )
        self.assertIn("registration_age_over_180d", cues)
        self.assertIn("url_path_depth_at_least_2", cues)
        self.assertIn("cms_like_path_token", cues)

    def test_schema_has_sightings_events_review_and_history_tables(self):
        schema = pipeline.SCHEMA_PATH.read_text(encoding="utf-8")
        self.assertIn("CREATE TABLE IF NOT EXISTS feed_observations", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS mitigation_events", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS review_annotations", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS rdap_observations", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS classification_history", schema)


class SnapshotTests(PatchedDataDirs):
    def test_raw_snapshot_manifest_has_hash_and_source(self):
        path = pipeline.save_raw_snapshot("openphish", b"sample", ".txt")
        manifest = path.with_suffix(path.suffix + ".manifest.json").read_text()
        self.assertIn(hashlib.sha256(b"sample").hexdigest(), manifest)
        self.assertIn('"source": "openphish"', manifest)

    def test_manifest_records_retrieval_time_not_file_time(self):
        path = pipeline.save_raw_snapshot("openphish", b"sample", ".txt", retrieved_at=T0)
        manifest = json.loads(path.with_suffix(path.suffix + ".manifest.json").read_text())
        self.assertEqual(manifest["fetched_at_utc"], T0.isoformat())
        self.assertIn("20261024T150000", path.name)

    def test_snapshot_loads_when_it_matches_its_manifest(self):
        path = pipeline.save_raw_snapshot("openphish", b"sample", ".txt", retrieved_at=T0)
        body, manifest = pipeline.load_verified_snapshot(path)
        self.assertEqual(body, b"sample")
        self.assertEqual(manifest["source"], "openphish")

    def test_altered_snapshot_is_rejected(self):
        path = pipeline.save_raw_snapshot("openphish", b"sample", ".txt", retrieved_at=T0)
        path.write_bytes(b"changed")
        with self.assertRaises(pipeline.SnapshotIntegrityError):
            pipeline.load_verified_snapshot(path)

    def test_snapshot_without_manifest_is_rejected(self):
        self.raw_dir.mkdir(parents=True)
        path = self.raw_dir / "openphish_x.txt"
        path.write_bytes(b"sample")
        with self.assertRaises(pipeline.SnapshotIntegrityError):
            pipeline.load_verified_snapshot(path)


class HostParsingTests(unittest.TestCase):
    def test_tenant_host_separates_the_tenant_from_the_registered_name(self):
        host = pipeline.parse_flagged_host("https://abc.vercel.app/x")
        self.assertEqual(host.flagged_name, "abc.vercel.app")
        self.assertEqual(host.registrable_domain, "vercel.app")
        self.assertEqual(host.sld, "abc")
        self.assertEqual(host.platform_basis, "psl_private")
        self.assertTrue(host.is_platform_tenant)

    def test_registered_name_is_not_a_tenant(self):
        host = pipeline.parse_flagged_host("https://www.example.org/x")
        self.assertEqual(host.flagged_name, "example.org")
        self.assertEqual(host.registrable_domain, "example.org")
        self.assertFalse(host.is_platform_tenant)

    def test_multi_label_public_suffix(self):
        host = pipeline.parse_flagged_host("https://www.example.co.uk/x")
        self.assertEqual(host.registrable_domain, "example.co.uk")
        self.assertFalse(host.is_platform_tenant)

    def test_platform_missing_from_the_bundled_suffix_list(self):
        host = pipeline.parse_flagged_host("https://a.webflow.io/x")
        self.assertEqual(host.flagged_name, "webflow.io")
        self.assertEqual(host.platform_basis, "curated_list")
        self.assertFalse(pipeline.parse_flagged_host("https://webflow.io/x").is_platform_tenant)

    def test_platform_apex_is_the_platforms_own_registered_name(self):
        host = pipeline.parse_flagged_host("https://vercel.app/x")
        self.assertEqual(host.flagged_name, "vercel.app")
        self.assertFalse(host.is_platform_tenant)

    def test_urls_without_a_registrable_name(self):
        for url in ("http://192.0.2.1/x", "http://[2001:db8::1]/x", "http://localhost/x", "http://[malformed/x"):
            self.assertIsNone(pipeline.parse_flagged_host(url), url)


class FeedSelectionTests(unittest.TestCase):
    def setUp(self):
        self.items = (
            [feed_item(f"http://192.0.2.{i}/x") for i in range(1, 25)]
            + [feed_item(f"https://site{i}.example.com/x") for i in range(3)]
        )

    def test_everything_is_kept_by_default(self):
        selected, counts = pipeline.select_feed_rows(self.items)
        self.assertEqual(len(selected), 3)
        self.assertEqual(counts, {
            "feed_rows": 27, "rows_considered": 27, "dropped_no_registrable_name": 24, "rows_selected": 3,
        })

    def test_raw_row_limit_applies_before_ip_hosts_are_removed(self):
        selected, counts = pipeline.select_feed_rows(self.items, raw_row_limit=25)
        self.assertEqual(len(selected), 1)
        self.assertEqual(counts["dropped_no_registrable_name"], 24)

    def test_limit_applies_after_ip_hosts_are_removed(self):
        selected, _ = pipeline.select_feed_rows(self.items, limit=2)
        self.assertEqual(len(selected), 2)
        self.assertTrue(all("example.com" in item["flagged_url"] for item in selected))


class AgeTests(unittest.TestCase):
    created = T0 - timedelta(days=400)
    registered = pipeline.parse_flagged_host("https://example.com/a/b")

    def test_row_without_feed_time_is_aged_from_collection_time(self):
        record = pipeline.build_flag_record(feed_item("https://example.com/a/b"), self.registered, self.created)
        self.assertIsNone(record["domain_age_at_flag_days"])
        self.assertEqual(record["domain_age_at_observation_days"], 400)
        self.assertEqual(record["classification_label"], "Possible_Compromised_Legitimate")
        self.assertIn("registration_age_over_180d", record["triage_features"])
        self.assertEqual(record["classification_rule_version"], pipeline.CLASSIFICATION_RULE_VERSION)

    def test_event_time_only_rules_reproduce_the_october_sample(self):
        record = pipeline.build_flag_record(
            feed_item("https://example.com/a/b"), self.registered, self.created, pipeline.RULE_SET_EVENT_TIME_ONLY
        )
        self.assertEqual(record["classification_label"], "Unverified")
        self.assertNotIn("registration_age_over_180d", record["triage_features"])
        self.assertIsNone(record["domain_age_at_flag_days"])
        self.assertEqual(record["domain_age_at_observation_days"], 400)

    def test_feed_event_time_is_preferred_when_present(self):
        flagged_at = self.created + timedelta(days=10)
        record = pipeline.build_flag_record(
            feed_item("https://a-b-c.example.com/x", flagged_at=flagged_at),
            pipeline.parse_flagged_host("https://a-b-c.example.com/x"),
            self.created,
        )
        self.assertEqual(record["domain_age_at_flag_days"], 10)
        self.assertEqual(record["domain_age_at_observation_days"], 400)
        self.assertIn("registration_age_under_60d", record["triage_features"])

    def test_negative_age_is_reported_and_ignored_by_the_rules(self):
        label, age, _ = pipeline.classify_abuse_flag(
            "https://example.com/a/b", "example.com", "example", "com", T0, T0 + timedelta(days=100)
        )
        self.assertEqual(age, -100)
        self.assertEqual(label, "Unverified")
        cues = pipeline.extract_triage_features("https://example.com/a/b", "example", age)
        self.assertNotIn("registration_age_under_60d", cues)

    def test_platform_registration_gives_a_tenant_no_age(self):
        url = "https://abc.vercel.app/a/b"
        record = pipeline.build_flag_record(feed_item(url), pipeline.parse_flagged_host(url), self.created)
        self.assertIsNone(record["domain_age_at_flag_days"])
        self.assertIsNone(record["domain_age_at_observation_days"])
        self.assertEqual(record["classification_label"], "Unverified")
        self.assertIn("platform operator", record["research_note"])


class RdapLookupTests(PatchedDataDirs):
    def lookup(self, session, domain, **resolver_kwargs):
        resolver = pipeline.RDAPBootstrapResolver(**resolver_kwargs)
        resolver.tld_map = {"uk": "https://rdap.example/", "com": "https://rdap.example/"}
        return asyncio.run(resolver.lookup_domain(session, domain))

    def test_endpoint_is_chosen_by_the_last_label(self):
        url = "https://rdap.example/domain/example.co.uk"
        result = self.lookup(FakeSession({url: FakeResponse(200, rdap_body())}), "example.co.uk")
        self.assertEqual(result["query_url"], url)
        self.assertTrue(result["via_iana_bootstrap"])
        self.assertEqual(result["lookup_status"], "ok")

    def test_tld_outside_the_bootstrap_uses_the_fallback(self):
        url = "https://rdap.org/domain/example.io"
        result = self.lookup(FakeSession({url: FakeResponse(200, rdap_body())}), "example.io")
        self.assertEqual(result["query_url"], url)
        self.assertFalse(result["via_iana_bootstrap"])

    def test_answer_is_stored_byte_for_byte_with_a_manifest(self):
        body = rdap_body(statuses=["client hold"])
        url = "https://rdap.example/domain/example.com"
        result = self.lookup(FakeSession({url: FakeResponse(200, body)}), "example.com")
        path = self.raw_dir / "rdap" / result["raw_snapshot"]
        stored, manifest = pipeline.load_verified_snapshot(path)
        self.assertEqual(stored, body)
        self.assertEqual(manifest["queried_domain"], "example.com")
        self.assertEqual(manifest["source_url"], url)
        self.assertEqual(result["raw_sha256"], hashlib.sha256(body).hexdigest())

        meta = pipeline.parse_rdap_metadata(result["rdap_json"])
        self.assertEqual(meta["creation_date"], datetime(2020, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(meta["registrar_name"], "Example Registrar")
        self.assertEqual(meta["registrar_iana_id"], 9999)
        self.assertEqual(meta["epp_statuses"], ["client hold"])
        self.assertEqual(meta["rdap_source_url"], url)
        self.assertEqual(meta["rdap_observed_at"], result["observed_at"])

    def test_failures_are_recorded_rather_than_raised(self):
        url = "https://rdap.example/domain/example.com"
        cases = [
            (FakeResponse(404, b""), "not_found", 404),
            (FakeResponse(503, b""), "http_error", 503),
            (FakeResponse(200, b"<html>"), "invalid_response", 200),
            (FakeResponse(200, b"[1]"), "invalid_response", 200),
            (asyncio.TimeoutError(), "network_error", None),
        ]
        for response, expected_status, expected_http in cases:
            result = self.lookup(FakeSession({url: response}), "example.com")
            self.assertEqual(result["lookup_status"], expected_status)
            self.assertEqual(result["http_status"], expected_http)
            self.assertIsNotNone(result["observed_at"])
            self.assertIsNone(result["rdap_json"])
            self.assertIsNone(result["raw_snapshot"])

    def test_many_urls_on_one_domain_cost_one_request(self):
        url = "https://rdap.example/domain/example.com"
        session = FakeSession({url: FakeResponse(200, rdap_body())})
        resolver = pipeline.RDAPBootstrapResolver()
        resolver.tld_map = {"com": "https://rdap.example/"}

        async def run():
            return await asyncio.gather(*(resolver.lookup_domain(session, "example.com") for _ in range(20)))

        results = asyncio.run(run())
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(len(results), 20)
        self.assertEqual(len(resolver.completed_lookups()), 1)

    def test_requests_to_one_host_are_spaced_out(self):
        session = FakeSession()
        resolver = pipeline.RDAPBootstrapResolver(min_host_interval=0.05)
        resolver.tld_map = {"com": "https://rdap.example/"}

        async def run():
            await asyncio.gather(*(resolver.lookup_domain(session, f"site{i}.com") for i in range(3)))

        asyncio.run(run())
        times = sorted(moment for _, moment in session.requests)
        self.assertEqual(len(times), 3)
        for earlier, later in zip(times, times[1:]):
            self.assertGreaterEqual(later - earlier, 0.04)


class ExportTests(PatchedDataDirs):
    def test_export_columns_include_what_the_paper_relies_on(self):
        for column in ("creation_date", "registrable_domain", "is_platform_tenant", "rdap_lookup_status",
                       "domain_age_at_observation_days", "last_raw_snapshot"):
            self.assertIn(column, pipeline.FLAG_EXPORT_COLUMNS)

    def test_email_addresses_are_masked_in_exported_urls(self):
        redact = pipeline.redact_email_addresses
        self.assertEqual(redact("https://a.example/x?u=jane.doe@example.org&y=1"), "https://a.example/x?u=[email-redacted]&y=1")
        self.assertEqual(redact("https://a.example/x?u=jane%40example.org"), "https://a.example/x?u=[email-redacted]")
        self.assertEqual(redact("https://a.example/x?u=1"), "https://a.example/x?u=1")
        self.assertIsNone(redact(None))

    def test_csv_writes_timestamps_as_iso8601(self):
        self.processed_dir.mkdir(parents=True)
        path = self.processed_dir / "out.csv"
        pipeline.write_csv(path, [{"a": T0, "b": None, "ignored": 1}], ["a", "b"])
        with path.open(encoding="utf-8", newline="") as handle:
            self.assertEqual(list(csv.DictReader(handle)), [{"a": T0.isoformat(), "b": ""}])


class ReplayTests(PatchedDataDirs):
    def setUp(self):
        super().setUp()
        urlhaus = {"query_status": "ok", "urls": [
            {"id": 1, "url": "http://192.0.2.1/x", "date_added": "2026-10-24 12:00:00 UTC"},
            {"id": 2, "url": "https://raw.githubusercontent.com/a/b/c", "date_added": "2026-10-24 12:00:00 UTC"},
        ]}
        self.urlhaus_path = pipeline.save_raw_snapshot(
            "urlhaus", json.dumps(urlhaus).encode("utf-8"), ".json", retrieved_at=T0
        )
        self.openphish_path = pipeline.save_raw_snapshot(
            "openphish",
            b"https://old-site.example.org/a/b\nhttps://abc.vercel.app/?u=jane@example.org\nhttps://new-site.example.com/x\n",
            ".txt", retrieved_at=T0,
        )

    def save_rdap(self, domain: str, retrieved_at: datetime, created: str = "2020-01-01T00:00:00Z"):
        pipeline.save_raw_snapshot(
            "rdap", rdap_body(created=created), ".json",
            retrieved_at=retrieved_at,
            source_url=f"https://rdap.example/domain/{domain}",
            directory=self.raw_dir / "rdap",
            name=domain,
            extra_manifest_fields={"queried_domain": domain},
        )

    def test_newest_snapshot_of_each_feed_is_the_default(self):
        newer = pipeline.save_raw_snapshot("openphish", b"", ".txt", retrieved_at=T0 + timedelta(days=1))
        self.assertEqual(pipeline.latest_feed_snapshots(), [self.urlhaus_path, newer])

    def test_replay_writes_a_csv_with_redacted_urls_and_touches_no_other_export(self):
        result = pipeline.replay_from_snapshots()
        self.assertEqual(result["counts"]["flagged_urls"], 4)
        self.assertEqual(result["counts"]["by_feed"], {"URLhaus": 1, "OpenPhish": 3})
        self.assertEqual(result["counts"]["platform_tenant_rows"], 2)
        self.assertEqual(result["selection"][self.urlhaus_path.name]["dropped_no_registrable_name"], 1)

        replay_dir = self.processed_dir / "replay"
        csv_path = next(replay_dir.glob("abuse_flags_replay_*.csv"))
        with csv_path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(list(rows[0].keys()), pipeline.FLAG_EXPORT_COLUMNS)
        self.assertTrue(any("[email-redacted]" in row["flagged_url"] for row in rows))
        self.assertFalse(any("jane@example.org" in row["flagged_url"] for row in rows))
        self.assertFalse((self.processed_dir / "abuse_flags_latest.csv").exists())
        self.assertEqual(json.loads(next(replay_dir.glob("run_replay_*.json")).read_text())["rule_version"],
                         pipeline.CLASSIFICATION_RULE_VERSION)

    def test_stored_rdap_response_supplies_the_registration_date(self):
        self.save_rdap("example.org", T0 + timedelta(minutes=1))
        rows = {row["domain_name"]: row for row in pipeline.replay_from_snapshots()["rows"]}
        self.assertEqual(rows["example.org"]["rdap_lookup_status"], "ok")
        self.assertEqual(rows["example.org"]["creation_date"], datetime(2020, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(rows["example.org"]["domain_age_at_observation_days"], (T0 - datetime(2020, 1, 1, tzinfo=timezone.utc)).days)
        self.assertEqual(rows["example.org"]["classification_label"], "Possible_Compromised_Legitimate")
        self.assertEqual(rows["example.com"]["rdap_lookup_status"], "not_available_in_replay")
        self.assertEqual(rows["abc.vercel.app"]["rdap_lookup_status"], "platform_tenant")

    def test_rule_version_changes_what_a_stored_date_can_do(self):
        self.save_rdap("example.org", T0 + timedelta(minutes=1))
        rows = pipeline.replay_from_snapshots(rule_version=pipeline.RULE_SET_EVENT_TIME_ONLY)["rows"]
        row = next(row for row in rows if row["domain_name"] == "example.org")
        self.assertEqual(row["classification_label"], "Unverified")
        self.assertIsNone(row["domain_age_at_flag_days"])
        self.assertIsNotNone(row["domain_age_at_observation_days"])

    def test_response_outside_the_window_is_not_used_and_the_closest_one_wins(self):
        self.save_rdap("example.org", T0 + timedelta(days=12))
        rows = {row["domain_name"]: row for row in pipeline.replay_from_snapshots()["rows"]}
        self.assertEqual(rows["example.org"]["rdap_lookup_status"], "not_available_in_replay")

        self.save_rdap("example.org", T0 + timedelta(hours=2), created="2021-01-01T00:00:00Z")
        self.save_rdap("example.org", T0 + timedelta(minutes=5), created="2022-01-01T00:00:00Z")
        rows = {row["domain_name"]: row for row in pipeline.replay_from_snapshots()["rows"]}
        self.assertEqual(rows["example.org"]["creation_date"], datetime(2022, 1, 1, tzinfo=timezone.utc))

    def test_replay_refuses_an_altered_snapshot(self):
        self.openphish_path.write_bytes(b"https://other.example.com/x\n")
        with self.assertRaises(pipeline.SnapshotIntegrityError):
            pipeline.replay_from_snapshots()

    def test_replay_without_snapshots_is_an_error(self):
        with patch.object(pipeline, "RAW_DATA_DIR", self.root / "empty"):
            with self.assertRaises(FileNotFoundError):
                pipeline.replay_from_snapshots()


class CommandLineTests(unittest.TestCase):
    def test_defaults_keep_every_row_and_use_the_current_rules(self):
        args = pipeline.parse_args([])
        self.assertFalse(args.replay)
        self.assertIsNone(args.raw_row_limit)
        self.assertIsNone(args.limit)
        self.assertEqual(args.rule_version, pipeline.CLASSIFICATION_RULE_VERSION)

    def test_invalid_combinations_are_rejected(self):
        for argv in (["--snapshot", "x"], ["--output-dir", "x"], ["--limit", "0"], ["--rule-version", "nope"]):
            with self.assertRaises(SystemExit), patch("sys.stderr"):
                pipeline.parse_args(argv)


@unittest.skipUnless(Path("pyproject.toml").exists(), "project metadata is not copied into the Docker image")
class ProjectMetadataTests(unittest.TestCase):
    def setUp(self):
        self.pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    def test_versions_agree(self):
        citation = re.search(r"^version: (\S+)$", Path("CITATION.cff").read_text(encoding="utf-8"), re.M).group(1)
        self.assertEqual(self.pyproject["project"]["version"], pipeline.__version__)
        self.assertEqual(citation, pipeline.__version__)

    def test_declared_licence_is_present(self):
        self.assertIn("license: MIT", Path("CITATION.cff").read_text(encoding="utf-8"))
        self.assertIn("MIT License", Path("LICENSE").read_text(encoding="utf-8"))

    def test_runtime_pins_agree_with_the_docker_requirements(self):
        requirements = {
            line.strip() for line in Path("requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        self.assertEqual(requirements, set(self.pyproject["project"]["dependencies"]))


if __name__ == "__main__":
    unittest.main()
