"""Database behaviour. These tests wipe the target database, so they run only against one named for testing:

    docker run --rm -d --name dns_abuse_test_pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=dns_abuse_test \
        -p 127.0.0.1:55433:5432 postgres:16-alpine
    TEST_DATABASE_DSN=postgresql://postgres:test@127.0.0.1:55433/dns_abuse_test python -m unittest discover -s tests
"""
from __future__ import annotations

import asyncio
import csv
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlparse

import asyncpg

import pipeline
from test_pipeline import FakeResponse, FakeSession, T0, feed_item, rdap_body

TEST_DATABASE_DSN = os.getenv("TEST_DATABASE_DSN", "")
OLD_SCHEMA = Path(__file__).parent / "fixtures" / "schema_v0_2_0.sql"
EXAMPLE_RDAP_URL = "https://rdap.example/domain/example.org"


@unittest.skipUnless(
    "test" in urlparse(TEST_DATABASE_DSN).path,
    "set TEST_DATABASE_DSN to a database with 'test' in its name to run these destructive tests",
)
class DatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name, value in (
            ("RAW_DATA_DIR", self.root / "raw"),
            ("PROCESSED_DATA_DIR", self.root / "processed"),
            ("PROJECT_ROOT", self.root),
        ):
            patcher = patch.object(pipeline, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        conn = await asyncpg.connect(TEST_DATABASE_DSN)
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await conn.close()
        self.pool = await asyncpg.create_pool(TEST_DATABASE_DSN, min_size=1, max_size=4)
        self.addAsyncCleanup(self.pool.close)

    async def apply_current_schema(self):
        async with self.pool.acquire() as conn:
            await pipeline.apply_schema(conn)

    async def run_once(self, items: list[dict], responses: dict, rule_version=pipeline.CLASSIFICATION_RULE_VERSION):
        """One collector run: a fresh resolver, every item stored, then the RDAP history appended."""
        resolver = pipeline.RDAPBootstrapResolver(min_host_interval=0)
        resolver.tld_map = {"org": "https://rdap.example/", "app": "https://rdap.example/"}
        session = FakeSession(responses)
        semaphore = asyncio.Semaphore(5)
        await asyncio.gather(*(
            pipeline.process_and_store_record(self.pool, resolver, session, item, semaphore, rule_version)
            for item in items
        ))
        await pipeline.store_rdap_observations(self.pool, resolver.completed_lookups())
        return session

    async def fetchrow(self, query: str, *args):
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def fetch(self, query: str, *args):
        async with self.pool.acquire() as conn:
            return await conn.fetch(query, *args)

    async def test_schema_can_be_applied_repeatedly(self):
        await self.apply_current_schema()
        await self.apply_current_schema()

    async def test_failed_lookup_keeps_what_earlier_runs_observed(self):
        await self.apply_current_schema()
        url = "https://www.example.org/a/b"
        created = "2020-01-01T00:00:00Z"
        await self.run_once(
            [feed_item(url, snapshot="run1.txt")],
            {EXAMPLE_RDAP_URL: FakeResponse(200, rdap_body(created=created, statuses=["client hold"]))},
        )
        await self.run_once(
            [feed_item(url, observed_at=T0 + timedelta(days=1), snapshot="run2.txt")],
            {EXAMPLE_RDAP_URL: FakeResponse(503, b"")},
        )

        domain = await self.fetchrow("SELECT * FROM monitored_domains WHERE domain_name = 'example.org'")
        self.assertEqual(json.loads(domain["rdap_epp_statuses"]), ["client hold"])
        self.assertEqual(domain["creation_date"], datetime(2020, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(domain["registrar_name"], "Example Registrar")
        self.assertEqual(domain["rdap_lookup_status"], "http_error")

        flag = await self.fetchrow("SELECT * FROM abuse_flags")
        self.assertEqual(flag["classification_label"], "Possible_Compromised_Legitimate")
        self.assertEqual(flag["domain_age_at_observation_days"], (T0 - datetime(2020, 1, 1, tzinfo=timezone.utc)).days)

        action = await self.fetchrow("SELECT * FROM mitigation_actions")
        self.assertEqual(json.loads(action["observed_epp_statuses"]), ["client hold"])

        history = await self.fetch(
            "SELECT lookup_status, http_status, epp_statuses FROM rdap_observations ORDER BY observed_at"
        )
        self.assertEqual([(row["lookup_status"], row["http_status"]) for row in history], [("ok", 200), ("http_error", 503)])
        self.assertEqual(json.loads(history[0]["epp_statuses"]), ["client hold"])
        self.assertEqual(json.loads(history[1]["epp_statuses"]), [])

    async def test_new_statuses_replace_old_ones_and_both_stay_in_the_history(self):
        await self.apply_current_schema()
        url = "https://www.example.org/a"
        await self.run_once(
            [feed_item(url, snapshot="run1.txt")], {EXAMPLE_RDAP_URL: FakeResponse(200, rdap_body(statuses=["active"]))}
        )
        await self.run_once(
            [feed_item(url, observed_at=T0 + timedelta(days=1), snapshot="run2.txt")],
            {EXAMPLE_RDAP_URL: FakeResponse(200, rdap_body(statuses=["server hold"]))},
        )
        domain = await self.fetchrow("SELECT rdap_epp_statuses FROM monitored_domains")
        self.assertEqual(json.loads(domain["rdap_epp_statuses"]), ["server hold"])
        history = await self.fetch("SELECT epp_statuses FROM rdap_observations ORDER BY observed_at")
        self.assertEqual([json.loads(row["epp_statuses"]) for row in history], [["active"], ["server hold"]])

    async def test_reruns_keep_the_first_sighting_and_the_label_history(self):
        await self.apply_current_schema()
        url = "https://www.example.org/a/b"
        later = T0 + timedelta(days=1)
        await self.run_once([feed_item(url, snapshot="run1.txt")], {EXAMPLE_RDAP_URL: FakeResponse(404, b"")})
        await self.run_once(
            [feed_item(url, observed_at=later, snapshot="run2.txt")],
            {EXAMPLE_RDAP_URL: FakeResponse(200, rdap_body())},
        )

        flag = await self.fetchrow("SELECT * FROM abuse_flags")
        self.assertEqual(flag["raw_snapshot"], "run1.txt")
        self.assertEqual(flag["observed_at"], T0)
        self.assertEqual(flag["last_raw_snapshot"], "run2.txt")
        self.assertEqual(flag["last_observed_at"], later)
        self.assertEqual(flag["classification_label"], "Possible_Compromised_Legitimate")

        labels = await self.fetch(
            "SELECT raw_snapshot, classification_label, domain_age_at_observation_days "
            "FROM classification_history ORDER BY classified_at"
        )
        self.assertEqual(
            [(row["raw_snapshot"], row["classification_label"]) for row in labels],
            [("run1.txt", "Unverified"), ("run2.txt", "Possible_Compromised_Legitimate")],
        )
        self.assertIsNone(labels[0]["domain_age_at_observation_days"])

        sightings = await self.fetch("SELECT raw_snapshot FROM feed_observations ORDER BY observed_at")
        self.assertEqual([row["raw_snapshot"] for row in sightings], ["run1.txt", "run2.txt"])

    async def test_the_same_snapshot_stored_twice_is_one_sighting(self):
        await self.apply_current_schema()
        item = feed_item("https://www.example.org/a", snapshot="run1.txt")
        responses = {EXAMPLE_RDAP_URL: FakeResponse(200, rdap_body())}
        await self.run_once([item], responses)
        await self.run_once([item], responses)
        counts = await self.fetchrow(
            "SELECT (SELECT COUNT(*) FROM abuse_flags) AS flags, (SELECT COUNT(*) FROM feed_observations) AS sightings, "
            "(SELECT COUNT(*) FROM classification_history) AS labels, (SELECT COUNT(*) FROM rdap_observations) AS rdap"
        )
        self.assertEqual(dict(counts), {"flags": 1, "sightings": 1, "labels": 1, "rdap": 2})

    async def test_histories_are_append_only(self):
        await self.apply_current_schema()
        await self.run_once(
            [feed_item("https://www.example.org/a")], {EXAMPLE_RDAP_URL: FakeResponse(200, rdap_body())}
        )
        async with self.pool.acquire() as conn:
            for statement in (
                "UPDATE rdap_observations SET lookup_status = 'edited'",
                "DELETE FROM rdap_observations",
                "UPDATE classification_history SET classification_label = 'Unverified'",
            ):
                with self.assertRaises(asyncpg.exceptions.RaiseError, msg=statement):
                    await conn.execute(statement)

    async def test_tenant_row_holds_no_registration_data_of_the_platform(self):
        await self.apply_current_schema()
        platform_url = "https://rdap.example/domain/vercel.app"
        session = await self.run_once(
            [feed_item("https://one.vercel.app/a/b"), feed_item("https://two.vercel.app/c/d")],
            {platform_url: FakeResponse(200, rdap_body(created="2020-01-28T00:00:00Z"))},
        )
        self.assertEqual([url for url, _ in session.requests], [platform_url])

        tenant = await self.fetchrow("SELECT * FROM monitored_domains WHERE domain_name = 'one.vercel.app'")
        self.assertEqual(tenant["registrable_domain"], "vercel.app")
        self.assertTrue(tenant["is_platform_tenant"])
        self.assertEqual(tenant["platform_tenant_basis"], "psl_private")
        self.assertEqual(tenant["rdap_lookup_status"], "platform_tenant")
        self.assertIsNone(tenant["creation_date"])
        self.assertIsNone(tenant["rdap_raw_json"])
        self.assertEqual(json.loads(tenant["rdap_epp_statuses"]), [])

        ages = await self.fetch("SELECT domain_age_at_observation_days AS age FROM abuse_flags")
        self.assertEqual([row["age"] for row in ages], [None, None])

        history = await self.fetch("SELECT queried_domain, creation_date FROM rdap_observations")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["queried_domain"], "vercel.app")
        self.assertEqual(history[0]["creation_date"], datetime(2020, 1, 28, tzinfo=timezone.utc))

    async def test_export_carries_creation_date_and_masks_emails(self):
        await self.apply_current_schema()
        await self.run_once(
            [feed_item("https://www.example.org/a?u=jane@example.org")],
            {EXAMPLE_RDAP_URL: FakeResponse(200, rdap_body())},
        )
        flags_path, summary_path = await pipeline.export_processed_data(self.pool)

        with flags_path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(list(rows[0].keys()), pipeline.FLAG_EXPORT_COLUMNS)
        self.assertEqual(rows[0]["creation_date"], "2020-01-01T00:00:00+00:00")
        self.assertEqual(rows[0]["flagged_url"], "https://www.example.org/a?u=[email-redacted]")
        self.assertEqual(rows[0]["registrable_domain"], "example.org")
        self.assertEqual(rows[0]["rdap_lookup_status"], "ok")
        self.assertEqual(rows[0]["is_platform_tenant"], "False")

        for name in ("abuse_flags_latest.csv", "classification_summary_latest.csv", "rdap_observations_latest.csv"):
            self.assertTrue((pipeline.PROCESSED_DATA_DIR / name).exists(), name)
        with (pipeline.PROCESSED_DATA_DIR / "rdap_observations_latest.csv").open(encoding="utf-8", newline="") as handle:
            history = list(csv.DictReader(handle))
        self.assertEqual(history[0]["queried_domain"], "example.org")
        self.assertEqual(history[0]["lookup_status"], "ok")
        self.assertTrue(summary_path.exists())

    async def test_upgrade_from_version_0_2_0_preserves_observations(self):
        run1, run2 = "openphish_run1.txt", "openphish_run2.txt"
        url = "https://www.example.org/a"
        statuses = '["server transfer prohibited", "add period"]'
        async with self.pool.acquire() as conn:
            await conn.execute(OLD_SCHEMA.read_text(encoding="utf-8"))
            domain_id = await conn.fetchval(
                """
                INSERT INTO monitored_domains (domain_name, tld, creation_date, registrant_category, rdap_raw_json,
                                               rdap_source_url, rdap_observed_at, rdap_epp_statuses)
                VALUES ('example.org', 'org', $1, 'Unknown', '{"status": []}'::jsonb, $2, $3, $4::jsonb)
                RETURNING domain_id;
                """,
                datetime(2020, 1, 1, tzinfo=timezone.utc), EXAMPLE_RDAP_URL, T0 + timedelta(seconds=44), statuses,
            )
            # Version 0.2.0 kept the first observed_at but overwrote raw_snapshot, so this row mixes two runs.
            await conn.execute(
                """
                INSERT INTO abuse_flags (domain_id, source_feed, threat_type, flagged_url, observed_at, raw_snapshot,
                                         source_url, timestamp_basis, observation_key, classification_rule_version,
                                         classification_label)
                VALUES ($1, 'OpenPhish', 'Phishing', $2, $3, $4, 'https://example.test/feed.txt',
                        'collection_time_no_feed_timestamp', $5, 'heuristics-2026-01', 'Unverified');
                """,
                domain_id, url, T0, run2, pipeline.make_observation_key("OpenPhish", url),
            )
            for moment, snapshot in ((T0, run1), (T0 + timedelta(seconds=43), run2)):
                await conn.execute(
                    """
                    INSERT INTO feed_observations (source_feed, flagged_url, observed_at, raw_snapshot, source_url, timestamp_basis)
                    VALUES ('OpenPhish', $1, $2, $3, 'https://example.test/feed.txt', 'collection_time_no_feed_timestamp');
                    """,
                    url, moment, snapshot,
                )

        await self.apply_current_schema()
        await self.apply_current_schema()

        flag = await self.fetchrow("SELECT * FROM abuse_flags")
        self.assertEqual(flag["raw_snapshot"], run1)
        self.assertEqual(flag["last_raw_snapshot"], run2)
        self.assertEqual(flag["observed_at"], T0)
        self.assertEqual(flag["last_observed_at"], T0 + timedelta(seconds=43))

        history = await self.fetch("SELECT * FROM rdap_observations")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["queried_domain"], "example.org")
        self.assertEqual(history[0]["collection_context"], "migrated_from_monitored_domains")
        self.assertEqual(json.loads(history[0]["epp_statuses"]), json.loads(statuses))
        self.assertTrue(history[0]["via_iana_bootstrap"])

        labels = await self.fetch("SELECT * FROM classification_history")
        self.assertEqual(len(labels), 1)
        self.assertEqual(labels[0]["classification_rule_version"], "heuristics-2026-01")
        self.assertEqual(labels[0]["raw_snapshot"], run2)

        # The first new run moves the row forward and leaves the migrated history in place.
        later = T0 + timedelta(days=12)
        await self.run_once(
            [feed_item(url, observed_at=later, snapshot="run3.txt")],
            {EXAMPLE_RDAP_URL: FakeResponse(200, rdap_body(statuses=["server hold"]))},
        )
        flag = await self.fetchrow("SELECT * FROM abuse_flags")
        self.assertEqual(flag["raw_snapshot"], run1)
        self.assertEqual(flag["last_raw_snapshot"], "run3.txt")
        self.assertEqual(flag["classification_rule_version"], pipeline.CLASSIFICATION_RULE_VERSION)
        rule_versions = await self.fetch("SELECT classification_rule_version AS v FROM classification_history ORDER BY classified_at")
        self.assertEqual([row["v"] for row in rule_versions], ["heuristics-2026-01", pipeline.CLASSIFICATION_RULE_VERSION])
        rdap_rows = await self.fetch("SELECT epp_statuses FROM rdap_observations ORDER BY observed_at")
        self.assertEqual([json.loads(row["epp_statuses"]) for row in rdap_rows], [json.loads(statuses), ["server hold"]])


if __name__ == "__main__":
    unittest.main()
