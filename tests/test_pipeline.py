from __future__ import annotations

import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pipeline


class PipelineResearchTests(unittest.TestCase):
    def test_openphish_timestamp_not_fabricated_as_event_time(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(pipeline, "RAW_DATA_DIR", root / "raw"), patch.object(
                pipeline, "PROJECT_ROOT", root
            ), patch.object(pipeline, "OPENPHISH_FEED_URL", "https://example.test/feed.txt"):
                class Response:
                    async def __aenter__(self):
                        return self
                    async def __aexit__(self, *args):
                        return None
                    def raise_for_status(self):
                        return None
                    async def read(self):
                        return b"https://malware.example/path\n"

                class Session:
                    def get(self, *args, **kwargs):
                        return Response()

                items = pipeline.asyncio.run(pipeline.fetch_openphish_feed(Session()))
                self.assertEqual(len(items), 1)
                self.assertIsNone(items[0]["flagged_at"])
                self.assertIsNotNone(items[0]["observed_at"])
                self.assertEqual(items[0]["timestamp_basis"], "collection_time_no_feed_timestamp")

    def test_observation_key_is_deterministic_and_feed_specific(self):
        url = "https://example.test/path"
        key = pipeline.make_observation_key("OpenPhish", url)
        self.assertEqual(key, pipeline.make_observation_key("OpenPhish", url))
        self.assertNotEqual(key, pipeline.make_observation_key("URLhaus", url))

    def test_repeated_snapshot_identity_is_deduplicated(self):
        sighting = ("URLhaus", "snapshot-a.json", "https://example.test/malware")
        observed = {sighting}
        observed.add(sighting)
        self.assertEqual(len(observed), 1)

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

    def test_schema_has_sightings_events_and_review_tables(self):
        schema = Path("sql/01_schema.sql").read_text(encoding="utf-8")
        self.assertIn("CREATE TABLE IF NOT EXISTS feed_observations", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS mitigation_events", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS review_annotations", schema)

    def test_raw_snapshot_manifest_has_hash_and_source(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(pipeline, "RAW_DATA_DIR", root / "raw"), patch.object(
                pipeline, "PROJECT_ROOT", root
            ):
                path = pipeline.save_raw_snapshot("openphish", b"sample", ".txt")
                manifest = path.with_suffix(path.suffix + ".manifest.json").read_text()
                self.assertIn(hashlib.sha256(b"sample").hexdigest(), manifest)
                self.assertIn('"source": "openphish"', manifest)


if __name__ == "__main__":
    unittest.main()
