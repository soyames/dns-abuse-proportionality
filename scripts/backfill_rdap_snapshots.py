"""Copy RDAP responses held only in the database out to snapshot files, so that a replay can use them.

Versions up to 0.2.0 kept RDAP responses only in monitored_domains.rdap_raw_json. This script reads that
column and writes files under data/raw/rdap. The files are re-serialised from JSONB, not the original
response bytes, and their manifests say so. It only reads from the database and changes nothing there.

    docker compose run --rm --no-deps pipeline python scripts/backfill_rdap_snapshots.py
"""
import asyncio
import json
import sys
from pathlib import Path

import asyncpg
from dateutil import parser as date_parser

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pipeline  # noqa: E402

RESEARCH_KEYS = ("_research_source_url", "_research_observed_at")


def snapshot_from_row(domain: str, rdap_raw_json: str) -> Path | None:
    """Write one stored response to a snapshot file. Returns None if it has no retrieval time or already exists."""
    data = json.loads(rdap_raw_json)
    source_url = data.get("_research_source_url")
    observed_at = data.get("_research_observed_at")
    if not observed_at:
        pipeline.logger.warning("Skipping %s: the stored response has no retrieval time.", domain)
        return None
    body = json.dumps({key: value for key, value in data.items() if key not in RESEARCH_KEYS}, indent=1).encode("utf-8")
    try:
        return pipeline.save_raw_snapshot(
            "rdap", body, ".json",
            retrieved_at=date_parser.isoparse(observed_at),
            source_url=source_url,
            directory=pipeline.RAW_DATA_DIR / "rdap",
            name=domain,
            attribution="RDAP response",
            limitations="Registration metadata at retrieval time; says nothing about who controls hosted content.",
            extra_manifest_fields={
                "queried_domain": domain,
                "provenance_note": "Re-serialised from monitored_domains.rdap_raw_json; not the original response bytes.",
            },
        )
    except FileExistsError:
        pipeline.logger.info("Already backfilled: %s", domain)
        return None


async def main() -> None:
    conn = await asyncpg.connect(**pipeline.DATABASE_CONFIG)
    try:
        rows = await conn.fetch(
            "SELECT domain_name, rdap_raw_json::text AS rdap_raw_json FROM monitored_domains "
            "WHERE rdap_raw_json IS NOT NULL ORDER BY domain_name;"
        )
    finally:
        await conn.close()
    written = [snapshot_from_row(row["domain_name"], row["rdap_raw_json"]) for row in rows]
    pipeline.logger.info("Wrote %d of %d stored RDAP responses.", sum(1 for path in written if path), len(rows))


if __name__ == "__main__":
    asyncio.run(main())
