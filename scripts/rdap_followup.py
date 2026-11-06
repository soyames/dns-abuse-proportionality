"""Repeat RDAP observation for every registrable domain in stored feed snapshots.

This is the follow-up behind the paper's 5 November 2026 figures. Each run adds one observation of
whether and when a hold appeared, so a panel is built by running it at intervals.

It queries RDAP services only and never requests a flagged URL or host.

    python scripts/rdap_followup.py                     query RDAP and report
    python scripts/rdap_followup.py --to-database       also append the results to rdap_observations
    python scripts/rdap_followup.py --analyze FILE      re-report a saved run, with no network
"""
import argparse
import asyncio
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
import asyncpg
from dateutil import parser as date_parser

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pipeline  # noqa: E402

AGE_BUCKETS = ("<30d", "30-180d", ">180d")


def age_bucket(age_days: int) -> str:
    if age_days < 30:
        return "<30d"
    return "30-180d" if age_days <= 180 else ">180d"


def on_hold(row: dict) -> bool:
    return any("hold" in str(status).lower() for status in row.get("epp") or [])


def registrable_domains(snapshot_paths: list[Path]) -> dict[str, list[str]]:
    """Map every registrable domain in the snapshots to the feeds that listed it."""
    domains: dict[str, set[str]] = {}
    for path in snapshot_paths:
        for item in pipeline.load_feed_items(path):
            host = pipeline.parse_flagged_host(item["flagged_url"])
            if host is not None:
                domains.setdefault(host.registrable_domain, set()).add(item["source_feed"])
    return {domain: sorted(feeds) for domain, feeds in sorted(domains.items())}


def reference_time_of(snapshot_paths: list[Path]) -> datetime:
    """Ages are measured at the earliest retrieval among the snapshots used."""
    times = [date_parser.isoparse(pipeline.load_verified_snapshot(path)[1]["fetched_at_utc"]) for path in snapshot_paths]
    return min(times)


def followup_row(lookup: dict, feeds: list[str], reference_time: datetime, in_bootstrap: bool) -> dict:
    meta = pipeline.parse_rdap_metadata(lookup["rdap_json"])
    return {
        "domain": lookup["queried_domain"],
        "tld": lookup["queried_domain"].rsplit(".", 1)[-1],
        "in_bootstrap": in_bootstrap,
        "status": lookup["http_status"] if lookup["http_status"] is not None else lookup["lookup_status"],
        "lookup_status": lookup["lookup_status"],
        "feeds": feeds,
        "observed_at": lookup["observed_at"].isoformat() if lookup["observed_at"] else None,
        "created": meta["creation_date"].isoformat() if meta["creation_date"] else None,
        "registrar": meta["registrar_name"],
        "epp": meta["epp_statuses"],
        "age_at_snapshot_days": pipeline.whole_days_between(reference_time, meta["creation_date"]),
        "raw_snapshot": lookup["raw_snapshot"],
        "error_detail": lookup["error_detail"],
    }


def analyse(rows: list[dict]) -> dict:
    answered = [row for row in rows if row.get("status") == 200]
    dated = [row for row in answered if row.get("age_at_snapshot_days") is not None]
    buckets = {bucket: {"domains": 0, "on_hold": 0} for bucket in AGE_BUCKETS}
    for row in dated:
        bucket = buckets[age_bucket(row["age_at_snapshot_days"])]
        bucket["domains"] += 1
        bucket["on_hold"] += on_hold(row)
    return {
        "domains": len(rows),
        "tld_in_iana_bootstrap": sum(1 for row in rows if row.get("in_bootstrap")),
        "answered": len(answered),
        "answered_with_registration_date": len(dated),
        "on_hold": sum(1 for row in answered if on_hold(row)),
        "by_age_at_snapshot": buckets,
        "failures_by_tld": dict(Counter(row.get("tld") for row in rows if row.get("status") != 200)),
        "domains_on_hold": sorted(
            (
                {
                    "domain": row["domain"],
                    "age_at_snapshot_days": row.get("age_at_snapshot_days"),
                    "hold_statuses": [status for status in row["epp"] if "hold" in str(status).lower()],
                }
                for row in answered if on_hold(row)
            ),
            key=lambda entry: entry["domain"],
        ),
    }


def load_saved_rows(path: Path) -> list[dict]:
    """Read a saved run. The 5 November 2026 run was saved as a bare list of rows."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else data["domains"]


async def collect(domains: dict[str, list[str]], reference_time: datetime, raw_dir: Path | None) -> tuple[list[dict], list[dict]]:
    resolver = pipeline.RDAPBootstrapResolver(raw_dir=raw_dir)
    semaphore = asyncio.Semaphore(5)
    async with aiohttp.ClientSession(headers={"User-Agent": pipeline.USER_AGENT}) as session:
        await resolver.load_bootstrap(session)

        async def look_up(domain: str) -> dict:
            async with semaphore:
                return await resolver.lookup_domain(session, domain)

        lookups = await asyncio.gather(*(look_up(domain) for domain in domains))
    rows = [
        followup_row(lookup, domains[lookup["queried_domain"]], reference_time, lookup["via_iana_bootstrap"])
        for lookup in lookups
    ]
    return rows, lookups


async def append_to_database(lookups: list[dict]) -> None:
    pool = await asyncpg.create_pool(**pipeline.DATABASE_CONFIG, min_size=1, max_size=2)
    try:
        async with pool.acquire() as conn:
            await pipeline.apply_schema(conn)
        await pipeline.store_rdap_observations(pool, lookups, context="rdap_followup")
    finally:
        await pool.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", action="append", type=Path, metavar="PATH",
                        help="feed snapshot to read (repeatable); defaults to the newest of each feed")
    parser.add_argument("--reference-time", metavar="ISO8601",
                        help="time to measure domain age against; defaults to the earliest snapshot retrieval")
    parser.add_argument("--output-dir", type=Path, metavar="DIR", help="where to write the JSON (default: data/processed)")
    parser.add_argument("--raw-dir", type=Path, metavar="DIR", help="where to store RDAP responses (default: data/raw/rdap)")
    parser.add_argument("--to-database", action="store_true", help="also append the results to rdap_observations")
    parser.add_argument("--analyze", type=Path, metavar="FILE", help="re-report a saved run, with no network")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.analyze:
        print(json.dumps(analyse(load_saved_rows(args.analyze)), indent=2))
        return

    snapshot_paths = args.snapshot or pipeline.latest_feed_snapshots()
    if not snapshot_paths:
        raise SystemExit(f"No feed snapshots found under {pipeline.RAW_DATA_DIR}")
    reference_time = date_parser.isoparse(args.reference_time) if args.reference_time else reference_time_of(snapshot_paths)
    domains = registrable_domains(snapshot_paths)
    pipeline.logger.info("Querying RDAP for %d registrable domains.", len(domains))

    run_at = datetime.now(timezone.utc)
    rows, lookups = asyncio.run(collect(domains, reference_time, args.raw_dir))
    if args.to_database:
        asyncio.run(append_to_database(lookups))

    output_dir = args.output_dir or pipeline.PROCESSED_DATA_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"rdap_followup_{run_at.strftime('%Y%m%dT%H%M%SZ')}.json"
    output_path.write_text(json.dumps({
        "pipeline_version": pipeline.__version__,
        "run_at": run_at.isoformat(),
        "reference_time": reference_time.isoformat(),
        "snapshots": [path.name for path in snapshot_paths],
        "domains": rows,
    }, indent=1) + "\n", encoding="utf-8")
    pipeline.logger.info("Saved follow-up to %s", pipeline.display_path(output_path))
    print(json.dumps(analyse(rows), indent=2))


if __name__ == "__main__":
    main()
