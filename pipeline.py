"""Observational research collector for DNS-abuse feeds, RDAP metadata and candidate labels.

    python pipeline.py            live collection into PostgreSQL, then CSV export
    python pipeline.py --replay   rebuild labels and CSVs from stored snapshots (no network, no database)

The tool never requests a flagged URL or host, and it never acts on a domain.
"""
import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlparse

import aiohttp
import asyncpg
import tldextract
from dateutil import parser as date_parser

__version__ = "0.3.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("dns_abuse_pipeline")

DATABASE_CONFIG = {
    "host": os.getenv("DATABASE_HOST", "db"),
    "port": int(os.getenv("DATABASE_PORT", "5432")),
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD", ""),
    "database": os.getenv("POSTGRES_DB", "dns_abuse_audit"),
}

IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK_BASE_URL = "https://rdap.org/"
RDAP_TIMEOUT_SECONDS = 12
RDAP_MIN_HOST_INTERVAL_SECONDS = 1.0
RDAP_REPLAY_WINDOW_HOURS = 24
URLHAUS_RECENT_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
USER_AGENT = "TUGraz-CSS-DNSAbuseResearch/1.0 (+https://soyames.com)"
PROJECT_ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = PROJECT_ROOT / "sql" / "01_schema.sql"
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"

# Both extractors use the suffix list bundled with the pinned tldextract, so parsing is reproducible.
# With the private section a tenant host such as tenant.vercel.app reads as a registrable name, which
# is what the lexical rules see. The ICANN section gives the name a registrar actually sponsors.
TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
ICANN_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

# Hosting platforms missing from the private section of that bundled list.
CURATED_PLATFORM_DOMAINS = {"webflow.io"}

TARGETED_BRAND_KEYWORDS = {
    "paypal", "microsoft", "apple", "google", "facebook", "netflix",
    "binance", "coinbase", "dhl", "ups", "usps", "bank", "secure",
    "login", "verify", "wallet", "account", "update", "office365"
}

NGO_TLDS = {"org", "ngo", "ong", "int"}
NGO_KEYWORDS = {
    "foundation", "fondation", "association", "charity", "relief",
    "humanrights", "rights", "health", "clinic", "press", "media",
    "society", "alliance", "network", "institute", "forum", "youth"
}

# heuristics-2026-01 produced the 24 October 2026 sample reported in the paper: it reads a domain's age
# only from a feed event time, so OpenPhish rows never have one. heuristics-2026-02 applies the same rules
# but falls back to collection time when a feed supplies no event time.
RULE_SET_EVENT_TIME_ONLY = "heuristics-2026-01"
CLASSIFICATION_RULE_VERSION = "heuristics-2026-02"
SUPPORTED_RULE_VERSIONS = (RULE_SET_EVENT_TIME_ONLY, CLASSIFICATION_RULE_VERSION)

EMAIL_IN_URL = re.compile(r"[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

FLAG_EXPORT_COLUMNS = [
    "flag_id", "source_feed", "source_record_id", "raw_snapshot", "last_raw_snapshot", "source_url", "timestamp_basis",
    "threat_type", "flagged_url", "flagged_at", "observed_at", "last_observed_at",
    "classification_label", "domain_age_at_flag_days", "domain_age_at_observation_days", "heuristic_confidence_score",
    "classification_rule_version", "triage_features", "domain_name", "registrable_domain", "is_platform_tenant",
    "platform_tenant_basis", "tld", "registrar_name", "creation_date", "registrant_category",
    "rdap_lookup_status", "rdap_source_url", "rdap_observed_at", "rdap_epp_statuses", "epp_status_applied",
    "observed_epp_statuses", "recommended_action", "human_review_status", "prior_notice_sent", "cure_period_hours",
    "collateral_impact_score", "due_process_compliant", "research_note", "case_notes",
]
SUMMARY_EXPORT_COLUMNS = [
    "classification_label", "registrant_category", "unique_feed_urls",
    "feed_observations", "avg_age_days", "avg_age_at_observation_days", "rdap_hold_domain_count",
]
RDAP_EXPORT_COLUMNS = [
    "queried_domain", "observed_at", "lookup_status", "http_status", "via_iana_bootstrap", "query_url",
    "creation_date", "registrar_name", "epp_statuses", "raw_snapshot", "raw_sha256", "error_detail",
    "collection_context",
]


class SnapshotIntegrityError(RuntimeError):
    """A stored snapshot does not match its manifest."""


class FlaggedHost(NamedTuple):
    flagged_name: str  # the name the lexical rules read (suffix list including its private section)
    registrable_domain: str  # the name a registrar sponsors (ICANN section only); RDAP is queried for this
    sld: str
    suffix: str
    platform_basis: str | None  # 'psl_private', 'curated_list', or None for a registered name

    @property
    def is_platform_tenant(self) -> bool:
        return self.platform_basis is not None


def parse_flagged_host(flagged_url: str) -> FlaggedHost | None:
    """Return the names behind a URL, or None if it has no registrable name (IP host, no public suffix)."""
    try:
        urlparse(flagged_url)
        private = TLD_EXTRACTOR(flagged_url)
        icann = ICANN_TLD_EXTRACTOR(flagged_url)
    except ValueError:
        return None
    if not icann.domain or not icann.suffix:
        return None

    registrable_domain = f"{icann.domain}.{icann.suffix}".lower()
    if private.domain:
        sld, suffix = private.domain, private.suffix
    else:
        # The URL is at the apex of a private suffix, so it is the platform's own registered name.
        sld, suffix = icann.domain, icann.suffix

    platform_basis = None
    if private.domain and private.suffix != icann.suffix:
        platform_basis = "psl_private"
    elif registrable_domain in CURATED_PLATFORM_DOMAINS and icann.subdomain:
        platform_basis = "curated_list"
    return FlaggedHost(f"{sld}.{suffix}".lower(), registrable_domain, sld, suffix, platform_basis)


def redact_email_addresses(url: str | None) -> str | None:
    """Mask email addresses embedded in a URL. Exports use this; the raw snapshots and database keep the URL."""
    return EMAIL_IN_URL.sub("[email-redacted]", url) if url else url


def display_path(path: Path) -> Path:
    try:
        return path.relative_to(PROJECT_ROOT)
    except ValueError:
        return path


def save_raw_snapshot(
    source: str,
    body: bytes,
    suffix: str,
    *,
    retrieved_at: datetime | None = None,
    source_url: str | None = None,
    directory: Path | None = None,
    name: str | None = None,
    attribution: str | None = None,
    limitations: str | None = None,
    extra_manifest_fields: dict | None = None,
) -> Path:
    """Save the exact response as a timestamped, never-overwritten file with an adjacent manifest.

    retrieved_at is when the response arrived. It is passed in rather than read from the file system,
    because a file's modification time changes when the file is copied or restored.
    """
    retrieved_at = retrieved_at or datetime.now(timezone.utc)
    directory = directory or RAW_DATA_DIR
    directory.mkdir(parents=True, exist_ok=True)
    stamp = retrieved_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = directory / f"{name or source}_{stamp}{suffix}"
    with path.open("xb") as raw_file:
        raw_file.write(body)
    manifest = {
        "source": source,
        "source_url": source_url or (URLHAUS_RECENT_API_URL if source == "urlhaus" else OPENPHISH_FEED_URL),
        "fetched_at_utc": retrieved_at.astimezone(timezone.utc).isoformat(),
        "snapshot_file": path.name,
        "sha256": hashlib.sha256(body).hexdigest(),
        "byte_count": len(body),
        "content_type": "application/json" if suffix == ".json" else "text/plain",
        "attribution": attribution or ("abuse.ch URLhaus" if source == "urlhaus" else "OpenPhish"),
        "limitations": limitations or "Threat-feed URL evidence; not proof of registrant intent or domain-wide compromise.",
    }
    manifest.update(extra_manifest_fields or {})
    path.with_suffix(path.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    logger.info("Saved raw %s response to %s", source, display_path(path))
    return path


def load_verified_snapshot(path: Path) -> tuple[bytes, dict]:
    """Read a snapshot and its manifest, refusing a file whose bytes no longer match the recorded digest."""
    manifest_path = path.with_suffix(path.suffix + ".manifest.json")
    if not manifest_path.exists():
        raise SnapshotIntegrityError(f"No manifest for snapshot {path.name}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    body = path.read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    if digest != manifest.get("sha256"):
        raise SnapshotIntegrityError(f"{path.name}: SHA-256 {digest} does not match manifest {manifest.get('sha256')}")
    return body, manifest


def parse_urlhaus_body(body: bytes, snapshot: str, retrieved_at: datetime) -> list[dict]:
    data = json.loads(body)
    if data.get("query_status") != "ok":
        logger.warning("URLhaus returned query status: %s", data.get("query_status"))
        return []
    items = []
    seen_urls = set()
    for row in data.get("urls", []):
        flagged_url = row.get("url")
        if not flagged_url or flagged_url in seen_urls:
            continue
        seen_urls.add(flagged_url)
        try:
            flagged_at = date_parser.parse(row["date_added"].removesuffix(" UTC"))
            if flagged_at.tzinfo is None:
                flagged_at = flagged_at.replace(tzinfo=timezone.utc)
        except (AttributeError, KeyError, TypeError, ValueError):
            flagged_at = None
        items.append({
            "source_feed": "URLhaus",
            "threat_type": "Malware",
            "flagged_url": flagged_url,
            "flagged_at": flagged_at,
            "observed_at": retrieved_at,
            "source_record_id": str(row.get("id", "")) or None,
            "raw_snapshot": snapshot,
            "source_url": URLHAUS_RECENT_API_URL,
            "timestamp_basis": "source_date_added",
        })
    return items


def parse_openphish_body(body: bytes, snapshot: str, retrieved_at: datetime) -> list[dict]:
    items = []
    seen_urls = set()
    for line in body.decode("utf-8", errors="replace").splitlines():
        flagged_url = line.strip()
        if not flagged_url.startswith("http") or flagged_url in seen_urls:
            continue
        seen_urls.add(flagged_url)
        items.append({
            "source_feed": "OpenPhish",
            "threat_type": "Phishing",
            "flagged_url": flagged_url,
            "flagged_at": None,
            "observed_at": retrieved_at,
            "source_record_id": None,
            "raw_snapshot": snapshot,
            "source_url": OPENPHISH_FEED_URL,
            "timestamp_basis": "collection_time_no_feed_timestamp",
        })
    return items


def select_feed_rows(items: list[dict], raw_row_limit: int | None = None, limit: int | None = None) -> tuple[list[dict], dict]:
    """Apply any sampling explicitly and report what each step removed.

    raw_row_limit caps the feed before IP-hosted URLs are removed, which is how the 24 October 2026 sample
    was drawn. limit caps the rows that remain after that filter. Both default to keeping everything.
    """
    considered = items[:raw_row_limit] if raw_row_limit is not None else items
    usable = [item for item in considered if parse_flagged_host(item["flagged_url"]) is not None]
    selected = usable[:limit] if limit is not None else usable
    return selected, {
        "feed_rows": len(items),
        "rows_considered": len(considered),
        "dropped_no_registrable_name": len(considered) - len(usable),
        "rows_selected": len(selected),
    }


def latest_feed_snapshots() -> list[Path]:
    """Return the newest stored snapshot of each feed, URLhaus first as in a live run."""
    paths = []
    for pattern in ("urlhaus_*.json", "openphish_*.txt"):
        matches = sorted(p for p in RAW_DATA_DIR.glob(pattern) if not p.name.endswith(".manifest.json"))
        if matches:
            paths.append(matches[-1])
    return paths


def load_feed_items(path: Path) -> list[dict]:
    """Parse a stored feed snapshot after checking it against its manifest."""
    body, manifest = load_verified_snapshot(path)
    retrieved_at = date_parser.isoparse(manifest["fetched_at_utc"])
    if manifest.get("source") == "urlhaus":
        return parse_urlhaus_body(body, path.name, retrieved_at)
    if manifest.get("source") == "openphish":
        return parse_openphish_body(body, path.name, retrieved_at)
    raise SnapshotIntegrityError(f"{path.name}: unknown feed source {manifest.get('source')!r}")


def write_csv(path: Path, rows, columns: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({
                key: value.isoformat() if hasattr(value, "isoformat") else value
                for key, value in dict(row).items()
            })


async def export_processed_data(pool: asyncpg.Pool) -> tuple[Path, Path]:
    """Export database observations and group summaries for analysis."""
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    async with pool.acquire() as conn:
        flag_rows = await conn.fetch(
            """
            SELECT af.flag_id, af.source_feed, af.source_record_id, af.raw_snapshot, af.last_raw_snapshot,
                   af.source_url, af.timestamp_basis,
                   af.threat_type, af.flagged_url, af.flagged_at, af.observed_at, af.last_observed_at,
                   af.classification_label, af.domain_age_at_flag_days, af.domain_age_at_observation_days,
                   af.heuristic_confidence_score, af.classification_rule_version, af.triage_features,
                   md.domain_name, md.registrable_domain, md.is_platform_tenant, md.platform_tenant_basis,
                   md.tld, md.registrar_name, md.creation_date,
                   md.registrant_category, md.rdap_lookup_status, md.rdap_source_url, md.rdap_observed_at,
                   md.rdap_epp_statuses, ma.epp_status_applied, ma.observed_epp_statuses, ma.recommended_action,
                   ma.human_review_status, ma.prior_notice_sent, ma.cure_period_hours,
                   ma.collateral_impact_score, ma.due_process_compliant, ma.research_note, ma.case_notes
            FROM abuse_flags AS af
            JOIN monitored_domains AS md ON md.domain_id = af.domain_id
            LEFT JOIN mitigation_actions AS ma ON ma.flag_id = af.flag_id
            ORDER BY af.flag_id;
            """
        )
        summary_rows = await conn.fetch(
            """
            SELECT af.classification_label, md.registrant_category,
                   COUNT(DISTINCT (af.source_feed, af.flagged_url)) AS unique_feed_urls,
                   SUM(COALESCE(fo.sighting_count, 0)) AS feed_observations,
                   ROUND(AVG(af.domain_age_at_flag_days)::numeric, 1) AS avg_age_days,
                   ROUND(AVG(af.domain_age_at_observation_days)::numeric, 1) AS avg_age_at_observation_days,
                   COUNT(DISTINCT md.domain_id) FILTER (WHERE EXISTS (
                       SELECT 1 FROM jsonb_array_elements_text(COALESCE(md.rdap_epp_statuses, '[]'::jsonb)) AS statuses(value)
                       WHERE value ILIKE '%hold%'
                   )) AS rdap_hold_domain_count
            FROM abuse_flags AS af
            JOIN monitored_domains AS md ON md.domain_id = af.domain_id
            LEFT JOIN (
                SELECT source_feed, flagged_url, COUNT(*) AS sighting_count
                FROM feed_observations
                GROUP BY source_feed, flagged_url
            ) AS fo ON fo.source_feed = af.source_feed AND fo.flagged_url = af.flagged_url
            GROUP BY af.classification_label, md.registrant_category
            ORDER BY unique_feed_urls DESC;
            """
        )
        rdap_rows = await conn.fetch(
            """
            SELECT queried_domain, observed_at, lookup_status, http_status, via_iana_bootstrap, query_url,
                   creation_date, registrar_name, epp_statuses, raw_snapshot, raw_sha256, error_detail,
                   collection_context
            FROM rdap_observations
            ORDER BY queried_domain, observed_at;
            """
        )

    exported_flags = [
        {**dict(row), "flagged_url": redact_email_addresses(row["flagged_url"])} for row in flag_rows
    ]
    fetched_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    flags_path = PROCESSED_DATA_DIR / f"abuse_flags_{fetched_at}.csv"
    summary_path = PROCESSED_DATA_DIR / f"classification_summary_{fetched_at}.csv"
    rdap_path = PROCESSED_DATA_DIR / f"rdap_observations_{fetched_at}.csv"

    write_csv(flags_path, exported_flags, FLAG_EXPORT_COLUMNS)
    write_csv(summary_path, summary_rows, SUMMARY_EXPORT_COLUMNS)
    write_csv(rdap_path, rdap_rows, RDAP_EXPORT_COLUMNS)
    write_csv(PROCESSED_DATA_DIR / "abuse_flags_latest.csv", exported_flags, FLAG_EXPORT_COLUMNS)
    write_csv(PROCESSED_DATA_DIR / "classification_summary_latest.csv", summary_rows, SUMMARY_EXPORT_COLUMNS)
    write_csv(PROCESSED_DATA_DIR / "rdap_observations_latest.csv", rdap_rows, RDAP_EXPORT_COLUMNS)
    logger.info("Exported %d database rows to %s", len(flag_rows), display_path(flags_path))
    logger.info("Exported summary rows to %s", display_path(summary_path))
    logger.info("Exported %d RDAP observations to %s", len(rdap_rows), display_path(rdap_path))
    return flags_path, summary_path


class RDAPBootstrapResolver:
    """RDAP client for one run: one lookup per domain, throttled per RDAP host, with every outcome kept."""

    def __init__(self, raw_dir: Path | None = None, min_host_interval: float = RDAP_MIN_HOST_INTERVAL_SECONDS):
        self.tld_map: dict[str, str] = {}
        self.raw_dir = raw_dir
        self.min_host_interval = min_host_interval
        self._lookups: dict[str, asyncio.Future] = {}
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._host_next_request: dict[str, float] = {}

    async def load_bootstrap(self, session: aiohttp.ClientSession):
        logger.info("Fetching IANA RDAP Bootstrap registry...")
        async with session.get(IANA_RDAP_BOOTSTRAP_URL, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            resp.raise_for_status()
            data = await resp.json(content_type=None)
            for entry in data.get("services", []):
                tlds, urls = entry[0], entry[1]
                https_urls = [u for u in urls if u.startswith("https://")]
                selected_url = https_urls[0] if https_urls else urls[0]
                if not selected_url.endswith("/"):
                    selected_url += "/"
                for tld in tlds:
                    self.tld_map[tld.lower()] = selected_url
        logger.info(f"Loaded authoritative RDAP endpoints for {len(self.tld_map)} TLDs.")

    def query_url_for(self, domain: str) -> tuple[str, bool]:
        """Return the query URL and whether it came from the IANA bootstrap. The TLD is the last label."""
        base_url = self.tld_map.get(domain.rsplit(".", 1)[-1].lower())
        if base_url:
            return f"{base_url}domain/{domain}", True
        return f"{RDAP_FALLBACK_BASE_URL}domain/{domain}", False

    async def _wait_for_host(self, host: str) -> None:
        loop = asyncio.get_running_loop()
        async with self._host_locks.setdefault(host, asyncio.Lock()):
            delay = self._host_next_request.get(host, 0.0) - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            self._host_next_request[host] = loop.time() + self.min_host_interval

    async def _lookup(self, session: aiohttp.ClientSession, domain: str) -> dict:
        query_url, via_bootstrap = self.query_url_for(domain)
        await self._wait_for_host(urlparse(query_url).hostname or query_url)
        result = {
            "queried_domain": domain,
            "query_url": query_url,
            "via_iana_bootstrap": via_bootstrap,
            "observed_at": None,
            "lookup_status": "network_error",
            "http_status": None,
            "error_detail": None,
            "rdap_json": None,
            "raw_snapshot": None,
            "raw_sha256": None,
        }
        try:
            async with session.get(
                query_url,
                headers={"Accept": "application/rdap+json, application/json"},
                timeout=aiohttp.ClientTimeout(total=RDAP_TIMEOUT_SECONDS),
            ) as resp:
                result["http_status"] = resp.status
                body = await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as error:
            result["observed_at"] = datetime.now(timezone.utc)
            result["error_detail"] = f"{type(error).__name__}: {error}"[:500]
            logger.info("RDAP lookup failed for %s: %s", domain, result["error_detail"])
            return result

        observed_at = datetime.now(timezone.utc)
        result["observed_at"] = observed_at
        if result["http_status"] != 200:
            result["lookup_status"] = "not_found" if result["http_status"] == 404 else "http_error"
            logger.info("RDAP lookup for %s returned HTTP %s", domain, result["http_status"])
            return result
        try:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("RDAP response is not a JSON object")
        except ValueError as error:
            result["lookup_status"] = "invalid_response"
            result["error_detail"] = f"{type(error).__name__}: {error}"[:500]
            logger.info("RDAP response for %s was not usable JSON", domain)
            return result

        snapshot_path = save_raw_snapshot(
            "rdap", body, ".json",
            retrieved_at=observed_at,
            source_url=query_url,
            directory=self.raw_dir or RAW_DATA_DIR / "rdap",
            name=domain,
            attribution="RDAP response" if via_bootstrap else "RDAP response via rdap.org",
            limitations="Registration metadata at retrieval time; says nothing about who controls hosted content.",
            extra_manifest_fields={"queried_domain": domain},
        )
        data["_research_source_url"] = query_url
        data["_research_observed_at"] = observed_at.isoformat()
        result.update(
            lookup_status="ok",
            rdap_json=data,
            raw_snapshot=snapshot_path.name,
            raw_sha256=hashlib.sha256(body).hexdigest(),
        )
        return result

    async def lookup_domain(self, session: aiohttp.ClientSession, domain: str) -> dict:
        """Look a domain up at most once, so that many URLs on one platform cost one request."""
        if domain not in self._lookups:
            self._lookups[domain] = asyncio.ensure_future(self._lookup(session, domain))
        return await self._lookups[domain]

    def completed_lookups(self) -> list[dict]:
        return [
            future.result() for future in self._lookups.values()
            if future.done() and not future.cancelled() and future.exception() is None
        ]


def parse_rdap_metadata(rdap_json: dict | None) -> dict:
    result = {
        "creation_date": None,
        "registrar_name": None,
        "registrar_iana_id": None,
        "epp_statuses": [],
        "rdap_source_url": None,
        "rdap_observed_at": None,
    }
    if not rdap_json:
        return result

    result["epp_statuses"] = rdap_json.get("status", [])
    result["rdap_source_url"] = rdap_json.get("_research_source_url")
    observed_at = rdap_json.get("_research_observed_at")
    result["rdap_observed_at"] = date_parser.isoparse(observed_at) if observed_at else None

    for event in rdap_json.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                dt = date_parser.isoparse(event["eventDate"])
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                result["creation_date"] = dt
            except Exception:
                pass

    for entity in rdap_json.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                        result["registrar_name"] = str(prop[3])
            for pub_id in entity.get("publicIds", []):
                if pub_id.get("type") == "IANA Registrar ID":
                    try:
                        result["registrar_iana_id"] = int(pub_id.get("identifier"))
                    except (ValueError, TypeError):
                        pass

    return result


def infer_registrant_category(domain: str, sld: str, tld: str) -> str:
    """Return a weak name/TLD-based candidate only; never a verified registrant type."""
    sld_lower = sld.lower()
    if tld.lower() in {"edu", "ac"} or "univ" in sld_lower or "school" in sld_lower:
        return "Academic_Candidate"
    if any(k in sld_lower for k in ("news", "press", "media", "radio", "journal", "gazette")):
        return "Independent_Media_Candidate"
    if tld.lower() in NGO_TLDS or any(k in sld_lower for k in NGO_KEYWORDS):
        return "NonCommercial_Candidate"
    return "Unknown"


def make_observation_key(source_feed: str, flagged_url: str) -> str:
    return hashlib.sha256(f"{source_feed}\0{flagged_url}".encode("utf-8")).hexdigest()


def whole_days_between(later: datetime | None, earlier: datetime | None) -> int | None:
    """Signed whole days from earlier to later, or None if either time is unknown."""
    if later is None or earlier is None:
        return None
    return (later - earlier).days


def rule_reference_time(rule_version: str, flagged_at: datetime | None, observed_at: datetime | None) -> datetime | None:
    """The time a rule set measures a domain's age against.

    Collection time follows the unknown OpenPhish listing time, so an age from it is an upper bound.
    """
    if rule_version == RULE_SET_EVENT_TIME_ONLY:
        return flagged_at
    return flagged_at or observed_at


def extract_triage_features(flagged_url: str, sld: str, domain_age_days: int | None) -> list[str]:
    """Return human-readable heuristic cues; these are not verified facts."""
    parsed = urlparse(flagged_url)
    path_parts = [part for part in parsed.path.split("/") if part]
    cues = []
    lowered_path = parsed.path.lower()
    if domain_age_days is not None and domain_age_days >= 0:
        if domain_age_days > 180:
            cues.append("registration_age_over_180d")
        if domain_age_days < 60:
            cues.append("registration_age_under_60d")
    if len(path_parts) >= 2:
        cues.append("url_path_depth_at_least_2")
    if any(token in lowered_path for token in (
        "wp-content", "wp-includes", "wp-admin", "components", "modules", "uploads", ".well-known"
    )):
        cues.append("cms_like_path_token")
    lowered_sld = sld.lower()
    if any(brand in lowered_sld for brand in TARGETED_BRAND_KEYWORDS):
        cues.append("target_brand_substring")
    if lowered_sld.count("-") >= 2:
        cues.append("multiple_sld_hyphens")
    return cues


def classify_abuse_flag(
    flagged_url: str,
    domain: str,
    sld: str,
    tld: str,
    reference_time: datetime | None,
    creation_date: datetime | None,
) -> tuple[str, int | None, float | None]:
    """Return (candidate label, signed age in days or None, confidence).

    A negative age means the current registration is newer than the reference time, for example a
    re-registered name. It is reported as measured, and the age rules treat it as unknown.
    """
    parsed = urlparse(flagged_url)
    path_depth = len([p for p in parsed.path.split("/") if p])

    domain_age_days = whole_days_between(reference_time, creation_date)

    sld_lower = sld.lower()
    has_brand_spoof = any(brand in sld_lower for brand in TARGETED_BRAND_KEYWORDS)
    has_suspicious_hyphens = sld_lower.count("-") >= 2

    cms_compromise_indicators = (
        "wp-content", "wp-includes", "wp-admin", "components", "modules", "uploads", ".well-known"
    )
    is_cms_path = any(ind in parsed.path.lower() for ind in cms_compromise_indicators)

    if domain_age_days is not None and domain_age_days >= 0:
        if domain_age_days > 180 and (is_cms_path or path_depth >= 2) and not has_brand_spoof:
            return "Possible_Compromised_Legitimate", domain_age_days, None
        if domain_age_days < 30 and (has_brand_spoof or has_suspicious_hyphens):
            return "Possible_Maliciously_Registered", domain_age_days, None

    if is_cms_path and not has_brand_spoof:
        return "Possible_Compromised_Legitimate", domain_age_days, None
    if has_brand_spoof or has_suspicious_hyphens:
        return "Possible_Maliciously_Registered", domain_age_days, None

    return "Unverified", domain_age_days, None


def research_note_for(label: str, host: FlaggedHost) -> str:
    if label == "Possible_Compromised_Legitimate":
        note = (
            "Candidate pattern only: review path-level evidence, check registrant and hosting context, "
            "and consider targeted remediation before domain-wide action. No action was taken."
        )
    elif label == "Possible_Maliciously_Registered":
        note = (
            "Candidate pattern only: obtain independent evidence and human review before any intervention. "
            "No action was taken."
        )
    else:
        note = "Unverified: seek actionable evidence and human review. No action was taken."
    if host.is_platform_tenant:
        note += (
            f" This host is a tenant of {host.registrable_domain}: the tenant registered no domain, "
            "and any report belongs with the platform operator."
        )
    return note


def build_flag_record(
    item: dict,
    host: FlaggedHost,
    creation_date: datetime | None,
    rule_version: str = CLASSIFICATION_RULE_VERSION,
) -> dict:
    """Derive the label, cues and ages for one feed row. Pure, so live runs and replays share it."""
    # For a tenant host RDAP describes the platform's registration, not the tenant's, so it gives no age.
    registration_date = None if host.is_platform_tenant else creation_date
    label, rule_age_days, confidence = classify_abuse_flag(
        flagged_url=item["flagged_url"],
        domain=host.flagged_name,
        sld=host.sld,
        tld=host.suffix,
        reference_time=rule_reference_time(rule_version, item["flagged_at"], item["observed_at"]),
        creation_date=registration_date,
    )
    return {
        "classification_label": label,
        "classification_rule_version": rule_version,
        "triage_features": extract_triage_features(item["flagged_url"], host.sld, rule_age_days),
        "domain_age_at_flag_days": whole_days_between(item["flagged_at"], registration_date),
        "domain_age_at_observation_days": whole_days_between(item["observed_at"], registration_date),
        "heuristic_confidence_score": confidence,
        "research_note": research_note_for(label, host),
    }


async def fetch_urlhaus_feed(session: aiohttp.ClientSession) -> list[dict]:
    logger.info("Fetching live threat feed from URLhaus (Abuse.ch)...")
    auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        logger.info("Skipping URLhaus: set URLHAUS_AUTH_KEY in .env to enable this feed.")
        return []

    items = []
    try:
        async with session.get(
            URLHAUS_RECENT_API_URL,
            headers={"Auth-Key": auth_key},
            timeout=aiohttp.ClientTimeout(total=25),
        ) as resp:
            resp.raise_for_status()
            body = await resp.read()
            retrieved_at = datetime.now(timezone.utc)
            snapshot = save_raw_snapshot("urlhaus", body, ".json", retrieved_at=retrieved_at).name
            items = parse_urlhaus_body(body, snapshot, retrieved_at)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        logger.warning("URLhaus fetch error: %s", e)
    logger.info("Retrieved %d records from URLhaus.", len(items))
    return items


async def fetch_openphish_feed(session: aiohttp.ClientSession) -> list[dict]:
    logger.info("Fetching live phishing feed from OpenPhish...")
    items = []
    try:
        async with session.get(OPENPHISH_FEED_URL, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            resp.raise_for_status()
            body = await resp.read()
            retrieved_at = datetime.now(timezone.utc)
            snapshot = save_raw_snapshot("openphish", body, ".txt", retrieved_at=retrieved_at).name
            items = parse_openphish_body(body, snapshot, retrieved_at)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        logger.warning("OpenPhish fetch error: %s", e)
    logger.info("Retrieved %d records from OpenPhish.", len(items))
    return items


async def apply_schema(conn: asyncpg.Connection) -> None:
    await conn.execute(SCHEMA_PATH.read_text(encoding="utf-8"))


async def store_rdap_observations(pool: asyncpg.Pool, lookups: list[dict], context: str = "pipeline") -> None:
    """Append one row per lookup, successful or not, to the status history."""
    rows = []
    for lookup in lookups:
        meta = parse_rdap_metadata(lookup["rdap_json"])
        rows.append((
            lookup["queried_domain"], lookup["observed_at"], lookup["query_url"], lookup["via_iana_bootstrap"],
            lookup["lookup_status"], lookup["http_status"], lookup["error_detail"], meta["creation_date"],
            meta["registrar_name"], meta["registrar_iana_id"], json.dumps(meta["epp_statuses"]),
            lookup["raw_snapshot"], lookup["raw_sha256"], context,
        ))
    if not rows:
        return
    async with pool.acquire() as conn:
        await conn.executemany(
            """
            INSERT INTO rdap_observations (
                queried_domain, observed_at, query_url, via_iana_bootstrap, lookup_status, http_status, error_detail,
                creation_date, registrar_name, registrar_iana_id, epp_statuses, raw_snapshot, raw_sha256,
                collection_context
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, $14);
            """,
            rows,
        )


async def process_and_store_record(
    pool: asyncpg.Pool,
    rdap_resolver: RDAPBootstrapResolver,
    session: aiohttp.ClientSession,
    item: dict,
    semaphore: asyncio.Semaphore,
    rule_version: str = CLASSIFICATION_RULE_VERSION,
):
    async with semaphore:
        flagged_url = item["flagged_url"]
        host = parse_flagged_host(flagged_url)
        if host is None:
            return

        lookup = await rdap_resolver.lookup_domain(session, host.registrable_domain)
        # A tenant's row stays free of the platform's registration data; the lookup is still kept in the history.
        rdap_json = None if host.is_platform_tenant else lookup["rdap_json"]
        lookup_status = "platform_tenant" if host.is_platform_tenant else lookup["lookup_status"]
        rdap_meta = parse_rdap_metadata(rdap_json)
        rdap_answered = rdap_meta["rdap_observed_at"] is not None

        async with pool.acquire() as conn:
            async with conn.transaction():
                domain_row = await conn.fetchrow(
                    """
                    INSERT INTO monitored_domains (
                        domain_name, tld, registrable_domain, is_platform_tenant, platform_tenant_basis,
                        registrar_iana_id, registrar_name, creation_date, registrant_category,
                        rdap_raw_json, rdap_source_url, rdap_observed_at, rdap_epp_statuses, rdap_lookup_status
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13::jsonb, $14)
                    ON CONFLICT (domain_name) DO UPDATE
                    SET registrable_domain = EXCLUDED.registrable_domain,
                        is_platform_tenant = EXCLUDED.is_platform_tenant,
                        platform_tenant_basis = EXCLUDED.platform_tenant_basis,
                        registrar_iana_id = COALESCE(EXCLUDED.registrar_iana_id, monitored_domains.registrar_iana_id),
                        registrar_name = COALESCE(EXCLUDED.registrar_name, monitored_domains.registrar_name),
                        creation_date = COALESCE(EXCLUDED.creation_date, monitored_domains.creation_date),
                        rdap_raw_json = COALESCE(EXCLUDED.rdap_raw_json, monitored_domains.rdap_raw_json),
                        rdap_source_url = COALESCE(EXCLUDED.rdap_source_url, monitored_domains.rdap_source_url),
                        rdap_observed_at = COALESCE(EXCLUDED.rdap_observed_at, monitored_domains.rdap_observed_at),
                        -- A failed lookup says nothing about statuses, so the last observed ones stay.
                        rdap_epp_statuses = CASE
                            WHEN EXCLUDED.rdap_observed_at IS NOT NULL THEN EXCLUDED.rdap_epp_statuses
                            ELSE monitored_domains.rdap_epp_statuses
                        END,
                        rdap_lookup_status = EXCLUDED.rdap_lookup_status
                    RETURNING domain_id, creation_date;
                    """,
                    host.flagged_name,
                    host.suffix.lower(),
                    host.registrable_domain,
                    host.is_platform_tenant,
                    host.platform_basis,
                    rdap_meta["registrar_iana_id"],
                    rdap_meta["registrar_name"],
                    rdap_meta["creation_date"],
                    infer_registrant_category(host.flagged_name, host.sld, host.suffix.lower()),
                    json.dumps(rdap_json) if rdap_json else None,
                    rdap_meta["rdap_source_url"],
                    rdap_meta["rdap_observed_at"],
                    json.dumps(rdap_meta["epp_statuses"]),
                    lookup_status,
                )

                # Classify on the merged date, so a failed lookup cannot undo what an earlier run learned.
                record = build_flag_record(item, host, domain_row["creation_date"], rule_version)
                triage_features = json.dumps(record["triage_features"])
                flag_id = await conn.fetchval(
                    """
                    INSERT INTO abuse_flags (
                        domain_id, source_feed, threat_type, flagged_url, flagged_at,
                        source_record_id, raw_snapshot, last_raw_snapshot, source_url, timestamp_basis,
                        observation_key, classification_rule_version, triage_features, observed_at, last_observed_at,
                        classification_label, domain_age_at_flag_days, domain_age_at_observation_days,
                        heuristic_confidence_score
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11, $12::jsonb, $13, $13, $14, $15, $16, $17)
                    -- observed_at and raw_snapshot stay at the first sighting; the last_* columns move forward.
                    ON CONFLICT (observation_key) DO UPDATE SET
                        flagged_at = COALESCE(abuse_flags.flagged_at, EXCLUDED.flagged_at),
                        source_record_id = COALESCE(EXCLUDED.source_record_id, abuse_flags.source_record_id),
                        source_url = EXCLUDED.source_url,
                        last_raw_snapshot = EXCLUDED.last_raw_snapshot,
                        last_observed_at = EXCLUDED.last_observed_at,
                        classification_label = EXCLUDED.classification_label,
                        classification_rule_version = EXCLUDED.classification_rule_version,
                        triage_features = EXCLUDED.triage_features,
                        domain_age_at_flag_days = COALESCE(EXCLUDED.domain_age_at_flag_days, abuse_flags.domain_age_at_flag_days),
                        domain_age_at_observation_days = COALESCE(
                            abuse_flags.domain_age_at_observation_days, EXCLUDED.domain_age_at_observation_days
                        ),
                        heuristic_confidence_score = EXCLUDED.heuristic_confidence_score
                    RETURNING flag_id;
                    """,
                    domain_row["domain_id"],
                    item["source_feed"],
                    item["threat_type"],
                    flagged_url,
                    item["flagged_at"],
                    item.get("source_record_id"),
                    item["raw_snapshot"],
                    item["source_url"],
                    item.get("timestamp_basis", "unknown"),
                    make_observation_key(item["source_feed"], flagged_url),
                    record["classification_rule_version"],
                    triage_features,
                    item["observed_at"],
                    record["classification_label"],
                    record["domain_age_at_flag_days"],
                    record["domain_age_at_observation_days"],
                    record["heuristic_confidence_score"],
                )

                await conn.execute(
                    """
                    INSERT INTO classification_history (
                        flag_id, classified_at, raw_snapshot, classification_rule_version, classification_label,
                        triage_features, domain_age_at_flag_days, domain_age_at_observation_days
                    ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
                    ON CONFLICT (flag_id, raw_snapshot, classification_rule_version) DO NOTHING;
                    """,
                    flag_id,
                    item["observed_at"],
                    item["raw_snapshot"],
                    record["classification_rule_version"],
                    record["classification_label"],
                    triage_features,
                    record["domain_age_at_flag_days"],
                    record["domain_age_at_observation_days"],
                )

                await conn.execute(
                    """
                    INSERT INTO feed_observations (
                        source_feed, source_record_id, flagged_url, source_event_at,
                        observed_at, raw_snapshot, source_url, timestamp_basis
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (source_feed, raw_snapshot, flagged_url) DO NOTHING;
                    """,
                    item["source_feed"], item.get("source_record_id"), flagged_url,
                    item.get("flagged_at"), item["observed_at"],
                    item["raw_snapshot"], item["source_url"],
                    item.get("timestamp_basis", "unknown"),
                )

                # Registry statuses are observations, not actions performed by this pipeline.
                await conn.execute(
                    """
                    INSERT INTO mitigation_actions (
                        flag_id, epp_status_applied, observed_epp_statuses,
                        recommended_action, prior_notice_sent, cure_period_hours,
                        action_taken_at, collateral_impact_score,
                        due_process_compliant, human_review_status, research_note
                    )
                    VALUES ($1, NULL, $2::jsonb, NULL, NULL, NULL, NULL, NULL, NULL,
                            'not_reviewed', $3)
                    ON CONFLICT (flag_id) DO UPDATE SET
                        observed_epp_statuses = CASE
                            WHEN $4 THEN EXCLUDED.observed_epp_statuses
                            ELSE mitigation_actions.observed_epp_statuses
                        END,
                        research_note = EXCLUDED.research_note;
                    """,
                    flag_id,
                    json.dumps(rdap_meta["epp_statuses"]),
                    record["research_note"],
                    rdap_answered,
                )

        logger.info(
            "Logged %s | Feed: %s | Age at observation: %s | Class: %s | RDAP: %s",
            host.flagged_name, item["source_feed"], record["domain_age_at_observation_days"],
            record["classification_label"], lookup_status,
        )


def load_rdap_snapshot_index(directory: Path) -> dict[str, list[tuple[datetime, Path]]]:
    """Map each domain to its stored RDAP responses and their retrieval times."""
    index: dict[str, list[tuple[datetime, Path]]] = {}
    for manifest_path in directory.glob("*.manifest.json"):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        snapshot = manifest_path.with_name(manifest["snapshot_file"])
        index.setdefault(manifest["queried_domain"], []).append(
            (date_parser.isoparse(manifest["fetched_at_utc"]), snapshot)
        )
    return index


def stored_rdap_response(
    index: dict[str, list[tuple[datetime, Path]]], domain: str, observed_at: datetime, window_hours: int
) -> dict | None:
    """Return the stored response closest in time to a feed snapshot, if one falls inside the window."""
    candidates = [
        (abs(retrieved - observed_at), snapshot) for retrieved, snapshot in index.get(domain, [])
        if abs(retrieved - observed_at) <= timedelta(hours=window_hours)
    ]
    if not candidates:
        return None
    _, snapshot = min(candidates, key=lambda candidate: candidate[0])
    body, manifest = load_verified_snapshot(snapshot)
    data = json.loads(body)
    data["_research_source_url"] = manifest["source_url"]
    data["_research_observed_at"] = manifest["fetched_at_utc"]
    return data


def summarise_flag_rows(rows: list[dict]) -> dict:
    """The counts reported in the paper's Table 3, computed from export rows."""
    def known(column: str) -> int:
        return sum(1 for row in rows if row.get(column) not in (None, ""))

    tenants = sum(1 for row in rows if row.get("is_platform_tenant") is True)
    return {
        "flagged_urls": len(rows),
        "distinct_names": len({row["domain_name"] for row in rows}),
        "by_feed": dict(Counter(row["source_feed"] for row in rows)),
        "by_label": dict(Counter(row["classification_label"] for row in rows)),
        "by_registrant_category": dict(Counter(row["registrant_category"] for row in rows)),
        "age_at_flag_known": known("domain_age_at_flag_days"),
        "age_at_observation_known": known("domain_age_at_observation_days"),
        "creation_date_known": known("creation_date"),
        "platform_tenant_rows": tenants,
        "registered_name_rows": len(rows) - tenants,
        "rule_versions": sorted({row["classification_rule_version"] for row in rows}),
    }


def replay_from_snapshots(
    snapshot_paths: list[Path] | None = None,
    *,
    raw_row_limit: int | None = None,
    limit: int | None = None,
    rule_version: str = CLASSIFICATION_RULE_VERSION,
    output_dir: Path | None = None,
    rdap_window_hours: int = RDAP_REPLAY_WINDOW_HOURS,
) -> dict:
    """Rebuild candidate labels and a CSV export from stored snapshots, with no network or database.

    RDAP data comes only from responses stored under data/raw/rdap. Domains with no stored response
    close enough in time to the feed snapshot are marked not_available_in_replay.
    """
    paths = [Path(path) for path in snapshot_paths] if snapshot_paths else latest_feed_snapshots()
    if not paths:
        raise FileNotFoundError(f"No feed snapshots found under {RAW_DATA_DIR}")

    rdap_index = load_rdap_snapshot_index(RAW_DATA_DIR / "rdap")
    rows = []
    selection = {}
    for path in paths:
        selected, selection[path.name] = select_feed_rows(load_feed_items(path), raw_row_limit, limit)
        for item in selected:
            host = parse_flagged_host(item["flagged_url"])
            rdap_json = None
            lookup_status = "platform_tenant"
            if not host.is_platform_tenant:
                rdap_json = stored_rdap_response(rdap_index, host.registrable_domain, item["observed_at"], rdap_window_hours)
                lookup_status = "ok" if rdap_json else "not_available_in_replay"
            meta = parse_rdap_metadata(rdap_json)
            record = build_flag_record(item, host, meta["creation_date"], rule_version)
            rows.append({
                **item,
                **record,
                "flag_id": len(rows) + 1,
                "flagged_url": redact_email_addresses(item["flagged_url"]),
                "last_raw_snapshot": item["raw_snapshot"],
                "last_observed_at": item["observed_at"],
                "triage_features": json.dumps(record["triage_features"]),
                "domain_name": host.flagged_name,
                "registrable_domain": host.registrable_domain,
                "is_platform_tenant": host.is_platform_tenant,
                "platform_tenant_basis": host.platform_basis,
                "tld": host.suffix.lower(),
                "registrar_name": meta["registrar_name"],
                "creation_date": meta["creation_date"],
                "registrant_category": infer_registrant_category(host.flagged_name, host.sld, host.suffix.lower()),
                "rdap_lookup_status": lookup_status,
                "rdap_source_url": meta["rdap_source_url"],
                "rdap_observed_at": meta["rdap_observed_at"],
                "rdap_epp_statuses": json.dumps(meta["epp_statuses"]),
                "observed_epp_statuses": json.dumps(meta["epp_statuses"]),
                "human_review_status": "not_reviewed",
            })

    output_dir = Path(output_dir) if output_dir else PROCESSED_DATA_DIR / "replay"
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    flags_path = output_dir / f"abuse_flags_replay_{stamp}.csv"
    write_csv(flags_path, rows, FLAG_EXPORT_COLUMNS)

    summary = {
        "mode": "replay",
        "pipeline_version": __version__,
        "rule_version": rule_version,
        "raw_row_limit": raw_row_limit,
        "limit": limit,
        "snapshots": [path.name for path in paths],
        "selection": selection,
        "counts": summarise_flag_rows(rows),
        "export": str(display_path(flags_path)),
    }
    (output_dir / f"run_replay_{stamp}.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return {**summary, "rows": rows}


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect or replay DNS-abuse feed observations.")
    parser.add_argument(
        "--replay", action="store_true",
        help="rebuild labels and a CSV from stored snapshots, with no network or database",
    )
    parser.add_argument(
        "--snapshot", action="append", type=Path, metavar="PATH",
        help="feed snapshot to replay (repeatable); defaults to the newest of each feed",
    )
    parser.add_argument(
        "--raw-row-limit", type=positive_int, metavar="N",
        help="keep only the first N rows of each feed before IP-hosted URLs are removed, as in the October 2026 sample",
    )
    parser.add_argument(
        "--limit", type=positive_int, metavar="N",
        help="keep only the first N rows of each feed after IP-hosted URLs are removed",
    )
    parser.add_argument(
        "--rule-version", choices=SUPPORTED_RULE_VERSIONS, default=CLASSIFICATION_RULE_VERSION,
        help="rule set to apply (default: %(default)s)",
    )
    parser.add_argument("--output-dir", type=Path, metavar="DIR", help="where a replay writes its CSV")
    args = parser.parse_args(argv)
    if not args.replay and (args.snapshot or args.output_dir):
        parser.error("--snapshot and --output-dir apply only with --replay")
    return args


async def _run_collection_and_export(
    pool: asyncpg.Pool,
    rdap_resolver: RDAPBootstrapResolver,
    semaphore: asyncio.Semaphore,
    args: argparse.Namespace,
) -> None:
    selection = {}
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        await rdap_resolver.load_bootstrap(session)

        all_items = []
        for feed, items in (
            ("URLhaus", await fetch_urlhaus_feed(session)),
            ("OpenPhish", await fetch_openphish_feed(session)),
        ):
            selected, selection[feed] = select_feed_rows(items, args.raw_row_limit, args.limit)
            all_items.extend(selected)
            logger.info("%s selection: %s", feed, selection[feed])

        tasks = [
            process_and_store_record(pool, rdap_resolver, session, item, semaphore, args.rule_version)
            for item in all_items
        ]
        await asyncio.gather(*tasks)

    lookups = rdap_resolver.completed_lookups()
    await store_rdap_observations(pool, lookups)
    outcomes = dict(Counter(lookup["lookup_status"] for lookup in lookups))
    logger.info("RDAP lookups by outcome: %s", outcomes)

    flags_path, _ = await export_processed_data(pool)
    run_record = {
        "mode": "live",
        "pipeline_version": __version__,
        "rule_version": args.rule_version,
        "raw_row_limit": args.raw_row_limit,
        "limit": args.limit,
        "selection": selection,
        "rdap_lookups_by_outcome": outcomes,
        "export": flags_path.name,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (PROCESSED_DATA_DIR / f"run_{stamp}.json").write_text(json.dumps(run_record, indent=2) + "\n", encoding="utf-8")


async def main(args: argparse.Namespace):
    logger.info("Starting DNS Abuse Proportionality-by-Design Empirical Pipeline...")
    pool = await asyncpg.create_pool(**DATABASE_CONFIG, min_size=2, max_size=10)

    async with pool.acquire() as conn:
        await apply_schema(conn)
    logger.info("PostgreSQL schema and research migrations verified.")

    rdap_resolver = RDAPBootstrapResolver()
    semaphore = asyncio.Semaphore(5)
    try:
        await _run_collection_and_export(pool, rdap_resolver, semaphore, args)
    finally:
        await pool.close()
    logger.info("Pipeline run completed successfully.")


def cli(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.replay:
        result = replay_from_snapshots(
            args.snapshot,
            raw_row_limit=args.raw_row_limit,
            limit=args.limit,
            rule_version=args.rule_version,
            output_dir=args.output_dir,
        )
        print(json.dumps({key: value for key, value in result.items() if key != "rows"}, indent=2))
    else:
        asyncio.run(main(args))


if __name__ == "__main__":
    cli()
