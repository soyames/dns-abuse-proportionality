import asyncio
import csv
import json
import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
import asyncpg
import tldextract
from dateutil import parser as date_parser

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
URLHAUS_RECENT_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
PROJECT_ROOT = Path(__file__).resolve().parent
TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"

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

SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS monitored_domains (
    domain_id BIGSERIAL PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    tld VARCHAR(63) NOT NULL,
    registrar_iana_id INT,
    registrar_name VARCHAR(255),
    creation_date TIMESTAMPTZ,
    registrant_category VARCHAR(50),
    region_code VARCHAR(10),
    rdap_raw_json JSONB,
    rdap_source_url TEXT,
    rdap_observed_at TIMESTAMPTZ,
    rdap_epp_statuses JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE monitored_domains ADD COLUMN IF NOT EXISTS rdap_source_url TEXT;
ALTER TABLE monitored_domains ADD COLUMN IF NOT EXISTS rdap_observed_at TIMESTAMPTZ;
ALTER TABLE monitored_domains ADD COLUMN IF NOT EXISTS rdap_epp_statuses JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE monitored_domains DROP CONSTRAINT IF EXISTS monitored_domains_registrant_category_check;
ALTER TABLE monitored_domains ADD CONSTRAINT monitored_domains_registrant_category_check CHECK (
    registrant_category IN ('NonCommercial_Candidate', 'Independent_Media_Candidate', 'Academic_Candidate', 'Unknown')
) NOT VALID;
ALTER TABLE monitored_domains VALIDATE CONSTRAINT monitored_domains_registrant_category_check;

CREATE TABLE IF NOT EXISTS abuse_flags (
    flag_id BIGSERIAL PRIMARY KEY,
    domain_id BIGINT NOT NULL REFERENCES monitored_domains(domain_id) ON DELETE CASCADE,
    source_feed VARCHAR(100) NOT NULL,
    threat_type VARCHAR(50) NOT NULL,
    flagged_url TEXT NOT NULL,
    flagged_at TIMESTAMPTZ,
    observed_at TIMESTAMPTZ NOT NULL,
    source_record_id VARCHAR(255),
    raw_snapshot VARCHAR(255) NOT NULL,
    source_url TEXT NOT NULL,
    timestamp_basis VARCHAR(50) NOT NULL,
    observation_key VARCHAR(64) NOT NULL UNIQUE,
    classification_rule_version VARCHAR(50) NOT NULL,
    triage_features JSONB NOT NULL DEFAULT '[]'::jsonb,
    classification_label VARCHAR(80) NOT NULL,
    domain_age_at_flag_days INT,
    heuristic_confidence_score NUMERIC(4,3),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE abuse_flags ALTER COLUMN flagged_at DROP NOT NULL;
ALTER TABLE abuse_flags ADD COLUMN IF NOT EXISTS observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE abuse_flags ADD COLUMN IF NOT EXISTS source_record_id VARCHAR(255);
ALTER TABLE abuse_flags ADD COLUMN IF NOT EXISTS raw_snapshot VARCHAR(255);
ALTER TABLE abuse_flags ADD COLUMN IF NOT EXISTS source_url TEXT;
ALTER TABLE abuse_flags ADD COLUMN IF NOT EXISTS timestamp_basis VARCHAR(50) NOT NULL DEFAULT 'unknown';
ALTER TABLE abuse_flags ADD COLUMN IF NOT EXISTS observation_key VARCHAR(64);
ALTER TABLE abuse_flags ADD COLUMN IF NOT EXISTS classification_rule_version VARCHAR(50) NOT NULL DEFAULT 'legacy';
ALTER TABLE abuse_flags ADD COLUMN IF NOT EXISTS triage_features JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE abuse_flags DROP CONSTRAINT IF EXISTS abuse_flags_classification_label_check;
ALTER TABLE abuse_flags ADD CONSTRAINT abuse_flags_classification_label_check CHECK (
    classification_label IN ('Possible_Compromised_Legitimate', 'Possible_Maliciously_Registered', 'Unverified')
) NOT VALID;
ALTER TABLE abuse_flags VALIDATE CONSTRAINT abuse_flags_classification_label_check;
CREATE UNIQUE INDEX IF NOT EXISTS uq_abuse_flags_observation_key ON abuse_flags(observation_key);

CREATE TABLE IF NOT EXISTS feed_observations (
    observation_id BIGSERIAL PRIMARY KEY,
    source_feed VARCHAR(100) NOT NULL,
    source_record_id VARCHAR(255),
    flagged_url TEXT NOT NULL,
    source_event_at TIMESTAMPTZ,
    observed_at TIMESTAMPTZ NOT NULL,
    raw_snapshot VARCHAR(255) NOT NULL,
    source_url TEXT NOT NULL,
    timestamp_basis VARCHAR(50) NOT NULL,
    UNIQUE (source_feed, raw_snapshot, flagged_url)
);
CREATE INDEX IF NOT EXISTS idx_feed_observations_url_time ON feed_observations(flagged_url, observed_at);

CREATE TABLE IF NOT EXISTS mitigation_actions (
    action_id BIGSERIAL PRIMARY KEY,
    flag_id BIGINT NOT NULL UNIQUE REFERENCES abuse_flags(flag_id) ON DELETE CASCADE,
    epp_status_applied VARCHAR(100),
    observed_epp_statuses JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_action VARCHAR(255),
    prior_notice_sent BOOLEAN,
    cure_period_hours INT,
    action_taken_at TIMESTAMPTZ,
    restored_at TIMESTAMPTZ,
    collateral_impact_score INT CHECK (collateral_impact_score BETWEEN 1 AND 5),
    due_process_compliant BOOLEAN,
    human_review_status VARCHAR(50) NOT NULL DEFAULT 'not_reviewed',
    research_note TEXT,
    case_notes TEXT
);
ALTER TABLE mitigation_actions ADD COLUMN IF NOT EXISTS observed_epp_statuses JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE mitigation_actions ADD COLUMN IF NOT EXISTS recommended_action VARCHAR(255);
ALTER TABLE mitigation_actions ADD COLUMN IF NOT EXISTS human_review_status VARCHAR(50) NOT NULL DEFAULT 'not_reviewed';
ALTER TABLE mitigation_actions ADD COLUMN IF NOT EXISTS research_note TEXT;
ALTER TABLE mitigation_actions ALTER COLUMN prior_notice_sent DROP DEFAULT;
ALTER TABLE mitigation_actions ALTER COLUMN cure_period_hours DROP DEFAULT;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mitigation_actions_flag ON mitigation_actions(flag_id);

CREATE TABLE IF NOT EXISTS mitigation_events (
    event_id BIGSERIAL PRIMARY KEY,
    flag_id BIGINT NOT NULL REFERENCES abuse_flags(flag_id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
        'notice_sent', 'registrar_action', 'epp_status_observed', 'appeal_filed',
        'appeal_outcome', 'restoration', 'service_impact', 'human_review'
    )),
    occurred_at TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_type VARCHAR(50),
    action_scope VARCHAR(100),
    evidence_source TEXT,
    evidence_reference TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified BOOLEAN,
    reviewer_code VARCHAR(100),
    protocol_version VARCHAR(50)
);
CREATE INDEX IF NOT EXISTS idx_mitigation_events_flag_time ON mitigation_events(flag_id, occurred_at);

CREATE TABLE IF NOT EXISTS review_annotations (
    review_id BIGSERIAL PRIMARY KEY,
    flag_id BIGINT NOT NULL REFERENCES abuse_flags(flag_id) ON DELETE CASCADE,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewer_code VARCHAR(100) NOT NULL,
    protocol_version VARCHAR(50) NOT NULL,
    reviewed_label VARCHAR(80) NOT NULL,
    evidence_basis TEXT NOT NULL,
    confidence_level VARCHAR(30),
    disagreements_with_model BOOLEAN,
    UNIQUE (flag_id, reviewer_code, protocol_version)
);
CREATE INDEX IF NOT EXISTS idx_review_annotations_flag ON review_annotations(flag_id);

CREATE INDEX IF NOT EXISTS idx_monitored_domains_tld ON monitored_domains(tld);
CREATE INDEX IF NOT EXISTS idx_monitored_domains_category ON monitored_domains(registrant_category);
CREATE INDEX IF NOT EXISTS idx_abuse_flags_classification ON abuse_flags(classification_label);
CREATE INDEX IF NOT EXISTS idx_abuse_flags_source_time ON abuse_flags(source_feed, observed_at);
CREATE INDEX IF NOT EXISTS idx_rdap_jsonb ON monitored_domains USING GIN (rdap_raw_json);
"""


def save_raw_snapshot(source: str, body: bytes, suffix: str) -> Path:
    """Save the exact feed response as a timestamped, never-overwritten file."""
    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
    fetched_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = RAW_DATA_DIR / f"{source}_{fetched_at}{suffix}"
    with path.open("xb") as raw_file:
        raw_file.write(body)
    fetched_at_iso = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    manifest = {
        "source": source,
        "source_url": URLHAUS_RECENT_API_URL if source == "urlhaus" else OPENPHISH_FEED_URL,
        "fetched_at_utc": fetched_at_iso,
        "snapshot_file": path.name,
        "sha256": hashlib.sha256(body).hexdigest(),
        "byte_count": len(body),
        "content_type": "application/json" if source == "urlhaus" else "text/plain",
        "attribution": "abuse.ch URLhaus" if source == "urlhaus" else "OpenPhish",
        "limitations": "Threat-feed URL evidence; not proof of registrant intent or domain-wide compromise.",
    }
    path.with_suffix(path.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    logger.info("Saved raw %s feed to %s", source, path.relative_to(PROJECT_ROOT))
    return path


async def export_processed_data(pool: asyncpg.Pool) -> tuple[Path, Path]:
    """Export database observations and group summaries for analysis."""
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    async with pool.acquire() as conn:
        flag_rows = await conn.fetch(
            """
            SELECT af.flag_id, af.source_feed, af.source_record_id, af.raw_snapshot, af.source_url, af.timestamp_basis,
                   af.threat_type, af.flagged_url, af.flagged_at, af.observed_at, af.classification_label,
                   af.domain_age_at_flag_days, af.heuristic_confidence_score,
                   af.classification_rule_version, af.triage_features,
                   md.domain_name, md.tld, md.registrar_name,
                   md.registrant_category, md.rdap_source_url, md.rdap_observed_at,
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

    fetched_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    flags_path = PROCESSED_DATA_DIR / f"abuse_flags_{fetched_at}.csv"
    summary_path = PROCESSED_DATA_DIR / f"classification_summary_{fetched_at}.csv"
    flags_latest = PROCESSED_DATA_DIR / "abuse_flags_latest.csv"
    summary_latest = PROCESSED_DATA_DIR / "classification_summary_latest.csv"
    flags_columns = [
        "flag_id", "source_feed", "source_record_id", "raw_snapshot", "source_url", "timestamp_basis",
        "threat_type", "flagged_url", "flagged_at", "observed_at",
        "classification_label", "domain_age_at_flag_days", "heuristic_confidence_score",
        "classification_rule_version", "triage_features", "domain_name", "tld", "registrar_name", "registrant_category",
        "rdap_source_url", "rdap_observed_at", "rdap_epp_statuses", "epp_status_applied", "observed_epp_statuses",
        "recommended_action", "human_review_status", "prior_notice_sent", "cure_period_hours",
        "collateral_impact_score", "due_process_compliant", "research_note", "case_notes",
    ]
    summary_columns = [
        "classification_label", "registrant_category", "unique_feed_urls",
        "feed_observations", "avg_age_days", "rdap_hold_domain_count",
    ]

    def write_csv(path: Path, rows, columns: list[str]) -> None:
        with path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                values = dict(row)
                writer.writerow({
                    key: value.isoformat() if hasattr(value, "isoformat") else value
                    for key, value in values.items()
                })

    write_csv(flags_path, flag_rows, flags_columns)
    write_csv(summary_path, summary_rows, summary_columns)
    write_csv(flags_latest, flag_rows, flags_columns)
    write_csv(summary_latest, summary_rows, summary_columns)
    logger.info("Exported %d database rows to %s", len(flag_rows), flags_path.relative_to(PROJECT_ROOT))
    logger.info("Exported summary rows to %s", summary_path.relative_to(PROJECT_ROOT))
    return flags_path, summary_path


class RDAPBootstrapResolver:
    def __init__(self):
        self.tld_map: dict[str, str] = {}

    async def load_bootstrap(self, session: aiohttp.ClientSession):
        logger.info("Fetching IANA RDAP Bootstrap registry...")
        async with session.get(IANA_RDAP_BOOTSTRAP_URL, timeout=20) as resp:
            resp.raise_for_status()
            data = await resp.json()
            for entry in data.get("services", []):
                tlds, urls = entry[0], entry[1]
                https_urls = [u for u in urls if u.startswith("https://")]
                selected_url = https_urls[0] if https_urls else urls[0]
                if not selected_url.endswith("/"):
                    selected_url += "/"
                for tld in tlds:
                    self.tld_map[tld.lower()] = selected_url
        logger.info(f"Loaded authoritative RDAP endpoints for {len(self.tld_map)} TLDs.")

    async def query_domain(
        self, session: aiohttp.ClientSession, domain: str, tld: str
    ) -> dict | None:
        base_url = self.tld_map.get(tld.lower())
        if not base_url:
            query_url = f"https://rdap.org/domain/{domain}"
        else:
            query_url = f"{base_url}domain/{domain}"

        try:
            async with session.get(
                query_url,
                headers={"Accept": "application/rdap+json, application/json"},
                timeout=12,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    data["_research_source_url"] = query_url
                    data["_research_observed_at"] = datetime.now(timezone.utc).isoformat()
                    return data
        except Exception as e:
            logger.debug(f"RDAP lookup failed for {domain}: {e}")
        return None


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


CLASSIFICATION_RULE_VERSION = "heuristics-2026-01"


def make_observation_key(source_feed: str, flagged_url: str) -> str:
    return hashlib.sha256(f"{source_feed}\0{flagged_url}".encode("utf-8")).hexdigest()


def extract_triage_features(flagged_url: str, sld: str, domain_age_days: int | None) -> list[str]:
    """Return human-readable heuristic cues; these are not verified facts."""
    parsed = urlparse(flagged_url)
    path_parts = [part for part in parsed.path.split("/") if part]
    cues = []
    lowered_path = parsed.path.lower()
    if domain_age_days is not None:
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
    flagged_at: datetime,
    creation_date: datetime | None,
) -> tuple[str, int | None, float | None]:
    parsed = urlparse(flagged_url)
    path_depth = len([p for p in parsed.path.split("/") if p])

    domain_age_days = None
    if creation_date and flagged_at:
        delta = flagged_at - creation_date
        domain_age_days = max(0, delta.days)

    sld_lower = sld.lower()
    has_brand_spoof = any(brand in sld_lower for brand in TARGETED_BRAND_KEYWORDS)
    has_suspicious_hyphens = sld_lower.count("-") >= 2

    cms_compromise_indicators = (
        "wp-content", "wp-includes", "wp-admin", "components", "modules", "uploads", ".well-known"
    )
    is_cms_path = any(ind in parsed.path.lower() for ind in cms_compromise_indicators)

    if domain_age_days is not None:
        if domain_age_days > 180 and (is_cms_path or path_depth >= 2) and not has_brand_spoof:
            return "Possible_Compromised_Legitimate", domain_age_days, None
        if domain_age_days < 30 and (has_brand_spoof or has_suspicious_hyphens):
            return "Possible_Maliciously_Registered", domain_age_days, None

    if is_cms_path and not has_brand_spoof:
        return "Possible_Compromised_Legitimate", domain_age_days, None
    if has_brand_spoof or has_suspicious_hyphens:
        return "Possible_Maliciously_Registered", domain_age_days, None

    return "Unverified", domain_age_days, None


async def fetch_urlhaus_feed(
    session: aiohttp.ClientSession, limit: int = 25
) -> list[dict]:
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
            timeout=25,
        ) as resp:
            resp.raise_for_status()
            body = await resp.read()
            snapshot = save_raw_snapshot("urlhaus", body, ".json").name
            data = json.loads(body)
            if data.get("query_status") != "ok":
                logger.warning("URLhaus returned query status: %s", data.get("query_status"))
                return items
            seen_urls = set()
            for row in data.get("urls", []):
                try:
                    flagged_at = date_parser.parse(row["date_added"].removesuffix(" UTC"))
                    if flagged_at.tzinfo is None:
                        flagged_at = flagged_at.replace(tzinfo=timezone.utc)
                except (KeyError, TypeError, ValueError):
                    flagged_at = None
                flagged_url = row.get("url")
                if flagged_url and flagged_url not in seen_urls:
                    seen_urls.add(flagged_url)
                    items.append({
                        "source_feed": "URLhaus",
                        "threat_type": "Malware",
                        "flagged_url": flagged_url,
                        "flagged_at": flagged_at,
                        "observed_at": datetime.now(timezone.utc),
                        "source_record_id": str(row.get("id", "")) or None,
                        "raw_snapshot": snapshot,
                        "source_url": URLHAUS_RECENT_API_URL,
                        "timestamp_basis": "source_date_added",
                    })
                    if len(items) >= limit:
                        break
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        logger.warning("URLhaus fetch error: %s", e)
    logger.info("Retrieved %d records from URLhaus.", len(items))
    return items


async def fetch_openphish_feed(session: aiohttp.ClientSession, limit: int = 25) -> list[dict]:
    logger.info("Fetching live phishing feed from OpenPhish...")
    items = []
    try:
        async with session.get(OPENPHISH_FEED_URL, timeout=20) as resp:
            resp.raise_for_status()
            body = await resp.read()
            snapshot = save_raw_snapshot("openphish", body, ".txt").name
            text = body.decode("utf-8", errors="replace")
            now = datetime.now(timezone.utc)
            for line in text.splitlines():
                url = line.strip()
                if url.startswith("http") and not any(
                    item["flagged_url"] == url for item in items
                ):
                    items.append({
                        "source_feed": "OpenPhish",
                        "threat_type": "Phishing",
                        "flagged_url": url,
                        "flagged_at": None,
                        "observed_at": now,
                        "source_record_id": None,
                        "raw_snapshot": snapshot,
                        "source_url": OPENPHISH_FEED_URL,
                        "timestamp_basis": "collection_time_no_feed_timestamp",
                    })
                    if len(items) >= limit:
                        break
    except Exception as e:
        logger.warning(f"OpenPhish fetch error: {e}")
    logger.info(f"Retrieved {len(items)} records from OpenPhish.")
    return items


async def process_and_store_record(
    pool: asyncpg.Pool,
    rdap_resolver: RDAPBootstrapResolver,
    session: aiohttp.ClientSession,
    item: dict,
    semaphore: asyncio.Semaphore,
):
    async with semaphore:
        flagged_url = item["flagged_url"]
        ext = TLD_EXTRACTOR(flagged_url)
        if not ext.domain or not ext.suffix:
            return

        registered_domain = f"{ext.domain}.{ext.suffix}".lower()
        tld = ext.suffix.lower()

        rdap_json = await rdap_resolver.query_domain(session, registered_domain, tld)
        rdap_meta = parse_rdap_metadata(rdap_json)

        registrant_category = infer_registrant_category(registered_domain, ext.domain, tld)
        classification_label, age_days, confidence = classify_abuse_flag(
            flagged_url=flagged_url,
            domain=registered_domain,
            sld=ext.domain,
            tld=tld,
            flagged_at=item["flagged_at"],
            creation_date=rdap_meta["creation_date"],
        )
        triage_features = extract_triage_features(flagged_url, ext.domain, age_days)

        epp_statuses = rdap_meta["epp_statuses"]
        # Registry statuses are observations, not actions performed by this pipeline.
        epp_applied = None
        due_process_compliant = None
        collateral_impact = None
        if classification_label == "Possible_Compromised_Legitimate":
            recommended_note = (
                "Candidate pattern only: review path-level evidence, check registrant and hosting context, "
                "and consider targeted remediation before domain-wide action. No action was taken."
            )
        elif classification_label == "Possible_Maliciously_Registered":
            recommended_note = (
                "Candidate pattern only: obtain independent evidence and human review before any intervention. "
                "No action was taken."
            )
        else:
            recommended_note = "Unverified: seek actionable evidence and human review. No action was taken."

        async with pool.acquire() as conn:
            async with conn.transaction():
                domain_id = await conn.fetchval(
                    """
                    INSERT INTO monitored_domains (
                        domain_name, tld, registrar_iana_id, registrar_name,
                        creation_date, registrant_category, rdap_raw_json, rdap_source_url,
                        rdap_observed_at, rdap_epp_statuses
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10::jsonb)
                    ON CONFLICT (domain_name) DO UPDATE
                    SET registrar_name = COALESCE(EXCLUDED.registrar_name, monitored_domains.registrar_name),
                        creation_date = COALESCE(EXCLUDED.creation_date, monitored_domains.creation_date),
                        rdap_raw_json = COALESCE(EXCLUDED.rdap_raw_json, monitored_domains.rdap_raw_json),
                        rdap_source_url = COALESCE(EXCLUDED.rdap_source_url, monitored_domains.rdap_source_url),
                        rdap_observed_at = COALESCE(EXCLUDED.rdap_observed_at, monitored_domains.rdap_observed_at),
                        rdap_epp_statuses = EXCLUDED.rdap_epp_statuses
                    RETURNING domain_id;
                    """,
                    registered_domain,
                    tld,
                    rdap_meta["registrar_iana_id"],
                    rdap_meta["registrar_name"],
                    rdap_meta["creation_date"],
                    registrant_category,
                    json.dumps(rdap_json) if rdap_json else None,
                    rdap_meta["rdap_source_url"],
                    rdap_meta["rdap_observed_at"],
                    json.dumps(rdap_meta["epp_statuses"]),
                )

                observation_key = make_observation_key(item["source_feed"], flagged_url)
                flag_id = await conn.fetchval(
                    """
                    INSERT INTO abuse_flags (
                        domain_id, source_feed, threat_type, flagged_url, flagged_at,
                        source_record_id, raw_snapshot, source_url, timestamp_basis, observation_key, classification_rule_version,
                        triage_features, observed_at, classification_label, domain_age_at_flag_days, heuristic_confidence_score
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14, $15, $16)
                    ON CONFLICT (observation_key) DO UPDATE SET
                        flagged_at = COALESCE(abuse_flags.flagged_at, EXCLUDED.flagged_at),
                        source_record_id = COALESCE(EXCLUDED.source_record_id, abuse_flags.source_record_id),
                        raw_snapshot = EXCLUDED.raw_snapshot,
                        source_url = EXCLUDED.source_url,
                        classification_label = EXCLUDED.classification_label,
                        classification_rule_version = EXCLUDED.classification_rule_version,
                        triage_features = EXCLUDED.triage_features,
                        domain_age_at_flag_days = EXCLUDED.domain_age_at_flag_days,
                        heuristic_confidence_score = EXCLUDED.heuristic_confidence_score
                    RETURNING flag_id;
                    """,
                    domain_id,
                    item["source_feed"],
                    item["threat_type"],
                    flagged_url,
                    item["flagged_at"],
                    item.get("source_record_id"),
                    item.get("raw_snapshot"),
                    item.get("source_url"),
                    item.get("timestamp_basis", "unknown"),
                    observation_key,
                    CLASSIFICATION_RULE_VERSION,
                    json.dumps(triage_features),
                    item.get("observed_at", datetime.now(timezone.utc)),
                    classification_label,
                    age_days,
                    confidence,
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
                    item.get("flagged_at"), item.get("observed_at", datetime.now(timezone.utc)),
                    item.get("raw_snapshot") or "unknown", item.get("source_url") or "unknown",
                    item.get("timestamp_basis", "unknown"),
                )

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
                        observed_epp_statuses = EXCLUDED.observed_epp_statuses,
                        research_note = EXCLUDED.research_note;
                    """,
                    flag_id,
                    json.dumps(epp_statuses),
                    recommended_note,
                )

        logger.info(
            f"Logged {registered_domain} | Feed: {item['source_feed']} | "
            f"Age: {age_days}d | Class: {classification_label} | EPP: {epp_applied}"
        )


async def main():
    logger.info("Starting DNS Abuse Proportionality-by-Design Empirical Pipeline...")
    pool = await asyncpg.create_pool(**DATABASE_CONFIG, min_size=2, max_size=10)

    async with pool.acquire() as conn:
        await conn.execute(SQL_SCHEMA)
    logger.info("PostgreSQL schema and research migrations verified.")

    rdap_resolver = RDAPBootstrapResolver()
    semaphore = asyncio.Semaphore(5)
    try:
        await _run_collection_and_export(pool, rdap_resolver, semaphore)
    finally:
        await pool.close()
    logger.info("Pipeline run completed successfully.")


async def _run_collection_and_export(
    pool: asyncpg.Pool,
    rdap_resolver: RDAPBootstrapResolver,
    semaphore: asyncio.Semaphore,
) -> None:

    async with aiohttp.ClientSession(
        headers={"User-Agent": "TUGraz-CSS-DNSAbuseResearch/1.0 (+https://soyames.com)"}
    ) as session:
        await rdap_resolver.load_bootstrap(session)

        urlhaus_items = await fetch_urlhaus_feed(session, limit=25)
        openphish_items = await fetch_openphish_feed(session, limit=25)
        all_items = urlhaus_items + openphish_items

        tasks = [
            process_and_store_record(pool, rdap_resolver, session, item, semaphore)
            for item in all_items
        ]
        await asyncio.gather(*tasks)

    await export_processed_data(pool)


if __name__ == "__main__":
    asyncio.run(main())
