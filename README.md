# DNS Abuse Proportionality-by-Design

Research pipeline for collecting community threat-feed observations, querying RDAP, and studying how evidence and registration context could support more careful DNS-abuse triage. It is an observational research tool, not a mitigation service. It never requests a flagged URL or host, and it never acts on a domain.

## Run locally

1. Copy `.env.example` to `.env` and set unique database and pgAdmin passwords. Add a URLhaus Auth-Key if using that feed.
2. Start dependencies: `docker compose up -d db pgadmin`.
3. Collect and export: `docker compose build pipeline`, then `docker compose run --rm pipeline`.
4. Run the tests: `python -m unittest discover -s tests`, with `requirements.txt` installed. Python 3.11 and 3.13 are tested. The database tests are skipped unless `TEST_DATABASE_DSN` is set, because they wipe their target; `tests/test_database.py` shows how to start a throwaway server.
5. Review `data/raw/` and `data/processed/`; open `notebooks/exploratory_analysis.ipynb` for descriptive analysis (`uv sync` installs its dependencies).

A live run keeps every row of each feed. These options change that:

| Option | Effect |
|---|---|
| `--limit N` | Keep the first N rows of each feed after IP-hosted URLs are removed. |
| `--raw-row-limit N` | Keep the first N rows of each feed before IP-hosted URLs are removed. This is how the October 2026 sample was drawn. |
| `--rule-version V` | Apply `heuristics-2026-02` (default) or `heuristics-2026-01`. |

Each run writes its parameters and the number of rows each step removed to `data/processed/run_*.json`.

## Reproduce the published sample

The paper's 24 October 2026 sample came from version 0.2.0, whose rules are kept as `heuristics-2026-01`. This command rebuilds it from the stored snapshots, with no network or database. It checks each snapshot against the SHA-256 in its manifest first.

```bash
python pipeline.py --replay --snapshot data/raw/urlhaus_20261024T151744.643288Z.json --snapshot data/raw/openphish_20261024T151744.852386Z.txt --raw-row-limit 25 --rule-version heuristics-2026-01 --output-dir data/processed/replay_2026-10-24
```

Set `ABUSE_FLAGS_CSV` to the resulting CSV to run the notebook on it, which regenerates Figure 2. `tests/test_published_sample.py` checks the figures in the paper against these files wherever they are present.

The snapshots are not in this repository. The OpenPhish terms restrict redistribution without written permission, and flagged URLs can carry personal data. The author can provide them on request, subject to those terms. CSV exports mask email addresses found in URLs; raw snapshots and the database keep the URL as received. Encoded addresses are not detected.

## Repeat RDAP observation

RDAP reports hold statuses, so querying the same domains at intervals shows whether and when a hold appeared. This script queries every registrable domain in the stored feed snapshots. It contacts RDAP services only.

```bash
docker compose run --rm --no-deps pipeline python scripts/rdap_followup.py
```

Add `--to-database` to append the results to `rdap_observations`. To re-report the 5 November 2026 run behind the figures in the paper's Section 4, with no network:

```bash
python scripts/rdap_followup.py --analyze data/processed/rdap_followup_20261105.json
```

## Upgrade an existing database

A run applies `sql/01_schema.sql`, which is safe to repeat and keeps existing rows. It moves `raw_snapshot` back to each URL's first sighting and seeds the two history tables from the values already stored.

Versions up to 0.2.0 kept RDAP responses only in the database. To copy them out to `data/raw/rdap/` so that a replay can use them, run this once. It only reads from the database.

```bash
docker compose run --rm --no-deps pipeline python scripts/backfill_rdap_snapshots.py
```

## Repository layout

- `pipeline.py`: feed collection, RDAP lookup, heuristic candidate tagging, database writes, exports, and replay.
- `scripts/rdap_followup.py`: repeated RDAP observation of the domains in stored snapshots.
- `scripts/backfill_rdap_snapshots.py`: one-off copy of RDAP responses from the database to snapshot files.
- `sql/01_schema.sql`: schema and additive/non-destructive upgrades.
- `data/raw/`: timestamped source responses and SHA-256 provenance manifests (feeds at the top level, RDAP under `rdap/`).
- `data/processed/`: timestamped CSV exports, latest convenience exports, and run records.
- `notebooks/`: exploratory analysis of processed observations.
- `docs/`: architecture and methods limitations.
- `tests/`: unit tests for parsing and research safeguards, database tests, and checks of the published figures.

## Research scope and evidence gaps

The current experiment describes community threat-feed URLs and available RDAP metadata. It does not sample registrar decisions or contain the case evidence needed to answer whether suspensions were wrongful, disproportionate, appealed, or harmful to non-commercial organizations. It also does not include ICANN Contractual Compliance reports, Domain Metrica data, Lumen records, PhishTank, CZDS zone histories, historical NS/MX, Tranco, verified organization status, or observed notices and service outages. Treat those as proposed future data sources unless they have actually been acquired, documented, and joined. Current candidate labels are exploratory and cannot support false-positive rates or causal/human-rights conclusions.

The rules themselves are deliberately unchanged, so that labels stay comparable with the published sample. They are not fit to route real cases:

- Lexical cues match substrings, so "groups" matches "ups" and a food bank's name matches "bank".
- The brand and hyphen tests read a tenant label on a shared platform as if it were a registered name. `is_platform_tenant` lets an analysis separate those rows.
- A CMS-like path can produce `Possible_Compromised_Legitimate` with no age evidence.
- Registrant categories are lexical guesses. For example, the `.ac` TLD reads as academic, while `ox.ac.uk` reads as unknown.

## Licence

The code is released under the [MIT License](LICENSE). The licence does not cover third-party feed data, which remains subject to its providers' terms.
