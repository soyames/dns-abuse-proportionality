# DNS Abuse Proportionality-by-Design

Research pipeline for collecting community threat-feed observations, querying RDAP, and studying how evidence and registration context could support more careful DNS-abuse triage. It is an observational research tool, not a mitigation service.

## Run locally

1. Copy `.env.example` to `.env` and set unique database and pgAdmin passwords. Add a URLhaus Auth-Key if using that feed.
2. Start dependencies: `docker compose up -d db pgadmin`.
3. Collect and export: `docker compose run --rm pipeline`.
4. Run unit tests: `python -m unittest discover -s tests`.
5. Review `data/raw/` and `data/processed/`; open `notebooks/exploratory_analysis.ipynb` for descriptive analysis.

## Repository layout

- `pipeline.py`: feed collection, RDAP lookup, heuristic candidate tagging, database writes, and exports.
- `sql/01_schema.sql`: schema and additive/non-destructive upgrades.
- `data/raw/`: timestamped source responses and SHA-256 provenance manifests.
- `data/processed/`: timestamped CSV exports and latest convenience exports.
- `notebooks/`: exploratory analysis of processed observations.
- `docs/`: architecture and methods limitations.
- `tests/`: offline unit tests for parsing and research safeguards.

## Research scope and evidence gaps

The current experiment describes community threat-feed URLs and available RDAP metadata. It does not sample registrar decisions or contain the case evidence needed to answer whether suspensions were wrongful, disproportionate, appealed, or harmful to non-commercial organizations. It also does not include ICANN Contractual Compliance/DAAR datasets, Lumen records, PhishTank, CZDS zone histories, historical NS/MX, Tranco, verified organization status, or observed notices and service outages. Treat those as proposed future data sources unless they have actually been acquired, documented, and joined. Current candidate labels are exploratory and cannot support false-positive rates or causal/human-rights conclusions.

