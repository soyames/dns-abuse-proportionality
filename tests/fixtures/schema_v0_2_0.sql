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
