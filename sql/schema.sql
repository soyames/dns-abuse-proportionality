-- sql/01_schema.sql
-- Empirical Audit Schema: Proportionality-by-Design in Automated DNS Abuse Mitigation

CREATE TABLE IF NOT EXISTS monitored_domains (
    domain_id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) UNIQUE NOT NULL,
    tld VARCHAR(63) NOT NULL,
    registrar_iana_id INT,
    registrar_name VARCHAR(255),
    creation_date TIMESTAMP WITH TIME ZONE,
    registrant_category VARCHAR(50) CHECK (
        registrant_category IN ('NGO_Civil_Society', 'Independent_Media', 'Academic', 'Commercial', 'Unknown')
    ),
    region_code VARCHAR(10),
    rdap_raw_json JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS abuse_flags (
    flag_id SERIAL PRIMARY KEY,
    domain_id INT REFERENCES monitored_domains(domain_id) ON DELETE CASCADE,
    source_feed VARCHAR(100) NOT NULL,
    threat_type VARCHAR(50) CHECK (
        threat_type IN ('Phishing', 'Malware', 'Botnet', 'Pharming', 'Spam', 'Content_Dispute', 'KYC_Verification')
    ),
    flagged_url TEXT,
    flagged_at TIMESTAMP WITH TIME ZONE NOT NULL,
    classification_label VARCHAR(50) CHECK (
        classification_label IN ('Compromised_Legitimate', 'Maliciously_Registered', 'False_Positive_Benign', 'Unverified')
    ),
    domain_age_at_flag_days INT,
    heuristic_confidence_score NUMERIC(4,3)
);

CREATE TABLE IF NOT EXISTS mitigation_actions (
    action_id SERIAL PRIMARY KEY,
    flag_id INT REFERENCES abuse_flags(flag_id) ON DELETE CASCADE,
    epp_status_applied VARCHAR(100),
    prior_notice_sent BOOLEAN DEFAULT FALSE,
    cure_period_hours INT,
    action_taken_at TIMESTAMP WITH TIME ZONE,
    restored_at TIMESTAMP WITH TIME ZONE,
    collateral_impact_score INT CHECK (collateral_impact_score BETWEEN 1 AND 5),
    due_process_compliant BOOLEAN,
    case_notes TEXT
);

-- Indexes for fast analytical queries on JSONB and timestamps
CREATE INDEX IF NOT EXISTS idx_monitored_domains_tld ON monitored_domains(tld);
CREATE INDEX IF NOT EXISTS idx_monitored_domains_category ON monitored_domains(registrant_category);
CREATE INDEX IF NOT EXISTS idx_abuse_flags_classification ON abuse_flags(classification_label);
CREATE INDEX IF NOT EXISTS idx_rdap_jsonb ON monitored_domains USING GIN (rdap_raw_json);