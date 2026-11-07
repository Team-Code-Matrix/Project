-- ==============================================================================
-- Intelligent Phishing, Web Security, PKI Validation & CTI Platform
-- PostgreSQL 16 + pgvector Production Schema
-- ==============================================================================

-- 1. Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- 2. Enumerated Types
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE backend_verdict AS ENUM ('CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'PKI_TRUST_COMPROMISED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE finding_severity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE finding_category AS ENUM ('PHISHING', 'PKI', 'WEB_SEC', 'CTI');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE cert_type AS ENUM ('leaf', 'intermediate', 'root');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE tlp_marking AS ENUM ('TLP:WHITE', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ==============================================================================
-- 3. RBAC & Multi-Tenancy Tables
-- ==============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    api_key_hash VARCHAR(255) NOT NULL UNIQUE,
    private_scan_mode BOOLEAN DEFAULT FALSE,
    kms_key_arn VARCHAR(512),
    rate_limit_per_minute INT DEFAULT 60,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 4. Scans & Dual-Lane Telemetry Tables
-- ==============================================================================

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    submitted_url TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    target_url_defanged TEXT NOT NULL,
    status scan_status NOT NULL DEFAULT 'QUEUED',
    backend_verdict backend_verdict DEFAULT 'CLEAN',
    backend_risk_score INT DEFAULT 0 CHECK (backend_risk_score >= 0 AND backend_risk_score <= 100),
    ui_trust_score INT DEFAULT 100 CHECK (ui_trust_score >= 0 AND ui_trust_score <= 100),
    summary TEXT,
    analyst_reason_codes TEXT[] DEFAULT '{}',
    is_private BOOLEAN DEFAULT FALSE,
    scan_duration_ms INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(backend_verdict);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant_id);

-- Fast-Path Synchronous Lane Telemetry Table (<150ms evaluation)
CREATE TABLE IF NOT EXISTS fast_path_results (
    scan_id UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    evaluated_in_ms INT NOT NULL,
    bloom_filter_hit BOOLEAN NOT NULL DEFAULT FALSE,
    bloom_source VARCHAR(64),
    google_safe_browsing_match BOOLEAN NOT NULL DEFAULT FALSE,
    gsb_threat_type VARCHAR(64),
    cached_reputation VARCHAR(32) DEFAULT 'UNRATED',
    mozilla_onecrl_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    preliminary_verdict backend_verdict NOT NULL,
    summary TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Worker Status Tracking Table
CREATE TABLE IF NOT EXISTS scan_worker_statuses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    worker_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    duration_ms INT,
    summary_snippet TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_scan_worker UNIQUE (scan_id, worker_id)
);

-- ==============================================================================
-- 5. Pillar Telemetry Tables
-- ==============================================================================

-- Pillar 1: Advanced Phishing & DOM Detonation
CREATE TABLE IF NOT EXISTS phishing_telemetry (
    scan_id UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    detonation_sandbox VARCHAR(64) NOT NULL DEFAULT 'Firecracker microVM',
    anti_bot_cloaking_defeated BOOLEAN NOT NULL DEFAULT FALSE,
    redirect_chain JSONB NOT NULL DEFAULT '[]'::jsonb,
    dom_heuristics JSONB NOT NULL DEFAULT '{}'::jsonb,
    yara_rules_matched TEXT[] DEFAULT '{}',
    targeted_brand VARCHAR(128),
    visual_similarity_score REAL DEFAULT 0.0,
    phash_hex VARCHAR(64),
    dhash_hex VARCHAR(64),
    favicon_murmurhash3 VARCHAR(64),
    is_impersonation BOOLEAN DEFAULT FALSE,
    screenshot_s3_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Pillar 2: Cryptographic Trust, PKI & Certificate Validation
CREATE TABLE IF NOT EXISTS pki_telemetry (
    scan_id UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    key_entropy_verdict VARCHAR(64) NOT NULL DEFAULT 'VALID',
    fermat_factorization_passed BOOLEAN NOT NULL DEFAULT TRUE,
    small_prime_gcd_passed BOOLEAN NOT NULL DEFAULT TRUE,
    curve_point_valid BOOLEAN NOT NULL DEFAULT TRUE,
    key_ceremony_anomaly_flag BOOLEAN NOT NULL DEFAULT FALSE,
    key_ceremony_notes TEXT,
    chain_validation_status VARCHAR(64) NOT NULL DEFAULT 'VERIFIED',
    trust_store_compatibility JSONB NOT NULL DEFAULT '{}'::jsonb,
    path_len_constraint_valid BOOLEAN NOT NULL DEFAULT TRUE,
    cross_signed_bypass_detected BOOLEAN NOT NULL DEFAULT FALSE,
    certificate_transparency JSONB NOT NULL DEFAULT '{}'::jsonb,
    revocation_health JSONB NOT NULL DEFAULT '{}'::jsonb,
    dns_caa_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- X.509 Certificate Hierarchy Details
CREATE TABLE IF NOT EXISTS certificate_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cert_type cert_type NOT NULL,
    subject_common_name VARCHAR(255) NOT NULL,
    subject_org VARCHAR(255),
    issuer_common_name VARCHAR(255) NOT NULL,
    issuer_org VARCHAR(255),
    serial_number VARCHAR(128) NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    days_remaining INT NOT NULL,
    is_expired BOOLEAN NOT NULL DEFAULT FALSE,
    signature_algorithm VARCHAR(64) NOT NULL,
    public_key_algorithm VARCHAR(64) NOT NULL,
    key_size_bits INT NOT NULL,
    sha256_fingerprint VARCHAR(64) NOT NULL,
    raw_pem TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cert_fingerprint ON certificate_items(sha256_fingerprint);
CREATE INDEX IF NOT EXISTS idx_cert_scan_id ON certificate_items(scan_id);

-- Pillar 3: Application-Level Web Security Assessment
CREATE TABLE IF NOT EXISTS web_security_telemetry (
    scan_id UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    http_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    cookie_security JSONB NOT NULL DEFAULT '{}'::jsonb,
    cors_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    tls_fingerprints JSONB NOT NULL DEFAULT '{}'::jsonb,
    passive_exposure JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Individual Security Findings across all Pillars
CREATE TABLE IF NOT EXISTS scan_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    severity finding_severity NOT NULL,
    category finding_category NOT NULL,
    description TEXT NOT NULL,
    source VARCHAR(128) NOT NULL,
    evidence TEXT[] DEFAULT '{}',
    recommendation TEXT,
    cve_reference VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON scan_findings(severity);

-- Pillar 4: Forensic Evidence & Encrypted Artifacts
CREATE TABLE IF NOT EXISTS forensic_artifacts (
    scan_id UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    target_url_defanged TEXT NOT NULL,
    screenshot_s3_key TEXT,
    screenshot_timestamp TIMESTAMPTZ,
    dom_snapshot_s3_key TEXT,
    har_trace_s3_key TEXT,
    raw_cert_chain_s3_key TEXT,
    har_summary JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 6. pgvector Brand Templates & Perceptual Embeddings Table
-- ==============================================================================

CREATE TABLE IF NOT EXISTS brand_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    brand_name VARCHAR(128) NOT NULL,
    canonical_domain VARCHAR(255) NOT NULL UNIQUE,
    category VARCHAR(64) NOT NULL DEFAULT 'Financial & Tech',
    favicon_murmurhash3 VARCHAR(64),
    phash_hex VARCHAR(64),
    dhash_hex VARCHAR(64),
    -- 512-dimensional visual embedding vector from vision encoder
    logo_embedding vector(512),
    logo_image_s3_key TEXT,
    is_protected BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create HNSW Index for rapid approximate nearest neighbors cosine similarity searches
CREATE INDEX IF NOT EXISTS idx_brand_embedding_hnsw 
ON brand_templates 
USING hnsw (logo_embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- Pre-seed Protected Corporate Brand Verification Targets
INSERT INTO brand_templates (brand_name, canonical_domain, category, favicon_murmurhash3, phash_hex, is_protected)
VALUES 
    ('Google LLC', 'google.com', 'Technology & Identity', '709511739', 'e3a1f8b2c4d6e8f0', TRUE),
    ('Microsoft Corporation', 'microsoft.com', 'Technology & Cloud', '-123456789', 'f0e8d6c4b2a1f8e3', TRUE),
    ('Apple Inc.', 'apple.com', 'Consumer Electronics & Services', '987654321', '1234567890abcdef', TRUE),
    ('PayPal Inc.', 'paypal.com', 'Fintech & Payments', '-998877665', 'abcdef0123456789', TRUE),
    ('Bank of America', 'bankofamerica.com', 'Banking & Finance', '445566778', '89abcdef01234567', TRUE),
    ('Meta Platforms', 'facebook.com', 'Social & Identity', '112233445', 'fedcba9876543210', TRUE)
ON CONFLICT (canonical_domain) DO NOTHING;

-- Verification Notice
DO $$
BEGIN
    RAISE NOTICE 'TrustShield PostgreSQL 16 schema + pgvector tables successfully initialized.';
END $$;
