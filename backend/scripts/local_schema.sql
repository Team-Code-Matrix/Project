-- ============================================================================
-- TrustShield Local Database Schema (SQLite / PostgreSQL Compatible)
-- Replaces external cloud databases with fully embedded, zero-cost storage.
-- ============================================================================

-- 1. Users & Authentication
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Scans Table
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    submitted_url TEXT NOT NULL,
    verdict TEXT NOT NULL,
    trust_score INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    ml_prediction TEXT,
    ml_confidence REAL,
    raw_telemetry TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);

-- 3. Threat Reports Table
CREATE TABLE IF NOT EXISTS threat_reports (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    targeted_brand TEXT,
    status TEXT DEFAULT 'under_investigation',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_reports_domain ON threat_reports(domain);
CREATE INDEX IF NOT EXISTS idx_threat_reports_created ON threat_reports(created_at DESC);

-- 4. Audit Trail
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

