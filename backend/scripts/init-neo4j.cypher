// ==============================================================================
// Intelligent Phishing, Web Security, PKI Validation & CTI Platform
// Neo4j Cypher Schema: STIX 2.1 SDOs, SCOs & SROs Initializer
// ==============================================================================

// ------------------------------------------------------------------------------
// 1. Constraints (Enforcing Global Uniqueness across STIX Identifiers & Values)
// ------------------------------------------------------------------------------

CREATE CONSTRAINT c_stix_indicator_id IF NOT EXISTS 
FOR (i:StixIndicator) REQUIRE i.id IS UNIQUE;

CREATE CONSTRAINT c_stix_domain_value IF NOT EXISTS 
FOR (d:StixDomain) REQUIRE d.value IS UNIQUE;

CREATE CONSTRAINT c_stix_ipv4_value IF NOT EXISTS 
FOR (ip:StixIPv4Address) REQUIRE ip.value IS UNIQUE;

CREATE CONSTRAINT c_stix_asn_number IF NOT EXISTS 
FOR (a:StixASN) REQUIRE a.number IS UNIQUE;

CREATE CONSTRAINT c_stix_cert_fingerprint IF NOT EXISTS 
FOR (c:StixCertificate) REQUIRE c.sha256_fingerprint IS UNIQUE;

CREATE CONSTRAINT c_stix_ja4_hash IF NOT EXISTS 
FOR (j:StixJA4Fingerprint) REQUIRE j.hash IS UNIQUE;

CREATE CONSTRAINT c_stix_threat_actor_id IF NOT EXISTS 
FOR (t:StixThreatActor) REQUIRE t.id IS UNIQUE;

CREATE CONSTRAINT c_stix_infrastructure_id IF NOT EXISTS 
FOR (inf:StixInfrastructure) REQUIRE inf.id IS UNIQUE;

// ------------------------------------------------------------------------------
// 2. Traversal Indexes for Fast Multi-Hop Infrastructure Resolution
// ------------------------------------------------------------------------------

CREATE INDEX idx_domain_risk IF NOT EXISTS 
FOR (d:StixDomain) ON (d.risk_state);

CREATE INDEX idx_domain_tld IF NOT EXISTS 
FOR (d:StixDomain) ON (d.tld);

CREATE INDEX idx_ip_asn IF NOT EXISTS 
FOR (ip:StixIPv4Address) ON (ip.asn);

CREATE INDEX idx_cert_issuer IF NOT EXISTS 
FOR (c:StixCertificate) ON (c.issuer_cn);

CREATE INDEX idx_cert_revocation IF NOT EXISTS 
FOR (c:StixCertificate) ON (c.is_revoked);

CREATE INDEX idx_indicator_tlp IF NOT EXISTS 
FOR (i:StixIndicator) ON (i.tlp_marking);

CREATE INDEX idx_threat_actor_name IF NOT EXISTS 
FOR (t:StixThreatActor) ON (t.name);

// ------------------------------------------------------------------------------
// 3. Seed Reference Entities & High-Profile Incident Graph (eMudhra Incident Simulation)
// ------------------------------------------------------------------------------

// Threat Actor: TA-0922 (AiTM Credential Harvester Group)
MERGE (ta:StixThreatActor {id: "threat-actor--7c9a9e34-58a4-4df1-8bc6-9817f53f9321"})
ON CREATE SET 
    ta.name = "TA-0922 (PhishBypass Operator)",
    ta.aliases = ["Storm-1152-affiliate", "ReverseProxy-Gang"],
    ta.description = "Adversary group utilizing Evilginx2 reverse-proxies and fraudulent intermediate certs.",
    ta.confidence = 90,
    ta.first_seen = datetime("2026-08-15T00:00:00Z"),
    ta.tlp_marking = "TLP:AMBER";

// Malicious ASN
MERGE (asn:StixASN {number: 62450})
ON CREATE SET 
    asn.organization = "Bulletproof Hostings LLC",
    asn.country = "SC",
    asn.risk_state = "malicious";

// Compromised Certificate (eMudhra ECDSA P-384 scalar vulnerability case)
MERGE (cert:StixCertificate {sha256_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
ON CREATE SET 
    cert.subject_cn = "eMudhra Sub-CA 2026 G3",
    cert.issuer_cn = "eMudhra Global Root CA",
    cert.key_algorithm = "ECDSA",
    cert.curve = "secp384r1",
    cert.key_size_bits = 384,
    cert.is_revoked = true,
    cert.revocation_reason = "Weak key generation during ceremony / scalar vulnerability",
    cert.valid_from = datetime("2026-01-01T00:00:00Z"),
    cert.valid_until = datetime("2027-01-01T00:00:00Z");

// JA4S AiTM Reverse Proxy Fingerprint (Evilginx2)
MERGE (ja4:StixJA4Fingerprint {hash: "t13d1516h2_8daaf6152771_b38696d92714"})
ON CREATE SET 
    ja4.label = "Evilginx2 Reverse-Proxy Signature",
    ja4.risk_state = "malicious",
    ja4.detected_tool = "Evilginx2 / Muraena";

// Malicious Phishing Domain Node
MERGE (dom:StixDomain {value: "auth-portal-microsoft.com.cdn-relay.cc"})
ON CREATE SET 
    dom.tld = "cc",
    dom.risk_state = "malicious",
    dom.age_days = 4,
    dom.created_at = datetime("2026-11-03T10:00:00Z");

// Malicious IP Node
MERGE (ip:StixIPv4Address {value: "185.220.101.5"})
ON CREATE SET 
    ip.country = "NL",
    ip.asn = 62450,
    ip.risk_state = "malicious";

// STIX Indicator
MERGE (ind:StixIndicator {id: "indicator--98b3c94f-f903-4f51-b0dc-0870f7cf7c6a"})
ON CREATE SET 
    ind.name = "PhishBypass Infrastructure Token",
    ind.pattern = "[domain-name:value = 'auth-portal-microsoft.com.cdn-relay.cc']",
    ind.pattern_type = "stix",
    ind.valid_from = datetime("2026-11-03T00:00:00Z"),
    ind.tlp_marking = "TLP:RED",
    ind.confidence = 95,
    ind.description = "Active AiTM credential harvester targeting Office 365 enterprise sessions.";

// ------------------------------------------------------------------------------
// 4. STIX 2.1 Relationship Objects (SROs) Linking the Infrastructure
// ------------------------------------------------------------------------------

MERGE (dom)-[:RESOLVES_TO]->(ip);
MERGE (ip)-[:ANNOUNCED_BY]->(asn);
MERGE (dom)-[:SECURED_BY]->(cert);
MERGE (dom)-[:FINGERPRINTED_AS]->(ja4);
MERGE (dom)-[:ATTRIBUTED_TO]->(ta);
MERGE (ind)-[:INDICATES]->(dom);
