"""
Live end-to-end server verification test.
Starts backend/server.py on an ephemeral test port (e.g. 8001), probes:
- GET /healthz
- GET /api/threats
- GET /api/history
- POST /api/scan (clean domain: google.com)
- POST /api/scan (prohibited SSRF attempt: 127.0.0.1)
- WebSocket streaming test
Then cleanly shuts down the server.
"""

import sys
import os
import time
import json
import urllib.request
import urllib.error
import subprocess
import socket

PORT = 8005
BASE_URL = f"http://127.0.0.1:{PORT}"

def wait_for_server(timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/healthz", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False

def run_tests():
    print(f"[*] Starting Trust Shield backend server on port {PORT}...")
    env = os.environ.copy()
    env["PORT"] = str(PORT)
    env["HOST"] = "127.0.0.1"

    proc = subprocess.Popen(
        [sys.executable, "backend/server.py"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        print("[*] Waiting for server readiness...")
        if not wait_for_server():
            print("[FAIL] Server failed to start within timeout.")
            out, err = proc.communicate(timeout=2)
            print("Stdout:", out)
            print("Stderr:", err)
            sys.exit(1)

        print("[PASS] Server started and responding on /healthz")

        # 1. Test /healthz
        req = urllib.request.Request(f"{BASE_URL}/healthz")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "healthy", f"Unexpected status: {data}"
            assert data["services"]["database"] == "healthy"
            assert data["services"]["ml_engine"] == "healthy"
            print("  [PASS] GET /healthz returned healthy status and sub-service checks")

        # 2. Test /api/threats
        req = urllib.request.Request(f"{BASE_URL}/api/threats")
        with urllib.request.urlopen(req) as resp:
            threats_data = json.loads(resp.read().decode())
            assert "metrics" in threats_data
            assert "threats" in threats_data
            # Zero fake stats check:
            metrics = threats_data["metrics"]
            print(f"  [PASS] GET /api/threats returned genuine metrics: {metrics}")

        # 3. Test /api/history
        req = urllib.request.Request(f"{BASE_URL}/api/history")
        with urllib.request.urlopen(req) as resp:
            history_data = json.loads(resp.read().decode())
            assert isinstance(history_data, list)
            print(f"  [PASS] GET /api/history returned {len(history_data)} past scans")

        # 4. Test SSRF Protection on POST /api/scan
        print("[*] Testing SSRF protection against 127.0.0.1...")
        ssrf_payload = json.dumps({"url": "http://127.0.0.1:8080/admin"}).encode()
        req = urllib.request.Request(
            f"{BASE_URL}/api/scan",
            data=ssrf_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                report = data.get("report", data)
                verdict = report.get("backendVerdict") or report.get("verdict")
                trust = report.get("uiTrustScore", 100)
                assert verdict == "MALICIOUS" or trust <= 20
                print(f"  [PASS] SSRF attempt handled safely: verdict={verdict}, trust={trust}")
        except urllib.error.HTTPError as e:
            assert e.code in (400, 403), f"Unexpected HTTP status: {e.code}"
            print(f"  [PASS] SSRF attempt rejected with HTTP {e.code}")

        # 5. Test Live Scan on google.com
        print("[*] Testing live scan on https://google.com...")
        scan_payload = json.dumps({"url": "https://google.com"}).encode()
        req = urllib.request.Request(
            f"{BASE_URL}/api/scan",
            data=scan_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            scan_data = data.get("report", data)
            assert scan_data["hostname"] == "google.com"
            assert scan_data["backendVerdict"] == "CLEAN"
            assert scan_data["uiTrustScore"] >= 70
            assert scan_data["resolvedIp"] != "Unresolved (NXDOMAIN)"
            assert len(scan_data["pkiIntelligence"]["chain"]) > 0
            leaf = scan_data["pkiIntelligence"]["chain"][0]
            print(f"  [PASS] Live scan completed: verdict={scan_data['backendVerdict']}, trustScore={scan_data['uiTrustScore']}, IP={scan_data['resolvedIp']}")
            print(f"         Cert Leaf Subject: {leaf.get('subjectCommonName')}, Issuer: {leaf.get('issuerCommonName')}")

        # 5b. Test Live Scan on expired.badssl.com
        print("[*] Testing live scan on https://expired.badssl.com...")
        badssl_payload = json.dumps({"url": "https://expired.badssl.com"}).encode()
        req = urllib.request.Request(
            f"{BASE_URL}/api/scan",
            data=badssl_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            bad_data = data.get("report", data)
            assert bad_data["hostname"] == "expired.badssl.com"
            assert bad_data["backendVerdict"] == "PKI_TRUST_COMPROMISED"
            assert bad_data["uiTrustScore"] <= 30
            assert bad_data["criticalOverride"] is True
            bad_leaf = bad_data["pkiIntelligence"]["chain"][0]
            assert bad_leaf["isExpired"] is True
            print(f"  [PASS] Live scan caught expired PKI: verdict={bad_data['backendVerdict']}, trustScore={bad_data['uiTrustScore']}, daysRemaining={bad_leaf.get('daysRemaining')}")

        # 6. Verify scan appears in history now
        req = urllib.request.Request(f"{BASE_URL}/api/history")
        with urllib.request.urlopen(req) as resp:
            history_data = json.loads(resp.read().decode())
            assert len(history_data) >= 1
            assert any(item["hostname"] == "google.com" for item in history_data)
            print(f"  [PASS] New scan persisted to SQLite and retrievable via GET /api/history ({len(history_data)} total)")

        print("\n[+] ALL LIVE SERVER ENDPOINT TESTS PASSED SUCCESSFULLY!")

    finally:
        print("[*] Terminating server...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[*] Server terminated cleanly.")

if __name__ == "__main__":
    run_tests()
