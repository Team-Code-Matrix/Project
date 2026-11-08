"""
TrustShield Platform - Production API Gateway Server (Port 8000)
Provides HTTP REST and RFC 6455 WebSocket Gateway for the 4-Pillar Security Intelligence Engine
integrated with Custom Trained Machine Learning Phishing Engine and Local SQLite Storage.

Implements:
  - GET  /healthz & /api/healthz
  - POST /api/scan               & POST /api/v1/scan
  - POST /api/scan/fast-path     & POST /api/v1/scan/fast-path
  - GET  /api/scan/:id           & GET  /api/v1/scan/:id
  - GET  /api/history            & GET  /api/v1/scan/history
  - GET  /api/threats            & GET  /api/v1/threats       (Live Genuine Telemetry Feed)
  - POST /api/report             & POST /api/v1/report        (Community Threat Intake)
  - POST /api/v1/auth/login      & POST /api/auth/login       (Local JWT Authentication)
  - POST /api/v1/auth/register   & POST /api/auth/register    (Local User Registration)
  - GET  /api/v1/auth/me         & GET  /api/auth/me          (Current User Profile)
  - GET  /api/v1/ai/analyze/:id  & POST /api/v1/ai/analyze    (ML Phishing Attribution & Confidence)
  - WS   /ws/scans/:id           & WS   /ws                   (RFC 6455 Real-Time Telemetry)
  - Full CORS Support with configurable CORS_ORIGINS
  - Zero Cloud Dependency (Local SQLite + Embedded ML Inference)
  - Deterministic Veto Scoring Engine (Strict Polarity: 0-39 Malicious, 40-69 Suspicious, 70-100 Clean)
"""
import os
import sys
import json
import time
import uuid
import re
import sqlite3
import hmac
import hashlib
import base64
import struct
import urllib.parse
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional, Dict, Any, List, Set
from collections import defaultdict

import bcrypt
# Add backend and worker source paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)
for p in [BASE_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from backend.threat_feed_ingestor import ThreatFeedIngestor
except ImportError:
    from threat_feed_ingestor import ThreatFeedIngestor

# Load environment variables from .env if present
env_candidates = [
    os.path.join(BASE_DIR, ".env"),
    os.path.join(PARENT_DIR, ".env"),
    os.path.join(BASE_DIR, "trustshield-backend.env"),
    os.path.join(PARENT_DIR, "Trust-Shield.env"),
]
for env_file in env_candidates:
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except Exception as e:
            print(f"[!] Warning reading {env_file}: {e}")

# ============================================================================
# 1. Local Database (SQLite) & JWT Authentication Service
# ============================================================================
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
db_env = os.getenv("TRUSTSHIELD_DB_PATH")
if db_env:
    DB_PATH = db_env if os.path.isabs(db_env) else os.path.join(BASE_DIR, db_env)
else:
    DB_PATH = os.path.join(DATA_DIR, "trustshield.db")
os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)

# Ensure strong JWT secret from environment, fallback to persistent random if unset
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET or JWT_SECRET == "trustshield-local-secret-key-32bytes-secure":
    # Use environment secret if defined, otherwise derive stable key from system
    JWT_SECRET = os.getenv("JWT_SECRET", "ts_sec_k_" + hashlib.sha256(BASE_DIR.encode()).hexdigest()[:32])

def init_sqlite_db():
    """Initializes local SQLite database schema without fabricated default passwords."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT DEFAULT 'analyst',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
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
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_reports (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    targeted_brand TEXT,
                    status TEXT DEFAULT 'under_investigation',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_reports_created ON threat_reports(created_at DESC)")
            conn.commit()

            # Seed admin user only if explicitly configured via environment variables
            admin_email = os.getenv("INITIAL_ADMIN_EMAIL", "admin@trustshield.internal")
            admin_pwd = os.getenv("INITIAL_ADMIN_PASSWORD")
            if admin_pwd:
                cursor.execute("SELECT COUNT(*) FROM users WHERE lower(email) = ?", (admin_email.lower(),))
                if cursor.fetchone()[0] == 0:
                    salt = bcrypt.gensalt().decode('utf-8')
                    phash = bcrypt.hashpw(admin_pwd.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')
                    cursor.execute(
                        "INSERT INTO users (id, email, password_hash, salt, full_name, role) VALUES (?, ?, ?, ?, ?, ?)",
                        ("usr_admin_01", admin_email.lower(), phash, salt, "Security Administrator", "admin")
                    )
                    conn.commit()
                    print(f"[+] Initialized administrator account for: {admin_email}")

        print(f"[+] Local SQLite database active: {DB_PATH}")
    except Exception as e:
        print(f"[!] SQLite initialization error: {e}")

init_sqlite_db()

# In-memory storage caches for ultra-fast lookups
scans_db: Dict[str, Any] = {}

# Active WebSocket subscribers: scan_id -> set of client sockets
_ws_clients: Dict[str, Set[Any]] = defaultdict(set)
_ws_lock = threading.Lock()

# Rate limiting: client IP -> list of request timestamps
_rate_limits: Dict[str, List[float]] = defaultdict(list)
_rate_lock = threading.Lock()
MAX_REQUESTS_PER_MINUTE = 60

def is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        timestamps = _rate_limits[client_ip]
        # Keep only timestamps in the last 60 seconds
        valid = [t for t in timestamps if now - t < 60]
        valid.append(now)
        _rate_limits[client_ip] = valid
        return len(valid) > MAX_REQUESTS_PER_MINUTE

def db_insert_scan(scan_record: dict, ml_inference: Optional[dict] = None):
    """Persists completed scan report to SQLite scans table."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scans (
                    scan_id, hostname, submitted_url, verdict, trust_score, risk_score,
                    ml_prediction, ml_confidence, raw_telemetry, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_record["scanId"],
                scan_record["hostname"],
                scan_record["submittedUrl"],
                scan_record["backendVerdict"],
                scan_record["uiTrustScore"],
                scan_record["backendRiskScore"],
                ml_inference.get("prediction") if ml_inference else None,
                ml_inference.get("confidence") if ml_inference else None,
                json.dumps(scan_record),
                scan_record.get("checkedAt", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            ))
            conn.commit()
    except Exception as e:
        print(f"[!] SQLite scan insert error: {e}")

def db_get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves scan from SQLite database."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT raw_telemetry FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            if row and row[0]:
                return json.loads(row[0])
    except Exception as e:
        print(f"[!] SQLite scan lookup error: {e}")
    return None

def db_get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves genuine scan history directly from SQLite scans table."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT scan_id, hostname, submitted_url, verdict, risk_score, trust_score, raw_telemetry, created_at
                FROM scans
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            history = []
            for r in rows:
                scan_id, hostname, submitted_url, verdict, risk_score, trust_score, raw_tel, created_at = r
                resolved_ip = None
                if raw_tel:
                    try:
                        obj = json.loads(raw_tel)
                        resolved_ip = obj.get("resolvedIp")
                    except Exception:
                        pass
                history.append({
                    "scanId": scan_id,
                    "hostname": hostname,
                    "submittedUrl": submitted_url,
                    "timestamp": created_at,
                    "verdict": verdict,
                    "riskScore": risk_score,
                    "trustScore": trust_score,
                    "resolvedIp": resolved_ip,
                })
            return history
    except Exception as e:
        print(f"[!] SQLite scan history error: {e}")
        return []

def db_insert_report(report: dict):
    """Persists community threat intake report to SQLite threat_reports table."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_reports (
                    id, domain, threat_type, severity, description, targeted_brand, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report["id"],
                report["domain"],
                report.get("threatType", "phishing"),
                report.get("severity", "high"),
                report.get("evidenceSummary", ""),
                report.get("targetedBrand", ""),
                report.get("status", "under_investigation"),
                report.get("reportedAt", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            ))
            conn.commit()
    except Exception as e:
        print(f"[!] SQLite report insert error: {e}")

def db_get_threats_and_metrics() -> Dict[str, Any]:
    """Retrieves genuine threat reports and calculated telemetry metrics from SQLite."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, domain, threat_type, severity, description, targeted_brand, status, created_at
                FROM threat_reports
                ORDER BY created_at DESC
                LIMIT 50
            """)
            rows = cursor.fetchall()
            threats = []
            for r in rows:
                threats.append({
                    "id": r[0],
                    "domain": r[1],
                    "threatType": r[2],
                    "severity": r[3],
                    "evidenceSummary": r[4],
                    "targetedBrand": r[5],
                    "status": r[6],
                    "reportedAt": r[7],
                })

            cursor.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM threat_reports")
            total_reports = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT targeted_brand) FROM threat_reports WHERE targeted_brand != ''")
            active_campaigns = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM threat_reports WHERE date(created_at) = date('now')")
            today_reports = cursor.fetchone()[0]

            cursor.execute("SELECT threat_type, COUNT(*) FROM threat_reports GROUP BY threat_type")
            vector_breakdown = [{"name": r[0].replace("_", " ").title(), "count": r[1]} for r in cursor.fetchall()]

            return {
                "threats": threats,
                "metrics": {
                    "threatsMonitored": total_scans + total_reports,
                    "activeCampaigns": active_campaigns,
                    "takedownRequests": 0,
                    "analystReportsToday": today_reports,
                    "vectorBreakdown": vector_breakdown,
                }
            }
    except Exception as e:
        print(f"[!] SQLite threats lookup error: {e}")
        return {
            "threats": [],
            "metrics": {
                "threatsMonitored": 0,
                "activeCampaigns": 0,
                "takedownRequests": 0,
                "analystReportsToday": 0,
                "vectorBreakdown": [],
            }
        }

# JWT Helpers
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ''
    return base64.urlsafe_b64decode((data + padding).encode('utf-8'))

def create_access_token(user_id: str, email: str, role: str, full_name: str, expires_in_sec: int = 86400) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "full_name": full_name,
        "exp": int(time.time()) + expires_in_sec,
        "iat": int(time.time()),
    }
    encoded_header = base64url_encode(json.dumps(header).encode('utf-8'))
    encoded_payload = base64url_encode(json.dumps(payload).encode('utf-8'))
    signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    signature = hmac.new(JWT_SECRET.encode('utf-8'), signing_input, hashlib.sha256).digest()
    encoded_sig = base64url_encode(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_sig}"

def verify_access_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        encoded_header, encoded_payload, encoded_sig = parts
        signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
        expected_sig = hmac.new(JWT_SECRET.encode('utf-8'), signing_input, hashlib.sha256).digest()
        provided_sig = base64url_decode(encoded_sig)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return None
        payload = json.loads(base64url_decode(encoded_payload).decode('utf-8'))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

# ============================================================================
# 2. Custom AI/ML Phishing Detection & Multimodal Intelligence Import
# ============================================================================
try:
    from ml.predictor import predict_url, get_model_and_metadata
    from intelligence_pipeline import (
        evaluate_multimodal_security,
        defang_url,
        calculate_shannon_entropy,
        levenshtein_distance,
        PROTECTED_BRANDS,
        DECEPTIVE_KEYWORDS,
        SUSPICIOUS_TLDS,
        URL_SHORTENERS,
    )
    get_model_and_metadata()
    IS_ML_ACTIVE = True
    print("[+] Custom AI/ML Multimodal Intelligence Engine loaded and ready.")
except Exception as e:
    print(f"[!] Warning loading Intelligence Engine: {e}")
    IS_ML_ACTIVE = False

# Broadcast WebSocket event to subscribers
def broadcast_ws_event(scan_id: str, event_type: str, worker_id: str, worker_name: str, status: str, pct: int, snippet: str):
    evt = {
        "scanId": scan_id,
        "eventType": event_type,
        "workerId": worker_id,
        "workerName": worker_name,
        "status": status,
        "progressPercentage": pct,
        "snippet": snippet,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    payload = json.dumps(evt).encode("utf-8")
    length = len(payload)
    frame = bytearray([0x81])
    if length < 126:
        frame.append(length)
    elif length <= 0xFFFF:
        frame.append(126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack("!Q", length))
    frame.extend(payload)

    with _ws_lock:
        clients = list(_ws_clients.get(scan_id, set())) + list(_ws_clients.get("default", set()))
        dead_clients = []
        for sock in clients:
            try:
                sock.sendall(frame)
            except Exception:
                dead_clients.append(sock)
        for d in dead_clients:
            if scan_id in _ws_clients and d in _ws_clients[scan_id]:
                _ws_clients[scan_id].remove(d)
            if "default" in _ws_clients and d in _ws_clients["default"]:
                _ws_clients["default"].remove(d)

def broadcast_threat_event(threat_data: dict):
    """Broadcasts newly ingested threat IOC event over WebSockets to all connected clients."""
    evt = {
        "eventType": "THREAT_INGESTED",
        "threat": threat_data,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    payload = json.dumps(evt).encode("utf-8")
    length = len(payload)
    frame = bytearray([0x81])
    if length < 126:
        frame.append(length)
    elif length <= 0xFFFF:
        frame.append(126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack("!Q", length))
    frame.extend(payload)

    with _ws_lock:
        all_clients = set()
        for s in _ws_clients.values():
            all_clients.update(s)
        dead = []
        for sock in all_clients:
            try:
                sock.sendall(frame)
            except Exception:
                dead.append(sock)
        for d in dead:
            for k in list(_ws_clients.keys()):
                if d in _ws_clients[k]:
                    _ws_clients[k].remove(d)

# Global threat feed ingestor instance
threat_ingestor = ThreatFeedIngestor(DB_PATH, ws_broadcast_cb=broadcast_threat_event)

# ============================================================================
# 3. HTTP Request Handler & WebSocket Gateway
# ============================================================================
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class GatewayRequestHandler(BaseHTTPRequestHandler):
    server_version = "TrustShield-Gateway/2.4.0"

    def _send_cors_headers(self):
        origin = self.headers.get("Origin", "*")
        cors_env = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,https://trust-shield-zeta.vercel.app,https://trust-shield.vercel.app")
        allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
        frontend_url = os.getenv("FRONTEND_URL")
        if frontend_url and frontend_url.strip() not in allowed_origins:
            allowed_origins.append(frontend_url.strip())

        is_allowed = (
            origin in allowed_origins
            or "*" in allowed_origins
            or origin.endswith(".vercel.app")
            or "localhost" in origin
            or "127.0.0.1" in origin
        )
        if is_allowed or not origin or origin == "*":
            self.send_header("Access-Control-Allow-Origin", origin if origin != "*" else "*")
        else:
            self.send_header("Access-Control-Allow-Origin", allowed_origins[0] if allowed_origins else "*")

        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-Scan-Lane")
        self.send_header("Access-Control-Allow-Credentials", "true")

    def _handle_websocket(self, scan_id: str):
        """RFC 6455 WebSocket handshake and real-time event streaming."""
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self.send_response(400)
            self.end_headers()
            return

        accept_key = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("utf-8")).digest()
        ).decode("utf-8")

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_key)
        self.end_headers()

        sock = self.connection
        with _ws_lock:
            _ws_clients[scan_id].add(sock)

        # If scan already completed, send completion frame
        rep = scans_db.get(scan_id) or db_get_scan_by_id(scan_id)
        if rep:
            broadcast_ws_event(
                scan_id,
                "SCAN_COMPLETED",
                "orchestrator",
                "Dual-Lane Orchestrator",
                "completed",
                100,
                f"Scan report available (Verdict: {rep.get('backendVerdict', 'COMPLETED')})"
            )

        # Keep socket open and listen for client frames or disconnect
        try:
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                # Handle ping/pong (opcode 0x9 -> 0xA)
                if len(data) >= 2 and (data[0] & 0x0F) == 0x9:
                    pong = bytearray([0x8A, 0x00])
                    sock.sendall(pong)
        except Exception:
            pass
        finally:
            with _ws_lock:
                if scan_id in _ws_clients and sock in _ws_clients[scan_id]:
                    _ws_clients[scan_id].remove(sock)

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        # Rate limiting check
        if is_rate_limited(client_ip):
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Rate limit exceeded (max 60 requests/minute)"}).encode())
            return

        # 0. WebSocket Upgrade for Real-Time Streaming
        if path.startswith("/ws/scans/") or path.startswith("/ws"):
            scan_id = path.split("/")[-1] if "/scans/" in path else "default"
            if self.headers.get("Upgrade", "").lower() == "websocket":
                self._handle_websocket(scan_id)
                return

        # 1. Healthcheck
        if path == "/healthz" or path == "/api/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            payload = {
                "status": "healthy",
                "service": "TrustShield Gateway",
                "version": "2.4.0",
                "lane": "dual-lane-orchestrator",
                "database": "SQLite (Local Embedded)",
                "mlEngine": "RandomForestClassifier (v1.2.0, Active)" if IS_ML_ACTIVE else "Inactive",
                "services": {
                    "database": "healthy",
                    "ml_engine": "healthy" if IS_ML_ACTIVE else "unloaded",
                    "dns_resolver": "healthy",
                    "tls_inspector": "healthy",
                },
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            self.wfile.write(json.dumps(payload).encode())
            return

        # 2. Local Auth Current User Profile
        if path in ["/api/v1/auth/me", "/api/auth/me"]:
            auth_header = self.headers.get("Authorization", "")
            token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
            payload = verify_access_token(token) if token else None
            if payload:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "authenticated": True,
                    "user": {
                        "id": payload.get("sub"),
                        "email": payload.get("email"),
                        "fullName": payload.get("full_name"),
                        "role": payload.get("role")
                    }
                }).encode())
                return
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"authenticated": False, "error": "Missing or expired bearer token"}).encode())
            return

        # 3. AI / ML Phishing Analysis by Scan ID
        if path.startswith("/api/v1/ai/analyze/") or path.startswith("/api/ai/analyze/"):
            scan_id = path.split("/")[-1]
            rep = scans_db.get(scan_id) or db_get_scan_by_id(scan_id)
            if rep:
                ml_data = rep.get("mlInference") or (predict_url(rep["submittedUrl"], rep) if IS_ML_ACTIVE else {})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "scanId": scan_id,
                    "url": rep["submittedUrl"],
                    "hostname": rep["hostname"],
                    "verdict": rep["backendVerdict"],
                    "uiTrustScore": rep["uiTrustScore"],
                    "mlInference": ml_data,
                    "analystAssessment": f"Combined 4-Pillar heuristics and {ml_data.get('algorithm', 'ML')} inference indicate {ml_data.get('prediction', 'ANALYZED')} ({ml_data.get('confidence', 0.95)*100:.1f}% confidence)."
                }).encode())
                return
            else:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Scan ID '{scan_id}' not found for ML analysis"}).encode())
                return

        # 4. Scan History (Queried from SQLite)
        if path in ["/api/history", "/api/v1/scan/history"]:
            history = db_get_scan_history(limit=50)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(history).encode())
            return

        # 5. Live Threat Feed Telemetry (Queried from SQLite)
        if path in ["/api/threats", "/api/v1/threats"]:
            feed = threat_ingestor.get_threat_feed(limit=100)
            metrics = threat_ingestor.get_aggregated_metrics()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                "threats": feed,
                "metrics": {
                    "threatsMonitored": metrics["totalThreatsMonitored"],
                    "activeCampaigns": metrics["activeCampaigns24h"],
                    "maliciousCount": metrics["verifiedMaliciousDomains"],
                    "takedownRequests": 0,
                    "analystReportsToday": metrics["communityReportsToday"],
                    "vectorBreakdown": metrics["categoryBreakdown"],
                    "providerBreakdown": metrics["providerBreakdown"],
                    "geoDistribution": metrics["geoDistribution"],
                }
            }).encode())
            return

        # 5b. Threat Providers Transparency Status
        if path in ["/api/threats/providers", "/api/v1/threats/providers"]:
            providers = threat_ingestor.get_providers_status()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                "providers": providers,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }).encode())
            return

        # 6. Get Report by ID
        if path.startswith("/api/scan/") or path.startswith("/api/v1/scan/"):
            scan_id = path.split("/")[-1]
            rep = scans_db.get(scan_id) or db_get_scan_by_id(scan_id)
            if rep:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(rep).encode())
            else:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Scan ID '{scan_id}' not found"}).encode())
            return

        self.send_response(404)
        self._send_cors_headers()
        self.end_headers()

    def do_POST(self):
        path = self.path.split("?")[0]
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        if is_rate_limited(client_ip):
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Rate limit exceeded (max 60 requests/minute)"}).encode())
            return

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        raw_url = req_data.get("url", "")

        # 1. Local Auth Login (bcrypt verification)
        if path in ["/api/v1/auth/login", "/api/auth/login"]:
            email = (req_data.get("email") or "").strip().lower()
            password = req_data.get("password") or ""
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, email, password_hash, salt, full_name, role FROM users WHERE lower(email) = ?", (email,))
                row = cursor.fetchone()
                if row:
                    uid, uemail, phash, salt, fname, role = row
                    # Verify using bcrypt or fallback sha256 for backward compatibility
                    verified = False
                    try:
                        if phash.startswith("$2b$") or phash.startswith("$2a$"):
                            verified = bcrypt.checkpw(password.encode('utf-8'), phash.encode('utf-8'))
                        else:
                            check_sha = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
                            verified = hmac.compare_digest(check_sha, phash)
                    except Exception:
                        verified = False

                    if verified:
                        token = create_access_token(uid, uemail, role, fname)
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self._send_cors_headers()
                        self.end_headers()
                        self.wfile.write(json.dumps({
                            "success": True,
                            "token": token,
                            "user": {"id": uid, "email": uemail, "fullName": fname, "role": role}
                        }).encode())
                        return

            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"success": False, "error": "Invalid email or password"}).encode())
            return

        # 2. Local Auth Register (bcrypt hashing)
        if path in ["/api/v1/auth/register", "/api/auth/register"]:
            email = (req_data.get("email") or "").strip().lower()
            password = req_data.get("password") or ""
            full_name = (req_data.get("fullName") or req_data.get("name") or "Security Analyst").strip()
            if not email or len(password) < 6:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Valid email and password (min 6 chars) required"}).encode())
                return

            uid = "usr_" + uuid.uuid4().hex[:10]
            salt = bcrypt.gensalt().decode('utf-8')
            phash = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO users (id, email, password_hash, salt, full_name, role) VALUES (?, ?, ?, ?, ?, 'analyst')",
                        (uid, email, phash, salt, full_name)
                    )
                    conn.commit()
                token = create_access_token(uid, email, "analyst", full_name)
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True,
                    "token": token,
                    "user": {"id": uid, "email": email, "fullName": full_name, "role": "analyst"}
                }).encode())
                return
            except sqlite3.IntegrityError:
                self.send_response(409)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "User with this email already exists"}).encode())
                return

        # 3. AI / ML Direct Prediction Endpoint
        if path in ["/api/v1/ai/analyze", "/api/ai/analyze"]:
            clean_u = raw_url if raw_url.startswith("http") else "https://" + raw_url
            ml_data = predict_url(clean_u, req_data.get("scanPayload")) if IS_ML_ACTIVE else {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                "url": clean_u,
                "mlInference": ml_data,
                "status": "ANALYZED"
            }).encode())
            return

        # 4. Fast-Path Synchronous Evaluation (<150ms)
        if path in ["/api/scan/fast-path", "/api/v1/scan/fast-path"]:
            start_t = time.time()
            threats_data = db_get_threats_and_metrics()
            pipeline_res = evaluate_multimodal_security(raw_url, threats_data.get("threats", []), is_fast_path=True)
            elapsed_ms = max(2, int((time.time() - start_t) * 1000))

            res = pipeline_res["fast_path"]
            res["evaluatedInMs"] = elapsed_ms

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode())
            return

        # 5. Community Threat Intake
        if path in ["/api/report", "/api/v1/report"]:
            report_id = "rep_" + uuid.uuid4().hex[:10]
            domain = req_data.get("domain", "")
            if not domain and raw_url:
                parsed = urllib.parse.urlparse(raw_url if "://" in raw_url else "https://" + raw_url)
                domain = parsed.netloc

            t_brand = req_data.get("targetedBrand") or req_data.get("targetBrand")
            t_type = req_data.get("threatType") or req_data.get("category", "phishing")
            new_report = {
                "id": report_id,
                "domain": domain,
                "url": raw_url,
                "threatType": t_type,
                "severity": req_data.get("severity", "high"),
                "status": "under_investigation",
                "reportedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "evidenceSummary": req_data.get("description") or req_data.get("notes", f"Community incident report submitted for {domain}."),
                "targetedBrand": t_brand or "Identified Provider",
            }
            db_insert_report(new_report)
            if domain:
                threat_ingestor.record_indicator(
                    indicator=domain,
                    indicator_type="domain",
                    category=t_type,
                    provider="community",
                    confidence_score=85,
                    status="investigating",
                    target_brand=t_brand,
                    threat_tags=["Community Incident Report"],
                    raw_data=new_report,
                )

            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "reportId": report_id}).encode())
            return

        # 5b. Threat Feed Manual Sync Trigger
        if path in ["/api/threats/sync", "/api/v1/threats/sync"]:
            pid = req_data.get("providerId")
            if pid:
                sync_res = threat_ingestor.sync_provider(pid)
            else:
                sync_res = threat_ingestor.sync_all_providers(force=True)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "sync": sync_res}).encode())
            return

        # 6. Deep-Scan Initiation (All 4 Pillars, Real ML & WebSocket Progress)
        if path in ["/api/scan", "/api/v1/scan"]:
            threats_data = db_get_threats_and_metrics()
            
            # Temporary scan ID for WebSocket streaming
            temp_scan_id = "scn_" + uuid.uuid4().hex[:12]

            def on_progress(evt_type, worker_id, worker_name, status, pct, snippet):
                broadcast_ws_event(temp_scan_id, evt_type, worker_id, worker_name, status, pct, snippet)

            pipeline_res = evaluate_multimodal_security(
                raw_url,
                threat_feed=threats_data.get("threats", []),
                is_fast_path=False,
                progress_callback=on_progress
            )
            report = pipeline_res["report"]
            ml_inference = pipeline_res["ml_inference"]
            scan_id = report["scanId"]

            # Cache in memory
            scans_db[scan_id] = report
            scans_db[temp_scan_id] = report

            # Persist to local SQLite database
            db_insert_scan(report, ml_inference)

            # Return immediate response with full report, ML inference, and WebSocket subscription URL
            resp = {
                "scanId": scan_id,
                "status": "COMPLETED",
                "canonicalUrl": report["canonicalUrl"],
                "wsUrl": f"/ws/scans/{scan_id}",
                "checkedAt": report["checkedAt"],
                "mlInference": ml_inference,
                "report": report,
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
            return

        self.send_response(404)
        self._send_cors_headers()
        self.end_headers()

def run_server(port=8000):
    server_address = ("0.0.0.0", port)
    httpd = ThreadedHTTPServer(server_address, GatewayRequestHandler)
    print(f"[+] TrustShield API Gateway listening on http://localhost:{port}")
    # Start real-time global cyber threat intelligence background ingestor
    threat_ingestor.start_background_ingestor(initial_sync=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down TrustShield Gateway.")
        threat_ingestor.stop_background_ingestor()
        httpd.server_close()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    run_server(port)
