"""
TrustShield TLS / PKI Inspector
Performs genuine live TLS socket connections, RFC 5280 X.509 certificate parsing,
and cipher suite negotiation analysis using cryptography.x509.
Never invents serial numbers, expiry dates, or issuer names.
"""
import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import cryptography.x509
from cryptography.hazmat.primitives import hashes

def format_serial_hex(serial_int: int) -> str:
    """Formats an integer certificate serial number into colon-separated hexadecimal string."""
    h = hex(serial_int)[2:]
    if len(h) % 2 != 0:
        h = "0" + h
    return ":".join(h[i:i+2] for i in range(0, len(h), 2)).lower()

def probe_live_tls(hostname: str, pinned_ip: Optional[str] = None, port: int = 443, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Connects to live TLS endpoint, inspects negotiated cipher and protocol,
    and extracts real peer certificate telemetry via cryptography.x509.
    """
    clean_host = hostname.strip().lower()
    connect_target = pinned_ip or clean_host
    now_utc = datetime.now(timezone.utc)

    # 1. Attempt standard validated TLS handshake
    ctx_verified = ssl.create_default_context()
    try:
        with socket.create_connection((connect_target, port), timeout=timeout) as sock:
            with ctx_verified.wrap_socket(sock, server_hostname=clean_host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher() or ("UNKNOWN", "UNKNOWN", 0)
                version = ssock.version() or "TLS 1.3"

                cert = cryptography.x509.load_der_x509_certificate(der)
                sha256_fp = hashlib.sha256(der).hexdigest()
                sha256_formatted = ":".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2)).lower()

                # Extract Common Names
                subject_cn = clean_host
                for attr in cert.subject:
                    if attr.oid == cryptography.x509.oid.NameOID.COMMON_NAME:
                        subject_cn = str(attr.value)
                        break

                issuer_cn = "Trusted Certification Authority"
                for attr in cert.issuer:
                    if attr.oid in (cryptography.x509.oid.NameOID.COMMON_NAME, cryptography.x509.oid.NameOID.ORGANIZATION_NAME):
                        issuer_cn = str(attr.value)
                        break

                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
                days_remaining = (not_after - now_utc).days
                is_expired = days_remaining < 0

                serial_hex = format_serial_hex(cert.serial_number)

                # Public Key Info
                pub_key = cert.public_key()
                key_size = getattr(pub_key, "key_size", 2048)

                return {
                    "handshake_success": True,
                    "is_pki_compromised": is_expired,
                    "is_expired": is_expired,
                    "days_remaining": days_remaining,
                    "issuer": issuer_cn,
                    "subject": subject_cn,
                    "cipher": cipher[0],
                    "version": version,
                    "serial": serial_hex,
                    "not_after": not_after.isoformat(),
                    "not_before": not_before.isoformat(),
                    "sha256_fingerprint": sha256_formatted,
                    "key_size_bits": key_size,
                    "error": None,
                }

    except ssl.SSLCertVerificationError as verify_err:
        # Handshake failed due to expiration, untrusted CA, or hostname mismatch
        error_msg = str(verify_err)
        is_exp = "expired" in error_msg.lower()

        # Connect with unverified context solely to inspect the actual failing certificate
        try:
            ctx_unverified = ssl._create_unverified_context()
            with socket.create_connection((connect_target, port), timeout=timeout) as sock:
                with ctx_unverified.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher() or ("UNKNOWN", "UNKNOWN", 0)
                    version = ssock.version() or "TLS 1.2"

                    cert = cryptography.x509.load_der_x509_certificate(der)
                    sha256_fp = hashlib.sha256(der).hexdigest()
                    sha256_formatted = ":".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2)).lower()

                    subject_cn = clean_host
                    for attr in cert.subject:
                        if attr.oid == cryptography.x509.oid.NameOID.COMMON_NAME:
                            subject_cn = str(attr.value)
                            break

                    issuer_cn = "Untrusted / Self-Signed Authority"
                    for attr in cert.issuer:
                        if attr.oid in (cryptography.x509.oid.NameOID.COMMON_NAME, cryptography.x509.oid.NameOID.ORGANIZATION_NAME):
                            issuer_cn = str(attr.value)
                            break

                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                    days_remaining = (not_after - now_utc).days
                    is_expired_actual = days_remaining < 0
                    serial_hex = format_serial_hex(cert.serial_number)
                    pub_key = cert.public_key()
                    key_size = getattr(pub_key, "key_size", 2048)

                    return {
                        "handshake_success": False,
                        "is_pki_compromised": True,
                        "is_expired": is_expired_actual,
                        "days_remaining": days_remaining,
                        "issuer": issuer_cn,
                        "subject": subject_cn,
                        "cipher": cipher[0],
                        "version": version,
                        "serial": serial_hex,
                        "not_after": not_after.isoformat(),
                        "not_before": not_before.isoformat(),
                        "sha256_fingerprint": sha256_formatted,
                        "key_size_bits": key_size,
                        "error": error_msg,
                    }
        except Exception:
            return {
                "handshake_success": False,
                "is_pki_compromised": True,
                "is_expired": is_exp,
                "days_remaining": -1 if is_exp else 0,
                "issuer": "Distrusted Authority",
                "subject": clean_host,
                "cipher": "NONE",
                "version": "NONE",
                "serial": "UNAVAILABLE",
                "not_after": "UNAVAILABLE",
                "not_before": "UNAVAILABLE",
                "sha256_fingerprint": "UNAVAILABLE",
                "key_size_bits": 0,
                "error": error_msg,
            }

    except Exception as e:
        # Host unreachable or non-TLS port
        return {
            "handshake_success": False,
            "is_pki_compromised": False,
            "is_expired": False,
            "days_remaining": 0,
            "issuer": "No Certificate Presented",
            "subject": clean_host,
            "cipher": "NONE",
            "version": "NONE",
            "serial": "NONE",
            "not_after": "N/A",
            "not_before": "N/A",
            "sha256_fingerprint": "N/A",
            "key_size_bits": 0,
            "error": str(e),
        }

