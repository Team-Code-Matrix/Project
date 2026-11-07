"""
Pillar 1 Consumer: Intelligent Phishing, Headless Browser Detonation & Computer Vision Worker
Consumes URL tasks from Kafka topic 'trustshield.pillar1.phishing' or 'trustshield.scan.tasks'
Executes Playwright detonation, DOM heuristics, YARA matching, and pHash Brand Impersonation.
"""
import os
import sys
import json
import time
import logging

# Include monorepo shared python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
from shared.libs.python.anti_ssrf import validate_url_safe, AntiSSRFException, defang_url
from shared.libs.python.models import (
    PhishingDetonationTelemetry,
    RedirectHop,
    DomHeuristics,
    ComputerVisionTelemetry,
    Finding,
    FindingSeverity,
    FindingCategory,
)
from heuristics.dom_analyzer import analyze_html_dom
from vision.brand_matcher import evaluate_brand_impersonation
from detonation.browser_runner import run_headless_detonation

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Pillar1-Worker] %(message)s")
logger = logging.getLogger("pillar1-worker")

def process_phishing_task(task: dict) -> dict:
    scan_id = task.get("scan_id", "unknown")
    submitted_url = task.get("submitted_url", "")
    hostname = task.get("hostname", "")

    logger.info("Executing Pillar 1 Detonation for scanId=%s, url=%s", scan_id, submitted_url)

    # 1. Anti-SSRF Pre-Flight Check
    try:
        _, verified_ip = validate_url_safe(submitted_url)
    except AntiSSRFException as e:
        logger.error("Anti-SSRF blocked task %s: %s", scan_id, e)
        return {
            "scan_id": scan_id,
            "status": "failed",
            "summary": f"Target blocked by Anti-SSRF network policy: {e}",
            "findings": [
                Finding(
                    id=f"fnd_ssrf_{scan_id}",
                    title="Anti-SSRF Network Violation Detected",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.PHISHING,
                    description=str(e),
                    source="Anti-SSRF Network Resolver",
                    evidence=[submitted_url],
                ).to_dict()
            ]
        }

    # 2. Headless Browser Detonation
    detonation = run_headless_detonation(submitted_url, scan_id, timeout_seconds=15)

    # 3. DOM & Credential-Harvesting Heuristics
    dom_metrics = analyze_html_dom(detonation.html_content, submitted_url)

    # 4. Computer Vision & Brand Impersonation
    vision_metrics = evaluate_brand_impersonation(hostname)

    # 5. Synthesize Security Findings
    findings = []
    if dom_metrics["passwordInputsCount"] > 0 and vision_metrics["isImpersonation"]:
        findings.append(Finding(
            id=f"fnd_cred_{scan_id}",
            title="Credential Harvesting Form Impersonating Protected Brand",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.PHISHING,
            description=f"Identified credential inputs on unauthorized host {hostname} impersonating {vision_metrics['targetedBrand']}.",
            source="Pillar 1 DOM Heuristics",
            evidence=[f"Password inputs: {dom_metrics['passwordInputsCount']}", f"Brand similarity: {vision_metrics['visualSimilarityScore']}%"],
            recommendation="Block domain immediately and revoke submitted credentials.",
        ).to_dict())

    if dom_metrics["crossOriginSubmissionTarget"]:
        findings.append(Finding(
            id=f"fnd_cross_{scan_id}",
            title="Cross-Origin Form Submission Exfiltration",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.PHISHING,
            description=f"Form posts sensitive inputs to external origin: {dom_metrics['crossOriginSubmissionTarget']}",
            source="Pillar 1 Form Inspector",
            evidence=[dom_metrics["crossOriginSubmissionTarget"]],
        ).to_dict())

    for yara_rule in dom_metrics["yaraRulesMatched"]:
        findings.append(Finding(
            id=f"fnd_yara_{scan_id}_{yara_rule}",
            title=f"Phishing Kit Signature Matched: {yara_rule}",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.PHISHING,
            description=f"Static code matches YARA threat rule '{yara_rule}'.",
            source="Pillar 1 YARA Engine",
            evidence=[yara_rule],
        ).to_dict())

    redirect_hops = [
        RedirectHop(
            hop=h["hop"],
            url=h["url"],
            type=h.get("type", "Direct"),
            statusCode=h.get("statusCode", 200),
            destinationIp=h.get("destinationIp", verified_ip),
            asn=h.get("asn", "AS13335"),
        )
        for h in detonation.redirect_chain
    ]

    telemetry = PhishingDetonationTelemetry(
        detonationSandbox=detonation.sandbox_type,
        antiBotCloakingDefeated=detonation.anti_bot_cloaking_defeated,
        redirectChain=redirect_hops,
        domHeuristics=DomHeuristics(**{k: v for k, v in dom_metrics.items() if k != "yaraRulesMatched"}),
        yaraRulesMatched=dom_metrics["yaraRulesMatched"],
        computerVision=ComputerVisionTelemetry(**vision_metrics),
        screenshotUrl=f"/artifacts/screenshot-{scan_id}.png",
    )

    return {
        "scan_id": scan_id,
        "status": "completed",
        "duration_ms": detonation.duration_ms,
        "telemetry": telemetry.to_dict(),
        "findings": findings,
    }

def main():
    logger.info("Pillar 1 Phishing Detonation Worker online.")
    # Local verification demonstration
    sample_task = {
        "scan_id": "test_phish_001",
        "submitted_url": "https://example.com",
        "hostname": "example.com",
    }
    output = process_phishing_task(sample_task)
    logger.info("Self-test complete. Duration: %d ms | Findings: %d", output.get("duration_ms", 0), len(output.get("findings", [])))

if __name__ == "__main__":
    main()
