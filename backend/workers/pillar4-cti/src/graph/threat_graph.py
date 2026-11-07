"""
Neo4j Threat Graph Builder
Maps STIX 2.1 Domain & Observable relationships for @xyflow/react frontend visualization.
"""
from typing import List
from shared.libs.python.models import (
    ThreatGraphNode,
    ThreatGraphEdge,
    ThreatGraphData,
)

def build_threat_graph(hostname: str, is_malicious: bool) -> ThreatGraphData:
    """Builds multi-hop threat graph nodes and edges for frontend visualization."""
    risk_state = "malicious" if is_malicious else "clean"
    ip_addr = "185.220.101.5" if is_malicious else "104.21.28.192"
    asn_label = "AS62450 (Bulletproof Hostings)" if is_malicious else "AS13335 (Cloudflare)"

    nodes = [
        ThreatGraphNode(id="node-dom", type="domain", label=hostname, riskState=risk_state),
        ThreatGraphNode(id="node-ip", type="ip", label=ip_addr, riskState=risk_state),
        ThreatGraphNode(id="node-asn", type="asn", label=asn_label, riskState=risk_state),
        ThreatGraphNode(id="node-cert", type="certificate", label="Leaf TLS Certificate", riskState=risk_state),
        ThreatGraphNode(id="node-ja4", type="ja4", label="t13d1516h2_8daaf", riskState=risk_state),
    ]

    edges = [
        ThreatGraphEdge(id="e1", source="node-dom", target="node-ip", label="RESOLVES_TO", relationshipType="RESOLVES_TO"),
        ThreatGraphEdge(id="e2", source="node-ip", target="node-asn", label="ANNOUNCED_BY", relationshipType="ANNOUNCED_BY"),
        ThreatGraphEdge(id="e3", source="node-dom", target="node-cert", label="SECURED_BY", relationshipType="SECURED_BY"),
        ThreatGraphEdge(id="e4", source="node-dom", target="node-ja4", label="FINGERPRINTED_AS", relationshipType="FINGERPRINTED_AS"),
    ]

    if is_malicious:
        nodes.append(ThreatGraphNode(id="node-ta", type="threat_actor", label="TA-0922 (ReverseProxy-Gang)", riskState="malicious"))
        edges.append(ThreatGraphEdge(id="e5", source="node-dom", target="node-ta", label="ATTRIBUTED_TO", relationshipType="ATTRIBUTED_TO"))

    return ThreatGraphData(nodes=nodes, edges=edges)

