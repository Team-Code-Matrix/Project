# Intelligent Phishing, Web Security, PKI Validation & CTI Platform - Backend

This repository houses the microservices backend for the Intelligent Phishing & Trust Platform, engineered to protect against complex web threats, zero-day credential harvesters, and cryptographic trust compromises (such as the October 2026 eMudhra incident).

## Architectural Topology

```
                         +-----------------------------------+
                         |         Frontend (React/Vite)      |
                         +-----------------+-----------------+
                                           | HTTP / WS
                                           v
                         +-----------------------------------+
                         |   API Gateway & Dual-Lane Router  |
                         |           (Go / Fiber)            |
                         +--------+-----------------+--------+
                                  |                 |
     Fast-Path (<150ms)           |                 | Deep-Scan (2-15s)
     +----------------------------+                 |
     |                                              v
+----+-------------------+               +--------------------+
|  Redis Stack           |               |   Apache Kafka     |
|  - Bloom Filters       |               |   (KRaft Mode)     |
|  - Cuckoo Filters      |               +---------+----------+
|  - OneCRL / GSB Cache  |                         |
+------------------------+                         | Topics
                                +------------------+------------------+
                                |                  |                  |
                                v                  v                  v
                       +----------------+ +----------------+ +----------------+
                       | Pillar 1:      | | Pillar 2:      | | Pillar 3:      |
                       | Phishing &     | | PKI & CT       | | Web Security & |
                       | Detonation     | | Validation     | | JA4S           |
                       +-------+--------+ +-------+--------+ +-------+--------+
                               |                  |                  |
                               +------------------+------------------+
                                                  |
                                                  v
                                         +----------------+
                                         | Pillar 4:      |
                                         | CTI Threat     |
                                         | Graph (Neo4j)  |
                                         +----------------+
```

## Microservices Monorepo Layout

- `gateway/`: Go Fiber API Gateway, Dual-Lane URL Router, Fast-Path Bloom evaluator, WebSocket stream hub.
- `workers/pillar1-phishing/`: Playwright DOM Detonation, YARA, MurmurHash3 favicon, pHash brand similarity with `pgvector`.
- `workers/pillar2-pki/`: RFC 5280 Multi-store path validator, Fermat/ROCA key auditor, CT log verifier, OCSP/CRL monitor.
- `workers/pillar3-websec/`: OWASP Security Header auditor, CORS/Cookie inspector, JA4S/JA3S TLS reverse-proxy detector.
- `workers/pillar4-cti/`: STIX 2.1 & TAXII 2.1 bi-directional federation, Neo4j threat graph correlation, time-decay engine.
- `shared/proto/`: Protobuf schemas for Kafka topics and contracts.
- `shared/libs/`: Anti-SSRF dialers, domain canonicalizers, cryptographic primitives.
- `scripts/`: Postgres (pgvector) and Neo4j initialization scripts.

## Ports & Infrastructure Matrix

| Service | Port | Description |
| :--- | :--- | :--- |
| **API Gateway** | `8000` | Main REST & WebSocket API |
| **PostgreSQL 16** | `5432` | Relational, RBAC & `pgvector` store |
| **Redis Stack** | `6379` | Bloom / Cuckoo filter & L1 cache |
| **Kafka (KRaft)** | `9092` / `9094` | Event broker (internal / external) |
| **Kafka UI** | `8080` | Topic and message observability |
| **Neo4j** | `7474` / `7687` | STIX 2.1 Threat Graph (HTTP / Bolt) |
| **MinIO** | `9000` / `9001` | S3-Compatible Encrypted Artifact Vault |

