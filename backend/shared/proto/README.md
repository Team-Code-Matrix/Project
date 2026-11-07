# Shared Protobuf Schemas

This directory holds the Protocol Buffer (`.proto`) schemas for Kafka event topics and inter-service gRPC communication.
In Phase 2, the following schemas will be compiled into Go and Python stubs:
- `scan_task.proto`: Dispatched from the API Gateway to Kafka topics (`trustshield.scan.tasks` & worker topics).
- `scan_telemetry.proto`: Streamed progress and pillar telemetry from workers back to the Gateway / WebSocket.
- `scan_result.proto`: Aggregated final verdict and STIX 2.1 indicator payload.

