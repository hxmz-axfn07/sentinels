# SENTINEL — Project Report

**Project status:** Day 3 implementation milestone. This report records implemented and verified work only. Institutional details remain placeholders where they have not been provided.

## Abstract

SENTINEL is a defensive network intrusion detection system for offline analysis of authorized network captures. The completed Day 1–3 milestones provide a FastAPI backend, a React and TypeScript client, Docker-managed MySQL persistence, secure PCAP/PCAPNG ingestion, packet metadata extraction, and synchronous bidirectional flow generation. Canonical endpoint ordering combines reverse-direction packets into one flow while preserving directional counts. Flow statistics include volume, timing, packet-length distributions, available TCP flags, and rates. Packet payloads are not persisted. Detection, machine learning, and evaluation against labeled traffic remain future work; no detection metrics are claimed.

## Chapter 1 — Introduction

Network captures preserve packet-level evidence that can be reviewed offline. SENTINEL provides a controlled ingestion path for authorized captures and aggregates persisted packet metadata into bidirectional conversations. The current implementation computes summaries; it does not identify malicious activity or imply that an observed packet or flow is an attack.

## Chapter 2 — Objectives

Day 2 established content-validated PCAP/PCAPNG upload, bounded storage, and packet metadata extraction without payload persistence. Day 3 adds bidirectional flow identification, documented flow features, persistence, and API and interface support for flow generation and review.

## Chapter 3 — Problem Statement and Need

Capture files are untrusted inputs and may be large, malformed, or mislabeled. A reliable offline analysis application therefore needs content-based validation, bounded upload handling, safe storage names, clear failure states, and database records that accurately describe processing outcomes. Packet records alone also do not summarize a conversation; bidirectional aggregation supplies a consistent unit for subsequent analysis. Detection remains outside these milestones.

## Chapter 4 — Software Requirements Specification

The backend uses Python 3.12, FastAPI, SQLAlchemy 2.x, Alembic, Scapy, and MySQL 8.0. The web client uses React, TypeScript, and Vite. MySQL runs through Docker Compose. The maximum upload size defaults to 100 MiB and is configurable. Upload and flow generation run synchronously in API requests. Offline operation requires no root privileges.

## Chapter 5 — Literature and Technical Background

PCAP stores a file header followed by timestamped packet records. SENTINEL accepts classic PCAP version 2.4 in both byte orders and with microsecond or nanosecond timestamp resolution. PCAPNG is block based; this implementation accepts version 1.0 sections and validates the supported section, interface, and packet block structures. Scapy's incremental `PcapReader` decodes packets without loading the full capture into application memory.

A flow represents packets exchanged between two endpoints under one protocol. For TCP and UDP, SENTINEL uses a five-tuple: IP version, protocol, and two address/port pairs. Other protocols use endpoint addresses without ports. The two endpoints are canonically ordered, allowing both traffic directions to share a flow key.

## Chapter 6 — Proposed Solution and Methodology

The request body is constrained before multipart parsing. Capture bytes are streamed in bounded chunks to private application storage, validated by content and structure, and assigned a generated server-side key. Scapy extracts ordered packet metadata. Failures clear partial packet rows and record a generic failed-analysis state; packet payloads are not persisted.

Flow generation reads only persisted packet metadata, in bounded database batches. The stable flow identifier is SHA-256 over canonical JSON containing analysis scope, IP version, protocol identity, and ordered endpoints. The analysis ID ensures identical endpoint tuples in separate analyses remain distinct. Endpoint A to B is the deterministic forward direction; B to A is backward. This direction does not imply client/server roles. Original source/destination details from the earliest capture-index packet are retained separately.

TCP/UDP packets with missing addresses or ports and packets with inconsistent protocol metadata are isolated by packet index to avoid merging unrelated conversations. Invalid address and port values are not exposed as valid flow endpoints; invalid ports become null. Unknown transport labels include the IP protocol number in the key. ICMP flows use endpoint pair and protocol; this implementation does not split them by ICMP message type, code, or echo identifier.

The engine calculates total and directional packet and byte counts; first and last timestamps; duration; minimum, maximum, mean, and population standard deviation of packet length; inter-arrival minimum, maximum, mean, and population standard deviation; available TCP SYN, ACK, FIN, RST, PSH, and URG bit counts; and packet/byte rates. Inter-arrival statistics use timestamp order with packet index as a tie breaker. Rates are `total_packets / duration` and `total_bytes / duration`; rates are null for zero or unavailable duration. Missing timestamps and unavailable TCP flag metadata remain null. An empty input creates no flow records; a single packet has zero packet-length deviation and null inter-arrival features. The implementation avoids division by zero and persists finite `Decimal` values.

Generation is synchronous. A database row lock claims generation for a completed analysis. Packet flow assignments and flow records are written in one transaction, so processing failure rolls them back before a generic failed status is recorded. A repeated request returns the existing completed result, supported by a unique `(analysis_id, flow_id)` constraint.

## Chapter 7 — Implementation, Testing and Results

### 7.1 API and interface

Day 3 adds `POST /api/v1/analyses/{analysis_id}/flows/generate`, paginated and filterable `GET /api/v1/analyses/{analysis_id}/flows`, and `GET /api/v1/analyses/{analysis_id}/flows/{flow_id}`. Flow generation requires a completed packet analysis. The React interface adds flow generation status and action, directional packet/byte summaries, protocol/endpoints, duration, loading/error/empty states, and flow pagination. The existing upload and packet metadata interface remains available.

### 7.2 Database

Alembic revision `0003_bidirectional_flows` adds analysis generation state, nullable flow ID and canonical direction columns plus ordering indexes to packet metadata, and an indexed `network_flows` table. The table references its analysis with `ON DELETE CASCADE`, stores endpoint and aggregate feature fields without payload data, and uniquely constrains `(analysis_id, flow_id)`. Revisions `0001` and `0002` are unchanged. Downgrading revision `0003` deletes generated flows and packet assignments and removes analysis generation state; the operation is data-destructive and was not run on the development database.

### 7.3 Verification

Tests use deterministic synthetic packets and captures. They are not real-world traffic or labeled attack data. The final backend suite has **61 passing tests** and the frontend suite has **8 passing tests**. Backend Ruff lint and format checks, frontend ESLint and Prettier checks, and the Vite production build passed. API integration tests exercised persistence, reverse-direction totals, pagination and filters, repeated generation, rollback after a flow row was flushed, packet-assignment rollback, and generation across forced database page boundaries using SQLite. A disposable SQLite database seeded at revision `0002` upgraded to `0003`; its existing analysis and packet row remained, with the new default flow state. The existing MySQL database upgraded additively to `0003_bidirectional_flows`; it retained zero analysis, packet, and flow rows. Alembic reported no schema drift. Compose configuration validated and its MySQL container remained healthy. The API started on port 8001: liveness and MySQL readiness succeeded, and a flow request for a missing analysis returned 404. The server was stopped after verification. No real-world traffic, throughput, detection accuracy, or classification results were measured.

## Chapter 8 — Conclusion and Future Scope

The Day 3 milestone provides a bounded, reproducible bidirectional flow summary over persisted packet metadata. Synchronous generation makes the result straightforward to retry and verify, but long analyses occupy an API worker. Incomplete TCP/UDP tuples are conservatively isolated, and ICMP identity does not include message-specific identifiers. Rule-based detection, Isolation Forest, hybrid scoring, alert investigation, live capture, and labeled-data evaluation remain future work.

## References

1. Scapy Project, “Usage — Reading and writing packets,” <https://scapy.readthedocs.io/>.
2. FastAPI, “Request Files,” <https://fastapi.tiangolo.com/tutorial/request-files/>.
3. PCAPNG format specification, IETF Internet-Draft, <https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/>.

## Appendix A — Pagination

Analysis, packet, and flow list endpoints accept `offset` (minimum 0) and `limit` (1–200; default 50). Responses include items, total count, offset, and limit.
