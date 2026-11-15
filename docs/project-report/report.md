# SENTINEL — Project Report

**Project status:** Day 4 implementation milestone. This report records implemented and verified work only. Institutional details remain placeholders where they have not been provided.

## Abstract

SENTINEL is a defensive network intrusion detection system for offline analysis of authorized network captures. The completed Day 1–4 milestones provide a FastAPI backend, a React and TypeScript client, Docker-managed MySQL persistence, secure PCAP/PCAPNG ingestion, packet metadata extraction, synchronous bidirectional flow generation, and three configurable rule-based indicators. The rules identify multi-port probing, capture-wide SYN-only packet volume, and distinct TCP flow tuples with observed SYN-only traffic. Findings include deterministic severity, structured evidence, and supporting flow links. They indicate suspicious patterns and do not prove malicious activity. No real-world detection metrics are claimed.

## Chapter 1 — Introduction

Network captures preserve packet-level evidence that can be reviewed offline. SENTINEL provides a controlled ingestion path for authorized captures, aggregates persisted packet metadata into bidirectional conversations, and evaluates selected flow patterns using explicit rules. A finding is an explainable indicator; it does not establish intent or confirm an attack.

## Chapter 2 — Objectives

Day 2 established content-validated PCAP/PCAPNG upload, bounded storage, and packet metadata extraction without payload persistence. Day 3 added bidirectional flow identification and feature persistence. Day 4 added configurable port-scan, SYN-flood-like, and connection-attempt indicators, persisted findings, query APIs, and a findings interface.

## Chapter 3 — Problem Statement and Need

Capture files are untrusted inputs and may be large, malformed, or mislabeled. A reliable offline analysis application therefore needs content-based validation, bounded upload handling, safe storage names, clear failure states, and database records that accurately describe processing outcomes. Packet records alone do not summarize a conversation; bidirectional aggregation supplies a useful unit for rule evaluation. Threshold rules can identify patterns consistently, but benign activity can satisfy the same conditions, so findings require contextual interpretation.

## Chapter 4 — Software Requirements Specification

The backend uses Python 3.12, FastAPI, SQLAlchemy 2.x, Alembic, Scapy, and MySQL 8.0. The web client uses React, TypeScript, and Vite. MySQL runs through Docker Compose. The maximum upload size defaults to 100 MiB and is configurable. Upload, flow generation, and rule evaluation run synchronously in API requests. Detection thresholds and per-rule enablement are environment configurable and validated. Offline operation requires no root privileges.

## Chapter 5 — Literature and Technical Background

PCAP stores a file header followed by timestamped packet records. SENTINEL accepts classic PCAP version 2.4 in both byte orders and with microsecond or nanosecond timestamp resolution. PCAPNG is block based; this implementation accepts version 1.0 sections and validates the supported section, interface, and packet block structures. Scapy's incremental `PcapReader` decodes packets without loading the full capture into application memory.

A flow represents packets exchanged between two endpoints under one protocol. For TCP and UDP, SENTINEL uses a five-tuple: IP version, protocol, and two address/port pairs. Other protocols use endpoint addresses without ports. The two endpoints are canonically ordered, allowing both traffic directions to share a flow key.

Rule-based detection compares observed flow properties with documented conditions. Threshold rules are interpretable and reproducible, though they can produce false positives and miss activity below configured values. Their findings should remain distinct from future machine-learning anomalies and should not be interpreted as confirmed attacks.

## Chapter 6 — Proposed Solution and Methodology

The request body is constrained before multipart parsing. Capture bytes are streamed in bounded chunks to private application storage, validated by content and structure, and assigned a generated server-side key. Scapy extracts ordered packet metadata. Failures clear partial packet rows and record a generic failed-analysis state; packet payloads are not persisted.

Flow generation reads only persisted packet metadata, in bounded database batches. The stable flow identifier is SHA-256 over canonical JSON containing analysis scope, IP version, protocol identity, and ordered endpoints. The analysis ID ensures identical endpoint tuples in separate analyses remain distinct. Endpoint A to B is the deterministic forward direction; B to A is backward. This direction does not imply client/server roles. Original source/destination details from the earliest capture-index packet are retained separately.

TCP/UDP packets with missing addresses or ports and packets with inconsistent protocol metadata are isolated by packet index to avoid merging unrelated conversations. Invalid address and port values are not exposed as valid flow endpoints; invalid ports become null. Unknown transport labels include the IP protocol number in the key. ICMP flows use endpoint pair and protocol; this implementation does not split them by ICMP message type, code, or echo identifier.

The engine calculates total and directional packet and byte counts; first and last timestamps; duration; minimum, maximum, mean, and population standard deviation of packet length; inter-arrival minimum, maximum, mean, and population standard deviation; available TCP SYN, ACK, FIN, RST, PSH, and URG bit counts; and packet/byte rates. Inter-arrival statistics use timestamp order with packet index as a tie breaker. Rates are `total_packets / duration` and `total_bytes / duration`; rates are null for zero or unavailable duration. Missing timestamps and unavailable TCP flag metadata remain null. An empty input creates no flow records; a single packet has zero packet-length deviation and null inter-arrival features. The implementation avoids division by zero and persists finite `Decimal` values.

Generation is synchronous. A database row lock claims generation for a completed analysis. Packet flow assignments and flow records are written in one transaction, so processing failure rolls them back before a generic failed status is recorded. A repeated request returns the existing completed result, supported by a unique `(analysis_id, flow_id)` constraint.

Day 4 adds directional TCP handshake counts to each flow. SYN-only packets have the SYN bit set without ACK; SYN+ACK packets have both bits set. Revision `0004_rule_based_detection` backfills these directional counts from persisted packet flags and flow directions, preserving the capture metadata already stored. Four-level threshold settings are validated in increasing order. Defaults are 5/10/25/50 distinct ports, 20/100/500/1,000 SYN-only packets, and 10/25/50/100 distinct TCP flow tuples with SYN-only traffic for Low/Medium/High/Critical severity bands.

For port probing, eligible flows are grouped by the observed directed source/target IP pair; destination ports are deduplicated across TCP and UDP. The SYN indicator sums directional SYN-only packet counts by TCP source and target over the entire capture. It reports SYN+ACK responses separately. Per-packet timestamps are not associated with directional flags, so the implementation does not claim a time-window rate. Connection attempts count distinct TCP flow tuples containing at least one SYN-only packet. This does not prove that connections were established, and repeated sessions that reuse the same five-tuple are merged by Day 3 flow generation.

Each detection run stores its validated configuration snapshot and hash. Repeating a completed run with the same configuration reuses it; changing configuration creates a new run while preserving previous results. Findings and up to 100 associated supporting flow samples per finding are committed transactionally. Exact support counts and a truncation indicator are retained. Failed runs leave no partial findings and record a generic error. Detection reads flow rows in batches and executes synchronously.

## Chapter 7 — Implementation, Testing and Results

### 7.1 API and interface

Day 3 adds `POST /api/v1/analyses/{analysis_id}/flows/generate`, paginated and filterable `GET /api/v1/analyses/{analysis_id}/flows`, and `GET /api/v1/analyses/{analysis_id}/flows/{flow_id}`. Day 4 adds `POST /api/v1/analyses/{analysis_id}/detections/run`, `GET /api/v1/analyses/{analysis_id}/detection-summary`, paginated/filterable `GET /api/v1/analyses/{analysis_id}/findings`, and `GET /api/v1/analyses/{analysis_id}/findings/{finding_id}`. The run endpoint requires a completed analysis with generated flows. The React interface adds rule execution, status, severity summaries, evidence, filtering, pagination, loading, and error states. The existing upload, packet metadata, and flow functions remain available.

### 7.2 Database

Alembic revision `0003_bidirectional_flows` adds analysis generation state, nullable flow ID and canonical direction columns plus ordering indexes to packet metadata, and an indexed `network_flows` table. Revision `0004_rule_based_detection` adds directional SYN-only/SYN+ACK counts, config-specific detection runs, structured findings, and a supporting-flow link table. Runs and findings reference their parent analysis; findings are unique within a run and configuration. Revisions `0001`–`0003` were not rewritten. Downgrading revision `0004` removes all Day 4 findings and run snapshots and drops directional flow counts; it is data-destructive and was not run.

### 7.3 Verification

All rule fixtures are deterministic synthetic flows; they are not real-world traffic or labeled attack data. The complete backend suite completed with **85 passed** and three deprecation warnings (Starlette's `TestClient`/HTTPX integration and Alembic's missing `path_separator` setting). Ruff lint passed and all 47 backend files were formatted. The frontend suite completed with **12 passed**; ESLint, Prettier, and the Vite production build passed.

The SQLite migration test upgraded a disposable database from revision `0003` through `0004`, preserved its analysis, packet, and flow rows, and backfilled one forward SYN-only count and one backward SYN+ACK count. The configured MySQL database upgraded to `0004_rule_based_detection`; Alembic reported no schema drift and Docker Compose configuration validated. MySQL remained healthy. A MySQL-backed API integration used six synthetic flow rows, persisted two findings and their supporting-flow links, verified that a same-configuration repeat reused the completed run, and deleted the temporary analysis. Final read-only row counts for analyses, flows, runs, and findings were all zero. No real-world traffic, throughput, detection accuracy, or false-positive measurements were evaluated.

## Chapter 8 — Conclusion and Future Scope

The Day 4 milestone adds explainable, configurable indicators over persisted flows. It is an offline IDS component and takes no preventive action. Synchronous execution occupies an API worker while each analysis is evaluated. The capture-wide SYN rule cannot express a time-window threshold because directional flag timestamps are unavailable. Flow tuple reuse can undercount repeated TCP sessions, and all configured thresholds need environment-specific validation. Isolation Forest, hybrid analysis, alert correlation, incident investigation, live capture, and labeled-data evaluation remain future work.

## References

1. Scapy Project, “Usage — Reading and writing packets,” <https://scapy.readthedocs.io/>.
2. FastAPI, “Request Files,” <https://fastapi.tiangolo.com/tutorial/request-files/>.
3. PCAPNG format specification, IETF Internet-Draft, <https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/>.

## Appendix A — Pagination

Analysis, packet, and flow list endpoints accept `offset` (minimum 0) and `limit` (1–200; default 50). Responses include items, total count, offset, and limit.
