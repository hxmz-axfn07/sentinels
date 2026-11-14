# SENTINEL — Project Report

**Project status:** Day 2 implementation milestone. This report records implemented and verified work only. Institutional details remain placeholders where they have not been provided.

## Abstract

SENTINEL is a defensive network intrusion detection system for offline analysis of authorized network captures. The completed foundation and Day 2 milestone provide a FastAPI backend, a React and TypeScript client, Docker-managed MySQL persistence, and secure PCAP/PCAPNG ingestion. Uploaded captures are checked structurally, stored under generated server-side names, parsed incrementally with Scapy, and represented in the database by analysis lifecycle data and ordered packet metadata. Packet payloads are not persisted. Flow aggregation, detection, machine learning, and evaluation against labeled traffic remain future work; no detection metrics are claimed.

## Chapter 1 — Introduction

Network captures preserve packet-level evidence that can be reviewed offline. This milestone establishes a controlled ingestion path for authorized captures and a data model that can support later analysis. The current implementation stops at packet metadata extraction. It does not identify malicious activity or imply that an observed packet is an attack.

## Chapter 2 — Objectives

The Day 2 objectives were to accept valid PCAP and PCAPNG content, reject empty, unsupported, malformed, truncated, or oversized uploads, preserve capture data in private application storage, extract available packet metadata without payload persistence, expose analysis and packet records through typed API responses, and present those records in the existing web application.

## Chapter 3 — Problem Statement and Need

Capture files are untrusted inputs and may be large, malformed, or mislabeled. A reliable offline analysis application therefore needs content-based validation, bounded upload handling, safe storage names, clear failure states, and database records that accurately describe processing outcomes. This milestone addresses these ingestion concerns while leaving traffic interpretation and detection to later stages.

## Chapter 4 — Software Requirements Specification

The backend uses Python 3.12, FastAPI, SQLAlchemy 2.x, Alembic, Scapy, and MySQL 8.0. The web client uses React, TypeScript, and Vite. MySQL runs through Docker Compose. The maximum upload size defaults to 100 MiB and is configurable. Uploads are submitted as multipart field `file`. Analysis processing is synchronous in the upload request. Offline operation does not require root privileges.

## Chapter 5 — Literature and Technical Background

PCAP stores a file header followed by timestamped packet records. The implementation supports classic PCAP version 2.4 in both byte orders and with microsecond or nanosecond timestamp resolution. PCAPNG stores data in typed blocks and supports multiple sections and interfaces; this milestone accepts version 1.0 sections and validates the supported section, interface, and packet block structures. Scapy's incremental `PcapReader` provides packet decoding without loading the complete capture into application memory.

## Chapter 6 — Proposed Solution and Methodology

The request body is constrained before multipart parsing, and file bytes are streamed to a temporary file in bounded chunks under the configured storage directory. The implementation checks the captured content rather than relying on the submitted extension or MIME type. It validates structural lengths and supported versions, then moves the valid capture to a generated random storage key. A database analysis record is created and packet metadata is parsed in order and persisted in batches of 500. Processing errors mark the record failed, clear any partial packet rows, reset its packet count, and retain a generic error message. The uploaded capture remains associated with its analysis.

Metadata includes packet index, capture timestamp, captured length, IPv4/IPv6/ARP network information where available, transport protocol, source and destination ports when present, TCP flags, and ICMP type and code. Missing fields remain null. Raw payloads are not stored.

## Chapter 7 — Implementation, Testing and Results

### 7.1 API and interface

Implemented routes are `GET /health`, `GET /health/ready`, `GET /api/v1/analyses/limits`, `POST /api/v1/analyses/upload`, `GET /api/v1/analyses`, `GET /api/v1/analyses/{analysis_id}`, and paginated `GET /api/v1/analyses/{analysis_id}/packets`. The React interface supports file selection, upload progress, validation errors, analysis status/details, packet metadata, and packet pagination using API responses.

### 7.2 Database

Alembic revision `0002_capture_metadata` extends the Day 1 `analyses` table with original filename, storage key, file size, capture format, status, packet count, error message, and completion time. It adds `packet_metadata` with an analysis foreign key, ordered packet index, timestamp, network and transport metadata, and a unique index on `(analysis_id, packet_index)`. The migration backfills pre-existing analysis records as legacy entries with no associated capture file. The Day 1 migration was not rewritten. Downgrading revision 0002 drops packet metadata and capture fields and is destructive to Day 2 data.

### 7.3 Verification

Tests use small synthetic Scapy-generated captures; they do not represent real-world traffic or labeled attack data. The backend suite has **35 passing tests**, covering upload validation, PCAP variants, PCAPNG structure, packet metadata, API pagination, persistence, partial-batch failure recovery, and temporary-file cleanup. The frontend suite has **5 passing tests**. Ruff, ESLint, Prettier, and the Vite production build have passed. Docker Compose reports the MySQL 8.0 service healthy, and a read-only `SELECT 1` connectivity query succeeded. MySQL reports Alembic revision `0002_capture_metadata`; the schema contains `analyses` and `packet_metadata`. The API started on port 8001; `/health` returned `{"status":"ok"}` and `/health/ready` returned `{"status":"ready","database":"ok"}`. The Vite development server responded on port 5174. Both services were stopped after verification. No throughput, detection accuracy, or classification results were measured.

## Chapter 8 — Conclusion and Future Scope

The Day 2 milestone implements a bounded, content-validated upload and packet metadata persistence path for supported PCAP and PCAPNG files. Structural support is intentionally limited to the documented format variants. Processing occurs synchronously, so long captures occupy an API worker until processing finishes. Flow aggregation, feature extraction, rule-based detection, Isolation Forest, hybrid scoring, alert investigation, and labeled-data evaluation are future milestones and are not present in this implementation.

## References

1. Scapy Project, “Usage — Reading and writing packets,” <https://scapy.readthedocs.io/>.
2. FastAPI, “Request Files,” <https://fastapi.tiangolo.com/tutorial/request-files/>.
3. PCAPNG format specification, IETF Internet-Draft, <https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/>.

## Appendix A — API pagination

List and packet endpoints accept `offset` (minimum 0) and `limit` (1–200; default 50). Responses include items, total count, offset, and limit.
