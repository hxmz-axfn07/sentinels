# SENTINEL — Project Report

**Project status:** Day 5 implementation milestone. This report records implemented and verified work only. Institutional details remain placeholders where they have not been provided.

## Abstract

SENTINEL is a defensive network intrusion detection system for offline analysis of authorized network captures. The completed Day 1–5 milestones provide a FastAPI backend, a React and TypeScript client, Docker-managed MySQL persistence, secure PCAP/PCAPNG ingestion, packet metadata extraction, synchronous bidirectional flow generation, three configurable rule-based indicators, and an unsupervised Isolation Forest anomaly pipeline. The model uses a versioned numeric flow feature schema and persists application-generated artifacts and per-flow results. Rule findings and ML anomaly indicators remain separate; neither proves malicious activity. No real-world detection metrics are claimed.

## Chapter 1 — Introduction

Network captures preserve packet-level evidence that can be reviewed offline. SENTINEL provides a controlled ingestion path for authorized captures, aggregates persisted packet metadata into bidirectional conversations, and evaluates selected flow patterns using explicit rules. A finding is an explainable indicator; it does not establish intent or confirm an attack.

## Chapter 2 — Objectives

Day 2 established content-validated PCAP/PCAPNG upload, bounded storage, and packet metadata extraction without payload persistence. Day 3 added bidirectional flow identification and feature persistence. Day 4 added configurable port-scan, SYN-flood-like, and connection-attempt indicators, persisted findings, query APIs, and a findings interface. Day 5 added reproducible unsupervised flow anomaly detection, model metadata and artifact persistence, per-flow inference results, API access, and a model/inference interface.

## Chapter 3 — Problem Statement and Need

Capture files are untrusted inputs and may be large, malformed, or mislabeled. A reliable offline analysis application therefore needs content-based validation, bounded upload handling, safe storage names, clear failure states, and database records that accurately describe processing outcomes. Packet records alone do not summarize a conversation; bidirectional aggregation supplies a useful unit for rule evaluation. Threshold rules can identify patterns consistently, but benign activity can satisfy the same conditions, so findings require contextual interpretation.

## Chapter 4 — Software Requirements Specification

The backend uses Python 3.12, FastAPI, SQLAlchemy 2.x, Alembic, Scapy, NumPy, scikit-learn, and MySQL 8.0. The web client uses React, TypeScript, and Vite. MySQL runs through Docker Compose. The maximum upload size defaults to 100 MiB and is configurable. Upload, flow generation, rule evaluation, model training, and inference run synchronously in API requests. Detection thresholds and per-rule enablement are environment configurable and validated. Offline operation requires no root privileges.

## Chapter 5 — Literature and Technical Background

PCAP stores a file header followed by timestamped packet records. SENTINEL accepts classic PCAP version 2.4 in both byte orders and with microsecond or nanosecond timestamp resolution. PCAPNG is block based; this implementation accepts version 1.0 sections and validates the supported section, interface, and packet block structures. Scapy's incremental `PcapReader` decodes packets without loading the full capture into application memory.

A flow represents packets exchanged between two endpoints under one protocol. For TCP and UDP, SENTINEL uses a five-tuple: IP version, protocol, and two address/port pairs. Other protocols use endpoint addresses without ports. The two endpoints are canonically ordered, allowing both traffic directions to share a flow key.

Rule-based detection compares observed flow properties with documented conditions. Threshold rules are interpretable and reproducible, though they can produce false positives and miss activity below configured values. Their findings should remain distinct from future machine-learning anomalies and should not be interpreted as confirmed attacks.

Isolation Forest is an unsupervised outlier-detection algorithm. It builds random partition trees; observations isolated in fewer splits tend to be more unusual relative to the supplied training sample. The application stores negative scikit-learn `decision_function` as its anomaly score so larger values indicate more unusual model-relative observations. This score is neither a probability nor a confidence percentage. The prediction label is taken from scikit-learn's `predict` method.

## Chapter 6 — Proposed Solution and Methodology

The request body is constrained before multipart parsing. Capture bytes are streamed in bounded chunks to private application storage, validated by content and structure, and assigned a generated server-side key. Scapy extracts ordered packet metadata. Failures clear partial packet rows and record a generic failed-analysis state; packet payloads are not persisted.

Flow generation reads only persisted packet metadata, in bounded database batches. The stable flow identifier is SHA-256 over canonical JSON containing analysis scope, IP version, protocol identity, and ordered endpoints. The analysis ID ensures identical endpoint tuples in separate analyses remain distinct. Endpoint A to B is the deterministic forward direction; B to A is backward. This direction does not imply client/server roles. Original source/destination details from the earliest capture-index packet are retained separately.

TCP/UDP packets with missing addresses or ports and packets with inconsistent protocol metadata are isolated by packet index to avoid merging unrelated conversations. Invalid address and port values are not exposed as valid flow endpoints; invalid ports become null. Unknown transport labels include the IP protocol number in the key. ICMP flows use endpoint pair and protocol; this implementation does not split them by ICMP message type, code, or echo identifier.

The engine calculates total and directional packet and byte counts; first and last timestamps; duration; minimum, maximum, mean, and population standard deviation of packet length; inter-arrival minimum, maximum, mean, and population standard deviation; available TCP SYN, ACK, FIN, RST, PSH, and URG bit counts; and packet/byte rates. Inter-arrival statistics use timestamp order with packet index as a tie breaker. Rates are `total_packets / duration` and `total_bytes / duration`; rates are null for zero or unavailable duration. Missing timestamps and unavailable TCP flag metadata remain null. An empty input creates no flow records; a single packet has zero packet-length deviation and null inter-arrival features. The implementation avoids division by zero and persists finite `Decimal` values.

Generation is synchronous. A database row lock claims generation for a completed analysis. Packet flow assignments and flow records are written in one transaction, so processing failure rolls them back before a generic failed status is recorded. A repeated request returns the existing completed result, supported by a unique `(analysis_id, flow_id)` constraint.

Day 4 adds directional TCP handshake counts to each flow. SYN-only packets have the SYN bit set without ACK; SYN+ACK packets have both bits set. Revision `0004_rule_based_detection` backfills these directional counts from persisted packet flags and flow directions, preserving the capture metadata already stored. Four-level threshold settings are validated in increasing order. Defaults are 5/10/25/50 distinct ports, 20/100/500/1,000 SYN-only packets, and 10/25/50/100 distinct TCP flow tuples with SYN-only traffic for Low/Medium/High/Critical severity bands.

For port probing, eligible flows are grouped by the observed directed source/target IP pair; destination ports are deduplicated across TCP and UDP. The SYN indicator sums directional SYN-only packet counts by TCP source and target over the entire capture. It reports SYN+ACK responses separately. Per-packet timestamps are not associated with directional flags, so the implementation does not claim a time-window rate. Connection attempts count distinct TCP flow tuples containing at least one SYN-only packet. This does not prove that connections were established, and repeated sessions that reuse the same five-tuple are merged by Day 3 flow generation.

Each detection run stores its validated configuration snapshot and hash. Repeating a completed run with the same configuration reuses it; changing configuration creates a new run while preserving previous results. Findings and up to 100 associated supporting flow samples per finding are committed transactionally. Exact support counts and a truncation indicator are retained. Failed runs leave no partial findings and record a generic error. Detection reads flow rows in batches and executes synchronously.

Day 5 uses the ordered `flow-v1` feature schema: duration, packet and byte totals by direction, packet length statistics, inter-arrival statistics, TCP flag counts, and packet/byte rates. It excludes raw identifiers, endpoint addresses and ports, timestamps, and labels. Null flow metrics are filled from the training-set median and paired with missingness indicators. All nonnegative values receive `log1p` compression; constant transformed dimensions are removed. The fitted transformation and Isolation Forest are persisted together so training and inference use the same learned medians, retained dimensions, and feature order. Inputs containing negative or infinite values are rejected; insufficient training data and fully constant transformed data are also rejected.

Training requires operators to select completed analyses with generated flows. It does not assume that the unsupervised training data is benign and does not treat Day 4 rule findings as labels. At least 20 flows are required. Training uses at most 50,000 rows by default; larger populations are processed in stable analysis and flow ID order with seeded reservoir sampling. Defaults are 200 estimators, `contamination="auto"`, `max_samples="auto"`, and random seed 42. Numeric contamination must be greater than zero and at most 0.5. It affects the prediction threshold and does not estimate an independently measured attack rate. Every training operation creates a new model version instead of replacing an earlier artifact.

Model metadata stores the `flow-v1` schema and exact ordered feature names, active transformed dimensions, preprocessing configuration, Isolation Forest parameters, random seed, source analysis IDs, sample and population counts, scikit-learn version, version ID, and generated artifact key. Joblib artifacts are written atomically under private managed storage using generated names; the API accepts no uploaded model artifacts. Inference checks model/schema/software compatibility, scores flows in batches of 500, and stores a result for each flow in one database transaction. Results store the selected model and version, analysis, canonical flow key, normal/anomaly label, finite `-decision_function` score, and creation timestamp. A unique analysis/model/flow constraint and an analysis row lock make repeated inference reuse completed results.

## Chapter 7 — Implementation, Testing and Results

### 7.1 API and interface

Day 3 adds `POST /api/v1/analyses/{analysis_id}/flows/generate`, paginated and filterable `GET /api/v1/analyses/{analysis_id}/flows`, and `GET /api/v1/analyses/{analysis_id}/flows/{flow_id}`. Day 4 adds `POST /api/v1/analyses/{analysis_id}/detections/run`, `GET /api/v1/analyses/{analysis_id}/detection-summary`, paginated/filterable `GET /api/v1/analyses/{analysis_id}/findings`, and `GET /api/v1/analyses/{analysis_id}/findings/{finding_id}`. The run endpoint requires a completed analysis with generated flows. The React interface adds rule execution, status, severity summaries, evidence, filtering, pagination, loading, and error states. The existing upload, packet metadata, and flow functions remain available.

Day 5 adds `POST /api/v1/ml/models/train`, paginated `GET /api/v1/ml/models`, and `GET /api/v1/ml/models/{model_id}`. `POST /api/v1/analyses/{analysis_id}/ml/inference` accepts a model ID. `GET /api/v1/analyses/{analysis_id}/ml/summary`, filtered and paginated `GET /api/v1/analyses/{analysis_id}/ml/results`, and `GET /api/v1/analyses/{analysis_id}/ml/results/{result_id}` expose predictions. The frontend includes explicit training source selection and estimator settings, model selection, inference controls, prediction filtering, score display, and pagination. It labels anomalies as indicators, not confirmed attacks. These endpoints are synchronous.

### 7.2 Database

Alembic revision `0003_bidirectional_flows` adds analysis generation state, nullable flow ID and canonical direction columns plus ordering indexes to packet metadata, and an indexed `network_flows` table. Revision `0004_rule_based_detection` adds directional SYN-only/SYN+ACK counts, config-specific detection runs, structured findings, and a supporting-flow link table. Runs and findings reference their parent analysis; findings are unique within a run and configuration. Revisions `0001`–`0003` were not rewritten. Downgrading revision `0004` removes all Day 4 findings and run snapshots and drops directional flow counts; it is data-destructive and was not run.

Revision `0005_isolation_forest` adds `anomaly_models` and `ml_inference_results`. Results have composite foreign keys to the exact model version and to the canonical flow within its analysis, plus uniqueness on analysis/model/flow. The migration is additive and does not rewrite revisions `0001`–`0004`. Its downgrade deletes model metadata and result rows; private serialized artifacts are not automatically deleted by the database migration. Downgrade was not run against the development database.

### 7.3 Verification

All rule and ML fixtures are deterministic synthetic flows; they are not real-world traffic or labeled attack data. The complete backend suite completed with **104 passed** and five deprecation warnings (Starlette's TestClient/HTTPX integration and Alembic's missing `path_separator` setting). Ruff lint passed and all 59 backend Python files were formatted. The frontend suite completed with **16 passed**; ESLint, Prettier, and the Vite production build passed.

The existing Day 1–4 tests remain in the complete suite. Day 5 tests cover feature ordering and transformation, missing/invalid/constant values, deterministic sampling and model fitting, a synthetic normal/outlier pair with finite relative scores, artifact path restrictions, API persistence/idempotency, analysis isolation, failed-inference rollback, and the additive migration. A disposable SQLite migration upgraded from `0004` to `0005` while preserving its existing analysis and flow rows. The configured MySQL database migrated from `0004_rule_based_detection` to `0005_isolation_forest`; Alembic reported no schema drift and Docker Compose configuration validated. MySQL remained healthy. A MySQL API smoke test used 24 synthetic training flows and three synthetic inference flows, verified repeat inference reuse, then deleted only its generated model, analyses, results, and temporary artifact. The backend started on port 8001 and returned HTTP 200 from `/health`; Vite started on port 5174 and returned its application entry page. Both verification servers were stopped after the requests. No real-world traffic, throughput, detection accuracy, or false-positive measurements were evaluated.

## Chapter 8 — Conclusion and Future Scope

The Day 5 milestone adds model-relative anomaly indicators over persisted flow features. It is an offline IDS component and takes no preventive action. Training and inference execute synchronously and can occupy API workers. The training set is unsupervised and may contain anomalous or malicious behavior; contamination and the prediction threshold are not empirically calibrated for a production network. Capture limitations and five-tuple reuse affect the underlying flow measurements. The scikit-learn version and schema compatibility checks require retraining after incompatible changes. Rule/ML correlation, hybrid scoring, alert correlation, incident investigation, live capture, and labeled-data evaluation remain future work.

## References

1. Scapy Project, “Usage — Reading and writing packets,” <https://scapy.readthedocs.io/>.
2. FastAPI, “Request Files,” <https://fastapi.tiangolo.com/tutorial/request-files/>.
3. PCAPNG format specification, IETF Internet-Draft, <https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/>.

## Appendix A — Pagination

Analysis, packet, and flow list endpoints accept `offset` (minimum 0) and `limit` (1–200; default 50). Responses include items, total count, offset, and limit.

## Appendix B — Machine-Learning API

Training is requested with `POST /api/v1/ml/models/train` and one or more completed analysis IDs. Models are listed at `GET /api/v1/ml/models` and inspected at `GET /api/v1/ml/models/{model_id}`. Inference is started with `POST /api/v1/analyses/{analysis_id}/ml/inference` and a model ID in the JSON body. The result collection is paginated at `GET /api/v1/analyses/{analysis_id}/ml/results`; it accepts a model ID and an optional prediction label. The corresponding summary and individual result endpoints are documented in the README.
