# Rule-Based Detection

## Purpose

Rule-based detection checks observed traffic against explicit, reviewable conditions. A rule produces an indicator with the condition, threshold, endpoints, and supporting flows. It does not establish intent or prove that an attack occurred. These rules operate on SENTINEL's persisted bidirectional flow summaries and do not inspect payloads.

Rule-based methods are complementary to statistical anomaly detection. A rule can explain a specific pattern such as many distinct destination ports. A later anomaly model can identify unusual feature combinations that do not match a known rule. Neither signal alone should be treated as a confirmed incident.

## Flow direction and supporting evidence

TCP directional SYN-only and SYN+ACK counts are computed from each packet's TCP flags and the canonical direction stored during Day 3 flow generation. Revision `0004_rule_based_detection` adds these nullable flow columns and backfills them from persisted packet metadata. No capture file is reparsed.

For TCP, a packet is SYN-only when `(flags AND 0x02) != 0` and `(flags AND 0x10) = 0`. A SYN+ACK packet has both bits set. The migration and flow writer compute these values separately in the canonical forward and backward directions. If the original flag metadata is unavailable, the corresponding directional counts remain null and the rules do not invent them.

Each finding links to at most 100 deterministic supporting flow records. Its `supporting_flow_count` remains the exact count; `supporting_flow_sample_truncated` tells the client when only a sample is linked. Structured evidence stores counts and bounded port samples, not packet payloads.

## Rule 1: multi-port probing

For each directed source and target IP pair, let `P(s,d)` be the set of distinct destination port numbers in TCP and UDP flow records directed from `s` to `d`:

`port_count(s,d) = |P(s,d)|`

The rule triggers when the count reaches its configured Low threshold. A flow is counted once even though its packets are bidirectional. TCP direction prefers the direction with more observed SYN-only packets; ties and missing flag data use the earliest captured packet direction. UDP uses the earliest captured packet direction. Flows with missing destination ports or endpoint addresses are ignored. TCP and UDP probes to the same numeric port count as one distinct port, while both protocols appear in the evidence.

The evidence includes the target, distinct-port count, total eligible flow count, observed protocols, thresholds, and a sample of destination ports. A host administering several services can legitimately contact many ports; the result is an indicator, not a verdict.

## Rule 2: high SYN-only packet volume

For each directed TCP source-target pair, the rule sums the observed SYN-only packets over the whole analysis:

`syn_only(s,d) = Σ forward_or_backward_syn_only_count(flow)`

Only directional SYN-only counts contribute. SYN+ACK responses are reported separately and cannot by themselves trigger the rule. Severity is based on the observed SYN-only packet count.

The capture-wide count is not a rate. Packet timestamps are stored at flow level, not alongside every directional TCP flag, so SENTINEL cannot reliably apply a time window or calculate a SYN-only packets-per-second rate. Retransmitted SYN-only packets are included. Findings explicitly include this limitation and do not claim a confirmed denial-of-service attack.

## Rule 3: repeated TCP connection tuples with SYN

For each directed source-target pair, the rule counts distinct persisted TCP flow tuples that contain at least one SYN-only packet:

`attempts(s,d) = |{flow tuple: TCP and SYN-only count > 0}|`

Packets and retransmissions within one flow do not increase this count. UDP is excluded because it has no TCP connection handshake. The result is a proxy for observed TCP connection attempts; SENTINEL does not claim that a connection was established. Day 3 flow aggregation merges a reused five-tuple across the analysis, so multiple separate sessions using the same tuple may be undercounted.

## Thresholds and severity

Thresholds are environment configurable under `DETECTION_CONFIG__...` settings. All four values must be positive and strictly increasing. The starting defaults are:

| Rule measurement | Low | Medium | High | Critical |
| --- | ---: | ---: | ---: | ---: |
| Distinct destination ports | 5 | 10 | 25 | 50 |
| SYN-only packets in analysis | 20 | 100 | 500 | 1,000 |
| TCP flow tuples with SYN-only traffic | 10 | 25 | 50 | 100 |

These are project defaults for testing and initial use, not universal security thresholds. A value at the Low threshold produces Low severity; higher bands produce their corresponding severity. Severity describes the configured evidence magnitude and is not a probability or confidence score. Thresholds should be tuned to the monitored environment and validated against authorized representative traffic.

Each rule can be disabled independently with `DETECTION_CONFIG__PORT_SCAN_ENABLED`, `DETECTION_CONFIG__SYN_FLOOD_ENABLED`, or `DETECTION_CONFIG__CONNECTION_ATTEMPTS_ENABLED`. Thresholds and enablement are recorded in each run's configuration snapshot and SHA-256 configuration identifier.

## Runs, persistence, and API

Detection runs synchronously after flow generation. Flow rows are read in batches of 500; the evaluator retains compact per-source/target counters, distinct ports, and a maximum of 100 flow references per group instead of loading full flows or packet contents into a list. Findings and supporting-flow links are committed in one transaction. A failed run is recorded with a generic error and does not leave partial findings.

Repeating a completed run with the same configuration returns that run and creates no duplicates. A changed configuration creates a new run; prior run findings remain available through the `run_id` query parameter. A failed run with the same configuration can be retried. Database uniqueness constraints provide a final idempotency guard.

The API provides:

- `POST /api/v1/analyses/{analysis_id}/detections/run`
- `GET /api/v1/analyses/{analysis_id}/detection-summary`
- `GET /api/v1/analyses/{analysis_id}/findings` with pagination and severity/rule filters
- `GET /api/v1/analyses/{analysis_id}/findings/{finding_id}`

## False positives, false negatives, and tuning

Port scans can resemble service discovery, inventory checks, or administrators testing systems. Large SYN-only counts can arise from retransmission, packet loss, partial capture points, or legitimate load testing. Many distinct TCP tuples may reflect normal high-volume client activity. Thresholds that are too low increase false positives; thresholds that are too high miss lower-volume behavior. Capture truncation and visibility gaps can cause false negatives.

Validation in this milestone uses deterministic synthetic fixtures only. No real-world attack dataset, detection rate, false-positive rate, or accuracy score has been measured.
