# Traffic analytics and security events

SENTINEL analyzes stored PCAP/PCAPNG captures. The Day 9 charts describe the selected historical capture; the interface does not display live traffic.

## Traffic aggregation

`GET /api/v1/analytics/traffic/{analysis_id}` reads persisted packet metadata and, when present, bidirectional flow records. The analysis ID scopes every query. SQL aggregates compute packet counts, packet-length totals, protocol distribution, endpoint totals and flow protocol counts. The API returns top ten source/destination IP addresses and top ten flows by byte and packet totals. It never reads payloads.

Protocol packet counts and bytes are calculated from `packet_metadata.network_protocol` and `packet_length`. A percentage is the bucket's count or bytes divided by that analysis's corresponding total. A byte percentage is unavailable when the total byte count is zero. A protocol's `flow_count` is unavailable when no matching generated flow exists.

Directional totals are sourced from `network_flows.forward_*` and `backward_*`. They are `null` until flow generation is complete. These counts describe the flow engine's canonical direction assignment.

Packet lengths are grouped into fixed display ranges: under 64 bytes, 64–127, 128–511, 512–1499, and at least 1500 bytes. They are visualization buckets, not MTU or protocol classifications.

## Timeline buckets and rates

Packet timestamps are persisted as decimal Unix epoch seconds. The API queries the minimum, maximum and count of non-null packet timestamps, then groups packets in SQL into observed buckets. Bucket width adapts to the capture span: 1 second for identical timestamps, approximately span/20 for captures up to one second, at least 50 milliseconds for captures up to ten seconds, 1 second through one minute, and `ceil(span / 60)` for longer captures. Only buckets containing observed packets are returned; no empty intervals or interpolated traffic are fabricated.

When packet timestamps are identical, the duration is zero and all timestamped packets occupy one one-second bucket. If timestamps are absent, the timeline is empty. If only some packet timestamps are available, the API reports how many are missing and excludes them from the timeline. Packet and byte rates are `null` unless all persisted packet records have timestamps and the timestamp span is positive. This avoids presenting partial observations as complete rates.

## Security event feed

`GET /api/v1/events` uses a bounded, stable, database-paginated union of persisted rule findings, anomalous ML flow results and hybrid assessments. Events retain source type and database ID in a namespaced identifier (for example, `rule_finding:42`) so independent tables cannot collide. Results order by source-record timestamp descending, then type and source ID.

Filters include event type, severity, analysis ID, protocol, recorded-after and recorded-before timestamps. ML anomaly rows have no severity because Day 5 does not assign one. Protocol filtering is meaningful for rule and ML events; a hybrid assessment is analysis-wide and has no single protocol, so it is excluded when a protocol filter is active.

`GET /api/v1/events/{event_id}` loads evidence only when requested. Rule details include the stored evidence and related support-flow IDs. ML details include the persisted prediction and model-specific anomaly score plus its flow. The score is not a probability. Hybrid details retain the selected detection run/model provenance and persisted evidence references. Packet payloads are not exposed.

The event timestamp labels distinguish *finding recorded*, *anomaly scored*, and *assessment created*. These are record creation timestamps, not capture timestamps. Packet capture time is shown only in traffic analytics from packet timestamps.

The feed reports persisted records, not a de-duplicated incident count. Historical reruns can create distinct source findings or assessments; their source IDs and types make this provenance visible. Displaying a record in multiple UI sections does not create another backend event.

## Analysis comparison

`GET /api/v1/analytics/comparison?analysis_ids=…` accepts two to five unique analysis IDs. It returns each capture separately with packet/byte totals, flow counts where flow generation completed, protocol counts, the latest completed rule run, the latest persisted model inference selection, and latest hybrid assessment. Missing rule, ML or hybrid stages are `null`, not zero. Rule totals include zero-valued severities only when a completed run exists; the UI labels absent runs separately. ML counts are scoped to the model associated with the newest inference result for that analysis.

Comparisons are descriptive. Captures can differ in duration, content, feature coverage and processing configuration. A hybrid risk score is a prioritization measure, not an attack probability; values from different model/rule/scoring configurations should not be read as calibrated equivalents.

## Query efficiency and limitations

Aggregates use analysis-scoped SQL queries instead of loading all packet records in Python. Timeline work is grouped in SQL. Endpoint and flow rankings have fixed top-ten result limits, event pages are capped at 100 records, and comparisons accept at most five analyses. Detailed rule support-flow relationships are fetched only for an individual event, not for every list row.

The currently stored packet metadata represents the fields extracted by the parser; absent addresses or timestamps remain absent. Protocol labels reflect parser metadata, and endpoint rankings count packet appearances, not unique hosts over a time interval. Flow totals inherit the flow engine's capture-wide aggregation limitations. The charts and filters do not classify activity as benign or malicious, and synthetic fixtures used in tests are not real-world traffic evaluation.
