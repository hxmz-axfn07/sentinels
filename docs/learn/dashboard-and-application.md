# Dashboard and Application

## Application structure

SENTINEL's React application uses the existing FastAPI endpoints for all capture and detection data. The overview has one aggregate request, `GET /api/v1/dashboard/overview`; the detail panels continue to use their stage-specific paginated APIs. This avoids a request per analysis for the overview while leaving packet, flow, rule, ML, hybrid, and pipeline operations independently accessible.

The application is a single responsive page with keyboard-accessible anchor navigation. The overview, upload form, analysis history, packet metadata, generated flows, rule findings, ML results, hybrid risk groups, and pipeline status are sections of the same application. Selecting an analysis loads its persisted records and reveals the relevant stage controls. The user can revisit an analysis from either the recent overview or paginated history. `GET /api/v1/dashboard/analyses` supplies each page's file metadata and most recent persisted rule, ML, and hybrid state in batched queries rather than a request per row.

## Overview data and scope

The overview describes all persisted analyses, with protocol distribution across completed flow-generation stages. Packet totals include completed analyses only; flow totals include completed flow-generation stages only. A capture that failed or has not completed is not included as a completed packet result.

Rule counts use the latest completed detection run per analysis. A failed later run does not replace that last completed result for the rule totals. ML counts use the model associated with the most recently persisted inference result for each analysis; the result write is transactional and complete for that analysis/model pair. Hybrid severity distribution uses the latest assessment per analysis, avoiding duplicate historical assessments from repeated configuration versions. Recent analysis rows also show the latest rule stage status, whether inference exists, and whether a hybrid assessment exists.

Coverage accompanies detections: if no analysis has a completed rule run or an ML inference result, the corresponding overview value is displayed as unavailable (`—`), not as zero detections. Zero is shown only when results exist and those results contain no findings/anomalies. No absence of a detection result is interpreted as evidence of normal traffic.

## Workflow and pipeline

The interface retains independent controls for generating flows, running rules, training a model, running inference, and creating a hybrid assessment. The pipeline panel is the guided option for explicitly selecting stages. It requires a user-selected existing model for ML stages and never trains implicitly. Its ordered stage records expose prerequisite failures, reuse, successful prior work, and downstream skipped stages.

The typical path is:

1. Upload an authorized PCAP or PCAPNG and wait for packet extraction to finish.
2. Open the analysis from recent analyses or history.
3. Generate flows, run rule detection, and select an existing model for inference.
4. Request hybrid assessment from the selected persisted rule run and inference results.
5. Inspect the score, severity, groups, evidence provenance, and related source results.

Each stage remains separately callable. The pipeline is synchronous and uses existing stage services; large captures may take longer than a web request timeout. A pipeline execution does not make database and private file operations globally atomic.

## Loading, errors, and empty results

Overview, history, upload, and detail panels have independent loading or error states. Pagination requests only the current page. Analysis history uses server-side pagination in pages of 100. Empty states tell the user when to upload a capture or select an analysis. API validation messages are displayed without exposing internal filesystem paths or stack traces.

The overview refreshes after upload and after flow, rule, ML, hybrid, or pipeline output changes. It can also be refreshed manually. It is a persisted snapshot at request time rather than a live-monitoring view.

## Security and limitations

Capture uploads are content-validated and stored in managed private storage. Packet payloads are not retained in packet metadata or flow records. The browser is configured to call the local API; the database is not accessed by frontend code. Upload only captures the operator is authorized to inspect.

The interface is a browser-based offline analysis application, not live traffic monitoring. The dashboard aggregates historical analyses without a selectable time window. The protocol chart uses the top eight persisted flow protocols and does not imply volume over time. Detection counts can change when a later completed rule run is created; ML anomaly counts can change when another model is run. Anomaly scores are not probabilities, and hybrid scores are investigation-priority measures, not proof of compromise.
