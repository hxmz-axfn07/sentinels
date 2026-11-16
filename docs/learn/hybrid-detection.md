# Hybrid Detection and Risk Assessment

## Purpose

SENTINEL keeps rule detection and Isolation Forest inference as separate analysis stages. Hybrid assessment consumes their persisted outputs and produces an investigation priority for each correlated entity. It does not retrain a model, rerun rules, modify source findings, or establish that an attack occurred.

A rule finding means a configured traffic pattern was observed. An ML anomaly means a flow was unusual relative to one selected model and its training data. Both can be useful evidence, but neither is a ground-truth label.

## Evidence normalization and provenance

Each normalized item retains its source (`rule` or `ml`), source row ID, analysis, selected detection run or model version, and a JSON snapshot of the original evidence. Rule evidence keeps its rule ID, name, severity, explanation, evidence object, and sampled supporting flows. ML evidence keeps its prediction, original model-relative score, selected model version, and relevant flow features. Packet payloads are not part of the normalized evidence.

Assessment inputs are explicit: a completed analysis, one completed rule run for that analysis, and one ready model with inference results for every flow in the analysis. Incomplete inference or inconsistent rule counts are rejected. A completed rule run with zero findings and completed inference with zero anomalies is valid; the result is informational and explicitly does not mean that the traffic is safe. Analyses with no generated flows are rejected because there is no observation set to assess.

## Correlation

Evidence is first partitioned by analysis (the assessment has exactly one analysis). Within that boundary, items with usable addresses are grouped by the lexically ordered IP pair and protocol. Endpoint grouping is contextual: it does not prove that two observations refer to the same connection or attack. Port-level details remain in the source snapshots, but the primary rule findings describe endpoint-level patterns.

An exact-flow relationship is recognized only if the selected rule run's persisted supporting-flow relationship and the selected model's anomaly result point to the same flow ID. Only this exact shared-flow case receives the corroboration bonus. Endpoint-only overlap receives no bonus. The engine does not invent time windows or temporal relationships.

Items lacking endpoint addresses use source-specific fallback keys, so unrelated evidence without endpoints is not joined. Stable group IDs are SHA-256 digests of canonical JSON keys; they do not use Python's process-randomized hash.

## Score calculation

The score is a bounded prioritization value from 0 to 100, not a calibrated probability. The default scoring configuration is versioned as `hybrid-v1` and saved with each assessment.

Rule weights are Low = 10, Medium = 25, High = 45, and Critical = 65. For each group, repeated findings with the same rule ID contribute only the highest configured severity weight. Different rule IDs combine using a noisy-OR calculation:

`R = 100 × (1 − ∏(1 − wᵢ / 100))`

For each anomalous flow, the original negative `decision_function` score is retained as provenance, but is not directly added to the risk score. Its rank among results for the selected analysis and model is computed with `percent_rank` from 0 to 1. The bounded ML contribution is:

`M = 20 + 30 × rank`

The rank is specific to the selected model and analysis; it is not a probability. When multiple anomalous flows correlate to a group, the maximum contribution is used so repeated anomalies do not accumulate without bound.

Rule and ML components combine as:

`C = 100 × (1 − (1 − R / 100) × (1 − M / 100))`

If at least one anomalous flow is exactly shared with the selected rule run, the default 15 point bonus is added once:

`score = min(100, C + exact_flow_bonus)`

Endpoint-only overlap adds zero. The analysis summary score is the maximum group score. With no rule findings and no ML anomalies, there are no groups and the score is 0; the explanation states that this is not evidence of safety.

The scoring weights and severity boundaries are validated settings. The full configuration and a SHA-256 configuration hash are persisted. Repeating an assessment with the same analysis, rule run, model version, and configuration reuses the existing assessment. A changed scoring configuration creates a distinct assessment while preserving history.

## Severity bands

The default deterministic bands are:

| Score | Severity |
|---:|---|
| 0 | Informational |
| 1–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

Severity describes investigation priority under the saved configuration. It does not express certainty or intent.

## Persistence and API behavior

An assessment stores its analysis, rule-run ID, model ID and version, config version/hash/snapshot, top group score, severity, source counts, and explanation. Risk groups store component scores and endpoint/protocol context. Evidence rows reference the original finding or anomaly result and also retain a source snapshot. Foreign keys and unique constraints preserve source and analysis consistency. The synchronous API reads rule and anomaly evidence in batches and rejects workloads exceeding the configured implementation limit rather than allowing unbounded evidence accumulation.

The API starts an assessment with `POST /api/v1/analyses/{analysis_id}/hybrid/assessments`, using explicit `detection_run_id` and `model_id`. Read endpoints provide the latest summary, assessment history, risk groups, and paginated evidence. Severity filters apply to assessments and groups. Hybrid execution is synchronous, so large analyses can occupy an API worker until completion.

## Limitations

- Rule findings can summarize many flows and may contain only a bounded sample of supporting flow references. Exact-flow corroboration is available only for flows represented by persisted links.
- Endpoint and protocol overlap may connect distinct conversations; the UI labels this as endpoint-pair context rather than exact-flow correlation.
- ML ranks are calculated within one analysis/model result set and are sensitive to its composition. They cannot be compared as calibrated probabilities across models or captures.
- The inputs inherit the false positives, false negatives, capture truncation, and feature limitations of the rule and ML stages.
- Synthetic tests verify deterministic implementation behavior. They are not real-world security evaluation and provide no accuracy or false-positive metrics.

The score is intended to help an analyst prioritize review while keeping original evidence and its provenance visible. It is not an automatic response decision.
