# Isolation Forest Anomaly Detection

## Supervised and unsupervised learning

Supervised learning uses examples with known labels, such as benign or malicious flows. Unsupervised learning receives observations without those labels and describes structure in the supplied data. SENTINEL's Day 5 engine uses unsupervised Isolation Forest. A model output is an anomaly indicator relative to its training sample; it does not establish that a flow is malicious.

## Isolation Forest intuition

An Isolation Forest repeatedly chooses a feature and a random split within that feature's range. A point separated from other points by only a few splits has a short average path through the trees. Such points are easier to isolate and are treated as more unusual relative to the training observations.

In the original formulation, an anomaly score is derived from average path length:

\[
s(x,n) = 2^{-E[h(x)]/c(n)}
\]

where `h(x)` is the path length for observation `x`, `E[h(x)]` is its mean across trees, and `c(n)` is the expected path length for a sample of size `n`. Scikit-learn exposes its own score orientation: `score_samples` is lower for more unusual points. `decision_function` shifts that score by the fitted threshold. `predict` returns `-1` for an outlier and `+1` for an inlier.

SENTINEL persists `-decision_function` as `anomaly_score`, so a larger value means a more unusual observation under that model. It is a relative model score, not a probability or confidence percentage. Prediction labels come from scikit-learn's `predict` output, not from an independently invented cutoff.

## Flow feature schema

The versioned `flow-v1` schema uses this ordered set of persisted Day 3 numeric fields:

1. `duration_seconds`
2. `total_packets`
3. `total_bytes`
4. `forward_packets`
5. `backward_packets`
6. `forward_bytes`
7. `backward_bytes`
8. `packet_length_min`
9. `packet_length_max`
10. `packet_length_mean`
11. `packet_length_stddev`
12. `interarrival_min`
13. `interarrival_max`
14. `interarrival_mean`
15. `interarrival_stddev`
16. `syn_count`
17. `ack_count`
18. `fin_count`
19. `rst_count`
20. `psh_count`
21. `urg_count`
22. `packets_per_second`
23. `bytes_per_second`

Flow IDs, database IDs, analysis IDs, timestamps, IP addresses, ports, and prediction labels are not model inputs. These fields would either identify a record or introduce an arbitrary numeric encoding rather than a defensible traffic measurement.

All numeric values must be finite and nonnegative. A null means the source flow did not provide that measurement. Training medians impute missing measurements, and a separate missingness indicator is added for every input feature. A wholly unavailable feature is imputed to zero, but its indicator remains constant and is removed unless the training set contains variation in availability. Each metric value is transformed with `log1p` to compress the heavy-tailed scale of counts, bytes, durations, and rates. The tree model does not use standard scaling. Constant transformed dimensions are removed. If the complete transformed training matrix has no varying dimensions, training is rejected.

The fitted preprocessor and estimator are stored together in one scikit-learn pipeline. Inference validates the feature schema version and exact name order before loading and applying that pipeline.

## Training workflow and contamination

An operator explicitly selects one or more completed analyses whose flows have been generated. SENTINEL does not infer that these flows are benign and does not use Day 4 rule findings as ground-truth labels. At least 20 training flows are required. When the combined population exceeds the configured `ML_MAX_TRAINING_SAMPLES` limit (default 50,000), the service uses deterministic reservoir sampling in stable analysis/flow order with the configured random seed. Database reads remain in batches of 500.

`n_estimators` controls the number of trees. `max_samples` controls the number of training observations considered per tree; `auto` lets scikit-learn choose up to 256 observations per tree. The random seed is stored and passed to both sampling and the estimator.

Contamination controls the expected proportion of outliers used to set the prediction threshold. The default is scikit-learn's `auto`; a numeric value must be in `(0, 0.5]`. It is not an estimate of the true attack rate. If the training set already contains unusual or malicious flows, the model can learn those patterns as ordinary and fail to flag similar future flows. No labeled validation set or independent test set is supplied by this milestone, so no accuracy, precision, recall, or false-positive rate is reported.

## Model versioning and persistence

Each training request creates a new immutable model record and generated version identifier; it never silently replaces an older artifact. Metadata stores source analysis IDs, feature names and order, active transformed dimensions, preprocessing description, Isolation Forest parameters, random seed, training population/sample counts, feature schema version, scikit-learn version, and training time. Model files are generated by the application, written atomically with a random server-side key under private managed storage, and excluded from Git. No model-file upload API exists.

Joblib uses Python serialization and can execute code when loading a hostile artifact. SENTINEL only loads keys matching its generated artifact format from the configured managed directory, checks the resolved path, and expects an application-generated pipeline. Administrators must protect write access to that directory and database metadata. Models are rejected if the feature schema or exact scikit-learn version does not match the application environment; retraining is required after incompatible upgrades.

## Inference, storage, and limitations

Inference processes persisted flow rows in batches of 500 and writes one result per flow in one database transaction. Each result records analysis, canonical flow key, model ID and version, label, score, and timestamp. A unique database constraint and an analysis-row lock make repeated inference with the same model return the existing results instead of inserting duplicates. A different analysis or model is isolated by those keys.

The API executes training and inference synchronously. Large requests can occupy an API worker. Flow measurements depend on capture location, packet loss, capture duration, and the Day 3 aggregation behavior; repeated network sessions that reuse a five-tuple are already merged into a single flow. Isolation Forest finds relative statistical outliers, not known attacks, and can miss behavior represented in the training data. These outputs remain separate from Day 4 rule findings. Combining or ranking rule and ML evidence belongs to a later milestone.

Validation in this milestone uses deterministic synthetic flow fixtures and a temporary synthetic MySQL integration. These prove software behavior only; they are not real-world traffic evaluation.
