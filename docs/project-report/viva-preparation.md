# SENTINEL Viva Preparation

Answers below describe the implementation and the persisted synthetic evaluation. Avoid describing anomaly indicators as confirmed incidents or the synthetic measurements as real-world performance.

## System and design

### 1. Why did you build a NIDS instead of an IPS?

SENTINEL is intended to analyze authorized captures and help an analyst review evidence. Automatically blocking traffic would require a separate response design, authorization, safety checks, and operational validation. The application does not block addresses, change firewall rules, or alter network traffic.

### 2. Why offline PCAP analysis?

An offline capture gives a fixed input that can be reprocessed and inspected without privileged live capture. It suits reproducible analysis and local demonstration. It does not provide real-time monitoring, and its outputs depend on what the capture contains.

### 3. Why bidirectional flows?

Combining both directions summarizes a conversation in one record and supports directional packet/byte counts, duration, timing, and protocol features. Endpoint order is deterministic. It does not infer which endpoint is the client. Flow aggregation can merge repeated sessions that reuse one five-tuple within the capture.

### 4. Why Scapy?

Scapy is the packet parsing library used by the code. `PcapReader` lets the parser process capture records incrementally. SENTINEL validates supported PCAP/PCAPNG structure before parsing and persists selected packet metadata rather than payload bytes.

### 5. How are findings, events, and incidents different?

A finding is detection evidence from the rule engine, ML inference, or hybrid assessment. A security event is a persisted feed representation of such output. An incident is an explicit analyst-created investigation that can attach multiple evidence references, notes, and history. Creating or editing an incident does not mutate the original finding.

## Detection methodology

### 6. Why Isolation Forest?

It provides unsupervised outlier detection over numeric flow features and does not require known attack labels for fitting. It identifies unusual observations relative to training data; it does not determine intent. A model is trained from explicitly selected analyses and assigned a version.

### 7. Why not deep learning?

The project uses Isolation Forest as a modest, interpretable prototype with a manageable numeric feature pipeline and reproducible training. Deep learning was not implemented or evaluated; claiming it would improve this system without suitable data and comparison would be unsupported.

### 8. What features are used?

`flow-v1` has 23 numeric fields: duration, total/directional packet and byte counts, packet-length summary statistics, inter-arrival summary statistics, six TCP flag counts, and packet/byte rates. Identifiers, endpoints, timestamps, and labels are excluded. Missing values use training medians with missingness flags; nonnegative metrics are compressed using `log1p`; constant transformed dimensions are removed.

### 9. How does the hybrid score work?

Rule severities map to weights 10, 25, 45, and 65 for Low through Critical. Distinct rule contributions combine by noisy-OR. ML anomaly scores are converted to percent ranks within the selected analysis/model and mapped to a 20–50 contribution; only the maximum ML contribution per group is used. Rule and ML contributions combine by noisy-OR, with a 15-point bonus for exact shared-flow evidence, capped at 100. Endpoint-only overlap gets no bonus. The configuration and source provenance are stored.

### 10. Why are anomaly and hybrid scores not probabilities?

The Isolation Forest decision score is an uncalibrated model-relative output. The hybrid score combines configured weights, within-analysis ranks, and evidence links. Neither is fitted or validated as a calibrated probability of compromise.

## Evaluation

### 11. How was ground truth assigned?

Each synthetic label comes from the deterministic Scapy recipe before an engine is run. A named port-scan or SYN-heavy recipe is labelled suspicious; normal TCP/UDP/ICMP, incomplete metadata, and the benign port-burst recipe are labelled benign by their construction. Predictions never create their own labels.

### 12. How did you prevent train/test leakage?

Sixteen benign training capture IDs and 27 test capture IDs are disjoint. The model is trained only from the benign training partition. All three detection configurations use the same test captures. The persisted run records the IDs, seed, dataset version, model configuration, and `train_test_overlap=false`.

### 13. What are precision, recall, F1, and false-positive rate?

Precision is `TP/(TP+FP)` among positive predictions; recall is `TP/(TP+FN)` among actual positives; F1 is their harmonic mean; and FPR is `FP/(FP+TN)` among actual negatives. If a denominator is zero, SENTINEL records the metric as undefined (`null`) rather than substituting zero.

### 14. What were the actual results?

On 27 synthetic test captures (15 benign, 12 suspicious), rules had TP=12, FP=0, TN=15, FN=0 and precision/recall/F1=1.000. ML and hybrid both had TP=12, FP=4, TN=11, FN=0, precision=0.750, recall=1.000, F1=0.857, and FPR=0.267. The confusion matrix order is `[[TN, FP], [FN, TP]]`.

### 15. Why did hybrid not outperform ML?

The four false positives were two benign ICMP and two incomplete-metadata captures flagged by ML. Hybrid preserves ML-only risk groups; the capture-level evaluation calls any nonzero hybrid score positive. The rule stage did not suppress these groups, so its binary result matched ML. This is an observation on this dataset, not a general statement about hybrid methods.

### 16. Why is the synthetic benchmark limited?

It contains only 27 fixed recipe test captures and deliberately aligns suspicious cases with current rule logic. Labels are capture-level, not per-flow. It does not include a public benchmark dataset or authorized real-world traffic. Therefore its metrics cannot establish real-world detection accuracy or production performance.

### 17. What were the performance measurements?

In three repeated local passes over the 27 test captures, median end-to-end processing was 47.646 ms per capture; mean was 47.651 ms over 81 capture observations. The recorded aggregate throughput was 237.84 packets/s and 99.49 flows/s. The environment was Linux x86_64, Python 3.12.16, scikit-learn 1.9.1, four logical CPUs. Engine timing used temporary data and in-memory SQLite, excluded MySQL persistence and capture generation, and is not a production benchmark.

## Security, operations, and limitations

### 18. What are the major security risks?

There is no authentication or object-level authorization, so the API must remain on a trusted local interface. Processing is synchronous and captures have no automatic retention policy. Joblib is unsafe if an attacker can replace a trusted artifact. The cross-origin write check does not authenticate clients and permits requests without an Origin header. Day 12 also recorded two moderate npm advisories on React Router 6.30.6.

### 19. How are uploads bounded?

The default byte limit is 100 MiB. A packet-record ceiling defaults to 100,000 and is configurable up to 1,000,000. The upload path streams in chunks, checks PCAP/PCAPNG structure, uses generated names, and does not persist packet payloads. These bounds reduce work but do not promise fixed latency or memory use for every valid capture.

### 20. What would you improve with more time?

Evaluate on a documented public labelled dataset and then on authorized operational traffic; improve independent validation and score calibration; design authentication and per-user authorization; move long-running work to bounded background execution; add explicit capture retention/lifecycle controls; and expand protocol and capture-condition coverage. Live capture remains optional and would require a separate permissions and operational design.
