# SENTINEL Demonstration Script (8–12 minutes)

This demonstration uses the offline application and one generated synthetic PCAP. It does not represent real network traffic or prove an attack. Detection results should be described as indicators. Confirm that the target capture is authorized before uploading any other traffic.

## Preparation (before timing)

1. Follow the local setup in [README](../../README.md): start MySQL, apply migrations, then start the backend on `127.0.0.1:8001` and frontend on `localhost:5174`.
2. Check `http://127.0.0.1:8001/health/ready` and open `http://localhost:5174`.
3. Confirm an existing trained model is available and compatible. If none exists, use an explicitly selected completed training analysis with at least 20 flows to train a model in the UI. Training is a separate action; the pipeline never trains one implicitly.
4. Generate the fixture in a temporary directory:

   ```sh
   uv run --project backend python scripts/create_demo_capture.py
   ```

   The script prints the unique output path and recipe label `test-port_scan_pattern-01 (suspicious)`. It never overwrites an existing capture and does not create a PCAP in the repository. Keep the path available for the upload step; remove the temporary file after the demonstration.

## Timed sequence

| Time       | Page and action                                                                                                                                                     | Talking point                                                                                                                                                             |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0:00–0:45  | Open `http://localhost:5174/`.                                                                                                                                      | SENTINEL is an offline, defensive NIDS. Overview values come from persisted analyses and latest applicable stage outputs; they are not live telemetry.                    |
| 0:45–1:30  | Open `/upload`; choose the printed synthetic capture and upload.                                                                                                    | Content is validated server-side. Packet payloads are not stored. The upload and packet limit are displayed by the API.                                                   |
| 1:30–2:15  | Open the newly created analysis and its `/packets` section.                                                                                                         | Packet records are ordered and contain available metadata. Missing fields remain unavailable.                                                                             |
| 2:15–3:00  | Open `/analyses/{newId}/flows`; generate flows if needed.                                                                                                           | Flow IDs are analysis-scoped; direction is canonical endpoint order, not a client/server assertion.                                                                       |
| 3:00–3:45  | Open `/analyses/{newId}/rules`; execute the configured rule stage.                                                                                                  | The scan recipe is intentionally aligned to the multi-port rule; this synthetic finding is not proof of malicious activity.                                               |
| 3:45–4:45  | Open `/analyses/{newId}/ml`; select the existing trained model and run inference.                                                                                   | Inference uses an explicitly selected model. A model is not trained as a side effect. Scores are model-relative, not probabilities.                                       |
| 4:45–5:45  | Open `/analyses/{newId}/hybrid`; select the persisted rule run and model, then assess.                                                                              | Hybrid consumes stored evidence, keeps provenance, and provides an investigation-priority score, not compromise probability.                                              |
| 5:45–6:30  | Open `/analyses/{newId}/pipeline`.                                                                                                                                  | Point out requested stages, prerequisites, completion/reuse status, and the absence of implicit model training. Do not rerun completed stages just for the demonstration. |
| 6:30–7:15  | Open `/events`; filter to the new analysis, inspect the rule event and an ML indicator if present.                                                                  | Rule findings, ML anomaly indicators, and hybrid assessments remain distinct event types. Event-record time is distinguished from capture time.                           |
| 7:15–8:15  | From selected evidence, create or open an incident at `/incidents/{incidentId}`. Add a note, inspect evidence links and history, then change status if appropriate. | Incident creation is analyst-driven. Updating an incident does not rewrite the original finding. The application has no authenticated analyst identity.                   |
| 8:15–9:30  | Open `/evaluation`; inspect the persisted synthetic run and `/evaluation/1`.                                                                                        | Show the fixed dataset, train/test separation, three configurations, confusion matrices, and local benchmark. Synthetic performance is not real-world validation.         |
| 9:30–10:00 | Return to analysis detail or overview.                                                                                                                              | Summarize the strongest result and one limitation: four ML/hybrid false positives in the benchmark and no public dataset evaluation.                                      |

This sequence takes about ten minutes; spend more time on the evidence path if examiners ask about provenance. Route IDs are obtained from API/UI results at runtime; do not assume the latest uploaded analysis or incident has a particular ID.

## Backup steps

- If MySQL is not ready, run `docker compose up -d db`, wait for the health check, and verify `/health/ready`; do not remove the database volume.
- If the backend is unavailable, start it with the README command and inspect `http://localhost:8001/docs` before continuing.
- If the frontend fails, start Vite on an unused local port and check the configured `VITE_API_BASE_URL`; do not kill a process already using 5174.
- If upload processing fails, show the already-persisted synthetic analysis and evaluation run, and explain the failure without presenting a guessed result.
- If no trained model exists, demonstrate the explicit ML prerequisite and use the evaluation page to explain the independently trained synthetic benchmark. Do not imply that evaluation's temporary model is available for production inference.
- If a route or API result is unavailable, state that it could not be demonstrated and use the captured screenshots only to explain the previously verified screen, not as proof of the current service state.

## Cleanup

Remove only the exact temporary PCAP path printed by the fixture script after confirming it is the generated `sentinel-demo-*.pcap` file. Preserve database rows and the named Compose volume; do not use `docker compose down -v`.
