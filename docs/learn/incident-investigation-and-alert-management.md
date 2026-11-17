# Incident investigation and alert management

## Findings, events, and incidents

A **finding** is evidence produced by a rule, the Isolation Forest inference stage, or the hybrid assessment. A **security event** is a read-only representation of one persisted finding in the paginated event feed. An **incident** is a separate analyst-created investigation record. Displaying an event does not create an incident, and an ML anomaly indicator is not a confirmed attack.

Incident evidence rows refer to their original source record. Rule finding references retain the finding, detection run, and analysis relationship. ML references retain the inference result, model ID/version, and analysis. Hybrid references retain the assessment and analysis. Relational constraints validate source ownership, and a uniqueness constraint prevents the same source event from being attached twice to one incident. Source records are never edited by incident operations. An incident may reference evidence from multiple analyses when the original records support those references; the service does not infer a relationship between them.

## Lifecycle and priority

Statuses are `open`, `acknowledged`, `investigating`, `resolved`, and `closed`. The API validates transitions. Resolution requires a non-empty resolution summary. Closing requires a resolved incident. Reopening a resolved or closed incident returns it to `investigating` and clears the prior active resolution summary while retaining the previous transition in history. Priority is analyst-selected (`low`, `medium`, `high`, or `critical`); it represents investigation urgency and is not an attack probability.

## Notes and investigation history

Notes and history rows are append-only through the API. Meaningful changes record action, timestamp, and structured details. Actor fields remain nullable because SENTINEL has no authentication or analyst identity subsystem. The UI identifies this single-user limitation rather than inventing a user. Evidence can be detached from an incident; the source finding remains stored, and the detach action is recorded in history.

## API

- `GET /api/v1/incidents/summary` returns persisted status and priority counts.
- `GET /api/v1/incidents` supports bounded pagination, status, priority, and title search.
- `POST /api/v1/incidents` creates an incident and can attach selected event IDs in the same transaction.
- `GET /api/v1/incidents/{id}` returns incident details, evidence references, notes, and history.
- `PATCH /api/v1/incidents/{id}` updates title, description, or priority.
- `PATCH /api/v1/incidents/{id}/status` validates lifecycle transitions and resolution summary.
- `POST /api/v1/incidents/{id}/evidence` attaches persisted security-event IDs idempotently; `DELETE /api/v1/incidents/{id}/evidence/{evidence_id}` detaches one relationship.
- `POST /api/v1/incidents/{id}/notes` appends an investigation note.

The Day 10 schema is additive in Alembic revision `0008_incident_investigation`. Downgrade removes incident-specific records and tables in the target database. It does not alter detection evidence, but downgrading discards incident investigations, their notes, and their history; do not downgrade a database whose incident records should be retained.

## Security and limitations

API IDs and evidence types are validated, source records use relational integrity, duplicate references are prevented, and database exceptions are returned as safe client errors. Incident APIs do not include packet payloads, filesystem storage keys, model artifacts, or exception traces. There is no authentication, role-based access, assignment workflow, concurrency revision token, or multi-user attribution yet. Local use is single-user and should remain within the application's trusted environment. A future authenticated deployment should bind actor fields to verified identity rather than accepting client-supplied actor names.
