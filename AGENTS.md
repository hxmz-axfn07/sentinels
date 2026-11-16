# SENTINEL — PROJECT INSTRUCTIONS FOR CODEX

## 1. Project Identity

**Project Name:** Sentinel  
**Project Type:** Intelligent Hybrid Network Intrusion Detection System (NIDS)  
**Project Category:** Cybersecurity / Network Security / Machine Learning  
**Primary Objective:** Develop a functional, full-stack network intrusion detection application that analyzes network traffic, identifies suspicious activity using rule-based and machine-learning techniques, and presents security findings through an interactive dashboard.

Sentinel is a defensive cybersecurity application intended for authorized network monitoring, security analysis, and educational purposes.

The project must prioritize practical functionality, reliability, security, maintainability, and a professional user experience.

The final deliverable is a working application supported by formal academic documentation.

---

## 2. Project Goals

Sentinel must eventually support the following capabilities:

1. Accept PCAP and PCAPNG network capture files.
2. Parse captured network packets.
3. Aggregate packets into bidirectional network flows.
4. Extract meaningful network traffic features.
5. Detect suspicious activity using configurable detection rules.
6. Identify unusual network behavior using machine learning.
7. Correlate rule-based and ML findings.
8. Generate explainable security alerts.
9. Store analysis results and security events.
10. Present network activity and alerts through a dashboard.
11. Allow users to investigate suspicious events.
12. Provide meaningful summaries and downloadable reports.

The initial application must prioritize offline PCAP analysis.

Live network monitoring may be implemented as an optional extension if the core application is complete, stable, and sufficiently tested.

Do not compromise core functionality to implement optional features.

---

## 3. Project Scope and Limitations

### 3.1 In Scope

- Offline PCAP/PCAPNG upload and analysis.
- Packet parsing and metadata extraction.
- Bidirectional flow aggregation.
- Network traffic feature extraction.
- Rule-based intrusion detection.
- Isolation Forest anomaly detection.
- Hybrid detection and risk scoring.
- Security event persistence.
- Interactive monitoring dashboard.
- Incident investigation.
- API documentation.
- Application testing and evaluation.
- Formal academic project documentation.

### 3.2 Optional Extensions

Only implement these after the core application is functional:

- Live packet capture.
- Real-time network monitoring.
- Additional machine-learning algorithms.
- Advanced threat intelligence integrations.
- Automated notifications.
- Additional report export formats.

### 3.3 Out of Scope

Sentinel is an IDS, not an Intrusion Prevention System (IPS).

It must not automatically block IP addresses, terminate connections, modify firewall rules, or interfere with network traffic.

Do not implement offensive exploitation functionality.

All packet capture, analysis, and testing must be performed on networks and traffic the user is authorized to inspect.

---

## 4. Technology Stack

Use the following stack unless a genuine compatibility issue requires a documented change.

### Backend

- Python 3.12+
- FastAPI
- Uvicorn
- Pydantic
- SQLAlchemy 2.x
- Alembic
- Scapy
- pandas
- NumPy
- scikit-learn
- pytest
- HTTPX for API testing

Use asynchronous programming where appropriate, particularly for API endpoints and database operations.

Avoid unnecessary complexity in the initial implementation.

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- Recharts
- Vitest
- React Testing Library

The frontend must be responsive, accessible, and designed for a professional cybersecurity monitoring application.

### Database

- MySQL 8.0
- SQLAlchemy 2.x
- Alembic migrations

Use Docker Compose to run MySQL.

Do not require native MySQL installation on the host machine.

Store uploaded PCAP files in application-managed storage rather than directly inside MySQL BLOB fields.

Store file metadata, analysis records, flows, and security events in the database.

### Infrastructure

- Docker
- Docker Compose
- Git
- GitHub

### Development Environment

The project must support:

1. macOS on Apple Silicon (ARM64).
2. Arch Linux on x86_64.

Avoid platform-specific assumptions wherever possible.

---

## 5. Cross-Platform Development Requirements

The application must work on macOS and Arch Linux.

### Mandatory Requirements

- Use `pathlib` for filesystem paths.
- Avoid hardcoded absolute paths.
- Use environment variables for configuration.
- Provide `.env.example`.
- Maintain a suitable `.gitignore`.
- Use Docker Compose for MySQL.
- Avoid OS-specific shell commands in application code.
- Use Python virtual environments.
- Keep frontend and backend dependencies reproducible.
- Document OS-specific setup instructions when necessary.

### Python Environment

Use Python 3.12 or newer.

Create a virtual environment inside the backend directory.

Do not commit virtual environments.

### Live Capture Compatibility

Live packet capture may require different permissions and network interface configuration across operating systems.

Isolate capture functionality behind a dedicated interface or service.

Do not make offline PCAP analysis depend on privileged packet capture access.

The offline analysis functionality must work without root or administrator privileges.

---

## 6. System Architecture

Implement Sentinel using a modular architecture.

### 6.1 High-Level Processing Pipeline

PCAP/PCAPNG Input  
→ File Validation  
→ Packet Parsing  
→ Packet Metadata Extraction  
→ Bidirectional Flow Aggregation  
→ Feature Extraction  
→ Rule-Based Detection  
→ ML Anomaly Detection  
→ Hybrid Correlation and Risk Scoring  
→ Security Event Persistence  
→ Dashboard and Incident Investigation

### 6.2 Backend Responsibilities

The backend is responsible for:

- API endpoints.
- Authentication and authorization if included in the agreed scope.
- File upload and validation.
- Packet processing.
- Flow generation.
- Feature extraction.
- Detection execution.
- ML inference.
- Alert generation.
- Database persistence.
- Background analysis tasks.
- WebSocket event delivery where required.
- Report generation.

### 6.3 Frontend Responsibilities

The frontend is responsible for:

- Dashboard presentation.
- PCAP upload interface.
- Analysis progress.
- Network activity visualization.
- Security alert presentation.
- Incident investigation.
- Filtering and searching.
- Report access.
- Application configuration.

Keep API communication separate from UI components.

### 6.4 Architectural Principles

- Separate responsibilities into modules.
- Avoid monolithic files.
- Use typed interfaces.
- Prefer dependency injection where useful.
- Keep business logic separate from API routes.
- Avoid circular dependencies.
- Make components independently testable.
- Use clear error handling.
- Avoid unnecessary abstraction.

---

## 7. Network Traffic Analysis Requirements

### 7.1 PCAP Processing

Support PCAP and PCAPNG inputs.

Validate uploaded files before processing.

Handle:

- Invalid capture files.
- Empty capture files.
- Unsupported formats.
- Corrupted packets.
- Incomplete packet metadata.
- Large capture files.
- Processing failures.

Never trust filenames or MIME types alone to validate uploaded files.

Apply configurable upload size limits.

Avoid loading unnecessarily large capture files entirely into memory.

### 7.2 Packet Metadata

Extract relevant packet information where available:

- Timestamp.
- Source IP.
- Destination IP.
- Source port.
- Destination port.
- Protocol.
- Packet length.
- TCP flags.
- Relevant transport-layer metadata.

Do not store packet payloads unnecessarily.

Treat captured traffic as potentially sensitive.

### 7.3 Flow Aggregation

Group related packets into bidirectional network flows.

A flow should distinguish the two communication directions while preserving a consistent flow identity.

Candidate flow features include:

- Flow duration.
- Forward packet count.
- Reverse packet count.
- Forward byte count.
- Reverse byte count.
- Protocol.
- TCP flag counts.
- Packet rate.
- Byte rate.
- Packet inter-arrival-time statistics.

Document the final feature definitions.

Handle incomplete and non-TCP traffic correctly.

Do not assume every packet has TCP or UDP ports.

---

## 8. Detection Engine Requirements

Sentinel must use a hybrid detection architecture.

### 8.1 Rule-Based Detection

Initially implement indicators for:

- Port scanning.
- SYN flood-like activity.
- Excessive connection attempts.
- Suspicious connection patterns.
- Unusual traffic volume.

Rules must be configurable.

Each rule-based finding should include:

- Rule ID.
- Detection timestamp.
- Source information.
- Destination information.
- Severity.
- Evidence.
- Explanation.
- Relevant threshold or condition.
- Associated flow or analysis reference.

Avoid hardcoding thresholds throughout the codebase.

Centralize detection configuration.

Detection rules must be independently testable.

### 8.2 Machine Learning Detection

Use scikit-learn Isolation Forest as the initial anomaly detection algorithm.

Requirements:

- Reproducible model training.
- Consistent preprocessing.
- Missing-value handling.
- Feature validation.
- Model persistence.
- Model versioning or metadata.
- Separate training and evaluation data.
- No data leakage.
- Documented anomaly score interpretation.

An ML anomaly is not automatically a confirmed attack.

The UI must distinguish an anomalous observation from a rule-confirmed detection.

Never fabricate training metrics or detection accuracy.

### 8.3 Hybrid Detection

Combine rule-based and ML findings.

The hybrid engine should:

- Correlate related findings.
- Preserve the origin of each detection.
- Retain supporting evidence.
- Calculate transparent risk scores.
- Assign understandable severity levels.
- Avoid unnecessary duplicate alerts.
- Explain why an event was flagged.

Do not hide uncertainty behind a single risk score.

The system must make it possible to understand whether an alert originated from a rule, an ML anomaly, or both.

---

## 9. Database Requirements

Use SQLAlchemy 2.x and Alembic.

Database schema changes must be managed through migrations.

Do not modify production schema manually without updating migrations.

Potential entities include:

- Users, if authentication is implemented.
- PCAP files.
- Analysis jobs.
- Network flows.
- Security events.
- Threat alerts.
- Detection rules.
- Incidents.
- Audit logs.

Create only the entities required by the current milestone.

Do not overengineer the initial schema.

### Database Rules

- Use appropriate primary keys.
- Define foreign-key relationships.
- Add indexes for frequently queried fields.
- Use suitable timestamp handling.
- Validate data before persistence.
- Avoid unnecessary duplication.
- Handle database failures gracefully.
- Use transactions where appropriate.
- Never commit database credentials.
- Do not commit database volumes or raw datasets.

---

## 10. API Requirements

Use REST APIs for normal application operations.

Use WebSockets for real-time updates when needed.

FastAPI must provide automatically generated OpenAPI documentation.

Organize endpoints by responsibility.

Expected API areas include:

- Health.
- PCAP uploads.
- Analysis jobs.
- Network flows.
- Security events.
- Threat alerts.
- Incidents.
- Dashboard statistics.
- Reports.

Implement endpoints incrementally.

Do not create placeholder endpoints that falsely imply functionality exists.

Use correct HTTP status codes.

Validate request and response data with Pydantic.

Handle exceptions consistently.

---

## 11. Frontend and UI Requirements

The application should resemble a professional network security monitoring platform.

### Main Dashboard

Include relevant information such as:

- Total analyzed captures.
- Total network flows.
- Security alerts.
- Critical and high-severity findings.
- Traffic activity.
- Protocol distribution.
- Recent security events.
- Detection summaries.

Only display values supported by actual backend data.

### PCAP Analysis Interface

Include:

- File selection.
- Upload progress.
- File metadata.
- Analysis status.
- Processing errors.
- Analysis results.

### Security Events

Provide:

- Severity indicators.
- Detection source.
- Timestamp.
- Source and destination information.
- Evidence.
- Explanation.
- Filtering and searching.

### Incident Investigation

Allow users to inspect an event and its supporting evidence.

### Design Principles

- Clean, professional cybersecurity aesthetic.
- Consistent spacing and typography.
- Responsive layout.
- Accessible contrast.
- Useful loading and error states.
- Empty states when no data exists.
- No unnecessary animations.
- Avoid excessive visual clutter.

Do not hardcode demonstration statistics as if they were real results.

Seeded demo data, if needed, must be clearly identified as demonstration data.

---

## 12. Security Requirements

Security must be considered throughout development.

### File Upload Security

- Validate file extensions and actual file content.
- Apply file size limits.
- Generate safe server-side filenames.
- Prevent path traversal.
- Avoid trusting client-supplied filenames.
- Store uploaded files outside publicly accessible directories.
- Handle malformed files safely.

### API Security

- Validate all incoming data.
- Avoid exposing stack traces to clients.
- Use secure configuration practices.
- Avoid logging secrets.
- Apply appropriate CORS configuration.
- Protect sensitive endpoints.
- Use authentication and authorization if included in scope.

### Database Security

- Use parameterized queries through SQLAlchemy.
- Avoid hardcoded credentials.
- Use least-privilege database credentials where practical.
- Never expose database credentials to the frontend.

### General Security

- Do not disable TLS verification to bypass errors.
- Do not use unsafe deserialization.
- Do not execute uploaded files.
- Treat PCAP content as untrusted input.
- Avoid logging sensitive packet payloads.
- Do not automatically block network traffic.

---

## 13. Testing and Quality Assurance

Testing is mandatory.

Never claim that functionality works without verification.

### Backend Testing

Use pytest.

Test:

- Configuration.
- Health endpoints.
- Database connectivity.
- Database models.
- Migrations.
- Upload validation.
- PCAP parsing.
- Flow aggregation.
- Feature extraction.
- Detection rules.
- ML preprocessing.
- ML inference.
- Hybrid scoring.
- API error handling.

### Frontend Testing

Use Vitest and React Testing Library.

Test:

- Component rendering.
- User interactions.
- API integration behavior.
- Loading states.
- Error states.
- Empty states.
- Dashboard data presentation.

### Integration Testing

Verify the complete application pipeline where implemented.

Use representative test captures.

Clearly distinguish synthetic test traffic from real-world traffic.

### Evaluation Metrics

Where suitable labeled evaluation data is available, calculate:

- Precision.
- Recall.
- F1-score.
- False-positive rate.
- True-positive rate.
- Processing throughput.
- Analysis latency.

Document dataset characteristics and evaluation methodology.

Never fabricate results, benchmark numbers, screenshots, or test outcomes.

---

## 14. Documentation Requirements

Maintain two separate documentation tracks.

### 14.1 Learning and Technical Documentation

Location:

`docs/learn/`

Purpose:

Explain the concepts and implementation decisions behind Sentinel.

Include relevant material on:

- Network fundamentals.
- Packet structure.
- PCAP and PCAPNG.
- Network flows.
- Flow feature extraction.
- Intrusion detection systems.
- Rule-based detection.
- Isolation Forest.
- Anomaly detection.
- Hybrid detection.
- Risk scoring.
- FastAPI architecture.
- Database design.
- Deployment.
- Testing and evaluation.

Documentation should explain the actual implementation rather than describe features that do not exist.

### 14.2 Formal College Project Report

Location:

`docs/project-report/`

Maintain:

- `report.md` — master editable report.
- `report.docx` — exported Word document.

Use the academic structure and writing style of the sample report supplied by the user.

Maintain formal academic language, numbered headings, paragraphs, tables, figure captions, references, and appendices where appropriate.

Expected report structure:

1. Cover Page.
2. Declaration.
3. Acknowledgement.
4. Abstract.
5. Table of Contents.
6. List of Figures.
7. List of Tables.
8. List of Abbreviations.
9. Chapter 1 — Introduction.
10. Chapter 2 — Objectives.
11. Chapter 3 — Problem Statement and Need.
12. Chapter 4 — Software Requirements Specification.
13. Chapter 5 — Literature Review.
14. Chapter 6 — Proposed Solution and Methodology.
15. Chapter 7 — Implementation, Testing and Results.
16. Chapter 8 — Conclusion and Future Scope.
17. References.
18. Appendices.

Adapt chapter numbering only when required by the supplied institutional format.

### Report Accuracy

- Keep the report synchronized with actual implementation.
- Use placeholders for unknown institutional details.
- Do not invent supervisor names or signatures.
- Do not invent citations or references.
- Do not claim experiments were performed when they were not.
- Do not invent screenshots or performance results.
- Clearly identify planned, implemented, and evaluated functionality.
- Update the report after significant milestones.

The Markdown report is the master source.

Regenerate the DOCX export whenever meaningful report changes are made.

Research-paper publication is not part of the current project scope.

---

## 15. Development Roadmap — 14 Days

The project has a strict two-week delivery target.

Prioritize a complete, working application over optional features.

### Day 1 — Foundation

- Inspect existing repository and instructions.
- Initialize Git if needed.
- Configure GitHub remote if supplied by the user.
- Establish project structure.
- Scaffold FastAPI backend.
- Scaffold React frontend.
- Configure Docker Compose.
- Configure MySQL.
- Configure environment variables.
- Configure SQLAlchemy.
- Configure Alembic.
- Create initial database models.
- Implement health endpoints.
- Add basic tests.
- Verify local development setup.
- Update documentation.

**Day 1 must not implement PCAP processing, flow aggregation, detection rules, or machine learning.**

### Day 2 — PCAP Ingestion

- Implement secure file upload.
- Support PCAP and PCAPNG.
- Validate file content.
- Parse packets with Scapy.
- Extract packet metadata.
- Handle invalid and malformed captures.
- Add upload and parsing tests.

### Day 3 — Flow Engine

- Implement bidirectional flow identification.
- Aggregate packets.
- Calculate flow statistics.
- Extract traffic features.
- Add unit tests.

### Day 4 — Rule-Based Detection

- Implement port scan indicators.
- Implement SYN flood indicators.
- Implement excessive connection detection.
- Implement configurable thresholds.
- Produce explainable findings.
- Add detection tests.

### Day 5 — Machine Learning

- Implement feature preprocessing.
- Train Isolation Forest.
- Persist trained model.
- Implement inference.
- Record model metadata.
- Validate anomaly scoring.
- Add ML tests.

### Day 6 — Hybrid Detection

- Correlate rule and ML findings.
- Implement transparent risk scoring.
- Assign severity.
- Preserve detection provenance.
- Suppress duplicate findings where appropriate.
- Add hybrid detection tests.

### Day 7 — Backend Integration

- Integrate analysis pipeline.
- Persist results.
- Implement API endpoints.
- Add background processing where needed.
- Implement WebSocket updates where needed.
- Add integration tests.

### Day 8 — Dashboard Foundation

- Build application layout.
- Implement navigation.
- Build dashboard structure.
- Integrate backend API.
- Add loading, empty, and error states.

### Day 9 — Monitoring Interface

- Display traffic statistics.
- Add protocol charts.
- Add security event feed.
- Add alert summaries.
- Add filtering and search.
- Implement real-time updates if supported.

### Day 10 — Incident Management

- Implement incident investigation.
- Display evidence.
- Add event detail views.
- Implement report generation.
- Complete essential UI integration.

**Feature freeze at the end of Day 10.**

Only critical bug fixes and stability improvements should follow.

### Day 11 — Evaluation

- Prepare labeled evaluation traffic.
- Run controlled tests.
- Calculate appropriate metrics.
- Measure processing performance.
- Document limitations.
- Capture genuine screenshots.

### Day 12 — QA and Security Review

- Run backend tests.
- Run frontend tests.
- Run integration tests.
- Review file upload security.
- Review API validation.
- Review database handling.
- Fix critical bugs.

### Day 13 — Formal Report

- Update the complete academic report.
- Include verified architecture diagrams.
- Include actual implementation details.
- Include genuine test results.
- Include screenshots.
- Update references and appendices.
- Export the DOCX report.

### Day 14 — Finalization

- Test the application from a clean environment.
- Verify Docker Compose deployment.
- Verify database initialization.
- Verify core functionality.
- Finalize documentation.
- Prepare project demonstration.
- Prepare presentation material.
- Record known limitations.

---

## 16. Git and GitHub Automation

Codex is responsible for maintaining a clean and organized Git history throughout Sentinel development.

### 16.1 Repository Setup

During Day 1:

1. Initialize Git if not already initialized.
2. Configure the main branch as `main`.
3. Check `.gitignore`.
4. Configure the GitHub remote only when the correct repository URL is available.
5. Verify repository connectivity.
6. Create an initial project commit after the foundation passes tests.
7. Push the initial commit to GitHub after verifying the remote.

Never overwrite an existing Git repository or remote configuration without approval.

If no GitHub URL has been provided, initialize the local repository and ask the user for the URL before configuring the remote.

### 16.2 Commit Policy

Create meaningful Git commits after every completed milestone or independently verified feature.

Examples:

- `chore: initialize sentinel project structure`
- `build: configure docker compose and mysql`
- `feat: implement backend health endpoints`
- `feat: add database models and migrations`
- `feat: implement secure pcap ingestion`
- `feat: add bidirectional flow aggregation`
- `feat: implement rule-based intrusion detection`
- `feat: add isolation forest anomaly detection`
- `feat: implement hybrid threat scoring`
- `feat: build security monitoring dashboard`
- `test: add network detection test coverage`
- `docs: update final-year project documentation`

Commit messages must:

- Use conventional commit prefixes where appropriate.
- Describe actual changes.
- Avoid vague messages such as `update`, `changes`, or `fixed stuff`.
- Never claim functionality that has not been implemented.

### 16.3 Before Every Commit

Codex must:

1. Run relevant automated tests.
2. Run linting and formatting checks when configured.
3. Check for accidental secrets.
4. Inspect `git status`.
5. Inspect `git diff`.
6. Verify no generated datasets, PCAP files, credentials, `.env` files, or unnecessary build artifacts are included.
7. Stage only intended files.
8. Create a meaningful commit.

Never use `git add .` blindly.

### 16.4 GitHub Push Policy

After a successful milestone commit:

1. Verify the intended branch.
2. Verify the configured remote.
3. Push the completed commit to GitHub.
4. Verify that the push succeeded.

If authentication fails, report the error and provide the required manual steps.

Never force-push.

Never rewrite published Git history.

Never delete branches or repositories without explicit approval.

### 16.5 Branch Strategy

Use:

- `main`: stable, verified project state.
- `feature/*`: larger independent features.
- `fix/*`: bug fixes.

For small milestones, commits directly to `main` are acceptable when working alone.

For major features, use a feature branch and merge only after tests pass.

### 16.6 Commit Reporting

After every milestone, report:

- Branch name.
- Commit hash.
- Commit message.
- Files changed.
- Tests executed.
- Test results.
- Push status.
- Remaining issues.

### 16.7 Git Safety

Never commit:

- Secrets or credentials.
- `.env`.
- `node_modules/`.
- Python virtual environments.
- Database volumes.
- Raw PCAP datasets.
- Generated model artifacts unless intentionally versioned.
- Temporary build outputs.

Never force-push.

Never use destructive Git commands without explicit approval.

Never discard uncommitted user changes.

Never amend or rewrite published commits without approval.

If unrelated user changes exist, preserve them and stage only files belonging to the current milestone.

---

## 17. Codex Execution Rules

Codex must work incrementally and verify every milestone.

### Before Implementing

1. Read this entire `AGENTS.md`.
2. Inspect the existing repository.
3. Inspect existing files and configuration.
4. Identify existing functionality.
5. Identify potential conflicts.
6. Report a concise implementation plan.

Do not overwrite existing work without understanding it.

### During Implementation

- Follow the specified architecture.
- Use maintainable code.
- Prefer small, focused modules.
- Add type annotations.
- Handle errors explicitly.
- Write tests alongside functionality.
- Avoid unnecessary dependencies.
- Avoid duplicated logic.
- Update documentation when behavior changes.
- Keep configuration centralized.
- Do not silently change the agreed technology stack.

### After Implementation

1. Run relevant tests.
2. Run formatting and linting checks where configured.
3. Verify application startup.
4. Verify database connectivity where relevant.
5. Inspect changes.
6. Check for secrets.
7. Commit completed milestones.
8. Push after successful verification if a remote is configured.
9. Report exactly what was completed and what remains.

Never report a successful test that was not actually executed.

Never claim an application is functional based solely on generated files.

Never leave critical errors unreported.

### Dependency Management

- Pin or constrain dependencies appropriately.
- Keep dependency files synchronized.
- Avoid unnecessary packages.
- Document compatibility changes.
- Prefer stable, maintained packages.

### No Unnecessary Complexity

The project has a two-week deadline.

Prefer straightforward, reliable implementations over elaborate abstractions.

Do not add features simply because they are technically interesting.

Prioritize the minimum complete application that demonstrates the full detection pipeline.

---

## 18. Day 5 Implementation Record — Complete

**Current milestone:** Day 5 — reproducible Isolation Forest anomaly detection over persisted bidirectional flow features.

The user is currently developing on Arch Linux (x86_64). The project must remain compatible with macOS ARM64.

The user reports the following verified environment:

- System Python 3.14.10; use project Python 3.12.16 managed by uv.
- Node.js 24.20.0 and npm 11.19.0.
- Docker Engine 29.9.3 and Docker Compose 5.7.1.
- Git 2.56.1.
- Arch Linux x86_64.

Keep the project compatible with macOS Apple Silicon (ARM64). The Git repository is initialized on `main`, and `origin` is configured as `https://github.com/hxmz-axfn07/sentinels.git`.

Use backend port 8001, frontend port 5174, and host-accessible MySQL port 3307. Check availability before starting services. Existing services use ports 5173, 4000, 8000, 9443, and 11434; do not stop or alter unrelated services or containers.

### Implemented Day 2 through Day 4 scope

- Secure chunked upload with configurable size limits and generated private storage names.
- Content-based structural validation for classic PCAP 2.4 variants and PCAPNG 1.0 sections.
- Scapy packet metadata parsing and persistence without packet payloads.
- Analysis lifecycle and paginated analysis/packet APIs.
- Upload UI with progress and metadata results.
- Alembic revision `0002_capture_metadata`, preserving the Day 1 migration.
- Stable bidirectional flow identification and directional aggregation from stored packet metadata.
- Packet, byte, timing, packet-length, TCP-flag, and rate features with null behavior for unavailable values.
- Synchronous, retryable flow-generation API and paginated flow retrieval.
- Alembic revision `0003_bidirectional_flows`, preserving revisions 0001 and 0002.
- Flow generation UI and technical/report documentation.
- Three configurable rules for multi-port probing, capture-wide SYN-only packet volume, and TCP flow tuples with SYN-only traffic.
- Directional SYN-only and SYN+ACK flow counts, additively backfilled from stored packet flags by revision `0004_rule_based_detection`.
- Versioned, idempotent detection runs with validated config snapshots, structured findings, severity thresholds, and bounded supporting-flow samples.
- Paginated, filtered finding/summary APIs and the findings UI.

### Implemented Day 5 scope

- Versioned `flow-v1` numeric feature selection with identifier, endpoint, timestamp, and label exclusion.
- Median imputation with missingness indicators, `log1p` compression, finite/nonnegative validation, and constant transformed-dimension removal.
- Reproducible Isolation Forest training over explicitly selected completed analyses; deterministic bounded reservoir sampling caps the training population.
- Application-generated joblib artifacts in private managed storage, with path validation, restrictive permissions where supported, model version metadata, source analysis IDs, configuration, feature order, sample counts, and scikit-learn version.
- Bounded, synchronous, idempotent inference with per-flow predictions and `-decision_function` anomaly scores persisted by analysis/model/flow.
- Model training, listing, metadata, inference, result pagination/filtering, and summary APIs; React controls use actual API results.
- Learning documentation and academic report updates. Only deterministic synthetic validation was performed; no real-world model evaluation or detection metrics are claimed.
- Verified state for this milestone: backend tests 104 passed; frontend tests 16 passed; Ruff, ESLint, Prettier, production build, Docker Compose validation, MySQL migration/schema check, synthetic MySQL inference, and local backend/frontend startup checks passed.

The Day 5 model artifact format uses joblib serialization. Only application-generated artifacts addressed by generated storage keys are loaded; protect model storage and the database from untrusted writes. Model inference requires the same scikit-learn version recorded during training. Training data is not assumed benign, and anomaly scores are not probabilities.

At Day 5 completion, the development database was at revision `0005_isolation_forest`. The migration adds model metadata and inference-result tables without rewriting revisions 0001–0004. Downgrading revision 0005 deletes model metadata and inference results. It does not delete model files; artifact cleanup is a separate storage operation. Do not run destructive downgrades against the development database.

At Day 4 completion, the development database had revision `0004_rule_based_detection`; synthetic rows from Day 4 API integration had been cleaned up. Downgrading revision 0002 removes Day 2 packet/capture data, revision 0003 removes generated flows and packet assignments, and revision 0004 removes directional flow counts and detection results. These operations are data-destructive; do not downgrade if those records should be retained. Keep private captures out of Git.

### Day 5 scope boundary at that milestone

At the Day 5 milestone, Day 6 and later work required explicit user approval. Day 6 has since been explicitly authorized and completed. Day 7 and later work remains unauthorized until the user explicitly approves it.

### Completion report

Report actual files changed, feature schema and preprocessing, Isolation Forest configuration, training strategy, model persistence/versioning, inference behavior and score interpretation, migration status, API/frontend capability, executed test/lint/build/migration/MySQL integration checks, report and DOCX export status, branch/commit/push status, model/data limitations, and the exact Day 6 starting point. Never claim unexecuted checks.

---

## 19. Current Execution State — Day 6 Complete

Day 6 is complete. The implementation started on `main` at Day 5 commit `b84933e82ce7c43e8720160c82398450e9d8866d`. The Day 6 changes are verified and recorded as a milestone commit.

Hybrid assessment consumes the persisted findings from one completed Day 4 run and complete per-flow inference results from one selected Day 5 model version. It does not trigger either source engine. Evidence snapshots retain their source IDs and versions. Correlation is analysis-scoped and groups by canonical unordered endpoint IP pair plus protocol. Exact-flow corroboration requires a shared persisted support-flow reference; endpoint-pair overlap receives no bonus. Missing endpoints remain isolated. There is no invented time-window correlation.

Default rule weights are Low 10, Medium 25, High 45, and Critical 65. Duplicate rule IDs use the highest severity weight and distinct rule IDs combine by noisy-OR. Anomaly scores are normalized using percent rank within the selected analysis/model; ML contribution is `20 + 30 × rank`, using only the maximum contribution per group. Rule and ML components combine by noisy-OR; one 15-point exact-flow bonus applies if independent evidence shares a flow; scores cap at 100. The analysis score is the maximum risk-group score. Severity bands: informational 0, low 1–24, medium 25–49, high 50–74, critical 75–100. Scores are prioritization aids, not attack probabilities.

Alembic revision `0006_hybrid_assessments` is applied to MySQL. Read-only Alembic checks reported no schema drift; Docker Compose configuration validated and the MySQL service was healthy. The backend suite passed 112 tests; frontend tests passed 19 tests. Ruff, ESLint, Prettier, and frontend production build passed. The backend started on port 8001 and returned HTTP 200 from `/health`; Vite served the application on port 5174. The DOCX was regenerated and its archive/XML content validated. Hybrid API tests use synthetic fixtures in isolated SQLite; no synthetic rows were inserted into the development MySQL database. No real-world evaluation or detection metrics are claimed.

Known constraints: hybrid execution is synchronous; source-support samples can be truncated; endpoint correlation is contextual; anomaly rank is model- and analysis-relative; rule weights and thresholds have not been validated on labeled network data. The report and learning documentation describe these limits.

The exact Day 7 starting point is backend pipeline integration using the existing ingestion, flow, rule, ML, and hybrid APIs/services without silently rerunning or retraining prior stages. Day 7 has not started and requires explicit user approval.

## 20. Definition of Project Completion

Sentinel is considered complete only when:

1. The application can be started using documented instructions.
2. The database initializes correctly.
3. Users can upload valid PCAP/PCAPNG files.
4. The backend parses network packets.
5. Network flows are generated correctly.
6. Relevant flow features are extracted.
7. Rule-based detections work.
8. Isolation Forest inference works.
9. Hybrid findings are generated with explanations.
10. Results are persisted.
11. The dashboard displays real application data.
12. Users can investigate security events.
13. The main application pipeline is tested.
14. Evaluation results are calculated from actual test data.
15. Documentation matches the delivered implementation.
16. The final application can be demonstrated reliably.

Optional live monitoring is not required to satisfy the core completion criteria.

---

## 21. Final Instruction

Treat this file as the authoritative project specification.

The user has a strict two-week deadline.

Work in small, independently verifiable milestones.

Prioritize the core application, accurate detection, explainability, stability, testing, and documentation.

Do not fabricate functionality, metrics, research, or test results.

Do not silently expand the scope.

**Current authorization: Day 6 is complete. Wait for explicit user approval before starting Day 7.**
