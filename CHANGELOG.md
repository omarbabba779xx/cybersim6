# Changelog

All notable changes to CyberSim6 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-04-02

### Added
- **Incident Response Module** (`cybersim incident-response`): NIST SP 800-61 guided workflow with 6 phases (Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned), SLA tracking, and per-attack-type playbooks
- **Digital Forensics Module** (`cybersim forensics`): Timeline reconstruction, SHA-256 evidence hashing with chain of custody, IOC extraction (attack types, source IPs, endpoints, payloads)
- **Remediation Engine** (`cybersim remediation`): Prioritized remediation recommendations mapped to CWE/MITRE for all 6 attack types with actionable steps and references
- **Detection Metrics Engine**: Precision, Recall, F1-Score, Accuracy tracking per detection module with formatted reports
- **Base Detector class**: Common base for all detection modules with metrics integration and run-loop infrastructure
- **Anomaly Detection CLI** (`cybersim anomaly`): Expose statistical anomaly detector via CLI with configurable window/threshold
- **Attack Chain Mermaid Diagrams**: Generate Mermaid flowcharts for all scenarios with kill-chain phase coloring and MITRE technique annotations
- **Architecture Documentation** (`docs/architecture.md`): 3 Mermaid diagrams — module architecture, event flow, and safety framework layers
- **CLI Input Validation**: Port validation (1-65535), URL loopback enforcement, positive integer checks on all CLI arguments
- **Configurable Detection Thresholds**: All detection parameters now configurable via `config/default.yaml` (DDoS threshold, bruteforce limits, anomaly Z-score, IR SLA targets)
- 41 new tests covering all new modules (detection metrics, remediation, base detector, incident response, forensics, Mermaid generation)

### Changed
- Test suite expanded from 704 to 745 tests
- Total modules increased from 15 to 19 (added IR, Forensics, Remediation, Anomaly CLI)
- Config file enriched with detection, anomaly, and IR parameters

## [1.1.1] - 2026-03-29

### Added
- Runtime HTTP tests for local training servers (DDoS target, auth, phishing, XSS, SQLi)
- Round-trip ransomware encryption/decryption tests with integrity verification
- Cross-platform Makefile helpers via `tools/project_tasks.py`
- `pre-commit` configuration with repository hygiene hooks
- Targeted `mypy` configuration for maintained typed modules

### Changed
- Coverage gate raised from 50% to 85%
- Test suite expanded to 704 tests with 90% measured coverage
- CLI banner simplified to plain ASCII for reliable Windows terminals
- Dashboard and API docs no longer depend on external CDN assets

### Fixed
- Version metadata aligned across package, CLI, OpenAPI, dashboard, and docs
- Safety validation now handles IPv6 loopback correctly and blocks `0.0.0.0` as a target
- Local training servers now support ephemeral ports and clean shutdowns for tests and demos

## [1.1.0] - 2026-03-28

### Added
- WAF module with 50+ rules: CSRF, XXE, SSRF, Command Injection, Auth Bypass detection
- Honeypot cross-trap AttackCorrelator with threat levels (LOW/MEDIUM/HIGH/CRITICAL)
- Compliance weighted scoring with maturity levels and risk rating
- OpenAPI 3.0.3 documentation + Swagger UI at /api/docs
- Port scanner module
- Attack chain scenarios with MITRE ATT&CK mapping
- Interactive tutorial system
- Password analyzer utility
- Anomaly detection engine
- Audit trail with hash-chain integrity
- Threat scoring engine
- PDF report generation

### Changed
- CI/CD pipeline: 3 parallel jobs (test with coverage >=70%, flake8 lint, bandit security scan)
- Tests expanded from 436 to 662 (+210 new tests)

### Fixed
- Honeypot deadlock: threading.Lock replaced with RLock for reentrant locking

## [1.0.0] - 2026-03-18

### Added

#### Core Infrastructure
- Abstract `BaseModule` class with `run()`, `stop()`, `log_event()`, `_validate_safety()`
- Unified `CyberSimLogger` with JSON/CSV export and session tracking
- `ConfigLoader` with YAML-based configuration (`config/default.yaml`)
- `Reporter` for structured session summaries
- `PerfTracker` with `@timer` decorator for performance monitoring
- 7-layer safety framework (`safety.py`): IP validation, sandbox marker, anti-path traversal, file limits, confirmation, non-destructive, blocked directories

#### Attack Modules
- **DDoS** (port 8080): SYN Flood (Scapy) + HTTP Flood, rate-based detection
- **SQL Injection** (port 8081): Auth Bypass, UNION, Error-based, Blind Boolean — 9 regex detection patterns
- **Brute Force** (port 9090): Dictionary attack with wordlists, per-IP failed login counter
- **XSS** (port 8082): Reflected, Stored, DOM-based — 10 detection patterns + `sanitize()` function
- **Phishing** (port 8083): 3 templates (Corporate Login, Password Reset, Office365), multi-criteria risk scoring
- **Ransomware** (sandbox only): AES-256-CBC encryption/decryption, Shannon entropy detection, safety guard

#### Dashboard & Demo
- Real-time web dashboard (port 8888) with glassmorphism UI, KPI cards, event feed
- REST API: `/api/stats`, `/api/events`, `/api/timeline`
- Automated demo mode (`cybersim demo`) running all 6 modules sequentially
- Colored terminal output with ASCII art banner

#### Testing
- 214 unit tests with pytest (100% pass rate)
- Integration tests for attack-detect pipeline
- Edge case tests for ransomware entropy detection
- Pattern validation tests for SQLi (21 tests) and XSS (49 tests)
- Shared fixtures in `conftest.py`

#### Documentation
- Countermeasures guide (`docs/contre_mesures.md`)
- Security awareness guide (`docs/guide_sensibilisation.md`)
- Incident Response Plan — NIST SP 800-61 (`docs/plan_reponse_incidents_irp.md`)
- CVE/CWE/MITRE ATT&CK mapping (`docs/rapport_cve_cwe_mitre.md`)

#### DevOps
- GitHub Actions CI/CD: matrix testing (Python 3.10/3.11/3.12 x Ubuntu/Windows)
- Modern `pyproject.toml` packaging with `cybersim` CLI entry point
- Comprehensive `.gitignore`

[1.0.0]: https://github.com/omarbabba779xx/cybersim6/releases/tag/v1.0.0
