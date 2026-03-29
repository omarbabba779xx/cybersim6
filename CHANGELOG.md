# Changelog

All notable changes to CyberSim6 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
