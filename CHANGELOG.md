# Changelog

All notable changes to CyberSim6 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
