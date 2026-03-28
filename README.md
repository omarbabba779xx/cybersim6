<p align="center">
  <img src="docs/assets/banner.svg" alt="CyberSim6 Banner" width="800">
</p>

<p align="center">
  <strong>Plateforme de Simulation de Cyberattaques en Sandbox Isole — 15 Modules</strong>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
  <a href="#"><img src="https://img.shields.io/badge/tests-662%20passed-brightgreen?style=for-the-badge&logo=pytest&logoColor=white" alt="Tests"></a>
  <a href="#"><img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/EMSI-Tanger%204IIR-red?style=for-the-badge" alt="EMSI"></a>
  <a href="#"><img src="https://img.shields.io/badge/framework-MITRE%20ATT%26CK-orange?style=for-the-badge" alt="MITRE"></a>
</p>

<p align="center">
  <a href="#-installation">Installation</a> •
  <a href="#-demo-rapide">Demo</a> •
  <a href="#-modules">Modules</a> •
  <a href="#-dashboard">Dashboard</a> •
  <a href="#-documentation">Documentation</a>
</p>

---

## Screenshots

<details>
<summary><strong>CLI Banner</strong> — Interface ligne de commande</summary>
<p align="center">
  <img src="docs/screenshots/cli_banner.png" alt="CyberSim6 CLI Banner" width="800">
</p>
</details>

<details>
<summary><strong>Demo Mode</strong> — Execution automatisee des modules</summary>
<p align="center">
  <img src="docs/screenshots/demo_start.png" alt="Demo Start - DDoS Phase" width="800">
  <br><em>Phase 1 : Demarrage des serveurs + DDoS HTTP Flood</em>
</p>
<p align="center">
  <img src="docs/screenshots/demo_sqli_bruteforce.png" alt="Demo SQLi + BruteForce" width="800">
  <br><em>Phase 3-4 : SQL Injection (4 types) + Brute Force Dictionary Attack</em>
</p>
<p align="center">
  <img src="docs/screenshots/demo_xss_phishing.png" alt="Demo XSS + Phishing" width="800">
  <br><em>Phase 5-6 : XSS (Reflected + Stored + DOM) + Phishing Campaign</em>
</p>
<p align="center">
  <img src="docs/screenshots/demo_report.png" alt="Demo Final Report" width="800">
  <br><em>Phase 7 : Ransomware AES-256 + Rapport Final (238 events, 6/6 modules)</em>
</p>
</details>

<details>
<summary><strong>Dashboard</strong> — Monitoring temps reel</summary>
<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="CyberSim6 Dashboard" width="800">
</p>
</details>

<details open>
<summary><strong>Tests</strong> — 662 tests passed</summary>
<p align="center">
  <img src="docs/screenshots/tests_passed.png" alt="662 Tests Passed" width="800">
</p>
</details>

---

## A propos

**CyberSim6** est une plateforme educative de simulation de cyberattaques developpee dans le cadre du projet academique EMSI Tanger (4IIR, 2025-2026). Elle permet de simuler, detecter et analyser des cyberattaques a travers **15 modules** (6 attaque + 3 defense + 6 utilitaires) dans un environnement sandbox completement isole.

> **Objectif pedagogique** : Comprendre les mecanismes d'attaque pour mieux s'en defendre.

### Pourquoi CyberSim6 ?

- **100% Sandbox** : Toutes les attaques ciblent uniquement `localhost` avec 7 couches de securite
- **15 Modules** : 6 modules d'attaque, 3 de defense (WAF, Honeypot, Scanner) et 6 utilitaires (Tutorial, Scenarios, Compliance, Report, Password Analyzer, Dashboard)
- **WAF Avance** : 50+ regles couvrant CSRF, XXE, SSRF, Command Injection, Auth Bypass
- **Honeypot Intelligent** : AttackCorrelator multi-trap avec detection de recon, brute-force et lateral movement
- **Conformite** : Scoring pondere ISO 27001, NIST CSF, RGPD avec niveaux de maturite et risk rating
- **Dashboard Temps Reel** : Visualisation live + API documentee (Swagger UI + OpenAPI 3.0.3)
- **Scenarios MITRE ATT&CK** : Chaines d'attaque completes avec mapping tactiques/techniques
- **CI/CD** : 3 jobs paralleles (tests coverage >= 70%, flake8, bandit)
- **Mode Demo Automatise** : Une seule commande pour tout tester
- **662 Tests** : Suite de tests complete (unit + integration + patterns + compliance + WAF + honeypot)

---

## Architecture

```
                    ┌──────────────────────────────────────────────────┐
                    │                 CyberSim6 CLI                    │
                    │           python -m cybersim <module>            │
                    └────────────────────┬─────────────────────────────┘
                                         │
       ┌──────────────┬──────────────────┼──────────────────┬──────────────┐
       │              │                  │                  │              │
 ┌─────▼─────┐ ┌─────▼──────┐   ┌───────▼───────┐  ┌──────▼──────┐ ┌────▼─────┐
 │  Attaque  │ │  Defense   │   │  Utilitaires  │  │  Dashboard  │ │ Scenarios│
 │  Modules  │ │  Modules   │   │   Modules     │  │  Web UI     │ │ MITRE    │
 │ (6 types) │ │ WAF/Honey/ │   │ Tutorial/Scan │  │ Swagger API │ │ ATT&CK   │
 └─────┬─────┘ │ Scanner    │   │ Compliance    │  └──────┬──────┘ └────┬─────┘
       │       └─────┬──────┘   └───────┬───────┘         │             │
       │             │                  │                  │             │
       │    ┌────────▼──────────────────▼──────────────────▼─────────────▼───┐
       │    │          Core Services                                         │
       │    │  ┌──────────┐ ┌────────────┐ ┌────────────┐ ┌───────────────┐ │
       │    │  │ Anomaly  │ │ Audit      │ │ Threat     │ │ PDF Report    │ │
       │    │  │Detection │ │ Trail      │ │ Score      │ │ Generator     │ │
       │    │  └──────────┘ └────────────┘ └────────────┘ └───────────────┘ │
       │    │  ┌──────────────────────────────────────────────────────────┐  │
       │    │  │         Unified Logging Engine (JSON/CSV)                │  │
       │    │  └──────────────────────────────────────────────────────────┘  │
       │    └────────────────────────────┬──────────────────────────────────┘
       │                                 │
 ┌─────▼─────────────────────────────────▼──────┐
 │              Safety Framework                 │
 │  ┌──────────┐ ┌──────────┐ ┌───────────────┐ │
 │  │ Loopback │ │ Sandbox  │ │ Anti-Path     │ │
 │  │   Only   │ │ Marker   │ │ Traversal     │ │
 │  └──────────┘ └──────────┘ └───────────────┘ │
 └───────────────────────────────────────────────┘
```

---

## Les 15 Modules

### Modules d'Attaque (6)

| # | Module | Port | Attaque | Detection | MITRE |
|---|--------|------|---------|-----------|-------|
| 1 | **DDoS** | 8080 | SYN Flood, HTTP Flood | Rate monitoring, seuils | T1498, T1499 |
| 2 | **SQL Injection** | 8081 | Auth Bypass, UNION, Error, Blind | Regex patterns (9 rules) | T1190 |
| 3 | **Brute Force** | 9090 | Attaque par dictionnaire | Failed login counter | T1110 |
| 4 | **XSS** | 8082 | Reflected, Stored, DOM-based | Pattern matching (10 rules) | T1204 |
| 5 | **Phishing** | 8083 | 3 templates, campagne simulee | Scoring multi-criteres | T1566 |
| 6 | **Ransomware** | Sandbox | AES-256-CBC, note de rancon | Entropie Shannon, extensions | T1486 |

### Modules de Defense (3)

| # | Module | Description |
|---|--------|-------------|
| 7 | **WAF** | Web Application Firewall avec 50+ regles : CSRF, XXE, SSRF, Command Injection, Auth Bypass |
| 8 | **Honeypot** | Pots de miel avec AttackCorrelator multi-trap, niveaux de menace, detection recon/brute-force/lateral-movement |
| 9 | **Scanner** | Scanner de ports reseau (`port_scanner.py`) pour la reconnaissance |

### Modules Utilitaires (6)

| # | Module | Description |
|---|--------|-------------|
| 10 | **Tutorial** | Mode interactif d'apprentissage (`interactive.py`) |
| 11 | **Scenarios** | Chaines d'attaque completes avec mapping MITRE ATT&CK (`attack_chain.py`) |
| 12 | **Compliance** | Audit ISO 27001, NIST CSF, RGPD — scoring pondere, niveaux de maturite (NOT_IMPLEMENTED / PARTIAL / COMPLIANT), risk rating |
| 13 | **Report** | Generation de rapports PDF (`pdf_report.py`) |
| 14 | **Password Analyzer** | Analyse de robustesse des mots de passe (`password_analyzer.py`) |
| 15 | **Dashboard** | Interface web temps reel + API REST documentee (Swagger UI) |

---

## Installation

### Prerequis

- Python 3.10+
- pip

### Setup

```bash
# Cloner le repository
git clone https://github.com/omarbabba779xx/cybersim6.git
cd cybersim6

# Installer les dependances
pip install -e .

# Preparer le sandbox
python -m cybersim sandbox setup
```

### Installation rapide (sans packaging)

```bash
pip install -r requirements.txt
python -m cybersim sandbox setup
```

---

## Demo Rapide

### Mode Demo Automatise (recommande)

Une seule commande pour lancer tous les modules avec dashboard :

```bash
python -m cybersim demo
```

Cela va :
1. Demarrer les 5 serveurs cibles
2. Executer les 6 attaques sequentiellement
3. Lancer la detection pour chaque module
4. Afficher un rapport final complet
5. Ouvrir le dashboard sur `http://127.0.0.1:8888/dashboard`

### Module par module

```bash
# --- DDoS ---
python -m cybersim ddos server          # Demarrer la cible
python -m cybersim ddos http-flood      # Lancer l'attaque
python -m cybersim ddos detect          # Detection

# --- SQL Injection ---
python -m cybersim sqli server          # Serveur vulnerable
python -m cybersim sqli attack          # 4 types d'injection
python -m cybersim sqli detect          # Detection patterns

# --- Brute Force ---
python -m cybersim bruteforce server    # Serveur auth
python -m cybersim bruteforce attack    # Attaque dictionnaire
python -m cybersim bruteforce detect    # Detection

# --- XSS ---
python -m cybersim xss server           # App vulnerable
python -m cybersim xss attack           # Reflected + Stored + DOM
python -m cybersim xss detect           # Detection patterns

# --- Phishing ---
python -m cybersim phishing server      # Page de phishing
python -m cybersim phishing campaign    # Campagne simulee
python -m cybersim phishing detect      # Analyse d'indicateurs

# --- Ransomware ---
python -m cybersim ransomware encrypt --sandbox ./sandbox/test_files
python -m cybersim ransomware detect --watch ./sandbox/test_files
python -m cybersim ransomware decrypt --sandbox ./sandbox/test_files
```

### Dashboard seul

```bash
python -m cybersim dashboard            # http://127.0.0.1:8888
```

### Logs

```bash
python -m cybersim logs export --format json
python -m cybersim logs export --format csv
```

---

## Dashboard

Le dashboard web offre une visualisation temps reel :

- **4 cartes KPI** : Total events, Attaques, Detections, Modules actifs
- **Graphiques** : Events par module et par status
- **Live Feed** : Flux d'evenements en temps reel (auto-refresh 2s)
- **API REST** : `/api/stats`, `/api/events`, `/api/timeline`
- **Documentation API** : Swagger UI sur `/api/docs`, specification OpenAPI 3.0.3 sur `/api/openapi.json`

Acces : `http://127.0.0.1:8888/dashboard`

---

## Securite (7 couches)

CyberSim6 est concu avec des mecanismes de securite multi-couches pour garantir que les simulations restent dans l'environnement sandbox :

| Couche | Mecanisme | Description |
|--------|-----------|-------------|
| 1 | **IP Validation** | Seul `127.0.0.1` / `localhost` est autorise comme cible |
| 2 | **Sandbox Marker** | Fichier `.cybersim_sandbox` requis dans le repertoire |
| 3 | **Anti-Path Traversal** | `resolve()` + verification de prefix |
| 4 | **Limites Ransomware** | MAX_FILES=50, MAX_SIZE=10MB, extension whitelist |
| 5 | **Confirmation Interactive** | Prompt `YES` avant chiffrement |
| 6 | **Non-Destructif** | Originaux conserves par defaut |
| 7 | **Repertoires Bloques** | Home, C:\, Windows, Program Files interdits |

---

## Tests

```bash
# Lancer tous les tests
python -m pytest tests/ -v

# Tests par module
python -m pytest tests/test_core/ -v
python -m pytest tests/test_ddos/ -v
python -m pytest tests/test_sqli/ -v
python -m pytest tests/test_xss/ -v
python -m pytest tests/test_phishing/ -v
python -m pytest tests/test_bruteforce/ -v
python -m pytest tests/test_ransomware/ -v
python -m pytest tests/test_dashboard/ -v
python -m pytest tests/test_waf/ -v
python -m pytest tests/test_honeypot/ -v
python -m pytest tests/test_scanner/ -v
python -m pytest tests/test_scenarios/ -v
python -m pytest tests/test_tutorial/ -v
python -m pytest tests/test_utils/ -v
python -m pytest tests/test_cli.py -v

# Avec couverture
python -m pytest tests/ --cov=cybersim --cov-report=html
```

**662 tests** couvrant : safety, logging, config, reporter, perf, base_module, detection (6 modules), patterns, integration, dashboard API, WAF (50+ regles), honeypot, scanner, scenarios, tutorial, compliance, audit trail, anomaly detection, threat score, PDF report, password analyzer.

---

## CI/CD

Le pipeline CI/CD GitHub Actions execute **3 jobs en parallele** :

| Job | Outil | Seuil |
|-----|-------|-------|
| **Tests** | `pytest --cov` | Couverture >= 70% |
| **Lint** | `flake8` | Zero erreur |
| **Security** | `bandit` | Zero vulnerabilite |

```yaml
# Declenchement : push / pull_request sur main
# Python : 3.10, 3.11, 3.12 (matrice)
# Les 3 jobs s'executent en parallele pour un feedback rapide
```

---

## Structure du Projet

```
cybersim6/
├── cybersim/
│   ├── core/                       # Infrastructure commune
│   │   ├── base_module.py          #   Classe abstraite BaseModule
│   │   ├── safety.py               #   Framework de securite (7 couches)
│   │   ├── logging_engine.py       #   Logger unifie JSON/CSV
│   │   ├── config_loader.py        #   Chargeur YAML
│   │   ├── reporter.py             #   Generateur de rapports
│   │   ├── anomaly_detection.py    #   Detection d'anomalies comportementales
│   │   ├── audit_trail.py          #   Piste d'audit horodatee
│   │   ├── compliance.py           #   Audit ISO 27001, NIST CSF, RGPD
│   │   ├── pdf_report.py           #   Generation de rapports PDF
│   │   └── threat_score.py         #   Scoring de menace multi-facteurs
│   ├── ddos/                       # Module DDoS
│   │   ├── target_server.py        #   Serveur HTTP cible
│   │   ├── syn_flood.py            #   Attaque SYN Flood (Scapy)
│   │   ├── http_flood.py           #   Attaque HTTP Flood
│   │   └── detection.py            #   Detection par seuils
│   ├── sqli/                       # Module SQL Injection
│   │   ├── vulnerable_server.py    #   App SQLite vulnerable
│   │   ├── injection_attack.py     #   4 types d'injection
│   │   └── detection.py            #   9 patterns regex
│   ├── bruteforce/                 # Module Brute Force
│   │   ├── auth_server.py          #   Serveur d'authentification
│   │   ├── dictionary_attack.py    #   Attaque par dictionnaire
│   │   ├── detection.py            #   Compteur d'echecs/IP
│   │   └── wordlists/              #   Wordlists de test
│   ├── xss/                        # Module XSS
│   │   ├── vulnerable_app.py       #   App avec 4 endpoints vulnerables
│   │   ├── xss_attack.py           #   Reflected + Stored + DOM
│   │   └── detection.py            #   10 patterns + sanitize()
│   ├── phishing/                   # Module Phishing
│   │   ├── phishing_server.py      #   3 templates de pages
│   │   ├── campaign.py             #   Campagne simulee (pas de vrai email)
│   │   └── detection.py            #   Scoring multi-criteres
│   ├── ransomware/                 # Module Ransomware
│   │   ├── encryptor.py            #   AES-256-CBC + SHA-256
│   │   ├── decryptor.py            #   Dechiffrement + verification
│   │   ├── ransom_note.py          #   Note simulee + disclaimers
│   │   ├── detection.py            #   Entropie Shannon + extensions
│   │   └── safety_guard.py         #   Safety specifique ransomware
│   ├── waf/                        # Web Application Firewall
│   │   └── ...                     #   50+ regles (CSRF, XXE, SSRF, CmdInj, AuthBypass)
│   ├── honeypot/                   # Honeypot intelligent
│   │   └── ...                     #   AttackCorrelator multi-trap
│   ├── scanner/                    # Scanner reseau
│   │   └── port_scanner.py         #   Scan de ports TCP
│   ├── scenarios/                  # Scenarios d'attaque
│   │   └── attack_chain.py         #   Chaines MITRE ATT&CK
│   ├── tutorial/                   # Mode tutoriel
│   │   └── interactive.py          #   Apprentissage interactif
│   ├── utils/                      # Utilitaires
│   │   └── password_analyzer.py    #   Analyse de mots de passe
│   ├── dashboard/                  # Dashboard Web
│   │   └── server.py               #   Serveur HTTP + Swagger UI + API REST
│   ├── demo.py                     # Mode demo automatise
│   └── cli.py                      # CLI unifie (argparse)
├── config/
│   └── default.yaml                # Configuration par defaut
├── sandbox/
│   ├── setup_sandbox.py            # Script de creation sandbox
│   └── test_files/                 # Fichiers fictifs
├── tests/                          # 662 tests pytest
│   ├── test_core/                  #   Core (safety, logging, compliance, audit, ...)
│   ├── test_ddos/                  #   DDoS
│   ├── test_sqli/                  #   SQL Injection
│   ├── test_bruteforce/            #   Brute Force
│   ├── test_xss/                   #   XSS
│   ├── test_phishing/              #   Phishing
│   ├── test_ransomware/            #   Ransomware
│   ├── test_dashboard/             #   Dashboard + API
│   ├── test_waf/                   #   WAF
│   ├── test_honeypot/              #   Honeypot
│   ├── test_scanner/               #   Scanner
│   ├── test_scenarios/             #   Scenarios
│   ├── test_tutorial/              #   Tutorial
│   ├── test_utils/                 #   Utils (password analyzer)
│   └── test_cli.py                 #   CLI
├── docs/                           # Documentation complete
│   ├── contre_mesures.md           #   Fiches contre-mesures
│   ├── guide_sensibilisation.md    #   Guide de sensibilisation
│   ├── plan_reponse_incidents_irp.md  # IRP (6 scenarios)
│   └── rapport_cve_cwe_mitre.md    #   CVE/CWE + MITRE ATT&CK
├── pyproject.toml                  # Configuration Python moderne
├── requirements.txt                # Dependances
└── LICENSE                         # MIT
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Contre-Mesures](docs/contre_mesures.md) | Fiches Detection / Mitigation / Recuperation pour les 6 attaques |
| [Guide de Sensibilisation](docs/guide_sensibilisation.md) | IOC, bonnes pratiques, regles d'or |
| [Plan de Reponse aux Incidents](docs/plan_reponse_incidents_irp.md) | IRP NIST SP 800-61, 6 scenarios, KPI <= 15 min |
| [Rapport CVE/CWE/MITRE](docs/rapport_cve_cwe_mitre.md) | References CVE, CWE, mapping MITRE ATT&CK |
| [Security Policy](SECURITY.md) | Architecture de securite, signalement de vulnerabilites |
| [Changelog](CHANGELOG.md) | Historique des versions et changements |

---

## Quick Commands (Makefile)

```bash
make help        # Afficher toutes les commandes
make install     # Installer le projet
make dev         # Installer avec outils de dev
make test        # Lancer les 662 tests
make coverage    # Tests + rapport de couverture HTML
make demo        # Lancer la demo automatisee
make dashboard   # Demarrer le dashboard web
make clean       # Nettoyer les fichiers temporaires
```

---

## Technologies

| Composant | Technologie |
|-----------|-------------|
| Langage | Python 3.10+ |
| Paquets reseau | Scapy |
| Chiffrement | PyCryptodome (AES-256-CBC) |
| Configuration | PyYAML |
| HTTP | requests + stdlib http.server |
| Base de donnees | SQLite (in-memory) |
| Tests | pytest |
| Dashboard | HTML5 / CSS3 / Vanilla JS |

---

## Equipe

| Role | Membre |
|------|--------|
| Encadrante | **Pr. Mariem Bouri** |
| Etablissement | **EMSI Tanger** - 4eme annee Ingenierie Informatique et Reseaux |
| Annee | 2025-2026 |

---

## Avertissement Legal

> **Ce projet est strictement educatif.** Toutes les attaques sont simulees dans un environnement sandbox isole (localhost uniquement). L'utilisation de ces techniques sur des systemes sans autorisation explicite est **illegale** et passible de poursuites penales.

---

## Licence

Ce projet est sous licence [MIT](LICENSE).

---

<p align="center">
  <sub>CyberSim6 - EMSI Tanger 4IIR | Projet Academique 2025-2026</sub>
</p>
