"""
CyberSim6 - Automated Demo Mode
Runs all 6 attack simulations + detections sequentially with a final report.
"""

import sys
import os
import time
from pathlib import Path

# Fix Windows terminal encoding
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.config_loader import load_config, get_module_config
from cybersim.core.reporter import generate_summary

# ANSI
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
D = "\033[2m"
BOLD = "\033[1m"
RST = "\033[0m"

DEMO_PHASES = [
    (R,  "DDoS",       "HTTP Flood Simulation"),
    (Y,  "SQLi",       "SQL Injection (4 types)"),
    (B,  "BruteForce", "Dictionary Attack"),
    (M,  "XSS",        "Reflected + Stored + DOM"),
    (G,  "Phishing",   "Campaign Simulation"),
    (R,  "Ransomware", "AES-256 Encrypt/Decrypt"),
]


def run_demo(config_path: str = None, with_dashboard: bool = True):
    """Run a full automated demo of all 6 CyberSim6 modules."""
    config = load_config(config_path)
    logger = CyberSimLogger(log_dir=Path(config["general"]["log_dir"]))

    print(f"""
{B}{BOLD}  ╔══════════════════════════════════════════════════════╗
  ║          CyberSim6 - AUTOMATED DEMO MODE            ║
  ╚══════════════════════════════════════════════════════╝{RST}
  {D}Session:{RST} {C}{logger.session_id}{RST}  {D}|{RST}  {G}6 attacks{RST} + {Y}detections{RST} + {M}report{RST}
""")

    dashboard = None
    if with_dashboard:
        try:
            from cybersim.dashboard.server import Dashboard
            dashboard = Dashboard(port=8888, logger=logger)
            dashboard.start()
        except Exception as e:
            print(f"[!] Dashboard failed to start: {e}")

    servers = []
    results = {}

    try:
        # ========== Phase 1: Start servers ==========
        print("\n[Phase 1] Starting target servers...")
        servers = _start_servers(config, logger)
        time.sleep(1)

        demo_modules = [
            ("ddos",       _demo_ddos),
            ("sqli",       _demo_sqli),
            ("bruteforce", _demo_bruteforce),
            ("xss",        _demo_xss),
            ("phishing",   _demo_phishing),
            ("ransomware", _demo_ransomware),
        ]

        for i, (key, func) in enumerate(demo_modules):
            color, label, desc = DEMO_PHASES[i]
            phase_num = i + 2
            print(f"\n  {color}{BOLD}▸ Phase {phase_num}/7{RST}  {color}{label}{RST}  {D}— {desc}{RST}")
            print(f"  {D}{'─' * 50}{RST}")
            results[key] = func(config, logger)

        # ========== Final Report ==========
        _print_final_report(logger, results)

        # Export logs
        json_path = logger.export_json()
        csv_path = logger.export_csv()
        print("\n[+] Logs exported:")
        print(f"    JSON: {json_path}")
        print(f"    CSV:  {csv_path}")

        if dashboard:
            print("\n[+] Dashboard still running at http://127.0.0.1:8888/dashboard")
            print("[*] Press Ctrl+C to stop...")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    except KeyboardInterrupt:
        print("\n[!] Demo interrupted.")
    finally:
        for srv in servers:
            try:
                srv.stop()
            except Exception:
                pass
        if dashboard:
            dashboard.stop()


def _start_servers(config, logger):
    """Start all target servers."""
    servers = []

    # DDoS target
    from cybersim.ddos.target_server import TargetServer
    ddos_srv = TargetServer(port=8080, logger=logger)
    ddos_srv.start()
    servers.append(ddos_srv)
    print("  [+] DDoS target server on :8080")

    # Brute force auth server
    from cybersim.bruteforce.auth_server import AuthServer
    bf_srv = AuthServer(port=9090, logger=logger)
    bf_srv.start()
    servers.append(bf_srv)
    print("  [+] Brute force auth server on :9090")

    # SQLi vulnerable server
    from cybersim.sqli.vulnerable_server import VulnerableSQLServer
    sqli_srv = VulnerableSQLServer(port=8081, logger=logger)
    sqli_srv.start()
    servers.append(sqli_srv)
    print("  [+] SQLi vulnerable server on :8081")

    # XSS vulnerable app
    from cybersim.xss.vulnerable_app import XSSVulnerableServer
    xss_srv = XSSVulnerableServer(port=8082, logger=logger)
    xss_srv.start()
    servers.append(xss_srv)
    print("  [+] XSS vulnerable app on :8082")

    # Phishing server
    from cybersim.phishing.phishing_server import PhishingServer
    phish_srv = PhishingServer(port=8083, logger=logger)
    phish_srv.start()
    servers.append(phish_srv)
    print("  [+] Phishing server on :8083")

    return servers


def _demo_ddos(config, logger):
    """Run DDoS HTTP Flood demo."""
    from cybersim.ddos.http_flood import HTTPFloodAttack
    from cybersim.ddos.detection import DDoSDetector

    ddos_config = get_module_config(config, "ddos")

    # Run attack (reduced for demo)
    attack = HTTPFloodAttack(config=ddos_config.get("http_flood", {}), logger=logger)
    attack.run(target_url="http://127.0.0.1:8080", request_count=100, threads=4)

    # Run detection
    print("  [*] Running detection...")
    detector = DDoSDetector(config=ddos_config.get("detection", {}), logger=logger)
    detector.run(duration=3)

    return {"status": "completed", "type": "HTTP Flood", "requests": 100}


def _demo_sqli(config, logger):
    """Run SQL Injection demo."""
    from cybersim.sqli.injection_attack import SQLInjectionAttack
    from cybersim.sqli.detection import SQLInjectionDetector

    sqli_config = get_module_config(config, "sqli") or {}

    # Run attack
    attack = SQLInjectionAttack(config={"target_url": "http://127.0.0.1:8081"}, logger=logger)
    results = attack.run(target_url="http://127.0.0.1:8081", attack_type="all")

    # Run detection
    print("  [*] Running detection...")
    detector = SQLInjectionDetector(config=sqli_config, logger=logger)
    detector.run(duration=3)

    findings = results.get("findings", []) if results else []
    return {"status": "completed", "successful": results.get("successful", 0) if results else 0,
            "findings": len(findings)}


def _demo_bruteforce(config, logger):
    """Run Brute Force demo (limited attempts)."""
    from cybersim.bruteforce.dictionary_attack import DictionaryAttack
    from cybersim.bruteforce.detection import BruteForceDetector

    bf_config = get_module_config(config, "bruteforce")

    # Run attack with limited attempts
    attack = DictionaryAttack(config=bf_config, logger=logger)
    password = attack.run(
        target_url="http://127.0.0.1:9090/login",
        username="admin",
        max_attempts=10,
        delay_ms=20,
    )

    # Run detection
    print("  [*] Running detection...")
    detector = BruteForceDetector(config=bf_config.get("detection", {}), logger=logger)
    detector.run(duration=3)

    return {"status": "completed", "password_found": password is not None}


def _demo_xss(config, logger):
    """Run XSS demo."""
    from cybersim.xss.xss_attack import XSSAttack
    from cybersim.xss.detection import XSSDetector

    xss_config = get_module_config(config, "xss") or {}

    # Run attack
    attack = XSSAttack(config={"target_url": "http://127.0.0.1:8082"}, logger=logger)
    results = attack.run(target_url="http://127.0.0.1:8082", attack_type="all")

    # Run detection
    print("  [*] Running detection...")
    detector = XSSDetector(config=xss_config, logger=logger)
    detector.run(duration=3)

    findings = results.get("findings", []) if results else []
    return {"status": "completed", "injected": results.get("injected", 0) if results else 0,
            "findings": len(findings)}


def _demo_phishing(config, logger):
    """Run Phishing demo."""
    from cybersim.phishing.campaign import PhishingCampaign
    from cybersim.phishing.detection import PhishingDetector

    # Run campaign
    campaign = PhishingCampaign(config={}, logger=logger)
    result = campaign.run(template="corporate_login", phishing_url="127.0.0.1:8083")

    # Run detection
    print("  [*] Running detection...")
    detector = PhishingDetector(config={}, logger=logger)
    detector.run()

    return {"status": "completed", "emails_sent": result.get("emails_sent", 0) if result else 0}


def _demo_ransomware(config, logger):
    """Run Ransomware demo (sandbox only)."""
    from cybersim.ransomware.detection import RansomwareDetector

    rw_config = get_module_config(config, "ransomware")
    sandbox_dir = Path(rw_config.get("sandbox_dir", "./sandbox/test_files"))

    # Ensure sandbox exists
    if not sandbox_dir.exists():
        try:
            from sandbox.setup_sandbox import setup
            setup()
        except Exception:
            print("  [!] Sandbox not available, skipping ransomware encryption.")
            # Still run detection scan
            detector = RansomwareDetector(config=rw_config, logger=logger)
            if sandbox_dir.exists():
                detector.scan_directory(sandbox_dir)
            return {"status": "skipped", "reason": "no sandbox"}

    # Run encryption (no confirmation in demo mode)
    try:
        from cybersim.ransomware.encryptor import RansomwareSimulator
        encryptor = RansomwareSimulator(config=rw_config, logger=logger)
        enc_result = encryptor.run(sandbox_dir=str(sandbox_dir), confirm=False)
    except Exception as e:
        print(f"  [!] Encryption skipped: {e}")
        enc_result = None

    # Run detection scan
    print("  [*] Running detection scan...")
    detector = RansomwareDetector(config=rw_config, logger=logger)
    scan = detector.scan_directory(sandbox_dir)
    print(f"  [*] Scan: {scan.get('total_files', 0)} files, "
          f"{len(scan.get('encrypted_files', []))} encrypted, "
          f"compromised={scan.get('is_compromised', False)}")

    # Decrypt
    if enc_result and enc_result.get("key_file"):
        try:
            from cybersim.ransomware.decryptor import RansomwareDecryptor
            decryptor = RansomwareDecryptor(config=rw_config, logger=logger)
            decryptor.run(sandbox_dir=str(sandbox_dir))
            print("  [+] Files decrypted successfully.")
        except Exception as e:
            print(f"  [!] Decryption error: {e}")

    encrypted = enc_result.get("encrypted_count", 0) if enc_result else 0
    return {"status": "completed", "encrypted": encrypted, "scan": scan.get("is_compromised", False)}


def _print_final_report(logger, results):
    """Print a formatted final report."""
    summary = generate_summary(logger)

    print(f"""
{G}{BOLD}  ╔══════════════════════════════════════════════════════╗
  ║            DEMO COMPLETE - FINAL REPORT              ║
  ╚══════════════════════════════════════════════════════╝{RST}
  {D}Session:{RST} {C}{summary.get('session_id', 'N/A')}{RST}  {D}|{RST}  Total Events: {BOLD}{summary.get('total_events', 0)}{RST}
""")

    if summary.get("total_events", 0) > 0:
        print(f"  {D}Time:{RST} {summary['time_range']['start']}")
        print(f"  {D}   -> {summary['time_range']['end']}{RST}")

    print(f"\n  {BOLD}Module Results:{RST}")
    print(f"  {D}{'─' * 56}{RST}")

    module_display = [
        ("ddos",       R, "DDoS (HTTP Flood)"),
        ("sqli",       Y, "SQL Injection"),
        ("bruteforce", B, "Brute Force"),
        ("xss",        M, "XSS"),
        ("phishing",   G, "Phishing"),
        ("ransomware", R, "Ransomware"),
    ]

    for key, color, name in module_display:
        r = results.get(key, {})
        status = r.get("status", "not run")
        icon = f"{G}✓{RST}" if status == "completed" else f"{D}–{RST}"
        details = ""
        if key == "ddos":
            details = f"{r.get('requests', 0)} requests"
        elif key == "sqli":
            details = f"{r.get('successful', 0)} payloads, {r.get('findings', 0)} findings"
        elif key == "bruteforce":
            details = "password found" if r.get("password_found") else "limited demo"
        elif key == "xss":
            details = f"{r.get('injected', 0)} injections, {r.get('findings', 0)} findings"
        elif key == "phishing":
            details = f"{r.get('emails_sent', 0)} emails"
        elif key == "ransomware":
            details = f"{r.get('encrypted', 0)} files encrypted"

        print(f"  {icon}  {color}{BOLD}{name:<22}{RST} {D}{details}{RST}")

    print(f"\n  {BOLD}Events by Module:{RST}")
    for mod, count in summary.get("events_by_module", {}).items():
        bar = "█" * min(count, 40)
        print(f"    {C}{mod:<28}{RST} {D}{bar}{RST} {count}")

    print(f"\n  {D}{'═' * 56}{RST}")
