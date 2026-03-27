"""
CyberSim6 - Unified CLI Entry Point
Command-line interface for all attack, defense, and analysis modules.
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Fix Windows terminal encoding
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"

from cybersim.core.config_loader import load_config, get_module_config
from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.reporter import print_summary


# ── ANSI Colors ──
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


BANNER = f"""
{C.BLUE}{C.BOLD}   ██████╗██╗   ██╗██████╗ ███████╗██████╗ {C.RED}███████╗██╗███╗   ███╗ ██████╗
{C.BLUE}  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗{C.RED}██╔════╝██║████╗ ████║██╔════╝
{C.BLUE}  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝{C.RED}███████╗██║██╔████╔██║███████╗
{C.BLUE}  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗{C.RED}╚════██║██║██║╚██╔╝██║██╔═══╝
{C.BLUE}  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║{C.RED}███████║██║██║ ╚═╝ ██║╚██████╗
{C.BLUE}   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝{C.RED}╚══════╝╚═╝╚═╝     ╚═╝ ╚═════╝{C.RESET}
{C.DIM}   ──────────────────────────────────────────────────────────────{C.RESET}
{C.CYAN}   10 Attack & Defense Modules  {C.DIM}|{C.RESET}  {C.GREEN}Detection & Analysis  {C.DIM}|{C.RESET}  {C.YELLOW}Sandbox Only{C.RESET}
{C.DIM}   EMSI Tanger 4IIR  |  Projet Academique 2025-2026{C.RESET}
"""

MODULE_ICONS = {
    "ddos": f"{C.RED}DDoS{C.RESET}",
    "sqli": f"{C.YELLOW}SQLi{C.RESET}",
    "bruteforce": f"{C.BLUE}BruteForce{C.RESET}",
    "xss": f"{C.MAGENTA}XSS{C.RESET}",
    "phishing": f"{C.GREEN}Phishing{C.RESET}",
    "ransomware": f"{C.RED}{C.BOLD}Ransomware{C.RESET}",
    "demo": f"{C.CYAN}Demo{C.RESET}",
    "dashboard": f"{C.CYAN}Dashboard{C.RESET}",
    "logs": f"{C.DIM}Logs{C.RESET}",
    "sandbox": f"{C.DIM}Sandbox{C.RESET}",
    "waf": f"{C.GREEN}{C.BOLD}WAF{C.RESET}",
    "scanner": f"{C.CYAN}Scanner{C.RESET}",
    "honeypot": f"{C.YELLOW}{C.BOLD}Honeypot{C.RESET}",
    "tutorial": f"{C.MAGENTA}Tutorial{C.RESET}",
    "scenario": f"{C.RED}Scenario{C.RESET}",
    "report": f"{C.BLUE}Report{C.RESET}",
    "compliance": f"{C.GREEN}Compliance{C.RESET}",
    "analyze-password": f"{C.YELLOW}Password{C.RESET}",
}


def create_parser():
    parser = argparse.ArgumentParser(
        prog="cybersim",
        description="CyberSim6 - Plateforme de Simulation de Cyberattaques (EDUCATIONAL ONLY)",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    parser.add_argument("--config", type=str, default=None, help="Path to config YAML")

    subparsers = parser.add_subparsers(dest="module", help="Module to run")

    # --- DDoS ---
    ddos_parser = subparsers.add_parser("ddos", help="DDoS simulation module")
    ddos_sub = ddos_parser.add_subparsers(dest="action")

    syn = ddos_sub.add_parser("syn-flood", help="SYN Flood attack")
    syn.add_argument("--target", default="127.0.0.1")
    syn.add_argument("--port", type=int, default=8080)
    syn.add_argument("--count", type=int, default=1000)
    syn.add_argument("--rate", type=int, default=100)

    http = ddos_sub.add_parser("http-flood", help="HTTP Flood attack")
    http.add_argument("--url", default="http://127.0.0.1:8080")
    http.add_argument("--requests", type=int, default=500)
    http.add_argument("--threads", type=int, default=4)

    ddos_sub.add_parser("server", help="Start target HTTP server")
    detect = ddos_sub.add_parser("detect", help="DDoS detection")
    detect.add_argument("--duration", type=int, default=30)

    # --- Brute Force ---
    bf_parser = subparsers.add_parser("bruteforce", help="Brute Force simulation module")
    bf_sub = bf_parser.add_subparsers(dest="action")

    attack = bf_sub.add_parser("attack", help="Dictionary attack")
    attack.add_argument("--url", default="http://127.0.0.1:9090/login")
    attack.add_argument("--username", default="admin")
    attack.add_argument("--wordlist", default=None)
    attack.add_argument("--max-attempts", type=int, default=1000)
    attack.add_argument("--delay", type=int, default=50, help="Delay in ms")

    bf_sub.add_parser("server", help="Start auth server")
    bf_detect = bf_sub.add_parser("detect", help="Brute force detection")
    bf_detect.add_argument("--duration", type=int, default=60)

    # --- SQL Injection ---
    sqli_parser = subparsers.add_parser("sqli", help="SQL Injection simulation module")
    sqli_sub = sqli_parser.add_subparsers(dest="action")

    sqli_sub.add_parser("server", help="Start vulnerable SQL server")
    sqli_attack = sqli_sub.add_parser("attack", help="Run SQL injection attacks")
    sqli_attack.add_argument("--url", default="http://127.0.0.1:8081")
    sqli_attack.add_argument("--type", choices=["auth_bypass", "union_based", "error_based", "blind_boolean", "all"],
                             default="all", dest="attack_type")

    sqli_detect = sqli_sub.add_parser("detect", help="SQL injection detection")
    sqli_detect.add_argument("--duration", type=int, default=30)

    # --- XSS ---
    xss_parser = subparsers.add_parser("xss", help="XSS simulation module")
    xss_sub = xss_parser.add_subparsers(dest="action")

    xss_sub.add_parser("server", help="Start vulnerable XSS app")
    xss_attack = xss_sub.add_parser("attack", help="Run XSS attacks")
    xss_attack.add_argument("--url", default="http://127.0.0.1:8082")
    xss_attack.add_argument("--type", choices=["reflected", "stored", "dom", "all"],
                            default="all", dest="attack_type")

    xss_detect = xss_sub.add_parser("detect", help="XSS detection")
    xss_detect.add_argument("--duration", type=int, default=30)

    # --- Phishing ---
    phish_parser = subparsers.add_parser("phishing", help="Phishing simulation module")
    phish_sub = phish_parser.add_subparsers(dest="action")

    phish_server = phish_sub.add_parser("server", help="Start phishing server")
    phish_server.add_argument("--template", choices=["corporate_login", "password_reset", "office365"],
                              default="corporate_login")
    phish_server.add_argument("--port", type=int, default=8083)

    phish_campaign = phish_sub.add_parser("campaign", help="Run phishing campaign simulation")
    phish_campaign.add_argument("--template", default="corporate_login")
    phish_campaign.add_argument("--phishing-url", default="127.0.0.1:8083")

    phish_sub.add_parser("detect", help="Analyze phishing indicators")
    phish_sub.add_parser("templates", help="List available phishing templates")

    # --- Ransomware ---
    rw_parser = subparsers.add_parser("ransomware", help="Ransomware simulation module")
    rw_sub = rw_parser.add_subparsers(dest="action")

    encrypt = rw_sub.add_parser("encrypt", help="Encrypt files in sandbox")
    encrypt.add_argument("--sandbox", default="./sandbox/test_files")
    encrypt.add_argument("--no-confirm", action="store_true")

    decrypt = rw_sub.add_parser("decrypt", help="Decrypt files in sandbox")
    decrypt.add_argument("--sandbox", default="./sandbox/test_files")
    decrypt.add_argument("--keyfile", default=None)

    rw_detect = rw_sub.add_parser("detect", help="Ransomware detection")
    rw_detect.add_argument("--watch", default="./sandbox/test_files")
    rw_detect.add_argument("--duration", type=int, default=60)

    rw_sub.add_parser("scan", help="One-time scan for ransomware indicators")

    # --- WAF ---
    waf_parser = subparsers.add_parser("waf", help="Start the Web Application Firewall")
    waf_parser.add_argument("--port", type=int, default=8877, help="WAF listening port")
    waf_parser.add_argument("--backend-port", type=int, default=8080, help="Backend server port")

    # --- Scanner ---
    scanner_parser = subparsers.add_parser("scanner", help="Run the port scanner")
    scanner_parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    scanner_parser.add_argument("--ports", default="common", choices=["common", "quick", "1-1024"],
                                help="Port range to scan")
    scanner_parser.add_argument("--threads", type=int, default=50, help="Number of threads")

    # --- Honeypot ---
    honeypot_parser = subparsers.add_parser("honeypot", help="Start the honeypot server")
    honeypot_parser.add_argument("--port", type=int, default=9090, help="Honeypot listening port")

    # --- Tutorial ---
    tutorial_parser = subparsers.add_parser("tutorial", help="Start interactive tutorial")
    tutorial_parser.add_argument(
        "--module",
        dest="tutorial_module",
        default=None,
        help="Tutorial module (omit to list all)",
    )

    # --- Scenario ---
    scenario_parser = subparsers.add_parser("scenario", help="Run APT attack scenarios")
    scenario_parser.add_argument("--name", default=None, help="Scenario name (omit to list all)")
    scenario_parser.add_argument("--all", action="store_true", dest="run_all",
                                 help="Run all scenarios")

    # --- Report ---
    report_parser = subparsers.add_parser("report", help="Generate HTML security report")
    report_parser.add_argument("--session", required=True, help="Session ID to report on")
    report_parser.add_argument("--output", default=None, help="Output file path")

    # --- Compliance ---
    compliance_parser = subparsers.add_parser("compliance", help="Run compliance check")
    compliance_parser.add_argument("--framework", choices=["iso27001", "nist", "rgpd", "all"],
                                   default="all", help="Compliance framework")
    compliance_parser.add_argument("--session", default=None, help="Session ID to analyze")

    # --- Analyze Password ---
    pw_parser = subparsers.add_parser("analyze-password", help="Analyze password strength")
    pw_parser.add_argument("--password", required=True, help="Password to analyze")

    # --- Demo ---
    demo_parser = subparsers.add_parser("demo", help="Run automated demo of all 6 modules")
    demo_parser.add_argument("--no-dashboard", action="store_true", help="Disable web dashboard")

    # --- Dashboard ---
    dash_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dash_parser.add_argument("--port", type=int, default=8888, help="Dashboard port")

    # --- Logs ---
    logs_parser = subparsers.add_parser("logs", help="Log management")
    logs_sub = logs_parser.add_subparsers(dest="action")

    export = logs_sub.add_parser("export", help="Export logs")
    export.add_argument("--format", choices=["json", "csv"], default="json")
    export.add_argument("--output", default=None)

    # --- Sandbox ---
    sandbox_parser = subparsers.add_parser("sandbox", help="Sandbox management")
    sandbox_sub = sandbox_parser.add_subparsers(dest="action")
    sandbox_sub.add_parser("setup", help="Setup sandbox environment")
    sandbox_sub.add_parser("clean", help="Clean sandbox files")

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.module:
        print(BANNER)
        parser.print_help()
        return

    # Load config
    config = load_config(args.config)
    logger = CyberSimLogger(log_dir=Path(config["general"]["log_dir"]))

    module_name = MODULE_ICONS.get(args.module, args.module)
    action = getattr(args, 'action', 'N/A')
    print(f"\n  {C.BOLD}{C.BLUE}CyberSim6{C.RESET} {C.DIM}|{C.RESET} Session: {C.CYAN}{logger.session_id}{C.RESET} {C.DIM}|{C.RESET} {module_name} {C.DIM}>{C.RESET} {action}\n")

    try:
        if args.module == "ddos":
            _handle_ddos(args, config, logger)
        elif args.module == "bruteforce":
            _handle_bruteforce(args, config, logger)
        elif args.module == "sqli":
            _handle_sqli(args, config, logger)
        elif args.module == "xss":
            _handle_xss(args, config, logger)
        elif args.module == "phishing":
            _handle_phishing(args, config, logger)
        elif args.module == "ransomware":
            _handle_ransomware(args, config, logger)
        elif args.module == "demo":
            _handle_demo(args, config, logger)
        elif args.module == "dashboard":
            _handle_dashboard(args, config, logger)
        elif args.module == "waf":
            _handle_waf(args, config, logger)
        elif args.module == "scanner":
            _handle_scanner(args, config, logger)
        elif args.module == "honeypot":
            _handle_honeypot(args, config, logger)
        elif args.module == "tutorial":
            _handle_tutorial(args, config, logger)
        elif args.module == "scenario":
            _handle_scenario(args, config, logger)
        elif args.module == "report":
            _handle_report(args, config, logger)
        elif args.module == "compliance":
            _handle_compliance(args, config, logger)
        elif args.module == "analyze-password":
            _handle_password(args, config, logger)
        elif args.module == "logs":
            _handle_logs(args, config, logger)
        elif args.module == "sandbox":
            _handle_sandbox(args)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"\n[ERROR] {e}")
    finally:
        if logger.events:
            print_summary(logger)
            export_path = logger.export_json()
            print(f"[+] Logs saved to: {export_path}")


def _handle_ddos(args, config, logger):
    ddos_config = get_module_config(config, "ddos")
    if args.action == "server":
        from cybersim.ddos.target_server import TargetServer
        server = TargetServer(port=8080, logger=logger)
        server.start()
        _wait_forever()
        server.stop()
    elif args.action == "syn-flood":
        from cybersim.ddos.syn_flood import SYNFloodAttack
        attack = SYNFloodAttack(config=ddos_config.get("syn_flood", {}), logger=logger)
        attack.run(target=args.target, port=args.port, packet_count=args.count, rate_limit=args.rate)
    elif args.action == "http-flood":
        from cybersim.ddos.http_flood import HTTPFloodAttack
        attack = HTTPFloodAttack(config=ddos_config.get("http_flood", {}), logger=logger)
        attack.run(target_url=args.url, request_count=args.requests, threads=args.threads)
    elif args.action == "detect":
        from cybersim.ddos.detection import DDoSDetector
        detector = DDoSDetector(config=ddos_config.get("detection", {}), logger=logger)
        detector.run(duration=args.duration)


def _handle_bruteforce(args, config, logger):
    bf_config = get_module_config(config, "bruteforce")
    if args.action == "server":
        from cybersim.bruteforce.auth_server import AuthServer
        server = AuthServer(port=9090, logger=logger)
        server.start()
        _wait_forever()
        server.stop()
    elif args.action == "attack":
        from cybersim.bruteforce.dictionary_attack import DictionaryAttack
        attack = DictionaryAttack(config=bf_config, logger=logger)
        attack.run(target_url=args.url, username=args.username, wordlist=args.wordlist,
                   max_attempts=args.max_attempts, delay_ms=args.delay)
    elif args.action == "detect":
        from cybersim.bruteforce.detection import BruteForceDetector
        detector = BruteForceDetector(config=bf_config.get("detection", {}), logger=logger)
        detector.run(duration=args.duration)


def _handle_sqli(args, config, logger):
    sqli_config = get_module_config(config, "sqli") or {}
    if args.action == "server":
        from cybersim.sqli.vulnerable_server import VulnerableSQLServer
        server = VulnerableSQLServer(port=8081, logger=logger)
        server.start()
        _wait_forever()
        server.stop()
    elif args.action == "attack":
        from cybersim.sqli.injection_attack import SQLInjectionAttack
        attack = SQLInjectionAttack(config={"target_url": args.url}, logger=logger)
        results = attack.run(target_url=args.url, attack_type=args.attack_type)
        if results:
            print(f"\n  SQLi Results: {results['successful']}/{results['total']} payloads successful")
            print(f"  Findings: {len(results['findings'])}")
            for f in results["findings"]:
                print(f"    [{f['type']}] {f.get('description', '')} | Endpoint: {f.get('endpoint', '')}")
    elif args.action == "detect":
        from cybersim.sqli.detection import SQLInjectionDetector
        detector = SQLInjectionDetector(config=sqli_config, logger=logger)
        detector.run(duration=args.duration)


def _handle_xss(args, config, logger):
    xss_config = get_module_config(config, "xss") or {}
    if args.action == "server":
        from cybersim.xss.vulnerable_app import XSSVulnerableServer
        server = XSSVulnerableServer(port=8082, logger=logger)
        server.start()
        _wait_forever()
        server.stop()
    elif args.action == "attack":
        from cybersim.xss.xss_attack import XSSAttack
        attack = XSSAttack(config={"target_url": args.url}, logger=logger)
        results = attack.run(target_url=args.url, attack_type=args.attack_type)
        if results:
            print(f"\n  XSS Results: {results['injected']}/{results['total']} payloads injected")
            print(f"  Findings: {len(results['findings'])}")
            for f in results["findings"]:
                print(f"    [{f['type']}] {f.get('description', '')} | Endpoint: {f.get('endpoint', '')}")
    elif args.action == "detect":
        from cybersim.xss.detection import XSSDetector
        detector = XSSDetector(config=xss_config, logger=logger)
        detector.run(duration=args.duration)


def _handle_phishing(args, config, logger):
    if args.action == "server":
        from cybersim.phishing.phishing_server import PhishingServer
        server = PhishingServer(port=args.port, template=args.template, logger=logger)
        server.start()
        _wait_forever()
        server.stop()
    elif args.action == "campaign":
        from cybersim.phishing.campaign import PhishingCampaign
        campaign = PhishingCampaign(config={}, logger=logger)
        campaign.run(template=args.template, phishing_url=args.phishing_url)
    elif args.action == "detect":
        from cybersim.phishing.detection import PhishingDetector
        detector = PhishingDetector(config={}, logger=logger)
        results = detector.run()
        if results:
            print("\n  Phishing Template Analysis:")
            for r in results:
                print(f"    [{r['template']}] Risk: {r['risk_level']} (score: {r['risk_score']}) "
                      f"| {r['findings_count']} indicators")
    elif args.action == "templates":
        from cybersim.phishing.phishing_server import PhishingServer
        templates = PhishingServer.list_templates()
        print("\n  Available phishing templates:")
        for key, name in templates.items():
            print(f"    - {key}: {name}")


def _handle_ransomware(args, config, logger):
    rw_config = get_module_config(config, "ransomware")
    if args.action == "encrypt":
        from cybersim.ransomware.encryptor import RansomwareSimulator
        sim = RansomwareSimulator(config=rw_config, logger=logger)
        sim.run(sandbox_dir=args.sandbox, confirm=not args.no_confirm)
    elif args.action == "decrypt":
        from cybersim.ransomware.decryptor import RansomwareDecryptor
        dec = RansomwareDecryptor(config=rw_config, logger=logger)
        dec.run(sandbox_dir=args.sandbox, key_file=args.keyfile)
    elif args.action == "detect":
        from cybersim.ransomware.detection import RansomwareDetector
        detector = RansomwareDetector(config=rw_config, logger=logger)
        detector.run(watch_dir=args.watch, duration=args.duration)
    elif args.action == "scan":
        from cybersim.ransomware.detection import RansomwareDetector
        detector = RansomwareDetector(config=rw_config, logger=logger)
        sandbox = rw_config.get("sandbox_dir", "./sandbox/test_files")
        results = detector.scan_directory(Path(sandbox))
        print(f"\n  Scan Results for: {sandbox}")
        print(f"  Total files: {results['total_files']}")
        print(f"  Encrypted files: {len(results['encrypted_files'])}")
        print(f"  High entropy files: {len(results['high_entropy_files'])}")
        print(f"  Ransom notes: {results['ransom_notes']}")
        print(f"  Compromised: {'YES' if results['is_compromised'] else 'NO'}")


def _handle_demo(args, config, logger):
    from cybersim.demo import run_demo
    run_demo(config_path=args.config, with_dashboard=not args.no_dashboard)


def _handle_dashboard(args, config, logger):
    from cybersim.dashboard.server import Dashboard
    dashboard = Dashboard(port=args.port, logger=logger)
    dashboard.start()
    _wait_forever()
    dashboard.stop()


def _handle_waf(args, config, logger):
    from cybersim.waf.firewall import WebApplicationFirewall, WAFServer

    backend_url = f"http://127.0.0.1:{args.backend_port}"
    waf = WebApplicationFirewall(logger=logger)
    server = WAFServer(("127.0.0.1", args.port), waf, backend_url=backend_url)
    server.start()
    print(f"[*] Backend origin: {backend_url}")
    _wait_forever()
    server.shutdown()
    server.server_close()


def _handle_scanner(args, config, logger):
    from cybersim.scanner.port_scanner import PortScanner

    scanner = PortScanner(config={"target": args.target, "threads": args.threads}, logger=logger)
    if args.ports == "common":
        results = scanner.scan_common()
    elif args.ports == "quick":
        results = scanner.quick_scan()
    else:
        results = scanner.scan_range(1, 1024, threads=args.threads)

    open_ports = [result for result in results if result.state == "open"]
    print(f"[*] Scan complete: {len(results)} ports scanned, {len(open_ports)} open")
    for result in open_ports:
        banner = f" | Banner: {result.banner}" if result.banner else ""
        service = result.service or "unknown"
        print(f"  - {result.port}/tcp open ({service}){banner}")


def _handle_honeypot(args, config, logger):
    from cybersim.honeypot.honeypot import HoneypotServer

    server = HoneypotServer(logger=logger, port=args.port)
    server.start()
    _wait_forever()
    server.stop()


def _handle_tutorial(args, config, logger):
    from cybersim.tutorial.interactive import InteractiveTutorial

    tutorial = InteractiveTutorial(logger=logger)
    if args.tutorial_module:
        tutorial.start_tutorial(args.tutorial_module)
        return

    print("  Available tutorials:")
    for module in tutorial.list_modules():
        print(
            f"    - {module['key']}: {module['name']} "
            f"({module['difficulty']}, {module['estimated_time']})"
        )


def _handle_scenario(args, config, logger):
    from cybersim.scenarios.attack_chain import ScenarioRunner

    runner = ScenarioRunner(logger)
    if args.run_all:
        results = runner.run_all()
        print(f"[*] Executed {len(results)} scenarios.")
        for result in results:
            print(
                f"  - {result.scenario_name}: "
                f"{result.steps_completed}/{result.steps_total} steps, "
                f"success={result.success}"
            )
        return

    if args.name:
        result = runner.run_scenario(args.name)
        print(
            f"[*] {result.scenario_name}: "
            f"{result.steps_completed}/{result.steps_total} steps, "
            f"duration={result.duration_seconds}s"
        )
        return

    print("  Available scenarios:")
    for scenario in runner.list_scenarios():
        print(
            f"    - {scenario['key']}: {scenario['name']} "
            f"({scenario['difficulty']}, {scenario['steps']} steps)"
        )


def _handle_report(args, config, logger):
    from cybersim.core.pdf_report import ReportGenerator

    session_logger = _load_session_logger(args.session, config)
    report = ReportGenerator(session_logger, session_id=args.session)
    path = report.generate(output_path=args.output)
    print(f"[+] Report generated: {path}")


def _handle_compliance(args, config, logger):
    from cybersim.core.compliance import ComplianceChecker

    source_logger = _load_session_logger(args.session, config) if args.session else logger
    if not source_logger.events:
        raise ValueError("No events available. Use --session to analyze a saved session.")

    checker = ComplianceChecker(logger=logger)
    if args.framework == "iso27001":
        reports = [checker.check_iso27001(source_logger.events)]
    elif args.framework == "nist":
        reports = [checker.check_nist(source_logger.events)]
    elif args.framework == "rgpd":
        reports = [checker.check_rgpd(source_logger.events)]
    else:
        reports = checker.check_all(source_logger.events)

    print(checker.generate_summary(reports))


def _handle_password(args, config, logger):
    from cybersim.utils.password_analyzer import PasswordAnalyzer

    analysis = PasswordAnalyzer().analyze(args.password)
    print(f"  Strength: {analysis.strength} ({analysis.score}/100)")
    print(f"  Entropy : {analysis.entropy_bits} bits")
    print(f"  Crack   : {analysis.crack_time_display}")
    print(f"  Patterns: {', '.join(analysis.patterns_found) if analysis.patterns_found else 'none'}")
    print("  Recommendations:")
    for recommendation in analysis.recommendations:
        print(f"    - {recommendation}")


def _handle_logs(args, config, logger):
    if args.action == "export":
        fmt = args.format
        output = args.output
        if fmt == "json":
            path = logger.export_json(Path(output) if output else None)
        else:
            path = logger.export_csv(Path(output) if output else None)
        print(f"[+] Logs exported to: {path}")


def _handle_sandbox(args):
    from sandbox.setup_sandbox import setup, clean
    if args.action == "setup":
        setup()
    elif args.action == "clean":
        clean()


def _load_session_logger(session_id, config):
    """Load a previously exported session log into a logger instance."""
    log_dir = Path(config["general"]["log_dir"])
    session_path = log_dir / f"session_{session_id}.json"
    if not session_path.exists():
        raise FileNotFoundError(f"Session log not found: {session_path}")

    with open(session_path, "r", encoding="utf-8") as handle:
        events = json.load(handle)

    session_logger = CyberSimLogger(log_dir=log_dir, session_id=session_id)
    session_logger.events = events
    return session_logger


def _wait_forever():
    """Wait until Ctrl+C."""
    import time
    print("[*] Press Ctrl+C to stop...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
