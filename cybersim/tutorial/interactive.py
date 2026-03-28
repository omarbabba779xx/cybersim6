"""
Interactive Tutorial Mode -- Step-by-step guided learning for each attack module.

Explains concepts, shows attacks in action, asks quiz questions, and provides
educational context about MITRE ATT&CK, CVEs, and defense strategies.

Each module walks through four phases:
    1. Theory   -- what the attack is and how it works
    2. Live Demo -- execute the attack in a sandboxed environment
    3. Detection -- how the detector identifies the attack
    4. Defense   -- recommended countermeasures and hardening

References used throughout:
    - MITRE ATT&CK Framework  (https://attack.mitre.org/)
    - OWASP Top 10            (https://owasp.org/www-project-top-ten/)
    - NIST Cybersecurity Framework (https://www.nist.gov/cyberframework)
    - CVE Database             (https://cve.mitre.org/)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

class _Colours:
    """ANSI escape sequences for terminal styling."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    MAGENTA = "\033[95m"

    # Compound styles
    HEADER = f"{BOLD}{CYAN}"
    INFO = WHITE
    WARNING = f"{BOLD}{YELLOW}"
    ATTACK = f"{BOLD}{RED}"
    DEFENSE = f"{BOLD}{GREEN}"
    QUIZ = f"{BOLD}{MAGENTA}"
    STEP = f"{BOLD}{BLUE}"
    SUCCESS = f"{BOLD}{GREEN}"


_C = _Colours


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TutorialStep:
    """A single step inside a tutorial module."""

    title: str
    explanation: str
    action: str
    mitre_technique: str
    defense_tip: str
    quiz_question: str
    quiz_answer: str


@dataclass
class TutorialModule:
    """A complete tutorial covering one attack type."""

    name: str
    description: str
    difficulty: str          # beginner | intermediate | advanced
    estimated_time: str      # human-readable, e.g. "5 minutes"
    steps: list[TutorialStep]
    prerequisites: list[str] = field(default_factory=list)


@dataclass
class TutorialResult:
    """Outcome returned after a tutorial session finishes."""

    module_name: str
    steps_completed: int
    quiz_score: int
    quiz_total: int
    duration_seconds: float


# ---------------------------------------------------------------------------
# Module catalogue -- six built-in tutorials
# ---------------------------------------------------------------------------

_DDOS_MODULE = TutorialModule(
    name="DDoS Attack & Defense",
    description=(
        "Learn how Distributed Denial of Service attacks work, "
        "how to detect volumetric floods, and proven mitigation strategies."
    ),
    difficulty="beginner",
    estimated_time="5 minutes",
    prerequisites=[],
    steps=[
        TutorialStep(
            title="Theory -- What is a DDoS Attack?",
            explanation=(
                "A Distributed Denial of Service (DDoS) attack overwhelms a "
                "target server or network with a massive volume of traffic so "
                "that legitimate users cannot access the service. Attackers "
                "typically use botnets -- networks of compromised machines -- "
                "to generate the flood. Common variants include SYN floods "
                "(layer 4) and HTTP floods (layer 7). Historical example: "
                "the 2016 Dyn DNS attack (Mirai botnet) disrupted Twitter, "
                "Netflix, and Reddit."
            ),
            action="No action -- this is a theory step.",
            mitre_technique="T1498 - Network Denial of Service",
            defense_tip=(
                "Deploy rate limiting at the edge, use a CDN / scrubbing "
                "service, and implement SYN cookies on the OS level."
            ),
            quiz_question="What is the main goal of a DDoS attack?",
            quiz_answer=(
                "To make a service unavailable by overwhelming it with traffic"
            ),
        ),
        TutorialStep(
            title="Live Demo -- HTTP Flood Simulation",
            explanation=(
                "We will simulate an HTTP flood by sending a burst of rapid "
                "requests to a local target server. This models a layer-7 "
                "DDoS attack where each request is individually valid but "
                "the aggregate volume exhausts server resources."
            ),
            action=(
                "Sending 100 concurrent HTTP GET requests to the local "
                "target server on 127.0.0.1."
            ),
            mitre_technique="T1498.001 - Direct Network Flood",
            defense_tip=(
                "Configure connection-rate limits per IP. Tools: iptables "
                "rate-limit rules, nginx limit_req_zone, AWS Shield."
            ),
            quiz_question=(
                "Which OSI layer does an HTTP flood attack target?"
            ),
            quiz_answer="Layer 7 (Application layer)",
        ),
        TutorialStep(
            title="Detection -- Identifying the Flood",
            explanation=(
                "CyberSim6's DDoS detector tracks requests per second (RPS) "
                "within a sliding window. When the RPS exceeds a configured "
                "threshold the detector raises an alert. Real-world systems "
                "use similar heuristics combined with machine-learning "
                "anomaly detection (e.g. NetFlow analysis)."
            ),
            action=(
                "Running the DDoS detector against the recorded traffic to "
                "show how the threshold triggers an alert."
            ),
            mitre_technique="T1498 - Network Denial of Service",
            defense_tip=(
                "NIST SP 800-61r2 recommends having an incident response "
                "plan that includes ISP coordination and traffic diversion."
            ),
            quiz_question=(
                "What metric does a simple DDoS detector typically monitor?"
            ),
            quiz_answer="Requests per second (RPS) within a time window",
        ),
        TutorialStep(
            title="Defense -- Hardening Your Infrastructure",
            explanation=(
                "Effective DDoS mitigation is layered: (1) network-level "
                "filtering with BCP38 / ingress filtering, (2) rate limiting "
                "at load balancers, (3) CDN / scrubbing services like "
                "Cloudflare or AWS Shield, and (4) auto-scaling to absorb "
                "spikes. NIST CSF Protect (PR.PT-4) covers resilient "
                "communications and network segmentation."
            ),
            action="No action -- review and discussion step.",
            mitre_technique="T1498 - Network Denial of Service",
            defense_tip=(
                "Combine on-premise rate limiting with cloud-based DDoS "
                "protection. Test your plan regularly with red-team exercises."
            ),
            quiz_question=(
                "Name one cloud service that provides DDoS scrubbing."
            ),
            quiz_answer=(
                "AWS Shield, Cloudflare, Akamai Prolexic, or Azure DDoS "
                "Protection (any one is correct)"
            ),
        ),
    ],
)

_SQLI_MODULE = TutorialModule(
    name="SQL Injection Attack & Defense",
    description=(
        "Understand SQL injection, one of the OWASP Top 10 vulnerabilities, "
        "and learn how parameterised queries prevent it."
    ),
    difficulty="beginner",
    estimated_time="6 minutes",
    prerequisites=[],
    steps=[
        TutorialStep(
            title="Theory -- What is SQL Injection?",
            explanation=(
                "SQL Injection (SQLi) occurs when user-supplied input is "
                "concatenated directly into an SQL query without sanitisation. "
                "Attackers craft malicious input like ' OR '1'='1 to alter "
                "query logic. SQLi is ranked #3 in the OWASP Top 10 (2021, "
                "A03:2021 Injection). Notable CVE: CVE-2019-9193 allowed "
                "arbitrary command execution in PostgreSQL via SQLi."
            ),
            action="No action -- this is a theory step.",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            defense_tip=(
                "Always use parameterised queries / prepared statements. "
                "Never concatenate user input into SQL strings."
            ),
            quiz_question="What OWASP Top 10 category covers SQL Injection?",
            quiz_answer="A03:2021 -- Injection",
        ),
        TutorialStep(
            title="Live Demo -- Extracting Data via SQLi",
            explanation=(
                "We will demonstrate a classic UNION-based SQLi against a "
                "vulnerable login form. The payload manipulates the WHERE "
                "clause so the query always returns true, bypassing "
                "authentication entirely."
            ),
            action=(
                "Injecting a UNION SELECT payload into the simulated login "
                "endpoint to bypass authentication."
            ),
            mitre_technique="T1190 - Exploit Public-Facing Application",
            defense_tip=(
                "Use an ORM or query builder that enforces parameterisation. "
                "Apply the principle of least privilege to database accounts."
            ),
            quiz_question=(
                "What SQL keyword lets an attacker append extra query results?"
            ),
            quiz_answer="UNION",
        ),
        TutorialStep(
            title="Detection -- WAF Rule Matching",
            explanation=(
                "CyberSim6's Web Application Firewall (WAF) inspects inbound "
                "requests for SQLi signatures such as single quotes, UNION "
                "SELECT, OR 1=1, and comment sequences (-- or #). Real WAFs "
                "like ModSecurity use the OWASP Core Rule Set (CRS) for "
                "pattern matching."
            ),
            action=(
                "Running the WAF detection engine against the injected "
                "payloads to show matched rules."
            ),
            mitre_technique="T1190 - Exploit Public-Facing Application",
            defense_tip=(
                "Deploy a WAF with the OWASP Core Rule Set in front of all "
                "web applications. Log and review blocked requests."
            ),
            quiz_question="What open-source WAF rule set detects SQLi patterns?",
            quiz_answer="OWASP Core Rule Set (CRS)",
        ),
        TutorialStep(
            title="Defense -- Secure Coding Practices",
            explanation=(
                "Prevention is better than detection. Use parameterised "
                "queries in every database call. Apply input validation "
                "with allowlists (not blocklists). Employ stored procedures "
                "where appropriate. NIST SP 800-53 SI-10 (Information Input "
                "Validation) and SI-16 (Memory Protection) provide guidance."
            ),
            action="No action -- review and discussion step.",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            defense_tip=(
                "Integrate SAST tools (e.g. Semgrep, SonarQube) into CI/CD "
                "to catch SQLi vulnerabilities before deployment."
            ),
            quiz_question=(
                "What is the most effective defence against SQL injection?"
            ),
            quiz_answer="Using parameterised queries / prepared statements",
        ),
    ],
)

_XSS_MODULE = TutorialModule(
    name="Cross-Site Scripting (XSS) Attack & Defense",
    description=(
        "Explore how XSS attacks inject malicious scripts into web pages "
        "and how Content Security Policy prevents execution."
    ),
    difficulty="intermediate",
    estimated_time="6 minutes",
    prerequisites=["sqli"],
    steps=[
        TutorialStep(
            title="Theory -- What is XSS?",
            explanation=(
                "Cross-Site Scripting (XSS) lets attackers inject client-side "
                "scripts into web pages viewed by other users. There are "
                "three types: Reflected (type 1), Stored (type 2), and "
                "DOM-based. XSS is OWASP A03:2021 (Injection). CVE-2020-11022 "
                "was a jQuery XSS vulnerability affecting millions of sites."
            ),
            action="No action -- this is a theory step.",
            mitre_technique="T1059.007 - JavaScript",
            defense_tip=(
                "Encode all output, use Content Security Policy (CSP) "
                "headers, and sanitise HTML with libraries like DOMPurify."
            ),
            quiz_question="Name the three types of XSS.",
            quiz_answer="Reflected, Stored, and DOM-based",
        ),
        TutorialStep(
            title="Live Demo -- Reflected XSS Payload",
            explanation=(
                "We will inject a <script>alert('XSS')</script> payload into "
                "a search parameter. The vulnerable application reflects the "
                "input directly in the HTML response without encoding, "
                "causing the browser to execute the script."
            ),
            action=(
                "Sending a crafted request with a script tag in the query "
                "parameter to the vulnerable endpoint."
            ),
            mitre_technique="T1059.007 - JavaScript",
            defense_tip=(
                "Apply context-aware output encoding: HTML-encode for HTML "
                "context, JS-encode for JavaScript context, URL-encode for "
                "URL parameters."
            ),
            quiz_question="What HTML tag is most commonly used in XSS payloads?",
            quiz_answer="<script>",
        ),
        TutorialStep(
            title="Detection -- XSS Pattern Analysis",
            explanation=(
                "The CyberSim6 WAF detects XSS by scanning for patterns "
                "like <script>, javascript:, on-event handlers (onerror, "
                "onload), and encoded variants (%3Cscript%3E). Advanced "
                "detectors also analyse DOM mutations and CSP violation "
                "reports."
            ),
            action=(
                "Running the XSS detection engine against various payloads "
                "including encoded and obfuscated variants."
            ),
            mitre_technique="T1059.007 - JavaScript",
            defense_tip=(
                "Enable CSP reporting (Content-Security-Policy-Report-Only) "
                "to discover XSS attempts without breaking functionality."
            ),
            quiz_question=(
                "What HTTP header helps prevent XSS execution in browsers?"
            ),
            quiz_answer="Content-Security-Policy (CSP)",
        ),
    ],
)

_BRUTEFORCE_MODULE = TutorialModule(
    name="Brute Force Attack & Defense",
    description=(
        "Learn how credential brute-force attacks work, how account lockout "
        "policies defend against them, and why password hashing matters."
    ),
    difficulty="beginner",
    estimated_time="5 minutes",
    prerequisites=[],
    steps=[
        TutorialStep(
            title="Theory -- What is a Brute Force Attack?",
            explanation=(
                "A brute force attack systematically tries every possible "
                "password (or a dictionary of common passwords) until the "
                "correct one is found. Credential stuffing is a variant that "
                "reuses leaked username/password pairs from data breaches. "
                "CVE-2021-29441 (Nacos) allowed brute-force bypass of "
                "authentication due to missing rate limiting."
            ),
            action="No action -- this is a theory step.",
            mitre_technique="T1110 - Brute Force",
            defense_tip=(
                "Enforce account lockout after N failed attempts, use "
                "multi-factor authentication (MFA), and require strong "
                "passwords (NIST SP 800-63B)."
            ),
            quiz_question=(
                "What is the difference between brute force and credential "
                "stuffing?"
            ),
            quiz_answer=(
                "Brute force tries all combinations; credential stuffing "
                "reuses leaked credentials from other breaches"
            ),
        ),
        TutorialStep(
            title="Live Demo -- Dictionary Attack Simulation",
            explanation=(
                "We will attempt to log in using a list of the top 100 most "
                "common passwords (rockyou-style). This demonstrates how "
                "quickly weak passwords can be compromised."
            ),
            action=(
                "Trying 100 common passwords against the simulated SSH "
                "login service."
            ),
            mitre_technique="T1110.001 - Password Guessing",
            defense_tip=(
                "Block the top 100k breached passwords. Use bcrypt or "
                "Argon2id for password hashing with a cost factor >= 12."
            ),
            quiz_question="What password hashing algorithm is recommended by OWASP?",
            quiz_answer="bcrypt or Argon2id",
        ),
        TutorialStep(
            title="Detection -- Login Anomaly Detection",
            explanation=(
                "CyberSim6 detects brute force by tracking failed login "
                "attempts per IP and per account. When the failure rate "
                "exceeds a threshold within a time window, an alert fires. "
                "Enterprise SIEMs correlate login events across systems for "
                "distributed attacks."
            ),
            action=(
                "Analysing the login attempt logs to show how the threshold "
                "detector identifies the attack."
            ),
            mitre_technique="T1110 - Brute Force",
            defense_tip=(
                "Implement progressive delays (exponential backoff) on "
                "failed logins to slow automated attacks."
            ),
            quiz_question=(
                "What NIST publication provides password policy guidance?"
            ),
            quiz_answer="NIST SP 800-63B (Digital Identity Guidelines)",
        ),
        TutorialStep(
            title="Defense -- Strong Authentication",
            explanation=(
                "Layer your defences: (1) enforce minimum password length of "
                "12+ characters, (2) check against breached-password lists, "
                "(3) deploy MFA (TOTP, FIDO2/WebAuthn), (4) use CAPTCHA "
                "after 3 failed attempts, and (5) monitor for credential "
                "stuffing with threat intelligence feeds. NIST CSF Protect "
                "(PR.AC) covers identity management and access control."
            ),
            action="No action -- review and discussion step.",
            mitre_technique="T1110 - Brute Force",
            defense_tip=(
                "FIDO2/WebAuthn eliminates password-based attacks entirely. "
                "Consider passwordless authentication for high-value accounts."
            ),
            quiz_question="What does MFA stand for and why is it important?",
            quiz_answer=(
                "Multi-Factor Authentication -- it requires two or more "
                "verification factors, making stolen passwords alone "
                "insufficient for access"
            ),
        ),
    ],
)

_PHISHING_MODULE = TutorialModule(
    name="Phishing Attack & Defense",
    description=(
        "Understand social engineering through phishing, learn to analyse "
        "suspicious emails, and build user-awareness defences."
    ),
    difficulty="intermediate",
    estimated_time="6 minutes",
    prerequisites=[],
    steps=[
        TutorialStep(
            title="Theory -- What is Phishing?",
            explanation=(
                "Phishing is a social-engineering attack that uses "
                "fraudulent emails, messages, or websites to trick victims "
                "into revealing credentials or installing malware. Spear "
                "phishing targets specific individuals using personal "
                "information. The 2020 Twitter hack (CVE-less, but widely "
                "documented) began with phone-based spear phishing of "
                "employees. MITRE classifies this under Initial Access."
            ),
            action="No action -- this is a theory step.",
            mitre_technique="T1566 - Phishing",
            defense_tip=(
                "Train users to inspect sender addresses, hover over links "
                "before clicking, and report suspicious emails. Deploy "
                "DMARC, DKIM, and SPF on your mail domain."
            ),
            quiz_question=(
                "What is the difference between phishing and spear phishing?"
            ),
            quiz_answer=(
                "Phishing is broad and untargeted; spear phishing targets "
                "specific individuals with personalised content"
            ),
        ),
        TutorialStep(
            title="Live Demo -- Crafting a Phishing Email",
            explanation=(
                "We will generate a simulated phishing email that mimics a "
                "password-reset notification from a well-known service. The "
                "email contains a link to a cloned login page. This "
                "demonstrates how convincing phishing can be."
            ),
            action=(
                "Generating a phishing email template and displaying it "
                "for analysis (no real emails are sent)."
            ),
            mitre_technique="T1566.001 - Spearphishing Attachment",
            defense_tip=(
                "Use email authentication (SPF, DKIM, DMARC) to prevent "
                "domain spoofing. Sandbox attachments before delivery."
            ),
            quiz_question="What three DNS-based email security protocols prevent spoofing?",
            quiz_answer="SPF, DKIM, and DMARC",
        ),
        TutorialStep(
            title="Detection -- Analysing Phishing Indicators",
            explanation=(
                "CyberSim6 analyses emails for phishing indicators: "
                "mismatched sender domains, suspicious URLs (typosquatting, "
                "IP-based links), urgency language, and attachment types. "
                "Real systems also check URL reputation databases and use "
                "ML classifiers trained on phishing corpora."
            ),
            action=(
                "Running the phishing detector on sample emails to score "
                "their suspicion level."
            ),
            mitre_technique="T1566.002 - Spearphishing Link",
            defense_tip=(
                "Integrate URL reputation checking (e.g. Google Safe "
                "Browsing, VirusTotal) into your email gateway."
            ),
            quiz_question="What is typosquatting in the context of phishing?",
            quiz_answer=(
                "Registering domain names that are slight misspellings of "
                "legitimate domains (e.g. g00gle.com instead of google.com)"
            ),
        ),
    ],
)

_RANSOMWARE_MODULE = TutorialModule(
    name="Ransomware Attack & Defense",
    description=(
        "Study how ransomware encrypts files, how to detect encryption "
        "activity, and why offline backups are critical."
    ),
    difficulty="advanced",
    estimated_time="7 minutes",
    prerequisites=["bruteforce", "phishing"],
    steps=[
        TutorialStep(
            title="Theory -- What is Ransomware?",
            explanation=(
                "Ransomware is malware that encrypts a victim's files and "
                "demands payment for the decryption key. Modern variants "
                "use double extortion -- encrypting data AND threatening to "
                "leak it. Notable examples: WannaCry (CVE-2017-0144, "
                "EternalBlue), NotPetya, and REvil. The Colonial Pipeline "
                "attack (2021) disrupted US fuel supply for days."
            ),
            action="No action -- this is a theory step.",
            mitre_technique="T1486 - Data Encrypted for Impact",
            defense_tip=(
                "Maintain offline, immutable backups (3-2-1 rule: 3 copies, "
                "2 media types, 1 offsite). Patch systems promptly."
            ),
            quiz_question=(
                "What CVE was exploited by WannaCry ransomware?"
            ),
            quiz_answer="CVE-2017-0144 (EternalBlue / MS17-010)",
        ),
        TutorialStep(
            title="Live Demo -- Simulated File Encryption",
            explanation=(
                "We will encrypt sample files in a sandboxed directory using "
                "AES-256. This simulates what ransomware does to victim "
                "files. The encryption is reversible in our simulation -- "
                "real ransomware often uses RSA to protect the AES key."
            ),
            action=(
                "Encrypting sample .txt files in the sandbox directory and "
                "generating a mock ransom note."
            ),
            mitre_technique="T1486 - Data Encrypted for Impact",
            defense_tip=(
                "Use application whitelisting to prevent unauthorised "
                "executables. Monitor for mass file-rename operations."
            ),
            quiz_question=(
                "What encryption scheme do most modern ransomware variants use?"
            ),
            quiz_answer=(
                "Hybrid encryption: AES for file content (speed) with RSA "
                "to protect the AES key"
            ),
        ),
        TutorialStep(
            title="Detection -- Entropy & Behaviour Analysis",
            explanation=(
                "CyberSim6 detects ransomware by monitoring file entropy "
                "(encrypted files have near-maximum entropy ~8.0) and by "
                "watching for suspicious patterns: rapid file renaming, "
                "deletion of shadow copies, and known ransom-note filenames. "
                "EDR tools use similar behavioural heuristics."
            ),
            action=(
                "Scanning the sandbox directory to measure file entropy "
                "before and after encryption."
            ),
            mitre_technique="T1486 - Data Encrypted for Impact",
            defense_tip=(
                "Deploy EDR with behavioural detection. Alert on vssadmin "
                "delete shadows and mass file operations."
            ),
            quiz_question=(
                "What file property indicates data has been encrypted?"
            ),
            quiz_answer=(
                "High Shannon entropy (close to 8.0 for byte-level analysis)"
            ),
        ),
        TutorialStep(
            title="Defense -- Resilience & Recovery",
            explanation=(
                "The NIST Cybersecurity Framework Recover function (RC) "
                "emphasises recovery planning and improvements. Key measures: "
                "(1) immutable backups tested regularly, (2) network "
                "segmentation to limit lateral movement, (3) least-privilege "
                "access to file shares, (4) email filtering to block "
                "initial delivery vectors, and (5) an incident response "
                "playbook. CISA publishes ransomware-specific guidance."
            ),
            action="No action -- review and discussion step.",
            mitre_technique="T1486 - Data Encrypted for Impact",
            defense_tip=(
                "Never pay the ransom -- it funds criminal operations and "
                "does not guarantee data recovery. Focus on prevention and "
                "backup-based recovery."
            ),
            quiz_question=(
                "What is the 3-2-1 backup rule?"
            ),
            quiz_answer=(
                "Keep 3 copies of data, on 2 different media types, with "
                "1 copy stored offsite"
            ),
        ),
    ],
)


# ---------------------------------------------------------------------------
# InteractiveTutorial -- main class
# ---------------------------------------------------------------------------

class InteractiveTutorial:
    """Guided learning experience for cybersecurity concepts.

    Each module walks through an attack type with explanations, live demos,
    detection analysis, and defence recommendations.

    Parameters
    ----------
    logger : optional
        A ``CyberSimLogger`` instance.  When provided, tutorial events are
        recorded to the simulation log.

    Example
    -------
    >>> tutorial = InteractiveTutorial()
    >>> modules = tutorial.list_modules()
    >>> result = tutorial.start_tutorial("ddos")
    """

    MODULES: dict[str, TutorialModule] = {
        "ddos": _DDOS_MODULE,
        "sqli": _SQLI_MODULE,
        "xss": _XSS_MODULE,
        "bruteforce": _BRUTEFORCE_MODULE,
        "phishing": _PHISHING_MODULE,
        "ransomware": _RANSOMWARE_MODULE,
    }

    def __init__(self, logger: Optional[object] = None) -> None:
        self.logger = logger

    # -- public API ---------------------------------------------------------

    def list_modules(self) -> list[dict]:
        """Return a summary list of all available tutorial modules.

        Returns
        -------
        list[dict]
            Each dict contains *name*, *description*, *difficulty*,
            *estimated_time*, *steps_count*, and *prerequisites*.
        """
        result: list[dict] = []
        for key, mod in self.MODULES.items():
            result.append({
                "key": key,
                "name": mod.name,
                "description": mod.description,
                "difficulty": mod.difficulty,
                "estimated_time": mod.estimated_time,
                "steps_count": len(mod.steps),
                "prerequisites": mod.prerequisites,
            })
        return result

    def get_module(self, name: str) -> TutorialModule:
        """Retrieve a single tutorial module by its key.

        Parameters
        ----------
        name : str
            Module key (e.g. ``"ddos"``, ``"sqli"``).

        Raises
        ------
        KeyError
            If the module name is not found.
        """
        if name not in self.MODULES:
            raise KeyError(
                f"Unknown tutorial module '{name}'. "
                f"Available: {', '.join(sorted(self.MODULES))}"
            )
        return self.MODULES[name]

    def start_tutorial(self, module_name: str) -> TutorialResult:
        """Run the interactive tutorial for a given module.

        Walks through every step, displaying explanations and quizzes in
        the terminal.  Returns a :class:`TutorialResult` with scores.

        Parameters
        ----------
        module_name : str
            Module key (same as :meth:`get_module`).

        Returns
        -------
        TutorialResult
        """
        module = self.get_module(module_name)
        start_time = time.time()

        self._print_header(
            f"  Tutorial: {module.name}  "
        )
        self._print_info(f"  {module.description}")
        self._print_info(
            f"  Difficulty: {module.difficulty.capitalize()}  |  "
            f"Estimated time: {module.estimated_time}"
        )
        if module.prerequisites:
            self._print_info(
                f"  Prerequisites: {', '.join(module.prerequisites)}"
            )
        print()

        quiz_score = 0
        quiz_total = 0
        steps_completed = 0

        for idx, step in enumerate(module.steps):
            self._display_step(step, idx, len(module.steps))
            steps_completed += 1

            if step.quiz_question:
                quiz_total += 1
                if self._display_quiz(step):
                    quiz_score += 1

        elapsed = time.time() - start_time

        # Summary
        print()
        self._print_header("  Tutorial Complete!  ")
        self._print_info(
            f"  Steps completed: {steps_completed}/{len(module.steps)}"
        )
        self._print_info(
            f"  Quiz score: {quiz_score}/{quiz_total}"
        )
        self._print_info(f"  Duration: {elapsed:.1f}s")
        print()

        if self.logger:
            try:
                self.logger.log_event(
                    module=f"tutorial_{module_name}",
                    module_type="education",
                    event_type="tutorial_completed",
                    details={
                        "module": module_name,
                        "steps_completed": steps_completed,
                        "quiz_score": quiz_score,
                        "quiz_total": quiz_total,
                        "duration": round(elapsed, 2),
                    },
                )
            except Exception as exc:
                self._print_warning(f"  Session logging unavailable: {exc}")

        return TutorialResult(
            module_name=module_name,
            steps_completed=steps_completed,
            quiz_score=quiz_score,
            quiz_total=quiz_total,
            duration_seconds=round(elapsed, 2),
        )

    # -- display helpers (ANSI coloured output) -----------------------------

    def _display_step(
        self, step: TutorialStep, index: int, total: int
    ) -> None:
        """Render a single tutorial step to the terminal."""
        separator = f"{_C.DIM}{'=' * 60}{_C.RESET}"
        print(separator)
        print(
            f"{_C.STEP}  Step {index + 1}/{total}: "
            f"{step.title}{_C.RESET}"
        )
        print(separator)
        print()

        # Explanation
        print(f"{_C.INFO}{step.explanation}{_C.RESET}")
        print()

        # Action
        if "no action" not in step.action.lower():
            print(f"{_C.ATTACK}  [ACTION] {step.action}{_C.RESET}")
            print()

        # MITRE reference
        print(
            f"{_C.WARNING}  MITRE ATT&CK: "
            f"{step.mitre_technique}{_C.RESET}"
        )

        # Defence tip
        print(
            f"{_C.DEFENSE}  Defense Tip: "
            f"{step.defense_tip}{_C.RESET}"
        )
        print()

    def _display_quiz(self, step: TutorialStep) -> bool:
        """Show a quiz question and the answer.

        In non-interactive mode (default), the answer is revealed
        automatically and the function returns ``True``.

        Returns
        -------
        bool
            Whether the quiz was scored as correct.
        """
        print(
            f"{_C.QUIZ}  [QUIZ] {step.quiz_question}{_C.RESET}"
        )
        print(
            f"{_C.SUCCESS}  Answer: {step.quiz_answer}{_C.RESET}"
        )
        print()
        return True

    # -- primitive print wrappers ------------------------------------------

    def _print_header(self, text: str) -> None:
        """Print a header line in cyan/bold."""
        border = "=" * len(text)
        print(f"{_C.HEADER}{border}{_C.RESET}")
        print(f"{_C.HEADER}{text}{_C.RESET}")
        print(f"{_C.HEADER}{border}{_C.RESET}")

    def _print_info(self, text: str) -> None:
        """Print an informational line in white."""
        print(f"{_C.INFO}{text}{_C.RESET}")

    def _print_warning(self, text: str) -> None:
        """Print a warning line in yellow/bold."""
        print(f"{_C.WARNING}{text}{_C.RESET}")
