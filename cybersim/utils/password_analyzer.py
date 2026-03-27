"""
Password Strength Analyzer -- Evaluate password security with multiple metrics.

Calculates entropy, checks patterns, estimates crack time, and provides
actionable recommendations.  Uses only the Python standard library.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PasswordAnalysis:
    """Result of a password strength evaluation."""

    password_length: int
    entropy_bits: float
    score: int                        # 0-100
    strength: str                     # "very_weak" | "weak" | "fair" | "strong" | "very_strong"
    crack_time_seconds: float
    crack_time_display: str           # e.g. "2 hours", "3 centuries"
    patterns_found: list[str]         # e.g. ["sequential_numbers", "common_word"]
    recommendations: list[str]
    char_diversity: dict[str, int]    # {"lowercase": 5, "uppercase": 2, ...}


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class PasswordAnalyzer:
    """Analyse password strength across entropy, patterns, and diversity.

    Usage::

        analyzer = PasswordAnalyzer()
        result = analyzer.analyze("P@ssw0rd!")
        print(result.strength, result.score)
    """

    COMMON_PASSWORDS: list[str] = [
        "password", "123456", "qwerty", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "login", "abc123", "111111",
        "password1", "iloveyou", "sunshine", "princess", "football",
    ]

    KEYBOARD_PATTERNS: list[str] = [
        "qwerty", "asdf", "zxcv", "1234", "qazwsx",
    ]

    # Assumed guesses/second for offline brute-force attack (modern GPU).
    _GUESSES_PER_SECOND: float = 1e10

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, password: str) -> PasswordAnalysis:
        """Run a full analysis on *password* and return a :class:`PasswordAnalysis`.

        Args:
            password: The password string to evaluate.

        Returns:
            A populated ``PasswordAnalysis`` dataclass.
        """
        length = len(password)
        diversity = self._char_diversity(password)
        entropy = self._calculate_entropy(password)
        patterns = self._detect_patterns(password)
        score = self._calculate_score(entropy, length, patterns)
        strength = self._get_strength(score)
        crack_seconds, crack_display = self._estimate_crack_time(entropy)

        analysis = PasswordAnalysis(
            password_length=length,
            entropy_bits=round(entropy, 2),
            score=score,
            strength=strength,
            crack_time_seconds=crack_seconds,
            crack_time_display=crack_display,
            patterns_found=patterns,
            recommendations=[],          # filled below
            char_diversity=diversity,
        )
        analysis.recommendations = self._get_recommendations(analysis)
        return analysis

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy in bits based on the character pool used.

        The pool size is the union of character classes present in the
        password (lowercase, uppercase, digits, special characters).
        Entropy = length * log2(pool_size).
        """
        if not password:
            return 0.0

        pool_size = 0
        if any(c in string.ascii_lowercase for c in password):
            pool_size += 26
        if any(c in string.ascii_uppercase for c in password):
            pool_size += 26
        if any(c in string.digits for c in password):
            pool_size += 10
        if any(c in string.punctuation for c in password):
            pool_size += 32

        if pool_size == 0:
            # Fallback: count unique characters
            pool_size = len(set(password))

        if pool_size <= 1:
            return 0.0

        return len(password) * math.log2(pool_size)

    def _estimate_crack_time(self, entropy: float) -> tuple[float, str]:
        """Estimate the time to brute-force given *entropy* bits.

        Returns:
            A ``(seconds, human_readable)`` tuple.
        """
        if entropy <= 0:
            return (0.0, "instant")

        total_guesses = 2 ** entropy
        seconds = total_guesses / self._GUESSES_PER_SECOND

        if seconds < 1:
            return (seconds, "instant")
        if seconds < 60:
            return (seconds, f"{int(seconds)} seconds")
        if seconds < 3600:
            return (seconds, f"{int(seconds // 60)} minutes")
        if seconds < 86400:
            return (seconds, f"{int(seconds // 3600)} hours")
        if seconds < 86400 * 365:
            return (seconds, f"{int(seconds // 86400)} days")
        if seconds < 86400 * 365 * 100:
            return (seconds, f"{int(seconds // (86400 * 365))} years")
        return (seconds, f"{int(seconds // (86400 * 365 * 100))} centuries")

    def _detect_patterns(self, password: str) -> list[str]:
        """Detect common weakness patterns in *password*.

        Checks:
        - common passwords
        - keyboard patterns
        - sequential numbers
        - repeated characters
        - date patterns
        """
        patterns: list[str] = []
        lower = password.lower()

        # Common password check
        if lower in self.COMMON_PASSWORDS:
            patterns.append("common_password")

        # Keyboard patterns
        for kp in self.KEYBOARD_PATTERNS:
            if kp in lower:
                patterns.append("keyboard_pattern")
                break

        # Sequential numbers (3+ consecutive ascending digits)
        for i in range(len(password) - 2):
            if (password[i].isdigit()
                    and password[i + 1].isdigit()
                    and password[i + 2].isdigit()):
                a, b, c = int(password[i]), int(password[i + 1]), int(password[i + 2])
                if b == a + 1 and c == b + 1:
                    patterns.append("sequential_numbers")
                    break

        # Repeated characters (3+ of the same character in a row)
        if re.search(r"(.)\1{2,}", password):
            patterns.append("repeated_characters")

        # Date-like patterns (e.g. 1990, 2024, 01/12)
        if re.search(r"(19|20)\d{2}", password):
            patterns.append("date_pattern")

        return patterns

    def _calculate_score(self, entropy: float, length: int, patterns: list[str]) -> int:
        """Derive a 0-100 score from entropy, length, and detected patterns.

        Base score comes from entropy, boosted by length, then penalised
        for every weakness pattern found.
        """
        # Base from entropy: 128 bits -> ~100
        base = min(100, int(entropy / 128 * 100))

        # Small length bonus
        length_bonus = min(10, max(0, length - 8))
        score = base + length_bonus

        # Penalty per pattern
        penalty = len(patterns) * 15
        score = max(0, score - penalty)

        return min(100, score)

    def _get_strength(self, score: int) -> str:
        """Map a numeric *score* (0-100) to a human-readable strength label."""
        if score < 20:
            return "very_weak"
        if score < 40:
            return "weak"
        if score < 60:
            return "fair"
        if score < 80:
            return "strong"
        return "very_strong"

    def _get_recommendations(self, analysis: PasswordAnalysis) -> list[str]:
        """Generate actionable recommendations based on *analysis*.

        Returns:
            A list of human-readable suggestion strings.
        """
        recs: list[str] = []

        if analysis.password_length < 12:
            recs.append("Use at least 12 characters.")

        div = analysis.char_diversity
        if div.get("uppercase", 0) == 0:
            recs.append("Add uppercase letters.")
        if div.get("lowercase", 0) == 0:
            recs.append("Add lowercase letters.")
        if div.get("digits", 0) == 0:
            recs.append("Include numbers.")
        if div.get("special", 0) == 0:
            recs.append("Include special characters (!@#$...).")

        if "common_password" in analysis.patterns_found:
            recs.append("Avoid common passwords.")
        if "keyboard_pattern" in analysis.patterns_found:
            recs.append("Avoid keyboard patterns (qwerty, asdf, ...).")
        if "sequential_numbers" in analysis.patterns_found:
            recs.append("Avoid sequential numbers (123, 456, ...).")
        if "repeated_characters" in analysis.patterns_found:
            recs.append("Avoid repeated characters (aaa, 111, ...).")
        if "date_pattern" in analysis.patterns_found:
            recs.append("Avoid dates or years in your password.")

        if not recs:
            recs.append("Your password is strong. Consider a passphrase for even better security.")

        return recs

    def _char_diversity(self, password: str) -> dict[str, int]:
        """Count characters in each class.

        Returns:
            ``{"lowercase": n, "uppercase": n, "digits": n, "special": n}``
        """
        return {
            "lowercase": sum(1 for c in password if c in string.ascii_lowercase),
            "uppercase": sum(1 for c in password if c in string.ascii_uppercase),
            "digits": sum(1 for c in password if c in string.digits),
            "special": sum(1 for c in password if c in string.punctuation),
        }
