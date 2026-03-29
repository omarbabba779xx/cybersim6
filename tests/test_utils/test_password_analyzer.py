"""Tests for cybersim.utils.password_analyzer module."""

from cybersim.utils.password_analyzer import PasswordAnalyzer


class TestPasswordAnalyzer:
    """Suite of 10 tests covering the PasswordAnalyzer."""

    def setup_method(self) -> None:
        self.analyzer = PasswordAnalyzer()

    # 1 — Empty password
    def test_empty_password_is_very_weak(self) -> None:
        result = self.analyzer.analyze("")
        assert result.password_length == 0
        assert result.entropy_bits == 0.0
        assert result.strength == "very_weak"
        assert result.score == 0

    # 2 — Common password detection
    def test_common_password_detected(self) -> None:
        result = self.analyzer.analyze("password")
        assert "common_password" in result.patterns_found
        assert result.strength in ("very_weak", "weak")

    # 3 — Keyboard pattern detection
    def test_keyboard_pattern_detected(self) -> None:
        result = self.analyzer.analyze("qwerty2023")
        assert "keyboard_pattern" in result.patterns_found

    # 4 — Sequential numbers detection
    def test_sequential_numbers_detected(self) -> None:
        result = self.analyzer.analyze("test123test")
        assert "sequential_numbers" in result.patterns_found

    # 5 — Repeated characters detection
    def test_repeated_characters_detected(self) -> None:
        result = self.analyzer.analyze("aaabbb")
        assert "repeated_characters" in result.patterns_found

    # 6 — Date pattern detection
    def test_date_pattern_detected(self) -> None:
        result = self.analyzer.analyze("born1990here")
        assert "date_pattern" in result.patterns_found

    # 7 — Strong password scores high
    def test_strong_password_high_score(self) -> None:
        result = self.analyzer.analyze("X#9kL!mZ@2pQ&vR$")
        assert result.score >= 60
        assert result.strength in ("strong", "very_strong")
        assert result.entropy_bits > 80

    # 8 — Character diversity counts
    def test_char_diversity_counts(self) -> None:
        result = self.analyzer.analyze("Abc1!")
        div = result.char_diversity
        assert div["lowercase"] == 2     # b, c
        assert div["uppercase"] == 1     # A
        assert div["digits"] == 1        # 1
        assert div["special"] == 1       # !

    # 9 — Crack time display is human-readable
    def test_crack_time_display_format(self) -> None:
        weak = self.analyzer.analyze("aaa")
        assert weak.crack_time_display in ("instant", "0 seconds")
        strong = self.analyzer.analyze("X#9kL!mZ@2pQ&vR$")
        assert any(w in strong.crack_time_display for w in
                   ("years", "centuries", "days"))

    # 10 — Recommendations generated for weak password
    def test_recommendations_for_short_password(self) -> None:
        result = self.analyzer.analyze("abc")
        assert len(result.recommendations) > 0
        assert any("12 characters" in r for r in result.recommendations)
