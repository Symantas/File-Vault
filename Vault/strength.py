"""Lightweight password-strength heuristics.

The only defense against offline brute force of a vault is the strength of the
password (see SECURITY.md). These checks catch the most dangerous mistakes —
empty, too short, or a well-known password — and are used by the CLI to warn or
block before a weak password is committed to a vault. They are intentionally
simple and conservative, not a full password-strength meter.
"""

MIN_LENGTH = 8

# A small sample of the most common leaked passwords. Lowercased for matching.
_COMMON = frozenset(
    {
        "123456",
        "12345678",
        "123456789",
        "password",
        "qwerty",
        "abc123",
        "111111",
        "letmein",
        "iloveyou",
        "admin",
        "welcome",
        "monkey",
        "dragon",
        "hunter2",
    }
)


def weaknesses(password: str) -> list[str]:
    """Return a list of reasons the password is weak (empty list means OK)."""
    reasons: list[str] = []
    if not password:
        reasons.append("password is empty")
        return reasons
    if len(password) < MIN_LENGTH:
        reasons.append(f"password is too short (minimum {MIN_LENGTH} characters)")
    if password.lower() in _COMMON:
        reasons.append("password is a common/wordlist password")
    return reasons


def is_acceptable(password: str) -> bool:
    """True if the password has no detected weaknesses."""
    return not weaknesses(password)
