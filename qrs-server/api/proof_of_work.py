"""Proof-of-work challenge — DDoS defense before a host may upload.

The challenge is deliberately cheap to verify but requires the host to burn CPU
(hashcash-style): find a `counter` such that sha256("{nonce}:{counter}") starts
with `difficulty` zero hex characters. Difficulty is a small integer (default 4,
~16 bits). Tokens issued after solving are short-lived.
"""
import hashlib
import secrets

DEFAULT_DIFFICULTY = 4
MAX_DIFFICULTY = 8
CHALLENGE_TTL_SECONDS = 300  # a challenge must be solved within 5 minutes


def generate_nonce() -> str:
    return secrets.token_hex(16)


def solve(nonce: str, difficulty: int) -> int:
    """Find the counter that satisfies the challenge (client side)."""
    target = "0" * difficulty
    counter = 0
    while True:
        digest = hashlib.sha256(f"{nonce}:{counter}".encode("ascii")).hexdigest()
        if digest.startswith(target):
            return counter
        counter += 1


def verify(nonce: str, difficulty: int, counter: int) -> bool:
    if difficulty < 1 or difficulty > MAX_DIFFICULTY:
        return False
    if counter < 0 or counter > 10**9:
        return False
    digest = hashlib.sha256(f"{nonce}:{counter}".encode("ascii")).hexdigest()
    return digest.startswith("0" * difficulty)
