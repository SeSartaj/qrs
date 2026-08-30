"""Tests for the distribution integration (qrs-server client)."""
from __future__ import annotations

import pytest

from enterprise.distribution import _solve


class TestProofOfWork:
    def test_solve_returns_valid_counter(self):
        nonce = "abc123"
        difficulty = 4
        counter = _solve(nonce, difficulty)
        import hashlib

        digest = hashlib.sha256(f"{nonce}:{counter}".encode("ascii")).hexdigest()
        assert digest.startswith("0" * difficulty)

    def test_solve_difficulty_1(self):
        counter = _solve("nonce", 1)
        import hashlib

        digest = hashlib.sha256("nonce:{}".format(counter).encode("ascii")).hexdigest()
        assert digest.startswith("0")