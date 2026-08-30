"""Distribution integration — publish signed statements to qrs-server.

The enterprise app uses the existing qrs-server as a distribution/mirror. This
module implements the client side of the qrs-server protocol:

1. ``POST /api/tcerts/<keyId>/challenge/`` → ``{nonce, difficulty}``
2. Solve the hashcash proof-of-work locally.
3. ``POST /api/tcerts/<keyId>/token/`` → ``{token, expiresAt}``
4. Upload the signed statement/attestation with ``Authorization: Bearer <token>``.

The server is an untrusted mirror: every object is already cryptographically
signed by qrs-core, so publishing never weakens security.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_DIFFICULTY = 4
MAX_DIFFICULTY = 8
CHALLENGE_TTL_SECONDS = 300


class DistributionError(Exception):
    """Base error for distribution failures."""


class DistributionUnavailableError(DistributionError):
    """Raised when no endpoint is configured or the server is unreachable."""


def _solve(nonce: str, difficulty: int) -> int:
    """Solve the hashcash challenge (client side)."""
    target = "0" * difficulty
    counter = 0
    while True:
        digest = hashlib.sha256(f"{nonce}:{counter}".encode("ascii")).hexdigest()
        if digest.startswith(target):
            return counter
        counter += 1


def _normalize_endpoint(endpoint: str) -> str:
    return endpoint.rstrip("/")


async def _get_token(client: httpx.AsyncClient, base: str, key_id: str) -> str:
    """Run the challenge → PoW → token flow and return a bearer token."""
    challenge = await client.post(f"{base}/api/tcerts/{key_id}/challenge/")
    challenge.raise_for_status()
    data = challenge.json()
    nonce = data["nonce"]
    difficulty = min(int(data.get("difficulty", DEFAULT_DIFFICULTY)), MAX_DIFFICULTY)
    counter = _solve(nonce, difficulty)
    token_resp = await client.post(
        f"{base}/api/tcerts/{key_id}/token/",
        json={"nonce": nonce, "counter": counter},
    )
    token_resp.raise_for_status()
    return token_resp.json()["token"]


async def publish_attestation(
    *,
    endpoint: str,
    ca_tcert_id: str,
    ca_key_id: str,
    target_tcert_b64: str,
    attestation_b64: str,
) -> dict[str, Any]:
    """Publish a CA attestation (and enroll the target TCert) to qrs-server."""
    base = _normalize_endpoint(endpoint)
    async with httpx.AsyncClient(timeout=30) as client:
        token = await _get_token(client, base, ca_key_id)
        resp = await client.post(
            f"{base}/api/cas/{ca_tcert_id}/attestations/",
            json={
                "targetTcertB64": target_tcert_b64,
                "attestationB64": attestation_b64,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code >= 400:
            raise DistributionError(f"attestation publish failed: {resp.status_code} {resp.text}")
        return resp.json()


async def publish_statement(
    *,
    endpoint: str,
    ca_tcert_id: str,
    ca_key_id: str,
    statement_b64: str,
) -> dict[str, Any]:
    """Publish a non-enrollment statement (revoke/block/unblock) to qrs-server."""
    base = _normalize_endpoint(endpoint)
    async with httpx.AsyncClient(timeout=30) as client:
        token = await _get_token(client, base, ca_key_id)
        resp = await client.post(
            f"{base}/api/cas/{ca_tcert_id}/statements/",
            json={"bytesB64": statement_b64},
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code >= 400:
            raise DistributionError(f"statement publish failed: {resp.status_code} {resp.text}")
        return resp.json()