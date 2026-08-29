"""EndpointService: distribution mirrors for a TCert (app-level convenience,
NOT protocol core).

A TCert's signed ``onlineEndpoint`` is the fixed default. Additional mirrors are
configured by the user at any time and stored app-locally via
:class:`IEndpointConfigStore`. The effective endpoint list is the default first,
then the configured mirrors (deduplicated). Servers are untrusted mirrors —
every downloaded object is still verified cryptographically, so a mirror is just
a routing hint.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..deps import ServiceDeps
from ..envelope import parse_signed_object

__all__ = ["EndpointService", "normalize_endpoint"]


def normalize_endpoint(endpoint: str) -> str:
    """Normalize a base URL: trim and strip trailing slashes."""
    return endpoint.strip().rstrip("/")


class EndpointService:
    def __init__(self, deps: ServiceDeps) -> None:
        self._deps = deps

    async def default_endpoint(self, tcert_id: str) -> str | None:
        """The signed default endpoint of a TCert (if any)."""
        data = await self._deps.certificate_store.get(tcert_id)
        if not data:
            return None
        try:
            parsed = parse_signed_object(data)
            ep = parsed.data.get("onlineEndpoint") if parsed.type == "tcert" else None
            return normalize_endpoint(ep) if isinstance(ep, str) and ep else None
        except Exception:
            return None

    async def list_mirrors(self, tcert_id: str) -> list[str]:
        """Configured mirrors (excluding the signed default)."""
        endpoints = await self._deps.endpoint_config_store.get_endpoints(tcert_id)
        return [normalize_endpoint(ep) for ep in endpoints if normalize_endpoint(ep)]

    async def effective_endpoints(self, tcert_id: str) -> list[str]:
        """All endpoints for a TCert, best-effort: the signed default first, then the
        user-configured mirrors. When the TCert has NO endpoints of its own but is
        attested by a CA, fall back to the CA's endpoints — a TCert without an
        endpoint hosts its attachments through the CA that attested it."""
        seen: set[str] = set()
        out: list[str] = []

        def push(ep: str | None) -> None:
            if not ep:
                return
            normalized = normalize_endpoint(ep)
            if normalized not in seen:
                seen.add(normalized)
                out.append(normalized)

        push(await self.default_endpoint(tcert_id))
        for ep in await self.list_mirrors(tcert_id):
            push(ep)

        if not out:
            attestations = await self._deps.trust_store.get_attestations(tcert_id)
            for att in attestations:
                ca_bytes = await self._deps.certificate_store.get(att.ca_tcert_id)
                if not ca_bytes:
                    continue
                try:
                    parsed = parse_signed_object(ca_bytes)
                    if parsed.type != "tcert":
                        continue
                    push(parsed.data.get("onlineEndpoint"))
                    for ep in await self._deps.endpoint_config_store.get_endpoints(att.ca_tcert_id):
                        push(ep)
                except Exception:
                    continue

        return out

    async def add_mirror(self, tcert_id: str, endpoint: str) -> list[str]:
        """Add a mirror endpoint (dedup + normalized). Returns the updated mirror list."""
        normalized = normalize_endpoint(endpoint)
        if normalized:
            await self._deps.endpoint_config_store.add_endpoint(tcert_id, normalized)
        return await self.list_mirrors(tcert_id)

    async def remove_mirror(self, tcert_id: str, endpoint: str) -> list[str]:
        """Remove a mirror endpoint. Returns the updated mirror list."""
        await self._deps.endpoint_config_store.remove_endpoint(tcert_id, normalize_endpoint(endpoint))
        return await self.list_mirrors(tcert_id)

    async def set_mirrors(self, tcert_id: str, endpoints: list[str]) -> list[str]:
        """Replace the whole mirror list. Returns the updated mirror list."""
        await self._deps.endpoint_config_store.set_endpoints(
            tcert_id, [normalize_endpoint(ep) for ep in endpoints if normalize_endpoint(ep)]
        )
        return await self.list_mirrors(tcert_id)