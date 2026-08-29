"""Context-provider abstraction (IoC for inputs).

The verification pipeline never calls platform APIs directly. Instead it asks an
:class:`IContextProvider` for whatever external information a field needs (time,
location, secrets, online objects). The package ships with one provider:

- :class:`DummyContextProvider` — the default; returns configured values or
  ``None`` (never prompts). This is what library consumers get unless they
  override it.

Consumers implement their own provider (e.g. read from a device, a remote
service, or a test fixture) and inject it via ``create_qrs``.
"""

from __future__ import annotations

from typing import Any, Protocol

from .fields import FieldSchema, VerificationContext

__all__ = ["IContextProvider", "adapt_provider", "DummyContextProvider"]


class IContextProvider(Protocol):
    """The external-input interface the core depends on."""

    def get_current_time(self) -> int: ...

    async def request_location(self, field: FieldSchema | None = None) -> dict[str, float] | None: ...

    async def request_secret(self, field: FieldSchema) -> str | None: ...

    async def request_object(
        self,
        object_id: str,
        field: FieldSchema | None = None,
        online_endpoints: list[str] | None = None,
    ) -> bytes | None: ...

    def build_context(self) -> VerificationContext: ...


def adapt_provider(provider: IContextProvider) -> VerificationContext:
    """Adapt any provider into a :class:`~qrs.fields.VerificationContext`."""

    class _Adapted:
        def get_current_time(self) -> int:
            return provider.get_current_time()

        async def get_location(self) -> dict[str, float] | None:
            return await provider.request_location()

        async def get_secret(self, field_name: str) -> str | None:
            return await provider.request_secret(
                FieldSchema(type="secretInput", name=field_name, label=field_name)
            )

        async def get_object(
            self, object_id: str, online_endpoints: list[str] | None = None
        ) -> bytes | None:
            return await provider.request_object(object_id, None, online_endpoints)

    return _Adapted()


class DummyContextProvider:
    """Default context provider. Never prompts: it returns the values it was
    configured with (or ``None`` when absent). This is what ``create_qrs`` wires
    in by default, so the core is fully usable headless; consumers override it
    with their own provider."""

    def __init__(
        self,
        time: int | None = None,
        location: dict[str, float] | None = None,
        secrets: dict[str, str] | None = None,
        objects: dict[str, bytes] | None = None,
    ) -> None:
        import time as _time

        self._time = time if time is not None else int(_time.time())
        self._location = location
        self._secrets = secrets or {}
        self._objects = objects or {}

    def get_current_time(self) -> int:
        return self._time

    async def request_location(self, field: FieldSchema | None = None) -> dict[str, float] | None:
        return self._location

    async def request_secret(self, field: FieldSchema) -> str | None:
        return self._secrets.get(field.name)

    async def request_object(
        self,
        object_id: str,
        field: FieldSchema | None = None,
        online_endpoints: list[str] | None = None,
    ) -> bytes | None:
        return self._objects.get(object_id)

    def build_context(self) -> VerificationContext:
        return adapt_provider(self)