"""End-to-end smoke test for the qrs core.

Exercises the full protocol flow with the reference (in-memory) wiring:

    generate key → create TCert → pin/CA → issue SDoc → verify

Run with:  python3 -m qrs.smoke
"""

from __future__ import annotations

import asyncio
import sys

from .context import DummyContextProvider
from .fields import FieldSchema
from .runtime import QrsDependencies, create_qrs
from .services.certificateService import CreateTcertParams
from .services.signingService import IssueSdocParams


async def main() -> None:
    qrs = create_qrs(
        QrsDependencies(
            context_provider=DummyContextProvider(secrets={"pin": "s3cret"}),
        )
    )

    # 1. Create a TCert (issuer) with a small schema.
    tcert = await qrs.certificates.create_tcert(
        CreateTcertParams(
            algorithm="Ed25519",
            name="AFDA Pharmacy License",
            fields=[
                FieldSchema(type="text", name="license_no", label="License number"),
                FieldSchema(type="date", name="expiry", label="Expiry date"),
                FieldSchema(type="secretInput", name="pin", label="PIN"),
            ],
        )
    )
    print("TCert:", tcert.tcert_id, "key:", tcert.key_id)

    # 2. Pin the TCert so verification has a trust path.
    await qrs.trust.pin(tcert.tcert_id)

    # 3. Issue an SDoc (secret 'pin' is stripped → signed into AAD, not stored).
    issued = await qrs.signing.issue_sdoc(
        IssueSdocParams(
            tcert_id=tcert.tcert_id,
            values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "s3cret"},
        )
    )
    print("SDoc:", issued.sdoc_id, "bytes:", len(issued.bytes))

    # 4. Verify with the correct secret.
    result = await qrs.verification.verify(issued.bytes)
    print("Verify (correct secret):", result.overall)
    assert result.overall == "valid", result

    # 5. Verify with the WRONG secret → cryptographic failure.
    qrs_wrong = create_qrs(
        QrsDependencies(
            context_provider=DummyContextProvider(secrets={"pin": "wrong"}),
        )
    )
    # Reuse the same stores by copying them is complex; instead verify against the
    # same runtime but override the secret via a fresh provider is not possible
    # post-hoc. So we demonstrate the wrong-secret path by re-issuing with a
    # different secret and verifying with the original.
    issued2 = await qrs.signing.issue_sdoc(
        IssueSdocParams(
            tcert_id=tcert.tcert_id,
            values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "other"},
        )
    )
    result2 = await qrs.verification.verify(issued2.bytes)
    print("Verify (wrong secret):", result2.overall)
    assert result2.overall == "invalid", result2

    print("\nSMOKE OK")


if __name__ == "__main__":
    asyncio.run(main())