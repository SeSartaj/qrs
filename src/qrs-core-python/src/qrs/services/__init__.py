"""High-level services: certificates, signing, trust, revocation, verification,
attachments, online import and endpoint mirrors.

Each service receives the full dependency bundle (:class:`~qrs.deps.ServiceDeps`)
and never depends on concrete store/provider implementations — that is what makes
the core invertible and testable.
"""

from .attachmentService import (
    ATTACHMENT_ID_HEX,
    AttachmentService,
    BuildAttachmentParams,
    BuiltAttachment,
    ParsedAttachment,
    attachment_id_of,
    build_attachment,
    parse_attachment,
    verify_attachment,
)
from .certificateService import (
    CertificateService,
    CreateTcertParams,
    CreateTcertResult,
)
from .endpointService import EndpointService, normalize_endpoint
from .onlineService import ImportedStatement, OnlineService
from .revocationService import (
    BlockSdocParams,
    RevocationCheck,
    RevocationService,
    RevokeKeyParams,
    RevokeTcertParams,
    StatementResult,
)
from .signingService import IssueSdocParams, IssueSdocResult, SigningService
from .statement import (
    BuiltStatement,
    ParsedStatement,
    StatementOptions,
    StatementTarget,
    build_statement,
    decode_target,
    encode_target,
    parse_statement,
    verify_statement,
)
from .trustService import (
    AddTcertParams,
    AttestParams,
    TrustResolution,
    TrustService,
)
from .verificationService import VerificationResult, VerificationService, VerifyOptions

__all__ = [
    "ATTACHMENT_ID_HEX",
    "AttachmentService",
    "BuildAttachmentParams",
    "BuiltAttachment",
    "ParsedAttachment",
    "attachment_id_of",
    "build_attachment",
    "parse_attachment",
    "verify_attachment",
    "CertificateService",
    "CreateTcertParams",
    "CreateTcertResult",
    "EndpointService",
    "normalize_endpoint",
    "ImportedStatement",
    "OnlineService",
    "BlockSdocParams",
    "RevocationCheck",
    "RevocationService",
    "RevokeKeyParams",
    "RevokeTcertParams",
    "StatementResult",
    "IssueSdocParams",
    "IssueSdocResult",
    "SigningService",
    "BuiltStatement",
    "ParsedStatement",
    "StatementOptions",
    "StatementTarget",
    "build_statement",
    "decode_target",
    "encode_target",
    "parse_statement",
    "verify_statement",
    "AddTcertParams",
    "AttestParams",
    "TrustResolution",
    "TrustService",
    "VerificationResult",
    "VerificationService",
    "VerifyOptions",
]