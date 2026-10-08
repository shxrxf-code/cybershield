"""Email detection: RFC 5322 parsing plus header, body, URL and attachment analysis."""

from app.detection_engine.email.analyzer import (
    EmailAnalysisResult,
    analyse_email,
    summarise_parsed,
)
from app.detection_engine.email.header_analyzer import (
    analyse_attachments,
    analyse_authentication,
    analyse_headers,
    analyse_identity,
)
from app.detection_engine.email.parser import EmailAttachment, ParsedEmail, parse_email

__all__ = [
    "EmailAnalysisResult",
    "EmailAttachment",
    "ParsedEmail",
    "analyse_attachments",
    "analyse_authentication",
    "analyse_email",
    "analyse_headers",
    "analyse_identity",
    "parse_email",
    "summarise_parsed",
]