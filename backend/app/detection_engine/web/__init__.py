"""Web content analysis package (bounded, non-executing)."""

from app.detection_engine.web.content import WebContentResult, analyse_web_content

__all__ = ["WebContentResult", "analyse_web_content"]