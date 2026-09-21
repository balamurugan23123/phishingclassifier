"""Opt-in deep analysis of attachment CONTENT (embedded macros).

The default pipeline only inspects attachment *metadata* (extension, size,
hash) because that keeps attacker payloads out of memory and is fast. This
module is invoked only when the operator explicitly asks for it
(``analyze --deep-attachments``): it is handed raw attachment bytes and looks
for VBA macros, which are the payload in most targeted phishing lures.

Baseline detection is pure stdlib -- an OOXML document is a ZIP and a
``vbaProject.bin`` member means macros are present regardless of what the file
extension claims. If the optional ``oletools`` package is installed it is used
to add depth on legacy OLE2 (.doc/.xls/.ppt) containers and to surface
suspicious macro behaviour (auto-exec entry points, shell/download calls).
"""

from __future__ import annotations

import io
import logging
import zipfile
from typing import Any, Dict, List

from .heuristics import W_HIGH, W_MEDHIGH, _signal

logger = logging.getLogger(__name__)

# DoS guards: never blow up on a huge or numerous attachment set.
MAX_SCAN_BYTES = 25 * 1024 * 1024
MAX_SCAN_ATTACHMENTS = 20

_ZIP_MAGIC = b"PK\x03\x04"
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe7"

_MACRO_MEMBER = "vbaproject.bin"
# extensions that legitimately declare a macro-enabled Office document
_MACRO_EXT = (".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam", ".ppam")
# auto-exec entry points that run when a document is opened
_VBA_AUTOEXEC = (
    "autoopen",
    "autonew",
    "autoexec",
    "document_open",
    "document_beforesave",
    "worksheet_activate",
    "worksheet_selectionchange",
)
# high-risk API calls inside macro code
_VBA_DANGER = (
    "shell(",
    "environ(",
    "urldownloadtofile",
    "msxml2.xmlhttp",
    "winhttp.request",
    "powershell",
    "cmd /c",
    'createobject("wscript.shell',
    "frombase64string",
)


def _ext(name: str) -> str:
    lower = name.lower()
    return lower[lower.rfind(".") :] if "." in lower else ""


def _scan_ooxml(data: bytes, filename: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return out
    if any(_MACRO_MEMBER in n.lower() for n in names):
        if _ext(filename) in _MACRO_EXT:
            out.append(
                _signal(
                    "attachment_macro_document",
                    W_HIGH,
                    "Macro-enabled Office document",
                    filename,
                )
            )
        else:
            # a VBA project inside a supposedly macro-free .docx/.xlsx is a
            # renaming/sanitisation evasion -- strongly malicious
            out.append(
                _signal(
                    "attachment_concealed_macro",
                    W_HIGH,
                    "Office document embeds a VBA project but its extension "
                    "claims a macro-free format",
                    filename,
                )
            )
    return out


def _scan_ole2(data: bytes, filename: str) -> List[Dict[str, Any]]:
    """Legacy compound-file (.doc/.xls/.ppt) macro scan.

    Without oletools installed we cannot reliably parse the OLE directory for
    VBA, so we defer entirely to the caller's extension heuristic and add
    nothing here. With oletools we extract the VBA source and inspect it.
    """
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        logger.debug("oletools not installed; skipping OLE2 macro extraction for %s", filename)
        return []

    chunks: List[str] = []
    try:
        vp = VBA_Parser(io.BytesIO(data))
        try:
            if vp.detect_vba_macros():
                for _ct, _cn, _fn, code in vp.extract_macros():
                    chunks.append((code or "").lower())
        finally:
            vp.close()
    except Exception:
        logger.debug("olevba failed on %s", filename, exc_info=True)
        return []

    if not chunks:
        return []

    src = "\n".join(chunks)
    auto = [t for t in _VBA_AUTOEXEC if t in src]
    danger = [t for t in _VBA_DANGER if t in src]
    out = [
        _signal(
            "attachment_macro_document",
            W_HIGH,
            "Office document contains VBA macros",
            f"{filename}; auto-exec entry points: {', '.join(auto) or 'none detected'}",
        )
    ]
    if danger:
        out.append(
            _signal(
                "attachment_macro_suspicious_api",
                W_HIGH,
                "Embedded macro calls high-risk APIs (download/exec)",
                f"{filename}; {', '.join(danger[:6])}",
            )
        )
    elif auto:
        out.append(
            _signal(
                "attachment_macro_autoexec",
                W_MEDHIGH,
                "Macro auto-executes when the document is opened",
                f"{filename}; {', '.join(auto)}",
            )
        )
    return out


def analyze_bytes(data: bytes, filename: str) -> List[Dict[str, Any]]:
    """Deep-scan one attachment's raw bytes and return any signals."""
    if len(data) > MAX_SCAN_BYTES:
        logger.debug("skip oversized attachment %s (%d bytes)", filename, len(data))
        return []
    magic = data[:8]
    if magic[:4] == _ZIP_MAGIC:
        return _scan_ooxml(data, filename)
    if magic == _OLE2_MAGIC:
        return _scan_ole2(data, filename)
    return []


def analyze_eml(path: str) -> List[Dict[str, Any]]:
    """Re-read an .eml and deep-scan every attachment payload (bounded)."""
    from .parser import iter_attachment_bytes

    findings: List[Dict[str, Any]] = []
    for index, (name, data) in enumerate(iter_attachment_bytes(path)):
        if index >= MAX_SCAN_ATTACHMENTS:
            logger.debug("hit attachment scan cap (%d) for %s", MAX_SCAN_ATTACHMENTS, path)
            break
        findings.extend(analyze_bytes(data, name))
    return findings
