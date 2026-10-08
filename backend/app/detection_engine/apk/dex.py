"""Read-only DEX (Dalvik Executable) string table extractor.

Classes.dex is where an APK's payload lives. We never disassemble or interpret
bytecode - executing or "understanding" the code would hand analysis to a
potential sandbox-evading program. What this module does is far narrower: it
reads the *metadata* strings the developer chose to embed (package names,
permission names, class names, URLs), because those survive compression
independent of bytecode and are used by the analyzer as corroborating evidence.

Format reference: the official ``dex-format`` document from AOSP.

Robustness
----------
Like the manifest parser this module is strict about structure and tolerant of
bad data. A truncated, fuzzed or deliberately malformed DEX yields whatever
strings could be decoded plus a recorded error, not an exception that aborts the
scan. Offsets are bounds-checked; a crafted ``string_data_off`` cannot walk the
reader off the buffer.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field

#: Hard bound so a malicious header cannot force an unbounded allocation.
MAX_STRING_IDS: int = 1_048_576
#: Maximum length of a single embedded string we will decode.
MAX_STRING_BYTES: int = 65_536
#: The MUTF-8 flavour used by DEX represents a NUL byte as ``C0 80``.
_MUTF8_NUL: bytes = b"\xc0\x80"

_DEX_MAGIC: bytes = b"dex\n"


class DexParseError(Exception):
    """Raised only when the input is not a DEX file at all."""


@dataclass(slots=True)
class DexInfo:
    """Metadata and strings decoded from one ``classes*.dex`` member."""

    version: str
    file_size: int
    string_count: int
    class_count: int
    method_count: int
    strings: list[str] = field(default_factory=list)
    #: SHA-256 of the raw DEX, useful as evidence of identity.
    sha256: str = ""
    checksum_valid: bool = False
    parse_errors: list[str] = field(default_factory=list)
    truncated: bool = False


def read_dex_strings(data: bytes) -> DexInfo:
    """Decode the string table and structure counts of a DEX file.

    Args:
        data: Raw bytes of a ``classes.dex`` member.

    Returns:
        A :class:`DexInfo` with the decoded strings and header metadata.

    Raises:
        DexParseError: If the data is not recognisably a DEX file (wrong magic
            or an implausible header size).
    """
    if len(data) < 112:
        raise DexParseError("DEX header is too small")
    if data[:4] != _DEX_MAGIC:
        raise DexParseError("missing 'dex\\n' magic, not a DEX file")

    version_bytes = data[4:8]
    version = version_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
    if not version:
        version = "?"

    file_size, header_size = struct.unpack_from("<II", data, 32)
    if header_size < 112:
        raise DexParseError(f"implausible DEX header size {header_size}")

    endian_tag = struct.unpack_from("<I", data, 40)[0]
    if endian_tag == 0x12345678:
        endian = "<"
    elif endian_tag == 0x78563412:
        endian = ">"
    else:
        raise DexParseError(f"unknown DEX endian tag 0x{endian_tag:08x}")

    (
        _link_size,
        _link_off,
        _map_off,
        string_ids_size,
        string_ids_off,
        _type_ids_size,
        _type_ids_off,
        _proto_ids_size,
        _proto_ids_off,
        _field_ids_size,
        _field_ids_off,
        method_ids_size,
        _method_ids_off,
        class_defs_size,
        _class_defs_off,
        _data_size,
        _data_off,
    ) = struct.unpack_from("<17I", data, 44)

    effective_size = min(file_size, len(data))
    checksum_adler = zlib.adler32(data[12:effective_size]) & 0xFFFFFFFF
    stored_checksum = struct.unpack_from("<I", data, 8)[0]
    checksum_valid = stored_checksum == checksum_adler

    info = DexInfo(
        version=version,
        file_size=file_size,
        string_count=min(string_ids_size, MAX_STRING_IDS),
        class_count=class_defs_size,
        method_count=method_ids_size,
        sha256=hashlib.sha256(data[:effective_size]).hexdigest(),
        checksum_valid=checksum_valid,
    )

    if string_ids_size > MAX_STRING_IDS:
        info.truncated = True
        info.parse_errors.append(
            f"string_ids_size {string_ids_size} exceeds the {MAX_STRING_IDS} cap"
        )

    string_ids_size = min(string_ids_size, MAX_STRING_IDS)
    table_end = string_ids_off + string_ids_size * 4
    if table_end > effective_size:
        info.truncated = True
        info.parse_errors.append("string_id table extends past end of file")
        string_ids_size = max(0, (effective_size - string_ids_off) // 4)

    for index in range(string_ids_size):
        position = string_ids_off + index * 4
        if position + 4 > effective_size:
            break
        (string_data_off,) = struct.unpack_from(f"<I", data, position)
        try:
            text = _read_string(data, string_data_off, effective_size)
        except (struct.error, IndexError):
            info.parse_errors.append(f"string #{index} offset {string_data_off} out of bounds")
            text = ""
        if text:
            info.strings.append(text)

    if info.truncated and not info.strings:
        info.parse_errors.append("no strings could be decoded")

    return info


def _read_string(data: bytes, offset: int, file_end: int) -> str:
    """Decode one MUTF-8 string at ``offset`` (uleb128 length + bytes)."""
    if offset >= file_end:
        raise IndexError("string data offset out of bounds")

    _utf16_size, offset = _read_uleb128(data, offset, file_end)
    if offset >= file_end:
        return ""

    start = offset
    while offset < file_end and data[offset] != 0x00 and (offset - start) < MAX_STRING_BYTES:
        offset += 1
    if offset >= file_end:
        return ""

    raw = data[start:offset]
    try:
        return _decode_mutf8(raw)
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def _read_uleb128(data: bytes, offset: int, file_end: int) -> tuple[int, int]:
    """Decode a ULEB128 unsigned integer, returning ``(value, next_offset)``."""
    result = 0
    shift = 0
    while True:
        if offset >= file_end:
            raise IndexError("uleb128 runs past end of file")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def _decode_mutf8(raw: bytes) -> str:
    """Decode modified UTF-8 (DEX flavour) into a Python string.

    MUTF-8 differs from UTF-8 in two ways, both of which plain ``decode``
    mishandles:
    - U+0000 is encoded as ``C0 80`` instead of ``00``.
    - Supplementary characters are split into two three-byte surrogate halves,
      exactly like CESU-8.
    Reconstructing proper Unicode is required so that identifiers comparing
    against a suspicious-token list (which are pure ASCII) still match, and so
    that genuine multi-byte text is presented readably rather than as replace
    characters.
    """
    if _MUTF8_NUL not in raw and b"\xed\xa0" not in raw and b"\xed\xb0" not in raw:
        return raw.decode("utf-8", errors="replace")

    out = bytearray()
    index = 0
    length = len(raw)
    while index < length:
        byte = raw[index]
        if raw[index : index + 2] == _MUTF8_NUL:
            out.append(0x00)
            index += 2
            continue
        # CESU-8 surrogate pair: three-byte high half (ED A0..AF) followed by
        # a three-byte low half (ED B0..BF). Reassembled into the supplementary
        # code point and encoded as proper UTF-8.
        if (
            byte == 0xED
            and index + 6 <= length
            and (raw[index + 1] & 0xC0) == 0x80
            and (raw[index + 2] & 0xC0) == 0x80
            and raw[index + 3] == 0xED
            and (raw[index + 4] & 0xC0) == 0x80
            and (raw[index + 5] & 0xC0) == 0x80
        ):
            high = (
                ((raw[index] & 0x0F) << 12)
                | ((raw[index + 1] & 0x3F) << 6)
                | (raw[index + 2] & 0x3F)
            )
            low = (
                ((raw[index + 3] & 0x0F) << 12)
                | ((raw[index + 4] & 0x3F) << 6)
                | (raw[index + 5] & 0x3F)
            )
            if 0xD800 <= high <= 0xDBFF and 0xDC00 <= low <= 0xDFFF:
                codepoint = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                out += chr(codepoint).encode("utf-8")
                index += 6
                continue
        out.append(byte)
        index += 1
    return bytes(out).decode("utf-8", errors="replace")


__all__ = [
    "DexInfo",
    "DexParseError",
    "read_dex_strings",
]