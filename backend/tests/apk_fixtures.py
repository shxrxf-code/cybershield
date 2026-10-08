"""Synthetic AXML builder used to test the binary manifest parser.

There is no legitimate way to obtain a real ``AndroidManifest.xml`` without an
Android SDK, and shipping a real APK into a test suite would mean committing
something a malware scanner's CI might then flag. Instead these helpers emit a
byte-for-byte valid compiled manifest for the documented chunk format, which
tests the parser against the format rather than against a sample.

The builder is deliberately minimal: it supports what the tests need (a UTF-8
string pool and start/end element chunks with string or boolean attributes).
"""

from __future__ import annotations

import struct
import zlib
from typing import Any

# Chunk types, mirrored from app.detection_engine.apk.manifest.
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
START_NAMESPACE = 0x0100
END_NAMESPACE = 0x0101
START_ELEMENT = 0x0102
END_ELEMENT = 0x0103

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12
TYPE_FLOAT = 0x04

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# ZIP entry used for the APK Signature Scheme v2/v3 signing block.
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


# ---------------------------------------------------------------------------
# Minimal DER / PKCS#7 certificate builders for v1-signature tests
# ---------------------------------------------------------------------------


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der(0x02, raw)


def _der_oid(hex_encoded: str) -> bytes:
    return _der(0x06, bytes.fromhex(hex_encoded))


def _der_string_tag(name: str) -> tuple[int, bytes]:
    """``(tag, oid_bytes)`` for a common name attribute."""
    table = {
        "CN": (0x0C, "550403"),
        "O": (0x0C, "55040a"),
        "OU": (0x0C, "55040b"),
    }
    return table[name]


def _der_name(attributes: dict[str, str]) -> bytes:
    """Build an X.509 ``Name`` from ``{CN: ..., O: ..., OU: ...}``."""
    rdns = bytearray()
    for key, value in attributes.items():
        tag, oid_hex = _der_string_tag(key)
        atv = _der(
            0x30,
            _der_oid(oid_hex) + _der(tag, value.encode("utf-8")),
        )
        rdns += _der(0x31, atv)  # SET OF AttributeTypeAndValue
    return _der(0x30, bytes(rdns))


def build_self_signed_cert(*, subject: dict[str, str], issuer: dict[str, str]) -> bytes:
    """Build a minimal self-signed-like X.509 v3 certificate DER.

    The public key is a placeholder (a zero-length ``BIT STRING``): the parser
    under test only reads the fingerprint and the subject/issuer names, so this
    fixture does not pretend to hold a usable key.
    """
    serial = _der_integer(1)
    signature_alg = _der(
        0x30, _der_oid("2a864886f70d01010b") + _der(0x05, b"")  # sha256WithRSA + NULL
    )
    validity = _der(
        0x30,
        _der(0x17, b"260101000000Z") + _der(0x17, b"370101000000Z"),  # UTC time
    )
    spki = _der(
        0x30,
        _der(
            0x30,
            _der_oid("2a864886f70d010101") + _der(0x05, b""),  # rsaEncryption + NULL
        )
        + _der(0x03, b"\x00\x00"),  # BIT STRING placeholder
    )

    tbs = _der(
        0x30,
        _der(0xA0, _der_integer(2))  # version [0] EXPLICIT INTEGER 2
        + serial
        + signature_alg
        + _der_name(issuer)
        + validity
        + _der_name(subject)
        + spki,
    )
    return _der(0x30, tbs + signature_alg + _der(0x03, b"\x00\x00"))


def build_pkcs7_signed_data(certificates: list[bytes]) -> bytes:
    """Wrap one or more certificates in a DER PKCS#7 SignedData container.

    The digest/signer sections are empty shells; only the certificate chain is
    populated, which is exactly what the v1 certificate extractor consumes.
    """
    digest_algorithms = _der(
        0x31,
        _der(
            0x30,
            _der_oid("608648016503040201") + _der(0x05, b""),  # sha-256 + NULL
        ),
    )
    content_info = _der(
        0x30, _der_oid("2a864886f70d010701")  # data content type
    )
    certs_field = _der(0xA0, b"".join(certificates))
    signer_infos = _der(0x31, _der(0x30, _der_integer(1)))  # minimal SignerInfo

    signed_data = _der(
        0x30,
        _der_integer(1)
        + digest_algorithms
        + content_info
        + certs_field
        + signer_infos,
    )
    return _der(
        0x30,
        _der_oid("2a864886f70d010702")  # signedData content type
        + _der(0xA0, signed_data),
    )


def _to_mutf8(value: str) -> bytes:
    """Encode a Python string as DEX modified UTF-8.

    MUTF-8 encodes U+0000 as ``C0 80`` and splits supplementary code points into
    two three-byte CESU-8 surrogate halves, which is what the DEX reader must
    unwind.
    """
    out = bytearray()
    for character in value:
        codepoint = ord(character)
        if codepoint == 0:
            out += b"\xc0\x80"
        elif codepoint <= 0x7F:
            out.append(codepoint)
        elif codepoint <= 0x7FF:
            out += bytes(
                [0xC0 | (codepoint >> 6), 0x80 | (codepoint & 0x3F)]
            )
        elif codepoint <= 0xFFFF:
            out += bytes(
                [
                    0xE0 | (codepoint >> 12),
                    0x80 | ((codepoint >> 6) & 0x3F),
                    0x80 | (codepoint & 0x3F),
                ]
            )
        else:
            value_minus_one = codepoint - 0x10000
            high = 0xD800 + (value_minus_one >> 10)
            low = 0xDC00 + (value_minus_one & 0x3FF)
            for surrogate in (high, low):
                out += bytes(
                    [
                        0xE0 | (surrogate >> 12),
                        0x80 | ((surrogate >> 6) & 0x3F),
                        0x80 | (surrogate & 0x3F),
                    ]
                )
    return bytes(out)


def _uleb128(value: int) -> bytes:
    """Encode an unsigned LEB128 integer."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_dex_file(strings: list[str], *, version: bytes = b"035\0") -> bytes:
    """Build a minimal valid DEX with the given strings in its string table.

    The header is byte-for-byte valid including the Adler-32 checksum, so the
    reader's checksum check passes and the string table can be decoded.
    """
    string_data = bytearray()
    offsets: list[int] = []
    for value in strings:
        offsets.append(len(string_data))
        string_data += _uleb128(len(value))
        string_data += _to_mutf8(value) + b"\x00"

    string_ids_off = 112
    data_off = string_ids_off + len(offsets) * 4
    data_off = (data_off + 3) & ~3
    alignment = data_off - (string_ids_off + len(offsets) * 4)
    string_data = b"\x00" * alignment + bytes(string_data)

    id_table = b"".join(struct.pack("<I", data_off + offset) for offset in offsets)
    file_size = data_off + len(string_data)

    header = bytearray(b"\x00" * 112)
    header[0:8] = b"dex\n" + version
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, 112)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<I", header, 52, 0)       # map_off
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 104, len(string_data))
    struct.pack_into("<I", header, 108, data_off)

    body = bytearray(header) + bytearray(id_table) + bytearray(string_data)
    checksum = zlib.adler32(body[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", body, 8, checksum)
    return bytes(body)


def build_apk_zip(
    entries: dict[str, bytes],
    *,
    sig_pairs: list[tuple[int, bytes]] | None = None,
) -> bytes:
    """Build a stored (uncompressed) ZIP, optionally with an APK signing block.

    Args:
        entries: Member name -> bytes, written uncompressed with a fixed DOS
            timestamp so output is deterministic.
        sig_pairs: ``(block_id, value)`` pairs placed into an APK Signature
            Scheme v2/v3 signing block between the entries and the central
            directory.

    Returns:
        Complete ZIP bytes including the end-of-central-directory record.
    """
    out = bytearray()
    central = bytearray()

    for raw_name, data in entries.items():
        name = raw_name.encode("utf-8")
        local_offset = len(out)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        local_header = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,  # local file header signature
            20,          # version needed
            0,           # flags (no data descriptor)
            0,           # method: stored
            0,           # mod time
            0x21,        # mod date (fixed, deterministic)
            crc,
            len(data),
            len(data),
            len(name),
            0,           # extra length
        )
        out += local_header + name + data

        central_header = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,      # central directory signature
            20,              # version made by
            20,              # version needed
            0,               # flags
            0,               # method
            0,               # mod time
            0x21,            # mod date
            crc,
            len(data),
            len(data),
            len(name),
            0,               # extra length
            0,               # comment length
            0,               # disk number
            0,               # internal attrs
            0,               # external attrs
            local_offset,
        )
        central += central_header + name

    if sig_pairs:
        pairs = b"".join(
            struct.pack("<QI", 12 + len(value), pair_id) + value
            for pair_id, value in sig_pairs
        )
        block_size = 8 + len(pairs)
        signing_block = struct.pack("<Q", block_size) + pairs
        out += signing_block
        out += struct.pack("<Q", block_size)
        out += APK_SIG_BLOCK_MAGIC

    central_offset = len(out)
    out += central
    entry_count = len(entries)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,   # EOCD signature
        0,            # disk number
        0,            # cd disk
        entry_count,
        entry_count,
        len(central),
        central_offset,
        0,            # comment length
    )
    out += eocd
    return bytes(out)


def _utf8_len(value: str) -> bytes:
    """Encode the aapt UTF-8 string length prefix pair."""
    encoded = value.encode("utf-8")
    utf16_units = len(value.encode("utf-16-le")) // 2

    if utf16_units > 0x7F:
        utf16_field = bytes([(0x80 | (utf16_units >> 8)), utf16_units & 0xFF])
    else:
        utf16_field = bytes([utf16_units])

    if len(encoded) > 0x7F:
        byte_field = bytes([(0x80 | (len(encoded) >> 8)), len(encoded) & 0xFF])
    else:
        byte_field = bytes([len(encoded)])
    return utf16_field + byte_field + encoded + b"\x00"


def build_string_pool(strings: list[str]) -> tuple[bytes, dict[str, int]]:
    """Build a RES_STRING_POOL chunk and a name -> index map."""
    offsets: list[int] = []
    blob = bytearray()
    for value in strings:
        offsets.append(len(blob))
        blob += _utf8_len(value)
    blob += b"\x00"  # pool terminator

    header_size = 28
    strings_start = header_size + len(strings) * 4
    # Offsets must be 4-byte aligned for the reader's benefit.
    padding = (-len(blob)) % 4
    blob += b"\x00" * padding

    chunk_size = strings_start + len(blob)
    header = struct.pack(
        "<HHIIIIII",
        RES_STRING_POOL,
        header_size,
        chunk_size,
        len(strings),
        0,          # styleCount
        1 << 8,     # UTF8_FLAG
        strings_start,
        0,          # stylesStart
    )
    offset_table = b"".join(struct.pack("<I", offset) for offset in offsets)
    chunk = header + offset_table + bytes(blob)
    return chunk, {value: index for index, value in enumerate(strings)}


def _attr_value(value: Any) -> tuple[int, int, int]:
    """Return ``(data_type, data, is_string)`` for an attribute value.

    ``data`` is the raw 32-bit ``Res_value.data`` payload: the boolean/int
    value directly, or 0 for strings (their pool index travels in the raw
    field). ``res0`` is always 0; ``size`` is always 8.
    """
    if isinstance(value, bool):
        return TYPE_INT_BOOLEAN, 1 if value else 0, False
    if isinstance(value, int):
        return TYPE_INT_DEC, value, False
    if isinstance(value, float):
        return TYPE_FLOAT, struct.unpack("<I", struct.pack("<f", value))[0], False
    if isinstance(value, str):
        return TYPE_STRING, 0, True
    raise TypeError(f"unsupported fixture attribute value: {value!r}")


class _StringCollector:
    """Accumulates strings and hands back their pool indices."""

    def __init__(self) -> None:
        self.values: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self.values)
            self.values.append(value)
        return self._index[value]

    @property
    def namespace(self) -> int:
        return self.add(ANDROID_NS)


def build_manifest_xml(manifest_attrs: dict[str, Any]) -> bytes:
    """Build a compiled manifest with one ``<manifest>`` element.

    Args:
        manifest_attrs: ``android:name``-style attributes for the root element.

    Returns:
        Bytes of a valid ``RES_XML_TYPE`` resource.
    """
    return build_manifest_tree(manifest_attrs, [])


#: An element spec for :func:`build_manifest_tree`:
#: ``(tag, {attr: value}, [child_spec, ...])``.
ElementSpec = tuple[str, dict[str, Any], list["ElementSpec"]]


def build_manifest_tree(
    manifest_attrs: dict[str, Any], children: list[ElementSpec]
) -> bytes:
    """Build a compiled manifest with a ``<manifest>`` element and children.

    Args:
        manifest_attrs: Attribtes for the root ``<manifest>`` element.
        children: Child element specs (e.g. ``uses-permission``, ``application``).

    Returns:
        Bytes of a valid ``RES_XML_TYPE`` resource with nested elements.
    """
    collector = _StringCollector()
    ns_index = collector.namespace
    android_prefix = collector.add("android")
    manifest_name = collector.add("manifest")

    def encode_attrs(attrs: dict[str, Any]) -> list[tuple[int, int, int, int, int]]:
        encoded: list[tuple[int, int, int, int, int]] = []
        for key, value in attrs.items():
            if key.startswith("android:"):
                attr_ns, name = ns_index, key[len("android:") :]
            else:
                # No namespace: aapt writes the "no namespace" marker here.
                attr_ns, name = 0xFFFFFFFF, key
            name_index = collector.add(name)
            data_type, data, is_string = _attr_value(value)
            raw_index = collector.add(value) if is_string else 0xFFFFFFFF
            encoded.append((attr_ns, name_index, raw_index, data_type, data))
        return encoded

    def prepare(spec: ElementSpec) -> tuple[int, list[Any], list[tuple[int, list[Any], list[Any]]]]:
        tag, attrs, subs = spec
        name_index = collector.add(tag)
        return (name_index, encode_attrs(attrs), [prepare(sub) for sub in subs])

    manifest_encoded = encode_attrs(manifest_attrs)
    # Phase 1 collects every string (tags, names, values). The pool must be
    # built only after this pass so newly registered indices are consistent.
    prepared_children = [prepare(spec) for spec in children]

    pool_chunk, _ = build_string_pool(collector.values)

    def element_chunk(name_index: int, attrs: list[tuple[int, int, int, int, int]]) -> bytes:
        attr_blob = b"".join(
            struct.pack("<IIIHBBI", ns, attr_name, raw, 8, 0, data_type, data)
            for ns, attr_name, raw, data_type, data in attrs
        )
        element_body = struct.pack("<II", ns_index, name_index)
        element_body += struct.pack("<HHH", 20, 20, len(attrs))
        element_body += struct.pack("<HHH", 0, 0, 0)  # id, class, style index
        element_size = 16 + len(element_body) + len(attr_blob)
        start = struct.pack("<HHIII", START_ELEMENT, 16, element_size, 1, 0xFFFFFFFF)
        return start + element_body + attr_blob

    def end_chunk(name_index: int) -> bytes:
        end = struct.pack("<HHIII", END_ELEMENT, 16, 24, 1, 0xFFFFFFFF)
        return end + struct.pack("<II", ns_index, name_index)

    def emit(prepared: tuple[int, list[Any], list[Any]]) -> bytes:
        name_index, attrs, subs = prepared
        out = element_chunk(name_index, attrs)
        for sub in subs:
            out += emit(sub)
        out += end_chunk(name_index)
        return out

    namespace_chunk = struct.pack("<HHIII", START_NAMESPACE, 16, 24, 1, 0xFFFFFFFF)
    namespace_chunk += struct.pack("<II", android_prefix, ns_index)

    body = pool_chunk + namespace_chunk
    body += element_chunk(manifest_name, manifest_encoded)
    for prepared in prepared_children:
        body += emit(prepared)
    body += end_chunk(manifest_name)

    header = struct.pack("<HHI", RES_XML, 8, 8 + len(body))
    return header + body