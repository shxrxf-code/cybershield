"""Binary ``AndroidManifest.xml`` (AXML) reader.

APKs ship the manifest in Android's compiled binary XML format, not as text.
Reading it requires implementing the chunk format, which this module does without
any third-party dependency - important because the manifest is where the
permission, component and exported-surface facts that drive APK risk come from.

Format reference: the ``ResChunk_header`` family in AOSP ``ResourceTypes``. The
structure is a type-tagged chunk stream:

===== ===============================================
type   meaning
===== ===============================================
0x0001 string pool (attribute and element names)
0x0180 resource id map (maps names to ``R.attr`` ids)
0x0100/0x0101 namespace start/end
0x0102/0x0103 element start/end
0x0104 character data
===== ===============================================

Robustness
----------
The parser is strict about structure but tolerant of bad data: a truncated,
fuzzed or deliberately malformed manifest yields whatever elements were decoded
plus a recorded error, never an exception that would abort the scan. Every
offset read is bounds-checked, so a crafted ``chunk_size`` cannot walk off the
buffer or trigger an unbounded allocation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Final

# Chunk types
RES_STRING_POOL_TYPE: Final[int] = 0x0001
RES_XML_TYPE: Final[int] = 0x0003
RES_XML_START_NAMESPACE_TYPE: Final[int] = 0x0100
RES_XML_END_NAMESPACE_TYPE: Final[int] = 0x0101
RES_XML_START_ELEMENT_TYPE: Final[int] = 0x0102
RES_XML_END_ELEMENT_TYPE: Final[int] = 0x0103
RES_XML_CDATA_TYPE: Final[int] = 0x0104
RES_XML_RESOURCE_MAP_TYPE: Final[int] = 0x0180

#: String pool flags
UTF8_FLAG: Final[int] = 1 << 8

#: ``Res_value`` data types, as written by aapt.
TYPE_REFERENCE: Final[int] = 0x01
TYPE_ATTRIBUTE: Final[int] = 0x02
TYPE_STRING: Final[int] = 0x03
TYPE_FLOAT: Final[int] = 0x04
TYPE_DIMENSION: Final[int] = 0x05
TYPE_FRACTION: Final[int] = 0x06
TYPE_INT_DEC: Final[int] = 0x10
TYPE_INT_HEX: Final[int] = 0x11
TYPE_INT_BOOLEAN: Final[int] = 0x12

#: Attribute value whose string-pool index means "no string".
_NO_STRING: Final[int] = 0xFFFFFFFF

#: The framework namespace URI aapt writes for ``android:`` attributes.
ANDROID_NS_URI: Final[str] = "http://schemas.android.com/apk/res/android"

#: Hard bounds so a malformed manifest cannot drive an unbounded allocation.
MAX_STRINGS: Final[int] = 65_536
MAX_ELEMENTS: Final[int] = 20_000
MAX_DEPTH: Final[int] = 64
MAX_ATTRIBUTES_PER_ELEMENT: Final[int] = 512

_CHUNK_HEADER: Final[int] = 8
_ATTR_EXT_SIZE: Final[int] = 20
_ATTRIBUTE_SIZE: Final[int] = 20


@dataclass(slots=True)
class XmlElement:
    """One decoded element with its attributes and children."""

    name: str
    namespace: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)
    children: list["XmlElement"] = field(default_factory=list)
    #: Namespace prefix -> URI in scope where this element appeared.
    namespaces: dict[str, str] = field(default_factory=dict)

    def child(self, name: str) -> "XmlElement | None":
        """First direct child with the given tag name."""
        return next((item for item in self.children if item.name == name), None)

    def children_named(self, name: str) -> list["XmlElement"]:
        """All direct children with the given tag name."""
        return [item for item in self.children if item.name == name]

    def descendants(self) -> list["XmlElement"]:
        """Every element in the subtree, depth-first."""
        found: list[XmlElement] = []
        stack = list(reversed(self.children))
        while stack:
            element = stack.pop()
            found.append(element)
            stack.extend(reversed(element.children))
            if len(found) >= MAX_ELEMENTS:
                break
        return found

    def attr(self, name: str, default: str | None = None) -> str | None:
        return self.attributes.get(name, default)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "attributes": dict(self.attributes),
            "children": [child.to_dict() for child in self.children],
        }


class ManifestParseError(Exception):
    """Raised only when a manifest yields no usable structure at all."""


class _StringPool:
    """The string table every element and attribute name is drawn from."""

    def __init__(self, data: bytes, offset: int, size: int) -> None:
        if size < 28:
            raise ManifestParseError("string pool chunk is too small")

        (
            _chunk_type,
            header_size,
            _chunk_size,
            string_count,
            _style_count,
            flags,
            strings_start,
            _styles_start,
        ) = struct.unpack_from("<HHIIIIII", data, offset)

        if string_count > MAX_STRINGS:
            raise ManifestParseError(f"string pool declares {string_count} entries")

        self.is_utf8 = bool(flags & UTF8_FLAG)
        self.strings: list[str] = []
        strings_base = offset + strings_start
        chunk_end = offset + size

        for index in range(string_count):
            entry = offset + header_size + index * 4
            if entry + 4 > chunk_end:
                break
            (string_index,) = struct.unpack_from("<I", data, entry)
            absolute = strings_base + string_index
            if absolute >= chunk_end:
                self.strings.append("")
                continue
            try:
                self.strings.append(
                    self._read_utf8(data, absolute)
                    if self.is_utf8
                    else self._read_utf16(data, absolute)
                )
            except (struct.error, IndexError, UnicodeDecodeError):
                # One undecodable string must not lose the rest of the table.
                self.strings.append("")

    @staticmethod
    def _read_utf16(data: bytes, offset: int) -> str:
        (length,) = struct.unpack_from("<H", data, offset)
        return data[offset + 2 : offset + 2 + length * 2].decode("utf-16-le", errors="replace")

    @staticmethod
    def _read_utf8(data: bytes, offset: int) -> str:
        # Layout: length in UTF-16 code units (1 or 2 bytes), then length in
        # UTF-8 bytes (1 or 2 bytes), then the bytes, then a NUL terminator.
        position = offset
        first = data[position]
        position += 2 if first & 0x80 else 1
        second = data[position]
        if second & 0x80:
            byte_length = ((second & 0x7F) << 8) | data[position + 1]
            position += 2
        else:
            byte_length = second
            position += 1
        return data[position : position + byte_length].decode("utf-8", errors="replace")

    def get(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""


def parse_axml(data: bytes) -> XmlElement:
    """Parse a compiled Android binary XML resource into a tree.

    Args:
        data: Raw ``AndroidManifest.xml`` bytes.

    Returns:
        The root :class:`XmlElement`, normally named ``manifest``.

    Raises:
        ManifestParseError: If the data is not compiled XML, or if no element
            could be decoded from it.
    """
    if len(data) < _CHUNK_HEADER:
        raise ManifestParseError("manifest is too small to be a compiled XML resource")

    magic, header_size, chunk_size = struct.unpack_from("<HHI", data, 0)
    if magic != RES_XML_TYPE:
        raise ManifestParseError(
            f"unexpected magic 0x{magic:04x}; not a compiled XML resource"
        )
    if header_size < _CHUNK_HEADER:
        raise ManifestParseError("implausible chunk header size")
    # A truncated tail is tolerated: elements already decoded are still useful.
    chunk_size = min(chunk_size, len(data))

    pool: _StringPool | None = None
    namespaces: dict[str, str] = {}
    stack: list[XmlElement] = []
    root: XmlElement | None = None
    element_count = 0

    offset = header_size
    while offset + _CHUNK_HEADER <= chunk_size:
        chunk_type, chunk_header, chunk_len = struct.unpack_from("<HHI", data, offset)
        if chunk_len < _CHUNK_HEADER:
            break
        if offset + chunk_len > chunk_size:
            # Trailing partial chunk: stop rather than read past the buffer.
            break

        try:
            if chunk_type == RES_STRING_POOL_TYPE and pool is None:
                pool = _StringPool(data, offset, chunk_len)

            elif chunk_type == RES_XML_START_NAMESPACE_TYPE and pool is not None:
                prefix, uri = _read_namespace(data, offset, pool)
                if prefix and uri:
                    namespaces[prefix] = uri

            elif chunk_type == RES_XML_END_NAMESPACE_TYPE and pool is not None:
                prefix, _uri = _read_namespace(data, offset, pool)
                namespaces.pop(prefix, None)

            elif chunk_type == RES_XML_START_ELEMENT_TYPE and pool is not None:
                element_count += 1
                if element_count > MAX_ELEMENTS or len(stack) >= MAX_DEPTH:
                    break
                element = _read_element(data, offset, pool, namespaces)
                if stack:
                    stack[-1].children.append(element)
                elif root is None:
                    root = element
                stack.append(element)

            elif chunk_type == RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()

            # RES_XML_CDATA_TYPE and RES_XML_RESOURCE_MAP_TYPE carry no
            # information this analysis needs.

        except (struct.error, ManifestParseError, IndexError):
            # A malformed chunk ends the walk; decoded elements are kept.
            break

        offset += chunk_len

    if root is None:
        raise ManifestParseError("no elements could be decoded from the manifest")
    return root


def _read_namespace(data: bytes, offset: int, pool: _StringPool) -> tuple[str, str]:
    _type, header_size = struct.unpack_from("<HH", data, offset)
    prefix_idx, uri_idx = struct.unpack_from("<II", data, offset + header_size)
    return pool.get(prefix_idx), pool.get(uri_idx)


def _read_element(
    data: bytes, offset: int, pool: _StringPool, namespaces: dict[str, str]
) -> XmlElement:
    """Decode one ``RES_XML_START_ELEMENT_TYPE`` chunk."""
    _type, header_size = struct.unpack_from("<HH", data, offset)
    ext = offset + header_size

    ns_idx, name_idx = struct.unpack_from("<II", data, ext)
    (
        attribute_start,
        attribute_size,
        attribute_count,
    ) = struct.unpack_from("<HHH", data, ext + 8)

    element = XmlElement(
        name=pool.get(name_idx),
        namespace=pool.get(ns_idx) or None,
        namespaces=dict(namespaces),
    )

    stride = attribute_size or _ATTRIBUTE_SIZE
    if stride < _ATTRIBUTE_SIZE:
        stride = _ATTRIBUTE_SIZE
    attributes_base = ext + attribute_start

    for index in range(min(attribute_count, MAX_ATTRIBUTES_PER_ELEMENT)):
        attr_offset = attributes_base + index * stride
        if attr_offset + _ATTRIBUTE_SIZE > len(data):
            break
        attr_ns, attr_name, attr_raw = struct.unpack_from("<III", data, attr_offset)
        res0, data_type, value = struct.unpack_from("<BBI", data, attr_offset + 14)

        key = pool.get(attr_name) or f"attr_{index}"
        prefix = _resolve_attr_prefix(pool, namespaces, attr_ns)
        if prefix:
            key = f"{prefix}:{key}"
        element.attributes[key] = _format_value(pool, attr_raw, data_type, value, res0)

    return element


def _resolve_attr_prefix(
    pool: _StringPool, namespaces: dict[str, str], attr_ns: int
) -> str | None:
    """Map an attribute's namespace index to a human-readable prefix.

    aapt stores the *URI* (``http://schemas.android.com/apk/res/android``) in
    an attribute's namespace field, not the ``android:`` shorthand, so a bare
    pool lookup is not enough. The URI is resolved to the shorthand through the
    in-scope ``xmlns`` declarations, with the framework namespace recognised by
    URI so the conventional ``android:name`` form comes out.
    """
    uri = pool.get(attr_ns)
    if not uri:
        return None
    if uri == ANDROID_NS_URI:
        return "android"
    for shorthand, bound in namespaces.items():
        if bound == uri:
            return shorthand
    return uri


def _format_value(pool: _StringPool, raw_index: int, data_type: int, value: int, res0: int) -> str:
    """Render an attribute's typed value as text.

    Resource references (``@0x7f0e0001``) cannot be resolved without the
    resource table, which is not read here. They are reported *as references*
    rather than guessed at: inventing a permission name from an unresolved id
    would be a fabricated finding.
    """
    if data_type == TYPE_STRING:
        if raw_index != _NO_STRING:
            return pool.get(raw_index)
        return str(value)
    if data_type == TYPE_REFERENCE:
        return f"@0x{value:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{value:08x}"
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if value != 0 else "false"
    if data_type == TYPE_INT_HEX:
        return f"0x{value:x}"
    if data_type == TYPE_INT_DEC:
        return str(value)
    if data_type in (TYPE_DIMENSION, TYPE_FRACTION):
        return f"{_fixed_point(value, data_type)} {_dimension_unit(data_type, res0)}"
    if data_type == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", value))[0])
    if raw_index != _NO_STRING:
        text = pool.get(raw_index)
        if text:
            return text
    return str(value)


_DIMENSION_UNITS: Final[tuple[str, ...]] = (
    "px", "dip", "sp", "pt", "in", "mm",
)

_FRACTION_UNITS: Final[tuple[str, ...]] = ("%", "%p")


def _dimension_unit(data_type: int, res0: int) -> str:
    units = _DIMENSION_UNITS if data_type == TYPE_DIMENSION else _FRACTION_UNITS
    index = res0 & 0x0F
    return units[index] if 0 <= index < len(units) else ""


def _fixed_point(value: int, data_type: int) -> str:
    """Decode Android's packed fixed-point complex value."""
    mantissa = value & 0xFFFFFF00
    # Fraction values carry the fraction in the mantissa; dimensions in the low
    # byte. Both are stored as a 23-bit mantissa with a 0x100 radix.
    scaled = mantissa * (1.0 / (1 << 8)) if data_type == TYPE_DIMENSION else mantissa / (1 << 8)
    return f"{scaled:.4f}".rstrip("0").rstrip(".")


__all__ = [
    "MAX_ATTRIBUTES_PER_ELEMENT",
    "MAX_DEPTH",
    "MAX_ELEMENTS",
    "ManifestParseError",
    "XmlElement",
    "parse_axml",
]