"""Synthetic Android package construction for tests.

Every APK the test-suite analyses is assembled here from a hand-encoded binary
``AndroidManifest.xml``, a stub DEX carrying a string pool, and a real v1 (JAR)
signature built with a self-signed certificate.  No real malware is used, nothing
is downloaded, and the generated packages are not installable - they exist only
to exercise the analyser's parsers.

Why encode AXML by hand
-----------------------
An APK fixture has to be a *real* archive with a *real* binary manifest for the
parser tests to mean anything, but committing binary blobs makes it impossible
to see what a fixture is testing.  Encoding the manifest in Python makes every
field in a test case legible at the point where it is set.

The encoding follows the public Android resource format: ``ResStringPool_header``
(a 28-byte header plus an offset table), ``ResXMLTree_header``, ``ResXMLTree_node``
(16-byte header), ``ResXMLTree_attrExt`` (20 bytes) and ``ResXMLTree_attribute``
(20 bytes per attribute).

Two constraints are worth recording, because they are easy to get wrong and
silently produce a manifest that no parser will read:

* ``attributeStart`` and ``attributeSize`` must both be 20.  Parsers skip
  ``attributeSize - 20`` bytes after each attribute, so any other value
  desynchronises the whole stream.
* ``attrExt`` is written *without* the ``ResStringPool_ref`` that the format
  nominally allows between the chunk header and the string pool.  The parser
  this project tests against locates the pool at ``header_size``, so the pool has
  to begin immediately after the 8-byte chunk header.
"""

from __future__ import annotations

import datetime
import hashlib
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Final

__all__ = [
    "ANDROID_NS",
    "AUTOFILL_PERMISSION",
    "apk_bytes",
    "build_apk",
    "build_dex",
    "build_manifest",
    "make_key_and_cert",
    "sign_v1",
]

ANDROID_NS: Final[str] = "http://schemas.android.com/apk/res/android"

RES_STRING_POOL_TYPE: Final[int] = 0x0001
RES_XML_TYPE: Final[int] = 0x0003
START_NAMESPACE: Final[int] = 0x0100
END_NAMESPACE: Final[int] = 0x0101
START_TAG: Final[int] = 0x0102
END_TAG: Final[int] = 0x0103
NO_ENTRY: Final[int] = 0xFFFFFFFF

TYPE_STRING: Final[int] = 0x03
TYPE_INT_DEC: Final[int] = 0x10
TYPE_INT_BOOLEAN: Final[int] = 0x12

UTF8_FLAG: Final[int] = 0x00000100

AUTOFILL_PERMISSION: Final[str] = "android.permission.BIND_AUTOFILL_SERVICE"


class _Pool:
    """A deduplicating string pool with stable indices."""

    def __init__(self) -> None:
        self.items: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self.items)
            self.items.append(value)
        return self._index[value]

    def encode(self) -> bytes:
        offsets: list[int] = []
        data = b""
        for item in self.items:
            offsets.append(len(data))
            encoded = item.encode("utf-8")
            # UTF-8 entry: char count (1-2 bytes), byte count (1 byte), data, NUL.
            data += bytes([len(item) & 0x7F, len(encoded)]) + encoded + b"\x00"
        if len(data) % 4:
            data += b"\x00" * (4 - (len(data) % 4))

        header_size = 28
        strings_start = header_size + 4 * len(self.items)
        header = struct.pack(
            "<HHIIIIII",
            RES_STRING_POOL_TYPE,
            header_size,
            strings_start + len(data),
            len(self.items),
            0,            # styleCount
            UTF8_FLAG,
            strings_start,
            0,            # stylesStart
        )
        offset_table = b"".join(struct.pack("<I", o) for o in offsets)
        return header + offset_table + data


def _res_value(data_type: int, value: object) -> bytes:
    if data_type == TYPE_STRING:
        return struct.pack("<HBBI", 8, 0, TYPE_STRING, int(value))
    return struct.pack("<HBBI", 8, 0, data_type, int(value) & 0xFFFFFFFF)


def _attribute(ns: int, name: int, raw: int, data_type: int, value: object) -> bytes:
    """``ResXMLTree_attribute``: ns, name, rawValue, then an 8-byte ``Res_value``."""
    return struct.pack("<III", ns, name, raw) + _res_value(data_type, value)


def _node(node_type: int, payload: bytes) -> bytes:
    """``ResXMLTree_node``: 16-byte header followed by *payload*."""
    return struct.pack("<HHIII", node_type, 16, 16 + len(payload), 1, NO_ENTRY) + payload


def _tag_payload(ns: int, name: int, attrs: bytes, attribute_count: int) -> bytes:
    """START_TAG payload: ``ResXMLTree_attrExt`` followed by the attributes.

    ``ResXMLTree_attrExt`` is ns, name, then six u16s: attributeStart,
    attributeSize, attributeCount, idIndex, classIndex and styleIndex.  The two
    offsets are 20 in every real manifest, and parsers rely on that.
    """
    return struct.pack("<IIHHHHHH", ns, name, 20, 20, attribute_count, 0, 0, 0) + attrs


def build_manifest(
    package: str,
    permissions: list[str],
    *,
    activities: list[tuple[str, str | None]] | None = None,
    services: list[tuple[str, str | None, str | None]] | None = None,
    receivers: list[tuple[str, str | None]] | None = None,
    debuggable: bool = False,
    version_name: str = "1.0",
    version_code: int = 1,
    min_sdk: int = 21,
    target_sdk: int = 33,
    shared_user: str | None = None,
    uses_features: list[str] | None = None,
) -> bytes:
    """Hand-encode a binary ``AndroidManifest.xml``.

    *activities* and *receivers* are ``(name, exported)`` pairs, where
    ``exported=None`` omits the attribute - which is how a component with no
    explicit export flag looks in a manifest built by older tooling.
    *services* are ``(name, exported, permission)`` triples, where the permission
    is what the component is bound to.  That is how an autofill or accessibility
    service identifies itself, and therefore how a password manager is told apart
    from a trojan that merely wants to watch the screen.
    """
    activities = activities or []
    services = services or []
    receivers = receivers or []
    uses_features = uses_features or []

    pool = _Pool()
    uri_ns = pool.add(ANDROID_NS)
    tag_manifest = pool.add("manifest")
    tag_application = pool.add("application")
    tag_uses_permission = pool.add("uses-permission")
    tag_uses_feature = pool.add("uses-feature")
    tag_uses_sdk = pool.add("uses-sdk")
    attr_package = pool.add("package")
    attr_version_name = pool.add("versionName")
    attr_version_code = pool.add("versionCode")
    attr_min_sdk = pool.add("minSdkVersion")
    attr_target_sdk = pool.add("targetSdkVersion")
    attr_shared_user = pool.add("sharedUserId")
    attr_debuggable = pool.add("debuggable")
    attr_exported = pool.add("exported")
    attr_name = pool.add("name")
    attr_required = pool.add("required")
    attr_permission = pool.add("permission")

    perm_ids = [pool.add("android.permission." + p) for p in permissions]
    feature_ids = [pool.add("android.hardware." + f) for f in uses_features]
    activity_ids = [
        (pool.add(name), pool.add("activity"), exported) for name, exported in activities
    ]
    service_tag = pool.add("service")
    receiver_tag = pool.add("receiver")
    service_ids = [
        (pool.add(name), service_tag, exported, pool.add(perm) if perm else None)
        for name, exported, perm in services
    ]
    receiver_ids = [
        (pool.add(name), receiver_tag, exported) for name, exported in receivers
    ]
    debug_value = pool.add("true" if debuggable else "false")
    version_value = pool.add(version_name)
    shared_value = pool.add(shared_user) if shared_user else None

    events = bytearray()

    def open_tag(name: int, attrs: list[bytes]) -> None:
        events.extend(
            _node(START_TAG, _tag_payload(NO_ENTRY, name, b"".join(attrs), len(attrs)))
        )

    def close_tag(name: int) -> None:
        events.extend(_node(END_TAG, struct.pack("<II", NO_ENTRY, name)))

    def leaf(name: int, attrs: list[bytes]) -> None:
        open_tag(name, attrs)
        close_tag(name)

    manifest_attrs = [
        _attribute(uri_ns, attr_package, pool.add(package), TYPE_STRING, pool.add(package)),
        _attribute(uri_ns, attr_version_name, version_value, TYPE_STRING, version_value),
        _attribute(uri_ns, attr_version_code, NO_ENTRY, TYPE_INT_DEC, version_code),
    ]
    if shared_value is not None:
        manifest_attrs.append(
            _attribute(NO_ENTRY, attr_shared_user, shared_value, TYPE_STRING, shared_value)
        )

    events += _node(START_NAMESPACE, struct.pack("<II", pool.add("android"), uri_ns))
    open_tag(tag_manifest, manifest_attrs)

    # SDK versions live on a <uses-sdk> element, not on <manifest>.
    leaf(
        tag_uses_sdk,
        [
            _attribute(uri_ns, attr_min_sdk, NO_ENTRY, TYPE_INT_DEC, min_sdk),
            _attribute(uri_ns, attr_target_sdk, NO_ENTRY, TYPE_INT_DEC, target_sdk),
        ],
    )
    for perm_id in perm_ids:
        leaf(tag_uses_permission, [_attribute(uri_ns, attr_name, perm_id, TYPE_STRING, perm_id)])
    for feature_id in feature_ids:
        leaf(
            tag_uses_feature,
            [
                _attribute(uri_ns, attr_name, feature_id, TYPE_STRING, feature_id),
                _attribute(NO_ENTRY, attr_required, NO_ENTRY, TYPE_INT_BOOLEAN, 1),
            ],
        )

    open_tag(
        tag_application,
        [_attribute(uri_ns, attr_debuggable, debug_value, TYPE_INT_BOOLEAN,
                    1 if debuggable else 0)],
    )
    for name_id, tag, exported in (*activity_ids, *receiver_ids):
        attrs = [_attribute(uri_ns, attr_name, name_id, TYPE_STRING, name_id)]
        if exported is not None:
            attrs.append(
                _attribute(NO_ENTRY, attr_exported, NO_ENTRY, TYPE_INT_BOOLEAN,
                           1 if exported else 0)
            )
        leaf(tag, attrs)
    for name_id, tag, exported, perm_id in service_ids:
        attrs = [_attribute(uri_ns, attr_name, name_id, TYPE_STRING, name_id)]
        if exported is not None:
            attrs.append(
                _attribute(NO_ENTRY, attr_exported, NO_ENTRY, TYPE_INT_BOOLEAN,
                           1 if exported else 0)
            )
        if perm_id is not None:
            attrs.append(_attribute(uri_ns, attr_permission, perm_id, TYPE_STRING, perm_id))
        leaf(tag, attrs)
    close_tag(tag_application)
    close_tag(tag_manifest)

    pool_bytes = pool.encode()
    # The parser locates the string pool at ``header_size``, so it goes straight
    # after the 8-byte chunk header with no ResStringPool_ref in between.
    header = struct.pack(
        "<HHI", RES_XML_TYPE, 8, 8 + len(pool_bytes) + len(events)
    )
    return header + pool_bytes + bytes(events)


def build_dex(strings: list[str]) -> bytes:
    """A DEX header carrying a string pool, with no real bytecode.

    A real DEX string pool is a MUTF-8 blob with ULEB128 lengths; this writes the
    pool as plain length-prefixed UTF-8, which is enough for the printable-run
    salvage path.  ``androguard`` will refuse the file as structurally invalid,
    which is itself a case worth covering: the analyser must report the gap
    rather than presenting a clean result.
    """
    pool = _Pool()
    for item in strings:
        pool.add(item)
    header = bytearray(112)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, 112)          # file_size
    struct.pack_into("<I", header, 36, 112)          # header_size
    struct.pack_into("<I", header, 56, 0x12345678)   # endian_tag
    struct.pack_into("<I", header, 60, len(strings))  # string_ids_size
    struct.pack_into("<I", header, 64, 112)          # string_ids_off
    return bytes(header) + pool.encode()


# ---------------------------------------------------------------------- #
# v1 (JAR) signing
# ---------------------------------------------------------------------- #

_KEY_CACHE: dict[str, tuple[bytes, bytes]] = {}


def make_key_and_cert(
    *,
    common_name: str = "Android Debug",
    organization: str = "Android",
    key_size: int = 2048,
    days_valid: int = 3650,
    not_before_offset_days: int = 0,
) -> tuple[bytes, bytes]:
    """Return ``(pem_private_key, der_certificate)`` for a self-signed pair.

    Results are cached by parameter tuple so a test run does not pay for RSA key
    generation on every fixture.  The parameters exist so a fixture can carry
    exactly the certificate properties the analyser is meant to detect:
    self-signed, expired, debug-keyed, platform-named, or below the key-size
    floor Android enforces.
    """
    cache_key = (
        f"{common_name}|{organization}|{key_size}|{days_valid}|{not_before_offset_days}"
    )
    if cache_key in _KEY_CACHE:
        return _KEY_CACHE[cache_key]

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    now = datetime.datetime.now(datetime.timezone.utc)
    # Validity runs from ``not_before``, so an expired fixture is expressed as a
    # backdated start plus a short window.  Anchoring ``not_after`` to ``now``
    # instead would silently produce a valid certificate.
    not_before = now + datetime.timedelta(days=not_before_offset_days)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    result = (pem_key, cert.public_bytes(serialization.Encoding.DER))
    _KEY_CACHE[cache_key] = result
    return result


def _sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sign_v1(
    entries: dict[str, bytes],
    pem_key: bytes,
    der_cert: bytes,
    *,
    alias: str = "CERT",
) -> dict[str, bytes]:
    """Return *entries* plus a valid ``META-INF`` v1 signature block.

    A v1 signature is three files: ``MANIFEST.MF`` holds a digest of every entry,
    ``CERT.SF`` digests the manifest, and ``CERT.RSA`` is a detached PKCS#7
    signature over the ``.SF`` file.
    """
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7

    key = serialization.load_pem_private_key(pem_key, password=None)
    cert = x509.load_der_x509_certificate(der_cert)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    manifest = ["Manifest-Version: 1.0", f"Created-By: {stamp}", ""]
    digests: list[tuple[str, str]] = []
    for name in sorted(entries):
        if name.upper() == "META-INF/MANIFEST.MF":
            continue
        digest = b64(_sha256_digest(entries[name]))
        digests.append((name, digest))
        manifest += [f"Name: {name}", f"SHA-256-Digest: {digest}", ""]
    manifest_bytes = "\r\n".join(manifest).encode("utf-8")

    sf = [
        "Signature-Version: 1.0",
        f"SHA-256-Digest-Manifest: {b64(_sha256_digest(manifest_bytes))}",
        f"Created-By: {stamp}",
        "",
    ]
    for name, digest in digests:
        section = f"Name: {name}\r\nSHA-256-Digest: {digest}\r\n"
        sf += [
            f"Name: {name}",
            f"SHA-256-Digest: {b64(_sha256_digest(section.encode('utf-8')))}",
            "",
        ]
    sf_bytes = "\r\n".join(sf).encode("utf-8")

    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(sf_bytes)
        .add_signer(cert, key, hashes.SHA256())
    )
    try:
        signature = builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    except Exception:  # pragma: no cover - legacy algorithm id unsupported
        signature = builder.sign(serialization.Encoding.DER, [])

    return {
        **entries,
        "META-INF/MANIFEST.MF": manifest_bytes,
        f"META-INF/{alias}.SF": sf_bytes,
        f"META-INF/{alias}.RSA": signature,
    }


def build_apk(
    path: str | Path,
    *,
    package: str = "com.example.app",
    permissions: list[str] | None = None,
    activities: list[tuple[str, str | None]] | None = None,
    services: list[tuple[str, str | None, str | None]] | None = None,
    receivers: list[tuple[str, str | None]] | None = None,
    dex_strings: list[str] | None = None,
    debuggable: bool = False,
    shared_user: str | None = None,
    uses_features: list[str] | None = None,
    version_name: str = "1.0",
    min_sdk: int = 21,
    target_sdk: int = 33,
    extra_files: dict[str, bytes] | None = None,
    manifest: bytes | None = None,
    dex: bytes | None = None,
    sign: bool | str = False,
    cert_cn: str = "Acme Software Ltd",
    cert_org: str = "Acme Software Ltd",
    cert_key_size: int = 2048,
    cert_days_valid: int = 3650,
    cert_not_before_offset_days: int = 0,
) -> Path:
    """Write an APK - a ZIP with the standard Android layout.

    ``sign`` selects the certificate shape: ``False`` for unsigned, ``True`` for
    an ordinary developer certificate, or one of ``"debug"``, ``"expired"``,
    ``"platform"`` or ``"weak"`` for the cases the analyser must distinguish.
    """
    files: dict[str, bytes] = {
        "AndroidManifest.xml": manifest
        if manifest is not None
        else build_manifest(
            package, permissions or [], activities=activities, services=services,
            receivers=receivers, debuggable=debuggable, shared_user=shared_user,
            uses_features=uses_features, version_name=version_name,
            min_sdk=min_sdk, target_sdk=target_sdk,
        ),
        "classes.dex": dex
        if dex is not None
        else build_dex(dex_strings or ["Landroid/os/Binder;"]),
        "resources.arsc": b"\x02\x00\x0c\x00" + b"\x00" * 64,
    }
    files.update(extra_files or {})

    if sign:
        if sign == "debug":
            key, der = make_key_and_cert(
                common_name="Android Debug", organization="Android", key_size=2048
            )
        elif sign == "expired":
            key, der = make_key_and_cert(
                common_name=cert_cn, organization=cert_org, key_size=2048,
                days_valid=1, not_before_offset_days=-3650,
            )
        elif sign == "platform":
            key, der = make_key_and_cert(
                common_name="AOSP", organization="Android", key_size=2048
            )
        elif sign == "weak":
            # ``cryptography`` refuses to generate below 1024 bits, so that is the
            # weakest key a fixture can carry.  It is still well below the
            # 2048-bit floor Google Play enforces for releases.
            key, der = make_key_and_cert(
                common_name=cert_cn, organization=cert_org, key_size=1024
            )
        else:
            key, der = make_key_and_cert(
                common_name=cert_cn, organization=cert_org, key_size=cert_key_size,
                days_valid=cert_days_valid,
                not_before_offset_days=cert_not_before_offset_days,
            )
        files = sign_v1(files, key, der)

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    # A fixed timestamp keeps generated fixtures byte-reproducible, which matters
    # when a test asserts on a hash.
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return out


def apk_bytes(**kwargs: Any) -> bytes:
    """Build an APK in memory and return its bytes.

    The analyser accepts raw bytes, so a test never needs a file on disk.
    """
    with tempfile.TemporaryDirectory() as workdir:
        return build_apk(Path(workdir) / "fixture.apk", **kwargs).read_bytes()