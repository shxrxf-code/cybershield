"""Tests for the static APK analysis layer (manifest, DEX, signature, analyzer).

All fixtures are synthetic: a compiled-XML builder, a DEX builder, a ZIP
builder and a PKCS#7 certificate builder. Real sample APKs are intentionally
not committed - a malware scanner's CI pipeline should not contain labelled
malware.
"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile

import pytest

from app.detection_engine.apk.analyzer import analyse_apk
from app.detection_engine.apk.dex import DexParseError, read_dex_strings
from app.detection_engine.apk.manifest import ManifestParseError, parse_axml
from app.detection_engine.apk.signature import (
    APK_SIG_BLOCK_MAGIC,
    APK_SIG_SCHEME_V2_BLOCK_ID,
    APK_SIG_SCHEME_V3_BLOCK_ID,
    SignatureSchemeInfo,
    detect_signature_schemes,
    extract_certificates,
)
from app.schemas.common import ObjectType, Verdict
from app.services.risk_engine import assess_risk

from tests.apk_fixtures import (
    build_apk_zip,
    build_dex_file,
    build_manifest_tree,
    build_manifest_xml,
    build_pkcs7_signed_data,
    build_self_signed_cert,
)


# ---------------------------------------------------------------------------
# AXML manifest parser
# ---------------------------------------------------------------------------


class TestManifestParser:
    def test_simple_attributes(self) -> None:
        data = build_manifest_xml(
            {
                "package": "com.example.app",
                "android:versionCode": 12,
                "android:versionName": "2.1",
                "android:debuggable": True,
            }
        )
        root = parse_axml(data)
        assert root.name == "manifest"
        assert root.attributes["package"] == "com.example.app"
        assert root.attributes["android:versionCode"] == "12"
        assert root.attributes["android:versionName"] == "2.1"
        assert root.attributes["android:debuggable"] == "true"

    def test_nested_elements(self) -> None:
        data = build_manifest_tree(
            {"package": "com.example.app"},
            [
                ("uses-permission", {"android:name": "android.permission.CAMERA"}, []),
                (
                    "application",
                    {"android:allowBackup": False},
                    [
                        ("activity", {"android:name": ".Main", "android:exported": True}, []),
                        ("service", {"android:name": ".Svc", "android:exported": "false"}, []),
                    ],
                ),
            ],
        )
        root = parse_axml(data)
        app = root.child("application")
        assert app is not None
        assert app.attributes["android:allowBackup"] == "false"
        activities = app.children_named("activity")
        assert activities[0].attributes["android:name"] == ".Main"
        assert activities[0].attributes["android:exported"] == "true"

    def test_long_and_multibyte_strings(self) -> None:
        long_name = "com.example." + "pkg" * 60
        data = build_manifest_xml(
            {"package": long_name, "android:label": "安全工具"}
        )
        root = parse_axml(data)
        assert root.attributes["package"] == long_name
        assert root.attributes["android:label"] == "安全工具"

    def test_rejects_non_axml(self) -> None:
        for blob in (b"PK\x03\x04garbage", b"\x00\x01notaxml", b"x"):
            with pytest.raises(ManifestParseError):
                parse_axml(blob)

    def test_truncated_input_raises(self) -> None:
        data = build_manifest_xml({"package": "com.example.app"})
        with pytest.raises(ManifestParseError):
            parse_axml(data[:20])

    def test_descendants_traversal(self) -> None:
        data = build_manifest_tree(
            {"package": "com.example.app"},
            [
                (
                    "application",
                    {},
                    [
                        ("activity", {}, []),
                        ("receiver", {}, [("service", {}, [])]),
                    ],
                )
            ],
        )
        root = parse_axml(data)
        names = {element.name for element in root.descendants()}
        assert names == {"application", "activity", "receiver", "service"}


# ---------------------------------------------------------------------------
# DEX string table
# ---------------------------------------------------------------------------


class TestDexParser:
    def test_strings_round_trip(self) -> None:
        values = [
            "android.permission.RECEIVE_SMS",
            "Lcom/example/cls;",
            "",
            "包管理程序",
            "x" * 300,
        ]
        info = read_dex_strings(build_dex_file(values))
        assert info.checksum_valid
        assert info.version == "035"
        for value in values:
            if value:
                assert value in info.strings

    def test_mutf8_nul_round_trip(self) -> None:
        # A literal NUL is encoded C0 80 and must decode back to "\x00".
        info = read_dex_strings(build_dex_file(["alpha\x00beta"]))
        assert "alpha\x00beta" in info.strings

    def test_supplementary_characters(self) -> None:
        info = read_dex_strings(build_dex_file(["emoji-\U0001f600"]))
        assert "emoji-\U0001f600" in info.strings

    def test_rejects_non_dex(self) -> None:
        with pytest.raises(DexParseError):
            read_dex_strings(b"MZ\x90\x00" + b"\x00" * 200)

    def test_malformed_offsets_tolerated(self) -> None:
        # Corrupt the string id table offset to point past the file. The parser
        # must decode whatever it safely can and record errors, not raise.
        data = bytearray(build_dex_file(["hello"]))
        struct.pack_into("<I", data, 60, 0xFFFFFF00)
        info = read_dex_strings(bytes(data))
        assert isinstance(info.parse_errors, list)
        assert info.truncated or info.parse_errors or not info.strings


# ---------------------------------------------------------------------------
# Signature scheme detection
# ---------------------------------------------------------------------------


def _cert_containing_data() -> tuple[bytes, bytes]:
    cert = build_self_signed_cert(
        subject={"CN": "Test Signer", "O": "Test Org", "OU": "Tools"},
        issuer={"CN": "Test Signer", "O": "Test Org"},
    )
    return cert, build_pkcs7_signed_data([cert])


class TestSignatureSchemes:
    def test_v1_extraction(self) -> None:
        cert, pkcs7 = _cert_containing_data()
        extracted = extract_certificates(pkcs7)
        assert len(extracted) == 1
        item = extracted[0]
        assert item.sha256_fingerprint == hashlib.sha256(cert).hexdigest()
        assert item.subject == {"CN": "Test Signer", "O": "Test Org", "OU": "Tools"}
        assert item.issuer == {"CN": "Test Signer", "O": "Test Org"}
        assert "Test Signer" in item.subject_label

    def test_junk_pkcs7_yields_nothing(self) -> None:
        assert extract_certificates(b"\x30\x00") == []
        assert extract_certificates(b"not der at all") == []
        assert extract_certificates(b"") == []

    def test_v2_v3_block_detection(self) -> None:
        cert, pkcs7 = _cert_containing_data()
        apk = build_apk_zip(
            {
                "AndroidManifest.xml": build_manifest_xml({"package": "com.a.b"}),
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n",
                "META-INF/CERT.RSA": pkcs7,
            },
            sig_pairs=[
                (APK_SIG_SCHEME_V2_BLOCK_ID, b"v2-signer"),
                (APK_SIG_SCHEME_V3_BLOCK_ID, b"v3-signer"),
            ],
        )
        with zipfile.ZipFile(io.BytesIO(apk)) as zf:
            info = detect_signature_schemes(zf, apk)
        assert info.v1_present
        assert info.v2_present
        assert info.v3_present
        assert not info.v3_1_present
        assert sorted(info.block_pair_ids) == sorted(
            [APK_SIG_SCHEME_V2_BLOCK_ID, APK_SIG_SCHEME_V3_BLOCK_ID]
        )
        assert info.signed == "v1+v2+v3"

    def test_signature_block_magic(self) -> None:
        assert len(APK_SIG_BLOCK_MAGIC) == 16
        assert APK_SIG_BLOCK_MAGIC.startswith(b"APK Sig Block")

    def test_unsigned_zip(self) -> None:
        apk = build_apk_zip({"file.txt": b"data"})
        with zipfile.ZipFile(io.BytesIO(apk)) as zf:
            info = detect_signature_schemes(zf, apk)
        assert isinstance(info, SignatureSchemeInfo)
        assert not info.any_scheme_present

    def test_no_bytes_means_no_v2_scan(self) -> None:
        apk = build_apk_zip(
            {"META-INF/MANIFEST.MF": b"m"},
            sig_pairs=[(APK_SIG_SCHEME_V2_BLOCK_ID, b"v2")],
        )
        with zipfile.ZipFile(io.BytesIO(apk)) as zf:
            info = detect_signature_schemes(zf, None)
        assert info.v1_present
        assert not info.v2_present
        assert info.notes, "expected a note explaining the limitation"


# ---------------------------------------------------------------------------
# End-to-end analyzer
# ---------------------------------------------------------------------------


def _build_apk(*, malicious: bool) -> bytes:
    if malicious:
        manifest = build_manifest_tree(
            {"package": "com.example.trojan", "android:debuggable": True},
            [
                ("uses-permission", {"android:name": "android.permission.SYSTEM_ALERT_WINDOW"}, []),
                ("uses-permission", {"android:name": "android.permission.RECEIVE_SMS"}, []),
                ("uses-permission", {"android:name": "android.permission.SEND_SMS"}, []),
                ("uses-permission", {"android:name": "android.permission.RECORD_AUDIO"}, []),
                ("uses-permission", {"android:name": "android.permission.READ_CONTACTS"}, []),
                ("uses-permission", {"android:name": "android.permission.BIND_ACCESSIBILITY_SERVICE"}, []),
                (
                    "application",
                    {"android:allowBackup": True, "android:usesCleartextTraffic": True},
                    [
                        ("activity", {"android:name": ".Main", "android:exported": True}, []),
                        (
                            "service",
                            {
                                "android:name": ".OverlaySvc",
                                "android:exported": "true",
                                "android:permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
                            },
                            [],
                        ),
                    ],
                ),
            ],
        )
        dex = build_dex_file(
            [
                "Landroid/telephony/SmsManager;",
                "sendTextMessage",
                "content://sms",
                "SYSTEM_ALERT_WINDOW",
            ]
        )
    else:
        manifest = build_manifest_tree(
            {"package": "com.example.camera"},
            [
                ("uses-permission", {"android:name": "android.permission.CAMERA"}, []),
                (
                    "application",
                    {"android:allowBackup": False},
                    [
                        ("activity", {"android:name": ".Main", "android:exported": False}, []),
                    ],
                ),
            ],
        )
        dex = build_dex_file(["Lcom/example/camera/Main;", "onCameraFrame"])

    cert, pkcs7 = _cert_containing_data()
    entries = {
        "AndroidManifest.xml": manifest,
        "classes.dex": dex,
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n",
        "META-INF/CERT.RSA": pkcs7,
    }
    if malicious:
        entries["lib/arm64-v8a/libnative.so"] = b"\x7fELFabc"
    return build_apk_zip(entries, sig_pairs=[(APK_SIG_SCHEME_V2_BLOCK_ID, b"signer")])


class TestAnalyzer:
    def test_malicious_style_signals(self) -> None:
        result = analyse_apk(_build_apk(malicious=True))
        codes = [s.code for s in result.signals]
        assert set(codes) >= {
            "apk.debuggable",
            "apk.allow_backup",
            "apk.cleartext_traffic",
            "apk.permission_sms",
            "apk.permission_microphone",
            "apk.overlay_permission",
            "apk.accessibility_bind",
            "apk.accessibility_service",
            "apk.exported_unprotected",
            "apk.dex_sms_usage",
            "apk.native_code",
        }
        assert "apk.unsigned" not in codes
        assert result.manifest.package_name == "com.example.trojan"

    def test_benign_apk_scores_safe(self) -> None:
        result = analyse_apk(_build_apk(malicious=False))
        assessment = assess_risk(result.bundle, object_type=ObjectType.APK)
        assert assessment.score < 20
        assert assessment.verdict.is_safe_enough

    def test_malicious_apk_scores_high(self) -> None:
        result = analyse_apk(_build_apk(malicious=True))
        assessment = assess_risk(result.bundle, object_type=ObjectType.APK)
        assert assessment.score >= 60
        assert assessment.verdict in (Verdict.HIGH_RISK, Verdict.MALICIOUS)

    def test_unsigned_apk_flagged(self) -> None:
        manifest = build_manifest_xml({"package": "com.example.x"})
        apk = build_apk_zip({"AndroidManifest.xml": manifest})
        result = analyse_apk(apk)
        assert "apk.unsigned" in [s.code for s in result.signals]

    def test_not_a_zip_rejected(self) -> None:
        with pytest.raises(ValueError):
            analyse_apk(b"not an apk")

    def test_package_captured(self) -> None:
        result = analyse_apk(_build_apk(malicious=False))
        assert result.manifest.package_name == "com.example.camera"

    def test_include_dex_strings_disabled(self) -> None:
        result = analyse_apk(_build_apk(malicious=False), include_dex_strings=False)
        assert result.dex_files == []