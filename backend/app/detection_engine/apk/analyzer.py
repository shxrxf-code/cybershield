"""Static APK analyzer: manifest, DEX strings, signing scheme - no execution.

The analyzer walks a ZIP (the APK) read-only and assembles :class:`DetectionSignal`
evidence from three independent sources:

* the compiled ``AndroidManifest.xml`` (permissions, exported components,
  debuggable/backup/cleartext attributes);
* the DEX string tables (corroborating strings such as ``SmsManager`` usage,
  only meaningful *paired* with the matching manifest permission);
* the ZIP layout (signing scheme v1/v2/v3, native libraries).

Nothing here disassembles bytecode, loads classes, invokes code, or even opens
``resources.arsc``. Layout evidence is reported as layout evidence; a scan can
never "prove" intent from bytes, so every signal is phrased as observable
structure and the risk engine combines them with calibrated weights.
"""

from __future__ import annotations

import io
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.detection_engine.apk.dex import DexInfo, DexParseError, read_dex_strings
from app.detection_engine.apk.manifest import (
    ManifestParseError,
    XmlElement,
    parse_axml,
)
from app.detection_engine.apk.signature import (
    SignatureSchemeInfo,
    detect_signature_schemes,
)
from app.schemas.common import Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator, IndicatorType, SignalBundle

logger = logging.getLogger(__name__)

#: Default ceiling for an analysed APK (matches the upload limit).
DEFAULT_MAX_APK_BYTES: int = 150 * 1024 * 1024
#: A manifest larger than this is refused outright - it has no legitimate role.
MAX_MANIFEST_BYTES: int = 20 * 1024 * 1024
#: DEX members larger than this are skipped after metadata extraction.
MAX_DEX_BYTES: int = 60 * 1024 * 1024
#: Upper bound on how many ``classes*.dex`` members are fully read.
MAX_DEX_FILES: int = 32

#: Permissions grouped by what they expose, with severity for the aggregate
#: finding. A genuine utility app may legitimately hold one group (for example
#: a camera needs CAMERA); several groups together edge toward app-hygiene
#: risk, which the risk engine's cross-category corroboration models.
_PERMISSION_GROUPS: dict[str, tuple[frozenset[str], Severity]] = {
    "sms": (
        frozenset(
            {
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.READ_WAP_PUSH",
            }
        ),
        Severity.HIGH,
    ),
    "contacts": (
        frozenset(
            {
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.GET_ACCOUNTS",
            }
        ),
        Severity.MEDIUM,
    ),
    "location": (
        frozenset(
            {
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
            }
        ),
        Severity.MEDIUM,
    ),
    "microphone": (
        frozenset({"android.permission.RECORD_AUDIO"}),
        Severity.HIGH,
    ),
    "camera": (
        frozenset({"android.permission.CAMERA"}),
        Severity.MEDIUM,
    ),
    "call_log": (
        frozenset(
            {
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.PROCESS_OUTGOING_CALLS",
                "android.permission.CALL_PHONE",
            }
        ),
        Severity.HIGH,
    ),
    "storage": (
        frozenset(
            {
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
                "android.permission.READ_MEDIA_IMAGES",
                "android.permission.READ_MEDIA_VIDEO",
                "android.permission.READ_MEDIA_AUDIO",
            }
        ),
        Severity.MEDIUM,
    ),
    "body_sensors": (
        frozenset(
            {
                "android.permission.BODY_SENSORS",
                "android.permission.ACTIVITY_RECOGNITION",
            }
        ),
        Severity.MEDIUM,
    ),
}

#: Permissions whose presence alone is notable regardless of group size.
_SPECIAL_PERMISSIONS: dict[str, tuple[str, Severity]] = {
    "android.permission.SYSTEM_ALERT_WINDOW": ("apk.overlay_permission", Severity.HIGH),
    "android.permission.QUERY_ALL_PACKAGES": ("apk.query_all_packages", Severity.MEDIUM),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "apk.install_other_apps",
        Severity.MEDIUM,
    ),
    "android.permission.BIND_DEVICE_ADMIN": ("apk.device_admin_permission", Severity.HIGH),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        "apk.accessibility_bind",
        Severity.HIGH,
    ),
}

#: Strictly system-role bindings, meaningless as app-declared permissions.
_NON_APP_PERMISSIONS: frozenset[str] = frozenset(
    {
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    }
)


@dataclass(slots=True)
class ApkManifestSummary:
    """Serialisable view of the manifest facts used by the report."""

    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    debuggable: bool = False
    allow_backup: bool | None = None
    cleartext_traffic: bool = False
    permissions: list[str] = field(default_factory=list)
    application_class: str | None = None


@dataclass(slots=True)
class ApkStaticResult:
    """Full static-analysis output for one APK, before external scanners/scoring."""

    manifest: ApkManifestSummary
    signature: SignatureSchemeInfo
    dex_files: list[DexInfo] = field(default_factory=list)
    native_lib_count: int = 0
    entry_count: int = 0
    signals: list[DetectionSignal] = field(default_factory=list)
    bundle: SignalBundle = field(default_factory=SignalBundle)
    issues: list[str] = field(default_factory=list)
    malformed: bool = False
    truncated: bool = False


def analyse_apk(
    apk_source: bytes | Path | str,
    *,
    max_bytes: int = DEFAULT_MAX_APK_BYTES,
    include_dex_strings: bool = True,
) -> ApkStaticResult:
    """Run the static analysis pipeline over an APK, never executing it.

    Args:
        apk_source: Raw APK bytes, or a path to the APK file.
        max_bytes: Size ceiling; larger inputs are refused.
        include_dex_strings: Read ``classes*.dex`` string tables. Disable to
            skip the read for a fast header-only check.

    Returns:
        An :class:`ApkStaticResult` holding manifest facts, signing schemes,
        DEX metadata and the assembled signals. Scoring is *not* performed here.

    Raises:
        ValueError: If the input is not a ZIP, is too large, or declares ZIP
            members beyond the safety caps.
    """
    if isinstance(apk_source, (bytes, bytearray)):
        raw = bytes(apk_source)
        zf_bytes = raw
        file_name = "bytes"
    else:
        path = Path(apk_source)
        file_name = path.name
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"cannot read APK {path}: {exc}") from exc

    if len(raw) > max_bytes:
        raise ValueError(
            f"APK is {len(raw)} bytes, exceeding the {max_bytes} byte analysis cap"
        )
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ValueError("not a valid ZIP archive (is this an APK?)") from exc

    try:
        return _analyse_zip(zf, raw, file_name, include_dex_strings=include_dex_strings)
    finally:
        zf.close()


def _analyse_zip(
    zf: zipfile.ZipFile,
    raw: bytes,
    file_name: str,
    *,
    include_dex_strings: bool,
) -> ApkStaticResult:
    infos = zf.infolist()
    result = ApkStaticResult(
        manifest=ApkManifestSummary(),
        signature=SignatureSchemeInfo(),
        entry_count=len(infos),
    )

    names = {info.filename for info in infos}

    # ---- manifest --------------------------------------------------
    manifest_summary, manifest_signals, manifest_issues = _analyse_manifest(zf)
    result.manifest = manifest_summary
    result.signals.extend(manifest_signals)
    result.issues.extend(manifest_issues)
    if not manifest_issues:
        result.issues.append("manifest parsed")

    # ---- signing scheme --------------------------------------------
    result.signature = detect_signature_schemes(zf, raw)
    result.signals.extend(_signal_signature(result.signature))

    # ---- DEX -------------------------------------------------------
    dex_members = sorted(
        info
        for info in infos
        if info.filename.startswith("classes")
        and info.filename.endswith(".dex")
        and "/" not in info.filename
    )
    if include_dex_strings:
        for index, member in enumerate(dex_members[:MAX_DEX_FILES]):
            if member.file_size > MAX_DEX_BYTES:
                result.truncated = True
                result.issues.append(
                    f"{member.filename}: {member.file_size} bytes exceeds DEX cap; "
                    "strings not decoded"
                )
                continue
            try:
                content = zf.read(member)
            except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
                result.issues.append(f"{member.filename}: cannot read ({exc})")
                continue
            try:
                dex_info = read_dex_strings(content)
            except DexParseError as exc:
                result.issues.append(f"{member.filename}: {exc}")
                continue
            result.dex_files.append(dex_info)
            if len(dex_members) > MAX_DEX_FILES and index == MAX_DEX_FILES - 1:
                result.issues.append(
                    f"more than {MAX_DEX_FILES} DEX members; remaining ones not decoded"
                )
        if len(dex_members) > MAX_DEX_FILES:
            result.truncated = True

    # ---- native libraries ------------------------------------------
    result.native_lib_count = sum(1 for name in names if "/lib/" in name or name.startswith("lib/"))
    if result.native_lib_count:
        result.signals.append(
            DetectionSignal(
                code="apk.native_code",
                title="APK bundles native libraries",
                description=(
                    "The APK contains compiled native code. Native payloads are harder to "
                    "audit than bytecode and can hide behaviour from static review; this is "
                    "a transparency consideration, not an indication of malice on its own."
                ),
                severity=Severity.LOW,
                category="transparency",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.9,
                evidence={"native_lib_count": result.native_lib_count},
            )
        )

    # ---- DEX string corroboration ----------------------------------
    if include_dex_strings and result.dex_files:
        result.signals.extend(_signal_dex_corrobration(result))

    # If none of the structural layers could be read, mark malformed.
    if not result.signature.any_scheme_present and not result.dex_files:
        result.malformed = True
        result.issues.append("no signing scheme and no DEX member decoded")

    result.bundle = SignalBundle(signals=result.signals)
    return result


def _analyse_manifest(
    zf: zipfile.ZipFile,
) -> tuple[ApkManifestSummary, list[DetectionSignal], list[str]]:
    """Parse ``AndroidManifest.xml`` and emit structure signals."""
    summary = ApkManifestSummary()
    signals: list[DetectionSignal] = []
    issues: list[str] = []

    try:
        member = zf.getinfo("AndroidManifest.xml")
    except KeyError:
        issues.append("AndroidManifest.xml is missing from the APK")
        signals.append(
            DetectionSignal(
                code="apk.manifest_missing",
                title="No AndroidManifest.xml in the APK",
                description=(
                    "A valid APK must contain a compiled AndroidManifest.xml. Its absence "
                    "means the archive is malformed, was built by a non-standard toolchain, "
                    "or was deliberately stripped."
                ),
                severity=Severity.HIGH,
                category="structural",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.9,
            )
        )
        return summary, signals, issues

    if member.file_size > MAX_MANIFEST_BYTES:
        raise ValueError(
            f"AndroidManifest.xml is {member.file_size} bytes, "
            f"exceeding the {MAX_MANIFEST_BYTES} byte cap"
        )
    try:
        manifest_raw = zf.read(member)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        issues.append(f"manifest unreadable ({exc})")
        signals.append(
            DetectionSignal(
                code="apk.manifest_unreadable",
                title="AndroidManifest.xml could not be read",
                description=(
                    "The manifest member could not be inflated. This usually indicates "
                    "corruption or deliberate tampering; a decision on this APK should not "
                    "be reached without resolving the archive integrity."
                ),
                severity=Severity.HIGH,
                category="structural",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.7,
            )
        )
        return summary, signals, issues

    try:
        root = parse_axml(manifest_raw)
    except ManifestParseError as exc:
        issues.append(f"manifest could not be parsed: {exc}")
        signals.append(
            DetectionSignal(
                code="apk.manifest_unparseable",
                title="AndroidManifest.xml is not valid compiled XML",
                description=(
                    "The manifest member does not decode as a compiled XML resource. Reacting "
                    "to such an APK without an analyst review is not justified, so this is "
                    "reported as an integrity problem rather than ignored."
                ),
                severity=Severity.HIGH,
                category="structural",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
                evidence={"error": str(exc)[:400]},
            )
        )
        return summary, signals, issues

    try:
        _summarise_manifest(root, summary)
    except Exception as exc:  # noqa: BLE001 - a manifest bug must not abort the scan
        issues.append(f"manifest interrogation failed: {exc}")

    signals.extend(_signal_manifest(summary, root))
    return summary, signals, issues


def _summarise_manifest(root: XmlElement, summary: ApkManifestSummary) -> None:
    """Pull the serialisable facts out of the manifest tree."""
    summary.package_name = root.attr("package")
    summary.version_name = root.attr("android:versionName")
    version_code_raw = root.attr("android:versionCode")
    if version_code_raw:
        try:
            summary.version_code = int(version_code_raw)
        except ValueError:
            summary.version_code = None

    min_sdk = root.attr("android:minSdkVersion")
    if min_sdk:
        summary.min_sdk = _parse_int(min_sdk)
    target_sdk = root.attr("android:targetSdkVersion")
    if target_sdk:
        summary.target_sdk = _parse_int(target_sdk)
    summary.debuggable = root.attr("android:debuggable") == "true"

    application = root.child("application")
    if application is not None:
        summary.application_class = application.attr("android:name")
        summary.allow_backup = application.attr("android:allowBackup") == "true"
        summary.cleartext_traffic = (
            application.attr("android:usesCleartextTraffic") == "true"
        )

    summary.permissions = [
        element.attributes.get("android:name", "")
        for element in root.children_named("uses-permission")
        if element.attributes.get("android:name")
    ]


def _parse_int(value: str) -> int | None:
    try:
        return int(value, 0)
    except ValueError:
        return None


def _signal_manifest(summary: ApkManifestSummary, root: XmlElement) -> list[DetectionSignal]:
    """Turn the parsed manifest into signals."""
    signals: list[DetectionSignal] = []
    permissions = set(summary.permissions)

    if summary.debuggable:
        signals.append(
            DetectionSignal(
                code="apk.debuggable",
                title="Application is debuggable",
                description=(
                    "android:debuggable=\"true\" allows a debugger to attach at runtime. In a "
                    "distributed APK this is a release-hygiene failure that also aids "
                    "side-loading and tampering of the installed app."
                ),
                severity=Severity.MEDIUM,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
            )
        )

    if summary.allow_backup:
        signals.append(
            DetectionSignal(
                code="apk.allow_backup",
                title="Application data is backed up to the cloud",
                description=(
                    "android:allowBackup=\"true\" lets Android's backup transport extract "
                    "private app data. Sensitive data (handled credentials, chats, tokens) "
                    "can leak through this default path."
                ),
                severity=Severity.MEDIUM,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.7,
            )
        )

    if summary.cleartext_traffic:
        signals.append(
            DetectionSignal(
                code="apk.cleartext_traffic",
                title="Cleartext network traffic is permitted",
                description=(
                    "android:usesCleartextTraffic=\"true\" permits unencrypted HTTP. Sensitive "
                    "data may travel without transport encryption; this weakens both the app's "
                    "confidentiality and the integrity of anything it downloads."
                ),
                severity=Severity.MEDIUM,
                category="transport",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
            )
        )

    if summary.target_sdk is not None and summary.target_sdk < 26:
        signals.append(
            DetectionSignal(
                code="apk.old_target_sdk",
                title="App targets an outdated Android API",
                description=(
                    f"targetSdkVersion {summary.target_sdk} predates the 8.0 runtime "
                    "permissions model, so dangerous permissions are granted at install "
                    "time rather than being user-consented at runtime."
                ),
                severity=Severity.LOW,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.9,
            )
        )

    signals.extend(_signal_permissions(permissions))
    signals.extend(_signal_exported_components(root))
    signals.extend(_signal_assistive_services(root, permissions))
    return signals


def _signal_permissions(permissions: set[str]) -> list[DetectionSignal]:
    """Emit one finding per *group* of dangerous permissions present."""
    signals: list[DetectionSignal] = []
    for group, (members, severity) in _PERMISSION_GROUPS.items():
        present = sorted(member for member in members if member in permissions)
        if not present:
            continue
        signals.append(
            DetectionSignal(
                code=f"apk.permission_{group}",
                title=f"App requests {group.replace('_', ' ')} access",
                description=(
                    "The manifest requests permissions that expose sensitive device data or "
                    "capabilities. Each request is legitimate in the right product context; "
                    "a request by itself is not proof of abuse."
                ),
                severity=severity,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.7,
                evidence={"permissions": present[:12]},
                indicators=tuple(
                    Indicator(type=IndicatorType.PERMISSION, value=name) for name in present[:4]
                ),
            )
        )

    for permission, (code, severity) in _SPECIAL_PERMISSIONS.items():
        if permission not in permissions:
            continue
        signals.append(
            DetectionSignal(
                code=code,
                title=f"Manifest requests {permission.rsplit('.', 1)[-1].replace('_', ' ')}",
                description=(
                    "This permission grants a capability that is frequently abused: drawing "
                    "over other apps (tap-jacking), enumerating every installed package, "
                    "triggering installs, or binding a system service. Report the request and "
                    "let corroborating evidence decide."
                ),
                severity=severity,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.6,
                evidence={"permission": permission},
            )
        )
    return signals


def _signal_exported_components(root: XmlElement) -> list[DetectionSignal]:
    """Flag exported components that lack a permission guard."""
    exposed: list[tuple[str, str]] = []
    for element in root.descendants():
        if element.name not in ("activity", "service", "receiver", "provider"):
            continue
        if element.attributes.get("android:exported") == "true" and (
            "android:permission" not in element.attributes
        ):
            name = element.attributes.get("android:name", f"<unnamed {element.name}>")
            exposed.append((element.name, name))

    if not exposed:
        return []
    names = [f"{kind}:{name}" for kind, name in exposed[:10]]
    return [
        DetectionSignal(
            code="apk.exported_unprotected",
            title=f"{len(exposed)} components are exported without a permission guard",
            description=(
                "Exported components are reachable by other apps. Without an "
                "android:permission guard, any app on the device can invoke them. This is "
                "how overlay services and data-collecting receivers are commonly driven."
            ),
            severity=Severity.MEDIUM if len(exposed) < 3 else Severity.HIGH,
            category="structural",
            source=SignalSource.STATIC_ANALYSIS,
            confidence=0.75,
            evidence={"components": names, "count": len(exposed)},
        )
    ]


def _signal_assistive_services(
    root: XmlElement, permissions: set[str]
) -> list[DetectionSignal]:
    """Accessibility/device-admin services declared in the manifest.

    Accessibility is *the* canonical capability abused by mobile banking trojans
    (reading what makes sense to the user, auto-tapping prompts). A declared
    service rather than merely the permission is what makes the capability real.
    """
    signals: list[DetectionSignal] = []
    accessibility_declared = device_admin_declared = False

    for element in root.descendants():
        if element.name != "service":
            continue
        if element.attributes.get("android:permission") == (
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        ):
            accessibility_declared = True
        if element.attributes.get("android:permission") == (
            "android.permission.BIND_DEVICE_ADMIN"
        ):
            device_admin_declared = True

    if accessibility_declared:
        signals.append(
            DetectionSignal(
                code="apk.accessibility_service",
                title="Declares an accessibility service",
                description=(
                    "The manifest declares a service bound to BIND_ACCESSIBILITY_SERVICE. "
                    "Accessibility APIs can observe and drive the UI on the user's behalf; "
                    "in malware this is the mechanism that reads tokens and performs "
                    "click-jacking. Legitimate screen-reader and automation apps also use it."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.6,
            )
        )
    if device_admin_declared:
        signals.append(
            DetectionSignal(
                code="apk.device_admin",
                title="Declares a device administrator receiver",
                description=(
                    "The manifest declares a device-admin receiver. Device admin can wipe data, "
                    "lock the screen and disable other admin apps; it is commonly claimed by "
                    "ransomware and phone-locking trojans."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.6,
            )
        )
    return signals


def _signal_dex_corrobration(result: ApkStaticResult) -> list[DetectionSignal]:
    """Pair DEX string table evidence with manifest permission requests.

    A string such as ``SmsManager`` in the bytecode is only notable when the
    manifest's ``SMS`` permission set makes it plausible the app *uses* the data
    sensored. Emitting these only in that pairing keeps the false-positive rate
    low; alone they fire no signal at all.
    """
    if not result.dex_files:
        return []
    permissions = set(result.manifest.permissions)

    strings = "\n".join("\n".join(dex.strings) for dex in result.dex_files)
    signals: list[DetectionSignal] = []

    sms_tokens = {
        "SmsManager",
        "sendTextMessage",
        "content://sms",
        "Telephony$Sms",
        "android.provider.Telephony$Sms",
    }
    if {"android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"} & permissions and any(
        token in strings for token in sms_tokens
    ):
        signals.append(
            DetectionSignal(
                code="apk.dex_sms_usage",
                title="DEX strings reference SMS APIs that match the requested permission",
                description=(
                    "The bytecode's string table references SMS sending/receiving APIs and "
                    "the manifest requests SMS access. Together this is the building block of "
                    "premium-rate SMS trojans; alone, either fact is common in legitimate apps."
                ),
                severity=Severity.MEDIUM,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.5,
                evidence={"matched_tokens": sorted(token for token in sms_tokens if token in strings)[:8]},
            )
        )

    overlay_tokens = {"SYSTEM_ALERT_WINDOW", "TYPE_APPLICATION_OVERLAY", "WindowManager$LayoutParams"}
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions and any(
        token in strings for token in overlay_tokens
    ):
        signals.append(
            DetectionSignal(
                code="apk.dex_overlay_usage",
                title="DEX strings reference overlay windows matching the overlay permission",
                description=(
                    "The bytecode may create system overlay windows and the manifest grants "
                    "SYSTEM_ALERT_WINDOW. Overlay abuse enables tap-jacking and "
                    "fake-UI credential theft."
                ),
                severity=Severity.MEDIUM,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.5,
                evidence={"matched_tokens": sorted(token for token in overlay_tokens if token in strings)[:8]},
            )
        )

    notify_tokens = {"notify", "NotificationCompat", "setContentIntent"}
    if "android.permission.POST_NOTIFICATIONS" in permissions and any(
        token in strings for token in notify_tokens
    ):
        # This pairing is common in adware; the token itself is extremely common,
        # so confidence stays low and the weight is left at default (LOW).
        signals.append(
            DetectionSignal(
                code="apk.dex_notification_usage",
                title="DEX strings reference notification APIs",
                description=(
                    "The app requests POST_NOTIFICATIONS and contains notification plumbing. "
                    "This is normal for many apps and only meaningful in combination with "
                    "abusive advertising or phish-style UI patterns."
                ),
                severity=Severity.LOW,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.35,
            )
        )
    return signals


def _signal_signature(signature: SignatureSchemeInfo) -> list[DetectionSignal]:
    """Signing scheme findings - presence and absence, not verification."""
    if not signature.any_scheme_present:
        return [
            DetectionSignal(
                code="apk.unsigned",
                title="APK has no recognizable signature scheme",
                description=(
                    "No v1, v2, v3 or v3.1 signature was found. Android requires all APKs to "
                    "be signed; an unsigned archive is malformed, re-tooled or tampered with, "
                    "and installing it is unsupported on modern Android."
                ),
                severity=Severity.HIGH,
                category="policy",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.85,
            )
        ]
    return []


def summarise_apk(result: ApkStaticResult) -> dict[str, Any]:
    """Serialise the APK report body (no scoring)."""
    return {
        "package_name": result.manifest.package_name,
        "version_name": result.manifest.version_name,
        "version_code": result.manifest.version_code,
        "min_sdk": result.manifest.min_sdk,
        "target_sdk": result.manifest.target_sdk,
        "debuggable": result.manifest.debuggable,
        "allow_backup": result.manifest.allow_backup,
        "cleartext_traffic": result.manifest.cleartext_traffic,
        "permissions": result.manifest.permissions[:60],
        "application_class": result.manifest.application_class,
        "signature_schemes": result.signature.signed,
        "v1_present": result.signature.v1_present,
        "v2_present": result.signature.v2_present,
        "v3_present": result.signature.v3_present,
        "certificates": [
            {
                "sha256_fingerprint": cert.sha256_fingerprint,
                "subject": cert.subject,
                "issuer": cert.issuer,
            }
            for cert in result.signature.certificates[:1]
        ],
        "dex_files": [
            {
                "version": dex.version,
                "string_count": len(dex.strings),
                "class_count": dex.class_count,
                "checksum_valid": dex.checksum_valid,
                "sha256": dex.sha256,
                "truncated": dex.truncated,
            }
            for dex in result.dex_files[:32]
        ],
        "native_lib_count": result.native_lib_count,
        "entry_count": result.entry_count,
        "issues": result.issues[:20],
        "truncated": result.truncated,
    }


__all__ = [
    "DEFAULT_MAX_APK_BYTES",
    "ApkManifestSummary",
    "ApkStaticResult",
    "analyse_apk",
    "summarise_apk",
]