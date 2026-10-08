"""AndroidManifest.xml analysis: identity, permissions and components.

What is checked, and why each check matters
------------------------------------------
``debuggable``
    A released app should not be debuggable: it lets anyone with an ADB cable
    attach a debugger and read process memory.  Repackaged trojans routinely
    ship debuggable so an analyst can trace them, and legitimate release builds
    always set it false.

``targetSdkVersion``
    Permission enforcement changed at API 23 and again at later levels.  An app
    targeting below 23 keeps the pre-Marshmallow model where granting a
    permission granted it all, and sideloaded malware relies on that.

``exported`` components
    An exported activity, service or provider is reachable by any other app on
    the device.  Exported *receivers* are how a broadcast can start the app with
    attacker-controlled data, which is the standard route for privilege
    escalation in a local attack.

Requesting permissions is not evidence of malice
------------------------------------------------
Thousands of legitimate apps request contacts, location and camera.  So this
module does not flag a permission on its own; it reports what the permission
*grants*, and raises a finding when the request set is internally inconsistent -
an SMS interceptor that also installs packages, a flashlight app that reads
call logs.  That is what separates a permission list from an attack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding, Severity, SignalSource
from .constants import (
    ACCESSIBILITY_SERVICE_PERMISSION,
    COUNTERFEIT_BRANDS,
    CRYPTO_AND_EXFIL_APIS,
    DANGEROUS_PERMISSION_GROUPS,
    DEVICE_ADMIN_PERMISSIONS,
    OVERLAY_PERMISSIONS,
    PACKAGE_INSTALL_PERMISSIONS,
    PERMISSION_CAPABILITIES,
    PERMISSION_PROTECTION,
    PERMISSION_RISK,
    SMS_PERMISSIONS,
    SUSPICIOUS_PACKAGE_TOKENS,
)

__all__ = ["ManifestInfo", "PermissionReview", "analyze_manifest", "review_permissions"]

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

#: Component tags that can be reached from outside the app when exported.
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

#: Permissions a component may be bound to when it is a legitimate platform
#: integration point.  ``BIND_AUTOFILL_SERVICE`` is the important one: password
#: managers legitimately need accessibility control, and they are identifiable
#: because they also register an autofill service.  A banking trojan asks for
#: accessibility access without ever registering an autofill service.
_AUTOFILL_PERMISSION = "android.permission.BIND_AUTOFILL_SERVICE"

#: Package names that impersonate a platform or a major vendor.
_PLATFORM_PREFIXES = (
    "com.android.system",
    "com.android.server",
    "com.android.vending",
    "com.google.android.gms",
    "com.samsung.android",
    "com.microsoft.office",
)

#: Segments a package name never needs because its publisher already *is* the
#: brand being named.  ``com.paypal.secure.login.official`` says "PayPal" and
#: then "secure" and "official"; the real PayPal app says only "PayPal".
_IMPERSONATION_SEGMENTS = frozenset(
    {
        "account",
        "alert",
        "auth",
        "authenticate",
        "confirm",
        "help",
        "id",
        "login",
        "official",
        "recovery",
        "secure",
        "security",
        "signin",
        "support",
        "update",
        "verify",
        "verification",
        "wallet",
    }
)

#: Application id segments that no honest developer chooses.
_RESERVED_PATH_TOKENS = frozenset(
    {
        "eval",
        "exec",
        "inject",
        "hook",
        "payload",
        "shell",
        "backdoor",
        "trojan",
        "exploit",
        "keylog",
        "c2",
        "beacon",
    }
)


@dataclass(slots=True)
class Component:
    """One declared component."""

    kind: str
    name: str
    exported: bool | None
    permission: str = ""
    authorities: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "exported": self.exported,
            "permission": self.permission,
            "authorities": self.authorities,
        }


@dataclass(slots=True)
class ManifestInfo:
    """Everything read out of AndroidManifest.xml."""

    package: str = ""
    version_name: str = ""
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    debuggable: bool | None = None
    shared_user_id: str = ""
    permissions: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    application_label: str = ""
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    native_libraries: bool = False
    native_code: bool = False
    parse_errors: list[str] = field(default_factory=list)

    @property
    def exported_components(self) -> list[Component]:
        return [c for c in self.components if c.exported is True]

    @property
    def permission_short_names(self) -> list[str]:
        return [_short_permission(p) for p in self.permissions]

    @property
    def registers_autofill_service(self) -> bool:
        """True when the app binds a real Android autofill service.

        This is the discriminator between a password manager and a trojan: both
        ask for accessibility control, but only a password manager also has to
        publish an ``AutofillService`` for the platform to bind it.
        """
        return any(
            component.permission.strip() == _AUTOFILL_PERMISSION
            for component in self.components
        )

    @property
    def capability_weights(self) -> dict[str, float]:
        """Capability granted -> combined risk weight, for scoring."""
        weights: dict[str, float] = {}
        for short in self.permission_short_names:
            if short in PERMISSION_RISK:
                weights[short] = PERMISSION_RISK[short]
        return weights

    def to_dict(self) -> dict[str, object]:
        return {
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "debuggable": self.debuggable,
            "shared_user_id": self.shared_user_id,
            "permissions": self.permissions,
            "features": self.features,
            "components": [c.to_dict() for c in self.components],
            "allow_backup": self.allow_backup,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "native_libraries": self.native_libraries,
            "parse_errors": self.parse_errors,
        }


def _short_permission(permission: str) -> str:
    """``android.permission.READ_SMS`` -> ``READ_SMS``."""
    return permission.rsplit(".", 1)[-1] if "." in permission else permission


def _as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("true", "1", "yes"):
        return True
    if lowered in ("false", "0", "no"):
        return False
    return None


def _as_int(value: str | None) -> int | None:
    try:
        return int((value or "").strip())
    except (TypeError, ValueError):
        return None


def analyze_manifest(xml_root: Any) -> ManifestInfo:
    """Read *xml_root*, an ``lxml`` element for ``<manifest>``.

    Every read is defensive: a manifest can be truncated, a packer can patch
    attribute types, and a scan must report what it could read plus what it
    could not rather than failing outright.
    """
    info = ManifestInfo()
    if xml_root is None:
        info.parse_errors.append("The manifest could not be decoded.")
        return info

    info.package = (xml_root.get(f"{ANDROID_NS}package") or xml_root.get("package") or "").strip()
    info.version_name = (
        xml_root.get(f"{ANDROID_NS}versionName") or xml_root.get("versionName") or ""
    ).strip()
    info.version_code = _as_int(
        xml_root.get(f"{ANDROID_NS}versionCode") or xml_root.get("versionCode")
    )
    info.shared_user_id = (
        xml_root.get(f"{ANDROID_NS}sharedUserId") or xml_root.get("sharedUserId") or ""
    ).strip()
    info.compile_sdk = _as_int(
        xml_root.get(f"{ANDROID_NS}compileSdkVersion") or xml_root.get("compileSdkVersion")
    )

    for element in xml_root.iter():
        tag = element.tag if isinstance(element.tag, str) else ""
        if not tag:
            # Comments and processing instructions have a callable tag.
            continue
        ns_tag = tag.split("}")[-1]

        if ns_tag == "uses-sdk":
            info.min_sdk = _as_int(
                element.get(f"{ANDROID_NS}minSdkVersion") or element.get("minSdkVersion")
            )
            info.target_sdk = _as_int(
                element.get(f"{ANDROID_NS}targetSdkVersion") or element.get("targetSdkVersion")
            )

        elif ns_tag == "uses-permission":
            name = (
                element.get(f"{ANDROID_NS}name") or element.get("name") or ""
            ).strip()
            if name:
                info.permissions.append(name)

        elif ns_tag == "uses-feature":
            name = (
                element.get(f"{ANDROID_NS}name") or element.get("name") or ""
            ).strip()
            if name:
                info.features.append(name)

        elif ns_tag in _COMPONENT_TAGS:
            name = (
                element.get(f"{ANDROID_NS}name") or element.get("name") or ""
            ).strip()
            if not name:
                continue
            exported_raw = element.get(f"{ANDROID_NS}exported")
            component = Component(
                kind=ns_tag,
                name=name,
                exported=_as_bool(exported_raw) if exported_raw is not None else None,
                permission=(
                    element.get(f"{ANDROID_NS}permission") or element.get("permission") or ""
                ).strip(),
                authorities=(
                    element.get(f"{ANDROID_NS}authorities")
                    or element.get("authorities")
                    or ""
                ).strip(),
            )
            info.components.append(component)
            if ns_tag == "service":
                info.services.append(name)
            elif ns_tag == "receiver":
                info.receivers.append(name)
            elif ns_tag == "provider":
                info.providers.append(name)

        elif ns_tag == "application":
            info.debuggable = _as_bool(
                element.get(f"{ANDROID_NS}debuggable") or element.get("debuggable")
            )
            info.allow_backup = _as_bool(
                element.get(f"{ANDROID_NS}allowBackup") or element.get("allowBackup")
            )
            info.uses_cleartext_traffic = _as_bool(
                element.get(f"{ANDROID_NS}usesCleartextTraffic")
                or element.get("usesCleartextTraffic")
            )
            info.native_libraries = _as_bool(
                element.get(f"{ANDROID_NS}hasCode")
            ) is False and bool(
                element.get(f"{ANDROID_NS}extractNativeLibs")
            )
            label = element.get(f"{ANDROID_NS}label") or element.get("label") or ""
            info.application_label = label.strip()

    # Permissions may legitimately be declared with the android prefix or not.
    seen: set[str] = set()
    unique: list[str] = []
    for permission in info.permissions:
        key = permission.lower()
        if key not in seen:
            seen.add(key)
            unique.append(permission)
    info.permissions = sorted(unique)

    if not info.package:
        info.parse_errors.append("The manifest declares no package name.")

    return info


@dataclass(slots=True)
class PermissionReview:
    """The judgement formed from a permission set."""

    requested: list[str]
    short_names: list[str]
    dangerous_groups: list[str]
    critical_capabilities: list[str]
    total_capability_weight: float
    combined_weight: float
    notes: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "requested": self.requested,
            "dangerous_groups": self.dangerous_groups,
            "critical_capabilities": self.critical_capabilities,
            "total_capability_weight": round(self.total_capability_weight, 2),
            "combined_weight": round(self.combined_weight, 2),
            "notes": self.notes,
        }


def review_permissions(info: ManifestInfo) -> PermissionReview:
    """Turn a permission list into a capability review.

    The combined weight uses the same diminishing-returns idea as the risk
    engine: each additional capability adds less than the previous one, because
    the marginal value of a tenth dangerous permission is much lower than the
    first.
    """
    shorts = [_short_permission(p) for p in info.permissions]
    groups = [
        name for name, members in DANGEROUS_PERMISSION_GROUPS.items()
        if any(m in shorts for m in members)
    ]
    critical = [
        short for short in shorts
        if short in SMS_PERMISSIONS
        or short in PACKAGE_INSTALL_PERMISSIONS
        or short in DEVICE_ADMIN_PERMISSIONS
        or short == ACCESSIBILITY_SERVICE_PERMISSION
        or short in OVERLAY_PERMISSIONS
    ]

    weights = [PERMISSION_RISK.get(short, 0.0) for short in shorts]
    total = sum(weights)

    # 1 - prod(1 - w/100): the same noisy-OR the risk engine uses, so a single
    # large capability cannot be diluted by many harmless ones and many small
    # ones cannot add up to a false positive as easily as plain addition.
    remaining = 1.0
    for weight in weights:
        if weight > 0:
            remaining *= 1.0 - min(0.95, weight / 100.0)
    combined = 100.0 * (1.0 - remaining)

    notes: list[str] = []
    if not shorts:
        notes.append("The app requests no permissions.")
    if len(groups) >= 3:
        notes.append(
            f"The app touches {len(groups)} distinct sensitive categories "
            f"({', '.join(sorted(groups))})."
        )
    if ACCESSIBILITY_SERVICE_PERMISSION in shorts:
        notes.append(
            "Accessibility access lets the app read everything on screen and "
            "perform taps on the user's behalf."
        )
    if PACKAGE_INSTALL_PERMISSIONS & set(shorts):
        notes.append("The app can install or remove other apps.")

    return PermissionReview(
        requested=info.permissions,
        short_names=shorts,
        dangerous_groups=groups,
        critical_capabilities=sorted(set(critical)),
        total_capability_weight=total,
        combined_weight=combined,
        notes=notes,
    )


def _brand_impersonation(lowered: str) -> tuple[str, list[str]] | None:
    """Return ``(brand, extra_segments)`` when *lowered* impersonates a brand.

    A brand namespace alone is legitimate - the real app lives there - so the
    signal is the *combination*: the brand prefix followed by segments whose only
    purpose is to assert legitimacy.  Requiring both keeps the genuine
    ``com.paypal.android.p2pmobile`` out of the findings while catching
    ``com.paypal.secure.login.official``.
    """
    for brand, prefixes in COUNTERFEIT_BRANDS.items():
        for prefix in prefixes:
            if not lowered.startswith(prefix):
                continue
            remainder = lowered[len(prefix) :]
            segments = [part for part in remainder.split(".") if part]
            extra = [part for part in segments if part in _IMPERSONATION_SEGMENTS]
            if extra:
                return brand, extra
    return None


def manifest_findings(
    info: ManifestInfo, review: PermissionReview
) -> list[Finding]:
    """Produce findings from the manifest and the permission review."""
    findings: list[Finding] = []

    # ---- identity --------------------------------------------------- #
    lowered = info.package.lower()
    for token in SUSPICIOUS_PACKAGE_TOKENS:
        if token in lowered:
            findings.append(
                Finding(
                    code="APK.SUSPICIOUS_PACKAGE_NAME",
                    title="Package name contains an abuse-associated phrase",
                    detail=(
                        f"The package is '{info.package}', which contains "
                        f"'{token}'. Names like this are used to appear as a "
                        "system update, a security tool or a rewards app while "
                        "belonging to an attacker. The package name alone proves "
                        "nothing, since anyone can choose any name, but it should "
                        "match the publisher you actually installed."
                    ),
                    severity=Severity.HIGH,
                    source=SignalSource.APK_MANIFEST,
                    category="impersonation",
                    weight=18.0,
                    evidence={"package": info.package, "token": token},
                )
            )
            break

    # ---- brand impersonation ----------------------------------------- #
    #
    # Occupying a brand's package namespace is not on its own evidence: the real
    # PayPal app *is* ``com.paypal.android.p2pmobile``.  What distinguishes a
    # counterfeit is a brand namespace followed by the words a credential-harvest
    # page would use - ``secure``, ``login``, ``verify``, ``official``.  No real
    # app ships with those segments appended to its own brand, because the brand
    # chose the name and would not need to tell you it is genuine.
    brand = _brand_impersonation(lowered)
    if brand is not None:
        brand_name, extra = brand
        findings.append(
            Finding(
                code="APK.COUNTERFEIT_BRAND",
                title=f"Package name impersonates {brand_name}",
                detail=(
                    f"The package is '{info.package}', which sits in the "
                    f"{brand_name} namespace and then adds "
                    f"{', '.join(repr(part) for part in extra)}. The genuine "
                    f"{brand_name} application does not append words like these to "
                    "its package name - a name that has to state it is 'secure' or "
                    "'official' is a name chosen to look official. Anyone can claim "
                    "any package name, so this is a reason to check the "
                    "certificate fingerprint against the developer's, not proof of "
                    "fraud."
                ),
                severity=Severity.HIGH,
                source=SignalSource.APK_MANIFEST,
                category="impersonation",
                weight=20.0,
                evidence={"package": info.package, "brand": brand_name, "segments": extra},
            )
        )

    for prefix in _PLATFORM_PREFIXES:
        if lowered.startswith(prefix) and not lowered.startswith(("com.android.vending",)):
            findings.append(
                Finding(
                    code="APK.PLATFORM_NAME_COLLISION",
                    title="Package name collides with an Android platform namespace",
                    detail=(
                        f"The package '{info.package}' starts with '{prefix}', a "
                        "namespace reserved for the platform and the major app "
                        "stores. Only the platform itself may publish there, so an "
                        "app in this namespace is either a repackaged system "
                        "component or an attempt to appear as one."
                    ),
                    severity=Severity.HIGH,
                    source=SignalSource.APK_MANIFEST,
                    category="impersonation",
                    weight=20.0,
                    evidence={"package": info.package, "prefix": prefix},
                )
            )
            break

    if info.shared_user_id:
        claims_system_uid = (
            info.shared_user_id.startswith(("android.", "com.android.", "system."))
            or info.shared_user_id in {"system", "root", "shell", "root", "media_rw"}
        )
        findings.append(
            Finding(
                code="APK.SHARED_USER_ID",
                title="App shares a user identity with other apps",
                detail=(
                    f"The manifest sets sharedUserId='{info.shared_user_id}'. "
                    "Apps sharing a user id run in the same Linux uid, so they "
                    "share data and permissions. This is how system components "
                    "work, and it is also how a trojan gains another app's "
                    "permissions without asking the user again."
                    + (
                        " The identifier it claims belongs to the platform, and a "
                        "third-party app that installs successfully under it is "
                        "either a system component or a repackaged one - a normal "
                        "app cannot be assigned a system uid, so this manifest "
                        "describes privileges the installer cannot actually grant."
                        if claims_system_uid
                        else ""
                    )
                ),
                severity=Severity.HIGH,
                source=SignalSource.APK_MANIFEST,
                category="privilege",
                # Calibrated so a system-uid claim lands in the LOW RISK band (20-39) on its
                # own: real enough to act on, not strong enough to accuse.  The
                # manifest alone cannot show what the app *does* with the uid.
                weight=44.0 if claims_system_uid else 20.0,
                evidence={
                    "shared_user_id": info.shared_user_id,
                    "claims_system_uid": claims_system_uid,
                },
            )
        )

    # ---- build configuration ---------------------------------------- #
    if info.debuggable:
        findings.append(
            Finding(
                code="APK.DEBUGGABLE",
                title="Release build is marked debuggable",
                detail=(
                    "android:debuggable is true. A shipped application should "
                    "always set this to false: it lets anyone with USB debugging "
                    "enabled attach a debugger and read the app's memory, private "
                    "data and decrypted traffic. Repackaged samples commonly keep "
                    "the flag so they can be traced."
                ),
                severity=Severity.HIGH,
                source=SignalSource.APK_MANIFEST,
                category="misconfiguration",
                weight=18.0,
                authoritative=True,
                evidence={"debuggable": True},
            )
        )

    if info.target_sdk is not None and info.target_sdk < 23:
        findings.append(
            Finding(
                code="APK.LEGACY_TARGET_SDK",
                title=f"Targets Android API {info.target_sdk}, before runtime permissions",
                detail=(
                    f"targetSdkVersion is {info.target_sdk}. From API 23 onwards, "
                    "dangerous permissions are granted one at a time by the user; "
                    "below that they are granted wholesale at install time. An app "
                    "targeting this old an API therefore gets contacts, SMS, "
                    "location and the microphone from a single blind 'install', "
                    "and sideloaded malware relies on exactly that."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.APK_MANIFEST,
                category="misconfiguration",
                weight=14.0,
                evidence={"target_sdk": info.target_sdk},
            )
        )

    if info.uses_cleartext_traffic is True:
        findings.append(
            Finding(
                code="APK.CLEARTEXT_TRAFFIC",
                title="App allows unencrypted HTTP traffic",
                detail=(
                    "android:usesCleartextTraffic is true. Traffic to any host can "
                    "be sent without TLS, so a network attacker can read and "
                    "modify it. Financial and messaging apps turn this off "
                    "deliberately."
                ),
                severity=Severity.LOW,
                source=SignalSource.APK_MANIFEST,
                category="misconfiguration",
                weight=6.0,
                evidence={},
            )
        )

    # ---- components -------------------------------------------------- #
    exported_receivers = [
        c for c in info.components if c.kind == "receiver" and c.exported is True
    ]
    if exported_receivers:
        findings.append(
            Finding(
                code="APK.EXPORTED_RECEIVERS",
                title="App exposes broadcast receivers to other apps",
                detail=(
                    f"{len(exported_receivers)} receiver(s) are exported: "
                    f"{', '.join(c.name for c in exported_receivers[:5])}. Any "
                    "app on the device can send them a broadcast, which is how a "
                    "second app hands the first one attacker-controlled data or "
                    "triggers work on its behalf. A receiver needs to be exported "
                    "to receive system broadcasts, so this is not automatically a "
                    "bug - it is worth checking which broadcasts are accepted."
                ),
                severity=Severity.LOW,
                source=SignalSource.APK_MANIFEST,
                category="attack_surface",
                weight=8.0,
                evidence={
                    "receivers": [c.to_dict() for c in exported_receivers[:10]]
                },
            )
        )

    unprotected_providers = [
        c for c in info.components
        if c.kind == "provider" and c.exported is True and not c.permission
    ]
    if unprotected_providers:
        findings.append(
            Finding(
                code="APK.EXPORTED_PROVIDERS_NO_PERMISSION",
                title="Content providers are reachable without a permission",
                detail=(
                    "Exported content providers without a permission attribute let "
                    f"any installed app read their data: "
                    f"{', '.join(c.name for c in unprotected_providers[:4])}. This "
                    "is the shape of a data-leak vulnerability, and it is the route "
                    "several widely-reported Android worms used to spread."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.APK_MANIFEST,
                category="attack_surface",
                weight=14.0,
                evidence={
                    "providers": [c.to_dict() for c in unprotected_providers[:10]]
                },
            )
        )

    # ---- permissions ------------------------------------------------- #
    findings.extend(_permission_findings(info, review))
    return findings


def _permission_findings(
    info: ManifestInfo, review: PermissionReview
) -> list[Finding]:
    """Findings that depend on the permission *combination*, not one permission.

    Where a combination has a known legitimate use, that use is detected and the
    finding is softened rather than dropped - the permissions are still recorded,
    the reader just learns why they are there.
    """
    findings: list[Finding] = []
    shorts = set(review.short_names)
    is_password_manager = info.registers_autofill_service

    if SMS_PERMISSIONS & shorts and (PACKAGE_INSTALL_PERMISSIONS & shorts):
        # Password managers read SMS to capture one-time codes and can install
        # their own browser extension companion, so the combination is not
        # decisive on its own once the autofill service is accounted for.
        softened = is_password_manager
        findings.append(
            Finding(
                code="APK.SMS_AND_INSTALL",
                title="App both reads messages and can install other apps",
                detail=(
                    "The manifest requests "
                    f"{', '.join(sorted(SMS_PERMISSIONS & shorts))} together with "
                    f"{', '.join(sorted(PACKAGE_INSTALL_PERMISSIONS & shorts))}. "
                    "An app that can read SMS can capture a payment's one-time "
                    "code, and an app that can install packages can then deliver "
                    "whatever the code authorised. No single app in the store needs "
                    "both at once."
                    + (
                        " This app also registers an autofill service, which is "
                        "what a password manager does to capture exactly those "
                        "codes, so the combination is expected here rather than "
                        "surprising."
                        if softened
                        else ""
                    )
                ),
                severity=Severity.MEDIUM if softened else Severity.CRITICAL,
                source=SignalSource.APK_PERMISSIONS,
                category="capability",
                weight=14.0 if softened else 34.0,
                authoritative=not softened,
                evidence={
                    "sms": sorted(SMS_PERMISSIONS & shorts),
                    "install": sorted(PACKAGE_INSTALL_PERMISSIONS & shorts),
                    "registers_autofill_service": is_password_manager,
                },
            )
        )

    if ACCESSIBILITY_SERVICE_PERMISSION in shorts and shorts & {
        "INTERNET",
        "READ_SMS",
        "RECORD_AUDIO",
        "READ_CONTACTS",
    }:
        extra = sorted(
            shorts & {"INTERNET", "READ_SMS", "RECORD_AUDIO", "READ_CONTACTS"}
        )
        findings.append(
            Finding(
                code="APK.ACCESSIBILITY_PLUS_ACCESS",
                title="App combines accessibility control with data access",
                detail=(
                    "The manifest requests accessibility service access together "
                    f"with {', '.join(extra)}. "
                    "Accessibility services can read everything displayed on "
                    "screen and perform taps as the user. Google Play restricts "
                    "this permission to accessibility tools, foreground "
                    "transcription and password managers, because it is the "
                    "single most abused capability on the platform and is the "
                    "mechanism behind most banking trojans."
                    + (
                        " This app also registers an autofill service, which is "
                        "the legitimate form of this combination: a password "
                        "manager needs to read the screen to offer to fill a "
                        "credential. The permission set is still unusually broad "
                        "and worth confirming against the publisher you installed "
                        "from, but the app has shown why it needs the access."
                        if is_password_manager
                        else " The app does not register an autofill service, so "
                        "it has not shown a reason to observe the screen that a "
                        "platform integration would not also need."
                    )
                ),
                severity=Severity.LOW if is_password_manager else Severity.CRITICAL,
                source=SignalSource.APK_PERMISSIONS,
                category="capability",
                weight=6.0 if is_password_manager else 36.0,
                authoritative=not is_password_manager,
                evidence={
                    "permissions": sorted(shorts),
                    "registers_autofill_service": is_password_manager,
                },
            )
        )

    if DEVICE_ADMIN_PERMISSIONS & shorts and PACKAGE_INSTALL_PERMISSIONS & shorts:
        findings.append(
            Finding(
                code="APK.DEVICE_ADMIN_PLUS_INSTALL",
                title="App combines device administrator with package installation",
                detail=(
                    "Device administrator access cannot be removed without "
                    "revoking it from system settings, and it lets the app change "
                    "the lock screen and wipe the device. Combined with the ability "
                    "to install packages, the app can add persistent components "
                    "the user cannot easily see or remove."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.APK_PERMISSIONS,
                category="capability",
                weight=32.0,
                authoritative=True,
                evidence={"permissions": sorted(shorts)},
            )
        )

    if len(review.dangerous_groups) >= 4:
        findings.append(
            Finding(
                code="APK.BROAD_CATEGORY_ACCESS",
                title=f"App requests {len(review.dangerous_groups)} sensitive categories at once",
                detail=(
                    "The permission set spans "
                    f"{', '.join(sorted(review.dangerous_groups))}. Legitimate apps "
                    "are narrow - a maps app asks for location and nothing more. A "
                    "broad set is the signature of an app that collects "
                    "everything it can reach, and it is also what a repackaged "
                    "app looks like when the original has been given extra "
                    "permissions."
                ),
                severity=Severity.HIGH,
                source=SignalSource.APK_PERMISSIONS,
                category="capability",
                weight=min(28.0, 6.0 + 4.0 * len(review.dangerous_groups)),
                evidence={
                    "groups": sorted(review.dangerous_groups),
                    "permissions": review.requested[:40],
                },
            )
        )

    unknown = [
        short
        for short in review.short_names
        if short not in PERMISSION_CAPABILITIES
        and short not in PERMISSION_RISK
        and not short.startswith(("com.", "android.permission-group."))
        and short.count(".") == 0
    ]
    if unknown:
        findings.append(
            Finding(
                code="APK.UNRECOGNISED_PERMISSIONS",
                title="Manifest requests permissions not in the known set",
                detail=(
                    f"{len(unknown)} permission(s) were not recognised: "
                    f"{', '.join(unknown[:8])}. They may be a custom permission, a "
                    "newer platform permission this version does not know about, or "
                    "a sign the manifest was assembled rather than built by a "
                    "normal toolchain. CyberShield cannot assess what they allow."
                ),
                severity=Severity.INFO,
                source=SignalSource.APK_PERMISSIONS,
                category="coverage",
                weight=0.0,
                evidence={"permissions": unknown[:30]},
            )
        )

    return findings


def _service_names(info: ManifestInfo) -> list[str]:
    """Component names in a readable form for evidence payloads."""
    names: list[str] = []
    for component in info.components:
        if re.search(r"(?i)(sync|upload|download|receiver|admin|boot|install|update)", component.name):
            names.append(component.name)
    return names[:20]


def permission_capability_table(info: ManifestInfo) -> list[dict[str, object]]:
    """Explain each requested permission, for the report's UI."""
    rows: list[dict[str, object]] = []
    for permission in info.permissions:
        short = _short_permission(permission)
        rows.append(
            {
                "permission": permission,
                "capability": PERMISSION_CAPABILITIES.get(
                    short, "Not a permission CyberShield recognises"
                ),
                "protection": PERMISSION_PROTECTION.get(short, "unknown"),
                "risk_weight": PERMISSION_RISK.get(short, 0.0),
            }
        )
    rows.sort(key=lambda row: -float(row["risk_weight"]))  # type: ignore[arg-type]
    return rows