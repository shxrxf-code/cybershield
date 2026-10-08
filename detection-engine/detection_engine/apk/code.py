"""Static code and string analysis for Android packages.

No bytecode is executed and no method is decompiled
---------------------------------------------------
CyberShield reads the DEX string pool, resource table and asset names.  It does
not execute anything, and it does not claim to have traced control flow, which
is what full decompilation would require and what obfuscation is designed to
prevent.  Every finding below is therefore evidence that something is *present*
in the file, never proof of what the app does when it runs.

Because of that, each pattern is chosen to be specific.  ``System.loadLibrary``
appears in thousands of legitimate apps; ``DexClassLoader`` loading a DEX from
the app's own private directory is normal, and loading one from external storage
downloaded at runtime is not.  The difference is in the surrounding evidence, so
the checks here look at combinations and at locations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from ..models import Finding, Severity, SignalSource
from .constants import (
    CRYPTO_AND_EXFIL_APIS,
    DYNAMIC_LOADING_APIS,
    EMULATOR_DETECTION_APIS,
    GENERIC_SECRET_PATTERNS,
    NAMED_CREDENTIAL_PATTERNS,
    PACKER_INDICATORS,
    REFLECTION_APIS,
    ROOT_DETECTION_APIS,
    ROOT_HINT_PATHS,
)

__all__ = ["StringEvidence", "scan_strings", "string_findings"]

#: A short random-looking label, the signature of an obfuscated identifier.
_OBFUSCATED_LABEL = re.compile(r"^[a-zA-Z]{1,2}$")
#: A single letter or two-letter class name such as ``a.a``.
_OBFUSCATED_CLASS = re.compile(r"^L[A-Za-z]{1,2}(/[A-Za-z]{1,2}){2,};$")
#: Straight ASCII run long enough to hide a URL, IP or command.
_URL_IN_STRING = re.compile(rb"https?://[!-~]{6,300}")
_IP_IN_STRING = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b(?::\d{1,5})?\b")
_EMAIL_IN_STRING = re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{4,}\.[A-Za-z]{2,24}")
_SHELL_COMMAND = re.compile(rb"(?:^|[;&|]\s*)(?:/bin/sh|sh\s+-c|cmd\.exe|powershell)\b")
_ANDROID_SHELL = re.compile(rb"\b(?:su|chmod|chown|mount|getprop|pm\s+install)\b")

#: Minimum Shannon entropy, in bits per character, for a long opaque string.
_HIGH_ENTROPY_THRESHOLD = 4.2
_HIGH_ENTROPY_MIN_LENGTH = 64


@dataclass(slots=True)
class StringEvidence:
    """Observations made while scanning an app's strings."""

    total_strings: int = 0
    class_like: int = 0
    obfuscated_class_like: int = 0
    method_like: int = 0
    obfuscated_method_like: int = 0
    unique_prefix_ratio: float = 0.0
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    secrets: list[tuple[str, str]] = field(default_factory=list)
    #: Credentials matching a named vendor's published key format.  Split from
    #: the generic opaque-value patterns because the two have very different
    #: false-positive rates and deserve very different weights.
    named_credentials: list[tuple[str, str]] = field(default_factory=list)
    packer_indicators: list[str] = field(default_factory=list)
    dynamic_loading: list[str] = field(default_factory=list)
    reflection: list[str] = field(default_factory=list)
    root_detection: list[str] = field(default_factory=list)
    emulator_detection: list[str] = field(default_factory=list)
    shell_commands: list[str] = field(default_factory=list)
    crypto_apis: list[str] = field(default_factory=list)
    suspicious_assets: list[str] = field(default_factory=list)
    high_entropy_strings: int = 0
    strings_available: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "total_strings": self.total_strings,
            "class_like": self.class_like,
            "obfuscated_class_like": self.obfuscated_class_like,
            "method_like": self.method_like,
            "obfuscated_method_like": self.obfuscated_method_like,
            "unique_prefix_ratio": round(self.unique_prefix_ratio, 4),
            "urls": self.urls[:50],
            "domains": sorted(self.domains)[:50],
            "ip_addresses": sorted(self.ip_addresses)[:50],
            "email_addresses": sorted(self.email_addresses)[:20],
            "secrets": [
                {"kind": kind, "redacted": redact(value)} for kind, value in self.secrets
            ],
            "named_credentials": [
                {"kind": kind, "redacted": redact(value)}
                for kind, value in self.named_credentials
            ],
            "packer_indicators": self.packer_indicators[:20],
            "dynamic_loading": self.dynamic_loading[:20],
            "reflection": self.reflection[:20],
            "root_detection": self.root_detection[:20],
            "emulator_detection": self.emulator_detection[:20],
            "shell_commands": self.shell_commands[:20],
            "crypto_apis": self.crypto_apis[:20],
            "suspicious_assets": self.suspicious_assets[:20],
            "high_entropy_strings": self.high_entropy_strings,
            "strings_available": self.strings_available,
        }


def redact(value: str) -> str:
    """Keep enough of a secret to search for it, never enough to use it.

    The first four and last two characters are shown so a user can tell which
    key matched their own credential set, and the middle is replaced.  The full
    value must never reach a scan report or an audit log.
    """
    if len(value) <= 12:
        return "***"
    return f"{value[:4]}{'*' * min(24, len(value) - 6)}{value[-2:]}"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    total = 0.0
    for count in counts:
        if not count:
            continue
        probability = count / length
        total -= probability * _log2(probability)
    return total


def _log2(value: float) -> float:
    import math

    return math.log2(value)


def _match_table(needles: Iterable[str], haystack_lower: str) -> list[str]:
    return [needle for needle in needles if needle.lower() in haystack_lower]


def scan_strings(
    strings: list[str],
    *,
    raw_bytes: bytes = b"",
    asset_names: Iterable[str] = (),
    dex_names: Iterable[str] = (),
) -> StringEvidence:
    """Scan a DEX string pool, plus the raw archive for embedded literals.

    *strings* come from the DEX string pool when androguard could read it, and
    are empty otherwise - in which case ``strings_available`` is False and the
    caller must treat DEX analysis as a coverage gap rather than a clean result.
    """
    evidence = StringEvidence()
    evidence.total_strings = len(strings)

    if not strings:
        evidence.strings_available = False

    # Two separate haystacks, because they answer different questions.
    #
    # ``literal`` is the string pool joined with separators.  It is the right
    # input for token and API matching, where only the token has to appear.
    #
    # ``contiguous`` is the raw archive.  It is used only for patterns that need
    # a contiguous plaintext run - a URL, an embedded credential, a shell command
    # - and only because an APK may store some entries uncompressed.  It cannot
    # replace ``literal``: the DEX itself is almost always deflated, so its
    # strings are absent from the archive bytes entirely.
    literal = "\x00".join(strings).encode("utf-8", errors="replace")
    contiguous = raw_bytes or literal

    # ---- name shape: obfuscation ------------------------------------- #
    for item in strings:
        if _OBFUSCATED_CLASS.match(item):
            evidence.class_like += 1
            evidence.obfuscated_class_like += 1
        elif item.startswith("L") and ";" in item:
            evidence.class_like += 1
        elif "(" in item and ")" in item:
            evidence.method_like += 1
            label = item.split("(", 1)[0].rsplit(".", 1)[-1]
            if _OBFUSCATED_LABEL.match(label):
                evidence.obfuscated_method_like += 1

    if evidence.class_like:
        evidence.unique_prefix_ratio = evidence.obfuscated_class_like / evidence.class_like

    # ---- embedded network literals ----------------------------------- #
    # Both haystacks are searched: a URL can live in the string pool or, for a
    # stored (uncompressed) resource, in the archive bytes.
    for haystack in (literal, contiguous):
        if not haystack:
            continue
        evidence.urls = sorted(
            set(evidence.urls)
            | {m.decode("ascii", "replace") for m in _URL_IN_STRING.findall(haystack)}
        )
        evidence.ip_addresses = sorted(
            set(evidence.ip_addresses)
            | {m.decode("ascii", "replace") for m in _IP_IN_STRING.findall(haystack)}
        )
        evidence.email_addresses = sorted(
            set(evidence.email_addresses)
            | {m.decode("ascii", "replace") for m in _EMAIL_IN_STRING.findall(haystack)}
        )
    evidence.ip_addresses = [
        address
        for address in evidence.ip_addresses
        # Filter out the loopback, broadcast and version placeholders that
        # appear in ordinary code as constants rather than as endpoints.
        if not address.startswith(("0.0.", "127.", "255."))
    ]
    evidence.domains = sorted(
        {
            re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0]
            for url in evidence.urls
        }
        - {""}
    )

    # ---- API usage ---------------------------------------------------- #
    text_lowered = literal.decode("utf-8", errors="replace").lower()
    evidence.dynamic_loading = _match_table(DYNAMIC_LOADING_APIS, text_lowered)
    evidence.reflection = _match_table(REFLECTION_APIS, text_lowered)
    evidence.root_detection = _match_table(ROOT_DETECTION_APIS, text_lowered) + [
        path for path in ROOT_HINT_PATHS if path.lower() in text_lowered
    ]
    evidence.emulator_detection = _match_table(EMULATOR_DETECTION_APIS, text_lowered)
    evidence.crypto_apis = _match_table(CRYPTO_AND_EXFIL_APIS, text_lowered)

    # ---- packers and protectors -------------------------------------- #
    joined_entries = "\n".join([*asset_names, *dex_names, *evidence.urls])
    evidence.packer_indicators = _match_table(PACKER_INDICATORS, joined_entries.lower())
    evidence.suspicious_assets = [
        name
        for name in asset_names
        if re.search(r"(?i)\.(so|dex|jar|bin|dat|elf)$", name)
        and not re.search(r"(?i)(res/|assets/fonts/|assets/images/)", name)
    ][:20]

    # ---- shell and secrets -------------------------------------------- #
    for haystack in (literal, contiguous):
        if not haystack:
            continue
        evidence.shell_commands = sorted(
            set(evidence.shell_commands)
            | {m.decode("ascii", "replace")[:120] for m in _SHELL_COMMAND.findall(haystack)}
            | {m.decode("ascii", "replace") for m in _ANDROID_SHELL.findall(haystack)}
        )
        for table, sink in (
            (NAMED_CREDENTIAL_PATTERNS, evidence.named_credentials),
            (GENERIC_SECRET_PATTERNS, evidence.secrets),
        ):
            for pattern, kind in table:
                for match in re.finditer(pattern.encode(), haystack):
                    entry = (kind, match.group(0).decode("ascii", "replace"))
                    if entry not in sink:
                        sink.append(entry)

    # The credential-assignment pattern needs its identifier and its value to
    # sit together.  In the string pool they are separate entries joined by a NUL,
    # so a straight search never sees ``client_secret=`` next to the value.  The
    # archive bytes do have them adjacent, but only for entries stored without
    # compression, which a real DEX rarely is.  This second pass glues each string
    # to its immediate neighbours before matching, so an assignment split across
    # pool entries is still found.
    if evidence.secrets is not None and strings:
        neighbour_joined = "\x00".join(strings).replace("\x00", "")
        for pattern, kind in GENERIC_SECRET_PATTERNS:
            for match in re.finditer(pattern.encode(), neighbour_joined.encode("utf-8", "replace")):
                entry = (kind, match.group(0).decode("ascii", "replace"))
                if entry not in evidence.secrets:
                    evidence.secrets.append(entry)

    # ---- high entropy, only where it means something ------------------ #
    if len(contiguous) >= _HIGH_ENTROPY_MIN_LENGTH:
        for start in range(0, len(contiguous) - _HIGH_ENTROPY_MIN_LENGTH, 512):
            window = contiguous[start : start + 256]
            if _entropy(window) >= _HIGH_ENTROPY_THRESHOLD and b"\x00" not in window[:16]:
                evidence.high_entropy_strings += 1

    return evidence


def string_findings(evidence: StringEvidence, package: str = "") -> list[Finding]:
    """Turn :class:`StringEvidence` into findings.

    Each finding says what was observed and what it does *not* establish, because
    a string match is evidence of presence and not of behaviour.
    """
    findings: list[Finding] = []

    if not evidence.strings_available:
        findings.append(
            Finding(
                code="APK.DEX_STRINGS_UNAVAILABLE",
                title="The DEX string pool could not be read",
                detail=(
                    "CyberShield could not extract strings from the DEX files. "
                    "Code analysis - dynamic loading, reflection, hardcoded "
                    "credentials, packer and emulator checks - was therefore not "
                    "performed. The result below reflects only the manifest and "
                    "any archive-level analysis, and this is a gap in coverage "
                    "rather than evidence that the app is clean."
                ),
                severity=Severity.INFO,
                source=SignalSource.APK_CODE,
                category="coverage",
                weight=0.0,
                evidence={},
            )
        )
        return findings

    if evidence.packer_indicators:
        findings.append(
            Finding(
                code="APK.PACKER_OR_PROTECTOR",
                title="Package is wrapped in a commercial packer or protector",
                detail=(
                    "Found: "
                    f"{', '.join(evidence.packer_indicators[:5])}. Packers encrypt "
                    "the real DEX and unpack it at runtime, which is legitimate for "
                    "IP protection and is also what malware uses so that the code "
                    "a store scanner sees is not the code that runs. CyberShield "
                    "cannot analyse what is inside, so this lowers confidence in "
                    "the rest of the result."
                ),
                severity=Severity.HIGH,
                source=SignalSource.APK_CODE,
                category="evasion",
                weight=20.0,
                evidence={"indicators": evidence.packer_indicators[:20]},
            )
        )

    if evidence.emulator_detection:
        findings.append(
            Finding(
                code="APK.EMULATOR_DETECTION",
                title="Package checks whether it is running in an emulator",
                detail=(
                    f"The code references {len(evidence.emulator_detection)} "
                    f"emulator-detection marker(s): "
                    f"{', '.join(evidence.emulator_detection[:6])}. Malware uses "
                    "this to stay dormant inside analysis sandboxes, so a report "
                    "generated in an emulator environment may understate what the "
                    "app does on a real device. Some legitimate apps use it for "
                    "developer warnings or licensing."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.APK_CODE,
                category="evasion",
                weight=14.0,
                evidence={"markers": evidence.emulator_detection[:20]},
            )
        )

    if evidence.root_detection:
        findings.append(
            Finding(
                code="APK.ROOT_DETECTION",
                title="Package checks whether the device is rooted",
                detail=(
                    "The code probes for root: "
                    f"{', '.join(evidence.root_detection[:5])}. Banking, DRM and "
                    "enterprise apps legitimately refuse to run on a rooted device, "
                    "so this is usually benign. It is recorded because the same "
                    "check is used to find out whether extra privileges are "
                    "available."
                ),
                severity=Severity.LOW,
                source=SignalSource.APK_CODE,
                category="environment",
                weight=6.0,
                evidence={"markers": evidence.root_detection[:20]},
            )
        )

    if evidence.dynamic_loading:
        findings.append(
            Finding(
                code="APK.DYNAMIC_CODE_LOADING",
                title="Package loads code at runtime",
                detail=(
                    "The code references "
                    f"{', '.join(evidence.dynamic_loading[:5])}. Runtime code "
                    "loading is normal for plugin systems and hot-fix delivery, and "
                    "it is also the standard way to fetch a payload that was never "
                    "present in the APK a store scanner inspected. CyberShield has "
                    "not determined which this is."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.APK_CODE,
                category="evasion",
                weight=12.0,
                evidence={"apis": evidence.dynamic_loading[:20]},
            )
        )

    if evidence.shell_commands:
        findings.append(
            Finding(
                code="APK.SHELL_INVOCATION",
                title="Package invokes a system shell",
                detail=(
                    f"The package contains shell command text: "
                    f"{'; '.join(evidence.shell_commands[:5])}. Executing shell "
                    "commands requires either an external shell binary or the "
                    "ability to gain root, both of which are used by trojans to "
                    "persist and to escalate."
                ),
                severity=Severity.HIGH,
                source=SignalSource.APK_CODE,
                category="capability",
                weight=18.0,
                evidence={"commands": evidence.shell_commands[:20]},
            )
        )

    if evidence.named_credentials:
        kinds = sorted({kind for kind, _ in evidence.named_credentials})
        findings.append(
            Finding(
                code="APK.EMBEDDED_CREDENTIAL",
                title="A vendor-issued credential is embedded in the package",
                detail=(
                    f"{len(evidence.named_credentials)} value(s) match the exact "
                    f"published format of a real credential type: "
                    f"{', '.join(kinds)}. A credential shipped inside an app is "
                    "public - it is in the APK that every downloader already has, "
                    "and it is recoverable by anyone who unzips the file. If the "
                    "service behind it trusts this credential, that service is "
                    "compromised by anyone who installs the app, and rotating the "
                    "credential is the only fix because the old one must be "
                    "assumed disclosed.\n\n"
                    "CyberShield has not tested whether these credentials still "
                    "work and does not attempt to; the values are redacted here "
                    "and are never written to a report or a log. A credential of "
                    "this shape in a shipped build is also usually a policy "
                    "violation: Google Play rejects apps containing API keys."
                ),
                severity=Severity.HIGH,
                source=SignalSource.APK_SECRET,
                category="secret",
                weight=52.0,
                evidence={
                    "kinds": kinds,
                    "count": len(evidence.named_credentials),
                    "redacted": [
                        {"kind": kind, "value": redact(value)}
                        for kind, value in evidence.named_credentials[:10]
                    ],
                },
            )
        )

    if evidence.secrets:
        kinds = sorted({kind for kind, _ in evidence.secrets})
        findings.append(
            Finding(
                code="APK.OPAQUE_SECRETS",
                title="Opaque credential-shaped constants found in the package",
                detail=(
                    f"{len(evidence.secrets)} long or credential-shaped constant(s) "
                    f"were found: {', '.join(kinds[:6])}. Unlike a recognised "
                    "vendor key, this is a shape rather than a confirmed type, and "
                    "compiled constants, packed resources and encoded asset data "
                    "routinely look like this - so this is weak evidence on its "
                    "own. It is listed so a reviewer can check whether any of it "
                    "belongs to the app's own backend."
                ),
                severity=Severity.LOW,
                source=SignalSource.APK_CODE,
                category="secret",
                weight=6.0,
                evidence={
                    "kinds": kinds,
                    "count": len(evidence.secrets),
                    "redacted": [
                        {"kind": kind, "value": redact(value)}
                        for kind, value in evidence.secrets[:10]
                    ],
                },
            )
        )

    if evidence.ip_addresses:
        findings.append(
            Finding(
                code="APK.HARDCODED_IP_ADDRESSES",
                title="Package contains raw IP addresses",
                detail=(
                    f"{len(evidence.ip_addresses)} literal IP address(es) appear in "
                    "the code or resources. Hard-coded addresses skip DNS, which "
                    "makes them resilient to takedown and invisible to "
                    "domain-based blocking, so they are a common choice for "
                    "command-and-control endpoints: "
                    f"{', '.join(evidence.ip_addresses[:5])}."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.APK_CODE,
                category="network",
                weight=12.0,
                evidence={"addresses": evidence.ip_addresses[:50]},
            )
        )

    if evidence.suspicious_assets:
        findings.append(
            Finding(
                code="APK.OPAQUE_ASSETS",
                title="Package bundles opaque binary assets",
                detail=(
                    "The archive contains native libraries or data blobs outside "
                    "the resource tree: "
                    f"{', '.join(evidence.suspicious_assets[:6])}. Content hidden "
                    "this way is not parsed by any store scanner, and it is where "
                    "encrypted second-stage payloads are usually kept."
                ),
                severity=Severity.LOW,
                source=SignalSource.APK_CODE,
                category="evasion",
                weight=8.0,
                evidence={"assets": evidence.suspicious_assets[:20]},
            )
        )

    if (
        evidence.total_strings >= 200
        and evidence.class_like >= 20
        and evidence.unique_prefix_ratio > 0.6
    ):
        findings.append(
            Finding(
                code="APK.HEAVILY_OBFUSCATED",
                title="Most class names have been obfuscated",
                detail=(
                    f"{evidence.obfuscated_class_like} of {evidence.class_like} "
                    f"class names ({evidence.unique_prefix_ratio:.0%}) are short "
                    "random labels. Obfuscation is normal commercial practice and "
                    "is not evidence of harm, but it does prevent a static reader "
                    "from judging what the code does, so it reduces confidence in "
                    "every other code-based check."
                ),
                severity=Severity.INFO,
                source=SignalSource.APK_CODE,
                category="coverage",
                weight=0.0,
                evidence={
                    "class_like": evidence.class_like,
                    "obfuscated": evidence.obfuscated_class_like,
                    "ratio": round(evidence.unique_prefix_ratio, 4),
                },
            )
        )

    return findings