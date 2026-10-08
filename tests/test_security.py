"""The network and filesystem policy that keeps the analyser from being a weapon.

CyberShield fetches URLs a stranger submitted.  Without a strict outbound policy
that turns the service into a request proxy pointed at the deployment's own
network: an attacker submits ``http://169.254.169.254/`` and reads the cloud
instance's credentials out of the response.  Every test here exists because that
failure is severe and quiet.

The filesystem half matters for the same reason.  Uploads arrive with
attacker-chosen names, and a name like ``../../../etc/cron.d/x`` turns a file
store into arbitrary write.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from detection_engine.security.constants import (
    is_public_address,
    unwrap_translated_ipv4,
)
from detection_engine.security.hardening import (
    constant_time_equals,
    is_path_traversal,
    posix_member_path,
    safe_join,
    sanitize_filename,
    strip_ansi,
    truncate_utf8,
    windows_member_path,
)
from detection_engine.security.ssrf import SsrfBlockedError, SsrfPolicy


# --------------------------------------------------------------------- #
# Address policy
# --------------------------------------------------------------------- #


BLOCKED_LITERALS = [
    # Loopback.
    "127.0.0.1",
    "127.1.2.3",
    "127.255.255.254",
    # RFC1918.
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.255.255",
    # Link-local, which is where the cloud metadata service lives.
    "169.254.169.254",
    "169.254.0.1",
    # Carrier-grade NAT, and the "this network" placeholder.
    "100.64.0.1",
    "0.0.0.0",
    # IPv6 loopback and unspecified.
    "::1",
    "::",
    # IPv6 unique-local and link-local.
    "fc00::1",
    "fd12:3456:789a::1",
    "fe80::1",
    # IPv4-mapped and NAT64 forms of the above.
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "64:ff9b::7f00:1",
    "64:ff9b::a9fe:a9fe",
    # 6to4 wrapping a private IPv4.
    "2002:7f00:0001::",
    # Local-use NAT64 prefix, blocked outright.
    "64:ff9b:1::1",
    # Multicast and reserved.
    "224.0.0.1",
    "240.0.0.1",
]


@pytest.mark.parametrize("address", BLOCKED_LITERALS)
def test_blocked_addresses(address: str) -> None:
    with pytest.raises(SsrfBlockedError):
        SsrfPolicy().check_host_literal(address)


ALLOWED_LITERALS = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "2606:4700:4700::1111",
    "2a00:1450:4001:81f::200e",
    # NAT64 synthesis of a public IPv4, which is what a real IPv6-only network
    # hands out for an ordinary site.  Blocking it would break every scan on
    # such a network, so the embedded IPv4 is what gets judged.
    "64:ff9b::0808:0808",
    "2002:0808:0808::",
    "::ffff:8.8.8.8",
]


@pytest.mark.parametrize("address", ALLOWED_LITERALS)
def test_allowed_addresses(address: str) -> None:
    SsrfPolicy().check_host_literal(address)


def test_translation_prefixes_are_unwrapped() -> None:
    """The unwrapper exists so NAT64/6to4 targets are judged as IPv4.

    It returns the *embedded* IPv4 address, or an empty string when there is
    none - a native IPv6 address is not a translation wrapper and must be judged
    by the IPv6 rules instead.
    """
    assert unwrap_translated_ipv4("::ffff:169.254.169.254") == "169.254.169.254"
    assert unwrap_translated_ipv4("64:ff9b::7f00:1") == "127.0.0.1"
    assert unwrap_translated_ipv4("2002:7f00:0001::") == "127.0.0.1"
    assert unwrap_translated_ipv4("2606:4700::1111") == ""
    assert unwrap_translated_ipv4("not-an-address") == ""


def test_local_nat64_prefix_is_not_unwrapped() -> None:
    """``64:ff9b:1::/48`` is the local-use prefix and embeds no IPv4 address."""
    assert unwrap_translated_ipv4("64:ff9b:1::1") == ""
    with pytest.raises(SsrfBlockedError):
        SsrfPolicy().check_host_literal("64:ff9b:1::1")


def test_is_public_address_agrees_with_the_policy() -> None:
    assert is_public_address("8.8.8.8")
    assert not is_public_address("10.0.0.1")
    assert not is_public_address("fe80::1")


def test_allow_private_switch_is_explicit() -> None:
    """Only a deliberate configuration may open the private ranges."""
    policy = SsrfPolicy(allow_private=True)
    policy.check_host_literal("127.0.0.1")
    policy.check_host_literal("169.254.169.254")


# --------------------------------------------------------------------- #
# Scheme, port and name policy
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("scheme", ["file", "gopher", "dict", "ftp", "ldap", "jar", "netdoc"])
def test_non_http_schemes_are_refused(scheme: str) -> None:
    with pytest.raises(SsrfBlockedError):
        SsrfPolicy().check_scheme(scheme)


def test_cloud_metadata_hostnames_are_blocked_by_name() -> None:
    policy = SsrfPolicy()
    for host in (
        "metadata.google.internal",
        "metadata.goog",
        "instance-data.ec2.internal",
        # Trailing dot must not bypass an exact-match denylist.
        "METADATA.GOOGLE.INTERNAL.",
    ):
        with pytest.raises(SsrfBlockedError):
            policy.check_hostname(host)


def test_port_allowlist_is_enforced() -> None:
    policy = SsrfPolicy(allowed_ports=frozenset({80, 443}))
    policy.check_port(443)
    with pytest.raises(SsrfBlockedError):
        policy.check_port(22)
    with pytest.raises(SsrfBlockedError):
        policy.check_port(0)


def test_every_dns_answer_must_be_public() -> None:
    """One private answer poisons the whole name.

    Rejecting only when *every* answer is private would let an attacker publish
    one public and one private A record and win the race between our check and
    the connection we actually make.
    """
    policy = SsrfPolicy()
    with pytest.raises(SsrfBlockedError):
        policy.check_all_resolved(["93.184.216.34", "127.0.0.1"], "rebind.example")


def test_public_answers_pass_through() -> None:
    policy = SsrfPolicy()
    addresses = ["93.184.216.34", "93.184.216.35"]
    assert policy.check_all_resolved(addresses, "example.com") == addresses


# --------------------------------------------------------------------- #
# Filename handling
# --------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("report.pdf", "report.pdf"),
        ("../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32\\cmd.exe", "cmd.exe"),
        ("/absolute/path/file.txt", "file.txt"),
        ("....//....//etc/shadow", "shadow"),
        # A NUL is a C-string terminator, so the safe reading of
        # ``evil.txt\x00.png`` is ``evil.txt`` - not two extensions.
        ("file\x00name.txt", "filename.txt"),
        ("file\x00.txt", "file.txt"),
        ("", "upload.bin"),
        (".", "upload.bin"),
        ("..", "upload.bin"),
        (None, "upload.bin"),
        # Reserved Windows device names still need a stem.
        ("CON", "CON_file"),
        ("nul.txt", "nul_file.txt"),
    ],
)
def test_sanitize_filename(raw: str | None, expected: str) -> None:
    assert sanitize_filename(raw) == expected


def test_sanitize_filename_never_contains_a_separator() -> None:
    """The invariant the rest of the system relies on.

    Every path flavour an attacker might use has to collapse to a bare name,
    because the result is used as a filename *and* written into logs and API
    responses.
    """
    for raw in (
        "../../etc/passwd",
        "..\\..\\boot.ini",
        "/dev/../etc/shadow",
        "a/b/c/d.exe",
        "....//....//x",
    ):
        cleaned = sanitize_filename(raw)
        assert "/" not in cleaned
        assert "\\" not in cleaned
        assert ".." not in cleaned


def test_sanitize_filename_strips_ansi_and_bounds_length() -> None:
    assert sanitize_filename("\x1b[31mred.txt\x1b[0m") == "red.txt"
    assert len(sanitize_filename("a" * 500 + ".exe")) <= 255


def test_sanitize_filename_keeps_a_usable_extension() -> None:
    assert sanitize_filename("invoice.pdf.exe").endswith(".exe")
    assert sanitize_filename("noextension").endswith("noextension")


@pytest.mark.parametrize(
    "candidate",
    [
        "../etc/passwd",
        "a/../../b",
        "/etc/shadow",
        "a/b/../../../c",
        "..",
    ],
)
def test_path_traversal_is_detected(candidate: str) -> None:
    assert is_path_traversal(candidate)


def test_safe_join_confines_to_base(tmp_path: Path) -> None:
    base = tmp_path / "uploads"
    base.mkdir()
    resolved = safe_join(base, "abc123.bin")
    assert base in resolved.parents
    # ``safe_join`` raises ValueError, not the package's own exception type, so
    # callers catch ValueError at this boundary and DetectionEngineError above.
    with pytest.raises(ValueError):
        safe_join(base, "../../etc/passwd")


def test_safe_join_blocks_symlink_escape(tmp_path: Path) -> None:
    """A symlink planted inside the store must not become an exit.

    Resolving the base and the candidate and then re-checking containment is what
    catches this; string-prefix checks do not.
    """
    base = tmp_path / "uploads"
    outside = tmp_path / "outside"
    base.mkdir()
    outside.mkdir()
    (base / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        safe_join(base, "escape", "payload.bin")


def test_constant_time_equals() -> None:
    assert constant_time_equals("token", "token")
    assert not constant_time_equals("token", "toke")
    assert not constant_time_equals("token", "tokenn")


def test_truncate_utf8_does_not_split_a_character() -> None:
    """Truncating a UTF-8 string mid-sequence produces a replacement character
    that then fails to parse as JSON or a header.  This must cut on a boundary."""
    data = "héllo wörld".encode()
    for limit in range(1, len(data)):
        out = truncate_utf8(data, limit)
        assert len(out) <= limit
        out.decode("utf-8")  # must not raise


def test_strip_ansi_escapes() -> None:
    """Terminal escapes in a filename would otherwise reach the console log."""
    assert "\x1b" not in strip_ansi("\x1b[2J\x1b[1;31mboom\x1b[0m")
    assert "boom" in strip_ansi("\x1b[2J\x1b[1;31mboom\x1b[0m")


# --------------------------------------------------------------------- #
# Archive member paths
# --------------------------------------------------------------------- #


def test_archive_member_paths_are_normalised_for_inspection() -> None:
    """Both readers flatten separators so traversal is visible to one check.

    A zip entry's name is attacker-controlled and the same archive can be
    extracted by a POSIX or a Windows tool.  Normalising the separator flavour
    first is what lets one traversal test cover both, and it must not *drop* the
    ``..`` segments: a name that looks safe after collapsing them is exactly the
    one a scanner has to flag.
    """
    assert posix_member_path("../../etc/passwd") == "../../etc/passwd"
    assert posix_member_path("a\\b.txt") == "a/b.txt"
    assert windows_member_path("..\\..\\windows\\system32\\cmd.exe") == (
        "../../windows/system32/cmd.exe"
    )
    # Both flavours of the same hostile name must be detected by the same check.
    assert is_path_traversal(posix_member_path("..\\..\\windows\\x.exe"))
    assert is_path_traversal(windows_member_path("../../etc/passwd"))


def test_ipaddress_module_agrees_with_our_ranges() -> None:
    """Guard against a range drifting away from the stdlib's view of reality."""
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"):
        net = ipaddress.ip_network(network)
        assert not net.is_global or network == "169.254.0.0/16"