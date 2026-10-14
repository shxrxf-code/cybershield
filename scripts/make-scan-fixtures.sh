#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Mobile ThreatGuard — generate local file-scan test fixtures.
#
# Produces a directory of harmless files that exercise every branch of the
# on-device scanning engine (signature hit, format mismatch, empty, corrupt,
# unsupported, oversized). Nothing here is real malware; the only "threat" is
# the industry-standard EICAR test string.
#
# Usage:
#   scripts/make-scan-fixtures.sh [out-dir]      # default: /tmp/threatguard-fixtures
#
# Then copy the directory to the device:
#   adb push /tmp/threatguard-fixtures /sdcard/Download/threatguard-fixtures
# ---------------------------------------------------------------------------
set -euo pipefail

OUT_DIR="${1:-/tmp/threatguard-fixtures}"
mkdir -p "$OUT_DIR"

python3 - "$OUT_DIR" <<'PY'
import os
import struct
import sys
import zipfile
import zlib

out = sys.argv[1]

def write(name: str, data: bytes) -> None:
    path = os.path.join(out, name)
    with open(path, "wb") as fh:
        fh.write(data)
    print(f"  {name:<28} {len(data):>10} bytes")

print(f"Writing fixtures to {out}")

# 1. A minimal, structurally valid PDF (one page, no actions).
valid_pdf = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)
write("valid.pdf", valid_pdf)

# 2. A real 1x1 PNG.
def png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )

png = (
    b"\x89PNG\r\n\x1a\n"
    + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    + png_chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
    + png_chunk(b"IEND", b"")
)
write("valid.png", png)

# 3. A synthetic APK: a zip with the two entries a real package must contain.
apk_path = os.path.join(out, "valid.apk")
with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00dummy-binary-manifest")
    zf.writestr("classes.dex", b"dex\n035\x00dummy")
    zf.writestr("res/values/strings.xml", b"<resources/>")
print(f"  {'valid.apk':<28} {os.path.getsize(apk_path):>10} bytes (synthetic zip)")

# 4. Unsupported/unknown type — random bytes with an unknown extension.
write("unsupported.xyz", os.urandom(2048))

# 5. Empty file.
write("empty.bin", b"")

# 6. "Corrupted" PDF — a valid header followed by garbage. Should scan without
#    crashing and raise no signature findings.
write("corrupted.pdf", b"%PDF-1.7\n" + os.urandom(4096))

# 7. Format mismatch — a PNG renamed to .jpg. Expected: low-severity
#    "contents do not match the extension" finding (suspicious, not malware).
write("mismatch.jpg", png)

# 8. A PDF that carries embedded JavaScript. Expected: suspicious.
pdf_with_js = (
    b"%PDF-1.5\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\n"
    b"4 0 obj<</S/JavaScript/JS(app.alert('hi'))>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)
write("pdf-with-js.pdf", pdf_with_js)

# 9. The EICAR anti-malware test string inside a text file. Expected: threat.
eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
write("eicar.txt", eicar + b"\n")

print()
print("Optional large-file guard test (disabled by default — writes ~110 MB):")
print(f"  head -c 115000000 /dev/urandom > {os.path.join(out, 'oversized.bin')}")
PY

echo
echo "Done. Fixtures are in: $OUT_DIR"
echo "Push them to a device with:"
echo "  adb push \"$OUT_DIR\" /sdcard/Download/threatguard-fixtures"
