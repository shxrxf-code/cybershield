#!/usr/bin/env bash
# Run the CyberShield Flutter client on Linux desktop.
#
# Handles three machine-specific wrinkles so the common case is a single
# command:
#
#   1. `flutter_secure_storage_linux` needs the `libsecret-1` development
#      files (headers + .pc). On a normal machine these come from the distro
#      package (Debian/Ubuntu: `sudo apt install libsecret-1-dev`). Where the
#      package is missing and you have no root, this script fetches the .deb
#      and extracts it into a user-local tree (default /tmp/opencode) instead;
#      the plugin's CMake uses the PKG_CONFIG_PATH above. The linker also needs
#      the directory via -L (fed through CMAKE_SHARED_LINKER_FLAGS below), and
#      the dev package's libsecret-1.so is a dangling symlink, so the runtime
#      lib is pointed at the system copy.
#
#   2. The bundled nlohmann/json.hpp in flutter_secure_storage_linux uses
#      deprecated literal operators that newer clang treats as errors under
#      -Werror. We suppress just that warning via CXXFLAGS.
#
#   3. On virtual/headless displays hardware GLX can die with GLXBadPixmap and
#      Impeller-on-llvmpipe can crash at startup. We force Mesa's software
#      rasteriser (LIBGL_ALWAYS_SOFTWARE=1, stable everywhere at the cost of
#      performance) and disable Impeller so the engine uses Skia instead, which
#      survives both GLX flakiness and software GL on this machine.
#
# API base URL: defaults to http://localhost:8000 (see lib/core/config.dart).
# Point it at another host with API_BASE_URL, e.g.
#
#     API_BASE_URL=http://10.0.0.5:8000 ./tool/run_linux.sh
#
# For an Android emulator, use the host's LAN IP rather than localhost.
set -euo pipefail

# --- locate repo root --------------------------------------------------- #
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${CLIENT_DIR}"

LIBDIR_ROOT="${LIBSECRET_PREFIX:-/tmp/opencode/libsecret-dev}"
FLAGS=()

# --- ensure libsecret-1 pkg-config metadata is available --------------- #
if pkg-config --exists libsecret-1 2>/dev/null; then
  echo "[run_linux] system libsecret-1 found"
else
  echo "[run_linux] libsecret-1 not on the system pkg-config path; using local tree"
  PC_DIR="${LIBDIR_ROOT}/root/usr/lib/x86_64-linux-gnu/pkgconfig"
  if ! pkg-config --exists libsecret-1 2>/dev/null \
      && [ ! -f "${PC_DIR}/libsecret-1.pc" ]; then
    echo "[run_linux] preparing local libsecret-1 dev tree under ${LIBDIR_ROOT} ..."
    mkdir -p "${LIBDIR_ROOT}"
    (
      cd "${LIBDIR_ROOT}"
      apt-get download libsecret-1-dev >/dev/null
      dpkg-deb -x libsecret-1-dev_*.deb root
      PC="root/usr/lib/x86_64-linux-gnu/pkgconfig/libsecret-1.pc"
      sed -i "s|^prefix=/usr$|prefix=${LIBDIR_ROOT}/root/usr|" "${PC}"
      sed -i '/^Requires.private:/d' "${PC}"
      ln -sf /usr/lib/x86_64-linux-gnu/libsecret-1.so.0 \
        "root/usr/lib/x86_64-linux-gnu/libsecret-1.so.0"
    )
  fi
  export PKG_CONFIG_PATH="${PC_DIR}"
  export LIBRARY_PATH="${LIBDIR_ROOT}/root/usr/lib/x86_64-linux-gnu"
  FLAGS+=("-DCMAKE_SHARED_LINKER_FLAGS=-L${LIBRARY_PATH}")
fi

# --- silence the bundled-json deprecation errors in the plugin ---------- #
export CXXFLAGS="-Wno-deprecated-literal-operator -Wno-error=deprecated-literal-operator"

# --- stable rendering on virtual displays ------------------------------- #
export LIBGL_ALWAYS_SOFTWARE=1
FLAGS+=("--no-enable-impeller")

# --- API base URL override ---------------------------------------------- #
if [ -n "${API_BASE_URL:-}" ]; then
  FLAGS+=("--dart-define=API_BASE_URL=${API_BASE_URL}")
fi

echo "[run_linux] executing: flutter run -d linux ${FLAGS[*]}"
exec /home/sharaf/flutter/bin/flutter run -d linux "${FLAGS[@]}"