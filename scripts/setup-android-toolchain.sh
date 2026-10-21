#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Mobile ThreatGuard – Android toolchain bootstrap (Fedora / Linux x64)
#
# Installs, into the locations scripts/dev-env.sh already expects:
#   * Temurin JDK 17  -> ~/.local/lib/threatguard-jdk17
#   * Android SDK     -> ~/Android/Sdk   (cmdline-tools, platform-tools,
#                                         platform, build-tools, NDK, cmake)
#
# Run it once:
#   ./scripts/setup-android-toolchain.sh
# then source the environment before building:
#   source scripts/dev-env.sh
#
# The script is idempotent: already-installed components are skipped, so it is
# safe to re-run after a partial download.
# ---------------------------------------------------------------------------
set -euo pipefail

JDK_HOME="${JDK_HOME:-$HOME/.local/lib/threatguard-jdk17}"
ANDROID_SDK="${ANDROID_SDK:-$HOME/Android/Sdk}"
# Last command-line tools drop published in Google's Android repository XML.
CMDLINE_TOOLS_BUILD="${CMDLINE_TOOLS_BUILD:-9862592}"

# Versions the Gradle build requires (android/build.gradle).
PLATFORM="platforms;android-37"
BUILD_TOOLS="build-tools;37.0.0"
NDK="ndk;27.1.12297006"
CMAKE="cmake;3.22.1"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null || die "curl is required"
command -v tar   >/dev/null || die "tar is required"
command -v unzip >/dev/null || die "unzip is required"

# --- 1. JDK ---------------------------------------------------------------
if [ -x "$JDK_HOME/bin/javac" ]; then
  log "JDK already present: $JDK_HOME ($("$JDK_HOME/bin/javac" -version 2>&1))"
else
  log "Downloading Temurin JDK 17"
  tmp_jdk="$(mktemp -d)"
  curl -fL --retry 3 --retry-delay 2 \
    -o "$tmp_jdk/jdk17.tar.gz" \
    "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse"
  mkdir -p "$tmp_jdk/extract"
  tar xzf "$tmp_jdk/jdk17.tar.gz" -C "$tmp_jdk/extract" --strip-components=1
  rm -rf "$JDK_HOME"
  mkdir -p "$(dirname "$JDK_HOME")"
  mv "$tmp_jdk/extract" "$JDK_HOME"
  rm -rf "$tmp_jdk"
  log "Installed $JDK_HOME ($("$JDK_HOME/bin/javac" -version 2>&1))"
fi

export JAVA_HOME="$JDK_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

# --- 2. Android SDK + cmdline-tools ---------------------------------------
if [ -d "$ANDROID_SDK" ]; then
  log "Android SDK already present: $ANDROID_SDK"
else
  mkdir -p "$ANDROID_SDK"
fi

if [ ! -x "$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  log "Downloading Android command-line tools"
  tmp_sdk="$(mktemp -d)"
  curl -fL --retry 3 --retry-delay 2 \
    -o "$tmp_sdk/cmdline-tools.zip" \
    "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_BUILD}_latest.zip"
  unzip -q "$tmp_sdk/cmdline-tools.zip" -d "$tmp_sdk"
  mkdir -p "$ANDROID_SDK/cmdline-tools"
  rm -rf "$ANDROID_SDK/cmdline-tools/latest"
  mv "$tmp_sdk/cmdline-tools" "$ANDROID_SDK/cmdline-tools/latest"
  rm -rf "$tmp_sdk"
fi

SDKMANAGER="$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager"
export ANDROID_SDK_ROOT="$ANDROID_SDK"

log "Accepting SDK licences"
yes | "$SDKMANAGER" --sdk_root="$ANDROID_SDK" --licenses >/dev/null || true

# --- 3. SDK packages -------------------------------------------------------
log "Determining available packages"
available="$("$SDKMANAGER" --sdk_root="$ANDROID_SDK" --list 2>/dev/null || true)"

wanted=("$PLATFORM" "$BUILD_TOOLS" "$NDK" "$CMAKE")
missing=()
for pkg in "${wanted[@]}"; do
  if printf '%s' "$available" | grep -qF "$pkg"; then
    printf '  present : %s\n' "$pkg"
  else
    printf '  missing : %s\n' "$pkg"
    missing+=("$pkg")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  log "Requested packages not found in Google's repository:"
  printf '  %s\n' "${missing[@]}"
  printf '\nClosest available Android platforms:\n'
  printf '%s' "$available" | grep -E '^\s+platforms;android-[0-9]+' | sort -u | tail -10 || true
  die "The Gradle build expects these exact versions. Adjust android/build.gradle or wait for the repository to publish them."
fi

log "Installing SDK packages (platform-tools, $PLATFORM, $BUILD_TOOLS, $NDK, $CMAKE)"
"$SDKMANAGER" --sdk_root="$ANDROID_SDK" \
  "platform-tools" "$PLATFORM" "$BUILD_TOOLS" "$NDK" "$CMAKE"

log "Done"
printf '  JAVA_HOME=%s\n' "$JAVA_HOME"
printf '  ANDROID_HOME=%s\n' "$ANDROID_SDK"
printf '\nSource scripts/dev-env.sh before building the app.\n'
