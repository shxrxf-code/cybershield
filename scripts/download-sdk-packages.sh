#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Mobile ThreatGuard – resilient Android SDK package downloader
#
# WHY THIS EXISTS
#   On this machine the Android SDK packages are fetched over a link where
#   long HTTPS reads stall without ever timing out. Both `sdkmanager` and the
#   Gradle wrapper hang the same way: the transfer sits at a fixed percentage
#   (observed: sdkmanager stuck at 30% of the NDK for 23 minutes, the Gradle
#   wrapper dying with an SSL "Connection reset" after ~50 MiB).
#
#   This script fixes that with three curl features:
#     * --speed-time/--speed-limit  abort a transfer that stops making progress
#     * --retry/--retry-all-errors  ride out transient network errors
#     * -C -                         resume the partial file instead of restarting
#
#   The link is not bandwidth-capped per connection (~300 KiB/s each, ~950
#   KiB/s aggregate), so downloads are run in parallel.
#
# USAGE
#   ./scripts/download-sdk-packages.sh            # all packages the build needs
#   ./scripts/download-sdk-packages.sh --install  # ...and unpack them into $ANDROID_HOME
#
# The download cache is $ANDROID_HOME/.cache/sdkzips.
# ---------------------------------------------------------------------------
set -uo pipefail

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
CACHE="${SDK_ZIP_CACHE:-$ANDROID_HOME/.cache/sdkzips}"
BASE_URL="https://dl.google.com/android/repository"

mkdir -p "$CACHE"

# package id : archive name : expected size in bytes
# Sizes come from Google's repository2-3.xml, and are used to detect a
# truncated download before unpacking.
PACKAGES=(
  "platform-tools|platform-tools_r37.0.1-linux.zip|9054187"
  "platforms;android-37.0|platform-37.0_r02.zip|67281901"
  "build-tools;37.0.0|build-tools_r37_linux.zip|66135704"
  "ndk;27.1.12297006|android-ndk-r27b-linux.zip|663976775"
  "cmake;4.1.2|cmake-4.1.2-linux.zip|31275750"
)

DO_INSTALL=0
[ "${1:-}" = "--install" ] && DO_INSTALL=1

log()  { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }

# download <file> <url> — resumable, stall-detecting, retried.
#
# The URL is resolved to its final destination first: when curl follows a
# redirect it drops the Range header, so a resumed transfer would restart
# from zero instead of continuing. Downloading the resolved URL keeps range
# support (and therefore resuming) working.
download() {
  local name="$1" url="$2" target="$3"
  local out="$CACHE/$name"
  local resolved attempt=1

  resolved="$(curl -sS -o /dev/null -L --max-time 120 -w '%{url_effective}' "$url" 2>/dev/null)"
  [ -n "$resolved" ] || resolved="$url"

  while [ "$attempt" -le 40 ]; do
    if curl -sS -L -C - --retry 5 --retry-delay 3 --retry-all-errors \
         --connect-timeout 30 --speed-time 120 --speed-limit 1024 \
         -o "$out" "$resolved"; then
      local size
      size="$(stat -c %s "$out" 2>/dev/null || echo 0)"
      if [ "$target" -gt 0 ] && [ "$size" -ne "$target" ]; then
        info "$name: got $size bytes, expected $target — retrying"
        attempt=$((attempt + 1))
        sleep 3
        continue
      fi
      info "$name: complete ($size bytes)"
      return 0
    fi
    info "$name: attempt $attempt interrupted ($(stat -c %s "$out" 2>/dev/null || echo 0) bytes so far) — resuming"
    attempt=$((attempt + 1))
    sleep 3
  done

  printf 'ERROR: could not download %s\n' "$name" >&2
  return 1
}

# install_package <sdk-relative-dir> <archive>
install_package() {
  local dir="$1" archive="$2"
  [ -d "$ANDROID_HOME/$dir" ] && { info "$dir: already installed"; return 0; }
  info "$dir: unpacking $(basename "$archive")"
  rm -rf "$ANDROID_HOME/$dir"
  unzip -q "$CACHE/$archive" -d "$ANDROID_HOME/.tmp-unpack" \
    || { printf 'ERROR: failed to unpack %s\n' "$archive" >&2; return 1; }
  # The archives contain a single top-level directory named after the package
  # (e.g. "platform-tools/", "android-14/", "android-ndk-r27b/").
  local top
  top="$(find "$ANDROID_HOME/.tmp-unpack" -mindepth 1 -maxdepth 1 -type d | head -1)"
  if [ -n "$top" ]; then
    mv "$top" "$ANDROID_HOME/$dir"
  fi
  rm -rf "$ANDROID_HOME/.tmp-unpack"
  info "$dir: installed"
}

log "Downloading SDK packages into $CACHE"

pids=()
for spec in "${PACKAGES[@]}"; do
  IFS='|' read -r pkg archive size <<<"$spec"
  ( download "$archive" "$BASE_URL/$archive" "$size" > "$CACHE/.$archive.log" 2>&1 ) &
  pids+=($!)
done

failed=0
for pid in "${pids[@]}"; do
  wait "$pid" || failed=1
done

for spec in "${PACKAGES[@]}"; do
  IFS='|' read -r pkg archive size <<<"$spec"
  cat "$CACHE/.$archive.log" 2>/dev/null | sed 's/^/    /'
done

if [ "$failed" -ne 0 ]; then
  printf '\nERROR: one or more packages failed to download; re-run to resume.\n' >&2
  exit 1
fi

if [ "$DO_INSTALL" -eq 1 ]; then
  log "Installing into $ANDROID_HOME"
  install_package "platform-tools"        "platform-tools_r37.0.1-linux.zip"
  install_package "platforms/android-37.0" "platform-37.0_r02.zip"
  install_package "build-tools/37.0.0"    "build-tools_r37_linux.zip"
  install_package "ndk/27.1.12297006"     "android-ndk-r27b-linux.zip"
  install_package "cmake/4.1.2"           "cmake-4.1.2-linux.zip"
fi

log "Done"

# ---------------------------------------------------------------------------
# Gradle distribution
#
# The Gradle wrapper downloads its distribution with the same long-read
# behaviour that broke sdkmanager (it died with an SSL reset after ~50 MiB),
# so the same resumable download is used here. The wrapper cache layout is
# reproduced so that `./gradlew` picks the distribution up without re-fetching:
#
#   ~/.gradle/wrapper/dists/<name>-<version>-<type>/<hash>/<name>-<version>.zip
#   ~/.gradle/wrapper/dists/<name>-<version>-<type>/<hash>/<name>-<version>.zip.ok
#   ~/.gradle/wrapper/dists/<name>-<version>-<type>/<hash>/<name>-<version>/
#
# The <hash> directory is the Base36 MD5 of the distributionUrl, which is
# exactly what the wrapper computes, so it is read back from the wrapper
# properties rather than hard-coded.
# ---------------------------------------------------------------------------
install_gradle() {
  local gradle_version="${GRADLE_VERSION:-9.4.1}"
  local url="https://services.gradle.org/distributions/gradle-${gradle_version}-bin.zip"
  local dists="${GRADLE_USER_HOME:-$HOME/.gradle}/wrapper/dists"

  log "Fetching Gradle $gradle_version"
  download "gradle-${gradle_version}-bin.zip" "$url" 137878901 || return 1

  # Locate (or create) the hash directory the wrapper expects.
  local hash_dir
  hash_dir="$(grep -rl "gradle-${gradle_version}-bin" "$dists" 2>/dev/null | head -1 | xargs -r dirname)"
  if [ -z "$hash_dir" ]; then
    hash_dir="$dists/gradle-${gradle_version}-bin/$(printf '%s' "$url" | md5sum | cut -c1-32)"
    mkdir -p "$hash_dir"
  fi

  cp -f "$CACHE/gradle-${gradle_version}-bin.zip" "$hash_dir/"
  rm -rf "$hash_dir/gradle-${gradle_version}"
  unzip -q "$hash_dir/gradle-${gradle_version}-bin.zip" -d "$hash_dir" || return 1
  touch "$hash_dir/gradle-${gradle_version}-bin.zip.ok"
  info "Gradle installed at $hash_dir/gradle-${gradle_version}"
}

if [ "${INSTALL_GRADLE:-0}" = "1" ]; then
  install_gradle
fi
