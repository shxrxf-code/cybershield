#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Mobile ThreatGuard – local development environment
#
# The Android toolchain on this machine is not on the default PATH:
#   * Java is a locally installed Temurin JDK 17 (no system JDK exists).
#   * The Android SDK lives in $HOME/Android/Sdk but ANDROID_HOME is unset.
#
# Source this file before any Gradle / adb / emulator / react-native command:
#
#   source scripts/dev-env.sh
#
# It is intentionally non-fatal and safe to source from CI.
# ---------------------------------------------------------------------------

# --- Java ------------------------------------------------------------------
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/javac" ]; then
  if [ -x "$HOME/.local/lib/threatguard-jdk17/bin/javac" ]; then
    export JAVA_HOME="$HOME/.local/lib/threatguard-jdk17"
  fi
fi

# --- Android SDK -----------------------------------------------------------
if [ -z "${ANDROID_HOME:-}" ] && [ -d "$HOME/Android/Sdk" ]; then
  export ANDROID_HOME="$HOME/Android/Sdk"
fi
export ANDROID_SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -n "${ANDROID_HOME:-}" ]; then
  export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$JAVA_HOME/bin:$PATH"
fi

# --- npm script-policy workaround -----------------------------------------
# The user-level ~/.npmrc pins `allow-scripts=@opencode/cli`, which npm >=11.19
# rejects during project-scoped installs. Point npm at an empty user config for
# commands run from this repository so installs work without touching ~/.npmrc.
if [ -f "$HOME/.cache/tg/npmrc-empty" ]; then
  export npm_config_userconfig="$HOME/.cache/tg/npmrc-empty"
fi

# --- Reporting -------------------------------------------------------------
if [ "${THREATGUARD_ENV_QUIET:-0}" != "1" ]; then
  echo "threatguard dev-env"
  echo "  JAVA_HOME    = ${JAVA_HOME:-<unset>}"
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
    echo "  javac        = $("$JAVA_HOME/bin/javac" -version 2>&1)"
  fi
  echo "  ANDROID_HOME = ${ANDROID_HOME:-<unset>}"
fi
