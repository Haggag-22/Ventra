#!/usr/bin/env bash
# Ventra installer for AWS CloudShell — installs the latest release and self-upgrades.
#
# Safe to run every session: it upgrades to the newest released version on PyPI each time, so a
# client always gets the latest collector (CloudShell's $HOME persists between sessions, so a
# one-time install would otherwise pin them to an old build forever).
#
# One-liner for clients:
#   curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
#
# Then collect:
#   ventra collect aws --case CASE-2026-0042 --since 2026-05-11 --out ~/ventra-evidence
#
# Knobs:
#   VENTRA_INSTALL_SPEC='ventra==0.2.0'    pin to a specific released version
#   VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git@main'
#                                          test UNRELEASED code (force-reinstalls from git)
#   VENTRA_SKIP_UPGRADE=1                  use the already-installed build, skip the upgrade check
set -euo pipefail

VENV="${VENTRA_VENV:-$HOME/.ventra-venv}"
INSTALL_SPEC="${VENTRA_INSTALL_SPEC:-ventra}"
PATH_LINE='export PATH="$HOME/.ventra-venv/bin:$PATH"'

# When aws_cloudshell.sh sources this file it sets VENTRA_INSTALL_SOURCED=1.
# Do not use BASH_SOURCE here — it is unset under ``set -u`` for ``curl | bash``.
_ventra_show_hints() {
  [ "${VENTRA_INSTALL_SOURCED:-}" != "1" ]
}

_ventra_bin() {
  if [ -x "$VENV/bin/ventra" ]; then
    echo "$VENV/bin/ventra"
  elif command -v ventra >/dev/null 2>&1; then
    command -v ventra
  else
    return 1
  fi
}

# Installed version string ("0.2.0", a dev build, or "" if not installed). `ventra --version`
# prints "ventra X.Y.Z"; take the last field.
_ventra_installed_version() {
  local bin
  bin="$(_ventra_bin)" || { echo ""; return 0; }
  "$bin" --version 2>/dev/null | awk '{print $NF}'
}

ventra_ready() {
  local bin
  bin="$(_ventra_bin)" || return 1
  "$bin" --version >/dev/null 2>&1 && "$bin" collect aws --help >/dev/null 2>&1
}

ensure_path() {
  export PATH="$VENV/bin:$PATH"
  if [ -f "$HOME/.bashrc" ] && ! grep -qF '.ventra-venv/bin' "$HOME/.bashrc" 2>/dev/null; then
    {
      echo ''
      echo '# Ventra collector (added by bin/install-cloudshell.sh)'
      echo "$PATH_LINE"
    } >> "$HOME/.bashrc"
    echo "Added Ventra to ~/.bashrc — new shells will have \`ventra\` on PATH."
  fi
}

ensure_venv() {
  if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    echo "error: Ventra requires Python 3.11 or newer (found $(python3 --version 2>&1))." >&2
    echo "  CloudShell: try VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git' after upgrading," >&2
    echo "  or use a CloudShell region/runtime with Python 3.11+." >&2
    exit 1
  fi
  if [ ! -d "$VENV" ]; then
    echo "Creating Ventra environment at ${VENV}…"
    python3 -m venv "$VENV"
  fi
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
}

install_ventra() {
  pip install --quiet --upgrade pip
  if [[ "$INSTALL_SPEC" == git+* ]] || [[ "$INSTALL_SPEC" == http* ]]; then
    # Installing from a git ref (e.g. testing unreleased code): the version string may not
    # change between pushes, so force a reinstall to guarantee the working code is replaced.
    echo "Installing Ventra from ${INSTALL_SPEC} (forced reinstall)…"
    pip install --quiet --upgrade --force-reinstall "ventra @ ${INSTALL_SPEC}"
  else
    # Installing from PyPI: upgrade to the latest released version.
    echo "Installing/upgrading Ventra from PyPI (${INSTALL_SPEC})…"
    pip install --quiet --upgrade "${INSTALL_SPEC}"
  fi
}

main() {
  ensure_venv

  local before after
  before="$(_ventra_installed_version)"

  # Use the already-installed build only when explicitly asked (offline / repeat runs); the
  # default is to upgrade so a persisted CloudShell home always lands on the latest release.
  if [ "${VENTRA_SKIP_UPGRADE:-}" = "1" ] && ventra_ready; then
    ensure_path
    echo "Ventra ${before} (upgrade skipped: VENTRA_SKIP_UPGRADE=1)."
  else
    install_ventra
    ensure_path
  fi

  if ! ventra_ready; then
    bin="$(_ventra_bin || echo "$VENV/bin/ventra")"
    echo "error: Ventra install finished but \`ventra collect aws\` is not available." >&2
    echo "  bin: ${bin}" >&2
    "${bin}" --version 2>&1 | sed 's/^/  /' >&2 || true
    "${bin}" collect aws --help 2>&1 | head -3 | sed 's/^/  /' >&2 || true
    echo "  Try: VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git@main' bash -c \"\$(curl -fsSL .../install-cloudshell.sh)\"" >&2
    exit 1
  fi

  after="$(_ventra_installed_version)"
  if [ -n "$before" ] && [ "$before" != "$after" ]; then
    echo "Ventra upgraded: ${before} → ${after}"
  elif [ -n "$before" ]; then
    echo "Ventra already up to date: ${after}"
  else
    echo "Ventra installed: ${after}"
  fi

  if _ventra_show_hints; then
    echo
    echo "Collect evidence:"
    echo "  ventra collect aws --case CASE-2026-0042 --since 2026-05-11 --out ~/ventra-evidence"
    echo
    echo "List collectors:"
    echo "  ventra collect aws --list-collectors"
  fi
}

if [ "${VENTRA_INSTALL_SOURCED:-}" != "1" ]; then
  main "$@"
fi
