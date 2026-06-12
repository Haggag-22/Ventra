#!/usr/bin/env bash
# Idempotent Ventra install for AWS CloudShell.
#
# Safe to run every session — skips work when Ventra is already on PATH and working.
# One-liner for clients:
#   curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
#
# Then collect:
#   ventra collect aws --case CASE-2026-0042 --since 2026-05-11 --out ~/ventra-evidence
#
# Override install source (default: PyPI):
#   VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git' bash bin/install-cloudshell.sh
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
  if [ ! -d "$VENV" ]; then
    echo "Creating Ventra environment at ${VENV}…"
    python3 -m venv "$VENV"
  fi
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
}

install_ventra() {
  echo "Installing Ventra from ${INSTALL_SPEC}…"
  pip install --quiet --upgrade pip
  if [[ "$INSTALL_SPEC" == git+* ]] || [[ "$INSTALL_SPEC" == http* ]]; then
    pip install --quiet "ventra @ ${INSTALL_SPEC}"
  else
    pip install --quiet "${INSTALL_SPEC}"
  fi
}

main() {
  if [ "${VENTRA_FORCE_INSTALL:-}" != "1" ] && ventra_ready; then
    echo "Ventra already installed: $(_ventra_bin) $(_ventra_bin --version 2>&1 | tail -1)"
    ensure_path
    if _ventra_show_hints; then
      echo
      echo "Ready. Example:"
      echo "  ventra collect aws --case CASE-2026-0042 --since 2026-05-11 --out ~/ventra-evidence"
    fi
    return 0
  fi

  ensure_venv
  install_ventra
  ensure_path

  if ! ventra_ready; then
    echo "error: Ventra install finished but \`ventra collect aws\` is not available." >&2
    exit 1
  fi

  if _ventra_show_hints; then
    echo
    echo "Ventra installed: $(_ventra_bin) $(_ventra_bin --version 2>&1 | tail -1)"
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
