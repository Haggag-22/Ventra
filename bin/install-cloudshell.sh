#!/usr/bin/env bash
# Idempotent Harbor install for AWS CloudShell.
#
# Safe to run every session — skips work when Harbor is already on PATH and working.
# One-liner for clients:
#   curl -fsSL https://raw.githubusercontent.com/Haggag-22/Harbor/main/bin/install-cloudshell.sh | bash
#
# Then collect:
#   harbor collect aws --case CASE-2026-0042 --since 2026-05-11 --out ~/harbor-evidence
#
# Override install source (default: GitHub main):
#   HARBOR_INSTALL_SPEC='harbor-collector[zstd]' bash bin/install-cloudshell.sh
set -euo pipefail

VENV="${HARBOR_VENV:-$HOME/.harbor-venv}"
INSTALL_SPEC="${HARBOR_INSTALL_SPEC:-git+https://github.com/Haggag-22/Harbor.git}"
PATH_LINE='export PATH="$HOME/.harbor-venv/bin:$PATH"'

# When aws_cloudshell.sh sources this file it sets HARBOR_INSTALL_SOURCED=1.
# Do not use BASH_SOURCE here — it is unset under ``set -u`` for ``curl | bash``.
_harbor_show_hints() {
  [ "${HARBOR_INSTALL_SOURCED:-}" != "1" ]
}

_harbor_bin() {
  if [ -x "$VENV/bin/harbor" ]; then
    echo "$VENV/bin/harbor"
  elif command -v harbor >/dev/null 2>&1; then
    command -v harbor
  else
    return 1
  fi
}

harbor_ready() {
  local bin
  bin="$(_harbor_bin)" || return 1
  "$bin" --version >/dev/null 2>&1 && "$bin" collect aws --help >/dev/null 2>&1
}

ensure_path() {
  export PATH="$VENV/bin:$PATH"
  if [ -f "$HOME/.bashrc" ] && ! grep -qF '.harbor-venv/bin' "$HOME/.bashrc" 2>/dev/null; then
    {
      echo ''
      echo '# Harbor collector (added by bin/install-cloudshell.sh)'
      echo "$PATH_LINE"
    } >> "$HOME/.bashrc"
    echo "Added Harbor to ~/.bashrc — new shells will have \`harbor\` on PATH."
  fi
}

ensure_venv() {
  if [ ! -d "$VENV" ]; then
    echo "Creating Harbor environment at ${VENV}…"
    python3 -m venv "$VENV"
  fi
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
}

install_harbor() {
  echo "Installing Harbor from ${INSTALL_SPEC}…"
  pip install --quiet --upgrade pip
  if [[ "$INSTALL_SPEC" == git+* ]] || [[ "$INSTALL_SPEC" == http* ]]; then
    pip install --quiet "harbor-collector[zstd] @ ${INSTALL_SPEC}"
  else
    pip install --quiet "${INSTALL_SPEC}[zstd]"
  fi
}

main() {
  if [ "${HARBOR_FORCE_INSTALL:-}" != "1" ] && harbor_ready; then
    echo "Harbor already installed: $(_harbor_bin) $(_harbor_bin --version 2>&1 | tail -1)"
    ensure_path
    if _harbor_show_hints; then
      echo
      echo "Ready. Example:"
      echo "  harbor collect aws --case CASE-2026-0042 --since 2026-05-11 --out ~/harbor-evidence"
    fi
    return 0
  fi

  ensure_venv
  install_harbor
  ensure_path

  if ! harbor_ready; then
    echo "error: Harbor install finished but \`harbor collect aws\` is not available." >&2
    exit 1
  fi

  if _harbor_show_hints; then
    echo
    echo "Harbor installed: $(_harbor_bin) $(_harbor_bin --version 2>&1 | tail -1)"
    echo
    echo "Collect evidence:"
    echo "  harbor collect aws --case CASE-2026-0042 --since 2026-05-11 --out ~/harbor-evidence"
    echo
    echo "List collectors:"
    echo "  harbor collect aws --list-collectors"
  fi
}

if [ "${HARBOR_INSTALL_SOURCED:-}" != "1" ]; then
  main "$@"
fi
