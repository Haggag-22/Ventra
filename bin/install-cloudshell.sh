#!/usr/bin/env bash
# Ventra installer for AWS CloudShell — uses uv (not pip).
#
# Safe to run every session: upgrades to the newest release on PyPI each time.
#
# One-liner for clients:
#   curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
#
# Knobs:
#   VENTRA_INSTALL_SPEC='ventra==0.5.0'    pin to a specific released version
#   VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git@main'
#   VENTRA_SKIP_UPGRADE=1                  skip upgrade when ventra already works
set -euo pipefail

INSTALL_SPEC="${VENTRA_INSTALL_SPEC:-ventra}"
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'

_ventra_show_hints() {
  [ "${VENTRA_INSTALL_SOURCED:-}" != "1" ]
}

_ventra_bin() {
  if command -v ventra >/dev/null 2>&1; then
    command -v ventra
  elif [ -x "$HOME/.local/bin/ventra" ]; then
    echo "$HOME/.local/bin/ventra"
  elif [ -x "$HOME/.ventra-venv/bin/ventra" ]; then
    echo "$HOME/.ventra-venv/bin/ventra"
  else
    return 1
  fi
}

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

ensure_uv() {
  if command -v uv >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing uv…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:${PATH:-}"
}

ensure_path() {
  export PATH="$HOME/.local/bin:${PATH:-}"
  if [ -f "$HOME/.bashrc" ] && ! grep -qF '.local/bin' "$HOME/.bashrc" 2>/dev/null; then
    {
      echo ''
      echo '# uv / Ventra (added by bin/install-cloudshell.sh)'
      echo "$PATH_LINE"
    } >> "$HOME/.bashrc"
    echo "Added Ventra to ~/.bashrc — new shells will have \`ventra\` on PATH."
  fi
}

install_ventra() {
  if [[ "$INSTALL_SPEC" == git+* ]] || [[ "$INSTALL_SPEC" == http* ]]; then
    echo "Installing Ventra from ${INSTALL_SPEC} (forced reinstall)…"
    uv tool install --force "ventra @ ${INSTALL_SPEC}"
  else
    echo "Installing/upgrading Ventra (${INSTALL_SPEC})…"
    uv tool install --force "${INSTALL_SPEC}"
  fi
}

main() {
  ensure_uv

  local before after
  before="$(_ventra_installed_version)"

  if [ "${VENTRA_SKIP_UPGRADE:-}" = "1" ] && ventra_ready; then
    ensure_path
    echo "Ventra ${before} (upgrade skipped: VENTRA_SKIP_UPGRADE=1)."
  else
    install_ventra
    ensure_path
  fi

  if ! ventra_ready; then
    bin="$(_ventra_bin || echo "$HOME/.local/bin/ventra")"
    echo "error: Ventra install finished but \`ventra collect aws\` is not available." >&2
    echo "  bin: ${bin}" >&2
    "${bin}" --version 2>&1 | sed 's/^/  /' >&2 || true
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
    if ! command -v ventra >/dev/null 2>&1; then
      echo
      echo "Activate \`ventra\` in THIS shell:"
      echo "  source ~/.bashrc"
      echo "  # or: $HOME/.local/bin/ventra ..."
    fi
    echo
    echo "Collect evidence:"
    echo "  ventra collect aws --case CASE-2026-0042 --since 2026-05-11 --out ~/ventra-evidence"
  fi
}

if [ "${VENTRA_INSTALL_SOURCED:-}" != "1" ]; then
  main "$@"
fi
