#!/usr/bin/env bash
# Install Ventra on macOS or Linux using uv (recommended client / IR workstation path).
#
#   curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install.sh | bash
#
# Pin a release:
#   VENTRA_INSTALL_SPEC='ventra==0.5.0' bash -c "$(curl -fsSL .../install.sh)"
#
# Test unreleased code:
#   VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git@main' bash -c "$(curl -fsSL .../install.sh)"
#
# Install from a local wheel:
#   VENTRA_INSTALL_SPEC='/path/to/ventra-0.5.0-py3-none-any.whl' bash install.sh
set -euo pipefail

INSTALL_SPEC="${VENTRA_INSTALL_SPEC:-ventra}"
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'

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
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && ! grep -qF '.local/bin' "$rc" 2>/dev/null; then
      {
        echo ''
        echo '# uv / Ventra (added by bin/install.sh)'
        echo "$PATH_LINE"
      } >> "$rc"
      echo "Added ~/.local/bin to ${rc} — new shells will have \`ventra\` on PATH."
    fi
  done
}

install_ventra() {
  if [[ "$INSTALL_SPEC" == git+* ]] || [[ "$INSTALL_SPEC" == http* ]]; then
    echo "Installing Ventra from ${INSTALL_SPEC}…"
    uv tool install --force "ventra @ ${INSTALL_SPEC}"
  elif [[ "$INSTALL_SPEC" == *.whl ]] || [[ "$INSTALL_SPEC" == file://* ]]; then
    echo "Installing Ventra from wheel ${INSTALL_SPEC}…"
    uv tool install --force "${INSTALL_SPEC}"
  else
    echo "Installing/upgrading Ventra (${INSTALL_SPEC})…"
    uv tool install --force "${INSTALL_SPEC}"
  fi
}

main() {
  ensure_uv
  install_ventra
  ensure_path

  if ! command -v ventra >/dev/null 2>&1; then
    echo "error: ventra not on PATH after install. Run: source ~/.zshrc  (or ~/.bashrc)" >&2
    exit 1
  fi

  echo "Ventra $(ventra --version 2>/dev/null | awk '{print $NF}')"
  echo
  echo "Collect evidence:"
  echo "  ventra collect gcp --case CASE-001 --project MY-PROJECT --pack baseline-ir-gcp --out ./evidence"
}

main "$@"
