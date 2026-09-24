#!/usr/bin/env bash
# Install Ventra on macOS or Linux for production / IR workstations.
#
# Prefer pipx (isolated CLI apps from PyPI). Falls back to uv tool install.
#
#   curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install.sh | bash
#
# Pin a release:
#   VENTRA_INSTALL_SPEC='ventra==0.5.0' bash -c "$(curl -fsSL .../install.sh)"
#
# Force the installer backend:
#   VENTRA_INSTALLER=pipx bash -c "$(curl -fsSL .../install.sh)"
#   VENTRA_INSTALLER=uv   bash -c "$(curl -fsSL .../install.sh)"
#
# Test unreleased code:
#   VENTRA_INSTALL_SPEC='git+https://github.com/Haggag-22/Ventra.git@main' bash -c "$(curl -fsSL .../install.sh)"
#
# Install from a local wheel:
#   VENTRA_INSTALL_SPEC='/path/to/ventra-0.5.0-py3-none-any.whl' bash install.sh
set -euo pipefail

INSTALL_SPEC="${VENTRA_INSTALL_SPEC:-ventra}"
INSTALLER="${VENTRA_INSTALLER:-auto}"
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'

ensure_path() {
  export PATH="$HOME/.local/bin:${PATH:-}"
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && ! grep -qF '.local/bin' "$rc" 2>/dev/null; then
      {
        echo ''
        echo '# Ventra / pipx (added by bin/install.sh)'
        echo "$PATH_LINE"
      } >> "$rc"
      echo "Added ~/.local/bin to ${rc} — new shells will have \`ventra\` on PATH."
    fi
  done
}

have_pipx() {
  command -v pipx >/dev/null 2>&1
}

have_uv() {
  command -v uv >/dev/null 2>&1
}

ensure_pipx() {
  if have_pipx; then
    return 0
  fi
  echo "Installing pipx…"
  if command -v brew >/dev/null 2>&1; then
    brew install pipx
    pipx ensurepath || true
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath || true
  else
    echo "error: need Python 3.11+ (or Homebrew) to install pipx" >&2
    return 1
  fi
  export PATH="$HOME/.local/bin:${PATH:-}"
  have_pipx
}

ensure_uv() {
  if have_uv; then
    return 0
  fi
  echo "Installing uv…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:${PATH:-}"
}

pick_installer() {
  case "$INSTALLER" in
    pipx|uv) echo "$INSTALLER" ;;
    auto)
      if have_pipx || command -v brew >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
        echo pipx
      else
        echo uv
      fi
      ;;
    *)
      echo "error: VENTRA_INSTALLER must be auto|pipx|uv (got ${INSTALLER})" >&2
      exit 2
      ;;
  esac
}

install_with_pipx() {
  ensure_pipx || return 1
  echo "Installing/upgrading Ventra with pipx (${INSTALL_SPEC})…"
  if [[ "$INSTALL_SPEC" == git+* ]] || [[ "$INSTALL_SPEC" == http* ]]; then
    pipx install --force "${INSTALL_SPEC}"
  elif [[ "$INSTALL_SPEC" == *.whl ]] || [[ "$INSTALL_SPEC" == file://* ]]; then
    pipx install --force "${INSTALL_SPEC}"
  elif [[ "$INSTALL_SPEC" == ventra ]] || [[ "$INSTALL_SPEC" == ventra==* ]] || [[ "$INSTALL_SPEC" == ventra\[* ]]; then
    # Upgrade if already installed; otherwise install.
    if pipx list --short 2>/dev/null | grep -q '^ventra '; then
      pipx upgrade ventra
      # Re-inject if the user asked for an extras/pin that upgrade alone may not apply.
      if [[ "$INSTALL_SPEC" != ventra ]]; then
        pipx install --force "${INSTALL_SPEC}"
      fi
    else
      pipx install "${INSTALL_SPEC}"
    fi
  else
    pipx install --force "${INSTALL_SPEC}"
  fi
}

install_with_uv() {
  ensure_uv
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
  local backend
  backend="$(pick_installer)"
  echo "Installer backend: ${backend}"

  if [ "$backend" = pipx ]; then
    install_with_pipx || {
      echo "pipx install failed — falling back to uv…" >&2
      install_with_uv
    }
  else
    install_with_uv
  fi

  ensure_path

  if ! command -v ventra >/dev/null 2>&1; then
    echo "error: ventra not on PATH after install. Run: source ~/.zshrc  (or ~/.bashrc)" >&2
    exit 1
  fi

  echo "Ventra $(ventra --version 2>/dev/null | awk '{print $NF}')"
  echo
  echo "Collect evidence:"
  echo "  ventra collect gcp --case CASE-001 --project MY-PROJECT --pack baseline-ir-gcp --out ./evidence"
  echo "Run a downloaded kit:"
  echo "  ventra run ./My-Kit.kit --out ./evidence"
  echo "Upgrade later:"
  echo "  pipx upgrade ventra"
}

main "$@"
