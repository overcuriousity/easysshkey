#!/usr/bin/env bash
#
# SSH Key Manager installer
#
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/easysshkey/main/install.sh | bash
#
# Environment overrides:
#   INSTALL_DIR=/usr/local/bin   Where to install (default: ~/.local/bin, or /usr/local/bin as root)
#   REF=v1.2                     Branch or tag to install from (default: main)
#   BIN_NAME=sshkeymanager       Installed command name
#
# Uninstall:
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/easysshkey/main/install.sh | bash -s -- --uninstall

set -euo pipefail

REPO="${REPO:-overcuriousity/easysshkey}"
REF="${REF:-main}"
BIN_NAME="${BIN_NAME:-sshkeymanager}"
SCRIPT_NAME="sshkeymanager.sh"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${SCRIPT_NAME}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'; NC=$'\033[0m'
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; BLUE=""; NC=""; }

info()  { printf '%s\n' "${BLUE}==>${NC} $1"; }
warn()  { printf '%s\n' "${YELLOW}warning:${NC} $1" >&2; }
ok()    { printf '%s\n' "${GREEN}✓${NC} $1"; }
die()   { printf '%s\n' "${RED}error:${NC} $1" >&2; exit 1; }

# --- resolve install directory -----------------------------------------------
resolve_install_dir() {
    if [ -n "${INSTALL_DIR:-}" ]; then
        printf '%s' "$INSTALL_DIR"
    elif [ "$(id -u)" -eq 0 ]; then
        printf '%s' "/usr/local/bin"
    else
        printf '%s' "${XDG_BIN_HOME:-$HOME/.local/bin}"
    fi
}

# sudo only when the target is not writable and we are not root
maybe_sudo() {
    local dir="$1"
    if [ -w "$dir" ] || { [ ! -d "$dir" ] && [ -w "$(dirname "$dir")" ]; }; then
        printf '%s' ""
    elif [ "$(id -u)" -eq 0 ]; then
        printf '%s' ""
    elif command -v sudo >/dev/null 2>&1; then
        printf '%s' "sudo"
    else
        die "$dir is not writable and sudo is not available. Re-run with INSTALL_DIR=\$HOME/.local/bin"
    fi
}

# --- PATH hint ---------------------------------------------------------------
path_contains() {
    case ":${PATH}:" in *":$1:"*) return 0;; *) return 1;; esac
}

print_path_hint() {
    local dir="$1" shell_name
    shell_name="$(basename "${SHELL:-sh}")"
    warn "$dir is not on your PATH."
    echo
    case "$shell_name" in
        fish)
            echo "  Add it with:"
            echo "    fish_add_path $dir"
            ;;
        zsh)
            echo "  Add it with:"
            echo "    echo 'export PATH=\"$dir:\$PATH\"' >> ~/.zshrc && exec zsh"
            ;;
        *)
            echo "  Add it with:"
            echo "    echo 'export PATH=\"$dir:\$PATH\"' >> ~/.bashrc && exec bash"
            ;;
    esac
    echo
}

# --- download ----------------------------------------------------------------
fetch() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        die "neither curl nor wget is available"
    fi
}

# --- uninstall ---------------------------------------------------------------
do_uninstall() {
    local removed=0 dir target sudo_cmd
    for dir in "${INSTALL_DIR:-}" "$HOME/.local/bin" "$HOME/bin" /usr/local/bin /usr/bin; do
        [ -n "$dir" ] || continue
        target="$dir/$BIN_NAME"
        if [ -e "$target" ]; then
            sudo_cmd="$(maybe_sudo "$dir")"
            $sudo_cmd rm -f "$target"
            ok "removed $target"
            removed=1
        fi
    done
    if [ "$removed" -eq 0 ]; then
        warn "$BIN_NAME was not found in any standard location"
    else
        echo
        info "Your SSH keys and ~/.ssh were not touched."
    fi
    exit 0
}

# --- argument parsing --------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall) do_uninstall ;;
        --dir) INSTALL_DIR="${2:?--dir requires an argument}"; shift 2 ;;
        --ref) REF="${2:?--ref requires an argument}"
               RAW_URL="https://raw.githubusercontent.com/${REPO}/${REF}/${SCRIPT_NAME}"
               shift 2 ;;
        -h|--help)
            cat <<'USAGE'
SSH Key Manager installer

  curl -fsSL https://raw.githubusercontent.com/overcuriousity/easysshkey/main/install.sh | bash

Options:
  --dir <path>    Install directory (default: ~/.local/bin, or /usr/local/bin as root)
  --ref <ref>     Branch or tag to install from (default: main)
  --uninstall     Remove an installed sshkeymanager
  -h, --help      Show this message

Environment overrides:
  INSTALL_DIR, REF, BIN_NAME
USAGE
            exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

# --- preflight ---------------------------------------------------------------
command -v ssh-keygen >/dev/null 2>&1 || warn "ssh-keygen not found — install the OpenSSH client before using $BIN_NAME"

bash_major="${BASH_VERSINFO[0]:-0}"
[ "$bash_major" -ge 4 ] || warn "bash $bash_major detected; sshkeymanager needs bash 4.0 or later to run"

install_dir="$(resolve_install_dir)"
target="$install_dir/$BIN_NAME"

info "Installing $BIN_NAME from $REPO@$REF"

tmp="$(mktemp "${TMPDIR:-/tmp}/sshkeymanager.XXXXXX")"
trap 'rm -f "$tmp"' EXIT INT TERM

fetch "$RAW_URL" "$tmp" || die "download failed: $RAW_URL"

# Sanity-check what we downloaded before making it executable.
[ -s "$tmp" ] || die "downloaded file is empty"
head -n1 "$tmp" | grep -q '^#!.*\bbash\b' || die "downloaded file is not a bash script (bad ref '$REF'?)"
grep -q 'SSH Key Management Script' "$tmp" || die "downloaded file does not look like sshkeymanager.sh"
bash -n "$tmp" || die "downloaded script failed a syntax check; refusing to install"

sudo_cmd="$(maybe_sudo "$install_dir")"

if [ ! -d "$install_dir" ]; then
    $sudo_cmd mkdir -p "$install_dir" || die "could not create $install_dir"
fi

if [ -e "$target" ]; then
    info "Replacing existing $target"
fi

chmod 755 "$tmp"
$sudo_cmd cp "$tmp" "$target" || die "could not install to $target"
$sudo_cmd chmod 755 "$target"

ok "installed $target"

version="$(grep -m1 '^# Version:' "$target" | sed 's/^# Version: *//')"
[ -n "$version" ] && info "version $version"

echo
if path_contains "$install_dir"; then
    resolved="$(command -v "$BIN_NAME" 2>/dev/null || true)"
    if [ -n "$resolved" ] && [ "$resolved" != "$target" ]; then
        warn "another $BIN_NAME earlier in PATH shadows this one: $resolved"
    fi
    ok "Run it with: ${GREEN}$BIN_NAME${NC}"
else
    print_path_hint "$install_dir"
    ok "Or run it directly: ${GREEN}$target${NC}"
fi
