#!/usr/bin/env bash
# Ja4Scanner — Linux Installer
# Usage: sudo ./install.sh

set -euo pipefail

INSTALL_DIR="/opt/ja4scanner"
BIN_LINK="/usr/local/bin/ja4scanner"
BOLD="\033[1m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

echo -e "${BOLD}${CYAN}"
cat << 'EOF'
     _            _  _   ____
    | | __ _   _ | || | / ___|  ___ __ _ _ __  _ __   ___ _ __
 _  | |/ _` | | || || | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |_| | (_| |_  __  _|  ___) | (_| (_| | | | | | | |  __/ |
 \___/ \__,_| |_||_||_| |____/ \___\__,_|_| |_|_| |_|\___|_|
EOF
echo -e "${RESET}"
echo -e "${BOLD}  Ja4Scanner — Linux Installer${RESET}"
echo ""

# ── 1. Root check ──────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root. Use: sudo ./install.sh"
fi

# ── 2. Python 3 check ──────────────────────────────────────────────────────────
info "Checking for Python 3..."
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 8 ]]; then
            PYTHON="$candidate"
            success "Found $($PYTHON --version)"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    error "Python 3.8+ is required but not found. Install it with:\n  sudo apt install python3   # Debian/Ubuntu\n  sudo dnf install python3   # Fedora/RHEL"
fi

# ── 3. pip check / install ─────────────────────────────────────────────────────
info "Checking for pip..."
PIP=""
for candidate in pip3 pip; do
    if command -v "$candidate" &>/dev/null; then
        PIP="$candidate"
        success "Found $($PIP --version | cut -d' ' -f1-2)"
        break
    fi
done

if [[ -z "$PIP" ]]; then
    warn "pip not found — attempting to install via ensurepip..."
    "$PYTHON" -m ensurepip --upgrade 2>/dev/null || \
        error "Could not install pip. Run:\n  sudo apt install python3-pip"
    PIP="$PYTHON -m pip"
fi

# ── 4. Install Python dependencies ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ="$SCRIPT_DIR/requirements.txt"

if [[ ! -f "$REQ" ]]; then
    error "requirements.txt not found in $SCRIPT_DIR"
fi

info "Installing Python dependencies from requirements.txt..."
$PIP install --quiet -r "$REQ"
success "Dependencies installed: $(cat "$REQ" | grep -v '^#' | tr '\n' ' ')"

# ── 5. Copy tool to /opt/ja4scanner ───────────────────────────────────────────
info "Installing Ja4Scanner to $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR"/*.py "$INSTALL_DIR/"
cp "$REQ" "$INSTALL_DIR/"

# Fix line endings on all Python files (safety for files edited on Windows)
if command -v sed &>/dev/null; then
    sed -i 's/\r$//' "$INSTALL_DIR"/*.py
fi

success "Files copied to $INSTALL_DIR"

# ── 6. Make main.py executable ────────────────────────────────────────────────
chmod +x "$INSTALL_DIR/main.py"
success "main.py marked executable"

# ── 7. Create /usr/local/bin/ja4scanner launcher ──────────────────────────────
info "Creating global command: ja4scanner → $BIN_LINK"

cat > "$BIN_LINK" << LAUNCHER
#!/usr/bin/env bash
exec "$PYTHON" "$INSTALL_DIR/main.py" "\$@"
LAUNCHER

chmod +x "$BIN_LINK"
success "Global command created: $BIN_LINK"

# ── 8. Verify installation ────────────────────────────────────────────────────
info "Verifying installation..."
if "$PYTHON" -c "import colorama, rich" 2>/dev/null; then
    success "colorama and rich import correctly"
else
    error "Dependency import failed — check pip installation above"
fi

if [[ -x "$BIN_LINK" ]]; then
    success "ja4scanner command is ready at $BIN_LINK"
fi

echo ""
echo -e "${BOLD}${GREEN}  Installation complete!${RESET}"
echo -e "  Run from anywhere with: ${BOLD}ja4scanner${RESET}"
echo ""
