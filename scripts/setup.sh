#!/usr/bin/env bash
# =============================================================================
# setup.sh — Environment Setup for "Snort Rules for IoT Botnet Attacks"
# CSL-I09 B.Tech Cyber Security Lab Mini Project
# Student : Kushal Kumar | Roll: 23ESKCY026 | SKIT Jaipur
# =============================================================================
# Usage:
#   chmod +x scripts/setup.sh
#   cd Snort_Rules_IoT_Botnet_Attacks/
#   bash scripts/setup.sh
#
# Idempotent: safe to run multiple times. It will NOT overwrite existing files.
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'   # No Colour

ok()   { echo -e "  ${GREEN}[OK]${NC}    $*"; }
fail() { echo -e "  ${RED}[MISSING]${NC} $*"; SETUP_ERRORS=$((SETUP_ERRORS + 1)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
info() { echo -e "  ${CYAN}[INFO]${NC}  $*"; }

SETUP_ERRORS=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Snort Rules for IoT Botnet Attacks — Environment Setup     ║${NC}"
echo -e "${BOLD}║  CSL-I09 | Kushal Kumar | 23ESKCY026 | SKIT Jaipur          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Section 1: System Tool Availability ──────────────────────────────────────
echo -e "${BOLD}[1/5] Checking system tool availability …${NC}"

check_tool() {
    local tool="$1"
    local hint="$2"
    if command -v "$tool" &>/dev/null; then
        local ver
        ver="$("$tool" --version 2>&1 | head -1)"
        ok "$tool found  →  $ver"
        return 0
    else
        fail "$tool NOT found  (hint: $hint)"
        return 1
    fi
}

check_tool python3  "install python3 from https://python.org"
check_tool pip      "pip usually ships with python3; try: python3 -m ensurepip"
check_tool pip3     "alias for pip; install python3-pip via your OS package manager" || true

# Snort is optional — the Python fallback path is provided
if command -v snort &>/dev/null; then
    SNORT_VER="$(snort --version 2>&1 | head -1)"
    ok "snort found  →  $SNORT_VER"
    SNORT_AVAILABLE=true
else
    warn "snort NOT found — validation will use python3 fallback (alert_analyzer.py --validate-only)"
    SNORT_AVAILABLE=false
fi

echo ""

# ── Section 2: Create Directory Structure ────────────────────────────────────
echo -e "${BOLD}[2/5] Creating project directory structure …${NC}"

REQUIRED_DIRS=(
    "$PROJECT_ROOT/config"
    "$PROJECT_ROOT/rules"
    "$PROJECT_ROOT/src"
    "$PROJECT_ROOT/captures"
    "$PROJECT_ROOT/results"
    "$PROJECT_ROOT/tests"
    "$PROJECT_ROOT/scripts"
    "$PROJECT_ROOT/report"
    "$PROJECT_ROOT/logs"
)

for d in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$d" ]; then
        ok "dir exists  →  ${d#$PROJECT_ROOT/}"
    else
        mkdir -p "$d"
        ok "created     →  ${d#$PROJECT_ROOT/}"
    fi
done

echo ""

# ── Section 3: Python Package Installation ───────────────────────────────────
echo -e "${BOLD}[3/5] Installing Python dependencies from requirements.txt …${NC}"

REQUIREMENTS="$PROJECT_ROOT/requirements.txt"
if [ ! -f "$REQUIREMENTS" ]; then
    fail "requirements.txt not found at $REQUIREMENTS"
else
    ok "requirements.txt found"

    # Prefer pip3; fall back to pip
    PIP_CMD="pip3"
    command -v pip3 &>/dev/null || PIP_CMD="pip"

    info "Running: $PIP_CMD install -r $REQUIREMENTS --upgrade --quiet"
    if $PIP_CMD install -r "$REQUIREMENTS" --upgrade --quiet 2>&1; then
        ok "All Python packages installed successfully"
    else
        fail "pip install failed — check network / permissions"
    fi
fi

echo ""

# ── Section 4: Verify Project File Structure ─────────────────────────────────
echo -e "${BOLD}[4/5] Verifying project file structure …${NC}"

REQUIRED_FILES=(
    "config/snort.conf"
    "config/snort.lua"
    "rules/local.rules"
    "captures/README.md"
    "src/traffic_generator.py"
    "src/alert_analyzer.py"
    "src/report_generator.py"
    "src/main.py"
    "tests/test_alerts.py"
    "tests/test_cases.md"
    "scripts/setup.sh"
    "scripts/validate_rules.sh"
    "scripts/run_tests.sh"
    "README.md"
    "requirements.txt"
    ".gitignore"
)

for f in "${REQUIRED_FILES[@]}"; do
    FULL="$PROJECT_ROOT/$f"
    if [ -f "$FULL" ]; then
        SIZE=$(wc -c < "$FULL")
        ok "$f  (${SIZE} bytes)"
    else
        fail "$f  — FILE MISSING"
    fi
done

echo ""

# ── Section 5: Results Directory Writable? ───────────────────────────────────
echo -e "${BOLD}[5/5] Verifying write access to results/ …${NC}"

RESULTS_DIR="$PROJECT_ROOT/results"
TEST_FILE="$RESULTS_DIR/.setup_write_test"
if touch "$TEST_FILE" 2>/dev/null; then
    rm -f "$TEST_FILE"
    ok "results/ is writable"
else
    fail "results/ is NOT writable — check permissions"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
if [ "$SETUP_ERRORS" -eq 0 ]; then
    echo -e "${BOLD}║${NC}  ${GREEN}Setup completed successfully — 0 errors detected.${NC}           ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}  Next step:  bash scripts/run_tests.sh                       ${BOLD}║${NC}"
else
    echo -e "${BOLD}║${NC}  ${RED}Setup finished with $SETUP_ERRORS error(s).${NC}                        ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}  ${RED}Resolve the [MISSING] items above and re-run this script.${NC}  ${BOLD}║${NC}"
fi
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$SETUP_ERRORS" -gt 0 ]; then
    exit 1
fi
exit 0
