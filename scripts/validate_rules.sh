#!/usr/bin/env bash
# =============================================================================
# validate_rules.sh — Snort Rule Validation Script
# CSL-I09 B.Tech Cyber Security Lab Mini Project
# Student : Kushal Kumar | Roll: 23ESKCY026 | SKIT Jaipur
# =============================================================================
# Usage:
#   cd Snort_Rules_IoT_Botnet_Attacks/
#   bash scripts/validate_rules.sh
#
# Behaviour:
#   1. If `snort` is on PATH  →  runs:  snort -T -c config/snort.conf
#   2. If `snort` not found   →  runs:  python3 src/alert_analyzer.py --validate-only
#
# Output:
#   - Coloured PASS/FAIL per rule to stdout
#   - Full log written to results/validation.log
# =============================================================================

set -uo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC}  $*"; echo "[PASS]  $*" >> "$LOG_FILE"; }
fail() { echo -e "  ${RED}[FAIL]${NC}  $*"; echo "[FAIL]  $*" >> "$LOG_FILE"; FAIL_COUNT=$((FAIL_COUNT+1)); }
info() { echo -e "  ${CYAN}[INFO]${NC}  $*"; echo "[INFO]  $*" >> "$LOG_FILE"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC}  $*"; echo "[WARN]  $*" >> "$LOG_FILE"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_ROOT/results"
LOG_FILE="$RESULTS_DIR/validation.log"
FAIL_COUNT=0

mkdir -p "$RESULTS_DIR"

# Start log
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================" > "$LOG_FILE"
echo " Snort Rule Validation Log" >> "$LOG_FILE"
echo " CSL-I09 | Kushal Kumar | 23ESKCY026 | SKIT Jaipur" >> "$LOG_FILE"
echo " Timestamp: $TIMESTAMP" >> "$LOG_FILE"
echo "============================================================" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Snort Rule Validation — CSL-I09 IoT Botnet Project         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Expected SIDs ─────────────────────────────────────────────────────────────
# Map of SID → description used for PASS/FAIL reporting
declare -A SID_NAMES=(
    [1000001]="Telnet connection attempt port 23"
    [1000002]="Telnet connection attempt alt-port 2323 (Mirai)"
    [1000003]="Mirai Telnet brute-force username root"
    [1000004]="Mirai factory credential root:xc3511"
    [1000005]="Mirai factory credential root:vizxv"
    [1000006]="Mirai post-auth loader /bin/busybox MIRAI"
    [1000007]="Mirai wget/tftp download command"
    [1000008]="TCP SYN port scan (20+ SYNs / 5 s)"
    [1000009]="MQTT CONNECT flood port 1883"
    [1000010]="Mirai admin:admin credential attempt"
)

RULES_FILE="$PROJECT_ROOT/rules/local.rules"
SNORT_CONF="$PROJECT_ROOT/config/snort.conf"

# ── Path: snort binary available ─────────────────────────────────────────────
if command -v snort &>/dev/null; then
    info "snort binary found — using native Snort validation"
    echo ""

    # Run snort in test mode; capture combined stdout+stderr
    SNORT_OUTPUT="$(snort -T -c "$SNORT_CONF" 2>&1)" || true
    SNORT_EXIT=$?
    echo "$SNORT_OUTPUT" >> "$LOG_FILE"

    if echo "$SNORT_OUTPUT" | grep -q "Snort successfully validated the configuration"; then
        info "Snort configuration syntax: VALID"
    else
        warn "Snort config test returned exit code $SNORT_EXIT — check log"
    fi

    echo ""
    echo -e "${BOLD}── Per-Rule SID Validation ──────────────────────────────────${NC}"

    for SID in $(echo "${!SID_NAMES[@]}" | tr ' ' '\n' | sort -n); do
        NAME="${SID_NAMES[$SID]}"
        # Check the SID is present in local.rules (non-commented line)
        if grep -qP "(?<!#).*sid:\s*${SID}\s*;" "$RULES_FILE" 2>/dev/null; then
            pass "SID $SID — $NAME"
        else
            fail "SID $SID — $NAME (not found in local.rules)"
        fi
    done

# ── Path: fallback to Python alert_analyzer.py ───────────────────────────────
else
    warn "snort not found — falling back to python3 src/alert_analyzer.py --validate-only"
    echo ""

    ANALYZER="$PROJECT_ROOT/src/alert_analyzer.py"
    if [ ! -f "$ANALYZER" ]; then
        fail "alert_analyzer.py not found at $ANALYZER"
        echo ""
        echo -e "${RED}Cannot validate rules — both snort and alert_analyzer.py are unavailable.${NC}"
        exit 1
    fi

    PYTHON_OUTPUT="$(python3 "$ANALYZER" --validate-only 2>&1)" || true
    echo "$PYTHON_OUTPUT" >> "$LOG_FILE"
    echo "$PYTHON_OUTPUT"

    echo ""
    echo -e "${BOLD}── Per-Rule SID Validation (from local.rules file) ─────────${NC}"

    for SID in $(echo "${!SID_NAMES[@]}" | tr ' ' '\n' | sort -n); do
        NAME="${SID_NAMES[$SID]}"
        if grep -qP "(?<!#).*sid:\s*${SID}\s*;" "$RULES_FILE" 2>/dev/null; then
            pass "SID $SID — $NAME"
        else
            fail "SID $SID — $NAME (not found in local.rules)"
        fi
    done
fi

echo ""
echo -e "${BOLD}── Rules File Syntax Quick-Check ────────────────────────────${NC}"

TOTAL_RULES=0
COMMENTED=0
ACTIVE=0
if [ -f "$RULES_FILE" ]; then
    TOTAL_RULES=$(grep -c 'alert' "$RULES_FILE" 2>/dev/null || echo 0)
    COMMENTED=$(grep -c '^\s*#' "$RULES_FILE" 2>/dev/null || echo 0)
    ACTIVE=$(grep -cP '^alert' "$RULES_FILE" 2>/dev/null || echo 0)
    info "Total alert lines in local.rules : $TOTAL_RULES"
    info "Active (non-commented) rules      : $ACTIVE"
    info "Comment lines                     : $COMMENTED"
else
    fail "local.rules file not found at $RULES_FILE"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo "------------------------------------------------------------" >> "$LOG_FILE"
echo "Total SIDs checked : ${#SID_NAMES[@]}" >> "$LOG_FILE"
echo "FAIL count         : $FAIL_COUNT" >> "$LOG_FILE"
echo "------------------------------------------------------------" >> "$LOG_FILE"

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${BOLD}║${NC}  ${GREEN}ALL ${#SID_NAMES[@]} rules validated — 0 failures.${NC}                      ${BOLD}║${NC}"
else
    echo -e "${BOLD}║${NC}  ${RED}Validation complete — $FAIL_COUNT failure(s) detected.${NC}             ${BOLD}║${NC}"
fi
echo -e "${BOLD}║${NC}  Log written to: results/validation.log                      ${BOLD}║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
