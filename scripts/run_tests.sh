#!/usr/bin/env bash
# =============================================================================
# run_tests.sh — Full Test Suite Runner
# CSL-I09 B.Tech Cyber Security Lab Mini Project
# Student : Kushal Kumar | Roll: 23ESKCY026 | SKIT Jaipur
# =============================================================================
# Usage:
#   cd Snort_Rules_IoT_Botnet_Attacks/
#   bash scripts/run_tests.sh
#
# Pipeline:
#   Step 1 — python3 src/traffic_generator.py   (generate all PCAPs)
#   Step 2 — python3 src/alert_analyzer.py      (analyse PCAPs → detection_summary.json)
#   Step 3 — python3 -m pytest tests/test_alerts.py -v  (run unit tests)
#   Step 4 — Display consolidated summary
# =============================================================================

set -uo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step()  { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }
ok()    { echo -e "  ${GREEN}[OK]${NC}    $*"; }
fail()  { echo -e "  ${RED}[FAIL]${NC}  $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
info()  { echo -e "  ${CYAN}[INFO]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_ROOT/results"
CAPTURES_DIR="$PROJECT_ROOT/captures"

mkdir -p "$RESULTS_DIR" "$CAPTURES_DIR"

STEP_PASS=0
STEP_FAIL=0
START_TIME=$(date +%s)

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  IoT Botnet Detection — Full Test Suite Runner              ║${NC}"
echo -e "${BOLD}║  CSL-I09 | Kushal Kumar | 23ESKCY026 | SKIT Jaipur          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
info "Project root : $PROJECT_ROOT"
info "Results dir  : $RESULTS_DIR"
info "Captures dir : $CAPTURES_DIR"
echo ""

# ── Helper: run a command and track pass/fail ─────────────────────────────────
run_step() {
    local label="$1"; shift
    local cmd=("$@")
    info "Running: ${cmd[*]}"
    if "${cmd[@]}"; then
        ok "$label — SUCCESS"
        STEP_PASS=$((STEP_PASS+1))
        return 0
    else
        fail "$label — FAILED (exit code $?)"
        STEP_FAIL=$((STEP_FAIL+1))
        return 1
    fi
}

# ── Step 1: Generate PCAP files ───────────────────────────────────────────────
step "STEP 1 — Generate PCAP Traffic Captures"

cd "$PROJECT_ROOT"

TRAFFIC_GEN="$PROJECT_ROOT/src/traffic_generator.py"
if [ ! -f "$TRAFFIC_GEN" ]; then
    fail "src/traffic_generator.py not found — cannot generate PCAPs"
    STEP_FAIL=$((STEP_FAIL+1))
else
    run_step "Traffic Generator" python3 src/traffic_generator.py || true

    info "PCAPs in captures/:"
    if ls "$CAPTURES_DIR"/*.pcap 2>/dev/null | head -20; then
        PCAP_COUNT=$(ls "$CAPTURES_DIR"/*.pcap 2>/dev/null | wc -l)
        ok "$PCAP_COUNT PCAP file(s) created in captures/"
    else
        warn "No PCAP files found in captures/ — traffic_generator may need scapy/admin rights"
    fi
fi

# ── Step 2: Analyse PCAPs (alert detection) ───────────────────────────────────
step "STEP 2 — Analyse PCAPs with Alert Analyser"

ANALYZER="$PROJECT_ROOT/src/alert_analyzer.py"
if [ ! -f "$ANALYZER" ]; then
    fail "src/alert_analyzer.py not found — cannot analyse PCAPs"
    STEP_FAIL=$((STEP_FAIL+1))
else
    run_step "Alert Analyser" python3 src/alert_analyzer.py || true

    SUMMARY_JSON="$RESULTS_DIR/detection_summary.json"
    if [ -f "$SUMMARY_JSON" ]; then
        ok "detection_summary.json written to results/"
        info "File size: $(wc -c < "$SUMMARY_JSON") bytes"
    else
        warn "detection_summary.json not found — test_alerts.py will use mocked data"
    fi
fi

# ── Step 3: Run pytest test suite ─────────────────────────────────────────────
step "STEP 3 — Run Unit Tests (pytest)"

# Check test runner availability
TEST_FILE="$PROJECT_ROOT/tests/test_alerts.py"
if [ ! -f "$TEST_FILE" ]; then
    fail "tests/test_alerts.py not found"
    STEP_FAIL=$((STEP_FAIL+1))
else
    if python3 -m pytest --version &>/dev/null; then
        info "Running: python3 -m pytest tests/test_alerts.py -v --tb=short"
        if python3 -m pytest tests/test_alerts.py -v --tb=short \
               --junit-xml="$RESULTS_DIR/pytest_results.xml" \
               2>&1 | tee "$RESULTS_DIR/pytest_output.txt"; then
            ok "pytest — all tests PASSED"
            STEP_PASS=$((STEP_PASS+1))
        else
            warn "pytest — some tests FAILED (see results/pytest_output.txt)"
            STEP_FAIL=$((STEP_FAIL+1))
        fi
    else
        info "Running: python3 -m unittest tests/test_alerts.py -v"
        if python3 -m unittest tests/test_alerts.py -v 2>&1 | tee "$RESULTS_DIR/pytest_output.txt"; then
            ok "unittest — all tests PASSED"
            STEP_PASS=$((STEP_PASS+1))
        else
            warn "unittest — some tests FAILED (see results/pytest_output.txt)"
            STEP_FAIL=$((STEP_FAIL+1))
        fi
    fi
fi

# ── Step 4: Consolidated Summary ──────────────────────────────────────────────
step "STEP 4 — Summary"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

TOTAL_STEPS=$((STEP_PASS + STEP_FAIL))

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Test Suite Summary                                         ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
printf  "${BOLD}║${NC}  Pipeline steps passed  : ${GREEN}%-4s${NC}                              ${BOLD}║${NC}\n" "$STEP_PASS"
printf  "${BOLD}║${NC}  Pipeline steps failed  : ${RED}%-4s${NC}                              ${BOLD}║${NC}\n" "$STEP_FAIL"
printf  "${BOLD}║${NC}  Total steps executed   : %-4s                              ${BOLD}║${NC}\n" "$TOTAL_STEPS"
printf  "${BOLD}║${NC}  Elapsed time           : %-4s seconds                       ${BOLD}║${NC}\n" "$ELAPSED"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Result files:                                               ║${NC}"
echo -e "${BOLD}║${NC}    results/detection_summary.json  — alert detection data   ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    results/pytest_output.txt       — pytest console log     ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    results/pytest_results.xml      — JUnit XML report       ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    results/validation.log          — rule validation log     ${BOLD}║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$STEP_FAIL" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All pipeline steps completed successfully!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}$STEP_FAIL step(s) failed — review output above.${NC}"
    exit 1
fi
