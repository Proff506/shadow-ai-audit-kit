#!/bin/bash
#
# elect-rix AUDIT-KIT — USB Launcher (macOS / Linux)
#
# Priority:
#   1. audit-kit.py (polished wizard/express launcher) via system Python
#   2. Bundled Linux binary (bin/linux/scanner) — no Python needed
#   3. scanner.py via system Python (fallback)
#
# Usage:
#   ./run.sh              # Wizard mode (interactive)
#   ./run.sh --express    # Express mode (auto-detect)
#   ./run.sh --help       # Show options
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OS_TYPE="$(uname -s)"

echo "============================================================"
echo "elect-rix AUDIT-KIT"
echo "Shadow AI Discovery Scanner"
echo "============================================================"
echo "Platform: $OS_TYPE"
echo "USB:      $SCRIPT_DIR"
echo ""

# --- 0. Pre-scan validation ---

if [ ! -w "$SCRIPT_DIR" ]; then
    echo "ERROR: USB is not writable. Check write-protect switch or remount."
    exit 1
fi

FREE_KB=$(df "$SCRIPT_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "$FREE_KB" ] && [ "$FREE_KB" -lt 10240 ]; then
    echo "WARNING: USB has less than 10MB free. Reports may fail to save."
    echo "Run ./cleanup-reports.sh to free space."
    echo ""
fi

for f in scanner.py ai_domains.json report_template.html; do
    if [ ! -f "$SCRIPT_DIR/$f" ]; then
        echo "ERROR: Missing critical file: $f"
        echo "The USB may be corrupted. Re-copy from source."
        exit 1
    fi
done

# --- 1. Find runtime ---

PYTHON=""
SCANNER_CMD=()
CLT_MISSING=0

# On a Mac that has never had Xcode Command Line Tools installed,
# /usr/bin/python3 is a stub: `command -v python3` finds it (so it looks
# usable), but actually invoking it pops a blocking "Install Command Line
# Tools?" GUI dialog instead of running Python. `xcode-select -p` is a cheap
# pre-check — it just reads a stored path and does NOT trigger that dialog —
# so we can detect this before ever invoking python3.
python3_usable() {
    if [ "$OS_TYPE" = "Darwin" ] && ! xcode-select -p &>/dev/null; then
        CLT_MISSING=1
        return 1
    fi
    command -v python3 &>/dev/null
}

# Path 1: audit-kit.py via system Python (preferred)
if [ -f "$SCRIPT_DIR/audit-kit.py" ]; then
    if python3_usable; then
        PYTHON="python3"
    elif command -v python &>/dev/null; then
        PYTHON="python"
    fi
    if [ -n "$PYTHON" ]; then
        echo "Using: audit-kit.py ($($PYTHON --version 2>&1))"
        exec "$PYTHON" "$SCRIPT_DIR/audit-kit.py" "$@"
    fi
fi

if [ "$CLT_MISSING" -eq 1 ]; then
    echo "NOTE: python3 exists but Xcode Command Line Tools are not installed"
    echo "on this Mac, so it won't run. Install with: xcode-select --install"
    echo "(one-time, ~10 min download), then re-run. Trying other options first..."
    echo ""
fi

# Path 2: Bundled Linux binary (no Python needed)
if [ "$OS_TYPE" = "Linux" ] && [ -f "$SCRIPT_DIR/bin/linux/scanner" ]; then
    echo "Using: bundled Linux executable"
    SCANNER_CMD=("$SCRIPT_DIR/bin/linux/scanner")
# Path 3: Bundled macOS binary
elif [ "$OS_TYPE" = "Darwin" ] && [ -f "$SCRIPT_DIR/bin/mac/scanner" ]; then
    echo "Using: bundled macOS executable"
    SCANNER_CMD=("$SCRIPT_DIR/bin/mac/scanner")
# Path 4: scanner.py via system Python
elif [ -f "$SCRIPT_DIR/scanner.py" ]; then
    if [ -z "$PYTHON" ]; then
        if python3_usable; then
            PYTHON="python3"
        elif command -v python &>/dev/null; then
            PYTHON="python"
        elif [ "$CLT_MISSING" -eq 1 ]; then
            echo "ERROR: python3 requires Xcode Command Line Tools on this Mac."
            echo "Run: xcode-select --install (one-time, ~10 min), then re-run this scan."
            exit 1
        else
            echo "ERROR: No Python found and no bundled executable available."
            echo "Install Python 3 from python.org or restore bin/linux/scanner."
            exit 1
        fi
    fi
    echo "Using: scanner.py ($($PYTHON --version 2>&1))"
    SCANNER_CMD=("$PYTHON" "$SCRIPT_DIR/scanner.py")
else
    echo "ERROR: Neither audit-kit.py, scanner.py, nor bundled executable found."
    exit 1
fi

# --- 2. Get client name ---

echo ""
echo "Enter client name (for the report):"
read -r CLIENT_NAME

if [ -z "$CLIENT_NAME" ]; then
    echo "Client name is required."
    exit 1
fi

# --- 3. Get auditor name ---

echo ""
echo "Enter auditor name (default: elect-rix Auditor):"
read -r AUDITOR_NAME
AUDITOR_NAME="${AUDITOR_NAME:-elect-rix Auditor}"

# --- 4. Choose scan mode ---

echo ""
echo "Scan mode:"
echo "  1. Auto-detect everything (recommended) — browsers + software"
echo "  2. Auto-detect + staff interviews — full SA-1"
echo "  3. Browser history only"
echo "  4. Software inventory only"
echo "  5. DNS log file"
echo ""
echo "Choice (default 1):"
read -r SCAN_MODE
SCAN_MODE="${SCAN_MODE:-1}"

# --- 5. Run the scan ---

REPORTS_DIR="$SCRIPT_DIR/reports/$(date +%Y-%m-%d_%H%M%S)"
mkdir -p "$REPORTS_DIR"

case "$SCAN_MODE" in
    1)
        echo ""
        echo "Running auto-detect scan..."
        "${SCANNER_CMD[@]}" --auto --client "$CLIENT_NAME" --auditor "$AUDITOR_NAME" --output-dir "$REPORTS_DIR"
        ;;
    2)
        echo ""
        echo "Running auto-detect + interview..."
        "${SCANNER_CMD[@]}" --auto --interview --client "$CLIENT_NAME" --auditor "$AUDITOR_NAME" --output-dir "$REPORTS_DIR"
        ;;
    3)
        echo ""
        echo "Running browser history scan..."
        AUDITKIT_SKIP_SOFTWARE=1 "${SCANNER_CMD[@]}" --auto --client "$CLIENT_NAME" --auditor "$AUDITOR_NAME" --output-dir "$REPORTS_DIR"
        ;;
    4)
        echo ""
        echo "Running software inventory scan..."
        AUDITKIT_SKIP_BROWSER=1 "${SCANNER_CMD[@]}" --auto --client "$CLIENT_NAME" --auditor "$AUDITOR_NAME" --output-dir "$REPORTS_DIR"
        ;;
    5)
        echo ""
        echo "Enter path to DNS log file:"
        read -r DNS_LOG
        "${SCANNER_CMD[@]}" --dns-log "$DNS_LOG" --client "$CLIENT_NAME" --auditor "$AUDITOR_NAME" --output-dir "$REPORTS_DIR"
        ;;
    *)
        echo "Invalid choice. Running auto-detect."
        "${SCANNER_CMD[@]}" --auto --client "$CLIENT_NAME" --auditor "$AUDITOR_NAME" --output-dir "$REPORTS_DIR"
        ;;
esac

# --- 6. Open report ---

echo ""
echo "============================================================"
echo "Scan complete!"
echo "Reports saved to: $REPORTS_DIR"
echo "============================================================"

if [ -f "$REPORTS_DIR/report.html" ]; then
    echo ""
    echo "Open report now? (y/n, default y)"
    read -r OPEN_REPORT
    OPEN_REPORT="${OPEN_REPORT:-y}"

    if [ "$OPEN_REPORT" = "y" ] || [ "$OPEN_REPORT" = "Y" ]; then
        if [ "$OS_TYPE" = "Darwin" ]; then
            open "$REPORTS_DIR/report.html"
        else
            if command -v xdg-open &>/dev/null; then
                xdg-open "$REPORTS_DIR/report.html"
            else
                echo "Open manually: $REPORTS_DIR/report.html"
            fi
        fi
    fi
fi

echo ""
echo "Files generated:"
ls -la "$REPORTS_DIR/" 2>/dev/null || true
echo ""
echo "Copy the reports/ folder to take with you."
echo "Done."
