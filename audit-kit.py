#!/usr/bin/env python3
"""
elect-rix AUDIT-KIT — Unified Launcher
=======================================
Single entry point for the Shadow AI Discovery Scanner.
Two modes: wizard (interactive TUI) and express (CLI flags).

Usage:
  ./audit-kit.py                  # Wizard mode (interactive)
  ./audit-kit.py --express        # Express mode (auto-detect everything)
  ./audit-kit.py --client "Name"  # Express with client name
  ./audit-kit.py --help           # Full CLI reference

Design:
  - Stdlib only — no pip, no internet, runs on any Python 3.10+
  - ANSI colors — works on all modern terminals (macOS, Linux, Windows 10+)
  - Config persistence — remembers auditor name, preferences
  - Progress indicators — spinners, step counters, elapsed time
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI terminal helpers (no dependencies)
# ---------------------------------------------------------------------------

class Term:
    """ANSI escape codes for terminal formatting. Degrades gracefully on non-TTY."""

    _ENABLED = sys.stdout.isatty()

    @classmethod
    def _code(cls, n):
        return f"\033[{n}m" if cls._ENABLED else ""

    @classmethod
    def reset(cls):     return cls._code(0)
    @classmethod
    def bold(cls):      return cls._code(1)
    @classmethod
    def dim(cls):       return cls._code(2)
    @classmethod
    def red(cls):       return cls._code(31)
    @classmethod
    def green(cls):     return cls._code(32)
    @classmethod
    def yellow(cls):    return cls._code(33)
    @classmethod
    def blue(cls):      return cls._code(34)
    @classmethod
    def magenta(cls):   return cls._code(35)
    @classmethod
    def cyan(cls):      return cls._code(36)
    @classmethod
    def white(cls):     return cls._code(37)
    @classmethod
    def grey(cls):      return cls._code(90)
    @classmethod
    def clear_line(cls): return "\033[2K\r" if cls._ENABLED else ""
    @classmethod
    def up(cls, n=1):   return f"\033[{n}A" if cls._ENABLED else ""
    @classmethod
    def hide_cursor(cls): return "\033[?25l" if cls._ENABLED else ""
    @classmethod
    def show_cursor(cls): return "\033[?25h" if cls._ENABLED else ""

    @classmethod
    def header(cls, text):
        return f"{cls.bold()}{cls.blue()}{text}{cls.reset()}"

    @classmethod
    def success(cls, text):
        icon = "✓" if _supports_unicode() else "OK:"
        return f"{cls.green()}{cls.bold()}{icon}{cls.reset()} {text}"

    @classmethod
    def warn(cls, text):
        return f"{cls.yellow()}{cls.bold()}!{cls.reset()} {text}"

    @classmethod
    def error(cls, text):
        icon = "✗" if _supports_unicode() else "X"
        return f"{cls.red()}{cls.bold()}{icon}{cls.reset()} {text}"

    @classmethod
    def info(cls, text):
        icon = "→" if _supports_unicode() else "->"
        return f"{cls.cyan()}{cls.bold()}{icon}{cls.reset()} {text}"

    @classmethod
    def step(cls, n, total, text):
        return f"{cls.bold()}{cls.blue()}[{n}/{total}]{cls.reset()} {text}"

    @classmethod
    def badge(cls, text, color=None):
        c = color or cls.blue()
        return f"{c}{cls.bold()}{text}{cls.reset()}"

    @classmethod
    def risk(cls, level):
        colors = {"CRITICAL": cls.red, "HIGH": cls.red, "MEDIUM": cls.yellow, "LOW": cls.green}
        c = colors.get(level, cls.white)
        return f"{c()}{cls.bold()}{level}{cls.reset()}"


def _supports_unicode():
    """Detect if the terminal supports Unicode (braille spinner).
    Windows legacy cmd.exe does not; Windows Terminal, macOS, Linux do."""
    if platform.system() == "Windows":
        # Windows Terminal sets WT_SESSION; ConEmu sets ConEmuPID
        if os.environ.get("WT_SESSION") or os.environ.get("ConEmuPID"):
            return True
        # Check if we're in a modern terminal via TERM_PROGRAM
        if os.environ.get("TERM_PROGRAM"):
            return True
        return False
    return True  # macOS, Linux — always Unicode-capable


def _detect_terminal():
    """Return a human-readable terminal description for the banner."""
    if platform.system() == "Windows":
        if os.environ.get("WT_SESSION"):
            return "Windows Terminal"
        if os.environ.get("ConEmuPID"):
            return "ConEmu"
        if os.environ.get("TERM_PROGRAM"):
            return os.environ["TERM_PROGRAM"]
        return "Command Prompt (legacy — limited colors)"
    return os.environ.get("TERM_PROGRAM", os.environ.get("TERM", "terminal"))


class Spinner:
    """Simple terminal spinner for long-running operations.
    Uses Unicode braille on modern terminals, ASCII on legacy (cmd.exe)."""

    UNICODE_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    ASCII_FRAMES = ["|", "/", "-", "\\"]

    def __init__(self, message=""):
        self.message = message
        self._running = False
        self._idx = 0
        self._frames = self.UNICODE_FRAMES if _supports_unicode() else self.ASCII_FRAMES

    def start(self, message=None):
        if message:
            self.message = message
        self._running = True
        self._idx = 0
        if Term._ENABLED:
            sys.stdout.write(Term.hide_cursor())
            sys.stdout.flush()

    def tick(self, message=None):
        if not self._running or not Term._ENABLED:
            return
        if message:
            self.message = message
        frame = self._frames[self._idx % len(self._frames)]
        self._idx += 1
        sys.stdout.write(f"{Term.clear_line()}{Term.cyan()}{frame}{Term.reset()} {self.message}")
        sys.stdout.flush()

    def stop(self, message=None):
        self._running = False
        if Term._ENABLED:
            if message:
                sys.stdout.write(f"{Term.clear_line()}{message}\n")
            else:
                sys.stdout.write(f"{Term.clear_line()}")
            sys.stdout.write(Term.show_cursor())
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

CONFIG_DIR = Path.home() / ".elect-rix"
CONFIG_FILE = CONFIG_DIR / "audit-kit.conf"

DEFAULT_CONFIG = {
    "auditor_name": "elect-rix Auditor",
    "default_mode": "wizard",
    "last_client": "",
    "scan_count": 0,
    "version": 1,
}


def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            return {**DEFAULT_CONFIG, **cfg}
        except Exception:
            return dict(DEFAULT_CONFIG)
    return dict(DEFAULT_CONFIG)


def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


# ---------------------------------------------------------------------------
# System detection
# ---------------------------------------------------------------------------

def detect_system():
    """Return a dict describing the current machine."""
    info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "hostname": "",
        "username": "",
        "python_version": sys.version.split()[0],
        "is_tty": sys.stdout.isatty(),
    }
    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        pass
    try:
        info["username"] = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    except Exception:
        pass
    return info


def detect_browsers():
    """Quick check: which browsers are installed on this machine?
    Delegates to scanner.py's get_browser_paths() for single source of truth."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from scanner import get_browser_paths
        paths = get_browser_paths()
        # Deduplicate browser names (e.g. "Firefox-snap" and "Firefox" → "Firefox")
        seen = set()
        result = []
        for name, _, _ in paths:
            base = name.split("-")[0]  # "Firefox-snap" → "Firefox"
            if base not in seen:
                seen.add(base)
                result.append(base)
        return result
    except Exception:
        # Fallback: basic path checks if scanner import fails
        found = []
        home = Path.home()
        sysname = platform.system().lower()
        checks = []
        if sysname == "darwin":
            checks = [
                ("Chrome", home / "Library/Application Support/Google/Chrome"),
                ("Firefox", home / "Library/Application Support/Firefox"),
                ("Safari", home / "Library/Safari"),
                ("Edge", home / "Library/Application Support/Microsoft Edge"),
                ("Brave", home / "Library/Application Support/BraveSoftware/Brave-Browser"),
                ("Arc", home / "Library/Application Support/Arc"),
            ]
        elif sysname == "linux":
            checks = [
                ("Chrome", home / ".config/google-chrome"),
                ("Chromium", home / ".config/chromium"),
                ("Firefox", home / ".mozilla/firefox"),
                ("Brave", home / ".config/BraveSoftware/Brave-Browser"),
                ("Edge", home / ".config/microsoft-edge"),
            ]
            for snap_name in ["firefox", "chromium", "brave", "opera"]:
                if (home / "snap" / snap_name).exists():
                    checks.append((snap_name.title(), home / "snap" / snap_name))
        elif sysname == "windows":
            appdata = os.environ.get("LOCALAPPDATA", "")
            if appdata:
                checks = [
                    ("Chrome", Path(appdata) / "Google/Chrome"),
                    ("Edge", Path(appdata) / "Microsoft/Edge"),
                    ("Brave", Path(appdata) / "BraveSoftware/Brave-Browser"),
                ]
            appdata_r = os.environ.get("APPDATA", "")
            if appdata_r:
                checks.append(("Firefox", Path(appdata_r) / "Mozilla/Firefox"))
        for name, path in checks:
            if path.exists():
                found.append(name)
        return found


# ---------------------------------------------------------------------------
# Banner and UI helpers
# ---------------------------------------------------------------------------

BANNER = r"""
  ╔══════════════════════════════════════════╗
  ║  ███████╗██╗     ███████╗ ██████╗████████╗  ║
  ║  ██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝  ║
  ║  █████╗  ██║     █████╗  ██║        ██║     ║
  ║  ██╔══╝  ██║     ██╔══╝  ██║        ██║     ║
  ║  ███████╗███████╗███████╗╚██████╗   ██║     ║
  ║  ╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝     ║
  ║                                             ║
  ║     Shadow AI Discovery Scanner              ║
  ║     USB Audit Kit  ·  v1.0                  ║
  ╚══════════════════════════════════════════╝
"""


def print_banner():
    print(Term.blue() + BANNER + Term.reset())
    print(f"  {Term.dim()}elect-rix Technology Solutions  ·  RixBot Technologies Inc.{Term.reset()}")
    print(f"  {Term.dim()}elect-rix.tech  ·  (506) 801-2722{Term.reset()}")
    print()


def print_system_info(sysinfo, browsers):
    print(f"  {Term.header('System')}")
    print(f"  {Term.dim()}OS:       {sysinfo['os']} {sysinfo['os_release']}{Term.reset()}")
    print(f"  {Term.dim()}Host:     {sysinfo['hostname']}{Term.reset()}")
    print(f"  {Term.dim()}User:     {sysinfo['username']}{Term.reset()}")
    print(f"  {Term.dim()}Python:   {sysinfo['python_version']}{Term.reset()}")
    if browsers:
        print(f"  {Term.dim()}Browsers: {', '.join(browsers)}{Term.reset()}")
    else:
        print(f"  {Term.warn('No browsers detected on this system.')}")
    print()


def print_divider(char="─", width=50):
    print(f"  {Term.dim()}{char * width}{Term.reset()}")


def confirm(prompt, default=True):
    """Ask a yes/no question. Returns bool."""
    yn = "Y/n" if default else "y/N"
    while True:
        try:
            answer = input(f"  {Term.info(prompt)} [{yn}]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if answer == "":
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def ask(prompt, default=""):
    """Ask for text input with optional default."""
    if default:
        prompt_str = f"  {Term.info(prompt)} [{default}]: "
    else:
        prompt_str = f"  {Term.info(prompt)}: "
    try:
        answer = input(prompt_str).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return answer if answer else default


def ask_choice(prompt, options):
    """Ask user to pick from numbered options. Returns index (0-based)."""
    print(f"\n  {Term.header(prompt)}")
    for i, (label, desc) in enumerate(options, 1):
        print(f"    {Term.bold()}{i}{Term.reset()}. {label}  {Term.dim()}{desc}{Term.reset()}")
    print()
    while True:
        try:
            choice = input(f"  {Term.info('Choice')} [1]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if choice == "":
            return 0
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        print(f"  {Term.error('Please enter 1-{len(options)}')}")


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------

class Progress:
    """Show a progress bar for a known number of steps."""

    def __init__(self, total, label="", width=30):
        self.total = total
        self.label = label
        self.width = width
        self.current = 0
        self.start_time = time.time()

    def update(self, n=1, detail=""):
        self.current = min(self.current + n, self.total)
        pct = self.current / self.total if self.total > 0 else 1
        filled = int(self.width * pct)
        bar = f"{Term.green()}{'█' * filled}{Term.dim()}{'░' * (self.width - filled)}{Term.reset()}"
        elapsed = time.time() - self.start_time
        line = f"  {self.label} {bar} {int(pct*100)}%"
        if detail:
            line += f"  {Term.dim()}{detail}{Term.reset()}"
        sys.stdout.write(f"{Term.clear_line()}{line}")
        sys.stdout.flush()
        if self.current >= self.total:
            sys.stdout.write("\n")

    def done(self, message=""):
        self.current = self.total
        self.update(0, message)


# ---------------------------------------------------------------------------
# Scanner integration
# ---------------------------------------------------------------------------

def find_scanner():
    """Locate scanner.py relative to this launcher."""
    script_dir = Path(__file__).resolve().parent
    scanner = script_dir / "scanner.py"
    if scanner.exists():
        return scanner
    # Fallback: check if we're in a PyInstaller bundle
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "scanner.py"
    return None


def run_scanner_module(module_func, *args, **kwargs):
    """Run a scanner module and return (findings, extra_data)."""
    return module_func(*args, **kwargs)


# ---------------------------------------------------------------------------
# Wizard mode
# ---------------------------------------------------------------------------

def wizard_mode(config):
    """Interactive step-by-step audit wizard."""
    print_banner()

    sysinfo = detect_system()
    browsers = detect_browsers()
    print_system_info(sysinfo, browsers)

    # Step 1: Client info
    print_divider()
    print(f"  {Term.step(1, 5, 'Client Information')}")
    print()
    client_name = ask("Client / business name", config.get("last_client", ""))
    auditor_name = ask("Auditor name", config.get("auditor_name", "elect-rix Auditor"))
    print(f"\n  {Term.success(f'Client: {client_name}')}")
    print(f"  {Term.success(f'Auditor: {auditor_name}')}")

    # Save for next time
    config["auditor_name"] = auditor_name
    config["last_client"] = client_name
    save_config(config)

    # Step 2: Scan mode
    print(f"\n  {Term.step(2, 5, 'Scan Mode')}")
    mode_idx = ask_choice("What would you like to scan?", [
        ("Full auto-detect", "Browsers + installed software (recommended)"),
        ("Auto-detect + staff interviews", "Full SA-1 — browsers, software, and interactive interviews"),
        ("Browsers only", "Browser history scan only"),
        ("Software only", "Installed software inventory only"),
        ("DNS log file", "Provide a DNS log file to scan"),
    ])

    # Step 3: Output location
    print(f"\n  {Term.step(3, 5, 'Output Location')}")
    script_dir = Path(__file__).resolve().parent
    default_out = script_dir / "reports" / datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    output_dir = ask("Output directory", str(default_out))
    print(f"  {Term.success(f'Reports will save to: {output_dir}')}")

    # Step 4: Confirmation
    mode_labels = [
        "Full auto-detect (browsers + software)",
        "Auto-detect + staff interviews",
        "Browser history only",
        "Software inventory only",
        "DNS log file",
    ]
    print(f"\n  {Term.step(4, 5, 'Confirm')}")
    print()
    print(f"  {Term.bold()}Client:{Term.reset()}      {client_name}")
    print(f"  {Term.bold()}Auditor:{Term.reset()}     {auditor_name}")
    print(f"  {Term.bold()}Mode:{Term.reset()}        {mode_labels[mode_idx]}")
    print(f"  {Term.bold()}Output:{Term.reset()}      {output_dir}")
    print(f"  {Term.bold()}Platform:{Term.reset()}    {sysinfo['os']} {sysinfo['os_release']}")
    if browsers:
        print(f"  {Term.bold()}Browsers:{Term.reset()}    {', '.join(browsers)}")
    print()

    if not confirm("Start scan?"):
        print(f"\n  {Term.info('Cancelled. No scan performed.')}")
        return

    # Step 5: Run
    print(f"\n  {Term.step(5, 5, 'Running Scan')}")
    print()
    run_scan(mode_idx, client_name, auditor_name, output_dir, browsers, sysinfo)


# ---------------------------------------------------------------------------
# Express mode
# ---------------------------------------------------------------------------

def express_mode(config, client_name=None, auditor_name=None, output_dir=None):
    """Fast path: auto-detect everything, minimal interaction."""
    sysinfo = detect_system()
    browsers = detect_browsers()

    if not client_name:
        client_name = config.get("last_client", "")
        if not client_name:
            print(Term.error("No client name provided. Use --client or run wizard mode."))
            sys.exit(1)

    if not auditor_name:
        auditor_name = config.get("auditor_name", "elect-rix Auditor")

    script_dir = Path(__file__).resolve().parent
    if not output_dir:
        output_dir = script_dir / "reports" / datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")

    config["auditor_name"] = auditor_name
    config["last_client"] = client_name
    save_config(config)

    print_banner()
    print_system_info(sysinfo, browsers)
    print(f"  {Term.bold()}Client:{Term.reset()}   {client_name}")
    print(f"  {Term.bold()}Auditor:{Term.reset()}  {auditor_name}")
    print(f"  {Term.bold()}Mode:{Term.reset()}     Express (full auto-detect)")
    print(f"  {Term.bold()}Output:{Term.reset()}   {output_dir}")
    print()

    run_scan(0, client_name, auditor_name, str(output_dir), browsers, sysinfo)


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

def run_scan(mode_idx, client_name, auditor_name, output_dir, browsers, sysinfo):
    """Execute the selected scan mode, calling scanner.py as a subprocess."""
    scanner_path = find_scanner()
    if not scanner_path:
        print(f"\n  {Term.error('scanner.py not found on this USB.')}")
        print(f"  {Term.info('Expected at:')} {Path(__file__).resolve().parent / 'scanner.py'}")
        sys.exit(1)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build scanner args
    scanner_args = [
        sys.executable, str(scanner_path),
        "--client", client_name,
        "--auditor", auditor_name,
        "--output-dir", str(output_dir),
    ]

    if mode_idx == 0:  # Full auto-detect
        scanner_args.append("--auto")
    elif mode_idx == 1:  # Auto + interview
        scanner_args.extend(["--auto", "--interview"])
    elif mode_idx == 2:  # Browsers only
        scanner_args.append("--auto")
    elif mode_idx == 3:  # Software only
        scanner_args.append("--auto")
    elif mode_idx == 4:  # DNS log
        dns_path = ask("Path to DNS log file")
        scanner_args.extend(["--dns-log", dns_path])

    # For modes 2 and 3, we need to tell the scanner to skip the other module.
    env = os.environ.copy()
    if mode_idx == 2:  # Browsers only
        env["AUDITKIT_SKIP_SOFTWARE"] = "1"
    elif mode_idx == 3:  # Software only
        env["AUDITKIT_SKIP_BROWSER"] = "1"

    # Progress spinner while scanner runs
    spinner = Spinner()
    spinner.start("Scanning...")

    start_time = time.time()

    try:
        result = subprocess.run(
            scanner_args,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min max
        )
    except subprocess.TimeoutExpired:
        spinner.stop(Term.error("Scan timed out after 5 minutes."))
        sys.exit(1)
    except Exception as e:
        spinner.stop(Term.error(f"Scan failed: {e}"))
        sys.exit(1)

    elapsed = time.time() - start_time
    spinner.stop()

    # Print scanner output
    if result.stdout:
        for line in result.stdout.splitlines():
            if line.strip():
                print(f"  {Term.dim()}{line}{Term.reset()}")

    if result.returncode != 0:
        print(f"\n  {Term.error('Scanner exited with error.')}")
        if result.stderr:
            print(f"  {Term.dim()}{result.stderr}{Term.reset()}")
        sys.exit(1)

    # Post-scan summary
    print(f"\n  {Term.header('Scan Complete')}  {Term.dim()}({elapsed:.1f}s){Term.reset()}")
    print()

    # Try to load report.json for a summary
    report_json = output_dir / "report.json"
    if report_json.exists():
        try:
            with open(report_json) as f:
                report = json.load(f)
            summary = report.get("summary", {})
            findings = report.get("findings", [])

            total = summary.get("total_findings", 0)
            unique = summary.get("unique_tools", 0)
            risks = summary.get("risk_distribution", {})

            print(f"  {Term.bold()}Findings:{Term.reset()}       {total} total, {unique} unique tools")
            for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = risks.get(level, 0)
                if count > 0:
                    print(f"    {Term.risk(level):30s} {count}")

            if summary.get("pipeda_exposure"):
                print(f"\n  {Term.error('PIPEDA/PHIPA exposure detected — immediate action required.')}")
            else:
                print(f"\n  {Term.success('No immediate PIPEDA/PHIPA exposure detected.')}")

            if summary.get("insurance_gap_risk"):
                print(f"  {Term.warn('Insurance coverage gap risk — verify with provider.')}")

            # Top actions
            top = report.get("top_actions", [])[:3]
            if top:
                print(f"\n  {Term.header('Top Actions')}")
                for i, action in enumerate(top, 1):
                    print(f"  {Term.bold()}{i}.{Term.reset()} {action}")

        except Exception:
            pass

    # Report files
    print(f"\n  {Term.header('Report Files')}")
    for fname in ["report.html", "report.json", "inventory.csv", "findings.db", "machine_info.json", "scanner.log"]:
        fpath = output_dir / fname
        if fpath.exists():
            size = fpath.stat().st_size
            if size > 1024 * 1024:
                size_str = f"{size/1024/1024:.1f} MB"
            elif size > 1024:
                size_str = f"{size/1024:.1f} KB"
            else:
                size_str = f"{size} B"
            print(f"  {Term.success(fname):40s} {Term.dim()}{size_str}{Term.reset()}")

    print(f"\n  {Term.dim()}All reports saved to: {output_dir}{Term.reset()}")

    # Open report
    html_path = output_dir / "report.html"
    if html_path.exists() and confirm("\nOpen report in browser?", default=True):
        open_report(html_path)

    # Cleanup reminder
    print(f"\n  {Term.warn('Remember: copy reports to your laptop, then run ./cleanup-reports.sh')}")
    print(f"  {Term.warn('Client data must never persist on the USB between engagements.')}")
    print()

    # Update scan count
    cfg = load_config()
    cfg["scan_count"] = cfg.get("scan_count", 0) + 1
    save_config(cfg)


def open_report(path):
    """Open an HTML file in the default browser."""
    sysname = platform.system()
    try:
        if sysname == "Darwin":
            subprocess.run(["open", str(path)])
        elif sysname == "Windows":
            os.startfile(str(path))
        else:
            if shutil.which("xdg-open"):
                subprocess.run(["xdg-open", str(path)])
            else:
                print(f"  {Term.info(f'Open manually: {path}')}")
    except Exception:
        print(f"  {Term.info(f'Open manually: {path}')}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="elect-rix AUDIT-KIT — Shadow AI Discovery Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              ./audit-kit.py                        Wizard mode (interactive)
              ./audit-kit.py --express              Express mode (auto-detect)
              ./audit-kit.py --client "Acme Corp"   Express with client name
              ./audit-kit.py --client "Acme" --mode interview
              ./audit-kit.py --version              Show version
        """),
    )
    parser.add_argument("--express", action="store_true",
                        help="Express mode: auto-detect everything, minimal prompts")
    parser.add_argument("--client", help="Client name (required for express mode)")
    parser.add_argument("--auditor", help="Auditor name (uses saved config if omitted)")
    parser.add_argument("--output-dir", help="Output directory for reports")
    parser.add_argument("--mode", choices=["auto", "interview", "browsers", "software", "dns"],
                        default="auto", help="Scan mode (default: auto)")
    parser.add_argument("--dns-log", help="Path to DNS log file (for --mode dns)")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    args = parser.parse_args()

    # See scanner.py main() for why: avoid UnicodeEncodeError crashes on
    # legacy Windows cmd.exe, especially when output is redirected.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass

    if args.no_color:
        Term._ENABLED = False

    if args.version:
        print("elect-rix AUDIT-KIT v1.0")
        print("Shadow AI Discovery Scanner (SA-1)")
        print("elect-rix Technology Solutions · RixBot Technologies Inc.")
        sys.exit(0)

    config = load_config()

    # Handle SIGINT gracefully
    def handle_sigint(sig, frame):
        print(f"\n\n  {Term.info('Cancelled.')}")
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sigint)

    if args.express or args.client:
        # Express mode
        mode_map = {
            "auto": 0,
            "interview": 1,
            "browsers": 2,
            "software": 3,
            "dns": 4,
        }
        mode_idx = mode_map.get(args.mode, 0)
        express_mode(config, args.client, args.auditor, args.output_dir)
    else:
        # Wizard mode
        wizard_mode(config)


if __name__ == "__main__":
    main()
