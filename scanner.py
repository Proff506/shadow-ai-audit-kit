#!/usr/bin/env python3
"""
elect-rix Shadow AI Discovery Scanner (SA-1) — Cross-Platform

Automates the manual procedure in SHADOW-AI-FIELD-GUIDE.md:
  1. DNS log scanning — find AI tool domain queries
  2. Browser history scanning — auto-detect Chrome/Firefox/Safari/Edge
     on macOS, Linux, and Windows. No manual path entry needed.
  3. Software inventory — auto-scan installed software per OS
  4. Interview input — structured staff interview recording
  5. Report generation — risk-ranked HTML + PDF + JSON + CSV

Cross-platform: runs on macOS, Linux, and Windows with Python 3.10+.
All processing is local. No network calls. No telemetry.
"""

import argparse
import csv
import datetime
import html
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from collections import Counter, defaultdict
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# Scan coverage — AUDIT-INTEGRITY (2026-09-27)
# Every source the scanner tried is recorded here and printed in the client
# report. A source that could not be read must never look like a clean result.
# status: "ok" | "partial" | "failed" | "not_found"
# ---------------------------------------------------------------------------

SCAN_COVERAGE = []


def record_coverage(module, source, status, detail=""):
    SCAN_COVERAGE.append({"module": module, "source": str(source),
                          "status": status, "detail": str(detail)})


def reset_coverage():
    SCAN_COVERAGE.clear()


def _esc(value):
    """HTML-escape any value interpolated into the report."""
    return html.escape("" if value is None else str(value), quote=True)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
if getattr(sys, 'frozen', False):
    # Running as PyInstaller executable — resources are in _MEIPASS
    SCRIPT_DIR = Path(sys._MEIPASS)
DOMAINS_FILE = SCRIPT_DIR / "ai_domains.json"
PRACTICE_SOFTWARE_FILE = SCRIPT_DIR / "practice_software.json"
REPORT_TEMPLATE = SCRIPT_DIR / "report_template.html"

# Drive the kit itself is running from (Windows only). Document Discovery
# must never enumerate the AUDIT-KIT stick as a "client data location" —
# anchored to the exe when frozen (sys._MEIPASS is a temp dir on C:),
# to the script path otherwise.
if platform.system() == "Windows":
    _kit_anchor = Path(sys.executable if getattr(sys, 'frozen', False) else __file__).resolve()
    KIT_DRIVE = _kit_anchor.drive.upper()
else:
    KIT_DRIVE = ""

RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
RISK_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

OS_NAME = platform.system().lower()  # 'darwin', 'linux', 'windows'
IS_MAC = OS_NAME == "darwin"
IS_LINUX = OS_NAME == "linux"
IS_WINDOWS = OS_NAME == "windows"
HOME = Path.home()

def _chromium_profiles(user_data_dir, label):
    """Every profile under a Chromium-family user-data dir that has a History DB.

    Default -> "<label>", anything else -> "<label> (<profile dir>)".
    Covers Chrome/Edge/Brave/Vivaldi/Arc/Chromium "Profile N", Edge work
    profiles, and Guest profiles. (Before 2026-09-27 only Chrome got
    "Profile N" globbing; Edge/Brave extra profiles were silently skipped.)
    """
    base = Path(user_data_dir)
    found = []
    if not base.is_dir():
        return found
    try:
        candidates = sorted(base.glob("*/History"))
    except OSError:
        return found
    for history in candidates:
        profile = history.parent.name
        if profile == "System Profile":
            continue
        name = label if profile == "Default" else f"{label} ({profile})"
        found.append((name, history, "chrome"))
    return found


def _firefox_profiles(profiles_dir, label="Firefox"):
    """Every Firefox profile with a places.sqlite (profile names are arbitrary)."""
    base = Path(profiles_dir)
    if not base.is_dir():
        return []
    try:
        return [(label, p, "firefox") for p in sorted(base.glob("*/places.sqlite"))]
    except OSError:
        return []


def _opera_history(opera_dir, label="Opera"):
    """Opera keeps History directly in its profile dir (no Default/ level)."""
    p = Path(opera_dir) / "History"
    return [(label, p, "chrome")] if p.exists() else []


def get_browser_paths():
    """Auto-detect browser history database paths for the current OS.

    Returns a list of (browser_name, path, db_type) tuples for browsers found.
    """
    paths = []

    if IS_MAC:
        sup = HOME / "Library/Application Support"
        paths += _chromium_profiles(sup / "Google/Chrome", "Chrome")
        paths += _firefox_profiles(sup / "Firefox/Profiles")
        # Safari (History.db, TCC-protected — see _scan_safari_history)
        safari = HOME / "Library/Safari/History.db"
        if safari.exists():
            paths.append(("Safari", safari, "safari"))
        paths += _chromium_profiles(sup / "Microsoft Edge", "Edge")
        paths += _chromium_profiles(sup / "BraveSoftware/Brave-Browser", "Brave")
        paths += _chromium_profiles(sup / "Arc/User Data", "Arc")
        paths += _chromium_profiles(sup / "Vivaldi", "Vivaldi")
        paths += _opera_history(sup / "com.operasoftware.Opera")

    elif IS_LINUX:
        cfg = HOME / ".config"
        paths += _chromium_profiles(cfg / "google-chrome", "Chrome")
        paths += _chromium_profiles(cfg / "chromium", "Chromium")

        # Chromium (snap) — profiles live under ~/snap/chromium/
        snap_chromium = HOME / "snap/chromium"
        if snap_chromium.exists():
            for sub in ("common/.config/chromium", "common/chromium"):
                for name, p, t in _chromium_profiles(snap_chromium / sub, "Chromium-snap"):
                    paths.append((name, p, t))

        # Firefox — classic (~/.mozilla/firefox) AND XDG
        # (~/.config/mozilla/firefox) locations. Modern Firefox builds honor
        # XDG_CONFIG_HOME; checking only the classic path silently misses
        # the whole browser. Glob ANY subdir containing places.sqlite, not
        # just "*.default*" — profile dirs can be named arbitrarily
        # (e.g. "bmCbaQgY.Profile 1").
        xdg_config = Path(os.environ.get("XDG_CONFIG_HOME") or cfg)
        paths += _firefox_profiles(HOME / ".mozilla/firefox")
        paths += _firefox_profiles(xdg_config / "mozilla/firefox")
        paths += _firefox_profiles(HOME / "snap/firefox/common/.mozilla/firefox", "Firefox-snap")

        paths += _chromium_profiles(cfg / "BraveSoftware/Brave-Browser", "Brave")
        paths += _chromium_profiles(cfg / "microsoft-edge", "Edge")
        paths += _chromium_profiles(cfg / "vivaldi", "Vivaldi")
        paths += _opera_history(cfg / "opera")

    elif IS_WINDOWS:
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")

        if localappdata:
            la = Path(localappdata)
            paths += _chromium_profiles(la / "Google/Chrome/User Data", "Chrome")
            paths += _chromium_profiles(la / "Microsoft/Edge/User Data", "Edge")
            paths += _chromium_profiles(la / "BraveSoftware/Brave-Browser/User Data", "Brave")
            paths += _chromium_profiles(la / "Vivaldi/User Data", "Vivaldi")

        if appdata:
            ra = Path(appdata)
            paths += _firefox_profiles(ra / "Mozilla/Firefox/Profiles")
            paths += _opera_history(ra / "Opera Software/Opera Stable")

    # De-duplicate (XDG_CONFIG_HOME may equal ~/.config, etc.)
    seen, unique = set(), []
    for name, p, t in paths:
        key = str(p)
        if key not in seen:
            seen.add(key)
            unique.append((name, p, t))
    return unique


def get_software_inventory_paths():
    """Auto-detect software inventory sources for the current OS.

    Returns a list of (method_name, command_or_path, output_type) tuples.
    The scanner will run each and parse the output.
    """
    sources = []

    if IS_MAC:
        # macOS: list /Applications
        sources.append(("file", "/Applications", "ls"))
        # Also check user Applications
        user_apps = HOME / "Applications"
        if user_apps.exists():
            sources.append(("file", str(user_apps), "ls"))

    elif IS_LINUX:
        # Linux: dpkg or rpm
        if shutil.which("dpkg"):
            sources.append(("command", "dpkg -l", "dpkg"))
        if shutil.which("rpm"):
            sources.append(("command", "rpm -qa", "rpm"))
        # Also check flatpak
        if shutil.which("flatpak"):
            sources.append(("command", "flatpak list", "flatpak"))
        # Also check snap
        if shutil.which("snap"):
            sources.append(("command", "snap list", "snap"))

    elif IS_WINDOWS:
        # Windows: PowerShell first (modern, no admin, not deprecated), wmic fallback.
        # Passed as an argv list (not a shell=True string) so there is no
        # cmd.exe quoting layer to get wrong. "Unique" is not a real cmdlet
        # (Sort-Object -Unique is) and Select-Object without -ExpandProperty
        # prints a formatted table (header + dashes) instead of plain names —
        # both would have silently broken software detection on real Windows.
        if shutil.which("powershell"):
            ps_script = (
                "Get-ItemProperty "
                "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
                "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
                "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
                "-ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty DisplayName | "
                "Where-Object { $_ } | Sort-Object -Unique"
            )
            ps_cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
            sources.append(("command", ps_cmd, "powershell"))
        if shutil.which("wmic"):
            sources.append(("command", ["wmic", "product", "get", "name"], "wmic"))

    return sources


# ---------------------------------------------------------------------------
# Domain database loader
# ---------------------------------------------------------------------------

def load_domain_db():
    """Load the AI domain database."""
    with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_practice_software_db():
    """Load the practice management software database (Document Discovery)."""
    with open(PRACTICE_SOFTWARE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

class Finding:
    """A single Shadow AI discovery finding."""
    def __init__(self, source, tool, category, risk, evidence, notes=""):
        self.source = source
        self.tool = tool
        self.category = category
        self.risk = risk
        self.evidence = evidence
        self.notes = notes
        self.timestamp = datetime.datetime.now().isoformat()

    def to_dict(self):
        return {
            "source": self.source, "tool": self.tool, "category": self.category,
            "risk": self.risk, "evidence": self.evidence, "notes": self.notes,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        return f"Finding({self.source}/{self.tool}/{self.risk})"


class FindingStore:
    """SQLite-backed finding storage. Writes each finding immediately."""
    def __init__(self, db_path):
        self.conn = sqlite3.connect(str(db_path))
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL, tool TEXT NOT NULL, category TEXT,
                risk TEXT NOT NULL, evidence TEXT, notes TEXT,
                timestamp TEXT NOT NULL, client TEXT, auditor TEXT, scan_date TEXT
            )
        """)
        self.conn.commit()
        self.findings = []
        self._client = ""
        self._auditor = ""
        self._scan_date = ""

    def set_meta(self, client="", auditor="", scan_date=""):
        self._client = client
        self._auditor = auditor
        self._scan_date = scan_date

    def add(self, finding):
        self.findings.append(finding)
        self.conn.execute(
            "INSERT INTO findings (source, tool, category, risk, evidence, notes, timestamp, client, auditor, scan_date) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (finding.source, finding.tool, finding.category, finding.risk, finding.evidence, finding.notes, finding.timestamp, self._client, self._auditor, self._scan_date)
        )
        self.conn.commit()

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# Machine info capture (audit trail)
# ---------------------------------------------------------------------------

def capture_machine_info():
    """Capture hostname, user, IP, and OS details for audit trail."""
    info = {
        "hostname": "",
        "username": "",
        "ip_addresses": [],
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "captured_at": datetime.datetime.now().isoformat(),
    }
    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        pass
    try:
        info["username"] = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    except Exception:
        pass
    try:
        info["ip_addresses"] = socket.gethostbyname_ex(socket.gethostname())[2]
    except Exception:
        pass
    return info


def write_activity_log(output_dir, event, details=""):
    """Append a timestamped event to the scanner activity log."""
    log_path = Path(output_dir) / "scanner.log"
    timestamp = datetime.datetime.now().isoformat()
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {event}")
        if details:
            f.write(f" — {details}")
        f.write("\n")


# ---------------------------------------------------------------------------
# Module 1: DNS Log Scanner (unchanged — works on any OS with a log file)
# ---------------------------------------------------------------------------

DNS_LOG_PATTERNS = [
    re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?query\[A\]\s+(\S+)\s+from', re.IGNORECASE),
    re.compile(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?(\S+\.\S+)\s', re.IGNORECASE),
    re.compile(r'query\[A\]\s+(\S+)', re.IGNORECASE),
    re.compile(r'QNAME\s+=\s+(\S+)', re.IGNORECASE),
    re.compile(r'"question"\s*:\s*"([^"]+)"', re.IGNORECASE),
    re.compile(r'([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)', re.IGNORECASE),
]


def _match_ai_host(host, domain_map):
    """Return the AI-domain key for a hostname, or None.

    Exact host or a true subdomain only (host == d or host.endswith("." + d)).
    Longest match wins, so "chat.openai.com" beats "openai.com" if both exist.
    Entries with scan: false (gatekeeper-only) never match.
    """
    if not host:
        return None
    host = host.lower().strip(".")
    labels = host.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        info = domain_map.get(candidate)
        if info is not None and info.get("scan") is not False:
            return candidate
    return None


def _norm_ts(ts):
    """Normalize a timestamp string to 'YYYY-MM-DD HH:MM' (or None)."""
    if not ts:
        return None
    s = str(ts).replace("T", " ")
    return s[:16] if re.match(r"^\d{4}-\d{2}-\d{2}", s) else None


def _first_last(timestamps):
    """(earliest, latest) of the parseable timestamps, or ('unknown','unknown')."""
    vals = sorted(t for t in (_norm_ts(x) for x in timestamps) if t)
    if not vals:
        return "unknown", "unknown"
    return vals[0], vals[-1]


def scan_dns_log(log_path, domain_db):
    """Scan a DNS log file for AI tool domain queries.

    Each log line counts at most once per AI domain. (Before 2026-09-27 a
    dnsmasq line matched three patterns and was counted three times.)
    """
    findings = []
    domain_counts = Counter()
    domain_timestamps = defaultdict(list)
    domain_map = domain_db["domains"]

    with open(log_path, "r", errors="replace") as f:
        for line in f:
            hits = set()
            for pattern in DNS_LOG_PATTERNS:
                for match in pattern.findall(line):
                    domain = match[-1] if isinstance(match, tuple) else match
                    ai_domain = _match_ai_host(domain, domain_map)
                    if ai_domain:
                        hits.add(ai_domain)
            if not hits:
                continue
            ts_match = re.match(r'(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
            for ai_domain in hits:
                domain_counts[ai_domain] += 1
                if ts_match:
                    domain_timestamps[ai_domain].append(ts_match.group(1))

    record_coverage("dns", log_path, "ok", f"{sum(domain_counts.values())} AI queries")

    for domain, count in domain_counts.items():
        info = domain_map[domain]
        stamps = domain_timestamps[domain]
        first, last = (stamps[0], stamps[-1]) if stamps else ("unknown", "unknown")
        findings.append(Finding(
            source="dns", tool=info["tool"], category=info["category"],
            risk=info["risk_default"],
            evidence=f"DNS queries to {domain} ({count} queries)",
            notes=f"First seen: {first}. Last seen: {last}. {info.get('notes', '')}"
        ))

    return findings, domain_counts


# ---------------------------------------------------------------------------
# Module 2: Browser History Scanner (auto-detect)
# ---------------------------------------------------------------------------

BROWSER_ROW_LIMIT = 50000


def scan_browser_history_auto(domain_db, specific_path=None):
    """Auto-detect and scan all browser histories on this machine.

    If specific_path is provided, scan only that file.
    Otherwise, auto-detect all browsers for the current OS.
    Every browser attempted is recorded in SCAN_COVERAGE (ok/partial/failed).
    """
    findings = []
    domain_map = domain_db["domains"]
    visit_counts = Counter()
    visit_details = defaultdict(list)

    if specific_path:
        browser_paths = [("Manual", Path(specific_path), _detect_browser_type(specific_path))]
    else:
        browser_paths = get_browser_paths()

    if not browser_paths:
        print("  No browsers detected on this system.")
        record_coverage("browser", "(none)", "not_found",
                        "No supported browser history found for this user account")
        return findings, visit_counts, browser_paths

    for browser_name, path, db_type in browser_paths:
        print(f"  Scanning {browser_name}: {path}")
        label = f"{browser_name}"
        try:
            if db_type == "chrome":
                status, detail = _scan_chrome_history(path, domain_map, visit_counts, visit_details, browser_name)
            elif db_type == "firefox":
                status, detail = _scan_firefox_history(path, domain_map, visit_counts, visit_details, browser_name)
            elif db_type == "safari":
                status, detail = _scan_safari_history(path, domain_map, visit_counts, visit_details, browser_name)
            else:
                status, detail = "failed", f"unknown history type {db_type}"
        except Exception as e:
            print(f"    warn: could not read {browser_name} history: {e}")
            status, detail = "failed", f"could not read history: {type(e).__name__}: {e}"
        record_coverage("browser", label, status, detail)

    # Generate findings
    for domain, count in visit_counts.items():
        info = domain_map[domain]
        first, last = _first_last(visit_details[domain])
        findings.append(Finding(
            source="browser", tool=info["tool"], category=info["category"],
            risk=info["risk_default"],
            evidence=f"Browser visits to {domain} ({count} visits)",
            notes=f"First visit: {first} UTC. Last visit: {last} UTC. {info.get('notes', '')}"
        ))

    return findings, visit_counts, browser_paths


def _detect_browser_type(path):
    """Detect browser type from filename."""
    name = Path(path).name.lower()
    if "places" in name:
        return "firefox"
    if "history.db" in name:
        return "safari"
    return "chrome"  # Default to Chrome schema


def _snapshot_sqlite(path):
    """Copy a live browser SQLite DB (plus -wal/-shm/-journal) to a private temp dir.

    Firefox and Safari run in WAL mode: while the browser is open, the most
    recent visits exist only in the -wal file. Copying the main file alone
    silently drops them (found 2026-09-27). The companions are copied under
    the same basename so SQLite replays them on open.
    Returns (tmp_dir, db_copy_path). Caller must shutil.rmtree(tmp_dir).
    """
    import tempfile
    tmp_dir = tempfile.mkdtemp(prefix="sa-scan-")
    try:
        os.chmod(tmp_dir, 0o700)
    except OSError:
        pass
    src = Path(path)
    dst = Path(tmp_dir) / src.name
    try:
        shutil.copy2(str(src), str(dst))
        for suffix in ("-wal", "-shm", "-journal"):
            comp = Path(str(src) + suffix)
            if comp.exists():
                try:
                    shutil.copy2(str(comp), str(dst) + suffix)
                except OSError:
                    pass  # companion locked/vanished: main file still usable
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    return tmp_dir, dst


def _run_history_query(path, sql, row_handler, browser_name, kind):
    """Snapshot, query, and always clean up. Returns (status, detail)."""
    queries = sql if isinstance(sql, (list, tuple)) else [sql]
    tmp_dir, db_copy = _snapshot_sqlite(path)
    try:
        conn = sqlite3.connect(str(db_copy))
        try:
            last_err = None
            rows = None
            for q in queries:  # newest schema first; first query that runs wins
                try:
                    rows = conn.execute(q).fetchall()
                    break
                except sqlite3.OperationalError as e:
                    last_err = e
            if rows is None:
                # AUDIT-INTEGRITY: never swallow schema errors into silent zeros.
                print(f"    WARN: {browser_name} {kind} schema mismatch ({last_err}) — browser findings may be incomplete")
                return "failed", f"{kind} schema mismatch: {last_err}"
        finally:
            conn.close()
        for row in rows:
            row_handler(row)
        if len(rows) >= BROWSER_ROW_LIMIT:
            return "partial", f"only the most recent {BROWSER_ROW_LIMIT:,} history rows were read"
        return "ok", f"{len(rows):,} history rows read"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _scan_chrome_history(path, domain_map, visit_counts, visit_details, browser_name):
    """Scan Chrome/Edge/Brave/Arc/Vivaldi/Opera history (same SQLite schema)."""
    def handle(row):
        url, visit_time, n = row
        try:
            if visit_time and visit_time > 10000000000000000:
                timestamp = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=visit_time)).isoformat()
            else:
                timestamp = ""
        except Exception:
            timestamp = ""
        _check_url_for_ai(url, timestamp, domain_map, visit_counts, visit_details, max(int(n or 0), 1))

    return _run_history_query(
        path,
        [f"SELECT url, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT {BROWSER_ROW_LIMIT}",
         f"SELECT url, last_visit_time, 1 FROM urls ORDER BY last_visit_time DESC LIMIT {BROWSER_ROW_LIMIT}"],
        handle, browser_name, "History")


def _scan_firefox_history(path, domain_map, visit_counts, visit_details, browser_name):
    """Scan Firefox history (places.sqlite)."""
    def handle(row):
        url, timestamp, n = row
        _check_url_for_ai(url, timestamp or "", domain_map, visit_counts, visit_details, max(int(n or 0), 1))

    tail = f"FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT {BROWSER_ROW_LIMIT}"
    return _run_history_query(
        path,
        [f"SELECT url, datetime(last_visit_date/1000000, 'unixepoch'), visit_count {tail}",
         f"SELECT url, datetime(last_visit_date/1000000, 'unixepoch'), 1 {tail}"],
        handle, browser_name, "places.sqlite")


def _scan_safari_history(path, domain_map, visit_counts, visit_details, browser_name):
    """Scan Safari history (History.db — SQLite on modern macOS).

    Safari history is under TCC protection: even though the file is owned by
    the current user, macOS blocks reads from it unless the calling process
    (Terminal, or the Python interpreter itself) has been granted Full Disk
    Access. Denial surfaces as PermissionError, not FileNotFoundError — the
    path.exists() check upstream will have already succeeded.
    One row per visit, so each row counts once. Timestamps in UTC like the
    other browsers.
    """
    def handle(row):
        url, timestamp = row
        _check_url_for_ai(url, timestamp or "", domain_map, visit_counts, visit_details, 1)

    try:
        return _run_history_query(
            path,
            "SELECT url, datetime(visit_time + 978307200, 'unixepoch') FROM history_visits "
            "JOIN history_items ON history_visits.history_item = history_items.id "
            f"ORDER BY visit_time DESC LIMIT {BROWSER_ROW_LIMIT}",
            handle, browser_name, "History.db")
    except PermissionError as e:
        raise PermissionError(
            "macOS blocked Safari history access (Full Disk Access required). "
            "Grant Full Disk Access to Terminal (or the Python interpreter) in "
            "System Settings > Privacy & Security > Full Disk Access, then re-run "
            "the scan. Continuing without Safari data."
        ) from e


def scan_browser_history(history_path, domain_db):
    """Legacy single-file browser scan (kept for backward compat)."""
    return scan_browser_history_auto(domain_db, specific_path=history_path)[:2]


def _check_url_for_ai(url, timestamp, domain_map, visit_counts, visit_details, visits=1):
    """Check a URL's HOST against the AI domain database.

    Matches the hostname only. (Before 2026-09-27 the domain was searched
    anywhere in the URL, so Outlook SafeLinks / Google redirect URLs that
    merely contained an AI address in a query string counted as visits.)
    """
    if not url:
        return
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return
    ai_domain = _match_ai_host(host, domain_map)
    if ai_domain:
        visit_counts[ai_domain] += visits
        visit_details[ai_domain].append(str(timestamp))


# ---------------------------------------------------------------------------
# Module 3: Software Inventory Scanner (auto-detect OS)
# ---------------------------------------------------------------------------

def scan_software_inventory_auto(domain_db):
    """Auto-scan installed software on this machine."""
    findings = []
    software_map = domain_db.get("software_names", {})
    detected = set()
    sources = get_software_inventory_paths()

    if not sources:
        print("  No software inventory sources detected for this OS.")
        record_coverage("software", "(none)", "not_found", "No software inventory source for this OS")
        return findings, detected

    for method, source, output_type in sources:
        source_display = " ".join(source) if isinstance(source, list) else source
        print(f"  Scanning via {method}: {source_display[:80]}...")

        try:
            if method == "file":
                # List /Applications directory (macOS)
                app_dir = Path(source)
                if app_dir.exists():
                    for item in app_dir.iterdir():
                        app_name = item.stem
                        _match_software(app_name, software_map, detected)
                    record_coverage("software", source_display, "ok", "folder listed")
                else:
                    record_coverage("software", source_display, "not_found", "folder not present")

            elif method == "command":
                # Linux sources are plain shell strings (dpkg -l, rpm -qa, ...).
                # Windows sources are argv lists — run without a shell so
                # there's no cmd.exe quoting/escaping to get wrong.
                result = subprocess.run(
                    source, shell=isinstance(source, str),
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 127:
                    record_coverage("software", source_display[:60], "not_found", "package tool not installed")
                elif result.returncode != 0:
                    record_coverage("software", source_display[:60], "failed",
                                    f"exit {result.returncode}: {(result.stderr or '').strip()[:160]}")
                else:
                    record_coverage("software", source_display[:60], "ok",
                                    f"{len(result.stdout.splitlines())} entries listed")
                if result.returncode == 0 and result.stdout:
                    for line in result.stdout.splitlines():
                        if output_type == "dpkg":
                            # Keep the FULL line: _match_software parses the
                            # package-name field itself. Descriptions contain
                            # commas, so a CSV-style split would feed the
                            # description tail ("scalable cursor theme") to
                            # the matcher and false-positive as Cursor.
                            line_clean = line.strip()
                        else:
                            line_clean = line.strip().strip('"').split(",")[-1].strip()
                        _match_software(line_clean, software_map, detected)

        except FileNotFoundError:
            record_coverage("software", source_display[:60], "not_found", "package tool not installed")
        except Exception as e:
            print(f"    warn: {output_type} scan failed: {e}")
            record_coverage("software", source_display[:60], "failed", f"{type(e).__name__}: {e}")

    for sw_name, raw_line in sorted(detected):
        info = software_map[sw_name]
        findings.append(Finding(
            source="software", tool=sw_name, category=info["category"],
            risk=info["risk_default"],
            evidence=f"Installed software: {sw_name} (detected from: '{raw_line}')",
            notes=info.get("notes", "")
        ))

    return findings, detected


def _match_software(text, software_map, detected):
    """Match a software name against the known AI tools database.

    Uses token/word-boundary matching so package names like
    libwayland-cursor0 / libxcursor1 do not false-positive as Cursor.
    For dpkg -l lines, only the package name field is matched (not the
    human-readable description, which often contains words like "cursor").
    """
    if not text or not text.strip():
        return

    text_lower = text.lower().strip()

    # dpkg -l: "ii  package-name  version  arch  description"
    dpkg = re.match(r'^(?:ii|hi|rc|un|iU|iF)\s+(\S+)', text_lower)
    if dpkg:
        pkg = dpkg.group(1)
        # strip arch qualifier: libfoo:amd64 -> libfoo
        pkg_name = pkg.split(":", 1)[0]
        haystacks = [pkg_name]
        dpkg_mode = True
    else:
        haystacks = [text_lower]
        dpkg_mode = False

    for sw_name, info in software_map.items():
        sw = sw_name.lower()
        matched = False

        for hay in haystacks:
            # Exact / prefix package match (cursor, cursor-bin, cursor.editor)
            if dpkg_mode:
                if hay == sw or hay.startswith(sw + "-") or hay.startswith(sw + "."):
                    matched = True
                    break
                continue

            # Non-dpkg: word-boundary substring (apps, flatpak labels, paths)
            pattern = rf'(?<![a-z0-9]){re.escape(sw)}(?![a-z0-9])'
            if re.search(pattern, hay):
                matched = True
                break

        if not matched:
            continue

        # Hard rejects for library packages that embed tool names
        if sw == "cursor":
            check = haystacks[0]
            if re.search(r'(?:^|[^a-z])(?:lib\w*cursor|wayland-cursor|xcursor|libcursor)', check):
                continue
            if dpkg_mode and not (
                check == "cursor"
                or check.startswith("cursor-")
                or check.startswith("cursor.")
            ):
                continue

        detected.add((sw_name, text))


def scan_software_inventory(inventory_path, domain_db):
    """Legacy single-file software scan (kept for backward compat)."""
    findings = []
    software_map = domain_db.get("software_names", {})
    detected = set()

    with open(inventory_path, "r", errors="replace") as f:
        lines = f.readlines()

    for line in lines:
        line_clean = line.strip().strip('"').split(",")[-1].strip()
        _match_software(line_clean, software_map, detected)

    for sw_name, raw_line in sorted(detected):
        info = software_map[sw_name]
        findings.append(Finding(
            source="software", tool=sw_name, category=info["category"],
            risk=info["risk_default"],
            evidence=f"Installed software: {sw_name} (detected from: '{raw_line}')",
            notes=info.get("notes", "")
        ))

    return findings, detected


# ---------------------------------------------------------------------------
# Module 4: Interactive Interview (unchanged)
# ---------------------------------------------------------------------------

INTERVIEW_QUESTIONS = [
    ("name", "Staff member name (or initials, or role only): "),
    ("role", "Role at the firm: "),
    ("tools", "Which AI tools do you use for work? (comma-separated, or 'none'): "),
    ("use_cases", "What do you use them for? (drafting, summarizing, research, coding, etc.): "),
    ("data_types", "Have you ever put client, patient or financial information into these tools? (yes/no/unsure, then describe): "),
    ("account_type", "Personal or work accounts? (personal/work/both): "),
    ("mobile", "Do you use AI apps on your phone for work tasks? (yes/no, which): "),
    ("extensions", "Any AI browser extensions installed? (list, or 'none'): "),
]


_NEGATIVE_ANSWER = re.compile(r"^\s*(no|n|none|never|nope|not\b|nothing)\b", re.IGNORECASE)
_POSITIVE_ANSWER = re.compile(r"\b(yes|y|yeah|yep|sometimes|occasionally|client|clients|patient|patients|financial|pii)\b", re.IGNORECASE)


def answer_shares_sensitive_data(answer):
    """True only when the data-types answer says sensitive data WAS shared.

    A leading no/never/none wins ("no, never any client data" is not a
    CRITICAL). Before 2026-09-27 any answer containing "client" or "yes"
    anywhere escalated to CRITICAL, including plain denials.
    """
    a = (answer or "").strip()
    if not a or _NEGATIVE_ANSWER.match(a):
        return False
    return bool(_POSITIVE_ANSWER.search(a))


def interview_findings(responses, domain_db):
    """Turn one staff interview (dict) into Findings. Shared by the live
    interview and --interview-data so the two paths can't drift."""
    findings = []
    tools_str = (responses.get("tools") or "").lower()
    if not tools_str or tools_str.strip() == "none":
        return findings
    software_map = domain_db.get("software_names", {})
    sensitive = answer_shares_sensitive_data(responses.get("data_types", ""))
    who = f"{responses.get('name') or 'anonymous'} ({responses.get('role') or 'unknown role'})"
    use = responses.get("use_cases") or "unspecified"
    notes = (f"Data shared: {responses.get('data_types') or 'unknown'}. "
             f"Account type: {responses.get('account_type') or 'unknown'}. "
             f"Mobile: {responses.get('mobile') or 'unknown'}. "
             f"Extensions: {responses.get('extensions') or 'none'}")
    for tool_name in [t.strip() for t in tools_str.split(",")]:
        if not tool_name or tool_name == "none":
            continue
        match = next(((n, i) for n, i in software_map.items() if n.lower() in tool_name), None)
        if match:
            sw_name, info = match
            findings.append(Finding(
                source="interview", tool=sw_name, category=info["category"],
                risk="CRITICAL" if sensitive else info["risk_default"],
                evidence=f"Staff interview: {who} uses {sw_name} for {use}", notes=notes))
        else:
            findings.append(Finding(
                source="interview", tool=tool_name.title(), category="unknown",
                risk="CRITICAL" if sensitive else "MEDIUM",
                evidence=f"Staff interview: {who} uses {tool_name} for {use}", notes=notes))
    return findings


def interactive_interview():
    """Run an interactive staff interview and return findings."""
    print("\n" + "=" * 60)
    print("Shadow AI Discovery — Staff Interview")
    print("=" * 60)
    print("This is non-invasive. We're mapping what AI tools are being used.")
    print("No personal content is captured. No judgment — just facts.\n")

    responses = {}
    for key, prompt in INTERVIEW_QUESTIONS:
        responses[key] = input(prompt).strip()

    return interview_findings(responses, load_domain_db()), responses


# ---------------------------------------------------------------------------
# Module 5: Report Generator (unchanged from original)
# ---------------------------------------------------------------------------

def generate_report(findings, client_name, auditor_name, output_dir, scan_date=None, document_discovery=None, coverage=None):
    """Generate HTML, JSON, and CSV reports from findings.

    `document_discovery`, if provided, is the dict built by
    _build_document_discovery_report() — it is added to report.json under
    the `document_discovery` key and written to data_manifest.csv.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_date = scan_date or datetime.datetime.now().strftime("%Y-%m-%d")

    risk_counts = Counter(f.risk for f in findings)
    total_tools = len(set(f.tool for f in findings))
    total_findings = len(findings)
    category_counts = Counter(f.category for f in findings)
    source_counts = Counter(f.source for f in findings)

    sorted_findings = sorted(findings, key=lambda f: RISK_WEIGHTS.get(f.risk, 0), reverse=True)
    top_actions = []
    for f in sorted_findings[:3]:
        if f.risk in ("CRITICAL", "HIGH"):
            top_actions.append(f"Stop or restrict {f.tool} usage — {f.evidence}")
        else:
            top_actions.append(f"Review {f.tool} usage — {f.evidence}")

    # Software inventory alone means "tool present", not "client data shared".
    # PIPEDA/PHIPA exposure requires CRITICAL, or HIGH from usage evidence sources.
    pipeda_exposure = any(
        f.risk == "CRITICAL"
        or (f.risk == "HIGH" and f.source in ("interview", "browser", "dns"))
        for f in findings
    )
    insurance_gap = any(
        f.category in ("consumer_ai", "transcription")
        and f.risk in ("CRITICAL", "HIGH")
        and f.source in ("interview", "browser", "dns")
        for f in findings
    )

    # Interview-confirmed sharing is the only thing that proves data went in.
    pipeda_confirmed = any(f.risk == "CRITICAL" and f.source == "interview" for f in findings)

    coverage = [dict(c) for c in (SCAN_COVERAGE if coverage is None else coverage)]
    scan_complete = not any(c["status"] in ("failed", "partial") for c in coverage)

    json_report = {
        "report_type": "Shadow AI Discovery (SA-1)",
        "client": client_name, "auditor": auditor_name,
        "scan_date": scan_date, "generated": datetime.datetime.now().isoformat(),
        "platform": f"{platform.system()} {platform.release()}",
        "summary": {
            "total_findings": total_findings, "unique_tools": total_tools,
            "risk_distribution": dict(risk_counts),
            "category_distribution": dict(category_counts),
            "source_distribution": dict(source_counts),
            "pipeda_exposure": pipeda_exposure, "insurance_gap_risk": insurance_gap,
            "pipeda_confirmed_by_interview": pipeda_confirmed,
            "scan_complete": scan_complete,
        },
        "scan_coverage": coverage,
        "top_actions": top_actions,
        "findings": [f.to_dict() for f in sorted_findings],
    }
    if document_discovery is not None:
        json_report["document_discovery"] = document_discovery

    json_path = output_dir / "report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_report, f, indent=2)

    def _cell(v):
        v = "" if v is None else str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    csv_path = output_dir / "inventory.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Source", "Tool", "Category", "Risk Level", "Evidence", "Notes", "Timestamp"])
        for finding in sorted_findings:
            writer.writerow([_cell(x) for x in (finding.source, finding.tool, finding.category, finding.risk, finding.evidence, finding.notes, finding.timestamp)])

    manifest_path = None
    if document_discovery is not None:
        manifest_path = output_dir / "data_manifest.csv"
        with open(manifest_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Source", "Type", "Name", "Location", "Document_Count", "Total_Size",
                              "Export_Method", "Export_Instructions", "Access_Status"])
            for loc in document_discovery["data_locations"]:
                writer.writerow([_cell(x) for x in (
                    loc["source"], loc["type"], loc["name"], loc["location"],
                    loc["document_count"] if loc["document_count"] is not None else "—",
                    loc["total_size_human"], loc["export_method"] or "",
                    loc["export_instructions"] or "", loc["access_status"],
                )])
            for d in document_discovery["practice_software"]:
                writer.writerow([_cell(x) for x in (
                    "practice_software", "practice_management", d["tool_name"],
                    d.get("data_location") or "", "—", "—",
                    d.get("export_method") or "", d.get("export_instructions") or "",
                    "accessible",
                )])

    report_html = _generate_html_report(json_report, sorted_findings, client_name, auditor_name, scan_date, risk_counts, category_counts, source_counts, top_actions, pipeda_exposure, insurance_gap, document_discovery=document_discovery)
    html_path = output_dir / "report.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    pdf_path = None
    try:
        from weasyprint import HTML as WeasyHTML
        pdf_path = output_dir / "report.pdf"
        WeasyHTML(string=report_html).write_pdf(str(pdf_path))
    except ImportError:
        pass
    except Exception as e:
        print(f"  warn: PDF generation failed: {e}", file=sys.stderr)

    return {
        "json": str(json_path), "csv": str(csv_path), "html": str(html_path),
        "data_manifest": str(manifest_path) if manifest_path else None,
        "pdf": str(pdf_path) if pdf_path and pdf_path.exists() else None,
        "total_findings": total_findings, "unique_tools": total_tools,
        "risk_distribution": dict(risk_counts),
        "scan_complete": scan_complete,
    }


def _generate_document_discovery_html(dd):
    """Render the Document Discovery section (Data Manifest + Export Guide)."""
    if dd is None:
        return ""

    source_labels = {
        "local_file_store": "Local", "cloud_sync": "Cloud", "email_store": "Email",
        "network_share": "Network",
    }

    manifest_rows = ""
    for loc in dd["data_locations"]:
        source_label = _esc(source_labels.get(loc["source"], loc["source"]))
        doc_count = f"{loc['document_count']:,}" if loc.get("document_count") is not None else "—"
        manifest_rows += f"""
        <tr>
          <td>{source_label}</td>
          <td>{_esc(loc['type'])}</td>
          <td>{_esc(loc['name'])}</td>
          <td>{_esc(loc['location'])}</td>
          <td>{doc_count}</td>
          <td>{_esc(loc['total_size_human'])}</td>
          <td>{_esc(loc['export_method'] or '—')}</td>
        </tr>"""

    for d in dd["practice_software"]:
        manifest_rows += f"""
        <tr>
          <td>Practice</td>
          <td>practice_management</td>
          <td>{_esc(d['tool_name'])}</td>
          <td>{_esc(d.get('data_location') or '—')}</td>
          <td>—</td>
          <td>—</td>
          <td>{_esc(d.get('export_method') or '—')}</td>
        </tr>"""

    if not manifest_rows:
        manifest_rows = "<tr><td colspan='7'>No document locations found — client may be fully cloud-based.</td></tr>"

    dedup_notes = "".join(
        f"<li>{_esc(loc['name'])}: {_esc(loc['notes'])}</li>"
        for loc in dd["data_locations"]
        if loc.get("notes") and ("Overlaps with" in loc["notes"] or "deduplicated" in loc["notes"])
    )
    dedup_html = (
        f"<p style='margin-top:12px;font-size:13px;color:#475569'><strong>Note:</strong></p><ul>{dedup_notes}</ul>"
        if dedup_notes else ""
    )

    export_guide_html = "".join(
        f"""
        <div style="margin-bottom:16px">
          <strong>{_esc(d['tool_name'])} detected:</strong>
          <p style="font-size:13px;color:#475569;margin-top:4px">{_esc(d.get('export_instructions') or 'No export instructions available.')}</p>
          <p style="font-size:13px;color:#475569">Data: {_esc(', '.join(d.get('data_types') or []) or 'unknown')}</p>
        </div>"""
        for d in dd["practice_software"]
    ) or "<p style='font-size:13px;color:#475569'>No practice management software detected.</p>"

    summary = dd["summary"]
    note_html = f"<p style='font-size:13px;color:#475569;margin-bottom:12px'>{_esc(dd['note'])}</p>" if dd.get("note") else ""

    return f"""
  <div class="section">
    <h2>Document Discovery</h2>
    {note_html}
    <div class="summary-grid">
      <div class="summary-card"><div class="number">{summary['total_document_locations']}</div><div class="label">Locations</div></div>
      <div class="summary-card"><div class="number">{summary['total_documents']:,}</div><div class="label">Total Documents</div></div>
      <div class="summary-card"><div class="number">{_esc(summary['total_size_human'])}</div><div class="label">Total Size</div></div>
      <div class="summary-card"><div class="number">{_esc(summary['export_complexity'])}</div><div class="label">Export Complexity</div></div>
    </div>

    <h3 style="margin-top:16px">Data Manifest</h3>
    <table>
      <tr><th>Source</th><th>Type</th><th>Name</th><th>Location</th><th>Doc Count</th><th>Total Size</th><th>Export Method</th></tr>
      {manifest_rows}
    </table>
    {dedup_html}

    <h3 style="margin-top:16px">Export Guide</h3>
    {export_guide_html}
  </div>"""


def _generate_html_report(json_report, findings, client, auditor, scan_date, risk_counts, category_counts, source_counts, top_actions, pipeda_exposure, insurance_gap, document_discovery=None):
    """Generate the HTML report from the template file."""
    risk_badge = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}

    findings_rows = ""
    for f in findings:
        color = risk_badge.get(f.risk, "#6b7280")
        findings_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{_esc(f.risk)}</span></td>
          <td><strong>{_esc(f.tool)}</strong></td>
          <td>{_esc(f.category)}</td>
          <td>{_esc(f.source)}</td>
          <td>{_esc(f.evidence)}</td>
          <td>{_esc(f.notes or '—')}</td>
        </tr>"""

    top_actions_html = ""
    for i, action in enumerate(top_actions, 1):
        top_actions_html += f"<li><strong>{i}.</strong> {_esc(action)}</li>"
    if not top_actions_html:
        top_actions_html = "<li>No critical findings — no immediate action required.</li>"

    risk_summary_html = ""
    for level in RISK_LEVELS:
        count = risk_counts.get(level, 0)
        color = risk_badge.get(level, "#6b7280")
        risk_summary_html += f'<div class="risk-stat"><span class="badge" style="background:{color}">{level}</span><span class="count">{count}</span></div>'

    summary = json_report["summary"]
    coverage = json_report.get("scan_coverage", [])
    scan_complete = summary.get("scan_complete", True)

    # AUDIT-INTEGRITY (2026-09-27): wording must match the evidence.
    # A browser/DNS visit shows a tool was USED, not what was typed into it.
    if summary.get("pipeda_confirmed_by_interview"):
        pipeda_alert = ("<div class='alert critical'><strong>PIPEDA/PHIPA exposure confirmed by staff interview.</strong> "
                        "Staff report entering client, patient or financial information into AI tools. Immediate action required.</div>")
    elif pipeda_exposure:
        pipeda_alert = ("<div class='alert warning'><strong>Possible PIPEDA/PHIPA exposure.</strong> "
                        "Consumer AI tools are in use on this computer. Browsing and DNS records show a tool was used, "
                        "not what was entered into it. Confirm with staff interviews before drawing conclusions.</div>")
    elif not scan_complete:
        pipeda_alert = ("<div class='alert warning'><strong>Scan incomplete — this is not a clean result.</strong> "
                        "One or more sources could not be read (see Scan Coverage). No conclusion about PIPEDA/PHIPA exposure "
                        "can be drawn until they are scanned.</div>")
    else:
        pipeda_alert = "<div class='alert ok'><strong>No immediate PIPEDA/PHIPA exposure detected in the sources scanned.</strong> Review all findings for potential risks.</div>"

    status_label = {"ok": "Scanned", "partial": "Partial", "failed": "NOT SCANNED", "not_found": "Not found"}
    status_color = {"ok": "#16a34a", "partial": "#ca8a04", "failed": "#dc2626", "not_found": "#6b7280"}
    cov_rows = "".join(
        f"<tr><td>{_esc(c['module'])}</td><td>{_esc(c['source'])}</td>"
        f"<td><span class='badge' style='background:{status_color.get(c['status'], '#6b7280')}'>{_esc(status_label.get(c['status'], c['status']))}</span></td>"
        f"<td>{_esc(c['detail'])}</td></tr>"
        for c in coverage
    )
    if coverage:
        incomplete_banner = "" if scan_complete else (
            "<div class='alert critical'><strong>INCOMPLETE SCAN.</strong> "
            f"{sum(1 for c in coverage if c['status'] in ('failed', 'partial'))} source(s) could not be fully read. "
            "Findings below cover only the sources marked Scanned.</div>")
        coverage_html = (incomplete_banner +
                         "<h3 style='margin-top:12px'>Scan Coverage</h3><table>"
                         "<tr><th>Module</th><th>Source</th><th>Status</th><th>Detail</th></tr>"
                         f"{cov_rows}</table>")
    else:
        coverage_html = ""
    pipeda_alert = coverage_html + pipeda_alert

    insurance_alert = ""
    if insurance_gap:
        insurance_alert = "<div class='alert warning'><strong>Insurance Coverage Gap Risk.</strong> Unmanaged use of consumer AI tools may affect cyber insurance coverage. Verify with your insurance provider.</div>"

    platform_str = json_report.get('platform', 'Unknown')

    template_path = SCRIPT_DIR / "report_template.html"
    if not template_path.exists():
        template_path = Path(__file__).parent / "report_template.html"

    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    return template.format(
        client=_esc(client),
        auditor=_esc(auditor),
        scan_date=_esc(scan_date),
        platform=_esc(platform_str),
        total_findings=json_report['summary']['total_findings'],
        unique_tools=json_report['summary']['unique_tools'],
        critical_count=risk_counts.get('CRITICAL', 0),
        high_count=risk_counts.get('HIGH', 0),
        medium_count=risk_counts.get('MEDIUM', 0),
        low_count=risk_counts.get('LOW', 0),
        risk_summary_html=risk_summary_html,
        pipeda_alert=pipeda_alert,
        insurance_alert=insurance_alert,
        top_actions_html=top_actions_html,
        findings_rows=findings_rows or "<tr><td colspan='6'>No findings.</td></tr>",
        document_discovery_html=_generate_document_discovery_html(document_discovery),
    )


# ---------------------------------------------------------------------------
# Document Discovery — shared helpers (DataLocation model, size formatting)
# ---------------------------------------------------------------------------

def _human_size(num_bytes):
    """Format a byte count as a human-readable size string (e.g. '8.2 GB')."""
    try:
        size = float(num_bytes or 0)
    except (TypeError, ValueError):
        size = 0.0
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


class DataLocation:
    """A single document data location discovered during Document Discovery."""
    def __init__(self, source, type, name, location, document_count=0,
                 document_categories=None, total_size_bytes=0,
                 last_modified=None, export_method=None,
                 export_instructions=None, access_status="accessible",
                 access_error=None, notes=""):
        self.source = source
        self.type = type
        self.name = name
        self.location = location
        self.document_count = document_count
        self.document_categories = document_categories or {}
        self.total_size_bytes = total_size_bytes
        self.last_modified = last_modified
        self.export_method = export_method
        self.export_instructions = export_instructions
        self.access_status = access_status
        self.access_error = access_error
        self.notes = notes

    def to_dict(self):
        return {
            "source": self.source,
            "type": self.type,
            "name": self.name,
            "location": self.location,
            "document_count": self.document_count,
            "document_categories": self.document_categories,
            "total_size_bytes": self.total_size_bytes,
            "total_size_human": _human_size(self.total_size_bytes),
            "last_modified": self.last_modified,
            "export_method": self.export_method,
            "export_instructions": self.export_instructions,
            "access_status": self.access_status,
            "access_error": self.access_error,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Module 6: Document Discovery — Local File Stores (D1)
# ---------------------------------------------------------------------------

DOCUMENT_EXTENSIONS = {
    "pdf": [".pdf"],
    "word": [".docx", ".doc", ".rtf"],
    "excel": [".xlsx", ".xls"],
    "markdown": [".md", ".markdown"],
    "text": [".txt"],
    "csv": [".csv"],
    "powerpoint": [".pptx", ".ppt"],
    "outlook": [".pst", ".ost", ".msg", ".eml"],
    "accounting": [".qbw", ".qbb", ".qba", ".cas", ".tax"],
}
_EXT_TO_CATEGORY = {ext: cat for cat, exts in DOCUMENT_EXTENSIONS.items() for ext in exts}
MAX_FILES_PER_FOLDER = 500_000

# Overridable module-level roots so tests can redirect discovery away from
# real system paths (this dev box has real content under /mnt and a live
# network mount in /proc/mounts — scanning those for real in a test would be
# slow and non-deterministic).
LINUX_MOUNT_ROOTS = [Path("/mnt"), Path("/media")]
MACOS_VOLUMES_ROOT = Path("/Volumes")
PROC_MOUNTS_PATH = Path("/proc/mounts")


def count_documents(folder_path, max_depth=5, timeout=60):
    """Count documents in a folder by category.

    Walks the tree (no symlink following, hidden dirs skipped) up to
    max_depth levels, categorizing files by DOCUMENT_EXTENSIONS and summing
    their sizes. Aborts after `timeout` seconds or MAX_FILES_PER_FOLDER
    matched+unmatched files, returning partial results either way.

    Returns (counts_by_category, total_size_bytes, last_modified_iso, status)
    where status is "ok", "timeout", or "truncated".
    """
    folder_path = Path(folder_path)
    counts = {cat: 0 for cat in DOCUMENT_EXTENSIONS}
    total_size = 0
    last_modified = None
    total_files = 0
    status = "ok"
    start = time.monotonic()
    root_depth = len(Path(folder_path).parts)

    for dirpath, dirnames, filenames in os.walk(folder_path, topdown=True, followlinks=False):
        if time.monotonic() - start > timeout:
            status = "timeout"
            break

        dirnames[:] = [d for d in dirnames if not d.startswith(".")]

        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []  # do not descend further, but still count files here

        for filename in filenames:
            if time.monotonic() - start > timeout:
                status = "timeout"
                break

            total_files += 1
            if total_files > MAX_FILES_PER_FOLDER:
                status = "truncated"
                break

            fpath = Path(dirpath) / filename
            try:
                if fpath.is_symlink():
                    continue
                ext = fpath.suffix.lower()
                cat = _EXT_TO_CATEGORY.get(ext)
                if not cat:
                    continue
                st = fpath.stat()
            except OSError:
                continue

            counts[cat] += 1
            total_size += st.st_size
            mtime = datetime.datetime.fromtimestamp(st.st_mtime).isoformat()
            if last_modified is None or mtime > last_modified:
                last_modified = mtime

        if status in ("timeout", "truncated"):
            break

    return counts, total_size, last_modified, status


def _check_path_access(path, timeout=5):
    """Check whether `path` exists and is readable without risking a hang.

    A dead network automount (e.g. an unreachable sshfs/cifs mount) can
    block a plain stat() call indefinitely. The check runs in a daemon
    thread with a bounded join() — if it doesn't finish in time we treat
    the path as inaccessible rather than hanging the whole scan.

    Returns one of: "ok", "not_found", "access_denied", "timeout".
    """
    result = {}

    def _check():
        try:
            if not path.exists():
                result["status"] = "not_found"
            elif not os.access(path, os.R_OK):
                result["status"] = "access_denied"
            else:
                result["status"] = "ok"
        except OSError:
            result["status"] = "access_denied"

    t = threading.Thread(target=_check, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return "timeout"
    return result.get("status", "access_denied")


def _scan_folder_to_location(source, loc_type, name, location, export_method="USB copy",
                              max_depth=5, timeout=60, export_instructions=None, notes=""):
    """Run count_documents() against a folder and wrap the result in a
    DataLocation. Returns None if the folder does not exist (nothing to
    report), or a DataLocation with an access_status describing why the
    folder could not be scanned.
    """
    path = Path(location)
    access = _check_path_access(path)
    if access == "not_found":
        return None
    if access in ("access_denied", "timeout"):
        return DataLocation(
            source=source, type=loc_type, name=name, location=str(path),
            document_count=None, export_method=export_method,
            export_instructions=export_instructions,
            access_status="access_denied" if access == "access_denied" else "scan_timeout",
            access_error=("Permission denied" if access == "access_denied"
                          else "Path check timed out (possible dead network mount)"),
            notes=notes,
        )

    try:
        counts, total_size, last_modified, status = count_documents(path, max_depth=max_depth, timeout=timeout)
    except OSError as e:
        return DataLocation(source=source, type=loc_type, name=name, location=str(path),
                             access_status="access_denied", access_error=str(e), notes=notes)

    if status == "timeout":
        notes = (notes + " " if notes else "") + "Scan timed out — results are partial."
    elif status == "truncated":
        notes = (notes + " " if notes else "") + "File count exceeded 500,000 — counts are partial (500K+)."

    return DataLocation(
        source=source, type=loc_type, name=name, location=str(path),
        document_count=sum(counts.values()), document_categories=counts,
        total_size_bytes=total_size, last_modified=last_modified,
        export_method=export_method, export_instructions=export_instructions,
        access_status="accessible", notes=notes,
    )


def _windows_drive_letters():
    """List filesystem drive letters on Windows (e.g. ['C:', 'D:'])."""
    drives = []
    if shutil.which("powershell"):
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip().rstrip("\\")
                    if re.match(r'^[A-Za-z]:$', line):
                        drives.append(line)
        except Exception:
            pass
    if not drives:
        import string
        for letter in string.ascii_uppercase:
            if Path(f"{letter}:\\").exists():
                drives.append(f"{letter}:")
    return drives


def _scan_windows_network_shares():
    """Detect mapped SMB drives via Get-SmbMapping (PowerShell), falling
    back to `net use` (cmd.exe) if PowerShell is unavailable or fails."""
    shares = []
    if shutil.which("powershell"):
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-SmbMapping | ForEach-Object { \"$($_.LocalPath)|$($_.RemotePath)\" }"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if "|" in line:
                        local, remote = line.split("|", 1)
                        if local:
                            shares.append((local, remote, "cifs"))
                if shares:
                    return shares
        except Exception:
            pass
    try:
        result = subprocess.run(["net", "use"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                m = re.match(r'^(OK|Disconnected)\s+(\w:)\s+(\\\\\S+)', line.strip())
                if m:
                    _status, drive, unc = m.groups()
                    shares.append((drive, unc, "cifs"))
    except Exception:
        pass
    return shares


def _scan_mount_output_shares(fs_types):
    """Parse `mount` command output (macOS/Linux) for network filesystem types."""
    shares = []
    try:
        result = subprocess.run(["mount"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                m = re.match(r'^(\S+)\s+on\s+(\S.*?)\s+\(([^)]+)\)', line)
                if not m:
                    continue
                device, mount_point, opts = m.groups()
                fstype = opts.split(",")[0].strip()
                if fstype in fs_types:
                    shares.append((mount_point, device, fstype))
    except Exception:
        pass
    return shares


LINUX_NETWORK_FS_TYPES = {"cifs", "nfs", "nfs4", "smbfs", "sshfs", "davfs"}
# Desktop-integration FUSE mounts (gvfs, portal, snap) are not remote data
# stores — only flag FUSE filesystems that are actually network clients.
LINUX_FUSE_NETWORK_PREFIXES = ("fuse.sshfs", "fuse.rclone", "fuse.google-drive-ocamlfuse", "fuse.davfs")


def _scan_linux_network_shares():
    """Parse /proc/mounts for cifs/nfs/sshfs/fuse network filesystem mounts."""
    shares = []
    seen = set()
    try:
        with open(PROC_MOUNTS_PATH, "r", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mount_point, fstype = parts[0], parts[1], parts[2]
                if fstype in LINUX_NETWORK_FS_TYPES or fstype.startswith(LINUX_FUSE_NETWORK_PREFIXES):
                    if mount_point in seen:
                        continue
                    seen.add(mount_point)
                    shares.append((mount_point, device, fstype))
    except OSError:
        pass
    return shares


def _scan_network_shares(max_depth=5, timeout=60):
    """Module D1 §4.1.5: mounted network shares across all OSes."""
    if IS_WINDOWS:
        raw_shares = _scan_windows_network_shares()
    elif IS_MAC:
        raw_shares = _scan_mount_output_shares(fs_types={"smbfs", "nfs", "afpfs"})
    else:
        raw_shares = _scan_linux_network_shares()

    locations = []
    for mount_point, server_path, fstype in raw_shares:
        print(f"[docs] Checking network share {mount_point} ({fstype})...")
        loc_type = "smb_share" if fstype in ("cifs", "smbfs", "smb") else "network_mount"
        name = f"{fstype.upper()} share at {mount_point}"
        location = server_path or str(mount_point)

        # A share already present in the mount table "exists" by definition —
        # unlike a plain candidate folder, a not_found/timeout result here
        # means "currently unreachable" (e.g. a disconnected mapped drive or
        # a dead sshfs host), not "nothing to report". Record it either way.
        access = _check_path_access(Path(mount_point))
        if access != "ok":
            locations.append(DataLocation(
                source="network_share", type=loc_type, name=name, location=location,
                document_count=None, export_method="network rsync",
                access_status="scan_timeout" if access == "timeout" else "access_denied",
                access_error=("Path check timed out (possible dead network mount)" if access == "timeout"
                              else "Share not accessible (disconnected or permission denied)"),
                notes=f"Filesystem type: {fstype}.",
            ))
            continue

        loc = _scan_folder_to_location(
            "network_share", loc_type, name, mount_point,
            export_method="network rsync", max_depth=max_depth, timeout=timeout,
            notes=f"Filesystem type: {fstype}. Server path: {server_path or 'unknown'}",
        )
        if loc:
            loc.location = location
            locations.append(loc)
    return locations


def scan_local_file_stores(max_depth=5, timeout=60):
    """Module D1: local document folders + mounted network shares."""
    locations = []
    folder_specs = []  # list of (name, path)

    if IS_WINDOWS:
        folder_specs.append(("Documents folder", HOME / "Documents"))
        folder_specs.append(("Desktop", HOME / "Desktop"))
        folder_specs.append(("Downloads folder", HOME / "Downloads"))
        onedrive = HOME / "OneDrive"
        if onedrive.exists():
            folder_specs.append(("OneDrive folder", onedrive))
        for drive in _windows_drive_letters():
            if drive.upper() == KIT_DRIVE:
                continue  # never scan the audit kit's own USB drive
            for sub in ("Documents", "Shared"):
                p = Path(f"{drive}\\{sub}")
                if p not in (HOME / sub,):
                    folder_specs.append((f"{drive}\\{sub}", p))
    elif IS_MAC:
        folder_specs.append(("Documents folder", HOME / "Documents"))
        folder_specs.append(("Desktop", HOME / "Desktop"))
        folder_specs.append(("Downloads folder", HOME / "Downloads"))
        folder_specs.append(("iCloud Mobile Documents", HOME / "Library/Mobile Documents"))
        if MACOS_VOLUMES_ROOT.exists():
            try:
                for vol in MACOS_VOLUMES_ROOT.iterdir():
                    if vol.is_dir():
                        folder_specs.append((f"Volume: {vol.name}", vol))
            except OSError:
                pass
    else:  # Linux
        folder_specs.append(("Documents folder", HOME / "Documents"))
        folder_specs.append(("Desktop", HOME / "Desktop"))
        folder_specs.append(("Downloads folder", HOME / "Downloads"))
        folder_specs.append(("shared folder", HOME / "shared"))
        for base in LINUX_MOUNT_ROOTS:
            if base.exists():
                try:
                    for vol in base.iterdir():
                        # lost+found is a filesystem journal artifact, not a data location
                        if vol.is_dir() and vol.name != "lost+found":
                            folder_specs.append((f"Mounted: {vol}", vol))
                except OSError:
                    pass

    for name, path in folder_specs:
        print(f"[docs] Scanning {name}...")
        loc = _scan_folder_to_location("local_file_store", "documents", name, path,
                                        export_method="USB copy", max_depth=max_depth, timeout=timeout)
        if loc:
            if loc.access_status == "accessible":
                print(f"[docs]   {loc.document_count:,} files found ({_human_size(loc.total_size_bytes)})")
            locations.append(loc)

    locations.extend(_scan_network_shares(max_depth=max_depth, timeout=timeout))
    return locations


# ---------------------------------------------------------------------------
# Module 7: Document Discovery — Cloud Sync Folders (D2)
# ---------------------------------------------------------------------------

CLOUD_SYNC_SERVICES = {
    "Google Drive": {
        "export_method": "Google Takeout",
        "export_instructions": "Log in at takeout.google.com, select Drive, create an export, and download the ZIP when ready.",
    },
    "OneDrive": {
        "export_method": "OneDrive download",
        "export_instructions": "Sign in at onedrive.microsoft.com > Settings > Backup > Download all files as ZIP.",
    },
    "Dropbox": {
        "export_method": "Dropbox download",
        "export_instructions": "Sign in at dropbox.com, select all files, Download as ZIP (or copy the local sync folder directly).",
    },
    "iCloud Drive": {
        "export_method": "iCloud download",
        "export_instructions": "Sign in at icloud.com > Drive, download files (or copy the local sync folder directly).",
    },
    "Box": {
        "export_method": "Box download",
        "export_instructions": "Sign in at app.box.com, select all files, Download as ZIP (or copy the local sync folder directly).",
    },
}


def _cloud_sync_candidates():
    """Return (service, name, path) candidate cloud sync folders for this OS."""
    candidates = []
    if IS_WINDOWS:
        candidates.append(("Google Drive", "Google Drive", HOME / "Google Drive"))
        candidates.append(("Google Drive", "Google Drive", HOME / "GoogleDrive"))
        candidates.append(("OneDrive", "OneDrive", HOME / "OneDrive"))
        for p in HOME.glob("OneDrive - *"):
            candidates.append(("OneDrive", f"OneDrive ({p.name})", p))
        candidates.append(("Dropbox", "Dropbox", HOME / "Dropbox"))
        for p in HOME.glob("Dropbox (*)"):
            candidates.append(("Dropbox", f"Dropbox ({p.name})", p))
        candidates.append(("Box", "Box Sync", HOME / "Box Sync"))
    elif IS_MAC:
        candidates.append(("Google Drive", "Google Drive", HOME / "Google Drive"))
        cloud_storage = HOME / "Library/CloudStorage"
        if cloud_storage.exists():
            for p in cloud_storage.glob("OneDrive*"):
                candidates.append(("OneDrive", f"OneDrive ({p.name})", p))
        candidates.append(("Dropbox", "Dropbox", HOME / "Dropbox"))
        for p in HOME.glob("Dropbox (*)"):
            candidates.append(("Dropbox", f"Dropbox ({p.name})", p))
        candidates.append(("iCloud Drive", "iCloud Drive",
                           HOME / "Library/Mobile Documents/com~apple~CloudDocs"))
        candidates.append(("Box", "Box Sync", HOME / "Box Sync"))
    else:  # Linux
        candidates.append(("Google Drive", "Google Drive", HOME / "Google Drive"))
        candidates.append(("OneDrive", "OneDrive", HOME / "OneDrive"))
        candidates.append(("Dropbox", "Dropbox", HOME / "Dropbox"))
        candidates.append(("Dropbox", "Dropbox", HOME / ".dropbox"))
    return candidates


def scan_cloud_sync_folders(max_depth=5, timeout=60):
    """Module D2: desktop cloud sync folders (Google Drive, OneDrive,
    Dropbox, iCloud, Box). Detection is by local folder presence only —
    no network calls are made."""
    locations = []
    seen_paths = set()

    for service, name, path in _cloud_sync_candidates():
        try:
            if not path.is_dir():
                continue
            real = path.resolve()
        except OSError:
            continue
        if real in seen_paths:
            continue
        seen_paths.add(real)

        print(f"[docs] Scanning {name}...")
        info = CLOUD_SYNC_SERVICES[service]
        try:
            has_files = next(path.iterdir(), None) is not None
        except OSError:
            has_files = False
        loc = _scan_folder_to_location(
            "cloud_sync", "cloud_sync_folder", name, path,
            export_method=info["export_method"], max_depth=max_depth, timeout=timeout,
            export_instructions=info["export_instructions"],
            notes="Synced locally." if has_files else "",
        )
        if loc:
            if loc.access_status == "accessible":
                print(f"[docs]   {loc.document_count:,} files found ({_human_size(loc.total_size_bytes)})")
            locations.append(loc)

    return locations


# ---------------------------------------------------------------------------
# Module 8: Document Discovery — Email Stores (D3)
# ---------------------------------------------------------------------------

EMAIL_EXPORT_INSTRUCTIONS = {
    "Outlook PST": "Copy the .pst/.ost file directly (safe even while Outlook is running — we only stat the file, never open it). For a guided export, use Outlook > File > Open & Export > Import/Export.",
    "Apple Mail": "Copy the ~/Library/Mail directory, or use Mail > Mailbox > Export Mailbox for a portable .mbox.",
    "Thunderbird": "Copy the profile's Mail/ (and ImapMail/) folders, or use an add-on such as ImportExportTools NG to export mbox/eml.",
    "Mbox": "Copy the .mbox file/directory directly — it is a portable, standard mail store format.",
}


def _email_file_location(label, loc_type, path):
    """Build a DataLocation for a single email store file (PST/OST). Only
    stat()s the file — never opens or reads it."""
    try:
        st = path.stat()
        size = st.st_size
        mtime = datetime.datetime.fromtimestamp(st.st_mtime).isoformat()
        access_status = "accessible"
        error = None
    except OSError as e:
        size = 0
        mtime = None
        access_status = "access_denied"
        error = str(e)
    return DataLocation(
        source="email_store", type=loc_type, name=label, location=str(path),
        document_count=1, total_size_bytes=size, last_modified=mtime,
        export_method="Copy .pst/.ost file",
        export_instructions=EMAIL_EXPORT_INSTRUCTIONS["Outlook PST"],
        access_status=access_status, access_error=error,
    )


def scan_email_stores(max_depth=5, timeout=60):
    """Module D3: identify email data stores. Never opens or parses email
    contents — files are stat'd for path, size, and last-modified only."""
    locations = []

    if IS_WINDOWS:
        for base in filter(None, [os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA")]):
            outlook_dir = Path(base) / "Microsoft/Outlook"
            if not outlook_dir.exists():
                continue
            for ext, label in ((".pst", "Outlook PST"), (".ost", "Outlook OST")):
                for f in outlook_dir.glob(f"*{ext}"):
                    print(f"[docs] Checking email stores... {label} found ({_human_size(f.stat().st_size)})")
                    locations.append(_email_file_location(label, "email_pst", f))

    elif IS_MAC:
        mail_dir = HOME / "Library/Mail"
        if mail_dir.exists():
            print("[docs] Checking email stores...")
            try:
                emlx_count = sum(1 for _ in mail_dir.rglob("*.emlx"))
                total_size = sum(f.stat().st_size for f in mail_dir.rglob("*") if f.is_file())
                locations.append(DataLocation(
                    source="email_store", type="email_apple_mail", name="Apple Mail",
                    location=str(mail_dir), document_count=emlx_count,
                    total_size_bytes=total_size, export_method="Copy Mail directory",
                    export_instructions=EMAIL_EXPORT_INSTRUCTIONS["Apple Mail"],
                    access_status="accessible", notes=f"{emlx_count} .emlx message files.",
                ))
            except PermissionError:
                locations.append(DataLocation(
                    source="email_store", type="email_apple_mail", name="Apple Mail",
                    location=str(mail_dir), document_count=None, access_status="access_denied",
                    access_error="Full Disk Access required to read ~/Library/Mail. Grant it in "
                                 "System Settings > Privacy & Security > Full Disk Access.",
                ))

        outlook_mac = HOME / "Library/Group Containers/UBF8T346G9.Office/Outlook"
        if outlook_mac.exists():
            try:
                msg_files = list(outlook_mac.rglob("*.olk15message"))
                total_size = sum(f.stat().st_size for f in msg_files)
                locations.append(DataLocation(
                    source="email_store", type="email_pst", name="Outlook (Mac)",
                    location=str(outlook_mac), document_count=len(msg_files),
                    total_size_bytes=total_size, export_method="Copy Outlook data directory",
                    export_instructions=EMAIL_EXPORT_INSTRUCTIONS["Outlook PST"],
                    access_status="accessible",
                ))
            except PermissionError:
                pass

    # Thunderbird — all OSes
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA")
        tb_base = Path(appdata) / "Thunderbird/Profiles" if appdata else None
    elif IS_MAC:
        tb_base = HOME / "Library/Thunderbird/Profiles"
    else:
        tb_base = HOME / ".thunderbird"

    if tb_base and tb_base.exists():
        try:
            profiles = [p for p in tb_base.iterdir() if p.is_dir()]
        except OSError:
            profiles = []
        for profile in profiles:
            mail_subdir = profile / "Mail"
            prefs = profile / "prefs.js"
            if not (prefs.exists() or mail_subdir.exists()):
                continue
            print(f"[docs] Checking email stores... Thunderbird profile ({profile.name})")
            loc = _scan_folder_to_location(
                "email_store", "email_mbox", f"Thunderbird ({profile.name})",
                mail_subdir if mail_subdir.exists() else profile,
                export_method="Copy profile Mail folder", max_depth=max_depth, timeout=timeout,
                export_instructions=EMAIL_EXPORT_INSTRUCTIONS["Thunderbird"],
            )
            if loc:
                locations.append(loc)

    # Generic mbox files in common locations
    seen_mbox = set()
    for root in (HOME / "Mail", HOME / "Documents", HOME):
        if not root.exists():
            continue
        try:
            candidates = list(root.glob("*.mbox"))
        except OSError:
            continue
        for f in candidates:
            if f in seen_mbox:
                continue
            seen_mbox.add(f)
            try:
                st = f.stat()
            except OSError:
                continue
            print(f"[docs] Checking email stores... Mbox found ({_human_size(st.st_size)})")
            locations.append(DataLocation(
                source="email_store", type="email_mbox", name=f"Mbox: {f.name}",
                location=str(f), document_count=None, total_size_bytes=st.st_size,
                last_modified=datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
                export_method="Copy mbox file",
                export_instructions=EMAIL_EXPORT_INSTRUCTIONS["Mbox"],
                access_status="accessible",
            ))

    return locations


# ---------------------------------------------------------------------------
# Module 9: Document Discovery — Practice Management Software (D4)
# ---------------------------------------------------------------------------

# LEAP's only bare-word pattern was replaced with two-word patterns in
# practice_software.json; this set exists to reject any future single-word
# detect pattern that is a common English word, per DOCUMENT-DISCOVERY-SPEC
# §4.4. Short, non-dictionary brand tokens (Clio, Xero, MyCase) are exempt.
_COMMON_ENGLISH_WORDS = {
    "leap", "box", "drive", "share", "cloud", "desktop", "grow", "works",
    "mail", "tax", "file", "note", "task", "time", "form", "plan", "view",
    "work", "law", "legal", "practice", "manage", "management", "account",
    "accounting", "office", "team", "teams", "sync", "backup", "export",
    "import", "print", "scan", "book", "books", "pay", "bill", "billing",
    "case", "cases", "client", "clients", "matter", "matters", "document",
    "documents", "data", "smart", "simple", "easy", "quick", "pro", "plus",
    "online", "digital", "connect", "central", "hub", "suite", "system",
    "systems", "solution", "solutions", "app", "apps", "web", "site",
    "server", "network", "secure", "safe", "vault", "store", "storage",
}

# Tools whose D2 cloud-sync equivalent already covers them — do not
# double-detect as D4 "practice management" noise (spec §4.4.2).
_D4_CLOUD_SYNC_OVERLAP_TOOLS = {"Microsoft 365", "Google Workspace"}


def _is_dictionary_word_pattern(pattern):
    """Reject single-word detect patterns that are common English words
    (e.g. bare 'LEAP') to avoid false-positive matches. Multi-word patterns
    and short non-dictionary brand tokens ('Clio', 'Xero') are allowed."""
    words = pattern.strip().split()
    if len(words) != 1:
        return False
    return words[0].lower() in _COMMON_ENGLISH_WORDS


def _match_practice_software(text, tools_map, detected, os_key=None):
    """Match a software inventory line against practice_software.json tools.

    Mirrors _match_software's word-boundary / dpkg-package-name matching,
    but reads os_specific.<os>.detect_patterns instead of a flat name key,
    and rejects dictionary-word patterns per DOCUMENT-DISCOVERY-SPEC §4.4.
    `os_key` defaults to the running OS but can be overridden (tests only).
    """
    if not text or not text.strip():
        return

    text_lower = text.lower().strip()

    dpkg = re.match(r'^(?:ii|hi|rc|un|iU|iF)\s+(\S+)', text_lower)
    if dpkg:
        haystacks = [dpkg.group(1).split(":", 1)[0]]
        dpkg_mode = True
    else:
        haystacks = [text_lower]
        dpkg_mode = False

    if os_key is None:
        os_key = "windows" if IS_WINDOWS else "macos" if IS_MAC else "linux"

    for tool_name, tool_info in tools_map.items():
        os_info = (tool_info.get("os_specific") or {}).get(os_key)
        if not os_info:
            continue

        matched = False
        for pattern in os_info.get("detect_patterns") or []:
            if _is_dictionary_word_pattern(pattern):
                continue
            pat_lower = pattern.lower()

            for hay in haystacks:
                if dpkg_mode:
                    if hay == pat_lower or hay.startswith(pat_lower + "-") or hay.startswith(pat_lower + "."):
                        matched = True
                        break
                    continue
                boundary_pattern = rf'(?<![a-z0-9]){re.escape(pat_lower)}(?![a-z0-9])'
                if re.search(boundary_pattern, hay):
                    matched = True
                    break
            if matched:
                break

        if matched:
            detected.add((tool_name, text))


def scan_practice_software(practice_db):
    """Module D4: detect installed practice management software.

    Reuses the software inventory gathering from
    scan_software_inventory_auto() (same OS-specific sources), but matches
    against practice_software.json via _match_practice_software() instead
    of ai_domains.json's software_names.
    """
    detections = []
    tools_map = practice_db.get("tools", {})
    detected = set()
    sources = get_software_inventory_paths()

    for method, source, output_type in sources:
        try:
            if method == "file":
                app_dir = Path(source)
                if app_dir.exists():
                    for item in app_dir.iterdir():
                        _match_practice_software(item.stem, tools_map, detected)
            elif method == "command":
                result = subprocess.run(
                    source, shell=isinstance(source, str),
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0 and result.stdout:
                    for line in result.stdout.splitlines():
                        if output_type == "dpkg":
                            line_clean = line.strip()
                        else:
                            line_clean = line.strip().strip('"').split(",")[-1].strip()
                        _match_practice_software(line_clean, tools_map, detected)
        except Exception as e:
            print(f"    warn: {output_type} scan failed: {e}")

    for tool_name, raw_line in sorted(detected):
        if tool_name in _D4_CLOUD_SYNC_OVERLAP_TOOLS:
            continue
        info = tools_map[tool_name]
        print(f"[docs] Checking practice software... {info['display_name']} detected")
        detections.append({
            "tool_name": info["display_name"],
            "detected_from": f"{tool_name} (detected from: '{raw_line}')",
            "install_path": None,
            "data_location": info.get("data_location"),
            "export_method": info.get("export_method"),
            "export_instructions": info.get("export_instructions"),
            "data_types": info.get("data_types", []),
            "has_api_export": info.get("has_api_export", False),
            "has_file_export": info.get("has_file_export", False),
            "vendor_url": info.get("vendor_url"),
            "notes": info.get("notes", ""),
        })

    return detections


# ---------------------------------------------------------------------------
# Module 10: Document Discovery — Deduplication Pass (D5)
# ---------------------------------------------------------------------------

def _dedup_overlaps(local_locations, cloud_locations):
    """Subtract cloud sync folder counts from any containing local file
    store, to avoid double-counting (e.g. OneDrive synced inside
    Documents). Mutates both lists in place and adds notes to each side.
    Returns the number of overlaps adjusted.
    """
    adjustments = 0
    for cloud in cloud_locations:
        try:
            cloud_path = Path(cloud.location).resolve()
        except OSError:
            continue

        for local in local_locations:
            try:
                local_path = Path(local.location).resolve()
            except OSError:
                continue
            if cloud_path == local_path or not cloud_path.is_relative_to(local_path):
                continue

            local.document_count = max(0, (local.document_count or 0) - (cloud.document_count or 0))
            for cat, count in cloud.document_categories.items():
                if cat in local.document_categories:
                    local.document_categories[cat] = max(0, local.document_categories[cat] - count)
            local.total_size_bytes = max(0, (local.total_size_bytes or 0) - (cloud.total_size_bytes or 0))
            local.notes = (local.notes + " " if local.notes else "") + (
                f"Overlaps with {cloud.name} sync folder "
                f"({cloud.document_count or 0:,} docs, {_human_size(cloud.total_size_bytes)} subtracted)."
            )
            cloud.notes = (cloud.notes + " " if cloud.notes else "") + (
                f"Located inside {local.name} — deduplicated from local count."
            )
            adjustments += 1
            break  # a cloud folder overlaps at most one containing local store

    return adjustments


def _build_document_discovery_report(all_locations, practice_detections,
                                      modules_run, modules_skipped, dedup_adjustments):
    """Assemble the document_discovery report.json object (spec §5.3)."""
    cloud_services = sorted({l.name for l in all_locations if l.source == "cloud_sync"})
    email_stores = sorted({l.name for l in all_locations if l.source == "email_store"})
    practice_names = sorted({d["tool_name"] for d in practice_detections})

    total_documents = sum(l.document_count or 0 for l in all_locations)
    total_size = sum(l.total_size_bytes or 0 for l in all_locations)

    if len(all_locations) > 5 or len(practice_names) > 2:
        complexity = "complex"
    elif len(all_locations) > 2 or practice_names:
        complexity = "moderate"
    else:
        complexity = "simple"

    summary = {
        "total_document_locations": len(all_locations),
        "total_documents": total_documents,
        "total_size_human": _human_size(total_size),
        "cloud_services_detected": cloud_services,
        "email_stores_detected": email_stores,
        "practice_software_detected": practice_names,
        "dedup_adjustments": dedup_adjustments,
        "export_complexity": complexity,
    }

    architecture_sketch = {
        "local": [f"{l.name} ({l.document_count or 0:,} docs, {_human_size(l.total_size_bytes)})"
                  for l in all_locations if l.source in ("local_file_store", "network_share")],
        "cloud": [f"{l.name} (synced locally)" for l in all_locations if l.source == "cloud_sync"],
        "email": [f"{l.name} at {l.location} ({_human_size(l.total_size_bytes)})"
                  for l in all_locations if l.source == "email_store"],
    }

    report = {
        "scan_date": datetime.datetime.now().isoformat(),
        "modules_run": modules_run,
        "modules_skipped": modules_skipped,
        "data_locations": [l.to_dict() for l in all_locations],
        "practice_software": practice_detections,
        "summary": summary,
        "architecture_sketch": architecture_sketch,
    }
    if not all_locations:
        report["note"] = "No local document stores found — client may be fully cloud-based."
    return report


# ---------------------------------------------------------------------------
# Main CLI — with --auto flag for cross-platform auto-detect
# ---------------------------------------------------------------------------

def main():
    # Legacy Windows cmd.exe (OEM codepage) can raise UnicodeEncodeError on
    # unencodable characters, especially once stdout is redirected/piped
    # (e.g. `run.bat > log.txt`), where Python can't use the console's
    # Unicode-safe write path. Replace rather than crash the whole scan.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass

    parser = argparse.ArgumentParser(
        description="elect-rix Shadow AI Discovery Scanner (SA-1) — Cross-Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Cross-Platform Auto-Detect Mode (recommended):
  python scanner.py --client "Client" --auto --output-dir ./reports

  On macOS: detects Chrome, Firefox, Safari, Edge, Brave, Arc, Vivaldi, Opera
  On Linux: detects Chrome, Chromium, Firefox, Brave, Edge, Vivaldi, Opera
  On Windows: detects Chrome, Firefox, Edge, Brave, Vivaldi, Opera
  Every browser profile is scanned (e.g. Edge work profiles).

  Also auto-scans installed software per OS:
  macOS: /Applications
  Linux: dpkg, rpm, flatpak, snap
  Windows: wmic / PowerShell registry

Manual Mode (specific files):
  python scanner.py --client "Client" --dns-log <path> --output-dir ./reports
  python scanner.py --client "Client" --browser-history <path> --output-dir ./reports
  python scanner.py --client "Client" --software-inventory <path> --output-dir ./reports

Interactive Interview:
  python scanner.py --client "Client" --interview --output-dir ./reports
        """
    )
    parser.add_argument("--client", required=True, help="Client name for the report")
    parser.add_argument("--auditor", default="elect-rix Auditor", help="Auditor name")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-detect browser history and software inventory for this OS")
    parser.add_argument("--dns-log", help="Path to DNS log file")
    parser.add_argument("--browser-history", help="Path to browser history file (manual)")
    parser.add_argument("--software-inventory", help="Path to software inventory file (manual)")
    parser.add_argument("--interview", action="store_true", help="Run interactive staff interview")
    parser.add_argument("--interview-data", help="Path to pre-recorded interview JSON")
    parser.add_argument("--output-dir", default="./reports", help="Output directory for reports")
    parser.add_argument("--domain-db", help="Path to custom AI domains JSON")
    parser.add_argument("--docs", action="store_true",
                        help="Run Document Discovery modules (local/cloud/email stores, practice software)")
    parser.add_argument("--practice-db", help="Path to custom practice_software.json (default: bundled)")
    parser.add_argument("--docs-depth", type=int, default=5,
                        help="Folder recursion depth for Document Discovery (default: 5, max: 10)")
    parser.add_argument("--docs-timeout", type=int, default=60,
                        help="Per-folder scan timeout in seconds for Document Discovery (default: 60)")
    parser.add_argument("--docs-total-timeout", type=int, default=300,
                        help="Total timeout for all Document Discovery modules in seconds (default: 300)")

    args = parser.parse_args()

    # Load domain database
    global DOMAINS_FILE, PRACTICE_SOFTWARE_FILE
    if args.domain_db:
        DOMAINS_FILE = Path(args.domain_db)
    domain_db = load_domain_db()
    if args.practice_db:
        PRACTICE_SOFTWARE_FILE = Path(args.practice_db)

    # Initialize finding store
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d")
    store = FindingStore(output_dir / "findings.db")
    reset_coverage()
    store.set_meta(client=args.client, auditor=args.auditor, scan_date=scan_date)

    # Capture machine info for audit trail
    machine_info = capture_machine_info()
    write_activity_log(output_dir, "SCAN_START",
                       f"client={args.client} auditor={args.auditor} "
                       f"hostname={machine_info['hostname']} user={machine_info['username']} "
                       f"os={machine_info['os_name']} {machine_info['os_release']}")
    machine_info_path = output_dir / "machine_info.json"
    with open(machine_info_path, "w", encoding="utf-8") as f:
        json.dump(machine_info, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"elect-rix Shadow AI Discovery Scanner (Cross-Platform)")
    print(f"{'=' * 60}")
    print(f"Client:   {args.client}")
    print(f"Auditor:  {args.auditor}")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Date:     {scan_date}")
    print(f"Output:   {output_dir}")
    print(f"{'=' * 60}\n")

    # Check for module-skip env vars (set by audit-kit.py for targeted scans)
    skip_browser = os.environ.get("AUDITKIT_SKIP_BROWSER") == "1"
    skip_software = os.environ.get("AUDITKIT_SKIP_SOFTWARE") == "1"
    run_docs = (args.docs or os.environ.get("AUDITKIT_DOCS") == "1") and os.environ.get("AUDITKIT_SKIP_DOCS") != "1"

    # Module 1: DNS scanning
    if args.dns_log:
        print(f"[DNS] Scanning {args.dns_log}...")
        dns_findings, dns_counts = scan_dns_log(args.dns_log, domain_db)
        for f in dns_findings:
            store.add(f)
        write_activity_log(output_dir, "MODULE_DNS", f"file={args.dns_log} findings={len(dns_findings)}")
        if dns_counts:
            print(f"  Found {len(dns_findings)} AI tool(s) in DNS logs:")
            for domain, count in dns_counts.most_common():
                info = domain_db["domains"].get(domain, {})
                print(f"    {info.get('tool', domain):30s} {count:5d} queries  [{info.get('risk_default', '?')}]")
        else:
            print("  No AI tool domains found in DNS logs.")
        print()

    # Module 2: Browser history — auto-detect or manual
    if args.auto and not skip_browser:
        print("[Browser] Auto-detecting browsers...")
        browser_findings, browser_counts, browsers_found = scan_browser_history_auto(domain_db)
        for f in browser_findings:
            store.add(f)
        write_activity_log(output_dir, "MODULE_BROWSER",
                           f"browsers={len(browsers_found)} findings={len(browser_findings)}")
        if browsers_found:
            print(f"  Detected {len(browsers_found)} browser(s): {', '.join(b[0] for b in browsers_found)}")
        if browser_counts:
            print(f"  Found {len(browser_findings)} AI tool(s) in browser history:")
            for domain, count in browser_counts.most_common():
                info = domain_db["domains"].get(domain, {})
                print(f"    {info.get('tool', domain):30s} {count:5d} visits   [{info.get('risk_default', '?')}]")
        else:
            print("  No AI tool visits found in browser history.")
        print()

    elif args.browser_history:
        print(f"[Browser] Scanning {args.browser_history}...")
        browser_findings, browser_counts = scan_browser_history(args.browser_history, domain_db)
        for f in browser_findings:
            store.add(f)
        if browser_counts:
            print(f"  Found {len(browser_findings)} AI tool(s) in browser history:")
            for domain, count in browser_counts.most_common():
                info = domain_db["domains"].get(domain, {})
                print(f"    {info.get('tool', domain):30s} {count:5d} visits   [{info.get('risk_default', '?')}]")
        else:
            print("  No AI tool visits found in browser history.")
        print()

    # Module 3: Software inventory — auto-detect or manual
    if args.auto and not skip_software:
        print("[Software] Auto-detecting installed software...")
        sw_findings, sw_detected = scan_software_inventory_auto(domain_db)
        for f in sw_findings:
            store.add(f)
        write_activity_log(output_dir, "MODULE_SOFTWARE", f"findings={len(sw_findings)}")
        if sw_detected:
            print(f"  Found {len(sw_findings)} AI tool(s) in software inventory:")
            for sw_name, raw_line in sorted(sw_detected):
                info = domain_db.get("software_names", {}).get(sw_name, {})
                print(f"    {sw_name:30s} [{info.get('risk_default', '?')}]")
        else:
            print("  No AI tools found in software inventory.")
        print()

    elif args.software_inventory:
        print(f"[Software] Scanning {args.software_inventory}...")
        sw_findings, sw_detected = scan_software_inventory(args.software_inventory, domain_db)
        for f in sw_findings:
            store.add(f)
        if sw_detected:
            print(f"  Found {len(sw_findings)} AI tool(s) in software inventory:")
            for sw_name, raw_line in sorted(sw_detected):
                info = domain_db.get("software_names", {}).get(sw_name, {})
                print(f"    {sw_name:30s} [{info.get('risk_default', '?')}]")
        else:
            print("  No AI tools found in software inventory.")
        print()

    # Module 4: Interview
    if args.interview:
        print("[Interview] Starting interactive interview mode...\n")
        interview_count = 0
        total_interview_findings = 0
        while True:
            live_findings, responses = interactive_interview()
            for f in live_findings:
                store.add(f)
            interview_count += 1
            total_interview_findings += len(live_findings)
            print(f"\n  Recorded {len(live_findings)} finding(s) from interview.")
            another = input("\n  Interview another staff member? (y/n): ").strip().lower()
            if another != "y":
                break
            print()
        write_activity_log(output_dir, "MODULE_INTERVIEW",
                           f"staff_interviewed={interview_count} findings={total_interview_findings}")
        print()

    elif args.interview_data:
        print(f"[Interview] Loading interview data from {args.interview_data}...")
        with open(args.interview_data, "r") as f:
            interview_data = json.load(f)
        interviews = interview_data if isinstance(interview_data, list) else [interview_data]
        for interview in interviews:
            for f in interview_findings(interview, domain_db):
                store.add(f)
        print(f"  Processed {len(interviews)} interview(s).")
        print()

    # Modules 6-10: Document Discovery (D1-D5) — local/cloud/email stores,
    # practice software, and deduplication. Runs on --docs (alone or with
    # --auto); skipped entirely otherwise so existing scanner behavior is
    # unchanged when --docs is absent.
    document_discovery_report = None
    if run_docs:
        docs_depth = min(max(args.docs_depth, 1), 10)
        docs_timeout = args.docs_timeout
        docs_total_timeout = args.docs_total_timeout
        docs_start = time.monotonic()

        def _docs_time_left():
            return docs_total_timeout - (time.monotonic() - docs_start)

        print("[docs] Starting Document Discovery...")
        modules_run, modules_skipped = [], []
        local_locations, cloud_locations, email_locations, practice_detections = [], [], [], []

        try:
            if _docs_time_left() > 0:
                local_locations = scan_local_file_stores(max_depth=docs_depth, timeout=docs_timeout)
                modules_run.append("local_file_stores")
            else:
                modules_skipped.append("local_file_stores")
        except Exception as e:
            print(f"  warn: local file store scan failed: {e}")
            modules_skipped.append("local_file_stores")

        try:
            if _docs_time_left() > 0:
                cloud_locations = scan_cloud_sync_folders(max_depth=docs_depth, timeout=docs_timeout)
                modules_run.append("cloud_sync")
            else:
                modules_skipped.append("cloud_sync")
        except Exception as e:
            print(f"  warn: cloud sync scan failed: {e}")
            modules_skipped.append("cloud_sync")

        try:
            if _docs_time_left() > 0:
                email_locations = scan_email_stores(max_depth=docs_depth, timeout=docs_timeout)
                modules_run.append("email_stores")
            else:
                modules_skipped.append("email_stores")
        except Exception as e:
            print(f"  warn: email store scan failed: {e}")
            modules_skipped.append("email_stores")

        try:
            if _docs_time_left() > 0:
                practice_db = load_practice_software_db()
                practice_detections = scan_practice_software(practice_db)
                modules_run.append("practice_software")
            else:
                modules_skipped.append("practice_software")
        except Exception as e:
            print(f"  warn: practice software scan failed: {e}")
            modules_skipped.append("practice_software")

        dedup_adjustments = 0
        try:
            dedup_adjustments = _dedup_overlaps(local_locations, cloud_locations)
            modules_run.append("deduplication")
            for cloud in cloud_locations:
                if "deduplicated" in (cloud.notes or ""):
                    print(f"[docs] Deduplication: {cloud.name} overlaps a local store — adjusted")
        except Exception as e:
            print(f"  warn: deduplication pass failed: {e}")

        for m in modules_run:
            if m != "deduplication":
                record_coverage("docs", m, "ok")
        for m in modules_skipped:
            record_coverage("docs", m, "failed", "module errored or the total time budget ran out")

        all_locations = local_locations + cloud_locations + email_locations
        total_docs = sum(l.document_count or 0 for l in all_locations)
        total_size = sum(l.total_size_bytes or 0 for l in all_locations)
        print(f"[docs] Document Discovery complete: {len(all_locations)} locations, "
              f"{total_docs:,} docs, {_human_size(total_size)}")
        print()

        write_activity_log(output_dir, "MODULE_DOCS",
                           f"locations={len(all_locations)} docs={total_docs} size={_human_size(total_size)} "
                           f"practice_software={len(practice_detections)} modules_run={','.join(modules_run)}")

        document_discovery_report = _build_document_discovery_report(
            all_locations, practice_detections, modules_run, modules_skipped, dedup_adjustments)

    # Require at least one scan module; empty findings is a valid clean result.
    modules_selected = any([
        args.auto, args.dns_log, args.browser_history, args.software_inventory,
        args.interview, args.interview_data, run_docs,
    ])
    if not modules_selected:
        print("No scan modules selected.")
        print("Use --auto for auto-detect, or --dns-log / --browser-history / --software-inventory / --interview / --docs")
        store.close()
        sys.exit(1)

    # "No findings" messaging only applies when AI-detection modules actually ran;
    # in docs-only mode the [docs] summary already reported results.
    ai_modules_ran = any([
        args.auto, args.dns_log, args.browser_history, args.software_inventory,
        args.interview, args.interview_data,
    ])
    if args.interview or args.interview_data:
        record_coverage("interview", "staff interviews", "ok",
                        "live interview" if args.interview else f"loaded from {Path(args.interview_data).name}")

    incomplete = [c for c in SCAN_COVERAGE if c["status"] in ("failed", "partial")]
    if not store.findings and ai_modules_ran:
        print("No AI tools detected across selected scan modules.")
        if incomplete:
            print("Generating zero-finding report pack — marked INCOMPLETE (see coverage below).\n")
        else:
            print("Generating clean (zero-finding) report pack...\n")

    # Generate reports
    print(f"{'=' * 60}")
    print("Generating reports...")
    result = generate_report(store.findings, args.client, args.auditor, output_dir, scan_date,
                             document_discovery=document_discovery_report)

    print(f"\n  HTML: {result['html']}")
    if result.get("pdf"):
        print(f"  PDF:  {result['pdf']}")
    else:
        print(f"  PDF:  (install WeasyPrint for PDF output)")
    print(f"  JSON: {result['json']}")
    print(f"  CSV:  {result['csv']}")
    if result.get("data_manifest"):
        print(f"  Data Manifest: {result['data_manifest']}")
    print(f"  DB:   {output_dir / 'findings.db'}")

    print(f"\n  Total findings:    {result['total_findings']}")
    print(f"  Unique AI tools:   {result['unique_tools']}")
    print(f"  Risk distribution: {result['risk_distribution']}")
    if incomplete:
        print(f"\n  !! SCAN INCOMPLETE — {len(incomplete)} source(s) not fully read:")
        for c in incomplete:
            print(f"     - [{c['module']}] {c['source']}: {c['status']} — {c['detail']}")
        print("     The report says so. Fix access and re-run before calling this machine clean.")
    print(f"\n{'=' * 60}")
    print("Scan complete. Reports saved to output directory.")
    print(f"{'=' * 60}\n")

    write_activity_log(output_dir, "SCAN_COMPLETE",
                       f"findings={result['total_findings']} tools={result['unique_tools']} "
                       f"risks={result['risk_distribution']}")

    store.close()


if __name__ == "__main__":
    main()