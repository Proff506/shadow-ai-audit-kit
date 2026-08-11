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
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
if getattr(sys, 'frozen', False):
    # Running as PyInstaller executable — resources are in _MEIPASS
    SCRIPT_DIR = Path(sys._MEIPASS)
DOMAINS_FILE = SCRIPT_DIR / "ai_domains.json"
REPORT_TEMPLATE = SCRIPT_DIR / "report_template.html"

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

def get_browser_paths():
    """Auto-detect browser history database paths for the current OS.

    Returns a list of (browser_name, path, db_type) tuples for browsers found.
    """
    paths = []

    if IS_MAC:
        # Chrome
        chrome = HOME / "Library/Application Support/Google/Chrome/Default/History"
        if chrome.exists():
            paths.append(("Chrome", chrome, "chrome"))

        # Chrome profiles (Profile 1, Profile 2, etc.)
        for p in (HOME / "Library/Application Support/Google/Chrome").glob("Profile */History"):
            paths.append((f"Chrome ({p.parent.name})", p, "chrome"))

        # Firefox
        firefox_base = HOME / "Library/Application Support/Firefox/Profiles"
        if firefox_base.exists():
            for profile in firefox_base.glob("*.default*"):
                places = profile / "places.sqlite"
                if places.exists():
                    paths.append(("Firefox", places, "firefox"))

        # Safari (history is in a binary plist, not SQLite — needs special handling)
        safari = HOME / "Library/Safari/History.db"
        if safari.exists():
            paths.append(("Safari", safari, "safari"))

        # Edge
        edge = HOME / "Library/Application Support/Microsoft Edge/Default/History"
        if edge.exists():
            paths.append(("Edge", edge, "chrome"))  # Edge uses same SQLite schema as Chrome

        # Brave
        brave = HOME / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History"
        if brave.exists():
            paths.append(("Brave", brave, "chrome"))

        # Arc
        arc = HOME / "Library/Application Support/Arc/User Data/Default/History"
        if arc.exists():
            paths.append(("Arc", arc, "chrome"))

    elif IS_LINUX:
        # Chrome
        chrome = HOME / ".config/google-chrome/Default/History"
        if chrome.exists():
            paths.append(("Chrome", chrome, "chrome"))

        for p in (HOME / ".config/google-chrome").glob("Profile */History"):
            paths.append((f"Chrome ({p.parent.name})", p, "chrome"))

        # Chromium
        chromium = HOME / ".config/chromium/Default/History"
        if chromium.exists():
            paths.append(("Chromium", chromium, "chrome"))

        # Chromium (snap) — profiles live under ~/snap/chromium/
        snap_chromium = HOME / "snap/chromium"
        if snap_chromium.exists():
            for history in snap_chromium.glob("common/.config/chromium/*/History"):
                paths.append((f"Chromium-snap ({history.parent.name})", history, "chrome"))
            for history in snap_chromium.glob("common/chromium/*/History"):
                paths.append((f"Chromium-snap ({history.parent.name})", history, "chrome"))
            # Also check Default directly
            snap_chromium_default = snap_chromium / "common/.config/chromium/Default/History"
            if snap_chromium_default.exists():
                paths.append(("Chromium-snap", snap_chromium_default, "chrome"))

        # Firefox — classic (~/.mozilla/firefox) AND XDG
        # (~/.config/mozilla/firefox) locations. Modern Firefox builds honor
        # XDG_CONFIG_HOME; checking only the classic path silently misses
        # the whole browser. Glob ANY subdir containing places.sqlite, not
        # just "*.default*" — profile dirs can be named arbitrarily
        # (e.g. "bmCbaQgY.Profile 1").
        xdg_config = Path(os.environ.get("XDG_CONFIG_HOME") or (HOME / ".config"))
        firefox_bases = [HOME / ".mozilla/firefox", xdg_config / "mozilla/firefox"]

        # Firefox (snap) — profiles live under ~/snap/firefox/common/.mozilla/firefox/
        snap_firefox = HOME / "snap/firefox"
        if snap_firefox.exists():
            snap_ff_base = snap_firefox / "common/.mozilla/firefox"
            if snap_ff_base.exists():
                firefox_bases.append(snap_ff_base)

        for firefox_base in firefox_bases:
            if firefox_base.exists():
                for places in firefox_base.glob("*/places.sqlite"):
                    label = "Firefox-snap" if "snap" in str(firefox_base) else "Firefox"
                    paths.append((label, places, "firefox"))

        # Brave
        brave = HOME / ".config/BraveSoftware/Brave-Browser/Default/History"
        if brave.exists():
            paths.append(("Brave", brave, "chrome"))

        # Edge
        edge = HOME / ".config/microsoft-edge/Default/History"
        if edge.exists():
            paths.append(("Edge", edge, "chrome"))

    elif IS_WINDOWS:
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")

        if localappdata:
            # Chrome
            chrome = Path(localappdata) / "Google/Chrome/User Data/Default/History"
            if chrome.exists():
                paths.append(("Chrome", chrome, "chrome"))

            for p in (Path(localappdata) / "Google/Chrome/User Data").glob("Profile */History"):
                paths.append((f"Chrome ({p.parent.name})", p, "chrome"))

            # Edge
            edge = Path(localappdata) / "Microsoft/Edge/User Data/Default/History"
            if edge.exists():
                paths.append(("Edge", edge, "chrome"))

            # Brave
            brave = Path(localappdata) / "BraveSoftware/Brave-Browser/User Data/Default/History"
            if brave.exists():
                paths.append(("Brave", brave, "chrome"))

        if appdata:
            # Firefox
            firefox_base = Path(appdata) / "Mozilla/Firefox/Profiles"
            if firefox_base.exists():
                for profile in firefox_base.glob("*.default*"):
                    places = profile / "places.sqlite"
                    if places.exists():
                        paths.append(("Firefox", places, "firefox"))

    return paths


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


def scan_dns_log(log_path, domain_db):
    """Scan a DNS log file for AI tool domain queries."""
    findings = []
    domain_counts = Counter()
    domain_timestamps = defaultdict(list)
    domain_map = domain_db["domains"]

    with open(log_path, "r", errors="replace") as f:
        for line in f:
            for pattern in DNS_LOG_PATTERNS:
                matches = pattern.findall(line)
                if not matches:
                    continue
                for match in matches:
                    domain = match[-1] if isinstance(match, tuple) else match
                    domain = domain.lower().strip(".")
                    for ai_domain, info in domain_map.items():
                        if info.get("scan") is False:
                            continue  # infrastructure-only entry (cloud storage, OS update, etc.)
                        if domain == ai_domain or domain.endswith("." + ai_domain):
                            domain_counts[ai_domain] += 1
                            ts_match = re.match(r'(\d{4}-\d{2}-\d{2}|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
                            if ts_match:
                                domain_timestamps[ai_domain].append(ts_match.group(1))
                            break

    for domain, count in domain_counts.items():
        info = domain_map[domain]
        findings.append(Finding(
            source="dns", tool=info["tool"], category=info["category"],
            risk=info["risk_default"],
            evidence=f"DNS queries to {domain} ({count} queries)",
            notes=f"First seen: {domain_timestamps[domain][0] if domain_timestamps[domain] else 'unknown'}. Last seen: {domain_timestamps[domain][-1] if domain_timestamps[domain] else 'unknown'}. {info.get('notes', '')}"
        ))

    return findings, domain_counts


# ---------------------------------------------------------------------------
# Module 2: Browser History Scanner (auto-detect)
# ---------------------------------------------------------------------------

def scan_browser_history_auto(domain_db, specific_path=None):
    """Auto-detect and scan all browser histories on this machine.

    If specific_path is provided, scan only that file.
    Otherwise, auto-detect all browsers for the current OS.
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
        if specific_path:
            print(f"  (Manual path provided: {specific_path})")
        return findings, visit_counts, browser_paths

    for browser_name, path, db_type in browser_paths:
        print(f"  Scanning {browser_name}: {path}")

        try:
            if db_type == "chrome":
                _scan_chrome_history(path, domain_map, visit_counts, visit_details, browser_name)
            elif db_type == "firefox":
                _scan_firefox_history(path, domain_map, visit_counts, visit_details, browser_name)
            elif db_type == "safari":
                _scan_safari_history(path, domain_map, visit_counts, visit_details, browser_name)
        except Exception as e:
            print(f"    warn: could not read {browser_name} history: {e}")

    # Generate findings
    for domain, count in visit_counts.items():
        info = domain_map[domain]
        findings.append(Finding(
            source="browser", tool=info["tool"], category=info["category"],
            risk=info["risk_default"],
            evidence=f"Browser visits to {domain} ({count} visits)",
            notes=f"First visit: {visit_details[domain][0] if visit_details[domain] else 'unknown'}. Last visit: {visit_details[domain][-1] if visit_details[domain] else 'unknown'}. {info.get('notes', '')}"
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


def _scan_chrome_history(path, domain_map, visit_counts, visit_details, browser_name):
    """Scan Chrome/Edge/Brave/Arc history (all use same SQLite schema)."""
    # Copy to temp to avoid locking issues
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    shutil.copy2(str(path), tmp_path)

    try:
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50000")
            for url, visit_time in cursor.fetchall():
                try:
                    if visit_time and visit_time > 10000000000000000:
                        timestamp = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=visit_time)).isoformat()
                    else:
                        timestamp = str(visit_time)
                except Exception:
                    timestamp = str(visit_time)
                _check_url_for_ai(url, timestamp, domain_map, visit_counts, visit_details)
        except sqlite3.OperationalError:
            pass
        conn.close()
    finally:
        os.unlink(tmp_path)


def _scan_firefox_history(path, domain_map, visit_counts, visit_details, browser_name):
    """Scan Firefox history (places.sqlite)."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    shutil.copy2(str(path), tmp_path)

    try:
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT url, datetime(last_visit_date/1000000, 'unixepoch') FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 50000")
            for url, timestamp in cursor.fetchall():
                _check_url_for_ai(url, timestamp or "", domain_map, visit_counts, visit_details)
        except sqlite3.OperationalError:
            pass
        conn.close()
    finally:
        os.unlink(tmp_path)


def _scan_safari_history(path, domain_map, visit_counts, visit_details, browser_name):
    """Scan Safari history (History.db — SQLite on modern macOS).

    Safari history is under TCC protection: even though the file is owned by
    the current user, macOS blocks reads from it unless the calling process
    (Terminal, or the Python interpreter itself) has been granted Full Disk
    Access. Denial surfaces as PermissionError, not FileNotFoundError — the
    path.exists() check upstream will have already succeeded.
    """
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(str(path), tmp_path)
    except PermissionError as e:
        os.unlink(tmp_path)
        raise PermissionError(
            "macOS blocked Safari history access (Full Disk Access required). "
            "Grant Full Disk Access to Terminal (or the Python interpreter) in "
            "System Settings > Privacy & Security > Full Disk Access, then re-run "
            "the scan. Continuing without Safari data."
        ) from e

    try:
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT url, datetime(visit_time + 978307200, 'unixepoch', 'localtime') FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id ORDER BY visit_time DESC LIMIT 50000")
            for url, timestamp in cursor.fetchall():
                _check_url_for_ai(url, timestamp or "", domain_map, visit_counts, visit_details)
        except sqlite3.OperationalError:
            pass
        conn.close()
    finally:
        os.unlink(tmp_path)


def scan_browser_history(history_path, domain_db):
    """Legacy single-file browser scan (kept for backward compat)."""
    return scan_browser_history_auto(domain_db, specific_path=history_path)[:2]


def _check_url_for_ai(url, timestamp, domain_map, visit_counts, visit_details):
    """Check a URL against the AI domain database."""
    if not url:
        return
    url_lower = url.lower()

    for ai_domain, info in domain_map.items():
        if info.get("scan") is False:
            continue  # infrastructure-only entry (cloud storage, OS update, etc.)
        if (url_lower.startswith(f"https://{ai_domain}") or
            url_lower.startswith(f"http://{ai_domain}") or
            f".{ai_domain}/" in url_lower or
            f".{ai_domain}" in url_lower):
            visit_counts[ai_domain] += 1
            visit_details[ai_domain].append(str(timestamp))
            break


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

            elif method == "command":
                # Linux sources are plain shell strings (dpkg -l, rpm -qa, ...).
                # Windows sources are argv lists — run without a shell so
                # there's no cmd.exe quoting/escaping to get wrong.
                result = subprocess.run(
                    source, shell=isinstance(source, str),
                    capture_output=True, text=True, timeout=30
                )
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

        except Exception as e:
            print(f"    warn: {output_type} scan failed: {e}")

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
    ("data_types", "Do you ever paste client information into these tools? (yes/no, describe): "),
    ("account_type", "Personal or work accounts? (personal/work/both): "),
    ("mobile", "Do you use AI apps on your phone for work tasks? (yes/no, which): "),
    ("extensions", "Any AI browser extensions installed? (list, or 'none'): "),
]


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

    findings = []
    tools_str = responses.get("tools", "").lower()
    if tools_str and tools_str != "none":
        domain_db = load_domain_db()
        software_map = domain_db.get("software_names", {})

        for tool_name in [t.strip() for t in tools_str.split(",")]:
            matched = False
            for sw_name, info in software_map.items():
                if sw_name.lower() in tool_name.lower():
                    data_types = responses.get("data_types", "").lower()
                    risk_override = "CRITICAL" if any(w in data_types for w in ["yes", "client", "patient", "financial"]) else None
                    findings.append(Finding(
                        source="interview", tool=sw_name, category=info["category"],
                        risk=risk_override or info["risk_default"],
                        evidence=f"Staff interview: {responses.get('name', 'anonymous')} ({responses.get('role', 'unknown role')}) uses {sw_name} for {responses.get('use_cases', 'unspecified')}",
                        notes=f"Data shared: {responses.get('data_types', 'unknown')}. Account type: {responses.get('account_type', 'unknown')}. Mobile: {responses.get('mobile', 'unknown')}. Extensions: {responses.get('extensions', 'none')}"
                    ))
                    matched = True
                    break

            if not matched and tool_name and tool_name != "none":
                data_types = responses.get("data_types", "").lower()
                risk = "CRITICAL" if any(w in data_types for w in ["yes", "client", "patient", "financial"]) else "MEDIUM"
                findings.append(Finding(
                    source="interview", tool=tool_name.title(), category="unknown", risk=risk,
                    evidence=f"Staff interview: {responses.get('name', 'anonymous')} ({responses.get('role', 'unknown role')}) uses {tool_name} for {responses.get('use_cases', 'unspecified')}",
                    notes=f"Data shared: {responses.get('data_types', 'unknown')}. Account type: {responses.get('account_type', 'unknown')}. Mobile: {responses.get('mobile', 'unknown')}. Extensions: {responses.get('extensions', 'none')}"
                ))

    return findings, responses


# ---------------------------------------------------------------------------
# Module 5: Report Generator (unchanged from original)
# ---------------------------------------------------------------------------

def generate_report(findings, client_name, auditor_name, output_dir, scan_date=None):
    """Generate HTML, JSON, and CSV reports from findings."""
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
        },
        "top_actions": top_actions,
        "findings": [f.to_dict() for f in sorted_findings],
    }

    json_path = output_dir / "report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_report, f, indent=2)

    csv_path = output_dir / "inventory.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Source", "Tool", "Category", "Risk Level", "Evidence", "Notes", "Timestamp"])
        for finding in sorted_findings:
            writer.writerow([finding.source, finding.tool, finding.category, finding.risk, finding.evidence, finding.notes, finding.timestamp])

    html = _generate_html_report(json_report, sorted_findings, client_name, auditor_name, scan_date, risk_counts, category_counts, source_counts, top_actions, pipeda_exposure, insurance_gap)
    html_path = output_dir / "report.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    pdf_path = None
    try:
        from weasyprint import HTML as WeasyHTML
        pdf_path = output_dir / "report.pdf"
        WeasyHTML(string=html).write_pdf(str(pdf_path))
    except ImportError:
        pass
    except Exception as e:
        print(f"  warn: PDF generation failed: {e}", file=sys.stderr)

    return {
        "json": str(json_path), "csv": str(csv_path), "html": str(html_path),
        "pdf": str(pdf_path) if pdf_path and pdf_path.exists() else None,
        "total_findings": total_findings, "unique_tools": total_tools,
        "risk_distribution": dict(risk_counts),
    }


def _generate_html_report(json_report, findings, client, auditor, scan_date, risk_counts, category_counts, source_counts, top_actions, pipeda_exposure, insurance_gap):
    """Generate the HTML report from the template file."""
    risk_badge = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}

    findings_rows = ""
    for f in findings:
        color = risk_badge.get(f.risk, "#6b7280")
        findings_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.risk}</span></td>
          <td><strong>{f.tool}</strong></td>
          <td>{f.category}</td>
          <td>{f.source}</td>
          <td>{f.evidence}</td>
          <td>{f.notes or '—'}</td>
        </tr>"""

    top_actions_html = ""
    for i, action in enumerate(top_actions, 1):
        top_actions_html += f"<li><strong>{i}.</strong> {action}</li>"
    if not top_actions_html:
        top_actions_html = "<li>No critical findings — no immediate action required.</li>"

    risk_summary_html = ""
    for level in RISK_LEVELS:
        count = risk_counts.get(level, 0)
        color = risk_badge.get(level, "#6b7280")
        risk_summary_html += f'<div class="risk-stat"><span class="badge" style="background:{color}">{level}</span><span class="count">{count}</span></div>'

    if pipeda_exposure:
        pipeda_alert = "<div class='alert critical'><strong>PIPEDA/PHIPA Exposure Detected.</strong> Client or sensitive data is being shared with consumer AI tools. Immediate action required.</div>"
    else:
        pipeda_alert = "<div class='alert ok'><strong>No immediate PIPEDA/PHIPA exposure detected.</strong> However, review all findings for potential risks.</div>"

    insurance_alert = ""
    if insurance_gap:
        insurance_alert = "<div class='alert warning'><strong>Insurance Coverage Gap Risk.</strong> AI-related data sharing may void cyber insurance coverage. Verify with your insurance provider.</div>"

    platform_str = json_report.get('platform', 'Unknown')

    template_path = SCRIPT_DIR / "report_template.html"
    if not template_path.exists():
        template_path = Path(__file__).parent / "report_template.html"

    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    return template.format(
        client=client,
        auditor=auditor,
        scan_date=scan_date,
        platform=platform_str,
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
    )


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

  On macOS: detects Chrome, Firefox, Safari, Edge, Brave, Arc
  On Linux: detects Chrome, Chromium, Firefox, Brave, Edge
  On Windows: detects Chrome, Firefox, Edge, Brave

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

    args = parser.parse_args()

    # Load domain database
    global DOMAINS_FILE
    if args.domain_db:
        DOMAINS_FILE = Path(args.domain_db)
    domain_db = load_domain_db()

    # Initialize finding store
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d")
    store = FindingStore(output_dir / "findings.db")
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
            interview_findings, responses = interactive_interview()
            for f in interview_findings:
                store.add(f)
            interview_count += 1
            total_interview_findings += len(interview_findings)
            print(f"\n  Recorded {len(interview_findings)} finding(s) from interview.")
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
            tools_str = interview.get("tools", "").lower()
            if tools_str and tools_str != "none":
                software_map = domain_db.get("software_names", {})
                for tool_name in [t.strip() for t in tools_str.split(",")]:
                    matched = False
                    for sw_name, info in software_map.items():
                        if sw_name.lower() in tool_name.lower():
                            data_types = interview.get("data_types", "").lower()
                            risk_override = "CRITICAL" if any(w in data_types for w in ["yes", "client", "patient", "financial"]) else None
                            store.add(Finding(
                                source="interview", tool=sw_name, category=info["category"],
                                risk=risk_override or info["risk_default"],
                                evidence=f"Staff interview: {interview.get('name', 'anonymous')} ({interview.get('role', 'unknown')}) uses {sw_name} for {interview.get('use_cases', 'unspecified')}",
                                notes=f"Data shared: {interview.get('data_types', 'unknown')}. Account type: {interview.get('account_type', 'unknown')}."
                            ))
                            matched = True
                            break
                    if not matched and tool_name and tool_name != "none":
                        store.add(Finding(
                            source="interview", tool=tool_name.title(), category="unknown", risk="MEDIUM",
                            evidence=f"Staff interview: {interview.get('name', 'anonymous')} ({interview.get('role', 'unknown')}) uses {tool_name}",
                            notes=f"Data shared: {interview.get('data_types', 'unknown')}. Account type: {interview.get('account_type', 'unknown')}."
                        ))
        print(f"  Processed {len(interviews)} interview(s).")
        print()

    # Require at least one scan module; empty findings is a valid clean result.
    modules_selected = any([
        args.auto, args.dns_log, args.browser_history, args.software_inventory,
        args.interview, args.interview_data,
    ])
    if not modules_selected:
        print("No scan modules selected.")
        print("Use --auto for auto-detect, or --dns-log / --browser-history / --software-inventory / --interview")
        store.close()
        sys.exit(1)

    if not store.findings:
        print("No AI tools detected across selected scan modules.")
        print("Generating clean (zero-finding) report pack...\n")

    # Generate reports
    print(f"{'=' * 60}")
    print("Generating reports...")
    result = generate_report(store.findings, args.client, args.auditor, output_dir, scan_date)

    print(f"\n  HTML: {result['html']}")
    if result.get("pdf"):
        print(f"  PDF:  {result['pdf']}")
    else:
        print(f"  PDF:  (install WeasyPrint for PDF output)")
    print(f"  JSON: {result['json']}")
    print(f"  CSV:  {result['csv']}")
    print(f"  DB:   {output_dir / 'findings.db'}")

    print(f"\n  Total findings:    {result['total_findings']}")
    print(f"  Unique AI tools:   {result['unique_tools']}")
    print(f"  Risk distribution: {result['risk_distribution']}")
    print(f"\n{'=' * 60}")
    print("Scan complete. Reports saved to output directory.")
    print(f"{'=' * 60}\n")

    write_activity_log(output_dir, "SCAN_COMPLETE",
                       f"findings={result['total_findings']} tools={result['unique_tools']} "
                       f"risks={result['risk_distribution']}")

    store.close()


if __name__ == "__main__":
    main()