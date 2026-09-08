"""
Regression suite for the USB Audit Kit scanner (scanner.py).

Codifies the behavioral checks hand-verified in SPEC.md (2026-08-04 field
verification pass) so they can be re-run automatically before every client
visit instead of re-verified by hand.

Run with:
    /tmp/h2h/.venv/bin/python -m pytest tests/ -v
"""
import json
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pytest

KIT_DIR = Path(__file__).resolve().parent.parent
SCANNER_PY = KIT_DIR / "scanner.py"
DOMAINS_JSON = KIT_DIR / "ai_domains.json"
PRACTICE_SOFTWARE_JSON = KIT_DIR / "practice_software.json"

sys.path.insert(0, str(KIT_DIR))
import scanner  # noqa: E402  (must come after sys.path manipulation)


def run_cli(args, cwd):
    """Invoke scanner.py as a subprocess (as it runs in the field) and
    return the completed process."""
    return subprocess.run(
        [sys.executable, str(SCANNER_PY), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture(scope="module")
def domain_db():
    return scanner.load_domain_db()


# ---------------------------------------------------------------------------
# SPEC section A: Unit-style matcher asserts
# ---------------------------------------------------------------------------

class TestSoftwareMatcher:
    """SPEC.md 'A. Unit-style matcher asserts' — libwayland-cursor0 /
    libxcursor1 must not false-positive as Cursor; real Cursor installs
    (dpkg line and macOS .app) must be detected; Notion must match on its
    own name but not on a look-alike tool name."""

    @pytest.mark.parametrize("dpkg_line", [
        "ii  libwayland-cursor0:amd64          1.21.0-1       amd64        Wayland cursor library",
        "ii  libxcursor1:amd64                 1:1.2.0-2      amd64        X cursor library",
    ])
    def test_cursor_library_packages_do_not_match(self, domain_db, dpkg_line):
        software_map = domain_db["software_names"]
        detected = set()
        scanner._match_software(dpkg_line, software_map, detected)
        assert detected == set(), f"false-positive Cursor match from library package: {dpkg_line!r}"

    def test_cursor_dpkg_line_matches(self, domain_db):
        software_map = domain_db["software_names"]
        detected = set()
        scanner._match_software(
            "ii  cursor                            0.50.0         amd64        The AI Code Editor",
            software_map, detected,
        )
        assert len(detected) == 1
        (sw_name, _raw), = detected
        assert sw_name == "Cursor"

    def test_cursor_app_bundle_matches(self, domain_db):
        software_map = domain_db["software_names"]
        detected = set()
        scanner._match_software("Cursor.app", software_map, detected)
        assert len(detected) == 1
        (sw_name, _raw), = detected
        assert sw_name == "Cursor"

    def test_notion_matches_by_name(self, domain_db):
        software_map = domain_db["software_names"]
        detected = set()
        scanner._match_software("Notion 3.0", software_map, detected)
        assert len(detected) == 1
        (sw_name, _raw), = detected
        assert sw_name == "Notion"

    def test_notion_lookalike_does_not_match(self, domain_db):
        software_map = domain_db["software_names"]
        detected = set()
        scanner._match_software("my-notionally-named-tool", software_map, detected)
        assert detected == set(), "word-boundary match should reject 'notionally' as Notion"


# ---------------------------------------------------------------------------
# SPEC section B: Fixture inventory scan
# ---------------------------------------------------------------------------

FIXTURE_INVENTORY = """\
ii  libwayland-cursor0:amd64          1.21.0-1       amd64        Wayland cursor library
ii  libxcursor1:amd64                 1:1.2.0-2      amd64        X cursor library
ii  cursor                            0.50.0         amd64        The AI Code Editor
ii  vim                               2:9.0.1-1      amd64        Vi IMproved - enhanced vi editor
Notion Desktop
"""


class TestFixtureInventoryScan:
    """SPEC.md 'B. Fixture inventory scan' — mixed false-positive +
    real-tool dpkg fixture, run through the software-inventory scan path."""

    def test_matcher_finds_only_cursor_and_notion(self, domain_db, tmp_path):
        fixture = tmp_path / "dpkg_fixture.txt"
        fixture.write_text(FIXTURE_INVENTORY)

        findings, detected = scanner.scan_software_inventory(fixture, domain_db)

        tool_names = {sw_name for sw_name, _raw in detected}
        assert tool_names == {"Cursor", "Notion"}
        assert len(findings) == 2
        assert {f.tool for f in findings} == {"Cursor", "Notion"}

    def test_full_cli_pipeline_matches_spec_table(self, tmp_path):
        fixture = tmp_path / "dpkg_fixture.txt"
        fixture.write_text(FIXTURE_INVENTORY)
        output_dir = tmp_path / "out"

        result = run_cli(
            [
                "--client", "FixtureClient",
                "--auditor", "FixtureAuditor",
                "--software-inventory", str(fixture),
                "--output-dir", str(output_dir),
            ],
            cwd=tmp_path,
        )

        assert result.returncode == 0, result.stderr

        json_path = output_dir / "report.json"
        csv_path = output_dir / "inventory.csv"
        html_path = output_dir / "report.html"
        db_path = output_dir / "findings.db"
        assert json_path.exists()
        assert csv_path.exists()
        assert html_path.exists()
        assert db_path.exists()

        report = json.loads(json_path.read_text())
        json_findings = report["findings"]
        assert {f["tool"] for f in json_findings} == {"Cursor", "Notion"}

        conn = sqlite3.connect(str(db_path))
        try:
            row_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        finally:
            conn.close()
        assert row_count == len(json_findings), "findings.db row count must match JSON findings count"

        # software-only HIGH findings must not trip PIPEDA/PHIPA exposure
        assert report["summary"]["pipeda_exposure"] is False
        assert report["summary"]["total_findings"] == 2


# ---------------------------------------------------------------------------
# SPEC section C/D-derived: Zero-finding scan
# ---------------------------------------------------------------------------

CLEAN_INVENTORY = """\
ii  vim                               2:9.0.1-1      amd64        Vi IMproved - enhanced vi editor
ii  libwayland-cursor0:amd64          1.21.0-1       amd64        Wayland cursor library
ii  libxcursor1:amd64                 1:1.2.0-2      amd64        X cursor library
"""


class TestZeroFindingScan:
    """SPEC.md notes a clean (zero-finding) scan must still exit 0 and
    produce a full report pack rather than hard-failing. Reproduced
    deterministically via --software-inventory (the auditor's live host
    scan used --auto, which depends on what's installed on the day)."""

    def test_clean_scan_exits_zero_and_writes_report_pack(self, tmp_path):
        fixture = tmp_path / "clean_fixture.txt"
        fixture.write_text(CLEAN_INVENTORY)
        output_dir = tmp_path / "out"

        result = run_cli(
            [
                "--client", "CleanClient",
                "--auditor", "CleanAuditor",
                "--software-inventory", str(fixture),
                "--output-dir", str(output_dir),
            ],
            cwd=tmp_path,
        )

        assert result.returncode == 0, result.stderr

        json_path = output_dir / "report.json"
        assert json_path.exists()
        assert (output_dir / "inventory.csv").exists()
        assert (output_dir / "report.html").exists()
        assert (output_dir / "findings.db").exists()

        report = json.loads(json_path.read_text())
        assert report["summary"]["total_findings"] == 0
        assert report["summary"]["pipeda_exposure"] is False

        conn = sqlite3.connect(str(output_dir / "findings.db"))
        try:
            row_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        finally:
            conn.close()
        assert row_count == 0


# ---------------------------------------------------------------------------
# ai_domains.json integrity
# ---------------------------------------------------------------------------

class TestDomainDbIntegrity:
    """SPEC.md 'E. Domain twins' flagged a leading-space key bug
    (' Character.ai') caught by hand. Guard against key whitespace drift
    across both the domains and software_names tables."""

    def test_no_whitespace_padded_keys(self):
        with open(DOMAINS_JSON, "r") as f:
            db = json.load(f)

        for section in ("domains", "software_names"):
            for key in db[section]:
                assert key == key.strip(), f"whitespace-padded key in {section!r}: {key!r}"

    def test_domains_and_software_names_sections_present(self):
        with open(DOMAINS_JSON, "r") as f:
            db = json.load(f)
        assert db.get("domains"), "domains table is empty or missing"
        assert db.get("software_names"), "software_names table is empty or missing"


# ---------------------------------------------------------------------------
# 2026-08-09 field-run regressions
# ---------------------------------------------------------------------------

class TestDpkgCommaDescription:
    """Field run (2026-08-09): the dpkg line
    'ii  dmz-cursor-theme  0.4.5ubuntu1  all  Style neutral, scalable cursor theme'
    false-positived as Cursor [HIGH]. Root cause: the auto-scan path
    comma-split every command-output line (a CSV hack) and fed the
    description tail 'scalable cursor theme' to the matcher, bypassing the
    dpkg package-name parsing in _match_software."""

    DPKG_LINE = ("ii  dmz-cursor-theme  0.4.5ubuntu1  all  "
                 "Style neutral, scalable cursor theme")

    def test_full_dpkg_line_with_comma_description_does_not_match(self, domain_db):
        detected = set()
        scanner._match_software(self.DPKG_LINE, domain_db["software_names"], detected)
        assert detected == set(), "dpkg description text must never be matched"

    def test_auto_path_preserves_dpkg_lines(self, domain_db, monkeypatch):
        """End-to-end through scan_software_inventory_auto with mocked dpkg
        output: no Cursor finding from a cursor-THEME package, and a real
        'cursor' package IS still found (positive control)."""
        fake_dpkg = (
            self.DPKG_LINE + "\n"
            "ii  mint-cursor-themes  1.0.2  all  Linux Mint Cursor themes\n"
            "ii  vim  2:9.0.1-1  amd64  Vi IMproved, enhanced\n"
            "ii  cursor  0.50.0  amd64  The AI Code Editor\n"
        )

        class FakeResult:
            returncode = 0
            stdout = fake_dpkg

        monkeypatch.setattr(scanner, "get_software_inventory_paths",
                            lambda: [("command", "dpkg -l", "dpkg")])
        monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: FakeResult())

        findings, detected = scanner.scan_software_inventory_auto(domain_db)

        tool_names = {sw_name for sw_name, _raw in detected}
        assert tool_names == {"Cursor"}, f"expected only the real Cursor package, got: {tool_names}"
        assert len(findings) == 1
        assert findings[0].tool == "Cursor"


class TestFirefoxXdgProfilePath:
    """Field run (2026-08-09): Firefox was installed with 1,450 visited
    URLs, but the scanner reported no browser data. Root cause: Linux Firefox
    detection only checked ~/.mozilla/firefox; modern Firefox honors XDG and
    stores profiles at ~/.config/mozilla/firefox. Also, profile dirs are not
    always named '*.default*' (e.g. 'bmCbaQgY.Profile 1')."""

    def _fake_linux_home(self, monkeypatch, tmp_path):
        monkeypatch.setattr(scanner, "HOME", tmp_path)
        monkeypatch.setattr(scanner, "IS_MAC", False)
        monkeypatch.setattr(scanner, "IS_WINDOWS", False)
        monkeypatch.setattr(scanner, "IS_LINUX", True)
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        return tmp_path

    def test_xdg_config_mozilla_path_detected(self, monkeypatch, tmp_path):
        home = self._fake_linux_home(monkeypatch, tmp_path)
        profile = home / ".config/mozilla/firefox/abc123.default-release"
        profile.mkdir(parents=True)
        (profile / "places.sqlite").touch()

        paths = scanner.get_browser_paths()

        firefox_paths = [p for name, p, _t in paths if name == "Firefox"]
        assert firefox_paths == [profile / "places.sqlite"]

    def test_classic_path_still_detected(self, monkeypatch, tmp_path):
        home = self._fake_linux_home(monkeypatch, tmp_path)
        profile = home / ".mozilla/firefox/xyz.default"
        profile.mkdir(parents=True)
        (profile / "places.sqlite").touch()

        paths = scanner.get_browser_paths()

        firefox_paths = [p for name, p, _t in paths if name == "Firefox"]
        assert firefox_paths == [profile / "places.sqlite"]

    def test_non_default_profile_name_detected(self, monkeypatch, tmp_path):
        home = self._fake_linux_home(monkeypatch, tmp_path)
        profile = home / ".config/mozilla/firefox/bmCbaQgY.Profile 1"
        profile.mkdir(parents=True)
        (profile / "places.sqlite").touch()

        paths = scanner.get_browser_paths()

        firefox_paths = [p for name, p, _t in paths if name == "Firefox"]
        assert firefox_paths == [profile / "places.sqlite"]


# ---------------------------------------------------------------------------
# Windows hardening (2026-08-11): never run on real hardware, so path
# resolution and subprocess construction are covered with mocks instead.
# ---------------------------------------------------------------------------

class TestWindowsBrowserPaths:
    """Browser detection must key off %LOCALAPPDATA%/%APPDATA% (unaffected
    by OneDrive Known Folder Move, which only relocates Desktop/Documents),
    not a hardcoded home-relative path."""

    def _fake_windows_env(self, monkeypatch, tmp_path):
        monkeypatch.setattr(scanner, "IS_MAC", False)
        monkeypatch.setattr(scanner, "IS_LINUX", False)
        monkeypatch.setattr(scanner, "IS_WINDOWS", True)
        localappdata = tmp_path / "Local"
        appdata = tmp_path / "Roaming"
        monkeypatch.setenv("LOCALAPPDATA", str(localappdata))
        monkeypatch.setenv("APPDATA", str(appdata))
        return localappdata, appdata

    def test_chrome_edge_brave_detected_via_localappdata(self, monkeypatch, tmp_path):
        localappdata, _appdata = self._fake_windows_env(monkeypatch, tmp_path)
        chrome = localappdata / "Google/Chrome/User Data/Default/History"
        edge = localappdata / "Microsoft/Edge/User Data/Default/History"
        brave = localappdata / "BraveSoftware/Brave-Browser/User Data/Default/History"
        for p in (chrome, edge, brave):
            p.parent.mkdir(parents=True)
            p.touch()

        paths = scanner.get_browser_paths()

        names = {name for name, _p, _t in paths}
        assert names == {"Chrome", "Edge", "Brave"}
        assert all(t == "chrome" for _n, _p, t in paths)

    def test_firefox_detected_via_appdata_not_localappdata(self, monkeypatch, tmp_path):
        _localappdata, appdata = self._fake_windows_env(monkeypatch, tmp_path)
        profile = appdata / "Mozilla/Firefox/Profiles/abc123.default-release"
        profile.mkdir(parents=True)
        (profile / "places.sqlite").touch()

        paths = scanner.get_browser_paths()

        firefox = [(name, p, t) for name, p, t in paths if name == "Firefox"]
        assert firefox == [("Firefox", profile / "places.sqlite", "firefox")]

    def test_no_browsers_found_returns_empty_not_error(self, monkeypatch, tmp_path):
        self._fake_windows_env(monkeypatch, tmp_path)
        assert scanner.get_browser_paths() == []


class TestWindowsSoftwareInventorySources:
    """The PowerShell inventory command must be an argv list (no shell=True
    quoting layer) and must not rely on the invalid 'Unique' cmdlet."""

    def test_powershell_source_is_argv_list_not_shell_string(self, monkeypatch):
        monkeypatch.setattr(scanner, "IS_MAC", False)
        monkeypatch.setattr(scanner, "IS_LINUX", False)
        monkeypatch.setattr(scanner, "IS_WINDOWS", True)
        monkeypatch.setattr(scanner.shutil, "which",
                             lambda name: f"C:\\{name}.exe" if name == "powershell" else None)

        sources = scanner.get_software_inventory_paths()

        assert len(sources) == 1
        method, source, output_type = sources[0]
        assert method == "command"
        assert output_type == "powershell"
        assert isinstance(source, list), "must be an argv list, not a shell=True string"
        assert source[0] == "powershell"
        script = source[-1]
        assert "Unique" not in script.replace("-Unique", ""), \
            "'Unique' is not a real PowerShell cmdlet — must use Sort-Object -Unique"
        assert "-ExpandProperty DisplayName" in script

    def test_wmic_source_is_argv_list(self, monkeypatch):
        monkeypatch.setattr(scanner, "IS_MAC", False)
        monkeypatch.setattr(scanner, "IS_LINUX", False)
        monkeypatch.setattr(scanner, "IS_WINDOWS", True)
        monkeypatch.setattr(scanner.shutil, "which",
                             lambda name: f"C:\\{name}.exe" if name == "wmic" else None)

        sources = scanner.get_software_inventory_paths()

        assert sources == [("command", ["wmic", "product", "get", "name"], "wmic")]

    def test_list_command_runs_without_shell(self, monkeypatch, domain_db):
        """scan_software_inventory_auto must run list-type (Windows) sources
        with shell=False, and keep shell=True for Linux string sources."""
        captured = {}

        class FakeResult:
            returncode = 0
            stdout = "Notion\n"

        def fake_run(source, shell, **kwargs):
            captured["source"] = source
            captured["shell"] = shell
            return FakeResult()

        monkeypatch.setattr(scanner, "get_software_inventory_paths",
                             lambda: [("command", ["powershell", "-Command", "x"], "powershell")])
        monkeypatch.setattr(scanner.subprocess, "run", fake_run)

        findings, detected = scanner.scan_software_inventory_auto(domain_db)

        assert captured["shell"] is False
        assert isinstance(captured["source"], list)
        assert {sw for sw, _raw in detected} == {"Notion"}

    def test_string_command_still_runs_with_shell(self, monkeypatch, domain_db):
        """Linux behavior (dpkg -l as a plain string) must not regress."""
        captured = {}

        class FakeResult:
            returncode = 0
            stdout = "ii  vim  2:9.0.1-1  amd64  Vi IMproved\n"

        def fake_run(source, shell, **kwargs):
            captured["source"] = source
            captured["shell"] = shell
            return FakeResult()

        monkeypatch.setattr(scanner, "get_software_inventory_paths",
                             lambda: [("command", "dpkg -l", "dpkg")])
        monkeypatch.setattr(scanner.subprocess, "run", fake_run)

        scanner.scan_software_inventory_auto(domain_db)

        assert captured["shell"] is True
        assert captured["source"] == "dpkg -l"


# ---------------------------------------------------------------------------
# macOS hardening (2026-08-11): Safari Full Disk Access degrades gracefully.
# ---------------------------------------------------------------------------

class TestSafariFullDiskAccess:
    """Safari history is TCC-protected; without Full Disk Access, reading it
    raises PermissionError even though the path exists and is user-owned.
    The scanner must surface a clear, actionable message instead of a bare
    stack trace, and must not crash the rest of the scan."""

    def test_permission_error_raises_clear_full_disk_access_message(self, monkeypatch, tmp_path):
        fake_history = tmp_path / "History.db"
        fake_history.touch()

        def fake_copy2(src, dst):
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(scanner.shutil, "copy2", fake_copy2)

        with pytest.raises(PermissionError, match="Full Disk Access"):
            scanner._scan_safari_history(fake_history, {}, Counter(), defaultdict(list), "Safari")

    def test_denied_safari_does_not_abort_whole_browser_scan(self, monkeypatch, tmp_path, domain_db):
        """scan_browser_history_auto catches per-browser errors; a TCC denial
        on Safari must not prevent other browsers (or a clean zero-finding
        result) from being reported."""
        monkeypatch.setattr(scanner, "get_browser_paths",
                             lambda: [("Safari", tmp_path / "History.db", "safari")])
        monkeypatch.setattr(scanner, "_scan_safari_history",
                             lambda *a, **k: (_ for _ in ()).throw(
                                 PermissionError("macOS blocked Safari history access (Full Disk Access required)")))

        findings, visit_counts, browsers_found = scanner.scan_browser_history_auto(domain_db)

        assert findings == []
        assert browsers_found == [("Safari", tmp_path / "History.db", "safari")]


class TestChromeSchemaRegression:
    """Regression: Chrome/Edge/Brave `urls` table column is `last_visit_time`,
    NOT `visit_time` (that column only exists in Safari's history_visits).
    The wrong column name raised OperationalError which was silently swallowed,
    making the Chromium browser module return zero findings on real data.
    Found via Win11 VM field test, 2026-08-11."""

    def _make_chrome_db(self, tmp_path):
        db_path = tmp_path / "History"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
            "visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)"
        )
        # Chrome epoch: microseconds since 1601-01-01
        conn.execute(
            "INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden) "
            "VALUES ('https://chatgpt.com/', 'ChatGPT', 3, 0, 13400000000000000, 0)"
        )
        conn.execute(
            "INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden) "
            "VALUES ('https://ubuntu.com/', 'Ubuntu', 1, 0, 13400000000000001, 0)"
        )
        conn.commit()
        conn.close()
        return db_path

    def test_chrome_history_finds_ai_domains(self, tmp_path):
        import scanner
        db_path = self._make_chrome_db(tmp_path)
        domain_map = scanner.load_domain_db()["domains"]
        vc, vd = Counter(), defaultdict(list)
        scanner._scan_chrome_history(db_path, domain_map, vc, vd, "Chrome")
        assert "chatgpt.com" in vc, f"expected chatgpt.com finding, got {dict(vc)}"
        assert "ubuntu.com" not in vc

    def test_chrome_history_timestamp_converts(self, tmp_path):
        import scanner
        db_path = self._make_chrome_db(tmp_path)
        domain_map = scanner.load_domain_db()["domains"]
        vc, vd = Counter(), defaultdict(list)
        scanner._scan_chrome_history(db_path, domain_map, vc, vd, "Chrome")
        ts = vd["chatgpt.com"][0]
        assert ts.startswith("20"), f"timestamp not converted from Chrome epoch: {ts}"
