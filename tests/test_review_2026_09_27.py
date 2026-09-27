"""
Regression tests for the v1.2 adversarial review.
Each test reproduces a bug that was confirmed on the pre-fix code.
"""
import datetime
import json
import os
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pytest

KIT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(KIT_DIR))
import scanner  # noqa: E402


@pytest.fixture
def domain_db():
    return scanner.load_domain_db()


def chrome_db(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, "
              "typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)")
    for url, dt, vc in rows:
        us = int((dt - datetime.datetime(1601, 1, 1)).total_seconds() * 1e6)
        c.execute("INSERT INTO urls (url,title,visit_count,typed_count,last_visit_time,hidden) VALUES (?,?,?,?,?,0)",
                  (url, "t", vc, 0, us))
    c.commit()
    c.close()
    return path


@pytest.fixture(autouse=True)
def _clean_coverage():
    scanner.reset_coverage()
    yield
    scanner.reset_coverage()


# ---- A1: unreadable browser must not produce a clean-looking report ----------

class TestCoverage:
    def test_failed_browser_marks_report_incomplete(self, monkeypatch, tmp_path, domain_db):
        monkeypatch.setattr(scanner, "get_browser_paths",
                            lambda: [("Chrome", tmp_path / "missing/History", "chrome")])
        findings, _c, _b = scanner.scan_browser_history_auto(domain_db)
        out = tmp_path / "out"
        scanner.generate_report(findings, "C", "A", out)
        rep = json.loads((out / "report.json").read_text())
        html = (out / "report.html").read_text()
        assert rep["summary"]["scan_complete"] is False
        assert rep["scan_coverage"][0]["status"] == "failed"
        assert "INCOMPLETE SCAN" in html
        assert "NOT SCANNED" in html
        assert "No immediate PIPEDA" not in html

    def test_ok_browser_is_complete(self, monkeypatch, tmp_path, domain_db):
        h = chrome_db(tmp_path / "History", [("https://ubuntu.com/", datetime.datetime(2026, 9, 1), 1)])
        monkeypatch.setattr(scanner, "get_browser_paths", lambda: [("Chrome", h, "chrome")])
        findings, _c, _b = scanner.scan_browser_history_auto(domain_db)
        out = tmp_path / "out"
        scanner.generate_report(findings, "C", "A", out)
        rep = json.loads((out / "report.json").read_text())
        assert rep["summary"]["scan_complete"] is True
        assert "No immediate PIPEDA/PHIPA exposure detected in the sources scanned" in (out / "report.html").read_text()

    @pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs non-root POSIX chmod")
    def test_cli_permission_denied_history_is_reported(self, tmp_path):
        home = tmp_path / "home"
        h = chrome_db(home / ".config/google-chrome/Default/History",
                      [("https://chatgpt.com/", datetime.datetime(2026, 9, 1), 5)])
        os.chmod(h, 0)
        try:
            env = dict(os.environ, HOME=str(home), AUDITKIT_SKIP_SOFTWARE="1")
            out = tmp_path / "out"
            r = subprocess.run([sys.executable, str(KIT_DIR / "scanner.py"), "--client", "T", "--auto",
                                "--output-dir", str(out)], env=env, capture_output=True, text=True, timeout=60)
        finally:
            os.chmod(h, 0o600)
        assert r.returncode == 0, r.stderr
        assert "SCAN INCOMPLETE" in r.stdout
        rep = json.loads((out / "report.json").read_text())
        assert rep["summary"]["scan_complete"] is False


# ---- A2: WAL-mode history (Firefox/Safari running) ---------------------------

def test_firefox_wal_visits_are_read(tmp_path, domain_db):
    p = tmp_path / "places.sqlite"
    w = sqlite3.connect(p)
    w.execute("PRAGMA journal_mode=WAL")
    w.execute("PRAGMA wal_autocheckpoint=0")
    w.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)")
    w.commit()
    w.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    w.execute("INSERT INTO moz_places(url,visit_count,last_visit_date) VALUES('https://claude.ai/new', 2, 1790000000000000)")
    w.commit()  # browser still holds the DB open: the row lives only in -wal
    assert (tmp_path / "places.sqlite-wal").stat().st_size > 0
    try:
        findings, counts, _ = scanner.scan_browser_history_auto(domain_db, specific_path=str(p))
    finally:
        w.close()
    assert counts.get("claude.ai") == 2


# ---- A4: every Chromium profile, every OS ------------------------------------

def test_linux_edge_and_brave_extra_profiles(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "HOME", tmp_path)
    monkeypatch.setattr(scanner, "IS_MAC", False)
    monkeypatch.setattr(scanner, "IS_WINDOWS", False)
    monkeypatch.setattr(scanner, "IS_LINUX", True)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    for rel in [".config/microsoft-edge/Profile 1/History", ".config/BraveSoftware/Brave-Browser/Profile 2/History"]:
        (tmp_path / rel).parent.mkdir(parents=True)
        (tmp_path / rel).touch()
    names = {n for n, _p, _t in scanner.get_browser_paths()}
    assert names == {"Edge (Profile 1)", "Brave (Profile 2)"}


def test_windows_edge_work_profile_and_any_firefox_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "IS_MAC", False)
    monkeypatch.setattr(scanner, "IS_LINUX", False)
    monkeypatch.setattr(scanner, "IS_WINDOWS", True)
    la, ra = tmp_path / "Local", tmp_path / "Roaming"
    monkeypatch.setenv("LOCALAPPDATA", str(la))
    monkeypatch.setenv("APPDATA", str(ra))
    for p in [la / "Microsoft/Edge/User Data/Profile 1/History",
              ra / "Mozilla/Firefox/Profiles/k3j2.work/places.sqlite"]:
        p.parent.mkdir(parents=True)
        p.touch()
    got = {(n, t) for n, _p, t in scanner.get_browser_paths()}
    assert got == {("Edge (Profile 1)", "chrome"), ("Firefox", "firefox")}


# ---- A5: audit-kit interview mode must show its questions --------------------

@pytest.mark.skipif(os.name != "posix", reason="pty test")
def test_audit_kit_interview_questions_visible(tmp_path):
    import pty
    import select
    import time
    home = tmp_path / "home"
    home.mkdir()
    conf = KIT_DIR / ".audit-kit.conf"
    conf_before = conf.read_bytes() if conf.exists() else None
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(HOME=str(home), AUDITKIT_SKIP_SOFTWARE="1", AUDITKIT_SKIP_BROWSER="1")
        os.execvp(sys.executable, [sys.executable, str(KIT_DIR / "audit-kit.py"), "--client", "T", "--auditor", "A",
                                   "--mode", "interview", "--no-color", "--output-dir", str(tmp_path / "out")])
    buf, t0 = b"", time.time()
    try:
        while time.time() - t0 < 20 and b"Staff member name" not in buf:
            if select.select([fd], [], [], 0.3)[0]:
                try:
                    buf += os.read(fd, 65536)
                except OSError:
                    break
    finally:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        if conf_before is None:
            conf.unlink(missing_ok=True)  # never leave the test auditor "A" on a kit
        else:
            conf.write_bytes(conf_before)
    assert b"Staff member name" in buf, buf[-400:]
    assert not (home / ".elect-rix").exists(), "audit-kit must not write config into the client's home"


# ---- A6/A7: dates and counts --------------------------------------------------

def test_first_last_visit_order_and_visit_count(tmp_path, domain_db):
    h = chrome_db(tmp_path / "History", [("https://chatgpt.com/c/1", datetime.datetime(2026, 1, 5), 200),
                                         ("https://chatgpt.com/c/2", datetime.datetime(2026, 9, 20), 50)])
    f, counts, _ = scanner.scan_browser_history_auto(domain_db, specific_path=str(h))
    assert counts["chatgpt.com"] == 250
    assert "(250 visits)" in f[0].evidence
    assert f[0].notes.startswith("First visit: 2026-01-05")
    assert "Last visit: 2026-09-20" in f[0].notes


# ---- A8: host-only matching ---------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fchat.openai.com%2Fshare%2Fabc&data=05",
    "https://www.google.com/url?q=https://www.perplexity.ai/&sa=U",
    "https://chatgpt.com.evil.example/login",
    "https://notclaude.ai.example.org/",
])
def test_non_ai_hosts_do_not_match(url, domain_db):
    vc, vd = Counter(), defaultdict(list)
    scanner._check_url_for_ai(url, "", domain_db["domains"], vc, vd)
    assert not vc, dict(vc)


@pytest.mark.parametrize("url,expected", [
    ("https://chatgpt.com/c/x", "chatgpt.com"),
    ("https://www.perplexity.ai/search", "perplexity.ai"),
    ("HTTPS://Claude.AI/new", "claude.ai"),
])
def test_ai_hosts_match(url, expected, domain_db):
    vc, vd = Counter(), defaultdict(list)
    scanner._check_url_for_ai(url, "", domain_db["domains"], vc, vd)
    assert expected in vc


# ---- A9: interview answers -----------------------------------------------------

@pytest.mark.parametrize("answer,expected", [
    ("no, never any client data", False), ("No", False), ("none", False), ("never", False),
    ("", False), ("unsure", False), ("not client info", False),
    ("yes", True), ("Yes - client names", True), ("sometimes patient notes", True),
    ("client emails to summarise", True),
])
def test_answer_shares_sensitive_data(answer, expected):
    assert scanner.answer_shares_sensitive_data(answer) is expected


def test_interview_data_denial_is_not_critical(tmp_path):
    j = tmp_path / "i.json"
    j.write_text(json.dumps([{"name": "R", "role": "clerk", "tools": "chatgpt", "use_cases": "emails",
                              "data_types": "no, never any client data", "account_type": "work"}]))
    out = tmp_path / "out"
    subprocess.run([sys.executable, str(KIT_DIR / "scanner.py"), "--client", "T", "--interview-data", str(j),
                    "--output-dir", str(out)], capture_output=True, text=True, timeout=60)
    rep = json.loads((out / "report.json").read_text())
    assert rep["findings"][0]["risk"] != "CRITICAL"
    assert rep["summary"]["pipeda_confirmed_by_interview"] is False


# ---- A3: PIPEDA wording matches evidence ---------------------------------------

def test_browser_visit_says_possible_not_confirmed(tmp_path):
    f = scanner.Finding("browser", "ChatGPT", "consumer_ai", "HIGH", "Browser visits to chatgpt.com (1 visits)", "")
    out = tmp_path / "out"
    scanner.generate_report([f], "C", "A", out)
    html = (out / "report.html").read_text()
    assert "Possible PIPEDA/PHIPA exposure" in html
    assert "is being shared" not in html


def test_interview_critical_says_confirmed(tmp_path):
    f = scanner.Finding("interview", "ChatGPT", "consumer_ai", "CRITICAL", "Staff interview: R uses ChatGPT", "")
    out = tmp_path / "out"
    scanner.generate_report([f], "C", "A", out)
    assert "confirmed by staff interview" in (out / "report.html").read_text()


# ---- A10: HTML and CSV escaping ---------------------------------------------

def test_html_and_csv_are_escaped(tmp_path):
    f = scanner.Finding("interview", "ChatGPT", "consumer_ai", "HIGH",
                        "Staff interview: <img src=x onerror=alert(1)> uses ChatGPT", "=HYPERLINK(\"http://x\")")
    out = tmp_path / "out"
    scanner.generate_report([f], "Smith & <b>Jones</b>", "A", out)
    html = (out / "report.html").read_text()
    assert "<img src=x" not in html and "&lt;img src=x" in html
    assert "<b>Jones</b>" not in html and "Smith &amp; &lt;b&gt;Jones&lt;/b&gt;" in html
    csv_text = (out / "inventory.csv").read_text()
    assert "'=HYPERLINK" in csv_text


# ---- DNS lines counted once ---------------------------------------

def test_dns_line_counted_once(tmp_path, domain_db):
    log = tmp_path / "dns.log"
    log.write_text("2026-08-05 10:00:00 query[A] chatgpt.com from 192.168.1.1\n"
                   "2026-08-06 11:00:00 query[A] api.openai.com from 192.168.1.1\n")
    findings, counts = scanner.scan_dns_log(str(log), domain_db)
    assert counts["chatgpt.com"] == 1
    assert sum(counts.values()) == 2
