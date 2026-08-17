#!/usr/bin/env python3
# NTLM-Analyzer - find out who still uses NTLM in your Active Directory.
# Copyright (C) 2026  Nobrac / Carbon / NoPCAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
NTLM-Analyzer - central collection point + web dashboard for NTLM usage.

Die Windows-Agents (ntlm-agent.exe) pushen ihre Events per HTTP POST /ingest
as JSON. They are stored in a SQLite database; the dashboard at / shows them
in Echtzeit (auto-refresh).

Python standard library only - no dependencies, no pip required.

Start:
    python3 ntlm-collector.py --port 8080 --key GEHEIM123

Aufruf vom Agent:
    POST http://<server>:8080/ingest
    Header: X-Api-Key: GEHEIM123
    Body:   {"source":"DC01","events":[ {...}, ... ]}
"""
import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB_LOCK = threading.Lock()

MAX_BODY = 10 * 1024 * 1024          # 10 MB cap for POST bodies (DoS protection)

# ---- Login brute-force throttle (per source IP) -----------------------------
LOGIN_FAILS = {}                      # ip -> [failed_attempts, locked_until_epoch]
LOGIN_FAILS_LOCK = threading.Lock()
LOGIN_MAX_FAILS = 10                  # after this many failed attempts ...
LOGIN_LOCK_SECS = 300                 # ... lock this IP for 5 minutes

# ---- Auth / sessions (browser pages / and /api/data only) ------------------
SESSION_COOKIE = "ntlm_session"
SESSION_TTL = 12 * 60 * 60          # 12 Stunden
SESSIONS_LOCK = threading.Lock()


def utc_now():
    """Wall-clock UTC without tzinfo.

    Windows writes SystemTime in the event XML as UTC, and that is what the
    agent stores - so every comparison against event_time has to happen in UTC,
    regardless of which timezone the collector host runs in.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

def hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256. Gibt (salt, derived_key) zurueck."""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt, dk

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT,
    record_id     INTEGER,
    log           TEXT,
    event_id      INTEGER,
    kind          TEXT,            -- 'auth' (4624) | 'outgoing' (8001/8002) | 'kerberos' (4769)
    event_time    TEXT,
    user          TEXT,
    domain        TEXT,
    ntlm_version  TEXT,            -- NTLMv1 | NTLMv2 (kind=auth)
    process       TEXT,            -- exe (kind=outgoing)
    target_server TEXT,            -- SPN/service (kind=kerberos) or target server
    workstation   TEXT,
    ip            TEXT,
    logon_type    TEXT,
    enc_type      TEXT,            -- Kerberos-Verschluesselung, z. B. AES256 / RC4
    auth_method   TEXT,            -- 'Direct' (App nutzt NTLM) | 'Fallback' (Kerberos scheiterte)
    received_at   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_dedup ON events(source, log, record_id);
CREATE INDEX IF NOT EXISTS ix_time ON events(event_time);
CREATE INDEX IF NOT EXISTS ix_kind ON events(kind);

CREATE TABLE IF NOT EXISTS agents (
    source          TEXT PRIMARY KEY,
    is_dc           INTEGER,
    agent_version   TEXT,
    outgoing_audit  TEXT,          -- aus/audit/deny/unknown
    incoming_audit  TEXT,
    domain_audit    TEXT,          -- nur DC
    lm_level        TEXT,          -- LmCompatibilityLevel: welche NTLM-Versionen erlaubt sind
    block_v1sso     TEXT,          -- BlockNtlmv1SSO: audit/enforce/unset
    cred_guard      TEXT,          -- Credential Guard: on/off/unknown (aus der Registry)
    ntlm_log_kb     TEXT,          -- Maximalgröße des NTLM/Operational-Logs in KB
    os_version      TEXT,          -- Produktname + Build der meldenden Maschine
    restrict_out    TEXT,          -- Deny-Richtlinien: allow/deny-accounts/deny-all
    restrict_in     TEXT,
    restrict_dom    TEXT,
    exc_client      TEXT,          -- bereits konfigurierte GPO-Ausnahmelisten
    exc_dc          TEXT,
    domain_level    TEXT,          -- msDS-Behavior-Version der Domaene (roh)
    forest_level    TEXT,          -- msDS-Behavior-Version der Gesamtstruktur
    last_seen       TEXT
);
"""

# Kerberos-Fehlercodes aus fehlgeschlagenen 4769-Anfragen: auf Systemen ohne
# die 40xx-Ereignisse (2016/2019/2022) die einzige Fruehwarnung fuer die
# Ursachen hinter NTLM-Fallback. Kategorie -> dieselben Abhilfe-Texte wie beim
# Why-panel; unknown codes pass through as "unclear" with the raw code.
KRB_FAIL = {
    "0x6":  ("Kerberos: client account unknown", "unklar"),
    "0x7":  ("Kerberos: SPN not found (service principal unknown)", "spn"),
    "0xe":  ("Kerberos: encryption type not supported", "etype"),
    "0x12": ("Kerberos: account disabled, expired or locked out", "acct"),
    "0x1b": ("Kerberos: principal not allowed to delegate", "unklar"),
    "0x25": ("Kerberos: clock skew too great", "clock"),
}

# Usage-IDs des Client-Logs laut KB5064479. Jede Ursache hat eine eigene
# Abhilfe - deshalb wird nach ihr gruppiert statt nur nach Programm.
REASON_IDS = {
    "0":  ("Unknown reason", "unklar"),
    "1":  ("Application called NTLM directly", "app"),
    "2":  ("Local account logon", "local"),
    "4":  ("Cloud account logon", "cloud"),
    "5":  ("Target name was missing or empty", "spn"),
    "6":  ("Target name could not be resolved by Kerberos", "spn"),
    "7":  ("Target name contains an IP address", "ip"),
    "8":  ("Target name is duplicated in Active Directory", "spn"),
    "9":  ("No line of sight to a domain controller", "dc"),
    "10": ("NTLM called over loopback", "loop"),
    "11": ("NTLM called with a null session", "null"),
}


def normalize_process(p):
    """Vereinheitlicht Prozessnamen fuers Gruppieren: verschiedene Event-Quellen
    liefern denselben Prozess mal mit, mal ohne Endung ("lsass" aus 8001,
    "lsass.exe" aus 4020) - das ergab doppelte Zeilen in der Programmliste.
    Konservativ: Klammer-Labels ("(Kernel: SMB/HTTP.sys)", "(PID 4)"), Werte
    mit Punkt (haben schon eine Endung) und Platzhalter bleiben unangetastet."""
    if not p:
        return p
    v = p.strip()
    if not v or v == "-" or v.startswith("(") or "." in v:
        return p
    # Pseudo-Namen sind Konten, keine Programme ("SYSTEM" aus 8002-Loopback);
    # echte Prozessnamen ohne Endung enthalten auch nie Leerzeichen.
    if " " in v or v.lower() in ("system", "anonymous logon"):
        return p
    return v + ".exe"


FIELDS = ("record_id", "log", "event_id", "kind", "event_time", "user",
          "domain", "ntlm_version", "process", "target_server",
          "workstation", "ip", "logon_type", "enc_type", "auth_method",
          "reason", "reason_id", "mic", "epa", "server_os", "failure_code",
          "process_path")


def init_db(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript(SCHEMA)
    # Migration: fehlende Spalten in bestehenden DBs nachziehen
    have = {r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
    # agents-Tabelle nachziehen (aeltere Installationen kennen lm_level nicht)
    have_a = {r[1] for r in conn.execute("PRAGMA table_info(agents)")}
    for col in ("lm_level", "block_v1sso", "cred_guard", "ntlm_log_kb",
                "os_version", "restrict_out", "restrict_in", "restrict_dom",
                "exc_client", "exc_dc", "domain_level", "forest_level"):
        if have_a and col not in have_a:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} TEXT")
    # Bestandsdaten: Prozessnamen ohne Endung angleichen (einmalig wirksam,
    # danach findet das WHERE nichts mehr). Dieselben Regeln wie beim Ingest.
    conn.execute(
        "UPDATE events SET process = process || '.exe' "
        "WHERE process IS NOT NULL AND TRIM(process) != '' AND process != '-' "
        "AND process NOT LIKE '(%' AND process NOT LIKE '%.%' "
        "AND process NOT LIKE '% %' AND LOWER(process) != 'system'")
    # Rueckbau: eine fruehere Version dieser Migration hat den Pseudo-Namen
    # SYSTEM faelschlich zu SYSTEM.exe gemacht - es gibt keinen solchen Prozess.
    conn.execute("UPDATE events SET process = substr(process, 1, length(process)-4) "
                 "WHERE LOWER(process) = 'system.exe'")
    for col in ("enc_type", "auth_method", "reason", "reason_id", "mic", "epa",
                "server_os", "failure_code", "process_path"):
        if col not in have:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
    # Indexes for the dashboard queries (time-range filter, aggregates).
    # IF NOT EXISTS -> also runs cleanly against existing databases at startup.
    conn.executescript("""
    CREATE INDEX IF NOT EXISTS idx_ev_time   ON events(event_time);
    CREATE INDEX IF NOT EXISTS idx_ev_kind   ON events(kind, event_time);
    CREATE INDEX IF NOT EXISTS idx_ev_ver    ON events(ntlm_version, event_time);
    CREATE INDEX IF NOT EXISTS idx_ev_eid    ON events(event_id, event_time);
    CREATE INDEX IF NOT EXISTS idx_ev_source ON events(source);
    -- Work status for blocker/domain entries (open = no row)
    CREATE TABLE IF NOT EXISTS item_status (
        key        TEXT PRIMARY KEY,   -- 'proc|<prozess>|<ziel>' bzw. 'dom|<quelle>|<ziel>'
        status     TEXT NOT NULL,      -- 'arbeit' | 'erledigt'
        updated_at TEXT NOT NULL
    );
    """)
    conn.commit()
    return conn


class Handler(BaseHTTPRequestHandler):
    server_version = "NtlmCollector/1.0"
    sys_version = ""   # keep the Python version out of every response header

    # ---- Helpers ----------------------------------------------------------
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _security_headers(self):
        """Defence in depth. Nothing here is currently exploitable - there are no
        third-party contents and every value is escaped - but these are free."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        # The dashboard is one self-contained file: inline script and style, no
        # external resources at all. Everything else is denied, so an injected
        # tag could neither load nor exfiltrate anything.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; "
            "script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'")

    def log_message(self, fmt, *args):
        pass  # ruhig halten; bei Bedarf entkommentieren

    # ---- Auth / Sessions --------------------------------------------------
    def _cookie_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = SimpleCookie(raw)
        except Exception:
            return None
        m = jar.get(SESSION_COOKIE)
        return m.value if m else None

    def _valid_session(self):
        tok = self._cookie_token()
        if not tok:
            return False
        now = time.time()
        with SESSIONS_LOCK:
            exp = self.server.sessions.get(tok)
            if exp and exp > now:
                return True
            self.server.sessions.pop(tok, None)
        return False

    def _login_required(self):
        # Only enforce login when a password is configured at all.
        return bool(self.server.pw_hash) and not self._valid_session()

    def _new_session(self):
        tok = secrets.token_urlsafe(32)
        now = time.time()
        with SESSIONS_LOCK:
            for k in [k for k, v in self.server.sessions.items() if v <= now]:
                del self.server.sessions[k]
            self.server.sessions[tok] = now + SESSION_TTL
        return tok

    def _end_session(self):
        tok = self._cookie_token()
        if tok:
            with SESSIONS_LOCK:
                self.server.sessions.pop(tok, None)

    def _cookie_header(self, value, max_age):
        parts = [f"{SESSION_COOKIE}={value}", "Path=/", f"Max-Age={max_age}",
                 "HttpOnly", "SameSite=Lax"]
        if self.server.cookie_secure:
            parts.append("Secure")
        return "; ".join(parts)

    def _redirect(self, location, set_cookie=None, clear_cookie=False):
        self.send_response(302)
        self.send_header("Location", location)
        if set_cookie is not None:
            self.send_header("Set-Cookie", self._cookie_header(set_cookie, SESSION_TTL))
        if clear_cookie:
            self.send_header("Set-Cookie", self._cookie_header("", 0))
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()

    def _handle_login(self):
        if not self.server.pw_hash:        # Login deaktiviert -> einfach durchwinken
            self._redirect("/")
            return
        # Brute-force throttle per source IP: after LOGIN_MAX_FAILS failed
        # attempts the IP is locked for LOGIN_LOCK_SECS (regardless of concurrency).
        ip = self.client_address[0]
        now = time.time()
        with LOGIN_FAILS_LOCK:
            fails, locked_until = LOGIN_FAILS.get(ip, [0, 0.0])
            if locked_until > now:
                self._redirect("/login?err=2")
                return
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length < 0 or length > 64 * 1024:   # the login form is tiny
                raise ValueError("bad length")
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        except Exception:
            form = {}
        pw = (form.get("password") or [""])[0]
        salt, want = self.server.pw_hash
        _, got = hash_password(pw, salt)
        if hmac.compare_digest(got, want):
            with LOGIN_FAILS_LOCK:
                LOGIN_FAILS.pop(ip, None)          # success resets the counter
                # Expired lockouts of other IPs are dropped here too, so the map
                # cannot grow without bound from many distinct source addresses.
                for k in [k for k, v in LOGIN_FAILS.items() if v[1] and v[1] <= now]:
                    del LOGIN_FAILS[k]
            self._redirect("/", set_cookie=self._new_session())
        else:
            with LOGIN_FAILS_LOCK:
                fails, locked_until = LOGIN_FAILS.get(ip, [0, 0.0])
                if locked_until <= now:            # bestehende Sperre nie ueberschreiben
                    fails += 1
                    if fails >= LOGIN_MAX_FAILS:
                        LOGIN_FAILS[ip] = [0, now + LOGIN_LOCK_SECS]
                    else:
                        LOGIN_FAILS[ip] = [fails, 0.0]
            time.sleep(1.0)                # leichte Bremse gegen Erraten
            self._redirect("/login?err=1")

    # ---- Routing ----------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/login":
            if not self.server.pw_hash or self._valid_session():
                self._redirect("/")
            else:
                self._send(200, LOGIN_HTML, "text/html; charset=utf-8")
        elif u.path == "/logout":
            self._end_session()
            self._redirect("/login", clear_cookie=True)
        elif u.path == "/healthz":
            self._send(200, {"ok": True})
        elif u.path == "/":
            if self._login_required():
                self._redirect("/login")
            else:
                page = DASHBOARD_HTML
                if self.server.pw_hash:   # only show logout when there is a login
                    page = page.replace('id="logout" hidden', 'id="logout"', 1)
                self._send(200, page, "text/html; charset=utf-8")
        elif u.path == "/api/export.csv":
            if self._login_required():
                self._send(401, {"error": "login required"})
            else:
                self._send_csv(parse_qs(u.query))
        elif u.path == "/api/data":
            if self._login_required():
                self._send(401, {"error": "login required"})
            else:
                self._send(200, self._query_data(parse_qs(u.query)))
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":          # Browser-Login, nutzt KEINEN API-Key
            self._handle_login()
            return
        if u.path == "/item-status":    # browser action -> session, not API key
            if self._login_required():
                self._send(401, {"error": "login required"})
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length < 0 or length > 8 * 1024:
                    raise ValueError("bad length")
                p = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                self._send(400, {"error": "bad request"})
                return
            key = str(p.get("key") or "")[:400]
            status = str(p.get("status") or "")
            if not key or "|" not in key or status not in ("offen", "arbeit", "erledigt"):
                self._send(400, {"error": "bad key/status"})
                return
            # UTC, so the comparison against the agents' event timestamps (also
            # UTC) for "active again" has no timezone offset.
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            with DB_LOCK:
                if status == "offen":     # open = default -> remove the row
                    self.server.conn.execute("DELETE FROM item_status WHERE key=?", (key,))
                else:
                    self.server.conn.execute(
                        "INSERT INTO item_status (key,status,updated_at) VALUES (?,?,?) "
                        "ON CONFLICT(key) DO UPDATE SET status=excluded.status, "
                        "updated_at=excluded.updated_at", (key, status, now))
                self.server.conn.commit()
            self._send(200, {"ok": True})
            return
        if u.path not in ("/ingest", "/status"):
            self._send(404, {"error": "not found"})
            return
        if self.server.api_key and not hmac.compare_digest(
                str(self.headers.get("X-Api-Key") or ""), str(self.server.api_key)):
            self._send(401, {"error": "bad api key"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "bad content-length"})
            return
        if length < 0:
            self._send(400, {"error": "bad content-length"})
            return
        if length > MAX_BODY:
            self._send(413, {"error": "payload too large"})
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception as exc:
            self._send(400, {"error": f"bad json: {exc}"})
            return

        # A broken or hostile client must get a clean 400, not a dropped
        # connection with a traceback in the log: validate shape before use.
        if not isinstance(payload, dict):
            self._send(400, {"error": "payload must be a JSON object"})
            return
        source = payload.get("source")
        source = source.strip() if isinstance(source, str) and source.strip() else "unknown"
        if u.path == "/status":
            try:
                ok = self._upsert_agent(source, payload)
            except (TypeError, ValueError) as exc:
                self._send(400, {"error": f"bad status shape: {exc}"})
                return
            self._send(200, {"ok": ok})
            return
        events = payload.get("events") or []
        if isinstance(events, dict):      # Single-Event-Push -> in Liste wandeln
            events = [events]
        if not isinstance(events, list):
            self._send(400, {"error": "events must be a list"})
            return
        try:
            inserted = self._insert(source, events)
        except (TypeError, ValueError) as exc:
            self._send(400, {"error": f"bad event shape: {exc}"})
            return
        self._send(200, {"received": len(events), "inserted": inserted})

    def _upsert_agent(self, source, p):
        now = datetime.now(timezone.utc).isoformat()

        def g(key):
            """Status fields are display strings; a nested value from a broken
            client must not raise InterfaceError inside the UPSERT."""
            v = p.get(key)
            if v is None or isinstance(v, (int, float, str)):
                return v
            if isinstance(v, bool):
                return int(v)
            return str(v)[:200]

        with DB_LOCK:
            self.server.conn.execute(
                "INSERT INTO agents (source,is_dc,agent_version,outgoing_audit,"
                "incoming_audit,domain_audit,lm_level,block_v1sso,cred_guard,ntlm_log_kb,"
                "os_version,restrict_out,restrict_in,restrict_dom,exc_client,exc_dc,"
                "domain_level,forest_level,last_seen) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(source) DO UPDATE SET is_dc=excluded.is_dc, "
                "agent_version=excluded.agent_version, outgoing_audit=excluded.outgoing_audit, "
                "incoming_audit=excluded.incoming_audit, domain_audit=excluded.domain_audit, "
                "lm_level=excluded.lm_level, block_v1sso=excluded.block_v1sso, "
                "cred_guard=excluded.cred_guard, ntlm_log_kb=excluded.ntlm_log_kb, "
                "os_version=excluded.os_version, restrict_out=excluded.restrict_out, "
                "restrict_in=excluded.restrict_in, restrict_dom=excluded.restrict_dom, "
                "exc_client=excluded.exc_client, exc_dc=excluded.exc_dc, "
                "domain_level=excluded.domain_level, forest_level=excluded.forest_level, "
                "last_seen=excluded.last_seen",
                (source, 1 if p.get("is_dc") else 0, g("agent_version"),
                 g("outgoing_audit"), g("incoming_audit"),
                 g("domain_audit"), g("lm_level"), g("block_v1sso"),
                 g("cred_guard"), g("ntlm_log_kb"),
                 g("os_version"), g("restrict_out"), g("restrict_in"),
                 g("restrict_dom"), g("exc_client"), g("exc_dc"),
                 g("domain_level"), g("forest_level"), now))
            self.server.conn.commit()
        return True

    # ---- DB ---------------------------------------------------------------
    def _insert(self, source, events):
        now = datetime.now(timezone.utc).isoformat()

        def scalar(v):
            """SQLite accepts None/int/float/str. Anything nested (a dict or list
            in a field) would raise InterfaceError mid-batch - stringify instead
            of letting one malformed field kill the whole push."""
            if v is None or isinstance(v, (int, float, str)):
                return v
            if isinstance(v, bool):
                return int(v)
            return json.dumps(v, ensure_ascii=False)[:500]

        rows = []
        for e in events:
            if not isinstance(e, dict):
                continue                     # skip garbage entries, keep the rest
            e = {k: scalar(v) for k, v in e.items()}
            rows.append((
                source,
                e.get("record_id"),
                e.get("log"),
                e.get("event_id"),
                e.get("kind"),
                e.get("event_time"),
                e.get("user"),
                e.get("domain"),
                e.get("ntlm_version"),
                normalize_process(e.get("process")),
                e.get("target_server"),
                e.get("workstation"),
                e.get("ip"),
                e.get("logon_type"),
                e.get("enc_type"),
                e.get("auth_method"),
                e.get("reason"),
                e.get("reason_id"),
                e.get("mic"),
                e.get("epa"),
                e.get("server_os"),
                e.get("failure_code"),
                e.get("process_path"),
                now,
            ))
        if not rows:
            return 0
        cols = "source," + ",".join(FIELDS) + ",received_at"
        placeholders = ",".join(["?"] * (len(FIELDS) + 2))
        sql = f"INSERT OR IGNORE INTO events ({cols}) VALUES ({placeholders})"
        with DB_LOCK:
            cur = self.server.conn.executemany(sql, rows)
            self.server.conn.commit()
            return cur.rowcount

    @staticmethod
    def _event_filters(qs):
        """Shared filter construction for /api/data and /api/export.csv."""
        def one(name, default=None):
            v = qs.get(name, [default])
            return v[0] if v else default

        # Time-range filter: 24h / 7d / 30d / all. Cutoff as an ISO string, since
        # event_time is stored as ISO (so string comparison is correct).
        rng = one("range", "all")
        deltas = {"24h": timedelta(hours=24), "7d": timedelta(days=7),
                  "30d": timedelta(days=30)}
        cutoff = None
        if rng in deltas:
            cutoff = (utc_now() - deltas[rng]).strftime("%Y-%m-%dT%H:%M:%S")

        where, params = [], []
        if cutoff:
            where.append("event_time >= ?"); params.append(cutoff)
        if one("kind"):
            where.append("kind = ?"); params.append(one("kind"))
        if one("version"):
            where.append("ntlm_version = ?"); params.append(one("version"))
        if one("source"):
            where.append("source = ?"); params.append(one("source"))
        # Account type: machine accounts end with '$' (DOM\PC01$, PC01$@DOM.TLD)
        # and dominate the Kerberos view; 'user' hides them, 'machine' shows only
        # them. NULL users count as neither.
        acct = one("acct")
        if acct == "machine":
            where.append("(user LIKE '%$' OR user LIKE '%$@%')")
        elif acct == "user":
            where.append("(user IS NOT NULL AND user <> '' "
                         "AND user NOT LIKE '%$' AND user NOT LIKE '%$@%')")
        q = one("q")
        if q:
            like = f"%{q}%"
            where.append("(user LIKE ? OR process LIKE ? OR target_server LIKE ? "
                         "OR ip LIKE ? OR workstation LIKE ?)")
            params += [like, like, like, like, like]

        # Drill-down from the trend chart and the heatmap. These have to use the
        # very same expressions the charts are built from, in the viewer's local
        # time, or a click would select a different set than the bar counted.
        try:
            tzoff = int(one("tzoff") or 0)
        except (TypeError, ValueError):
            tzoff = 0
        tzoff = max(-840, min(840, tzoff))      # -14h .. +14h
        tzmod = f"{tzoff:+d} minutes"           # from an int, never from input

        bucket = one("bucket")                  # one bar of the trend chart
        if bucket:
            width = 13 if rng == "24h" else 10  # hourly bars in the 24h range
            where.append(f"substr(datetime(event_time, ?),1,{width}) = ?")
            params += [tzmod, bucket[:width]]
        wd = one("wd")                          # heatmap weekday, 0 = Sunday
        if wd not in (None, "") and str(wd).isdigit() and 0 <= int(wd) <= 6:
            where.append("CAST(strftime('%w', event_time, ?) AS INTEGER) = ?")
            params += [tzmod, int(wd)]
        hr = one("hr")                          # heatmap hour
        if hr not in (None, "") and str(hr).isdigit() and 0 <= int(hr) <= 23:
            where.append("CAST(strftime('%H', event_time, ?) AS INTEGER) = ?")
            params += [tzmod, int(hr)]
        # Both charts count NTLM only, so a click has to exclude Kerberos too -
        # otherwise the row count would not match the bar the user clicked.
        if one("nokrb") == "1":
            where.append("kind != 'kerberos'")
        # Drill-down from the "why NTLM" panel. That table has two sources and
        # each needs its own column: the enhanced 40xx events carry a usage id,
        # failed Kerberos requests carry a failure code. Same predicates the
        # aggregation uses, so a click lands on exactly the counted rows.
        rid = one("rid")
        if rid:
            where.append("reason_id = ?"); params.append(rid)
        fcode = one("fcode")
        if fcode:
            where.append("failure_code = ?"); params.append(fcode)
        return one, rng, cutoff, where, params

    def _send_csv(self, qs):
        """Gefilterte Ereignisliste als CSV (Excel-tauglich: BOM + Semikolon)."""
        one, _rng, _cutoff, where, params = self._event_filters(qs)
        limit = min(int(one("limit", "50000") or 50000), 200000)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        cols = ["event_time", "source", "kind", "event_id", "ntlm_version",
                "auth_method", "user", "domain", "process", "target_server",
                "workstation", "ip", "logon_type", "enc_type", "reason",
                "reason_id", "mic", "epa", "server_os", "failure_code",
                "process_path"]
        with DB_LOCK:
            rows = self.server.conn.execute(
                f"SELECT {','.join(cols)} FROM events{clause} "
                f"ORDER BY event_time DESC LIMIT ?", params + [limit]).fetchall()

        def cell(v):
            s = "" if v is None else str(v)
            # Schutz vor Formel-Injektion in Tabellenkalkulationen
            return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
        w.writerow(["Time (UTC)", "Machine", "Kind", "EventID", "NTLM version",
                    "Auth path", "User", "Domain", "Process", "Target",
                    "Source/Workstation", "IP", "Logon type", "Encryption",
                    "Reason", "Reason ID", "MIC", "Channel binding", "Server OS",
                    "Kerberos failure", "Process path"])
        for r in rows:
            w.writerow([cell(v) for v in r])
        body = "\ufeff" + buf.getvalue()   # BOM -> Excel erkennt UTF-8
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition",
                         'attachment; filename="ntlm-events.csv"')
        self.send_header("Content-Length", str(len(data)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def _query_data(self, qs):
        one, rng, cutoff, where, params = self._event_filters(qs)
        limit = min(int(one("limit", "300") or 300), 2000)
        # tf/tp sind der gemeinsame Filter ALLER Aggregate. Neben dem Zeitraum
        # wirkt hier auch die Maschinenauswahl - dadurch filtert sie global und
        # nicht nur die Ereignisliste. Die Klausel bleibt ein fester String,
        # Benutzereingaben gehen ausschliesslich als Parameter hinein.
        # Browser UTC offset in minutes (east positive). Everything is stored in
        # UTC; the day/hour buckets below have to be shifted into the viewer's
        # local time, otherwise "peak on Sunday at 03:00" names the wrong hour.
        try:
            tzoff = int(one("tzoff") or 0)
        except (TypeError, ValueError):
            tzoff = 0
        tzoff = max(-840, min(840, tzoff))          # -14h .. +14h
        tzmod = f"{tzoff:+d} minutes"               # built from an int, never from input

        tf_parts, tp = [], []
        if cutoff:
            tf_parts.append("event_time >= ?"); tp.append(cutoff)
        src = one("source")
        if src:
            tf_parts.append("source = ?"); tp.append(src)
        tf = " AND ".join(tf_parts) if tf_parts else "1=1"
        clause = (" WHERE " + " AND ".join(where)) if where else ""

        with DB_LOCK:
            c = self.server.conn
            # Work status (open/in progress/done) for blocker and domain rows
            st_map = {r[0]: (r[1], r[2]) for r in
                      c.execute("SELECT key, status, updated_at FROM item_status").fetchall()}
            def with_status(prefix, a, b, row):
                key = f"{prefix}|{a}|{b}"
                st, st_at = st_map.get(key, ("offen", None))
                row.update(key=key, st=st, st_at=st_at)
                return row
            stats = {
                "total":  c.execute(f"SELECT COUNT(*) FROM events WHERE {tf}", tp).fetchone()[0],
                "v1":     c.execute(f"SELECT COUNT(*) FROM events WHERE ntlm_version='NTLMv1' AND {tf}", tp).fetchone()[0],
                "v2":     c.execute(f"SELECT COUNT(*) FROM events WHERE ntlm_version='NTLMv2' AND {tf}", tp).fetchone()[0],
                "outbound": c.execute(f"SELECT COUNT(*) FROM events WHERE event_id IN (8001,4001,4020,4021,4013) AND {tf}", tp).fetchone()[0],
                "sources": c.execute(f"SELECT COUNT(DISTINCT source) FROM events WHERE {tf}", tp).fetchone()[0],
                "procs":   c.execute(f"SELECT COUNT(DISTINCT process) FROM events "
                                     f"WHERE process IS NOT NULL AND process NOT LIKE '(%' AND {tf}", tp).fetchone()[0],
                "krb":     c.execute(f"SELECT COUNT(DISTINCT target_server) FROM events WHERE kind='kerberos' AND {tf}", tp).fetchone()[0],
                # Kerberos ticket count (not services): the dashboard needs it to
                # state what share of authentication still runs over NTLM.
                "krb_ev":  c.execute(f"SELECT COUNT(*) FROM events WHERE kind='kerberos' AND {tf}", tp).fetchone()[0],
                "fallback": c.execute(f"SELECT COUNT(*) FROM events WHERE auth_method='Fallback' AND {tf}", tp).fetchone()[0],
                # Enhanced audits (Server 2025): NTLMv1-derived SSO credentials.
                # From October 2026 Windows blocks these by itself (BlockNtlmv1SSO).
                "v1sso": c.execute(f"SELECT COUNT(*) FROM events WHERE kind='ntlmv1sso' AND {tf}", tp).fetchone()[0],
                "inbound": c.execute(f"SELECT COUNT(*) FROM events WHERE kind='incoming' AND {tf}", tp).fetchone()[0],
                "downgrade": c.execute(f"SELECT COUNT(*) FROM events WHERE auth_method='Downgrade' AND {tf}", tp).fetchone()[0],
            }
            # Trend: NTLM events per time bucket (24h -> hourly, otherwise daily).
            # Buckets via substr on the ISO string; kerberos separate, for context only.
            # Buckets in the viewer's local time, same reason as the heatmap:
            # a "day" that runs 02:00-02:00 would put evening events on the
            # wrong bar. datetime(...) applies the offset, substr then cuts.
            bucket = ("substr(datetime(event_time, ?),1,13)" if rng == "24h"
                      else "substr(datetime(event_time, ?),1,10)")
            trend_rows = c.execute(
                f"SELECT {bucket} AS b, "
                f"SUM(CASE WHEN ntlm_version='NTLMv1' THEN 1 ELSE 0 END), "
                f"SUM(CASE WHEN ntlm_version='NTLMv2' THEN 1 ELSE 0 END), "
                f"SUM(CASE WHEN kind!='kerberos' AND ntlm_version IS NULL THEN 1 ELSE 0 END), "
                f"SUM(CASE WHEN kind='kerberos' THEN 1 ELSE 0 END) "
                f"FROM events WHERE event_time IS NOT NULL AND event_time!='' AND {tf} "
                f"GROUP BY b ORDER BY b DESC LIMIT 60", [tzmod] + tp).fetchall()
            trend = [dict(b=r[0], v1=r[1] or 0, v2=r[2] or 0,
                          other=r[3] or 0, krb=r[4] or 0) for r in reversed(trend_rows)]
            # Heatmap weekday x hour: batch jobs and maintenance windows are the
            # stragglers that break a shutdown, and they only show up as a
            # pattern over time - the daily trend averages them away.
            # SQLite %w: 0=Sunday..6=Saturday -> shifted to 0=Monday for display.
            heat_rows = c.execute(
                f"SELECT CAST(strftime('%w', event_time, ?) AS INTEGER), "
                f"CAST(strftime('%H', event_time, ?) AS INTEGER), COUNT(*) "
                f"FROM events WHERE kind != 'kerberos' AND {tf} "
                f"GROUP BY 1, 2", [tzmod, tzmod] + tp).fetchall()
            heat = [[0] * 24 for _ in range(7)]
            for wd, hr, n in heat_rows:
                if wd is None or hr is None:
                    continue
                heat[(wd + 6) % 7][hr] = n

            # Per-program mini time series for the sparklines. Limited to the
            # programs that actually appear in the blocker table, and bucketed
            # by day so a short range still yields a usable line.
            spark_rows = c.execute(
                f"SELECT process, date(event_time, ?), COUNT(*) "
                f"FROM events WHERE event_id IN (8001,4001,4020,4021,4013) "
                f"AND process IS NOT NULL AND {tf} "
                f"GROUP BY 1, 2 ORDER BY 2", [tzmod] + tp).fetchall()
            spark = {}
            for proc, day, n in spark_rows:
                spark.setdefault(proc, []).append([day, n])

            top_proc = [dict(name=r[0], n=r[1]) for r in c.execute(
                f"SELECT process, COUNT(*) "
                f"FROM events WHERE kind='outgoing' AND process IS NOT NULL AND {tf} "
                f"GROUP BY process ORDER BY COUNT(*) DESC LIMIT 15", tp).fetchall()]
            v1_users = [dict(name=r[0], n=r[1]) for r in c.execute(
                f"SELECT user, COUNT(*) FROM events WHERE ntlm_version='NTLMv1' AND {tf} "
                f"GROUP BY user ORDER BY COUNT(*) DESC LIMIT 15", tp).fetchall()]
            # Shutdown blockers: outgoing NTLM (8001) - breaks once the outgoing policy denies
            blockers = [with_status("proc", r[0], r[1],
                             dict(process=r[0], target=r[1], n=r[2], blocked=r[3],
                             users=r[4], sources=r[5], last_seen=r[6], who=r[7])) for r in c.execute(
                f"SELECT COALESCE(process,'(unknown)'), COALESCE(target_server,'(unknown)'), "
                f"COUNT(*), SUM(CASE WHEN event_id IN (4001,4002,4003,4004,4005,4006,4013) THEN 1 ELSE 0 END), COUNT(DISTINCT user), COUNT(DISTINCT source), MAX(event_time), "
                f"GROUP_CONCAT(DISTINCT user) "
                f"FROM events WHERE event_id IN (8001,4001,4020,4021,4013) AND {tf} "
                f"GROUP BY process, target_server ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            # "Why NTLM?" - grouped by the Usage ID of the enhanced 40xx events.
            # This is the actual worklist: each cause has its own remediation,
            # so the same program can appear under two different reasons.
            reasons = [dict(rid=r[0],
                            text=REASON_IDS.get(r[0], ("Unknown reason", "unklar"))[0],
                            cat=REASON_IDS.get(r[0], ("", "unklar"))[1],
                            n=r[1], procs=r[2], machines=r[3], last_seen=r[4],
                            sample=r[5]) for r in c.execute(
                f"SELECT reason_id, COUNT(*), COUNT(DISTINCT process), "
                f"COUNT(DISTINCT source), MAX(event_time), "
                f"MAX(COALESCE(target_server,'')) "
                f"FROM events WHERE reason_id IS NOT NULL AND reason_id != '' AND {tf} "
                f"GROUP BY reason_id ORDER BY COUNT(*) DESC", tp).fetchall()]
            # Zweite Quelle: fehlgeschlagene Kerberos-Anfragen (4769). Auf
            # Systemen ohne die 40xx-Ereignisse die einzige Fruehwarnung -
            # 0x7 (SPN fehlt) ist der klassische Fallback-Vorbote. Gleiche
            # Tabelle, gleiche Abhilfe-Spalte; rid bekommt ein "k"-Praefix,
            # damit die i18n-Schluessel nicht mit den Usage-IDs kollidieren.
            reasons += [dict(rid="k" + r[0],
                             text=KRB_FAIL.get(r[0], ("Kerberos failure " + r[0], "unklar"))[0],
                             cat=KRB_FAIL.get(r[0], ("", "unklar"))[1],
                             n=r[1], procs=0, machines=r[2], last_seen=r[3],
                             sample=r[4]) for r in c.execute(
                f"SELECT failure_code, COUNT(*), COUNT(DISTINCT source), "
                f"MAX(event_time), MAX(COALESCE(target_server,'')) "
                f"FROM events WHERE kind='krbfail' AND failure_code IS NOT NULL AND {tf} "
                f"GROUP BY failure_code", tp).fetchall()]
            reasons.sort(key=lambda x: -x["n"])

            # Relay exposure: an unprotected MIC or missing channel binding is
            # what makes an NTLM session relay-able. Only the 40xx events carry
            # these fields, so this counts a subset - never the whole picture.
            # Blocked events (4001-4006): under a deny policy the audit events
            # switch IDs. These are no longer a worklist but an alarm/success
            # signal, so they are counted and badged rather than mixed in.
            stats["blocked"] = c.execute(
                f"SELECT COUNT(*) FROM events WHERE {tf} AND "
                f"event_id IN (4001,4002,4003,4004,4005,4006,4013)", tp).fetchone()[0]
            # Credential Guard blocks (4013/4014): these never reach the regular
            # NTLM audit path, so a machine producing them looks clean while NTLM
            # is in fact being attempted. Counted per machine to flag that.
            cg_by_src = dict(c.execute(
                f"SELECT source, COUNT(*) FROM events WHERE kind='cgblock' AND {tf} "
                f"GROUP BY source", tp).fetchall())
            stats["cg_blocked"] = sum(cg_by_src.values())

            relay = c.execute(
                f"SELECT COUNT(*) FROM events WHERE {tf} AND "
                f"(mic = 'Unprotected' OR epa = 'Not Supported')", tp).fetchone()[0]
            stats["relay"] = relay
            stats["relay_scope"] = c.execute(
                f"SELECT COUNT(*) FROM events WHERE {tf} AND "
                f"(mic IS NOT NULL OR epa IS NOT NULL)", tp).fetchone()[0]

            # Incoming NTLM (8002/8003): which local service accepts NTLM, and
            # which remote accounts come in. 8002 carries the calling process,
            # 8003 the remote account - grouped per machine + process.
            incoming = [with_status("inc", r[0], r[1],
                          dict(machine=r[0], process=r[1], n=r[2], blocked=r[3],
                               users=r[4], sources=r[5], last_seen=r[6])) for r in c.execute(
                f"SELECT source, COALESCE(process,'(unknown)'), COUNT(*), "
                f"SUM(CASE WHEN event_id IN (4002,4003) THEN 1 ELSE 0 END), "
                f"COUNT(DISTINCT user), COUNT(DISTINCT workstation), MAX(event_time) "
                f"FROM events WHERE kind='incoming' AND {tf} "
                f"GROUP BY source, process ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            # NTLMv1 SSO (4024/4025): its own blocker with a hard October 2026 deadline
            v1sso = [with_status("v1sso", r[0], r[1],
                          dict(user=r[0], target=r[1], n=r[2], sources=r[3],
                               last_seen=r[4], blocked=bool(r[5]))) for r in c.execute(
                f"SELECT COALESCE(user,'(unknown)'), COALESCE(target_server,'(unknown)'), "
                f"COUNT(*), COUNT(DISTINCT source), MAX(event_time), "
                f"MAX(CASE WHEN event_id=4025 THEN 1 ELSE 0 END) "
                f"FROM events WHERE kind='ntlmv1sso' AND {tf} "
                f"GROUP BY user, target_server ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            # NTLM inside the domain (8004, from the DC): most reliable source->target view
            domain = [with_status("dom", r[0], r[1],
                           dict(workstation=r[0], target=r[1], users=r[2],
                           n=r[3], blocked=r[4], last_seen=r[5], who=r[6])) for r in c.execute(
                f"SELECT COALESCE(workstation,'(unknown)'), COALESCE(target_server,'(unknown)'), "
                f"COUNT(DISTINCT user), COUNT(*), "
                f"SUM(CASE WHEN event_id IN (4004,4005,4006) THEN 1 ELSE 0 END), "
                f"MAX(event_time), GROUP_CONCAT(DISTINCT user) "
                f"FROM events WHERE event_id IN (8004,8005,8006,4004,4005,4006,4022,4023,4030,4031,4032,4033) AND {tf} "
                f"GROUP BY workstation, target_server ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            # Kerberos (informational): which services/SPNs already use Kerberos
            kerberos = [dict(service=r[0], accounts=r[1], n=r[2],
                             enc=r[3], last_seen=r[4]) for r in c.execute(
                f"SELECT COALESCE(target_server,'(unknown)'), COUNT(DISTINCT user), COUNT(*), "
                f"       GROUP_CONCAT(DISTINCT enc_type), MAX(event_time) "
                f"FROM events WHERE kind='kerberos' AND {tf} "
                f"GROUP BY target_server ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            # Kerberos by account: the "safe side" - which accounts already use Kerberos
            kerberos_accounts = [dict(account=r[0], services=r[1], svc_count=r[2], n=r[3],
                                      enc=r[4], last_seen=r[5]) for r in c.execute(
                f"SELECT COALESCE(user,'(unknown)'), GROUP_CONCAT(DISTINCT target_server), "
                f"       COUNT(DISTINCT target_server), COUNT(*), "
                f"       GROUP_CONCAT(DISTINCT enc_type), MAX(event_time) "
                f"FROM events WHERE kind='kerberos' AND user IS NOT NULL AND user<>'' AND {tf} "
                f"GROUP BY user ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            srcs = [r[0] for r in c.execute(
                "SELECT DISTINCT source FROM events ORDER BY source").fetchall()]
            # Maschinen: Heartbeat (last_seen) + Audit-Status + Eventzahl je Quelle
            # (deliberately WITHOUT the time filter: shows the agents' current state)
            agents = [dict(source=r[0], is_dc=bool(r[1]), agent_version=r[2],
                           outgoing_audit=r[3], incoming_audit=r[4], domain_audit=r[5],
                           last_seen=r[6], events=r[7] or 0, last_event=r[8],
                           lm_level=r[9], first_event=r[10],
                           block_v1sso=r[11], cred_guard=r[12],
                           ntlm_log_kb=r[13], os_version=r[14],
                           restrict_out=r[15], restrict_in=r[16],
                           restrict_dom=r[17], exc_client=r[18],
                           exc_dc=r[19], domain_level=r[20], forest_level=r[21],
                           cg=cg_by_src.get(r[0], 0)) for r in c.execute(
                "SELECT a.source, a.is_dc, a.agent_version, a.outgoing_audit, a.incoming_audit, "
                "a.domain_audit, a.last_seen, "
                "(SELECT COUNT(*) FROM events e WHERE e.source=a.source), "
                "(SELECT MAX(event_time) FROM events e WHERE e.source=a.source), "
                "a.lm_level, "
                "(SELECT MIN(event_time) FROM events e WHERE e.source=a.source), "
                "a.block_v1sso, a.cred_guard, a.ntlm_log_kb, a.os_version, "
                "a.restrict_out, a.restrict_in, a.restrict_dom, a.exc_client, a.exc_dc, "
                "a.domain_level, a.forest_level "
                "FROM agents a ORDER BY a.last_seen DESC").fetchall()]

            # Datenbasis: seit wann liegen ueberhaupt Events vor? Zwei Wochen im
            # Normalbetrieb gelten als Minimum, damit auch woechentliche
            # Aufgaben und Batch-Jobs einmal gelaufen sind.
            first_all = c.execute("SELECT MIN(event_time) FROM events").fetchone()[0]
            coverage_days = None
            if first_all:
                try:
                    d0 = datetime.strptime(first_all[:19], "%Y-%m-%dT%H:%M:%S")
                    coverage_days = max(0, (utc_now() - d0).days)
                except ValueError:
                    coverage_days = None
            stats["coverage_days"] = coverage_days
            stats["coverage_target"] = 14
            cols2 = ["source"] + list(FIELDS)
            rows = c.execute(
                f"SELECT {','.join(cols2)} FROM events{clause} "
                f"ORDER BY event_time DESC, id DESC LIMIT ?",
                params + [limit]).fetchall()
            events = [dict(zip(cols2, r)) for r in rows]
            # The list is capped, the count must not be: without this the panel
            # reports the cap ("300") as if it were the result, which is plainly
            # wrong once a filter matches more than that.
            events_total = c.execute(
                f"SELECT COUNT(*) FROM events{clause}", params).fetchone()[0]

        return {"stats": stats, "v1sso": v1sso, "incoming": incoming, "reasons": reasons, "trend": trend, "trend_bucket": ("hour" if rng == "24h" else "day"), "heat": heat, "spark": spark,
                "top_proc": top_proc, "v1_users": v1_users,
                "blockers": blockers, "domain": domain, "kerberos": kerberos,
                "kerberos_accounts": kerberos_accounts,
                "agents": agents, "sources": srcs, "events": events,
                "events_total": events_total, "events_limit": limit,
                "generated_at": datetime.now(timezone.utc).isoformat()}


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NTLM-Analyzer</title>
<!-- Embedded rather than a separate file: the dashboard is one
     self-contained page with no external requests, and the CSP allows
     data: for images. A browser tab with the generic globe next to a
     security tool looks unfinished. Two sizes because 16 is what most
     tabs use and 32 what pinned tabs and bookmarks pick. -->
<link rel="icon" type="image/png" sizes="32x32" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAF9klEQVR42u1Xf0xdZxl+3u87915+3ba0tdAilkFs5raO1m40JaOV4ZyhTSUqTWasG5tZNc64rNl0/YcsmYn+MbVNaoJbxBZj0oszLHFgNzUtzKVESSm3QAXv3Ya9cvl1C/deLtx7zvke/4AyuiYb3dj+2pucnOTLOe/znPe8z/N+H7AYJBU+oViOZS0uiIiYoSH6TPbs/Vp5irTXu6qE3EzGuMaOqLncv4tIehGTQlKJiAmPpcsJ9Yf1G6w77AyQTBAEoN5DwxiCogBZObiQyMsTeL1AbMoZEJhvlRb4LpFUQlIuRaM5nvSaS5uLcspON//RPvVSk0Qnx+DYwFyaELleOiDLK/A5NoxtVkxCZ1nYWLQFjzx2hN9p+KZnNJIK2b54eXlhYcoSEfYOxaqLSnPKfvfbVvvJ73/XA48HxXlrsaWA+OI2HzIZAgC8PkHf0ByGNn0W/uK1cDPuB5AQwBikrkQR7P4Xnuz5JwDajzxaX/Z2OF0tm+XPFgD4srOL0hnw1ItNAmXhhb27UZGzHh3rg/jpjwqBaXch33oPjp+M4MTeamz7+p2Yn56HqA8ug0k7GPvF3zB8vAPNLzXJQ9+upy87u2ipCX1ZWZxNUP47HkV54WfwVPnt6Boew2zawJl2kYw7IAR+BcymDUxyHpnYLOyZFRAgIF6NgqM1GD83gMmro0gkIb6sLALAUouJAPOuwY78tTBaY94x0AJYGtBKoBVgaYESAEogWq3sshSYcaG8FrJvL4TJODf8tpukpmRhUWQVNSjvueN9CHzS8SmBTwmoBX93M0oEWiu4hh/fFHQJrRWUWsBcIiCGk5YF+HP9ci2dBnFLs2YFMhTAEHY8hVy/XyxrAXOJQDwZf4sAS7aW6NB0HOK6UCJYrVqIEjDtIDUyieKS2zQIxpPxt5YI9L7RF7IsRPZU7MZw7JpJpObg02p1CJAQj4Y9OoPZ0JjZVbkHHguR3jf6QgCgSOqGhup5Q3R+9cFa2oT5y9Uoci0Lhh+dAg2hc7yY7hqGnndMTe1+0qCzoaF6nqReUkFsarblrru3yRfuuVeO9/Yj6Rp4VsGPRSkwZWPkVBd27KqQ7ds/L7Gp2ZZ3rV/EJSnPPdP+uuPi4o+P/kT/IzLqNg2/jTzLAo358F9vu7DyszH1p14kLv/H/eGxY9o4uPjcM+2vL27JXAUArYBqbT3kxqZmnj1wsAa1B+rYErwI5dMQSz6UNOkY6DVZyAxNYqDxDL6yv577D9yP2NTMs62th9zWxf5TAHBIxA2QenvpurMz087pX578tVVQVOy0dY4jdg3w5yg4Lm8JXOV4waSN/u81Y2N2vnPixSYrfs05vb103dkAqQ+JuDc4YT1gSKrghe4n/P68/t+3nrH6wrZz4FgYsZQgP0/Bdfj+yiBAx4VemwUk0ug//BvM/3vcaWlrs9bk5fYHL3Q/QVLVA+YmKxYRAkBd3X2J0JWRg3fvvCvySscrVk/IdSp/MIjuYQc6X0OrBUfDcoWQoGMAJfBs9CPdN4qeg79C+nLUOdPRbu3YcUckdGXkYF3dfYnlWDfNAhExgQB1VcXW8OVgpGZ35b2h82+es5ysz9l7jlzkiZYY0o6Cx++DeC3QNaAhxNKwNuRCEfjfC3/FhQd/xs0q3z7b/aZVWXlPKBiM1FRVbA0HAtQiYlbgHdQA0Pba4JbRJM9F4i4ffvxpA9ng+DzruO2ph7h34CS/NNrM6mgzqy6d4J0/f5zZt5USyHMePvK0uRo3HE3yXNtrg1uW51xxBAKBxRf2WeEJ+/mJOWY6OntZ9eVvuII1jlq3yWyqreKm2irq/AID5DpV+77mtnf1cXyOmfCE/Tywz7ox1y1GYyPV9anUMzixazLN9miSfLUzyMOPHWVZyU6nrGSnc/jRo3y16zKjKXJiju09gxO7ru8BGxs/8pmTsrx8A+8kHphI8+WxFJMj0+TINDmWYnIizZcH3kk8cONv5OoNVZKKfDfh+eBwcXic9eFx1p8PDhcve04+1pM2SR0I3NxQgQD1LTcagP8DPY8VETPRB40AAAAASUVORK5CYII=">
<link rel="icon" type="image/png" sizes="16x16" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAChklEQVR42pWTT2iUZxDGf/O+m+ynMTSxMZtaPbQ9NAXNIU00EtEGK+1BsYEGIQTxH+2pUkp7VW+FCirqQUExiof2Qz2IVGrxX2nAqKiFWHNQTEJFiEaiSZrs7rfv00MSWa0KPrdhZn4M88wYU5LUAESAAOPlms5NmNk1gFRPj0rLMxzrPHnuy6tXr1vK0gQgcgGfJKiIZQb5iSz1zYt1b0jHxx7c6jBJjYdPXryyfV07y2vLaV4hynIJe+/PZqC5nijJIzMkYd5RGJngwf4/6Nx9lI62lkUpIOq60h221n3kFjZVUbfmEVEu8Oftebj2FZTnsgSbnEKFAlF1BRhc77ocOtpaohSgGelS91ZJCUNj4ww9yVOTC4yPTJAbGiGbLwYEwEjNiigdSztAqakFUpDwZngH3oE5w7zDgsOsaA/eoYKQBIB7luANVFTsgKw5p4LeABCEMxOQdUD/25ma4X/yCR70Wo5ADmnwXzJzqoeBfue9G2xoXNT9V2qmHo6OBo/jVRDnHeNPR0NlX6L6xUu6nfeDLgSxquH9XXNXrrJjPX+H6soy8sn/ESGXEL1Tyd1D58PqDz+xZc0f7FIIuDiWN7OzGzat75xZ11ry86neXGlNBBgqBJQEDCibX8Wto7/nlvZlSjq+2txpZmfjWB5Jtk1yktLXeodPt63/Vj+2Z5L2n1qTJU9+CSsfHQlNd/Yl1d9/kaxdt0U3ex+flpSe6pk0WJKZmSSlBp6y88Ceg9+c6TrBw8YKDKjqzdK64DM2bvl677sVfGdmyXSPFX2j2TOell++MfDDhV9/awFo+fzTC00fv7fDzC4BJgmbtPEFlySL49gXxbWSaqfjOI69pOdu7j+tZTR/mbSjAgAAAABJRU5ErkJggg==">
<style>
:root{
  /* Tells the browser to draw native controls - select popups, scrollbars,
     focus rings - in their dark variant. Without it the dropdown list is
     rendered by the OS with light defaults and unreadable grey text. */
  color-scheme:dark;
  --void:#0e131f; --card:#18202f; --card2:#1d2637;
  --edge:rgba(158,180,225,.13); --edge2:rgba(158,180,225,.24);
  --ink:#eef2fa; --dim:#a3b1c9; --faint:#7c8aa4;
  --v1:#ff6b6b; --v2:#f5b841; --krb:#3ddc97; --pol:#a78bfa; --grey:#4a5872;
  --disp:'Segoe UI Variable Display','Segoe UI',system-ui,-apple-system,sans-serif;
  --text:'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,sans-serif;
  --mono:'Cascadia Mono','IBM Plex Mono',ui-monospace,Consolas,'SF Mono',monospace;
  --r:14px; --pad:clamp(20px,2.8vw,52px);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
/* 390 px wide viewports scrolled ~4 px sideways. Nothing may exceed the
   viewport, and long unbroken values (SPNs, paths) are the usual culprit. */
html{overflow-x:hidden}
body{max-width:100vw;overflow-x:hidden;margin:0;background:var(--void);color:var(--ink);font-family:var(--text);font-size:18px;
  line-height:1.5;-webkit-font-smoothing:antialiased;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(1200px 600px at 10% -8%,rgba(255,107,107,.05),transparent 62%),
             radial-gradient(1200px 700px at 90% 108%,rgba(61,220,151,.042),transparent 62%)}
.stage{position:relative;z-index:1}
::selection{background:rgba(61,220,151,.25)}
:focus-visible{outline:2px solid var(--krb);outline-offset:2px;border-radius:6px}
button{font:inherit}
a{color:inherit}

header{position:sticky;top:0;z-index:60;backdrop-filter:blur(18px) saturate(1.4);
  background:rgba(14,19,31,.80);border-bottom:1px solid var(--edge)}
.hin{padding:0 var(--pad);height:66px;display:flex;align-items:center;gap:16px}
.logo{display:flex;align-items:center;gap:11px;font-family:var(--disp);font-size:17px;font-weight:600;
  letter-spacing:-.02em;white-space:nowrap}
.orb{width:9px;height:9px;border-radius:50%;background:var(--krb);position:relative;flex:none}
.orb::after{content:"";position:absolute;inset:-5px;border-radius:50%;border:1px solid var(--krb);
  opacity:.35;animation:ping 3.2s cubic-bezier(.2,.7,.3,1) infinite}
.orb.stale{background:var(--v2)} .orb.stale::after{border-color:var(--v2)}
@keyframes ping{0%{transform:scale(.6);opacity:.5}70%,100%{transform:scale(1.5);opacity:0}}
.tools{display:flex;align-items:center;gap:8px;margin-left:auto;flex-wrap:wrap;justify-content:flex-end}
.pill{display:flex;background:rgba(255,255,255,.035);border:1px solid var(--edge);border-radius:9px;
  padding:2px;gap:2px}
.pill button{background:none;border:0;color:var(--dim);font-family:var(--mono);font-size:12.5px;
  padding:5px 11px;border-radius:7px;cursor:pointer;transition:.18s;white-space:nowrap}
.pill button:hover{color:var(--ink)}
.pill button[aria-pressed=true]{background:rgba(255,255,255,.08);color:var(--ink)}
select,.ghost{background:rgba(255,255,255,.035);border:1px solid var(--edge);color:var(--ink);
  border-radius:9px;padding:6px 10px;font-family:var(--mono);font-size:12.5px;cursor:pointer;transition:.18s}
select:hover,.ghost:hover{border-color:var(--edge2);background:rgba(255,255,255,.06)}
select option,.sel-st option{background:#1d2637;color:var(--ink)}
select option:checked,.sel-st option:checked{background:#26314a;color:#fff}
.ghost[aria-pressed=true]{background:rgba(61,220,151,.1);border-color:rgba(61,220,151,.35);color:#9ff0cb}

.herotop{display:flex;gap:clamp(24px,4vw,70px);align-items:flex-start}
.herotext{flex:1 1 auto;min-width:0}
.osdon{flex:0 0 auto;width:330px;border:1px solid var(--edge);border-radius:var(--r);
  background:rgba(255,255,255,.02);padding:16px 18px}
.osdon .oh{font-family:var(--mono);font-size:12px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--faint);margin-bottom:12px}
.osdon .ow{display:flex;align-items:center;gap:16px}
.osdon svg{flex:none}
.osdon .ring circle{transition:stroke-dasharray 1.1s cubic-bezier(.16,1,.3,1)}
.osdon .mid{font-family:var(--disp);font-weight:620;fill:var(--ink)}
.osdon .midl{font-family:var(--mono);fill:var(--faint)}
.osdon .leg{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:5px}
.osdon .lr{display:flex;align-items:baseline;gap:7px;font-size:13px;color:var(--dim);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.osdon .lr i{width:9px;height:9px;border-radius:2px;flex:none;align-self:center}
.osdon .lr b{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--ink);
  font-variant-numeric:tabular-nums;min-width:2ch;text-align:right}
.osdon .note{font-family:var(--mono);font-size:11.5px;color:var(--faint);margin-top:11px;
  padding-top:10px;border-top:1px solid var(--edge)}
.osdon .fl{margin-top:10px;padding-top:10px;border-top:1px solid var(--edge);
  display:flex;flex-direction:column;gap:4px}
.osdon .flr{display:flex;align-items:baseline;gap:8px;font-size:13px;color:var(--dim)}
.osdon .flr span{flex:1 1 auto}
.osdon .flr b{font-family:var(--mono);font-size:13px;color:var(--ink);font-weight:600}
.osdon .flr em{font-style:normal;color:var(--v2);font-weight:700;cursor:help}
@media(max-width:1250px){.osdon{display:none}}
.jump{position:sticky;top:66px;z-index:55;backdrop-filter:blur(14px);background:rgba(14,19,31,.76);
  border-bottom:1px solid var(--edge);padding:9px var(--pad);display:flex;gap:5px;flex-wrap:wrap}
.jl{background:none;border:1px solid transparent;color:var(--faint);font-family:var(--mono);
  font-size:14px;padding:4px 9px;border-radius:7px;cursor:pointer;transition:.16s;display:flex;
  gap:6px;align-items:center;white-space:nowrap}
.jl:hover{color:var(--ink);border-color:var(--edge)}
.jl b{color:var(--dim);font-weight:400;font-variant-numeric:tabular-nums}
.jl.nil{opacity:.4}

.hero{padding:58px var(--pad) 44px}
.eyebrow{font-family:var(--mono);font-size:15.5px;letter-spacing:.16em;text-transform:uppercase;
  color:var(--faint);margin-bottom:16px}
.thesis{font-family:var(--disp);font-size:clamp(40px,4.2vw,66px);font-weight:380;line-height:1.09;
  letter-spacing:-.035em;max-width:24ch;margin:0 0 8px}
.thesis .big{font-weight:640;font-variant-numeric:tabular-nums}
.thesis .fade{color:var(--faint)}
.sub{color:var(--dim);font-size:18px;max-width:66ch;margin:0 0 30px}
.handbar{display:flex;height:50px;border-radius:10px;overflow:hidden;gap:2px;background:var(--edge);
  margin-bottom:12px}
.seg{position:relative;width:0;min-width:3px;flex:0 0 auto;transition:width 1.4s cubic-bezier(.16,1,.3,1);
  overflow:hidden;display:flex;align-items:center;padding:0 12px;cursor:pointer}
.seg.tight{padding:0 3px}
/* First tab stop. Reaching the tables meant tabbing through the whole header
   and section bar; this jumps straight to the part people came for. */
.skip{position:absolute;left:-9999px;top:0;z-index:100;background:var(--card2);
  color:var(--ink);border:1px solid var(--edge2);border-radius:0 0 10px 0;
  padding:12px 18px;font-size:15px;text-decoration:none}
.skip:focus{left:0}
.handbar{position:relative;overflow:visible}
.seg:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.seg.on{filter:brightness(1.45)}
.handbar:hover .seg:not(:hover){filter:brightness(.72)}
.segtip{position:absolute;bottom:calc(100% + 14px);left:0;transform:translateX(-50%) translateY(4px);
  background:#1d2637;border:1px solid var(--edge2);border-radius:12px;padding:13px 16px;
  box-shadow:0 18px 40px rgba(0,0,0,.45);pointer-events:none;opacity:0;visibility:hidden;
  transition:opacity .16s,transform .16s;z-index:30;white-space:nowrap}
.segtip.on{opacity:1;visibility:visible;transform:translateX(-50%) translateY(0)}
.segtip::after{content:"";position:absolute;top:100%;left:50%;margin-left:-6px;
  border:6px solid transparent;border-top-color:#1d2637}
.segtip .th{font-family:var(--disp);font-size:15px;font-weight:600;color:var(--ink);
  margin-bottom:9px;display:flex;align-items:center;gap:8px}
.segtip .th i{width:10px;height:10px;border-radius:3px;flex:none}
.segtip .tr{display:flex;align-items:baseline;justify-content:space-between;gap:22px;
  font-size:13px;color:var(--dim);padding:2px 0}
.segtip .tr b{font-family:var(--mono);font-size:14px;color:var(--ink);font-weight:600;
  font-variant-numeric:tabular-nums}
.segtip .tf{margin-top:9px;padding-top:8px;border-top:1px solid var(--edge);
  font-family:var(--mono);font-size:11.5px;color:var(--faint)}
.seg.s1{background:linear-gradient(180deg,rgba(255,107,107,.30),rgba(255,107,107,.16))}
.seg.s2{background:linear-gradient(180deg,rgba(245,184,65,.28),rgba(245,184,65,.14))}
.seg.s3{background:linear-gradient(180deg,rgba(61,220,151,.26),rgba(61,220,151,.13))}
.seg::after{content:"";position:absolute;left:0;top:0;bottom:0;width:2px}
.seg.s1::after{background:var(--v1)}.seg.s2::after{background:var(--v2)}.seg.s3::after{background:var(--krb)}
.seg b{font-family:var(--mono);font-size:15px;font-weight:500;white-space:nowrap;opacity:0;
  transition:opacity .5s .8s}
.seg.s1 b{color:#ffb3b3}.seg.s2 b{color:#ffd894}.seg.s3 b{color:#9ff0cb}
.seg:hover{filter:brightness(1.3)}
.handkey{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px}
.kk{display:flex;align-items:baseline;gap:9px;padding:9px 14px;border:1px solid var(--edge);
  border-radius:10px;background:rgba(255,255,255,.02);font-size:14px;color:var(--dim)}
.kk i{width:9px;height:9px;border-radius:3px;flex:none;align-self:center}
.kk b{font-family:var(--mono);font-size:17px;font-weight:600;color:var(--ink);
  font-variant-numeric:tabular-nums}
.kk em{font-family:var(--mono);font-size:13px;font-style:normal;color:var(--faint);
  font-variant-numeric:tabular-nums}
.kk.nil{opacity:.55}
.kk.nil b{color:var(--dim)}
.deadline{display:flex;align-items:center;gap:16px;margin-top:26px;padding:15px 19px;
  border:1px solid var(--edge);border-radius:var(--r);background:rgba(255,107,107,.045);max-width:700px}
.dnum{font-family:var(--disp);font-size:38px;font-weight:620;letter-spacing:-.03em;color:var(--v1);
  font-variant-numeric:tabular-nums;line-height:1}
.dtxt{font-size:15px;color:var(--dim)}
.dtxt b{color:var(--ink);font-weight:600;display:block;font-size:15.5px;margin-bottom:2px}

.focus{display:flex;gap:18px;flex-wrap:wrap;padding:0 var(--pad) 34px}
.fc{flex:1 1 260px;border:1px solid var(--edge);border-radius:11px;padding:19px 21px;background:var(--card);
  cursor:pointer;transition:transform .22s cubic-bezier(.16,1,.3,1),border-color .22s,background .22s;
  text-align:left;color:inherit}
.fc:hover{transform:translateY(-3px);border-color:var(--edge2);background:var(--card2)}
.fc .k{font-family:var(--mono);font-size:14px;letter-spacing:.13em;text-transform:uppercase;
  color:var(--faint);margin-bottom:6px}
.fc .v{font-family:var(--disp);font-size:19.5px;font-weight:580;letter-spacing:-.015em;margin-bottom:3px}
.fc .w{font-family:var(--mono);font-size:14.5px;color:var(--dim)}

/* Fixed column counts rather than auto-fit. Auto-fit packed four columns onto
   a wide monitor, which reads as a wall. Two is the working default; a third
   only appears on genuinely huge screens. */
.grid{padding:0 var(--pad) 90px;display:grid;gap:30px;grid-template-columns:1fr}
@media(min-width:1000px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(min-width:2900px){.grid{grid-template-columns:repeat(3,1fr)}}
.c2{grid-column:span 2}.call{grid-column:1/-1}
@media(max-width:999px){.c2{grid-column:span 1}}
@media(max-width:999px){.c2,.call{grid-column:span 1}}
.card{border:1px solid var(--edge);border-radius:var(--r);scroll-margin-top:118px;
  background:linear-gradient(180deg,rgba(255,255,255,.022),transparent 40%),var(--card);
  overflow:hidden;opacity:0;transform:translateY(16px);
  transition:opacity .6s cubic-bezier(.16,1,.3,1),transform .6s cubic-bezier(.16,1,.3,1),border-color .25s}
.card.in{opacity:1;transform:none}
.card:hover{border-color:var(--edge2)}
.ch{display:flex;align-items:center;gap:12px;padding:20px 22px 16px;flex-wrap:wrap}
.ch h2{margin:0;font-family:var(--disp);font-size:18.5px;font-weight:580;letter-spacing:-.012em}
.ch .meta{margin-left:auto;font-family:var(--mono);font-size:14px;color:var(--faint)}
.flag{font-family:var(--mono);font-size:12.5px;letter-spacing:.09em;text-transform:uppercase;
  padding:2px 7px;border-radius:5px;border:1px solid var(--edge2);color:var(--dim)}
.flag.due{color:var(--v1);border-color:rgba(255,107,107,.35);background:rgba(255,107,107,.07)}
.flag.ok{color:var(--krb);border-color:rgba(61,220,151,.3);background:rgba(61,220,151,.06)}
.mini{background:rgba(255,255,255,.04);border:1px solid var(--edge);color:var(--dim);border-radius:7px;
  padding:3px 9px;font-family:var(--mono);font-size:12px;cursor:pointer;transition:.16s}
.mini:hover{color:var(--ink);border-color:var(--krb)}

table{width:100%;border-collapse:collapse}
/* The header row used to sit at the same weight and near the same tone as the
   data, so a table read as one undifferentiated block. It is now a band: its
   own slightly lighter surface, a firm bottom edge, brighter and heavier type.
   Contrast against that band goes from 4.69:1 to 6.98:1. */
thead th{background:rgba(158,180,225,.055);border-bottom:1px solid var(--edge2);
  position:relative;cursor:pointer;user-select:none}
thead th:hover{color:var(--ink)}
thead th[aria-sort=ascending]::after{content:" \\2191";color:var(--krb)}
thead th[aria-sort=descending]::after{content:" \\2193";color:var(--krb)}
th{font-family:var(--mono);font-size:12.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--dim);font-weight:600;text-align:left;padding:12px 22px 12px;white-space:nowrap}
/* First data row needs no line of its own - the band already draws it. */
thead + tbody tr:first-child td{border-top:0}
td{padding:14px 22px;border-top:1px solid rgba(158,180,225,.11);font-size:16.5px;line-height:1.45}
tbody tr{transition:background .16s}
tbody tr:nth-child(even){background:rgba(158,180,225,.028)}
tbody tr.click{cursor:pointer}
tbody tr.click:hover{background:rgba(148,170,220,.06)}
tbody tr.on{background:rgba(61,220,151,.10);box-shadow:inset 3px 0 0 var(--krb)}
.r{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums}
.mn{font-family:var(--mono);font-size:15px}
/* Table cells marked .dm carry real content - target servers, accounts,
   timestamps - not asides, so they sit at the middle tone (7.5:1) rather than
   the faintest one (4.7:1). The gap to primary text stays wide enough to keep
   the hierarchy. */
.dm{color:var(--dim)}
.nm{font-weight:620}
.cut{display:inline-block;max-width:44ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  vertical-align:bottom}
.tag{display:inline-block;font-family:var(--mono);font-size:12.5px;padding:2px 7px;border-radius:5px;
  border:1px solid;line-height:15px;white-space:nowrap}
.tag.v1{color:var(--v1);border-color:rgba(255,107,107,.32);background:rgba(255,107,107,.07)}
.tag.v2{color:var(--v2);border-color:rgba(245,184,65,.32);background:rgba(245,184,65,.07)}
.tag.krb{color:var(--krb);border-color:rgba(61,220,151,.3);background:rgba(61,220,151,.06)}
.tag.pol{color:var(--pol);border-color:rgba(167,139,250,.32);background:rgba(167,139,250,.07)}
.tag.n{color:var(--faint);border-color:var(--edge2)}
.restn{color:var(--faint);font-family:var(--mono);font-size:12px;margin-left:6px}
.sel-st{background:rgba(255,255,255,.04);border:1px solid var(--edge);color:var(--dim);border-radius:7px;
  padding:3px 8px;font-family:var(--mono);font-size:13px}
.done td{opacity:.42}
.empty{padding:34px 20px;text-align:center;color:var(--faint);font-size:15.5px}
.empty b{display:block;color:var(--dim);font-size:15.5px;margin-bottom:5px;font-weight:500}

.bar{display:flex;align-items:center;gap:9px;flex-wrap:wrap;padding:2px 22px 14px}
.search{flex:1 1 240px;min-width:160px;background:rgba(255,255,255,.035);border:1px solid var(--edge);
  color:var(--ink);border-radius:9px;padding:7px 11px;font-family:var(--mono);font-size:13px}
.search::placeholder{color:var(--faint)}
.search:focus{outline:none;border-color:var(--edge2);background:rgba(255,255,255,.06)}
.chipset{display:flex;gap:5px;flex-wrap:wrap}
.chip{background:rgba(255,255,255,.035);border:1px solid var(--edge);color:var(--dim);border-radius:8px;
  padding:5px 11px;font-family:var(--mono);font-size:13px;cursor:pointer;transition:.16s;white-space:nowrap}
.chip:hover{color:var(--ink);border-color:var(--edge2)}
.chip[aria-pressed=true]{background:rgba(255,255,255,.09);color:var(--ink);border-color:var(--edge2)}
.active{display:flex;gap:6px;flex-wrap:wrap;padding:0 17px 11px}
.afl{display:inline-flex;align-items:center;gap:7px;background:rgba(61,220,151,.09);
  border:1px solid rgba(61,220,151,.28);color:#9ff0cb;border-radius:8px;padding:4px 8px;
  font-family:var(--mono);font-size:12px}
.afl button{background:none;border:0;color:inherit;cursor:pointer;opacity:.7;padding:0 0 0 2px;font-size:15px}
.afl button:hover{opacity:1}
.clearall{background:none;border:0;color:var(--faint);font-family:var(--mono);font-size:12px;
  cursor:pointer;text-decoration:underline;text-underline-offset:3px}
.clearall:hover{color:var(--ink)}
.more{display:block;width:100%;background:rgba(255,255,255,.03);border:0;border-top:1px solid var(--edge);
  color:var(--dim);font-family:var(--mono);font-size:12.5px;padding:11px;cursor:pointer;transition:.16s}
.more:hover{background:rgba(255,255,255,.06);color:var(--ink)}

.bars{padding:14px 22px 20px}
.brow{margin-bottom:10px;cursor:pointer}
.brow:last-child{margin-bottom:0}
.brow:hover .blab{color:var(--ink)}
.blab{display:flex;justify-content:space-between;gap:10px;font-size:15.5px;margin-bottom:4px;
  color:var(--dim);transition:color .16s}
.blab .bn{font-family:var(--mono);font-size:12.5px;color:var(--faint);flex:none}
.blab .btx{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btr{height:4px;background:rgba(148,170,220,.09);border-radius:3px;overflow:hidden}
.bfl{height:100%;width:0;border-radius:3px;transition:width 1s cubic-bezier(.16,1,.3,1)}
.bfl.red{background:linear-gradient(90deg,#c94a4a,var(--v1))}
.bfl.amb{background:linear-gradient(90deg,#c08b2c,var(--v2))}

/* align-items must stretch: the columns need a definite height, otherwise the
   percentage heights of the bars inside resolve against nothing and collapse
   to zero. The bars are pushed to the bottom by .bcol's justify-content. */
.blocks{padding:14px 17px 6px;display:flex;align-items:stretch;gap:2px;height:150px}
.bcol{flex:1;display:flex;flex-direction:column;justify-content:flex-end;min-width:0;cursor:default;
  transition:opacity .16s}
.bcol:hover{opacity:.7}
.bcol span{display:block;transition:height .8s cubic-bezier(.16,1,.3,1)}
.axis{display:flex;justify-content:space-between;padding:4px 17px 14px;font-family:var(--mono);
  font-size:12px;color:var(--faint)}

.hm{padding:8px 20px 18px}
.hr{display:grid;grid-template-columns:20px repeat(24,1fr);gap:2px;align-items:center;margin-bottom:2px}
.hr .lb{font-family:var(--mono);font-size:12px;color:var(--faint)}
.hc{aspect-ratio:1;border-radius:2px;background:rgba(148,170,220,.05);transform:scale(.4);opacity:0;
  transition:transform .5s cubic-bezier(.16,1,.3,1),opacity .5s}
.hc.in{transform:scale(1);opacity:1}
.hc{cursor:pointer}
.hc:hover{outline:1px solid var(--ink);outline-offset:1px}
.hc.on{outline:2px solid var(--krb);outline-offset:1px}
.bcol{cursor:pointer}
.bcol:hover span{filter:brightness(1.25)}
.bcol.on span{filter:brightness(1.5)}
.bcol.on{outline:1px solid var(--krb);outline-offset:1px;border-radius:2px}
.hnote{font-family:var(--mono);font-size:14px;color:var(--dim);margin-top:11px;padding-top:10px;
  border-top:1px solid var(--edge)}
.hnote b{color:var(--v2);font-weight:500}

.scrim{position:fixed;inset:0;background:rgba(6,9,16,.60);backdrop-filter:blur(3px);opacity:0;
  pointer-events:none;transition:opacity .3s;z-index:70}
.scrim.on{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(540px,100%);background:#151d2b;
  border-left:1px solid var(--edge2);z-index:80;transform:translateX(100%);
  transition:transform .42s cubic-bezier(.16,1,.3,1);display:flex;flex-direction:column;
  box-shadow:-30px 0 70px rgba(0,0,0,.45)}
.drawer.on{transform:none}
.dh{padding:20px 22px 15px;border-bottom:1px solid var(--edge);display:flex;align-items:flex-start;gap:12px}
.dh h3{margin:0 0 6px;font-family:var(--disp);font-size:22px;font-weight:580;letter-spacing:-.02em}
.dh .when{font-family:var(--mono);font-size:14.5px;color:var(--faint)}
.x{background:rgba(255,255,255,.05);border:1px solid var(--edge);color:var(--dim);border-radius:8px;
  width:34px;height:34px;cursor:pointer;margin-left:auto;flex:none;transition:.16s;font-size:17px}
.x:hover{color:var(--ink);border-color:var(--edge2)}
.dbody{overflow-y:auto;padding:4px 0 26px;flex:1}
.expl{margin:15px 22px;padding:13px 15px;border:1px solid var(--edge);border-radius:11px;
  background:rgba(148,170,220,.04);font-size:16px;color:var(--dim);line-height:1.6}
.expl b{display:block;color:var(--ink);font-weight:600;margin-bottom:4px}
.grp{margin:17px 22px 0}
.grp .gk{font-family:var(--mono);font-size:12.5px;letter-spacing:.11em;text-transform:uppercase;
  color:var(--faint);padding-bottom:8px;border-bottom:1px solid var(--edge);margin-bottom:4px}
.fr{display:grid;grid-template-columns:150px 1fr;gap:14px;padding:9px 0;font-size:16px;
  border-bottom:1px solid rgba(148,170,220,.05)}
.fr:last-child{border-bottom:0}
.fr .fk{color:var(--faint);font-family:var(--mono);font-size:14px;padding-top:2px}
.fr .fv{font-family:var(--mono);font-size:15.5px;word-break:break-word}
.fr .fv.none{color:var(--faint)}
.dact{display:flex;gap:8px;flex-wrap:wrap;margin:19px 22px 0}
.dact button{flex:1 1 auto;background:rgba(255,255,255,.04);border:1px solid var(--edge);color:var(--dim);
  border-radius:9px;padding:10px 14px;font-family:var(--mono);font-size:14px;cursor:pointer;transition:.18s}
.dact button:hover{color:var(--ink);border-color:var(--krb);background:rgba(61,220,151,.07)}
.code{margin:15px 22px;background:#0c1119;border:1px solid var(--edge);border-radius:10px;padding:13px 15px;
  font-family:var(--mono);font-size:15px;color:var(--dim);white-space:pre-wrap;word-break:break-all;
  max-height:360px;overflow-y:auto}

@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
  .card{opacity:1;transform:none}.hc{opacity:1;transform:none}
}
@media(max-width:720px){
  .hin{gap:10px;overflow-x:auto}.hero{padding:30px var(--pad) 20px}
  .fr{grid-template-columns:1fr;gap:2px}.jump{overflow-x:auto;flex-wrap:nowrap}
}
</style>
</head>
<body>
<a class="skip" href="#sec-events">Skip to the event list</a>
<div class="stage">
<header><div class="hin">
  <div class="logo"><span class="orb" id="orb"></span><span id="brand">NTLM-Analyzer</span></div>
  <div class="tools">
    <div class="pill" id="range"></div>
    <select id="mach"></select>
    <button class="ghost" id="hide"></button>
    <button class="ghost" id="csv">CSV</button>
    <button class="ghost" id="logout" hidden>Logout</button>
    <div class="pill" id="lang"><button data-l="de">DE</button><button data-l="en">EN</button></div>
  </div>
</div></header>

<div class="jump" id="jump"></div>

<section class="hero">
  <div class="herotop">
    <div class="herotext">
      <div class="eyebrow" id="eyebrow"></div>
      <h1 class="thesis" id="thesis"></h1>
      <p class="sub" id="subline"></p>
    </div>
    <aside class="osdon" id="osdon"></aside>
  </div>
  <div class="handbar" id="handbar"></div>
  <div class="handkey" id="handkey"></div>
  <div class="deadline">
    <div class="dnum" id="days">0</div>
    <div class="dtxt"><b id="ddl_t"></b><span id="ddl_b"></span></div>
  </div>
</section>

<div class="focus" id="focus"></div>
<div class="grid" id="grid"></div>
</div>

<div class="scrim" id="scrim"></div>
<aside class="drawer" id="drawer" role="dialog" aria-modal="true">
  <div class="dh"><div><h3 id="dtitle"></h3><div class="when" id="dwhen"></div></div>
    <button class="x" id="dclose">&#10005;</button></div>
  <div class="dbody" id="dbody"></div>
</aside>
<script>
const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = s => document.querySelector(s);
const esc = s => (s == null ? "" : String(s)).replace(/[&<>"]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

const I18N = {
de: {
  doc_title:'NTLM-Analyzer', h1:'NTLM-Analyzer',
  intro:'Wer im Netzwerk verwendet noch das ältere NTLM-Anmeldeverfahren – und was läuft bereits sicher über Kerberos. Ziel ist, NTLM nach und nach abzulösen.',
  live:'Aktualisiert sich automatisch · zuletzt',
  drill_hint:'klicken, um die Ereignisse zu sehen', f_day:'Tag',
  osbar_lbl:'Agenten nach Betriebssystem', osbar_other:'weitere', osbar_unknown:'unbekannt',
  ev_capped:'die neuesten {n} geladen',
  tip_events:'Ereignisse', tip_share:'Anteil', tip_click:'klicken, um danach zu filtern',
  fl_dom:'Domänenebene', fl_for:'Gesamtstruktur', fl_raw:'Ebene {n}',
  fl_split_t:'Die Agenten melden unterschiedliche Werte',
  osdon_mid:'Agenten', osdon_old:'{n} vor Server 2019 – dort fehlen die 40xx-Ereignisse', osbar_tip:'Gezählt werden nur Maschinen mit Agent, nicht die gesamte Domäne',
  leg_goal:'Farbbedeutung', leg_bad:'NTLMv1 · unsicher', leg_old:'NTLMv2 · veraltet', leg_good:'Kerberos · sicher',
  range:'Zeitraum', r7d:'7 Tage', r30d:'30 Tage', rall:'Alles',
  lab_total:'NTLM gesamt', sub_total:'erfasste Vorgänge', tt_total:'Zählt jedes erfasste Ereignis im gewählten Zeitraum – NTLM, Kerberos und Domänenmeldungen zusammen. Klick zeigt die Liste.',
  lab_v1:'Unsicher', sub_v1:'NTLMv1 – zuerst ablösen', tt_v1:'Zählt Anmeldungen mit NTLMv1: Ereignis 4624 mit Version NTLMv1 sowie 4024/4025 (NTLMv1-SSO). Klick filtert die Liste.',
  lab_v2:'Veraltet', sub_v2:'NTLMv2 – besser, aber alt', tt_v2:'Zählt Anmeldungen mit NTLMv2 (4624 und 40xx mit Version NTLMv2). Besser als v1, aber weiterhin Relay-anfällig. Klick filtert die Liste.',
  lab_krb:'Schon sicher', sub_krb:'Dienste über Kerberos', tt_krb:'Zählt Dienste, die bereits Kerberos-Servicetickets ausstellen (Ereignis 4769). Zum Vergleich, keine Aufgabe. Klick springt zur Übersicht.',
  lab_src:'Beteiligte Computer', sub_src:'Quellen & Server', tt_src:'Zählt verschiedene Maschinen, die als Quelle oder Ziel in NTLM-Ereignissen auftauchen. Klick springt zur Domänen-Sicht.',
  lab_proc:'Erkannte Programme', sub_proc:'die NTLM auslösen', tt_proc:'Zählt verschiedene Programme aus 8001/4020 – die Abschalt-Blockerliste. Klick springt dorthin.',
  trend_h:'Verlauf',
  trend_p:'NTLM-Vorgänge im gewählten Zeitraum – diese Balken sollen über die Wochen gegen null gehen. Rot = NTLMv1, Gelb = NTLMv2, Grau = NTLM ohne Versionsangabe (Domäne/ausgehend). Kerberos steht zur Einordnung im Tooltip.',
  prog_h:'Programme, die noch NTLM verwenden',
  prog_p:'Diese Programme melden sich per NTLM nach außen an. Vor dem Abschalten von NTLM sollten sie geprüft oder umgestellt werden. „Kernel: SMB/HTTP.sys" bedeutet, die Anfrage kam aus dem Kernel-Modus (PID 4) – Dateifreigaben, aber auch WinRM, ADWS, SSRS oder das Remotedesktop-Gateway. Dort lässt sich kein einzelnes Programm benennen.',
  dom_h:'Wer nutzt NTLM – und wohin',
  dom_p:'Vom Domänencontroller gemeldet: welcher Computer sich per NTLM mit welchem Server verbindet. Die zuverlässigste Gesamtsicht – auch wenn kein Programmname ermittelbar ist.',
  b_insec:'unsicher', b_sec:'sicher', b_sec2:'sicher',
  v1_h:'Unsichere Anmeldungen nach Benutzer',
  v1_p:'NTLMv1 gilt als unsicher und sollte zuerst abgelöst werden. Diese Benutzer bzw. Konten haben sich noch damit angemeldet.',
  krb_h:'Läuft bereits über Kerberos',
  krb_p:'Diese Dienste nutzen schon das moderne, sichere Kerberos – hier ist alles in Ordnung. Nur zur Information. „RC4/DES" wäre eine schwächere Verschlüsselung, „AES" ist gut.',
  krba_h:'Konten, die schon Kerberos nutzen',
  krba_p:'Die „sichere Seite": Diese Konten haben sich bereits erfolgreich per Kerberos authentifiziert – mit den Diensten, die sie nutzen, und der Verschlüsselung. „AES" ist gut, „RC4/DES" wäre schwächer. Nur zur Information.',
  ag_h:'Maschinen & Auditing-Status',
  ag_p:'Welche Agents melden – und ob das nötige Auditing dort aktiv ist. Ein grüner Punkt heißt „vor Kurzem gemeldet". Rote Auditing-Markierungen erklären, warum eine Maschine evtl. keine Daten liefert.',
  ev_h:'Letzte Ereignisse',
  ev_p:'Die neuesten erfassten Vorgänge. „Kerberos-Fallback" bei einer Anmeldung heißt: Kerberos wurde versucht, scheiterte aber – meist ein SPN-, DNS- oder Zeitabgleichs-Problem. Mit den Schaltflächen filtern oder oben suchen.',
  th_prog:'Programm', th_target:'Zielserver', th_count:'Anzahl', th_users:'Benutzer', th_comps:'Computer (Anz.)', th_status:'Status', th_last:'Zuletzt',
  th_srccomp:'Computer (Quelle)', th_target2:'Zielserver', th_users2:'Benutzer', th_count2:'Anzahl', th_status2:'Status', th_last2:'Zuletzt',
  th_service:'Dienst', th_accounts:'Konten', th_count3:'Anzahl', th_enc:'Verschlüsselung', th_last3:'Zuletzt',
  th_account:'Konto', th_services:'Dienste', th_tickets:'Tickets', th_enc2:'Verschlüsselung', th_last4:'Zuletzt',
  th_machine:'Maschine', th_type:'Typ', th_status3:'Status', th_lastrep:'Zuletzt gemeldet',
  th_time:'Zeit', th_kind:'Art', th_users3:'Benutzer', th_prog2:'Programm', th_tgtsrc:'Ziel / Quelle', th_comp:'Computer',
  search_ph:'Suchen: Benutzer, Programm, Server, Computer …',
  f_a_t:'Filtert die Ereignisliste und den CSV-Export (nicht die Kennzahlen oben)',
  lt2:'Interaktiv (lokal am Gerät)', lt3:'Netzwerk (Freigabe, RPC – hier entsteht der meiste NTLM)',
  lt4:'Batch (geplante Aufgabe)', lt5:'Dienst (Dienststart)',
  lt7:'Entsperren (Bildschirmsperre)', lt8:'Netzwerk-Klartext (Passwort im Klartext, z. B. Basic-Auth)',
  lt9:'Neue Anmeldeinformationen (runas /netonly)', lt10:'Remoteinteraktiv (RDP)',
  lt11:'Zwischengespeichert interaktiv (gespeicherte Domänenanmeldung)',
  lt12:'Zwischengespeichert remoteinteraktiv', lt13:'Zwischengespeichertes Entsperren',
  btn_exc:'Ausnahmeliste erzeugen', exc_copy:'Kopieren', exc_copied:'Kopiert!',
  exc_entries:'{n} Einträge (nur offene)', exc_empty:'Keine offenen Einträge – nichts zu tun.',
  exc_gpo_out:'Einfügen in: Netzwerksicherheit: NTLM einschränken: Remoteserverausnahmen für die NTLM-Authentifizierung hinzufügen',
  exc_gpo_dom:'Einfügen in: Netzwerksicherheit: NTLM einschränken: Serverausnahmen in dieser Domäne hinzufügen (auf den DCs)',
  exc_note:'Eine Ausnahme ist ein Aufschub, kein Fix – die Liste weiter abarbeiten.',
  b_krbfail:'Kerberos-Fehlschlag',
  tt_krbfail:'Kerberos wurde versucht und scheiterte – der Fehlercode nennt die Ursache. Auf Systemen ohne die 2025er-Ereignisse ist das die Frühwarnung vor NTLM-Fallback.',
  d_ppath:'Programmpfad',
  d_fcode:'Kerberos-Fehlercode',
  rid_k0x6:'Kerberos: Konto unbekannt (0x6)',
  rid_k0x7:'Kerberos: SPN nicht gefunden (0x7)',
  rid_k0xe:'Kerberos: Verschlüsselungstyp nicht unterstützt (0xE)',
  rid_k0x12:'Kerberos: Konto deaktiviert, abgelaufen oder gesperrt (0x12)',
  rid_k0x1b:'Kerberos: Delegierung nicht erlaubt (0x1B)',
  rid_k0x25:'Kerberos: Uhrzeitabweichung zu groß (0x25)',
  fix_etype:'Verschlüsselungstypen des Kontos prüfen (msDS-SupportedEncryptionTypes) – oft ein Nur-RC4-Konto gegen AES-only-Richtlinie',
  fix_acct:'Kontostatus prüfen: deaktiviert, abgelaufen oder gesperrt – kein SPN-Problem',
  fix_clock:'Zeitsynchronisation prüfen (w32tm /resync) – Kerberos erlaubt maximal 5 Minuten Abweichung',
  eid_4624:'Erfolgreiche Anmeldung (Security-Log). Nur hier steht die NTLM-Version – der DC sieht jede Domänenanmeldung.',
  eid_4769:'Kerberos-Serviceticket angefordert – dieser Dienst läuft bereits über Kerberos.',
  eid_8001:'Ausgehender NTLM-Verkehr dieser Maschine, mit dem verursachenden Programm.',
  eid_8002:'Eingehender NTLM ohne DC-Beteiligung (lokale Konten, Loopback) – nennt den annehmenden Dienst.',
  eid_8003:'Eingehender NTLM mit Domänenkonto auf einem Mitgliedsserver – wer kam von wo.',
  eid_8004:'DC-Prüfung einer NTLM-Anmeldung aus der Domäne (über den sicheren Kanal).',
  eid_8005:'NTLM direkt gegen den Domänencontroller selbst.',
  eid_8006:'NTLM-Anfrage aus einer vertrauten Domäne.',
  eid_4001:'BLOCKIERT: ausgehender NTLM wurde durch die Deny-Richtlinie verhindert (Gegenstück zu 8001).',
  eid_4002:'BLOCKIERT: eingehender NTLM verhindert (Gegenstück zu 8002).',
  eid_4003:'BLOCKIERT: eingehender NTLM mit Domänenkonto verhindert (Gegenstück zu 8003).',
  eid_4004:'BLOCKIERT: Domänenanmeldung per NTLM verhindert – feuert auch beim MS-CHAPv2-Blindfleck (0xc0000418).',
  eid_4005:'BLOCKIERT: NTLM direkt gegen den DC verhindert (Gegenstück zu 8005).',
  eid_4006:'BLOCKIERT: NTLM aus vertrauter Domäne verhindert (Gegenstück zu 8006).',
  eid_4020:'Erweitertes Client-Audit (Server 2025/24H2): ausgehender NTLM mit Version, Prozess und Grund.',
  eid_4021:'Erweitertes Client-Audit mit erkanntem Sicherheits-Downgrade.',
  eid_4022:'Erweitertes Server-Audit: eingehender NTLM auf diesem Server.',
  eid_4023:'Erweitertes Server-Audit mit erkanntem Downgrade.',
  eid_4024:'NTLMv1-abgeleitete SSO-Anmeldung erkannt (Audit) – ab Oktober 2026 standardmäßig blockiert.',
  eid_4025:'NTLMv1-abgeleitete SSO-Anmeldung BLOCKIERT (Enforce aktiv).',
  eid_4030:'Erweitertes DC-Audit: NTLM domänenübergreifend, mit Version.',
  eid_4031:'Erweitertes DC-Audit: domänenübergreifend, mit Downgrade.',
  eid_4032:'Erweitertes DC-Audit: NTLM innerhalb der Domäne, mit Version und Ziel-Betriebssystem.',
  eid_4033:'Erweitertes DC-Audit: innerhalb der Domäne, mit Downgrade.',
  tt_fb:'Kerberos wurde zuerst versucht und schlug fehl – meist SPN-, DNS- oder Zeitproblem. Die Ursache steht oft im „Warum NTLM?"-Abschnitt.',
  tt_down:'Sicherheits-Downgrade erkannt: NTLMv1, fehlende Kanalbindung oder fehlender MIC.',
  tt_th_lm:'LmCompatibilityLevel aus der Registry: welche NTLM-Versionen die Maschine noch erlaubt – unabhängig davon, was sie tatsächlich nutzt. Ziel: Stufe 5.',
  tt_th_oct:'Trifft die Oktober-2026-Umstellung (BlockNtlmv1SSO auf Enforce) diese Maschine? Credential Guard = ausgenommen.',
  tt_th_aud:'Welche Audit-Richtlinien auf der Maschine aktiv sind – ohne sie liefert sie keine Daten.',
  tt_th_tickets:'Anzahl der Kerberos-Servicetickets (4769) für dieses Konto im Zeitraum.',
  b_blocked:'blockiert', tt_blocked:'Eine Deny-Richtlinie hat diese Authentifizierung bereits verhindert (Ereignis 4001–4006). Das ist keine Aufgabe mehr, sondern Erfolgskontrolle – oder ein Alarm, falls unbeabsichtigt.',
  nav_heat:'Zeitmuster', heat_h:'Wann NTLM passiert',
  heat_p:'Wochentag gegen Tagesstunde. Batch-Jobs, Wartungsfenster und Wochenend-Skripte sind die Nachzügler, die eine Abschaltung sprengen – als Einzelzahl verstecken sie sich im Tagestrend, als Muster fallen sie auf.',
  heat_cell:'{d} {h}:00 – {n} Ereignisse', heat_peak:'Spitze: {d} {h}:00 Uhr mit {n} Ereignissen – bei ungewöhnlichen Zeiten lohnt der Blick auf geplante Aufgaben und Dienste.',
  d_mon:'Mo', d_tue:'Di', d_wed:'Mi', d_thu:'Do', d_fri:'Fr', d_sat:'Sa', d_sun:'So',
  th_trend2:'Verlauf', spark_tt:'Verlauf über {n} Tage – fallend ist gut, steigend heißt: hier kommt Neues dazu.',
  tt_th_trend:'Entwicklung dieser Zeile über den gewählten Zeitraum. Eine steigende Linie trotz sinkendem Gesamttrend ist die Zeile, die man zuerst anfasst.',
  b_policywarn:'Richtlinie: bricht später', b_policyblock:'von Richtlinie blockiert', b_secblock:'Sitzungssicherheit',
  eid_100:'NTLM abgelehnt, weil das Konto in der Gruppe „Geschützte Benutzer" ist. Für dieses Konto ist NTLM bereits heute gesperrt.',
  eid_101:'NTLM abgelehnt, weil Zugriffssteuerungs-Einschränkungen greifen (Authentifizierungsrichtlinie).',
  eid_301:'NTLM hat funktioniert, wird aber scheitern, sobald die Authentifizierungsrichtlinie erzwungen wird – eine Vorwarnung wie die Oktober-2026-Frist, nur aus anderer Richtung.',
  eid_4010:'Blockiert durch minimale Client-Sitzungssicherheit (NtlmMinClientSec).',
  eid_4011:'Blockiert durch minimale Server-Sitzungssicherheit (NtlmMinServerSec).',
  eid_4012:'Das DC-generierte NTLM-Geheimnis schlug fehl, der Client fiel auf das Domänenkennwort zurück.',
  eid_4015:'Ausgehender NTLM blockiert (nicht näher dokumentierte Variante zu 4001).',
  b_cg:'Credential Guard', b_cg_machine:'{n}× von Credential Guard blockiert',
  tt_cg_machine:'Credential Guard hat NTLM-Versuche auf dieser Maschine blockiert. Solche Versuche erreichen die normale NTLM-Protokollierung nicht – die Fundliste dieser Maschine ist dadurch unvollständig, nicht leer.',
  eid_4013:'NTLMv1-Versuch von Credential Guard blockiert – nennt Zielserver, Konto und aufrufenden Prozess. Das Programm versucht NTLMv1 und gehört auf die Liste.',
  eid_4014:'Credential Guard hat die Herausgabe des Credential Keys verweigert. Nennt nur den aufrufenden Prozess – ein Hinweis, dass hier NTLM versucht wird, ohne dass es regulär protokolliert wird.',
  b_os_old:'keine 40xx', tt_os_old:'Dieses System ist älter als Server 2025 / Windows 11 24H2 und kennt die erweiterten 40xx-Ereignisse nicht. Die Ursachenanalyse läuft hier über fehlgeschlagene Kerberos-Anfragen.',
  r_out:'Ausgehend', r_in:'Eingehend', r_dom:'Domäne',
  tt_restrict:'Eine Deny-Richtlinie ist aktiv – diese Maschine blockiert NTLM bereits. „deny-accounts" betrifft Konten, „deny-all" alles.',
  b_exc_cfg:'{n} Ausnahmen konfiguriert',
  tt_exc_cfg:'Bereits in der Gruppenrichtlinie eingetragene Ausnahmen:',
  b_logsize:'Log klein', log_default:'Standard, ~1 MB',
  tt_logsize:'Das NTLM/Operational-Log ist kleiner als 16 MB. Bei aktivem eingehendem Audit kann es zwischen zwei Abfragen überrollen – Ereignisse gehen dann verloren. Vergrößern mit: wevtutil sl Microsoft-Windows-NTLM/Operational /ms:20971520',
  d_os:'Server-Betriebssystem',
  d_mic:'MIC-Status', d_epa:'Kanalbindung (EPA)',
  relay_warn:'{n} von {t} Ereignissen mit Sicherheitsangaben sind relay-gefährdet (MIC ungeschützt oder EPA fehlt) – diese zuerst angehen.',
  relay_ok:'Alle {t} Ereignisse mit Sicherheitsangaben sind MIC-geschützt und nutzen Kanalbindung.',
  why_h:'Warum NTLM verwendet wurde', nav_why:'Warum NTLM',
  why_p:'Windows meldet bei jedem Rückfall den Grund (nur Server 2025 / Windows 11 24H2). Jede Ursache hat ihre eigene Abhilfe – das ist der kürzeste Weg vom Fund zur Lösung.',
  th_reason:'Ursache', th_fix:'Was hilft', th_count6:'Anzahl', th_progs:'Programme',
  th_machines2:'Maschinen', th_last7:'Zuletzt',
  rid_0:'Unbekannter Grund', rid_1:'Anwendung ruft NTLM direkt auf',
  rid_2:'Anmeldung mit lokalem Konto', rid_4:'Anmeldung mit Cloud-Konto',
  rid_5:'Zielname fehlte oder war leer', rid_6:'Zielname per Kerberos nicht auflösbar',
  rid_7:'Zielname enthält eine IP-Adresse', rid_8:'Zielname im AD doppelt vergeben',
  rid_9:'Keine Sichtverbindung zu einem Domänencontroller',
  rid_10:'NTLM über Loopback aufgerufen', rid_11:'NTLM mit Null-Session aufgerufen',
  fix_app:'Anwendung auf Negotiate umstellen – sonst Hersteller fragen',
  fix_local:'Domänenkonto statt lokalem Konto; LocalKDC kommt 2026',
  fix_cloud:'Entra-ID-Anmeldung, kein NTLM-Ersatz nötig',
  fix_spn:'SPN prüfen: fehlt, ist falsch oder doppelt (setspn -X findet Dubletten)',
  fix_ip:'Auf Hostnamen umstellen – über eine IP ist Kerberos nicht möglich',
  fix_dc:'Netzweg zum DC prüfen (Firewall, Segmentierung); IAKerb kommt 2026',
  fix_loop:'Meist RPC-Endpoint-Mapper; die beiden RPC-Richtlinien prüfen',
  fix_null:'Anonyme Verbindung – Aufrufer identifizieren und abstellen',
  fix_unklar:'Ursache prüfen – Windows meldet hier keine bekannte ID',
  k_relay:'Relay-gefährdet', k_relay_s:'ohne MIC oder EPA',
  nav_label:'Abschnitte', nav_prog:'Programme', nav_inc:'Dienste', nav_v1sso:'NTLMv1-SSO',
  nav_v1:'NTLMv1', nav_dom:'Domäne', nav_krb:'Kerberos', nav_mach:'Maschinen', nav_ev:'Ereignisse',
  g_machine:'Maschine', g_all_mach:'Alle Maschinen', g_hidedone:'Erledigte ausblenden',
  th_oct:'Okt. 2026', oct_enf:'schon enforce', oct_cg:'Credential Guard', oct_aff:'betroffen', oct_unk:'unklar',
  tt_oct_enf:'BlockNtlmv1SSO steht bereits auf Enforce – die Umstellung im Oktober 2026 ändert hier nichts mehr.',
  tt_oct_cg:'Credential Guard ist konfiguriert. Die Umstellung im Oktober 2026 greift auf solchen Maschinen nicht, weil Credential Guard NTLMv1-Kryptografie ohnehin verhindert.',
  tt_oct_aff:'BlockNtlmv1SSO steht auf Audit und Credential Guard ist aus: Diese Maschine ist von der Umstellung im Oktober 2026 betroffen. NTLMv1-abgeleitete Anmeldungen brechen dann.',
  tt_oct_unk:'Credential Guard ließ sich aus der Registry nicht sicher bestimmen. Moderne Windows-Versionen aktivieren es teils standardmäßig, ohne einen Wert zu setzen – bitte auf der Maschine prüfen.',
  th_lm:'NTLM-Stufe', lm_ok:'nur NTLMv2', lm_bad:'NTLMv1 erlaubt', lm_mid:'sendet v2',
  lm_unset:'nicht gesetzt',
  tt_lm5:'LmCompatibilityLevel 5: sendet und akzeptiert ausschließlich NTLMv2. Das ist der Zielzustand vor dem Abschalten.',
  tt_lm_low:'LmCompatibilityLevel 0–2: die Maschine akzeptiert noch LM bzw. NTLMv1. Das gehört als Erstes auf Stufe 5 gehoben.',
  tt_lm_mid:'LmCompatibilityLevel 3–4: sendet NTLMv2, akzeptiert als Server aber noch schwächere Antworten. Ziel ist Stufe 5.',
  tt_lm_unset:'LmCompatibilityLevel ist nicht gesetzt und verhält sich wie Stufe 3: sendet NTLMv2, akzeptiert aber noch schwächere Antworten. Ziel ist Stufe 5.',
  cov_ok:'Datenbasis: {d} Tage – ausreichend für eine belastbare Aussage.',
  cov_warn:'Datenbasis: erst {d} von empfohlenen {t} Tagen. Wöchentliche Aufgaben und Batch-Jobs sind womöglich noch nicht gelaufen – eine leere Fundliste sagt jetzt wenig aus.',
  inc_h:'Dienste, die NTLM annehmen',
  inc_p:'Die Gegenrichtung: welcher Dienst auf diesen Maschinen eingehenden NTLM annimmt. Braucht die Richtlinie „Eingehenden NTLM-Datenverkehr überwachen“ – ohne sie bleibt dieser Abschnitt leer.',
  th_mach2:'Maschine', th_svc:'Dienst / Prozess', th_count5:'Anzahl', th_users5:'Konten',
  th_status5:'Status', th_last6:'Zuletzt',
  lab_in:'Eingehend', sub_in:'NTLM angenommen', tt_in:'Zu den annehmenden Diensten springen',
  b_ip:'Ziel ist eine IP', tt_ip:'Kerberos braucht einen Namen mit SPN – über eine IP-Adresse ist es technisch nicht möglich. Auf Hostnamen umstellen.',
  f_a_all:'Alle Konten', f_a_user:'Nur Personen', f_a_mach:'Nur Computer',
  f_all:'Alle', f_v1:'Nur unsicher', f_v2:'Nur veraltet', f_out:'Programme', f_dom:'Domäne',
  csv:'CSV-Export', csv_t:'Aktuelle Auswahl als CSV herunterladen',
  g_logout:'Abmelden', g_logout_t:'Sitzung auf dem Server beenden',
  more:'weitere', b_v1:'NTLMv1 · unsicher', b_v2:'NTLMv2 · veraltet', b_krb:'Kerberos · sicher',
  b_dom:'NTLM (Domäne)', b_out:'NTLM ausgehend', b_fb:'Kerberos-Fallback',
  hb_on:'aktiv', hb_off:'still',
  au_out_on:'Ausgehend', au_out_off:'Ausgehend aus', au_dom_on:'Domäne', au_dom_off:'Domäne aus',
  st_offen:'offen', st_arbeit:'in Arbeit', st_erledigt:'erledigt', again:'wieder aktiv', what:'Was tun?',
  type_dc:'Domänencontroller', type_member:'Server/Client',
  hint_smb:'<b>Dateifreigabe-Zugriff über NTLM.</b> Häufigste Ursache: Zugriff per <b>IP statt Hostname</b> – Kerberos braucht einen Namen mit SPN. Netzlaufwerke, Verknüpfungen, Skripte und geplante Tasks von \\\\10.x.x.x auf \\\\SERVERNAME umstellen. Ebenfalls prüfen: Geräte außerhalb der Domäne (NAS, Drucker, Scanner) – die können kein Kerberos zur Domäne.',
  hint_proc:'<b>Programm nutzt NTLM direkt.</b> Prüfen: Unterstützt die Anwendung Kerberos bzw. „Windows-integrierte Anmeldung" (Hersteller-Doku)? Verbindet sie per IP statt Hostname? Hat das Dienstkonto des Ziels einen SPN (<b>setspn -L KONTO</b>)? Wenn nichts davon geht: Kandidat für die NTLM-Ausnahmeliste beim späteren Abschalten.',
  hint_dom:'<b>Quellcomputer nutzt NTLM zum Ziel.</b> Zum Eingrenzen auf dem Quellcomputer das ausgehende Audit aktivieren (Agent mit <b>--enable-outgoing-audit</b>) – dann erscheint dort der auslösende Prozess im Panel „Programme". Klassiker: Zugriff per IP statt Hostname, veraltete Clients, Geräte außerhalb der Domäne.',
  hint_fb:'<b>Kerberos wurde versucht und scheiterte</b> – erst dann NTLM-Fallback. Prüfen: fehlender oder doppelter SPN (<b>setspn -Q ...</b>, Duplikate mit setspn -X), DNS (Zugriff über den echten Hostnamen, nicht IP), Zeitabgleich (über 5 Minuten Abweichung bricht Kerberos) und ggf. Vertrauensstellung.',
  hint_rc4:'<b>Kerberos läuft, aber mit schwacher RC4-Verschlüsselung.</b> Am (Dienst-)Konto AES aktivieren: Attribut <b>msDS-SupportedEncryptionTypes</b> auf AES128/AES256 setzen und danach das Kontopasswort einmal ändern, damit AES-Schlüssel erzeugt werden.',
  trend_empty:'Noch keine Daten im gewählten Zeitraum.',
  tip_nover:'ohne Version',
  empty_blockers:'Noch keine ausgehenden NTLM-Programme erfasst.',
  empty_domain:'Noch keine Domänen-Meldungen (vom Domänencontroller).',
  empty_v1:'Keine unsicheren NTLMv1-Anmeldungen – sehr gut.',
  empty_krb:'Noch keine Kerberos-Daten erfasst.',
  empty_krba:'Noch keine Kerberos-Konten erfasst – sobald Konten Servicetickets ziehen, erscheinen sie hier.',
  empty_agents:'Noch keine Agent-Meldungen. Der Agent meldet seinen Status bei jedem Lauf.',
  empty_events:'Keine Ereignisse für diese Auswahl.',
  b_deadline:'Deadline', v1sso_h:'NTLMv1-SSO – funktioniert ab Oktober 2026 nicht mehr',
  v1sso_p:'Windows meldet hier die Nutzung NTLMv1-abgeleiteter Anmeldedaten. Microsoft stellt im Oktober 2026 automatisch auf Blockieren um – diese Zugriffe brechen dann von selbst, unabhängig von euren eigenen Richtlinien.',
  th_user4:'Benutzer', th_target4:'Ziel', th_count4:'Anzahl', th_state4:'Zustand',
  th_status4:'Status', th_last5:'Zuletzt',
  st_used:'wird genutzt', st_blocked:'bereits blockiert',
  lab_v1sso:'NTLMv1-SSO', sub_v1sso:'bricht im Okt. 2026', tt_v1sso:'Zu den NTLMv1-SSO-Funden springen',
  b_down:'Downgrade · unsicher', d_reason:'Grund',
  d_title:'Ereigniseigenschaften', d_log:'Protokoll', d_eid:'Ereignis-ID',
  d_rid:'Datensatz-ID', d_time:'Protokolliert', d_comp:'Computer',
  d_user:'Benutzer', d_dom:'Domäne', d_kind:'Art', d_ver:'NTLM-Version',
  d_auth:'Auth-Weg', d_proc:'Prozess', d_target:'Zielserver',
  d_ws:'Arbeitsstation', d_ip:'IP-Adresse', d_lt:'Anmeldetyp',
  d_enc:'Verschlüsselung',
  as_of:'Stand: ',
  hero_eyebrow:'{m} {ua} · {n} {ud} Datenbasis',
  u_agent:'Agent', u_agents:'Agenten', u_day:'Tag', u_days:'Tage',
  hero_thesis:'Noch {p} % aller Anmeldungen <span class="fade">laufen über NTLM.</span>',
  hero_down:'Zu Beginn des Zeitraums waren es {was} %.',
  hero_up:'Zu Beginn waren es {was} % — der Anteil steigt gerade.',
  hero_flat:'Der Anteil bewegt sich im Zeitraum kaum.',
  hero_tail:'{p} Programme und {u} Konten halten den Rest — angeführt von {top}.',
  hero_tail_nl:'{p} Programme und {u} Konten halten den Rest.',
  hero_ddl_t:'Tage bis Oktober 2026',
  hero_ddl_b:'Dann stellt Windows NTLMv1-SSO standardmäßig auf Blockieren um. Was dann noch NTLMv1 spricht, bricht von selbst.',
  foc_big:'Größter Posten', foc_big_w:'{n}× · {m} Maschinen',
  foc_win:'Schnellster Gewinn', foc_win_w:'{n}× · Ziel ist eine IP-Adresse',
  foc_due:'Vor der Frist', foc_due_w:'{n}× NTLMv1 · bricht im Oktober',
  foc_odd:'Unerwartet', foc_odd_w:'{n}× außerhalb der Bürozeiten',
  top_h:'Meistgenutzte Ziele',
},
en: {
  doc_title:'NTLM-Analyzer', h1:'NTLM-Analyzer',
  intro:'Who on the network still uses the legacy NTLM authentication – and what already runs securely over Kerberos. The goal is to phase NTLM out step by step.',
  live:'Refreshes automatically · last',
  drill_hint:'click to see the events', f_day:'Day',
  osbar_lbl:'Agents by OS', osbar_other:'others', osbar_unknown:'unknown',
  ev_capped:'newest {n} loaded',
  tip_events:'Events', tip_share:'Share', tip_click:'click to filter by this',
  fl_dom:'Domain level', fl_for:'Forest level', fl_raw:'level {n}',
  fl_split_t:'Agents report different values',
  osdon_mid:'agents', osdon_old:'{n} predate Server 2019 – no 40xx events there', osbar_tip:'Counts reporting machines only, not the whole domain',
  leg_goal:'Color legend', leg_bad:'NTLMv1 · insecure', leg_old:'NTLMv2 · outdated', leg_good:'Kerberos · secure',
  range:'Time range', r7d:'7 days', r30d:'30 days', rall:'All',
  lab_total:'NTLM total', sub_total:'recorded events', tt_total:'Counts every recorded event in the selected range - NTLM, Kerberos and domain reports combined. Click shows the list.',
  lab_v1:'Insecure', sub_v1:'NTLMv1 – replace first', tt_v1:'Counts NTLMv1 logons: event 4624 with version NTLMv1 plus 4024/4025 (NTLMv1 SSO). Click filters the list.',
  lab_v2:'Outdated', sub_v2:'NTLMv2 – better, but old', tt_v2:'Counts NTLMv2 logons (4624 and 40xx with version NTLMv2). Better than v1, but still relay-prone. Click filters the list.',
  lab_krb:'Already secure', sub_krb:'services via Kerberos', tt_krb:'Counts services already issuing Kerberos service tickets (event 4769). For contrast, not a to-do. Click jumps to the overview.',
  lab_src:'Computers involved', sub_src:'sources & servers', tt_src:'Counts distinct machines appearing as source or target in NTLM events. Click jumps to the domain view.',
  lab_proc:'Programs detected', sub_proc:'that trigger NTLM', tt_proc:'Counts distinct programs from 8001/4020 - the shutdown-blocker list. Click jumps there.',
  trend_h:'Trend',
  trend_p:'NTLM activity in the selected time range – these bars should approach zero over the weeks. Red = NTLMv1, yellow = NTLMv2, gray = NTLM without version info (domain/outgoing). Kerberos is shown in the tooltip for context.',
  prog_h:'Programs still using NTLM',
  prog_p:'These programs authenticate outward via NTLM. Before disabling NTLM they should be reviewed or reconfigured. "Kernel: SMB/HTTP.sys" means the request came from kernel mode (PID 4) – file shares, but also WinRM, ADWS, SSRS or the Remote Desktop Gateway. No single program can be named there.',
  dom_h:'Who uses NTLM – and where to',
  dom_p:'Reported by the domain controller: which computer connects to which server via NTLM. The most reliable overall view – even when no program name can be determined.',
  b_insec:'insecure', b_sec:'secure', b_sec2:'secure',
  v1_h:'Insecure logons by user',
  v1_p:'NTLMv1 is considered insecure and should be replaced first. These users or accounts still logged on with it.',
  krb_h:'Already running over Kerberos',
  krb_p:'These services already use modern, secure Kerberos – all good here. For information only. "RC4/DES" would be weaker encryption, "AES" is good.',
  krba_h:'Accounts already using Kerberos',
  krba_p:'The "safe side": these accounts have already authenticated successfully via Kerberos – with the services they use and the encryption. "AES" is good, "RC4/DES" would be weaker. For information only.',
  ag_h:'Machines & auditing status',
  ag_p:'Which agents report – and whether the required auditing is enabled there. A green dot means "reported recently". Red auditing badges explain why a machine may not deliver data.',
  ev_h:'Recent events',
  ev_p:'The latest recorded activity. "Kerberos fallback" on a logon means Kerberos was attempted but failed – usually an SPN, DNS or clock-skew issue. Filter with the buttons or search above.',
  th_prog:'Program', th_target:'Target server', th_count:'Count', th_users:'Users', th_comps:'Computers (no.)', th_status:'Status', th_last:'Last seen',
  th_srccomp:'Computer (source)', th_target2:'Target server', th_users2:'Users', th_count2:'Count', th_status2:'Status', th_last2:'Last seen',
  th_service:'Service', th_accounts:'Accounts', th_count3:'Count', th_enc:'Encryption', th_last3:'Last seen',
  th_account:'Account', th_services:'Services', th_tickets:'Tickets', th_enc2:'Encryption', th_last4:'Last seen',
  th_machine:'Machine', th_type:'Type', th_status3:'Status', th_lastrep:'Last reported',
  th_time:'Time', th_kind:'Kind', th_users3:'User', th_prog2:'Program', th_tgtsrc:'Target / source', th_comp:'Computer',
  search_ph:'Search: user, program, server, computer …',
  f_a_t:'Filters the event list and the CSV export (not the metric cards above)',
  lt2:'Interactive (locally at the device)', lt3:'Network (file share, RPC – where most NTLM comes from)',
  lt4:'Batch (scheduled task)', lt5:'Service (service start-up)',
  lt7:'Unlock (screen lock)', lt8:'Network cleartext (password sent in clear, e.g. basic auth)',
  lt9:'New credentials (runas /netonly)', lt10:'Remote interactive (RDP)',
  lt11:'Cached interactive (stored domain logon)',
  lt12:'Cached remote interactive', lt13:'Cached unlock',
  btn_exc:'Generate exception list', exc_copy:'Copy', exc_copied:'Copied!',
  exc_entries:'{n} entries (open items only)', exc_empty:'No open items - nothing to do.',
  exc_gpo_out:'Paste into: Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication',
  exc_gpo_dom:'Paste into: Network security: Restrict NTLM: Add server exceptions in this domain (on the DCs)',
  exc_note:'An exception is a stay of execution, not a fix - keep working the list down.',
  b_krbfail:'Kerberos failure',
  tt_krbfail:'Kerberos was attempted and failed - the failure code names the cause. On systems without the 2025 events this is the early warning before NTLM fallback.',
  d_ppath:'Program path',
  d_fcode:'Kerberos failure code',
  rid_k0x6:'Kerberos: account unknown (0x6)',
  rid_k0x7:'Kerberos: SPN not found (0x7)',
  rid_k0xe:'Kerberos: encryption type not supported (0xE)',
  rid_k0x12:'Kerberos: account disabled, expired or locked out (0x12)',
  rid_k0x1b:'Kerberos: delegation not allowed (0x1B)',
  rid_k0x25:'Kerberos: clock skew too great (0x25)',
  fix_etype:'Check the account\'s encryption types (msDS-SupportedEncryptionTypes) - often an RC4-only account against an AES-only policy',
  fix_acct:'Check the account state: disabled, expired or locked out - not an SPN problem',
  fix_clock:'Check time sync (w32tm /resync) - Kerberos allows at most 5 minutes of skew',
  eid_4624:'Successful logon (Security log). The only classic event carrying the NTLM version - the DC sees every domain logon.',
  eid_4769:'Kerberos service ticket requested - this service already runs over Kerberos.',
  eid_8001:'Outgoing NTLM from this machine, including the originating program.',
  eid_8002:'Incoming NTLM without DC involvement (local accounts, loopback) - names the accepting service.',
  eid_8003:'Incoming NTLM with a domain account on a member server - who came from where.',
  eid_8004:'DC validation of an NTLM logon from the domain (over the secure channel).',
  eid_8005:'NTLM straight against the domain controller itself.',
  eid_8006:'NTLM request from a trusted domain.',
  eid_4001:'BLOCKED: outgoing NTLM prevented by the deny policy (twin of 8001).',
  eid_4002:'BLOCKED: incoming NTLM prevented (twin of 8002).',
  eid_4003:'BLOCKED: incoming NTLM with a domain account prevented (twin of 8003).',
  eid_4004:'BLOCKED: domain NTLM logon prevented - also fires for the MS-CHAPv2 blind spot (0xc0000418).',
  eid_4005:'BLOCKED: NTLM straight to the DC prevented (twin of 8005).',
  eid_4006:'BLOCKED: NTLM from a trusted domain prevented (twin of 8006).',
  eid_4020:'Enhanced client auditing (Server 2025/24H2): outgoing NTLM with version, process and reason.',
  eid_4021:'Enhanced client auditing with a detected security downgrade.',
  eid_4022:'Enhanced server auditing: incoming NTLM on this server.',
  eid_4023:'Enhanced server auditing with a detected downgrade.',
  eid_4024:'NTLMv1-derived SSO credentials detected (audit) - blocked by default from October 2026.',
  eid_4025:'NTLMv1-derived SSO credentials BLOCKED (enforce active).',
  eid_4030:'Enhanced DC auditing: cross-domain NTLM, with version.',
  eid_4031:'Enhanced DC auditing: cross-domain, with downgrade.',
  eid_4032:'Enhanced DC auditing: same-domain NTLM, with version and target OS.',
  eid_4033:'Enhanced DC auditing: same-domain, with downgrade.',
  tt_fb:'Kerberos was tried first and failed - usually an SPN, DNS or clock issue. The cause often shows in the "Why NTLM?" section.',
  tt_down:'Security downgrade detected: NTLMv1, missing channel binding or missing MIC.',
  tt_th_lm:'LmCompatibilityLevel from the registry: which NTLM versions this machine still permits - regardless of what it actually uses. Target: level 5.',
  tt_th_oct:'Will the October 2026 change (BlockNtlmv1SSO to enforce) hit this machine? Credential Guard = exempt.',
  tt_th_aud:'Which audit policies are active on the machine - without them it delivers no data.',
  tt_th_tickets:'Number of Kerberos service tickets (4769) for this account in the range.',
  b_blocked:'blocked', tt_blocked:'A deny policy already prevented this authentication (event 4001-4006). No longer a to-do but a success check - or an alarm if unintended.',
  nav_heat:'Timing', heat_h:'When NTLM happens',
  heat_p:'Weekday against hour of day. Batch jobs, maintenance windows and weekend scripts are the stragglers that break a shutdown - as a single figure they hide in the daily trend, as a pattern they stand out.',
  heat_cell:'{d} {h}:00 - {n} events', heat_peak:'Peak: {d} at {h}:00 with {n} events - for unusual hours it is worth checking scheduled tasks and services.',
  d_mon:'Mon', d_tue:'Tue', d_wed:'Wed', d_thu:'Thu', d_fri:'Fri', d_sat:'Sat', d_sun:'Sun',
  th_trend2:'Trend', spark_tt:'Trend across {n} days - falling is good, rising means something new is coming in.',
  tt_th_trend:'How this row developed over the selected range. A rising line despite a falling overall trend is the row to tackle first.',
  b_policywarn:'Policy: breaks later', b_policyblock:'blocked by policy', b_secblock:'session security',
  eid_100:'NTLM rejected because the account is a member of Protected Users. NTLM is already off for this account today.',
  eid_101:'NTLM rejected because access control restrictions apply (authentication policy).',
  eid_301:'NTLM succeeded but will fail once the authentication policy is enforced - an early warning like the October 2026 deadline, from a different direction.',
  eid_4010:'Blocked by minimum client session security (NtlmMinClientSec).',
  eid_4011:'Blocked by minimum server session security (NtlmMinServerSec).',
  eid_4012:'The DC-generated NTLM secret failed, so the client fell back to the domain password.',
  eid_4015:'Outgoing NTLM blocked (an undocumented variant of 4001).',
  b_cg:'Credential Guard', b_cg_machine:'{n}× blocked by Credential Guard',
  tt_cg_machine:'Credential Guard blocked NTLM attempts on this machine. Such attempts never reach the regular NTLM audit path - this machine\'s findings are incomplete rather than empty.',
  eid_4013:'NTLMv1 attempt blocked by Credential Guard - names target server, account and calling process. The program is attempting NTLMv1 and belongs on the list.',
  eid_4014:'Credential Guard refused to hand out the credential key. Only names the calling process - a hint that NTLM is being attempted here without being logged normally.',
  b_os_old:'no 40xx', tt_os_old:'This system predates Server 2025 / Windows 11 24H2 and does not know the enhanced 40xx events. Cause analysis here runs on failed Kerberos requests instead.',
  r_out:'Outgoing', r_in:'Incoming', r_dom:'Domain',
  tt_restrict:'A deny policy is active - this machine already blocks NTLM. "deny-accounts" covers accounts, "deny-all" covers everything.',
  b_exc_cfg:'{n} exceptions configured',
  tt_exc_cfg:'Exceptions already present in Group Policy:',
  b_logsize:'log small', log_default:'default, ~1 MB',
  tt_logsize:'The NTLM/Operational log is smaller than 16 MB. With incoming auditing enabled it can roll over between two polls - events are then lost. Enlarge with: wevtutil sl Microsoft-Windows-NTLM/Operational /ms:20971520',
  d_os:'Server OS',
  d_mic:'MIC status', d_epa:'Channel binding (EPA)',
  relay_warn:'{n} of {t} events carrying security info are relay-exposed (MIC unprotected or EPA missing) - tackle these first.',
  relay_ok:'All {t} events carrying security info are MIC-protected and use channel binding.',
  why_h:'Why NTLM was used', nav_why:'Why NTLM',
  why_p:'Windows reports the reason for every fallback (Server 2025 / Windows 11 24H2 only). Each cause has its own fix - this is the shortest path from finding to remedy.',
  th_reason:'Reason', th_fix:'What helps', th_count6:'Count', th_progs:'Programs',
  th_machines2:'Machines', th_last7:'Last seen',
  rid_0:'Unknown reason', rid_1:'Application called NTLM directly',
  rid_2:'Local account logon', rid_4:'Cloud account logon',
  rid_5:'Target name was missing or empty', rid_6:'Target name could not be resolved by Kerberos',
  rid_7:'Target name contains an IP address', rid_8:'Target name is duplicated in Active Directory',
  rid_9:'No line of sight to a domain controller',
  rid_10:'NTLM called over loopback', rid_11:'NTLM called with a null session',
  fix_app:'Switch the application to Negotiate - otherwise ask the vendor',
  fix_local:'Use a domain account instead of a local one; LocalKDC arrives 2026',
  fix_cloud:'Entra ID logon, no NTLM replacement needed',
  fix_spn:'Check the SPN: missing, wrong or duplicated (setspn -X finds duplicates)',
  fix_ip:'Switch to host names - Kerberos cannot work over an IP address',
  fix_dc:'Check the network path to a DC (firewall, segmentation); IAKerb arrives 2026',
  fix_loop:'Usually the RPC endpoint mapper; review the two RPC policies',
  fix_null:'Anonymous connection - identify the caller and stop it',
  fix_unklar:'Investigate - Windows reported no known ID here',
  k_relay:'Relay-exposed', k_relay_s:'no MIC or EPA',
  nav_label:'Sections', nav_prog:'Programs', nav_inc:'Services', nav_v1sso:'NTLMv1 SSO',
  nav_v1:'NTLMv1', nav_dom:'Domain', nav_krb:'Kerberos', nav_mach:'Machines', nav_ev:'Events',
  g_machine:'Machine', g_all_mach:'All machines', g_hidedone:'Hide done',
  th_oct:'Oct 2026', oct_enf:'already enforce', oct_cg:'Credential Guard', oct_aff:'affected', oct_unk:'unclear',
  tt_oct_enf:'BlockNtlmv1SSO is already set to enforce - the October 2026 change makes no difference here.',
  tt_oct_cg:'Credential Guard is configured. The October 2026 change does not apply to such machines, because Credential Guard already prevents NTLMv1 cryptography.',
  tt_oct_aff:'BlockNtlmv1SSO is on audit and Credential Guard is off: this machine is affected by the October 2026 change. NTLMv1-derived logons will break then.',
  tt_oct_unk:'Credential Guard could not be determined reliably from the registry. Modern Windows may enable it by default without setting a value - please verify on the machine.',
  th_lm:'NTLM level', lm_ok:'NTLMv2 only', lm_bad:'NTLMv1 allowed', lm_mid:'sends v2',
  lm_unset:'not set',
  tt_lm5:'LmCompatibilityLevel 5: sends and accepts NTLMv2 only. This is the target state before switching NTLM off.',
  tt_lm_low:'LmCompatibilityLevel 0-2: this machine still accepts LM or NTLMv1. Raising it to level 5 is the first thing to do.',
  tt_lm_mid:'LmCompatibilityLevel 3-4: sends NTLMv2 but as a server still accepts weaker responses. The target is level 5.',
  tt_lm_unset:'LmCompatibilityLevel is not set and behaves like level 3: sends NTLMv2 but still accepts weaker responses. The target is level 5.',
  cov_ok:'Data basis: {d} days - enough for a meaningful conclusion.',
  cov_warn:'Data basis: only {d} of the recommended {t} days. Weekly tasks and batch jobs may not have run yet - an empty findings list means little at this point.',
  inc_h:'Services accepting NTLM',
  inc_p:'The other direction: which service on these machines accepts incoming NTLM. Needs the "Audit Incoming NTLM Traffic" policy - without it this section stays empty.',
  th_mach2:'Machine', th_svc:'Service / process', th_count5:'Count', th_users5:'Accounts',
  th_status5:'Status', th_last6:'Last seen',
  lab_in:'Incoming', sub_in:'NTLM accepted', tt_in:'Jump to the accepting services',
  b_ip:'target is an IP', tt_ip:'Kerberos needs a name with an SPN - over an IP address it is technically impossible. Switch to host names.',
  f_a_all:'All accounts', f_a_user:'People only', f_a_mach:'Computers only',
  f_all:'All', f_v1:'Insecure only', f_v2:'Outdated only', f_out:'Programs', f_dom:'Domain',
  csv:'CSV export', csv_t:'Download the current selection as CSV',
  g_logout:'Log out', g_logout_t:'End the session on the server',
  more:'more', b_v1:'NTLMv1 · insecure', b_v2:'NTLMv2 · outdated', b_krb:'Kerberos · secure',
  b_dom:'NTLM (domain)', b_out:'NTLM outgoing', b_fb:'Kerberos fallback',
  hb_on:'active', hb_off:'quiet',
  au_out_on:'Outgoing', au_out_off:'Outgoing off', au_dom_on:'Domain', au_dom_off:'Domain off',
  st_offen:'open', st_arbeit:'in progress', st_erledigt:'done', again:'active again', what:'What to do?',
  type_dc:'Domain controller', type_member:'Server/client',
  hint_smb:'<b>File-share access over NTLM.</b> Most common cause: access by <b>IP instead of hostname</b> – Kerberos needs a name with an SPN. Switch mapped drives, shortcuts, scripts and scheduled tasks from \\\\10.x.x.x to \\\\SERVERNAME. Also check: devices outside the domain (NAS, printers, scanners) – they cannot do Kerberos against the domain.',
  hint_proc:'<b>Application uses NTLM directly.</b> Check: does the application support Kerberos / "Windows integrated authentication" (vendor docs)? Does it connect by IP instead of hostname? Does the target service account have an SPN (<b>setspn -L ACCOUNT</b>)? If none of that works: a candidate for the NTLM exception list when disabling later.',
  hint_dom:'<b>Source computer uses NTLM towards the target.</b> To narrow it down, enable the outgoing audit on the source computer (agent with <b>--enable-outgoing-audit</b>) – the originating process will then appear in the "Programs" panel there. Classics: access by IP instead of hostname, outdated clients, devices outside the domain.',
  hint_fb:'<b>Kerberos was attempted and failed</b> – only then the NTLM fallback. Check: missing or duplicate SPN (<b>setspn -Q ...</b>, duplicates via setspn -X), DNS (access via the real hostname, not the IP), clock skew (more than 5 minutes breaks Kerberos) and, if applicable, trusts.',
  hint_rc4:'<b>Kerberos works, but with weak RC4 encryption.</b> Enable AES on the (service) account: set the <b>msDS-SupportedEncryptionTypes</b> attribute to AES128/AES256, then change the account password once so AES keys are generated.',
  trend_empty:'No data in the selected time range yet.',
  tip_nover:'unversioned',
  empty_blockers:'No outgoing NTLM programs recorded yet.',
  empty_domain:'No domain reports yet (from the domain controller).',
  empty_v1:'No insecure NTLMv1 logons – excellent.',
  empty_krb:'No Kerberos data recorded yet.',
  empty_krba:'No Kerberos accounts recorded yet – they will appear as soon as accounts request service tickets.',
  empty_agents:'No agent reports yet. The agent reports its status on every run.',
  empty_events:'No events for this selection.',
  b_deadline:'Deadline', v1sso_h:'NTLMv1 SSO – stops working in October 2026',
  v1sso_p:'Windows reports the use of NTLMv1-derived credentials here. In October 2026 Microsoft switches the default to blocking – these will then break on their own, regardless of your own policies.',
  th_user4:'User', th_target4:'Target', th_count4:'Count', th_state4:'State',
  th_status4:'Status', th_last5:'Last seen',
  st_used:'in use', st_blocked:'already blocked',
  lab_v1sso:'NTLMv1 SSO', sub_v1sso:'breaks Oct 2026', tt_v1sso:'Jump to the NTLMv1 SSO findings',
  b_down:'downgrade · insecure', d_reason:'Reason',
  d_title:'Event properties', d_log:'Log name', d_eid:'Event ID',
  d_rid:'Record ID', d_time:'Logged', d_comp:'Computer',
  d_user:'User', d_dom:'Domain', d_kind:'Kind', d_ver:'NTLM version',
  d_auth:'Auth path', d_proc:'Process', d_target:'Target server',
  d_ws:'Workstation', d_ip:'IP address', d_lt:'Logon type',
  d_enc:'Encryption',
  as_of:'As of: ',
  hero_eyebrow:'{m} {ua} · {n} {ud} of data',
  u_agent:'agent', u_agents:'agents', u_day:'day', u_days:'days',
  hero_thesis:'Still {p} % of all logons <span class="fade">go through NTLM.</span>',
  hero_down:'At the start of the period it was {was} %.',
  hero_up:'It was {was} % at the start — the share is rising.',
  hero_flat:'The share has barely moved over the period.',
  hero_tail:'{p} programs and {u} accounts hold the rest — led by {top}.',
  hero_tail_nl:'{p} programs and {u} accounts hold the rest.',
  hero_ddl_t:'days until October 2026',
  hero_ddl_b:'Windows then switches NTLMv1 SSO to blocking by default. Whatever still speaks NTLMv1 breaks on its own.',
  foc_big:'Largest item', foc_big_w:'{n}× · {m} machines',
  foc_win:'Quickest win', foc_win_w:'{n}× · target is an IP address',
  foc_due:'Before the deadline', foc_due_w:'{n}× NTLMv1 · breaks in October',
  foc_odd:'Unexpected', foc_odd_w:'{n}× outside office hours',
  top_h:'Most-used targets',
}};

// Remembered across reloads. The browser language is only the first guess -
// switching and then pressing F5 used to throw the choice away, which is a real
// annoyance on a page people keep open all day. localStorage is avoided for
// anything data-bearing; a display preference is not that.
function storedLang(){
  try { const v = localStorage.getItem('ntlm.lang'); return v === 'de' || v === 'en' ? v : null; }
  catch(e){ return null; }   // private mode or storage disabled
}
let LANG = storedLang() ||
  ((navigator.language || 'de').toLowerCase().startsWith('de') ? 'de' : 'en');
const t = (k, v) => { let s = (I18N[LANG] && I18N[LANG][k]) || (I18N.de[k]) || k;
  if(v) for(const a in v) s = s.split('{' + a + '}').join(v[a]);
  return s; };
const LOCALE = () => LANG === 'de' ? 'de-DE' : 'en-GB';

// Stored timestamps are UTC without a marker; append Z so the browser converts.
function toLocal(s){ if(!s) return null;
  const d = new Date(String(s).replace(' ', 'T') + (/[Z+]/.test(String(s).slice(10)) ? '' : 'Z'));
  return isNaN(d.getTime()) ? null : d; }
function when(s){ const d = toLocal(s);
  if(!d) return esc((s || '').replace('T', ' ').slice(0, 16));
  const p = n => String(n).padStart(2, '0');
  return esc(d.getFullYear() + '-' + p(d.getMonth()+1) + '-' + p(d.getDate())
    + ' ' + p(d.getHours()) + ':' + p(d.getMinutes())); }
const TZOFF = () => -new Date().getTimezoneOffset();

const KINDC = {outgoing:'v2', incoming:'v2', domain:'v2', auth:'v2', kerberos:'krb', krbfail:'v2',
  cgblock:'v1', ntlmv1sso:'v1', policyblock:'pol', policywarn:'pol', secblock:'v1'};
const KINDK = {outgoing:'b_out', incoming:'b_dom', domain:'b_dom', auth:'b_fb', kerberos:'b_krb',
  krbfail:'b_krbfail', cgblock:'b_cg', ntlmv1sso:'b_deadline', policyblock:'b_policyblock',
  policywarn:'b_policywarn', secblock:'b_secblock'};
const kindName = k => I18N[LANG][KINDK[k]] ? t(KINDK[k]) : k;
// DATA.heat rows run Monday..Sunday - the server rotates strftime's %w,
// which is Sunday-first. DN() is Sunday-first too, so every read of a heat
// row index has to be converted or the whole grid sits one day off.
const HW = i => (i + 1) % 7;          // heat row index -> strftime %w
const DN = () => LANG === 'de' ? ['So','Mo','Di','Mi','Do','Fr','Sa']
                               : ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

// ---- Zustand -------------------------------------------------------------
const S = {range:'30d', mach:'', hideDone:false, q:'', kind:'', acct:'all', shown:60,
           bucket:'', wd:'', hr:'', pick:'', rsn:''};
           // bucket/wd/hr: drill-down from the charts, pick: from the handover bar
let DATA = null, TIMER = null;

// ---- shareable state -------------------------------------------------------
// The filter state lives in the URL so a view can be sent to a colleague or
// bookmarked. This is the only place the page reads anything from the address
// bar, so every value is validated against what it is allowed to be rather
// than trusted - an unknown range or a 200-character "kind" never reaches the
// query the collector runs, and nothing from here is ever written to the DOM
// without going through esc() first.
const URL_RULES = {
  range:  v => ['24h', '7d', '30d', 'all'].includes(v) ? v : null,
  mach:   v => v.length <= 64 ? v : null,
  q:      v => v.length <= 100 ? v : null,
  kind:   v => /^[a-z]{0,16}$/.test(v) ? v : null,
  acct:   v => ['all', 'people', 'computers'].includes(v) ? v : null,
  pick:   v => ['NTLMv1', 'NTLMv2', 'kerberos'].includes(v) ? v : null,
  rsn:    v => /^k?[0-9a-fA-Fx]{1,12}$/.test(v) ? v : null,
  bucket: v => /^\d{4}-\d{2}-\d{2}(T\d{2})?$/.test(v) ? v : null,
  wd:     v => /^[0-6]$/.test(v) ? v : null,
  hr:     v => /^([0-9]|1[0-9]|2[0-3])$/.test(v) ? v : null
};

// Absent parameters reset to their default rather than being left alone -
// otherwise going Back to the unfiltered view would keep the old filter in S
// while the URL claims there is none.
const URL_DEFAULTS = {range: '30d', mach: '', q: '', kind: '', acct: 'all',
                      pick: '', rsn: '', bucket: '', wd: '', hr: ''};

function readUrlState(){
  let p;
  try { p = new URLSearchParams(location.search); } catch(e){ return; }
  for(const k in URL_RULES){
    const raw = p.get(k);
    const ok = raw === null ? null : URL_RULES[k](raw);
    S[k] = ok !== null ? ok : URL_DEFAULTS[k];
  }
  LAST_QS = null;   // the URL is now the source of truth again
}

// Filter changes get their own history entry so Back returns to the previous
// view - that is what people expect after clicking through three charts. Typing
// in the search box only replaces, otherwise every keystroke would be an entry
// and Back would be useless.
let LAST_QS = null;

function writeUrlState(){
  const p = new URLSearchParams();
  for(const k in URL_RULES){
    const v = S[k];
    if(v !== '' && v !== null && v !== undefined && !(k === 'range' && v === '30d')
       && !(k === 'acct' && v === 'all')) p.set(k, v);
  }
  const qs = p.toString();
  if(qs === LAST_QS) return;
  let onlySearch = false;
  if(LAST_QS !== null){
    const a = new URLSearchParams(LAST_QS), b = new URLSearchParams(qs);
    a.delete('q'); b.delete('q');
    onlySearch = a.toString() === b.toString();
  }
  const url = qs ? '?' + qs : location.pathname;
  try {
    if(LAST_QS === null || onlySearch) history.replaceState(null, '', url);
    else history.pushState(null, '', url);
  } catch(e){}
  LAST_QS = qs;
}

function params(extra){
  const p = new URLSearchParams();
  p.set('range', S.range);
  if(S.mach) p.set('source', S.mach);
  p.set('tzoff', String(TZOFF()));
  // A weekday of 0 (Sunday) and hour 0 are falsy but perfectly valid, so these
  // are tested against '' rather than for truthiness.
  if(S.bucket) p.set('bucket', S.bucket);
  if(S.wd !== '') p.set('wd', S.wd);
  if(S.hr !== '') p.set('hr', S.hr);
  if(S.bucket || S.wd !== '' || S.hr !== '') p.set('nokrb', '1');
  // The bar counts ntlm_version for the two NTLM slices and kind for Kerberos -
  // the filter has to use the same columns or the row count would not match.
  // A reason filter and a version filter would both want the 'kind' parameter,
  // so they are mutually exclusive - selecting one clears the other.
  if(S.rsn){
    if(S.rsn.charAt(0) === 'k'){ p.set('kind', 'krbfail'); p.set('fcode', S.rsn.slice(1)); }
    else p.set('rid', S.rsn);
  }
  else if(S.pick === 'kerberos') p.set('kind', 'kerberos');
  else if(S.pick) p.set('version', S.pick);
  if(extra) for(const k in extra) if(extra[k]) p.set(k, extra[k]);
  return p;
}
async function load(){
  let r;
  try { r = await fetch('/api/data?' + params().toString()); }
  catch(e){ return; }
  if(r.status === 401 || r.status === 403){ window.location = '/login'; return; }
  DATA = await r.json();
  render();
}

// ---- Bausteine -----------------------------------------------------------
const tag = (cls, txt, ti) => '<span class="tag ' + cls + '"' +
  (ti ? ' title="' + esc(ti) + '"' : '') + '>' + esc(txt) + '</span>';
const emptyBox = (a, b) => '<div class="empty"><b>' + esc(a) + '</b>' + esc(b || '') + '</div>';
// Every table on the page goes through here, so sorting added once applies to
// all of them. Sorting happens on the rendered rows rather than on the data:
// each panel shapes its own rows, and re-sorting the source would mean
// teaching this helper about a dozen different record shapes.
const tbl = (heads, rows) => '<table class="srt"><thead><tr>' + heads.map((h, i) =>
  '<th tabindex="0" role="button" aria-sort="none" data-col="' + i + '"' +
  (h[1] ? ' class="' + h[1] + '"' : '') + '>' + esc(h[0]) + '</th>').join('') +
  '</tr></thead><tbody>' + rows + '</tbody></table>';

// Numbers must not sort as text - "9" before "45" is the classic wrong answer.
// A cell that parses as a number after stripping spaces and thousands dots is
// compared numerically, everything else by locale.
function cellKey(td){
  const t = (td ? td.textContent : '').trim();
  // Only a leading number counts. Several cells carry a badge after the value
  // ("172" plus a blocked count of "24"); stripping everything non-numeric
  // glued those into 17224 and the column sorted into nonsense.
  const m = t.match(/^-?[\d\u00a0.,]+/);
  if(m){
    const n = parseFloat(m[0].replace(/[\s\u00a0.]/g, '').replace(',', '.'));
    if(!isNaN(n)) return {num: n};
  }
  return {txt: t.toLowerCase()};
}

function sortTable(th){
  const table = th.closest('table');
  const body = table ? table.querySelector('tbody') : null;
  if(!body) return;
  const col = +th.dataset.col;
  const asc = th.getAttribute('aria-sort') !== 'ascending';
  const rows = [...body.rows];
  rows.sort((a, b) => {
    const x = cellKey(a.cells[col]), y = cellKey(b.cells[col]);
    if('num' in x && 'num' in y) return asc ? x.num - y.num : y.num - x.num;
    const xs = 'num' in x ? String(x.num) : x.txt, ys = 'num' in y ? String(y.num) : y.txt;
    return asc ? xs.localeCompare(ys) : ys.localeCompare(xs);
  });
  rows.forEach(r => body.appendChild(r));
  table.querySelectorAll('th').forEach(o => o.setAttribute('aria-sort', 'none'));
  th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');
}

document.addEventListener('click', function(e){
  const th = e.target.closest && e.target.closest('table.srt th');
  if(th) sortTable(th);
});
document.addEventListener('keydown', function(e){
  if(e.key !== 'Enter' && e.key !== ' ') return;
  const th = e.target.closest && e.target.closest('table.srt th');
  if(th){ e.preventDefault(); sortTable(th); }
});
const CARD = (id, title, flag, meta, body, cls, extra) =>
  '<section class="card ' + (cls || '') + '" id="' + id + '"><div class="ch"><h2>' + esc(title) + '</h2>' +
  (flag ? '<span class="flag ' + (flag[1] || '') + '">' + esc(flag[0]) + '</span>' : '') +
  (extra || '') + (meta ? '<span class="meta">' + esc(meta) + '</span>' : '') + '</div>' + body + '</section>';
// SQLite's GROUP_CONCAT(DISTINCT ...) cannot take a separator, so these lists
// arrive as "a,b,c" with no spaces - a wall of text in a wide column. Split
// them, show the first few and count the rest; the full list stays in the
// tooltip so nothing is lost.
function nameList(v, max){
  const all = String(v == null ? '' : v).split(',').map(x => x.trim()).filter(Boolean);
  if(!all.length) return '<span class="dm">\u2013</span>';
  const show = all.slice(0, max || 3), rest = all.length - show.length;
  return '<span title="' + esc(all.join(', ')) + '">' + esc(show.join(', ')) +
    (rest ? '<span class="restn">+' + rest + '</span>' : '') + '</span>';
}
// Encryption types arrive concatenated too. Each gets its own chip, and a weak
// one (RC4/DES) is coloured as a finding instead of hiding in a list.
function encTags(v){
  const all = String(v == null ? '' : v).split(',').map(x => x.trim()).filter(Boolean);
  if(!all.length) return '<span class="dm">\u2013</span>';
  return all.slice(0, 3).map(e => tag(/RC4|DES/i.test(e) ? 'v2' : 'krb', e)).join(' ') +
    (all.length > 3 ? '<span class="restn">+' + (all.length - 3) + '</span>' : '');
}
const stSel = (key, st) => '<select class="sel-st" data-key="' + esc(key) + '" onclick="event.stopPropagation()">' +
  ['offen','arbeit','erledigt'].map(v => '<option value="' + v + '"' +
    ((st || 'offen') === v ? ' selected' : '') + '>' + esc(t('st_' + v)) + '</option>').join('') + '</select>';
function spark(series){
  if(!series || series.length < 2) return '<span class="dm mn">&ndash;</span>';
  const v = series.map(x => x[1]), mx = Math.max.apply(null, v) || 1;
  const pts = v.map((n, i) => (i / (v.length - 1) * 56).toFixed(1) + ',' + (14 - n / mx * 12).toFixed(1)).join(' ');
  const d = v[v.length - 1] - v[0];
  const col = d < 0 ? 'var(--krb)' : d > 0 ? 'var(--v1)' : 'var(--faint)';
  return '<svg width="58" height="15" viewBox="0 0 58 15" aria-hidden="true"><polyline fill="none" stroke="' +
    col + '" stroke-width="1.2" points="' + pts + '"/></svg> <span class="mn" style="color:' + col + '">' +
    (d > 0 ? '+' : '') + d + '</span>';
}
function bars(rows, cls, attr){
  if(!rows.length) return null;
  const mx = rows[0][1] || 1;
  return '<div class="bars">' + rows.map(r =>
    '<div class="brow" ' + attr(r[0]) + ' data-p="' + (r[1] / mx * 100) + '">' +
    '<div class="blab"><span class="btx">' + esc(r[0]) + '</span><span class="bn">' + r[1] + '&times;</span></div>' +
    '<div class="btr"><div class="bfl ' + cls + '"></div></div></div>').join('') + '</div>';
}
function countTo(el, to){
  if(!el) return;
  if(calm){ el.textContent = to; return; }
  const t0 = performance.now();
  (function step(n){ const p = Math.min(1, (n - t0) / 900);
    el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
    if(p < 1) requestAnimationFrame(step); })(t0);
}

// ---- Kopfbereich ---------------------------------------------------------
function renderChrome(){
  document.documentElement.lang = LANG;
  // Set here, not in render(): renderChrome runs afterwards and overwrote it.
  // With several tabs open the same title on each says nothing; the share is
  // the one number worth having in the tab strip.
  const st0 = (DATA && DATA.stats) || {};
  const share0 = st0.total
    ? Math.round((st0.total - (st0.krb_ev || 0)) / st0.total * 100) : null;
  document.title = share0 === null ? t('doc_title')
                                   : t('doc_title') + ' \u2013 ' + share0 + ' % NTLM';
  $('#range').innerHTML = [['24h', t('range')], ['7d', t('r7d')], ['30d', t('r30d')], ['all', t('rall')]]
    .map(r => '<button data-r="' + r[0] + '"' + (S.range === r[0] ? ' aria-pressed="true"' : '') + '>' +
      esc(r[1]) + '</button>').join('');
  const src = (DATA && DATA.sources) || [];
  $('#mach').innerHTML = '<option value="">' + esc(t('g_all_mach')) + '</option>' +
    src.map(s => '<option' + (S.mach === s ? ' selected' : '') + '>' + esc(s) + '</option>').join('');
  $('#hide').textContent = t('g_hidedone');
  $('#logout').textContent = t('g_logout');
  $('#logout').title = t('g_logout_t');
  $('#hide').setAttribute('aria-pressed', S.hideDone);
  document.querySelectorAll('#lang button').forEach(b =>
    b.setAttribute('aria-pressed', b.dataset.l === LANG));
}
// A non-zero share must never print as "0.0 %" - that reads as nothing at all.
function pctTxt(n, tot){
  if(!tot || !n) return '0 %';
  const p = n / tot * 100;
  return p < 0.1 ? '<0.1 %' : p.toFixed(1) + ' %';
}
// Hover card for the handover bar. One card is reused and moved rather than
// one per segment, so nothing accumulates in the DOM on re-render. It follows
// the segment centre and is clamped to the bar so a slice at either end does
// not push it off screen.
function segTip(sg){
  const bar = $('#handbar'), tip = $('#segtip');
  if(!bar || !tip) return;
  if(!sg){ tip.classList.remove('on'); return; }
  const bw = bar.clientWidth;
  const r = sg.getBoundingClientRect(), br = bar.getBoundingClientRect();
  tip.innerHTML =
    '<div class="th"><i style="background:var(' + esc(sg.dataset.col) + ')"></i>' +
      esc(sg.dataset.nm) + '</div>' +
    '<div class="tr">' + esc(t('tip_events')) + '<b>' +
      Number(sg.dataset.n).toLocaleString(LANG === 'de' ? 'de-DE' : 'en-GB') + '</b></div>' +
    '<div class="tr">' + esc(t('tip_share')) + '<b>' + esc(sg.dataset.pc) + '</b></div>' +
    '<div class="tf">' + esc(t('tip_click')) + '</div>';
  const mid = r.left - br.left + r.width / 2;
  tip.style.left = Math.max(90, Math.min(bw - 90, mid)) + 'px';
  tip.classList.add('on');
}
// After a drill-down the events panel is what the user wants to look at.
function goEvents(){
  const el = document.getElementById('sec-events');
  if(el) el.scrollIntoView({behavior:'smooth', block:'start'});
}
// A light touch of inventory context. This counts the machines that report
// in, not every server in the domain - the note under the ring says so, because
// "3 x Server 2025" in a header otherwise reads as a domain-wide census.
const OS_FAM = v => {
  const s = String(v || '');
  let m = s.match(/Windows Server\s+(\d{4}(?:\s*R2)?)/i);
  if(m) return 'Server ' + m[1].replace(/\s+/g, ' ');
  m = s.match(/Windows\s+(11|10|8\.1|7)\b/i);
  if(m) return 'Windows ' + m[1];
  return s ? t('osbar_unknown') : '';
};
// Colour by age rather than by arbitrary hue: green is current, amber is
// getting on, red predates the 40xx auditing events entirely - which is
// exactly the group whose NTLM traffic is hardest to see.
const OS_COL = f => {
  if(/^Server 2025/.test(f))             return '#3ddc97';
  if(/^Windows 11/.test(f))              return '#7ce0bd';   // current, but a client
  if(/^Server 2022/.test(f))             return '#5ec8c0';
  if(/^Server 2019/.test(f))             return '#6f9fd8';
  if(/^Windows 10/.test(f))              return '#9a8fc0';
  if(/^Server 2016/.test(f))             return '#f5b841';
  if(/^Server (2012|2008|2003)/.test(f)) return '#ff6b6b';
  return '#4a5872';
};
const OS_OLD = f => /^Server (2003|2008|2012|2016)/.test(f);

// msDS-Behavior-Version -> product name. Mapped in the collector, not the
// agent: Microsoft adds levels over time, and a value we do not know yet should
// still show as "Level 11" rather than disappear. 8 and 9 were never used -
// Server 2019 and 2022 introduced no new functional level.
const FL_NAME = {'0':'2000', '1':'2003 interim', '2':'2003', '3':'2008',
                 '4':'2008 R2', '5':'2012', '6':'2012 R2', '7':'2016', '10':'2025'};
const flText = v => {
  if(v === null || v === undefined || v === '') return null;
  const n = FL_NAME[String(v)];
  return n ? 'Server ' + n : t('fl_raw', {n: v});
};
// A functional level is a property of the domain, not of one machine, so all
// agents should report the same value. Take the most common one and flag a
// disagreement rather than silently picking a winner.
function levelOf(field){
  const seen = {};
  (DATA.agents || []).forEach(a => { const v = a[field];
    if(v !== null && v !== undefined && v !== '') seen[v] = (seen[v] || 0) + 1; });
  const rows = Object.entries(seen).sort((a, b) => b[1] - a[1]);
  if(!rows.length) return null;
  return {val: rows[0][0], split: rows.length > 1};
}
function renderOsDonut(){
  const el = $('#osdon'); if(!el) return;
  const tally = {};
  (DATA.agents || []).forEach(a => { const f = OS_FAM(a.os_version); if(f) tally[f] = (tally[f] || 0) + 1; });
  let rows = Object.entries(tally).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const total = rows.reduce((n, r) => n + r[1], 0);
  // Count the ageing builds before folding small slices away, otherwise a
  // Server 2016 swallowed by "other" would drop out of the warning.
  const old = rows.filter(r => OS_OLD(r[0])).reduce((n, r) => n + r[1], 0);
  if(!total){ el.innerHTML = ''; return; }
  // A ring stops being readable past a handful of slices, so anything beyond
  // the top five is folded into one - the machines panel has the full list.
  if(rows.length > 6){
    const rest = rows.slice(5).reduce((n, r) => n + r[1], 0);
    rows = rows.slice(0, 5).concat([[t('osbar_other'), rest]]);
  }
  const R = 46, C = 2 * Math.PI * R;
  let off = 0;
  const arcs = rows.map(r => {
    const len = r[1] / total * C;
    const seg = '<circle cx="60" cy="60" r="' + R + '" fill="none" stroke="' + OS_COL(r[0]) +
      '" stroke-width="17" stroke-dasharray="' + len.toFixed(2) + ' ' + (C - len).toFixed(2) +
      '" stroke-dashoffset="' + (-off).toFixed(2) + '" transform="rotate(-90 60 60)">' +
      '<title>' + esc(r[0] + ' \u00b7 ' + r[1] + ' \u00b7 ' +
        (r[1] / total * 100).toFixed(0) + ' %') + '</title></circle>';
    off += len;
    return seg;
  }).join('');
  el.innerHTML =
    '<div class="oh">' + esc(t('osbar_lbl')) + '</div>' +
    '<div class="ow"><svg class="ring" width="120" height="120" viewBox="0 0 120 120">' +
      '<circle cx="60" cy="60" r="' + R + '" fill="none" stroke="rgba(158,180,225,.09)" stroke-width="17"/>' +
      arcs +
      '<text class="mid" x="60" y="58" text-anchor="middle" font-size="26">' + total + '</text>' +
      '<text class="midl" x="60" y="76" text-anchor="middle" font-size="11">' +
        esc(t('osdon_mid')) + '</text>' +
    '</svg><div class="leg">' +
      rows.map(r => '<div class="lr" title="' + esc(r[0]) + '">' +
        '<i style="background:' + OS_COL(r[0]) + '"></i><b>' + r[1] + '</b>' + esc(r[0]) + '</div>').join('') +
    '</div></div>' +
    '<div class="note">' + esc(old ? t('osdon_old', {n: old}) : t('osbar_tip')) + '</div>' +
    levelRow();
}
// Domain and forest functional level, shown once - it describes the directory,
// not any single machine.
function levelRow(){
  const d = levelOf('domain_level'), f = levelOf('forest_level');
  if(!d && !f) return '';
  const cell = (lbl, x) => {
    if(!x) return '';
    const txt = flText(x.val) || '\u2013';
    return '<div class="flr"><span>' + esc(lbl) + '</span><b>' + esc(txt) + '</b>' +
      (x.split ? '<em title="' + esc(t('fl_split_t')) + '">!</em>' : '') + '</div>';
  };
  return '<div class="fl">' + cell(t('fl_dom'), d) + cell(t('fl_for'), f) + '</div>';
}
function renderHero(){
  // stats.total counts every stored event, stats.krb counts Kerberos SERVICES.
  // The share has to compare NTLM events against Kerberos TICKETS.
  const st = DATA.stats, krb = st.krb_ev || 0, ntlm = Math.max(0, st.total - krb);
  const pct = (ntlm + krb) ? Math.round(ntlm / (ntlm + krb) * 100) : 0;
  const nAg = (DATA.agents || []).length, nDay = st.coverage_days;
  $('#eyebrow').textContent = t('hero_eyebrow',
    {m: nAg, n: nDay,
     ua: t(nAg === 1 ? 'u_agent' : 'u_agents'),
     ud: t(nDay === 1 ? 'u_day' : 'u_days')});
  $('#thesis').innerHTML = t('hero_thesis').replace('{p}', '<span class="big" id="pct">0</span>');
  const tr = DATA.trend || [];
  let was = pct;
  if(tr.length > 2){
    const cut = Math.max(1, Math.round(tr.length / 3));
    let n = 0, k = 0;
    tr.slice(0, cut).forEach(b => { n += b.v1 + b.v2 + b.other; k += b.krb || 0; });
    if(n + k) was = Math.round(n / (n + k) * 100);
  }
  const top = (DATA.blockers || [])[0];
  $('#subline').textContent =
    t(was > pct ? 'hero_down' : was < pct ? 'hero_up' : 'hero_flat', {was: was}) + ' ' +
    (top && top.process && top.process !== '-' && top.process !== '(unknown)'
      ? t('hero_tail', {p: st.procs, u: (DATA.v1_users || []).length, top: top.process})
      : t('hero_tail_nl', {p: st.procs, u: (DATA.v1_users || []).length}));
  const tot = st.v1 + st.v2 + krb || 1;
  // A segment below ~8 % is too narrow for its label - the text would be
  // clipped mid-word. Hide the in-segment label there; the counts are always
  // readable in the legend underneath, and the tooltip still has them.
  // A share of zero gets no segment at all - an empty coloured block would
  // claim the reader's attention for something that is not there. Segments
  // that do carry a value keep a minimum width (class "has") so a one-percent
  // share stays visible and its label is never cut mid-word: full
  // "name · count" where it fits, the bare count in a middle band, nothing
  // below that. The legend underneath and the tooltip always carry the number.
  // The bar is the picture; the readout underneath is the text. In a healthy
  // domain NTLMv1 is the smallest slice by far - exactly the one that matters
  // most - so putting names inside the segments guarantees the important one
  // goes unlabelled. Labels live in the readout, which always lists all three.
  // A segment only carries text when it is comfortably wide.
  // Every colour carries its own name, always - a slice you cannot read is a
  // slice you cannot act on. Narrow segments are widened to fit their label via
  // a min-width computed from the text, and the wide one shrinks to make room.
  // That trades a little geometric accuracy for legibility, so the label spells
  // out the true share and the readout underneath repeats it exactly.
  // No text inside the segments at all. Squeezing a label into a 1 % slice was
  // the source of every layout problem this bar has had - clipped words, then
  // widened slices that misstated the proportions. The bar is now purely the
  // picture; detail appears on hover, and the readout underneath always carries
  // the numbers. Nothing has to fit anywhere any more.
  $('#handbar').innerHTML =
    [['s1', st.v1, 'NTLMv1', 'NTLMv1', '--v1'], ['s2', st.v2, 'NTLMv2', 'NTLMv2', '--v2'],
     ['s3', krb, 'Kerberos', 'kerberos', '--krb']]
    .filter(x => x[1] > 0)
    .map(x => '<div class="seg has ' + x[0] + (S.pick === x[3] ? ' on' : '') +
      '" tabindex="0" role="button"' +
      ' data-w="' + (x[1] / tot * 100).toFixed(1) + '"' +
      ' data-pick="' + esc(x[3]) + '" data-nm="' + esc(x[2]) + '"' +
      ' data-n="' + x[1] + '" data-pc="' + esc(pctTxt(x[1], tot)) + '"' +
      ' data-col="' + x[4] + '"' +
      ' aria-label="' + esc(x[2] + ' ' + x[1] + ' ' + pctTxt(x[1], tot)) + '"></div>').join('') +
    '<div class="segtip" id="segtip" aria-hidden="true"></div>';
  setTimeout(function(){ document.querySelectorAll('.seg').forEach(function(s){
    s.style.width = s.dataset.w + '%';
    const b = s.querySelector('b'); if(b) b.style.opacity = 1; }); }, 100);
  // Always all three, including a zero - "NTLMv1 0" is a result worth reading,
  // and a category that silently vanishes reads as a rendering fault.
  $('#handkey').innerHTML = [['--v1', 'leg_bad', st.v1], ['--v2', 'leg_old', st.v2],
      ['--krb', 'leg_good', krb]]
    .map(x => '<span class="kk' + (x[2] ? '' : ' nil') + '">' +
      '<i style="background:var(' + x[0] + ')"></i>' +
      '<b>' + x[2] + '</b><em>' + pctTxt(x[2], tot) + '</em>' +
      esc(t(x[1])) + '</span>').join('');
  $('#ddl_t').textContent = t('hero_ddl_t');
  $('#ddl_b').textContent = t('hero_ddl_b');
  countTo($('#pct'), pct);
  countTo($('#days'), Math.max(0, Math.round((new Date(2026, 9, 14) - new Date()) / 864e5)));
  const orb = $('#orb'); if(orb) orb.className = 'orb';
}
function renderFocus(){
  const bl = DATA.blockers || [], v1u = DATA.v1_users || [], out = [];
  if(bl.length) out.push('<button class="fc" data-prog="' + esc(bl[0].process) + '"><div class="k">' +
    esc(t('foc_big')) + '</div><div class="v">' + esc(bl[0].process) + '</div><div class="w">' +
    esc(t('foc_big_w', {n: bl[0].n, m: bl[0].sources})) + '</div></button>');
  const ip = bl.filter(b => /\d+\.\d+\.\d+\.\d+/.test(b.target || ''))[0];
  if(ip) out.push('<button class="fc" data-prog="' + esc(ip.process) + '"><div class="k">' +
    esc(t('foc_win')) + '</div><div class="v">' + esc(ip.process) + '</div><div class="w">' +
    esc(t('foc_win_w', {n: ip.n})) + '</div></button>');
  if(v1u.length) out.push('<button class="fc" data-q="' + esc(v1u[0].name) + '"><div class="k">' +
    esc(t('foc_due')) + '</div><div class="v">' + esc(v1u[0].name) + '</div><div class="w">' +
    esc(t('foc_due_w', {n: v1u[0].n})) + '</div></button>');
  let pd = -1, ph = 0, pv = 0;
  (DATA.heat || []).forEach((row, d) => row.forEach((v, h) => { if(v > pv){ pv = v; pd = d; ph = h; } }));
  // HW(pd) is the real weekday: 0 Sunday, 6 Saturday.
  if(pd >= 0 && (HW(pd) === 0 || HW(pd) === 6 || ph < 6 || ph > 19))
    out.push('<button class="fc" data-go="sec-heat"><div class="k">' + esc(t('foc_odd')) +
      '</div><div class="v">' + esc(DN()[HW(pd)] + ', ' + String(ph).padStart(2, '0') + ':00') +
      '</div><div class="w">' + esc(t('foc_odd_w', {n: pv})) + '</div></button>');
  $('#focus').innerHTML = out.join('');
}

// ---- Abschnitte ----------------------------------------------------------
function secTrend(){
  const tr = DATA.trend || [];
  if(!tr.length) return CARD('sec-trend', t('trend_h'), [t('leg_goal')], '',
    emptyBox(t('trend_empty'), ''), 'c2');
  const mx = Math.max.apply(null, tr.map(b => b.v1 + b.v2 + b.other)) || 1;
  const body = '<div class="blocks">' + tr.map(b =>
    '<div class="bcol' + (S.bucket === b.b ? ' on' : '') + '" data-bucket="' + esc(b.b) +
    '" title="' + esc(b.b + ' \u00b7 ' + (b.v1 + b.v2 + b.other) + ' \u2013 ' + t('drill_hint')) + '">' +
    '<span data-h="' + (b.other / mx * 100) + '" style="height:0;background:var(--grey)"></span>' +
    '<span data-h="' + (b.v2 / mx * 100) + '" style="height:0;background:var(--v2)"></span>' +
    '<span data-h="' + (b.v1 / mx * 100) + '" style="height:0;background:var(--v1)"></span></div>').join('') +
    '</div><div class="axis">' + [0, .33, .66, 1].map(p => '<span>' +
      esc(tr[Math.round(p * (tr.length - 1))].b) + '</span>').join('') + '</div>';
  return CARD('sec-trend', t('trend_h'), null, DATA.trend_bucket === 'day' ? '' : t('range'), body, 'c2');
}
function secPrograms(){
  let bl = (DATA.blockers || []).slice();
  if(S.hideDone) bl = bl.filter(b => b.st !== 'erledigt');
  const body = bl.length ? tbl([[t('th_prog')], [t('th_target')], [t('th_count'), 'r'],
      [t('th_trend2')], [t('th_users')], [t('th_status')]],
    bl.map(b => '<tr class="click' + (b.st === 'erledigt' ? ' done' : '') +
      '" data-prog="' + esc(b.process) + '"><td class="nm">' + esc(b.process) + '</td>' +
      '<td class="mn dm"><span class="cut">' + esc(b.target || '\u2013') + '</span>' +
      (/\d+\.\d+\.\d+\.\d+/.test(b.target || '') ? ' ' + tag('v1', t('b_ip')) : '') + '</td>' +
      '<td class="r">' + b.n + (b.blocked ? ' ' + tag('v1', b.blocked) : '') + '</td>' +
      '<td>' + spark((DATA.spark || {})[b.process]) + '</td>' +
      '<td class="dm">' + nameList(b.who, 3) + '</td>' +
      '<td>' + stSel(b.key, b.st) + '</td></tr>').join(''))
    : emptyBox(t('empty_blockers'), '');
  return CARD('sec-programs', t('prog_h'), [t('nav_label')], t('exc_entries', {n: bl.length}),
    body, 'c2', '<button class="mini" id="excbtn">' + esc(t('btn_exc')) + '</button>');
}
function secTargets(){
  const m = {};
  (DATA.blockers || []).forEach(b => { if(b.target) m[b.target] = (m[b.target] || 0) + b.n; });
  (DATA.domain || []).forEach(d => { if(d.target) m[d.target] = (m[d.target] || 0) + d.n; });
  const rows = Object.keys(m).map(k => [k, m[k]]).sort((a, b) => b[1] - a[1]).slice(0, 8);
  return CARD('sec-top', t('top_h'), null, '',
    bars(rows, 'amb', n => 'data-q="' + esc(n) + '"') || emptyBox(t('empty_blockers'), ''));
}
function secV1(){
  const rows = (DATA.v1_users || []).slice(0, 8).map(u => [u.name, u.n]);
  return CARD('sec-v1', t('v1_h'), [t('b_deadline'), 'due'], '',
    bars(rows, 'red', n => 'data-q="' + esc(n) + '"') || emptyBox(t('empty_v1'), ''));
}
function secHeat(){
  return CARD('sec-heat', t('heat_h'), null, '', '<div class="hm" id="hm"></div>');
}
function fillHeat(){
  const el = $('#hm'); if(!el) return;
  const g = DATA.heat || [], names = DN();
  let mx = 0; g.forEach(r => r.forEach(v => { if(v > mx) mx = v; })); mx = mx || 1;
  let h = '<div class="hr"><div></div>';
  for(let i = 0; i < 24; i++) h += '<div class="lb" style="text-align:center">' + (i % 6 === 0 ? i : '') + '</div>';
  h += '</div>';
  for(let d = 0; d < 7; d++){ const wd = HW(d);
    h += '<div class="hr"><div class="lb">' + names[wd] + '</div>';
    for(let x = 0; x < 24; x++){ const n = (g[d] && g[d][x]) || 0, v = n / mx;
      h += '<div class="hc' + (String(S.wd) === String(wd) && String(S.hr) === String(x) ? ' on' : '') +
        '" data-wd="' + wd + '" data-hr="' + x +
        '" title="' + names[wd] + ' ' + x + ':00 \u00b7 ' + n +
        (n ? ' \u2013 ' + esc(t('drill_hint')) : '') + '"' +
        (v ? ' style="background:rgba(' + Math.round(190 + v * 65) + ',' + Math.round(120 - v * 13) +
          ',' + Math.round(95 - v * 30) + ',' + (0.22 + v * 0.72) + ')"' : '') + '></div>'; }
    h += '</div>'; }
  let pd = 0, ph = 0, pv = 0;
  g.forEach((r, d) => r.forEach((v, x) => { if(v > pv){ pv = v; pd = d; ph = x; } }));
  el.innerHTML = h + (pv ? '<div class="hnote">' + t('heat_peak',
    {d: names[HW(pd)], h: String(ph).padStart(2, '0'), n: pv}) + '</div>' : '');
  if(!calm && window.IntersectionObserver){
    new IntersectionObserver(function(es, o){ es.forEach(function(e){ if(!e.isIntersecting) return;
      el.querySelectorAll('.hc').forEach(function(c, i){ setTimeout(function(){ c.classList.add('in'); }, i * 3); });
      o.unobserve(e.target); }); }).observe(el);
  } else el.querySelectorAll('.hc').forEach(c => c.classList.add('in'));
}
function secWhy(){
  const rs = DATA.reasons || [];
  const body = rs.length ? tbl([[t('th_reason')], [t('th_fix')], [t('th_count2'), 'r']],
    rs.map(r => '<tr class="click' + (S.rsn === r.rid ? ' on' : '') +
      '" data-rsn="' + esc(r.rid) + '" title="' + esc(t('drill_hint')) + '">' +
      '<td class="nm">' + esc(t('rid_' + r.rid)) + '</td>' +
      '<td class="dm">' + esc(t('fix_' + r.cat)) + '</td><td class="r">' + r.n + '</td></tr>').join(''))
    : emptyBox(t('empty_events'), '');
  return CARD('sec-why', t('why_h'), [t('nav_label')], '', body);
}
function secDomain(){
  const d = DATA.domain || [];
  const body = d.length ? tbl([[t('th_comp')], [t('th_target')], [t('th_users')],
      [t('th_count3'), 'r'], [t('th_last')]],
    d.slice(0, 40).map(x => '<tr class="click" data-q="' + esc(x.workstation) + '">' +
      '<td class="nm">' + esc(x.workstation) + '</td><td class="mn dm">' + esc(x.target) + '</td>' +
      '<td class="dm">' + nameList(x.who, 3) + '</td><td class="r">' + x.n + '</td>' +
      '<td class="mn dm">' + when(x.last_seen) + '</td></tr>').join(''))
    : emptyBox(t('empty_domain'), '');
  return CARD('sec-domain', t('dom_h'), [t('nav_label')], String(d.length), body, 'c2');
}
function secIncoming(){
  const i = DATA.incoming || [];
  const body = i.length ? tbl([[t('th_machine')], [t('th_service')], [t('th_count4'), 'r'],
      [t('th_accounts'), 'r']],
    i.map(x => '<tr class="click" data-mach="' + esc(x.machine) + '"><td class="nm">' + esc(x.machine) +
      '</td><td class="dm">' + esc(x.process) + '</td><td class="r">' + x.n + '</td>' +
      '<td class="r dm">' + x.users + '</td></tr>').join(''))
    : emptyBox(t('empty_events'), '');
  return CARD('sec-incoming', t('inc_h'), [t('nav_label')], String(i.length), body);
}
function secSso(){
  const s = DATA.v1sso || [];
  const body = s.length ? tbl([[t('th_account')], [t('th_target')], [t('th_count5'), 'r'], [t('th_status')]],
    s.map(x => '<tr class="click" data-q="' + esc(x.user) + '"><td class="nm">' + esc(x.user) + '</td>' +
      '<td class="mn dm"><span class="cut">' + esc(x.target || '\u2013') + '</span></td>' +
      '<td class="r">' + x.n + '</td><td>' + stSel(x.key, x.st) + '</td></tr>').join(''))
    : emptyBox(t('empty_v1'), '');
  return CARD('sec-v1sso', t('v1sso_h'), [t('b_deadline'), 'due'], '', body);
}
function secKrb(){
  const k = DATA.kerberos || [];
  const body = k.length ? tbl([[t('th_service')], [t('th_count6'), 'r'], [t('th_enc')]],
    k.map(x => '<tr><td class="mn"><span class="cut">' + esc(x.service) + '</span></td>' +
      '<td class="r">' + x.n + '</td><td>' + encTags(x.enc) + '</td></tr>').join(''))
    : emptyBox(t('empty_krb'), '');
  return CARD('sec-kerberos', t('krb_h'), [t('leg_good'), 'ok'], '', body);
}
function secKrbAcc(){
  const k = DATA.kerberos_accounts || [];
  const body = k.length ? tbl([[t('th_account')], [t('th_services'), 'r'], [t('th_count6'), 'r'], [t('th_enc2')]],
    k.slice(0, 12).map(x => '<tr class="click" data-q="' + esc(x.account) + '">' +
      '<td class="mn"><span class="cut">' + esc(x.account) + '</span></td>' +
      '<td class="r dm">' + x.svc_count + '</td><td class="r">' + x.n + '</td>' +
      '<td>' + encTags(x.enc) + '</td></tr>').join(''))
    : emptyBox(t('empty_krba'), '');
  return CARD('sec-kacc', t('krba_h'), [t('leg_good'), 'ok'], '', body);
}
function secAgents(){
  const a = DATA.agents || [];
  const AU = {audit: t('au_out_on'), deny: t('au_out_on'), aus: t('au_out_off'), an: t('au_dom_on')};
  const body = a.length ? tbl([[t('th_machine')], [t('th_type')], [t('th_status2')], ['LmCompat'],
      [t('th_oct')], [t('th_count'), 'r'], [t('th_last')]],
    a.map(m => {
      const au = [];
      if(m.outgoing_audit && m.outgoing_audit !== 'aus') au.push(tag('krb', t('r_out')));
      if(m.incoming_audit && m.incoming_audit !== 'aus') au.push(tag('krb', t('r_in')));
      if(m.domain_audit === 'an') au.push(tag('krb', t('r_dom')));
      if(m.cg) au.push(tag('v1', t('b_cg_machine', {n: m.cg})));
      if(m.ntlm_log_kb && +m.ntlm_log_kb < 20480) au.push(tag('v2', t('b_logsize')));
      const lm = m.lm_level;
      const oct = m.cred_guard === 'on' ? tag('krb', t('oct_cg'))
        : m.block_v1sso === 'deny' ? tag('krb', t('oct_enf'))
        : lm && +lm >= 4 ? tag('v2', t('oct_aff')) : tag('n', t('oct_unk'));
      return '<tr class="click" data-mach="' + esc(m.source) + '"><td class="nm">' + esc(m.source) +
        ' ' + (m.is_dc ? tag('n', t('type_dc')) : '') + '</td>' +
        '<td class="dm">' + esc(m.os_version || '\u2013') +
        (m.os_version && !/2600\d|2[6-9]\d{3}/.test(m.os_version) ? ' ' + tag('n', t('b_os_old')) : '') + '</td>' +
        '<td>' + (au.join(' ') || '<span class="dm">\u2013</span>') + '</td>' +
        '<td>' + (lm ? tag(+lm >= 5 ? 'krb' : +lm >= 3 ? 'v2' : 'v1', lm) : '<span class="dm">\u2013</span>') + '</td>' +
        '<td>' + oct + '</td><td class="r">' + (m.events || 0) + '</td>' +
        '<td class="mn dm">' + when(m.last_seen) + '</td></tr>'; }).join(''))
    : emptyBox(t('empty_agents'), '');
  return CARD('sec-agents', t('ag_h'), null,
    t('cov_ok', {d: DATA.stats.coverage_days}), body, 'c2');
}
function secEvents(){
  return CARD('sec-events', t('ev_h'), null, '\u2013',
    '<div class="bar"><input class="search" id="q" placeholder="' + esc(t('search_ph')) + '">' +
    '<div class="chipset" id="kinds"></div></div><div class="active" id="active"></div>' +
    '<div id="events"></div>', 'call');
}
function renderEvents(){
  const all = DATA.events || [];
  const ql = S.q.toLowerCase();
  const list = all.filter(e =>
    (!S.kind || e.kind === S.kind) &&
    (S.acct === 'all' || (S.acct === 'comp') === /\$/.test(e.user || '')) &&
    (!ql || [e.user, e.process, e.target_server, e.workstation, e.source, e.process_path]
      .join(' ').toLowerCase().indexOf(ql) >= 0));
  // Announced to screen readers: after a drill-down the only thing that
  // changes above the fold is this count, and silently swapping it leaves
  // anyone not looking at the table with no feedback at all.
  const m = document.querySelector('#sec-events .meta');
  if(m && !m.getAttribute('aria-live')){
    m.setAttribute('aria-live', 'polite');
    m.setAttribute('aria-atomic', 'true');
  }
  if(m){
    const found = DATA.events_total !== undefined ? DATA.events_total : all.length;
    const capped = all.length < found;
    m.textContent = list.length + ' / ' + found.toLocaleString(LANG === 'de' ? 'de-DE' : 'en-GB') +
      (capped ? ' \u2013 ' + t('ev_capped', {n: DATA.events_limit}) : '');
  }
  const kinds = [''].concat(Object.keys(KINDC).filter(k => all.some(e => e.kind === k)));
  $('#kinds').innerHTML = kinds.map(k => '<button class="chip" data-k="' + k + '" aria-pressed="' +
    (S.kind === k) + '">' + esc(k ? kindName(k) : t('f_all')) + '</button>').join('') +
    ['all','people','comp'].map(a => '<button class="chip" data-a="' + a + '" aria-pressed="' +
      (S.acct === a) + '">' + esc(t(a === 'all' ? 'f_a_all' : a === 'people' ? 'f_a_user' : 'f_a_mach')) +
      '</button>').join('');
  const act = [];
  if(S.q) act.push(['q', t('search_ph').split(':')[0] + ': ' + S.q]);
  if(S.kind) act.push(['kind', kindName(S.kind)]);
  if(S.mach) act.push(['mach', S.mach]);
  if(S.rsn) act.push(['rsn', t('rid_' + S.rsn)]);
  if(S.pick) act.push(['pick', S.pick === 'kerberos' ? 'Kerberos' : S.pick]);
  if(S.bucket) act.push(['bucket', t('f_day') + ': ' + S.bucket]);
  if(S.wd !== '' || S.hr !== ''){
    const nm = DN();
    act.push(['when', (S.wd !== '' ? nm[+S.wd] + ' ' : '') +
                      (S.hr !== '' ? String(S.hr).padStart(2, '0') + ':00' : '')]);
  }
  $('#active').innerHTML = act.length ? act.map(a => '<span class="afl">' + esc(a[1]) +
    '<button data-clr="' + a[0] + '">&times;</button></span>').join('') +
    '<button class="clearall" data-clr="all">' + esc(t('again')) + '</button>' : '';
  if(!list.length){ $('#events').innerHTML = emptyBox(t('empty_events'), ''); return; }
  $('#events').innerHTML = tbl([[t('th_time')], [t('th_kind')], [t('th_users')], [t('th_prog')],
      [t('th_target')], [t('th_comp')], ['ID', 'r']],
    list.slice(0, S.shown).map((e, i) => '<tr class="click" data-ev="' + i + '">' +
      '<td class="mn dm">' + when(e.event_time) + '</td>' +
      '<td>' + tag(KINDC[e.kind] || 'n', kindName(e.kind)) +
        (e.ntlm_version ? ' ' + tag(e.ntlm_version === 'NTLMv1' ? 'v1' : 'v2', e.ntlm_version) : '') + '</td>' +
      '<td>' + esc(e.user || '\u2013') + '</td>' +
      '<td class="dm">' + esc(e.process || '\u2013') + '</td>' +
      '<td class="mn dm"><span class="cut">' + esc(e.target_server || e.workstation || '\u2013') + '</span></td>' +
      '<td class="dm">' + esc(e.source) + '</td>' +
      '<td class="r dm">' + e.event_id + '</td></tr>').join('')) +
    (list.length > S.shown ? '<button class="more" id="more">' + esc(t('more')) + '</button>' : '');
  window.__EVLIST = list;
}
function renderJump(){
  const items = [['sec-trend', 'trend_h', null], ['sec-programs', 'nav_prog', (DATA.blockers || []).length],
    ['sec-top', 'top_h', null], ['sec-v1', 'nav_v1', (DATA.v1_users || []).length],
    ['sec-heat', 'nav_heat', null], ['sec-why', 'nav_why', (DATA.reasons || []).length],
    ['sec-domain', 'nav_dom', (DATA.domain || []).length],
    ['sec-incoming', 'nav_inc', (DATA.incoming || []).length],
    ['sec-v1sso', 'nav_v1sso', (DATA.v1sso || []).length],
    ['sec-kerberos', 'nav_krb', (DATA.kerberos || []).length],
    ['sec-kacc', 'krba_h', (DATA.kerberos_accounts || []).length],
    ['sec-agents', 'nav_mach', (DATA.agents || []).length],
    ['sec-events', 'nav_ev', (DATA.events || []).length]];
  $('#jump').innerHTML = items.map(x => '<button class="jl' + (x[2] === 0 ? ' nil' : '') +
    '" data-go="' + x[0] + '">' + esc(t(x[1])) +
    (x[2] === null ? '' : ' <b>' + x[2] + '</b>') + '</button>').join('');
}

// ---- Schublade -----------------------------------------------------------
function openEvent(i){
  const e = (window.__EVLIST || [])[i]; if(!e) return;
  $('#dtitle').innerHTML = tag(KINDC[e.kind] || 'n', kindName(e.kind)) +
    '<span style="margin-left:8px">' + esc(t('d_eid')) + ' ' + e.event_id + '</span>';
  const d = toLocal(e.event_time);
  $('#dwhen').textContent = (d ? d.toLocaleString(LOCALE(), {weekday:'long', day:'2-digit',
    month:'long', hour:'2-digit', minute:'2-digit', second:'2-digit'}) : e.event_time) + ' \u00b7 ' + e.source;
  const row = (k, v, hint) => '<div class="fr"><div class="fk">' + esc(k) + '</div><div class="fv' +
    (v ? '' : ' none') + '">' + (v ? esc(v) : '\u2013') + (hint ? '<div style="color:var(--faint);' +
    'font-family:var(--text);font-size:11.5px;margin-top:3px">' + esc(hint) + '</div>' : '') + '</div></div>';
  const grp = (title, rows) => rows.join('').length ? '<div class="grp"><div class="gk">' + esc(title) +
    '</div>' + rows.join('') + '</div>' : '';
  const eidKey = 'eid_' + e.event_id, eidTxt = I18N[LANG][eidKey] ? t(eidKey) : '';
  const fk = e.failure_code ? ('rid_k' + String(e.failure_code).toLowerCase()) : '';
  const fhint = fk && I18N[LANG][fk] ? t(fk) : '';
  $('#dbody').innerHTML =
    (eidTxt ? '<div class="expl"><b>' + esc(t('d_eid')) + ' ' + e.event_id + '</b>' + esc(eidTxt) + '</div>' : '') +
    grp(t('d_comp'), [row(t('d_user'), e.user), row(t('d_dom'), e.domain),
      row(t('d_ws'), e.workstation), row(t('d_ip'), e.ip)]) +
    grp(t('th_target'), [row(t('d_target'), e.target_server), row(t('d_os'), e.server_os)]) +
    grp(t('th_prog'), [row(t('d_proc'), e.process), row(t('d_ppath'), e.process_path)]) +
    grp(t('d_kind'), [row(t('d_ver'), e.ntlm_version), row(t('d_auth'), e.auth_method),
      row(t('d_lt'), e.logon_type), row(t('d_enc'), e.enc_type), row(t('d_mic'), e.mic),
      row(t('d_epa'), e.epa)]) +
    grp(t('th_reason'), [row(t('d_reason'), e.reason), row(t('d_fcode'), e.failure_code, fhint),
      row(t('d_log'), e.log), row(t('d_rid'), e.record_id)]) +
    '<div class="dact">' +
      (e.process ? '<button data-prog="' + esc(e.process) + '">' + esc(e.process) + '</button>' : '') +
      (e.user ? '<button data-q="' + esc(e.user) + '">' + esc(e.user) + '</button>' : '') +
      '<button data-mach="' + esc(e.source) + '">' + esc(e.source) + '</button>' +
      '<button data-kind="' + esc(e.kind) + '">' + esc(kindName(e.kind)) + '</button></div>';
  openDrawer();
}
function openExceptions(){
  const rows = (DATA.blockers || []).filter(b => b.st !== 'erledigt' && b.target);
  const seen = {}, list = [];
  rows.forEach(b => { const n = String(b.target).replace(/^[A-Za-z]+\//, '');
    if(!seen[n]){ seen[n] = 1; list.push(n); } });
  list.sort();
  $('#dtitle').textContent = t('exc_gpo_out');
  $('#dwhen').textContent = t('exc_entries', {n: list.length});
  $('#dbody').innerHTML = '<div class="expl">' + esc(t('exc_note')) + '</div>' +
    (list.length ? '<div class="code">' + list.map(esc).join('\n') + '</div>'
                 : emptyBox(t('exc_empty'), ''));
  openDrawer();
}
const openDrawer = () => { $('#drawer').classList.add('on'); $('#scrim').classList.add('on');
  $('#dclose').focus(); };
const closeDrawer = () => { $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on'); };

// ---- Zeichnen ------------------------------------------------------------
function render(){
  if(!DATA) return;
  writeUrlState();
  renderChrome(); renderOsDonut(); renderHero(); renderFocus();
  $('#grid').innerHTML = [secTrend(), secPrograms(), secTargets(), secV1(), secHeat(), secWhy(),
    secDomain(), secIncoming(), secSso(), secKrb(), secKrbAcc(), secAgents(), secEvents()].join('');
  fillHeat(); renderEvents(); renderJump();
  const qi = $('#q'); if(qi) qi.value = S.q;
  requestAnimationFrame(function(){
    document.querySelectorAll('.bfl').forEach(function(b){
      b.style.width = b.parentNode.parentNode.dataset.p + '%'; });
    document.querySelectorAll('.bcol span').forEach(function(s){ s.style.height = s.dataset.h + '%'; });
  });
  const cards = document.querySelectorAll('.card');
  if(calm || !window.IntersectionObserver){ cards.forEach(c => c.classList.add('in')); }
  else { const io = new IntersectionObserver(function(es, o){ es.forEach(function(e, i){
      if(!e.isIntersecting) return;
      setTimeout(function(){ e.target.classList.add('in'); }, i * 55); o.unobserve(e.target); });
    }, {rootMargin: '-30px'}); cards.forEach(c => io.observe(c)); }
}

// ---- Ereignisse ----------------------------------------------------------
document.addEventListener('click', function(ev){
  const el = ev.target;
  if(el.id === 'scrim' || el.id === 'dclose'){ closeDrawer(); return; }
  if(el.id === 'excbtn'){ openExceptions(); return; }
  if(el.id === 'more'){ S.shown += 60; renderEvents(); return; }
  if(el.id === 'csv'){ window.location = '/api/export.csv?' + params({q: S.q, kind: S.kind}).toString(); return; }
  if(el.id === 'logout'){ window.location = '/logout'; return; }
  if(el.id === 'hide'){ S.hideDone = !S.hideDone; render(); return; }
  const lang = el.closest('[data-l]');
  if(lang){
    LANG = lang.dataset.l;
    try { localStorage.setItem('ntlm.lang', LANG); } catch(e){}
    render(); return; }
  const r = el.closest('[data-r]');
  if(r){ S.range = r.dataset.r; load(); return; }
  const go = el.closest('[data-go]');
  if(go){ const c = document.getElementById(go.dataset.go);
    if(c) c.scrollIntoView({behavior: 'smooth', block: 'start'}); return; }
  const evrow = el.closest('[data-ev]');
  if(evrow){ openEvent(+evrow.dataset.ev); return; }
  const clr = el.closest('[data-clr]');
  if(clr){ const k = clr.dataset.clr;
    if(k === 'all'){ S.q = ''; S.kind = ''; S.mach = ''; S.bucket = ''; S.wd = ''; S.hr = '';
      S.pick = ''; S.rsn = ''; load(); }
    else if(k === 'pick'){ S.pick = ''; load(); }
    else if(k === 'rsn'){ S.rsn = ''; load(); }
    else if(k === 'mach'){ S.mach = ''; load(); }
    else if(k === 'bucket'){ S.bucket = ''; load(); }
    else if(k === 'when'){ S.wd = ''; S.hr = ''; load(); }
    else { S[k] = ''; render(); }
    return; }
  // Drill-down out of the two charts. Both are server-side filters, so the
  // whole payload is refetched - a day three weeks back is not in the event
  // list the page happens to be holding.
  const rw = el.closest('[data-rsn]');
  if(rw){
    S.rsn = S.rsn === rw.dataset.rsn ? '' : rw.dataset.rsn;
    S.pick = ''; S.shown = 60;
    load().then(function(){ if(S.rsn) goEvents(); });
    return; }
  const sg = el.closest('#handbar .seg');
  if(sg){
    S.pick = S.pick === sg.dataset.pick ? '' : sg.dataset.pick;
    // Mutually exclusive with the reason filter in both directions: both want
    // the 'kind' parameter, and a chip that is displayed but ignored would be
    // worse than no chip at all.
    S.rsn = ''; S.shown = 60;
    load().then(function(){ if(S.pick) goEvents(); });
    return; }
  const bar = el.closest('[data-bucket]');
  if(bar){
    S.bucket = S.bucket === bar.dataset.bucket ? '' : bar.dataset.bucket;
    S.wd = ''; S.hr = ''; S.shown = 60;
    load().then(() => { if(S.bucket) goEvents(); });
    return; }
  const cell = el.closest('[data-wd]');
  if(cell){
    const same = String(S.wd) === cell.dataset.wd && String(S.hr) === cell.dataset.hr;
    S.wd = same ? '' : cell.dataset.wd;
    S.hr = same ? '' : cell.dataset.hr;
    S.bucket = ''; S.shown = 60;
    load().then(() => { if(S.wd !== '') goEvents(); });
    return; }
  const chip = el.closest('.chip');
  if(chip){ if(chip.dataset.k !== undefined) S.kind = chip.dataset.k;
    if(chip.dataset.a) S.acct = chip.dataset.a;
    S.shown = 60; renderEvents(); return; }
  const jd = el.closest('[data-prog],[data-q],[data-mach],[data-kind]');
  if(jd){
    if(jd.dataset.mach){ S.mach = jd.dataset.mach; closeDrawer(); load(); return; }
    if(jd.dataset.prog) S.q = jd.dataset.prog;
    if(jd.dataset.q) S.q = jd.dataset.q;
    if(jd.dataset.kind) S.kind = jd.dataset.kind;
    S.shown = 60; closeDrawer(); render();
    const c = document.getElementById('sec-events');
    if(c) setTimeout(function(){ c.scrollIntoView({behavior: 'smooth', block: 'start'}); }, 50);
  }
});
document.addEventListener('input', function(e){
  if(e.target.id === 'q'){ S.q = e.target.value; S.shown = 60; renderEvents(); } });
document.addEventListener('change', function(e){
  if(e.target.id === 'mach'){ S.mach = e.target.value; load(); return; }
  const k = e.target.dataset && e.target.dataset.key;
  if(k){ const v = e.target.value;
    fetch('/item-status', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({key: k, status: v})}).then(function(){ load(); }).catch(function(){});
  } });
addEventListener('keydown', function(e){ if(e.key === 'Escape') closeDrawer(); });
// Pointer and keyboard both reach the card; the bar is a real control now.
document.addEventListener('mouseover', function(e){
  const sg = e.target.closest && e.target.closest('#handbar .seg');
  if(sg) segTip(sg);
});
document.addEventListener('mouseout', function(e){
  if(e.target.closest && e.target.closest('#handbar') &&
     !(e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest('#handbar'))) segTip(null);
});
document.addEventListener('focusin', function(e){
  const sg = e.target.closest && e.target.closest('#handbar .seg');
  segTip(sg || null);
});
document.addEventListener('focusout', function(e){
  if(e.target.closest && e.target.closest('#handbar .seg')) segTip(null);
});

readUrlState();
load();
TIMER = setInterval(load, 60000);

// Back and Forward should move between shared views rather than do nothing.
addEventListener('popstate', function(){
  readUrlState();
  load();
});

</script>
</body>
</html>
"""


LOGIN_HTML = r"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in - NTLM-Analyzer</title>
<style>
  :root{--paper:#f6f3ec;--card:#fff;--ink:#2c2a26;--soft:#6f6a60;--line:#e7e1d5;
        --accent:#2f6f6a;--bad:#c4453f;--bad-bg:#fbeceb;
        --serif:'Fraunces',Georgia,serif;--sans:'Hanken Grotesk','Segoe UI',system-ui,sans-serif}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:var(--paper);color:var(--ink);font-family:var(--sans)}
  .card{background:var(--card);border:1px solid var(--line);border-radius:18px;
        box-shadow:0 1px 2px rgba(40,35,25,.04),0 10px 30px rgba(40,35,25,.06);
        padding:30px 30px 26px;width:340px;max-width:92vw}
  h1{font-family:var(--serif);font-weight:600;font-size:21px;margin:0 0 4px}
  p.sub{margin:0 0 20px;color:var(--soft);font-size:13.5px;line-height:1.45}
  label{display:block;font-size:12px;font-weight:600;color:var(--soft);
        text-transform:uppercase;letter-spacing:.03em;margin:0 0 6px}
  input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:10px;
        font-size:15px;font-family:inherit;background:#fcfaf6;color:var(--ink)}
  input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(47,111,106,.12)}
  button{margin-top:16px;width:100%;padding:11px 12px;border:none;border-radius:10px;
         background:var(--accent);color:#fff;font-size:15px;font-weight:600;
         font-family:inherit;cursor:pointer}
  button:hover{filter:brightness(1.06)}
  .err{display:none;margin:0 0 16px;padding:10px 12px;border-radius:10px;
       background:var(--bad-bg);color:var(--bad);font-size:13px}
</style></head>
<body>
  <div class="card">
    <h1>NTLM Telemetrie</h1>
    <p class="sub" id="l_sub">Please sign in to view the dashboard.</p>
    <div class="err" id="err">Wrong password. Please try again.</div>
    <form method="post" action="/login">
      <label for="pw" id="l_pw">Password</label>
      <input id="pw" name="password" type="password" autofocus autocomplete="current-password">
      <button type="submit" id="l_btn">Sign in</button>
    </form>
  </div>
  <script>
    // Language: same setting as the dashboard (localStorage 'ntlm_lang')
    var L = {
      de: {sub:'Bitte anmelden, um das Dashboard zu sehen.', pw:'Passwort', btn:'Anmelden',
           e1:'Falsches Passwort. Bitte erneut versuchen.',
           e2:'Zu viele Fehlversuche. Bitte in ein paar Minuten erneut versuchen.'},
      en: {sub:'Please sign in to view the dashboard.', pw:'Password', btn:'Sign in',
           e1:'Wrong password. Please try again.',
           e2:'Too many failed attempts. Please try again in a few minutes.'}
    };
    var lang = 'de';
    try { lang = localStorage.getItem('ntlm_lang') || 'de'; } catch (e) {}
    var T = L[lang] || L.de;
    document.documentElement.lang = lang;
    document.getElementById('l_sub').textContent = T.sub;
    document.getElementById('l_pw').textContent = T.pw;
    document.getElementById('l_btn').textContent = T.btn;
    var el = document.getElementById('err'), q = location.search;
    if (q.indexOf('err=2') !== -1) { el.textContent = T.e2; el.style.display = 'block'; }
    else if (q.indexOf('err') !== -1) { el.textContent = T.e1; el.style.display = 'block'; }
  </script>
</body></html>
"""

def _tighten_file_permissions(db_path):
    """The database stores who authenticates to what - that is reconnaissance
    gold and must not be world-readable. A restrictive umask covers every file
    this process creates (DB, -wal, -shm, TLS temp files); the explicit chmod
    additionally fixes databases that already exist from earlier runs. On
    Windows both calls are effectively no-ops; NTFS ACLs govern there."""
    try:
        os.umask(0o077)
    except OSError:
        pass
    for suffix in ("", "-wal", "-shm"):
        try:
            os.chmod(db_path + suffix, 0o600)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="NTLM-Analyzer - Collector + Dashboard")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--db", default="ntlm.db")
    ap.add_argument("--key", default=os.environ.get("NTLM_API_KEY", ""),
                    help="Shared secret; Agents senden ihn als X-Api-Key")
    ap.add_argument("--password", default=os.environ.get("NTLM_DASHBOARD_PASSWORD", ""),
                    help="Password for the dashboard login. Empty = login OFF (open). "
                         "Besser ueber Env NTLM_DASHBOARD_PASSWORD setzen statt als Argument.")
    ap.add_argument("--secure-cookie", action="store_true",
                    help="Session-Cookie als 'Secure' markieren (nur ueber HTTPS senden). "
                         "Bei aktivem --cert/--tlskey automatisch an.")
    ap.add_argument("--cert", default="",
                    help="Path to the TLS certificate (PEM). Together with --tlskey this enables HTTPS.")
    ap.add_argument("--tlskey", default="",
                    help="Pfad zum privaten TLS-Schluessel (PEM).")
    ap.add_argument("--retention-days", type=int, default=0,
                    help="Automatically delete events older than N days (0 = off). "
                         "Runs at startup and every 6 hours after that.")
    args = ap.parse_args()

    if bool(args.cert) != bool(args.tlskey):
        ap.error("--cert and --tlskey must be given together.")

    _tighten_file_permissions(args.db)
    conn = init_db(args.db)
    # Per-connection timeout: without it a client that opens a socket and never
    # sends (or trickles bytes) pins a thread forever - enough such connections
    # and the thread pool starves (slowloris). 30s is generous for LAN agents.
    Handler.timeout = 30
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)

    scheme = "http"
    if args.cert:
        try:
            mode = os.stat(args.tlskey).st_mode
            # World bits only: group access is common practice (Debian's
            # ssl-cert group) and POSIX ACLs mirror their mask into the group
            # bits - warning on those would false-alarm on every clean
            # setfacl-based install.
            if os.name == "posix" and mode & 0o007:
                print("[NTLM-Analyzer] WARNING: TLS key file is world-readable "
                      "- consider: chmod o= " + args.tlskey)
        except OSError:
            pass
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(certfile=args.cert, keyfile=args.tlskey)
        except (ssl.SSLError, OSError) as exc:
            raise SystemExit(f"[NTLM-Analyzer] TLS startup failed: {exc}")
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    httpd.conn = conn
    httpd.api_key = args.key
    httpd.sessions = {}
    # Over HTTPS the Secure flag is always correct -> set it automatically.
    httpd.cookie_secure = args.secure_cookie or scheme == "https"
    httpd.pw_hash = hash_password(args.password) if args.password else None

    if args.retention_days > 0:
        def _retention_loop():
            while True:
                cutoff = (utc_now() - timedelta(days=args.retention_days)
                          ).strftime("%Y-%m-%dT%H:%M:%S")
                try:
                    with DB_LOCK:
                        cur = conn.execute(
                            "DELETE FROM events WHERE event_time < ?", (cutoff,))
                        conn.commit()
                    if cur.rowcount:
                        print(f"[NTLM-Analyzer] retention: deleted {cur.rowcount} events "
                              f"older than {args.retention_days} days")
                except Exception as exc:
                    print(f"[NTLM-Analyzer] retention cleanup failed: {exc}")
                time.sleep(6 * 3600)
        threading.Thread(target=_retention_loop, daemon=True).start()

    print(f"[NTLM-Analyzer] Dashboard:  {scheme}://{args.host}:{args.port}/")
    print(f"[NTLM-Analyzer] Ingest:     POST {scheme}://{args.host}:{args.port}/ingest")
    print(f"[NTLM-Analyzer] DB:         {os.path.abspath(args.db)}")
    print(f"[NTLM-Analyzer] API key:    {'set' if args.key else 'NONE (open!)'}")
    print(f"[NTLM-Analyzer] Login:      {'enabled' if args.password else 'OFF (dashboard open!)'}")
    print(f"[NTLM-Analyzer] TLS:        {'enabled (min. TLS 1.2)' if scheme == 'https' else 'OFF (clear text!)'}")
    print(f"[NTLM-Analyzer] Retention:  "
          f"{str(args.retention_days) + ' days' if args.retention_days > 0 else 'off (DB grows without bound)'}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[NTLM-Analyzer] stopped.")


if __name__ == "__main__":
    main()
