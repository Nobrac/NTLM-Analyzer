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
from datetime import datetime, timedelta, timezone
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
    outgoing_audit  TEXT,          -- aus/audit/deny/unbekannt
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
    last_seen       TEXT
);
"""

# Kerberos-Fehlercodes aus fehlgeschlagenen 4769-Anfragen: auf Systemen ohne
# die 40xx-Ereignisse (2016/2019/2022) die einzige Fruehwarnung fuer die
# Ursachen hinter NTLM-Fallback. Kategorie -> dieselben Abhilfe-Texte wie beim
# Warum-Panel; unbekannte Codes laufen als "unklar" mit rohem Code durch.
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
                "exc_client", "exc_dc"):
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

    # ---- Helpers ----------------------------------------------------------
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
                self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
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

        source = (payload.get("source") or "unknown").strip()
        if u.path == "/status":
            self._send(200, {"ok": self._upsert_agent(source, payload)})
            return
        events = payload.get("events") or []
        if isinstance(events, dict):      # Single-Event-Push -> in Liste wandeln
            events = [events]
        inserted = self._insert(source, events)
        self._send(200, {"received": len(events), "inserted": inserted})

    def _upsert_agent(self, source, p):
        now = datetime.now(timezone.utc).isoformat()
        with DB_LOCK:
            self.server.conn.execute(
                "INSERT INTO agents (source,is_dc,agent_version,outgoing_audit,"
                "incoming_audit,domain_audit,lm_level,block_v1sso,cred_guard,ntlm_log_kb,"
                "os_version,restrict_out,restrict_in,restrict_dom,exc_client,exc_dc,"
                "last_seen) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(source) DO UPDATE SET is_dc=excluded.is_dc, "
                "agent_version=excluded.agent_version, outgoing_audit=excluded.outgoing_audit, "
                "incoming_audit=excluded.incoming_audit, domain_audit=excluded.domain_audit, "
                "lm_level=excluded.lm_level, block_v1sso=excluded.block_v1sso, "
                "cred_guard=excluded.cred_guard, ntlm_log_kb=excluded.ntlm_log_kb, "
                "os_version=excluded.os_version, restrict_out=excluded.restrict_out, "
                "restrict_in=excluded.restrict_in, restrict_dom=excluded.restrict_dom, "
                "exc_client=excluded.exc_client, exc_dc=excluded.exc_dc, "
                "last_seen=excluded.last_seen",
                (source, 1 if p.get("is_dc") else 0, p.get("agent_version"),
                 p.get("outgoing_audit"), p.get("incoming_audit"),
                 p.get("domain_audit"), p.get("lm_level"), p.get("block_v1sso"),
                 p.get("cred_guard"), p.get("ntlm_log_kb"),
                 p.get("os_version"), p.get("restrict_out"), p.get("restrict_in"),
                 p.get("restrict_dom"), p.get("exc_client"), p.get("exc_dc"), now))
            self.server.conn.commit()
        return True

    # ---- DB ---------------------------------------------------------------
    def _insert(self, source, events):
        now = datetime.now(timezone.utc).isoformat()
        rows = []
        for e in events:
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
            cutoff = (datetime.now() - deltas[rng]).strftime("%Y-%m-%dT%H:%M:%S")

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
            return "'" + s if s[:1] in ("=", "+", "-", "@") else s

        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
        w.writerow(["Time", "Machine", "Kind", "EventID", "NTLM version",
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
        self.end_headers()
        self.wfile.write(data)

    def _query_data(self, qs):
        one, rng, cutoff, where, params = self._event_filters(qs)
        limit = min(int(one("limit", "300") or 300), 2000)
        # tf/tp sind der gemeinsame Filter ALLER Aggregate. Neben dem Zeitraum
        # wirkt hier auch die Maschinenauswahl - dadurch filtert sie global und
        # nicht nur die Ereignisliste. Die Klausel bleibt ein fester String,
        # Benutzereingaben gehen ausschliesslich als Parameter hinein.
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
                "fallback": c.execute(f"SELECT COUNT(*) FROM events WHERE auth_method='Fallback' AND {tf}", tp).fetchone()[0],
                # Enhanced audits (Server 2025): NTLMv1-derived SSO credentials.
                # From October 2026 Windows blocks these by itself (BlockNtlmv1SSO).
                "v1sso": c.execute(f"SELECT COUNT(*) FROM events WHERE kind='ntlmv1sso' AND {tf}", tp).fetchone()[0],
                "inbound": c.execute(f"SELECT COUNT(*) FROM events WHERE kind='incoming' AND {tf}", tp).fetchone()[0],
                "downgrade": c.execute(f"SELECT COUNT(*) FROM events WHERE auth_method='Downgrade' AND {tf}", tp).fetchone()[0],
            }
            # Trend: NTLM events per time bucket (24h -> hourly, otherwise daily).
            # Buckets via substr on the ISO string; kerberos separate, for context only.
            bucket = "substr(event_time,1,13)" if rng == "24h" else "substr(event_time,1,10)"
            trend_rows = c.execute(
                f"SELECT {bucket} AS b, "
                f"SUM(CASE WHEN ntlm_version='NTLMv1' THEN 1 ELSE 0 END), "
                f"SUM(CASE WHEN ntlm_version='NTLMv2' THEN 1 ELSE 0 END), "
                f"SUM(CASE WHEN kind!='kerberos' AND ntlm_version IS NULL THEN 1 ELSE 0 END), "
                f"SUM(CASE WHEN kind='kerberos' THEN 1 ELSE 0 END) "
                f"FROM events WHERE event_time IS NOT NULL AND event_time!='' AND {tf} "
                f"GROUP BY b ORDER BY b DESC LIMIT 60", tp).fetchall()
            trend = [dict(b=r[0], v1=r[1] or 0, v2=r[2] or 0,
                          other=r[3] or 0, krb=r[4] or 0) for r in reversed(trend_rows)]
            # Heatmap weekday x hour: batch jobs and maintenance windows are the
            # stragglers that break a shutdown, and they only show up as a
            # pattern over time - the daily trend averages them away.
            # SQLite %w: 0=Sunday..6=Saturday -> shifted to 0=Monday for display.
            heat_rows = c.execute(
                f"SELECT CAST(strftime('%w', event_time) AS INTEGER), "
                f"CAST(strftime('%H', event_time) AS INTEGER), COUNT(*) "
                f"FROM events WHERE kind != 'kerberos' AND {tf} "
                f"GROUP BY 1, 2", tp).fetchall()
            heat = [[0] * 24 for _ in range(7)]
            for wd, hr, n in heat_rows:
                if wd is None or hr is None:
                    continue
                heat[(wd + 6) % 7][hr] = n

            # Per-program mini time series for the sparklines. Limited to the
            # programs that actually appear in the blocker table, and bucketed
            # by day so a short range still yields a usable line.
            spark_rows = c.execute(
                f"SELECT process, date(event_time), COUNT(*) "
                f"FROM events WHERE event_id IN (8001,4001,4020,4021,4013) "
                f"AND process IS NOT NULL AND {tf} "
                f"GROUP BY 1, 2 ORDER BY 2", tp).fetchall()
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
                f"SELECT COALESCE(process,'(unbekannt)'), COALESCE(target_server,'(unbekannt)'), "
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
                f"SELECT COALESCE(user,'(unbekannt)'), COALESCE(target_server,'(unbekannt)'), "
                f"COUNT(*), COUNT(DISTINCT source), MAX(event_time), "
                f"MAX(CASE WHEN event_id=4025 THEN 1 ELSE 0 END) "
                f"FROM events WHERE kind='ntlmv1sso' AND {tf} "
                f"GROUP BY user, target_server ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            # NTLM inside the domain (8004, from the DC): most reliable source->target view
            domain = [with_status("dom", r[0], r[1],
                           dict(workstation=r[0], target=r[1], users=r[2],
                           n=r[3], blocked=r[4], last_seen=r[5], who=r[6])) for r in c.execute(
                f"SELECT COALESCE(workstation,'(unbekannt)'), COALESCE(target_server,'(unbekannt)'), "
                f"COUNT(DISTINCT user), COUNT(*), "
                f"SUM(CASE WHEN event_id IN (4004,4005,4006) THEN 1 ELSE 0 END), "
                f"MAX(event_time), GROUP_CONCAT(DISTINCT user) "
                f"FROM events WHERE event_id IN (8004,8005,8006,4004,4005,4006,4022,4023,4030,4031,4032,4033) AND {tf} "
                f"GROUP BY workstation, target_server ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            # Kerberos (informational): which services/SPNs already use Kerberos
            kerberos = [dict(service=r[0], accounts=r[1], n=r[2],
                             enc=r[3], last_seen=r[4]) for r in c.execute(
                f"SELECT COALESCE(target_server,'(unbekannt)'), COUNT(DISTINCT user), COUNT(*), "
                f"       GROUP_CONCAT(DISTINCT enc_type), MAX(event_time) "
                f"FROM events WHERE kind='kerberos' AND {tf} "
                f"GROUP BY target_server ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
            # Kerberos by account: the "safe side" - which accounts already use Kerberos
            kerberos_accounts = [dict(account=r[0], services=r[1], svc_count=r[2], n=r[3],
                                      enc=r[4], last_seen=r[5]) for r in c.execute(
                f"SELECT COALESCE(user,'(unbekannt)'), GROUP_CONCAT(DISTINCT target_server), "
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
                           exc_dc=r[19], cg=cg_by_src.get(r[0], 0)) for r in c.execute(
                "SELECT a.source, a.is_dc, a.agent_version, a.outgoing_audit, a.incoming_audit, "
                "a.domain_audit, a.last_seen, "
                "(SELECT COUNT(*) FROM events e WHERE e.source=a.source), "
                "(SELECT MAX(event_time) FROM events e WHERE e.source=a.source), "
                "a.lm_level, "
                "(SELECT MIN(event_time) FROM events e WHERE e.source=a.source), "
                "a.block_v1sso, a.cred_guard, a.ntlm_log_kb, a.os_version, "
                "a.restrict_out, a.restrict_in, a.restrict_dom, a.exc_client, a.exc_dc "
                "FROM agents a ORDER BY a.last_seen DESC").fetchall()]

            # Datenbasis: seit wann liegen ueberhaupt Events vor? Zwei Wochen im
            # Normalbetrieb gelten als Minimum, damit auch woechentliche
            # Aufgaben und Batch-Jobs einmal gelaufen sind.
            first_all = c.execute("SELECT MIN(event_time) FROM events").fetchone()[0]
            coverage_days = None
            if first_all:
                try:
                    d0 = datetime.strptime(first_all[:19], "%Y-%m-%dT%H:%M:%S")
                    coverage_days = max(0, (datetime.now() - d0).days)
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

        return {"stats": stats, "v1sso": v1sso, "incoming": incoming, "reasons": reasons, "trend": trend, "trend_bucket": ("hour" if rng == "24h" else "day"), "heat": heat, "spark": spark,
                "top_proc": top_proc, "v1_users": v1_users,
                "blockers": blockers, "domain": domain, "kerberos": kerberos,
                "kerberos_accounts": kerberos_accounts,
                "agents": agents, "sources": srcs, "events": events,
                "generated_at": datetime.now(timezone.utc).isoformat()}


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title data-i18n-doc="1">NTLM-Analyzer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0b0d11; --panel:#13161d; --panel-2:#171b23; --line:#222834; --line-2:#2c3340;
    --ink:#e7eaf0; --soft:#8a93a3; --faint:#5b6373;
    --accent:#46b3c4; --accent-dim:rgba(70,179,196,.14);
    --bad:#e76f6a;  --bad-bg:rgba(231,111,106,.12); --bad-bd:rgba(231,111,106,.32);
    --old:#dba63f;  --old-bg:rgba(219,166,63,.12);  --old-bd:rgba(219,166,63,.32);
    --good:#56bd8c; --good-bg:rgba(86,189,140,.13); --good-bd:rgba(86,189,140,.32);
    --neut:#94a0b3; --neut-bg:rgba(148,160,179,.10);--neut-bd:rgba(148,160,179,.24);
    --still:#9b8b67;
    --sans:'IBM Plex Sans','Segoe UI',system-ui,-apple-system,sans-serif;
    --mono:'IBM Plex Mono',ui-monospace,'Cascadia Code',Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
    font-size:14.5px;line-height:1.55;-webkit-font-smoothing:antialiased;
    background-image:radial-gradient(rgba(255,255,255,.022) 1px, transparent 1px);
    background-size:22px 22px;background-position:-1px -1px;}
  ::selection{background:var(--accent-dim);color:#fff}
  .wrap{max-width:1160px;margin:0 auto;padding:30px 22px 72px}

  header.top{padding-bottom:18px;margin-bottom:22px;border-bottom:1px solid var(--line);position:relative}
  .langbar{position:absolute;top:2px;right:0;display:flex;gap:6px}
  .lchip{cursor:pointer;font-family:var(--mono);font-size:11.5px;color:var(--soft);
    border:1px solid var(--line-2);border-radius:7px;padding:5px 10px;user-select:none;transition:all .12s}
  .lchip:hover{color:var(--ink);border-color:var(--faint)}
  .lchip.on{background:var(--accent-dim);color:var(--accent);border-color:var(--accent)}
  .top h1{font-weight:600;font-size:25px;letter-spacing:-.2px;margin:0 0 7px;
    display:flex;align-items:center;gap:11px}
  .top h1::before{content:"";width:8px;height:19px;border-radius:2px;
    background:linear-gradient(180deg,var(--accent),#2c8f9e);box-shadow:0 0 14px var(--accent-dim)}
  .top p{margin:0;color:var(--soft);font-size:14px;max-width:74ch}
  .live{display:inline-flex;align-items:center;gap:9px;margin-top:13px;
    color:var(--soft);font-size:12px;font-family:var(--mono);letter-spacing:.02em}
  .live .dot{width:7px;height:7px;border-radius:50%;background:var(--accent);position:relative;flex:none}
  .live .dot::after{content:"";position:absolute;inset:-4px;border-radius:50%;
    border:1px solid var(--accent);opacity:.5;animation:pulse 2.4s ease-out infinite}
  @keyframes pulse{0%{transform:scale(.5);opacity:.6}100%{transform:scale(1.7);opacity:0}}

  .legend{display:flex;flex-wrap:wrap;gap:10px 22px;align-items:center;
    font-family:var(--mono);font-size:12px;color:var(--soft);
    border:1px solid var(--line);border-radius:10px;background:var(--panel);
    padding:11px 16px;margin:20px 0 24px}
  .legend .goal{font-weight:600;color:var(--ink);margin-right:auto;
    text-transform:uppercase;letter-spacing:.05em;font-size:11px}
  .key{display:inline-flex;align-items:center;gap:8px}
  .swatch{width:9px;height:9px;border-radius:2px;display:inline-block}
  .s-bad{background:var(--bad)}.s-old{background:var(--old)}.s-good{background:var(--good)}

  .stats{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;
    background:var(--line);border:1px solid var(--line);border-radius:12px;
    overflow:hidden;margin-bottom:26px}
  .stat{background:var(--panel);padding:17px 16px 15px;position:relative;
    display:flex;flex-direction:column;min-height:106px}
  .stat::before{content:"";position:absolute;left:0;top:0;height:2px;width:100%;
    background:var(--neut);opacity:.45}
  .stat.bad::before{background:var(--bad);opacity:1}
  .stat.old::before{background:var(--old);opacity:1}
  .stat.good::before{background:var(--good);opacity:1}
  .num{font-family:var(--mono);font-weight:600;font-size:30px;line-height:1;
    letter-spacing:-.5px;font-variant-numeric:tabular-nums;color:var(--ink)}
  .lab{font-size:12px;font-weight:600;color:var(--ink);margin-top:9px;
    text-transform:uppercase;letter-spacing:.04em}
  .sub{font-size:11.5px;color:var(--soft);margin-top:2px}
  .stat.clickable{cursor:pointer;transition:background .14s}
  .stat.clickable:hover{background:var(--panel-2)}
  .stat.clickable:hover .num{color:#fff}
  .stat.clickable:focus-visible{outline:none;box-shadow:inset 0 0 0 1px var(--accent)}
  .stat.clickable::after{content:"\203A";position:absolute;right:13px;top:11px;
    color:var(--faint);opacity:0;font-size:17px;transition:opacity .14s,transform .14s}
  .stat.clickable:hover::after{opacity:1;transform:translateX(2px)}

  section{background:var(--panel);border:1px solid var(--line);border-radius:12px;
    margin-bottom:18px;overflow:hidden}
  .head{padding:16px 20px 13px;border-bottom:1px solid var(--line)}
  .head h2{font-size:15px;font-weight:600;margin:0;letter-spacing:-.1px;
    display:flex;align-items:center;gap:9px;flex-wrap:wrap}
  .head p{margin:8px 0 0;color:var(--soft);font-size:13px;line-height:1.5;max-width:90ch}

  .scroll{overflow-x:auto}
  .scroll::-webkit-scrollbar{height:8px}
  .scroll::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:4px}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  thead th{text-align:left;background:var(--panel-2);font-family:var(--mono);
    font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.05em;
    color:var(--soft);padding:10px 18px;border-bottom:1px solid var(--line);white-space:nowrap}
  tbody td{padding:11px 18px;border-bottom:1px solid var(--line);vertical-align:middle}
  tbody tr:last-child td{border-bottom:none}
  tbody tr{transition:background .1s}
  tbody tr:hover td{background:rgba(255,255,255,.022)}
  .strong{font-weight:600;color:var(--ink)}
  .soft{color:var(--soft)}
  .mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
  .num-cell{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;color:var(--ink)}
  .empty{padding:30px 18px;text-align:center;color:var(--faint);font-size:13px}

  .heatwrap{display:grid;grid-template-columns:38px repeat(24,1fr);gap:2px;margin-top:4px}
  .hcell{height:15px;border-radius:2px;background:#171d26}
  .hhr{font-size:9px;color:#5d6b7c;text-align:center;line-height:12px}
  .hday{font-size:11px;color:#8fa0b4;line-height:15px}
  .sparkrow{display:flex;align-items:center;gap:10px}
  .sparkrow svg{flex:none}
  .btn{background:#1c2430;border:1px solid #2e3a4a;color:#c6d4e2;border-radius:7px;
       padding:6px 14px;font:inherit;font-size:13px;cursor:pointer;margin-top:8px}
  .btn:hover{background:#243044}
  .excbox{margin-top:10px;background:#0d1218;border:1px solid #2e3a4a;border-radius:9px;padding:12px}
  .excbox textarea{width:100%;box-sizing:border-box;background:#0a0e13;color:#d8e4ef;
       border:1px solid #26303d;border-radius:7px;padding:9px;font-family:ui-monospace,monospace;
       font-size:12.5px;resize:vertical;margin:6px 0}
  .tgtwrap{display:inline-flex;align-items:center;gap:10px;white-space:nowrap}
  .badge.b-inline{padding:3px 11px;gap:7px}
  .badge{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:6px;
    font-size:11.5px;font-weight:500;font-family:var(--mono);letter-spacing:.01em;
    white-space:nowrap;border:1px solid transparent;line-height:1.45}
  .badge .d{width:6px;height:6px;border-radius:50%;flex:none}
  .b-bad{background:var(--bad-bg);color:var(--bad);border-color:var(--bad-bd)} .b-bad .d{background:var(--bad)}
  .b-old{background:var(--old-bg);color:var(--old);border-color:var(--old-bd)} .b-old .d{background:var(--old)}
  .b-good{background:var(--good-bg);color:var(--good);border-color:var(--good-bd)} .b-good .d{background:var(--good)}
  .b-neut{background:var(--neut-bg);color:var(--neut);border-color:var(--neut-bd)} .b-neut .d{background:var(--neut)}

  .bars{padding:10px 20px 18px;display:grid;gap:13px}
  .bar .row{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px;gap:12px}
  .bar .nm{font-weight:500;color:var(--ink);font-size:13.5px}
  .bar .ct{font-family:var(--mono);font-size:12px;color:var(--soft);font-variant-numeric:tabular-nums}
  .track{height:7px;border-radius:4px;background:var(--line-2);overflow:hidden}
  .fill{height:100%;border-radius:4px}
  .fill.bad{background:linear-gradient(90deg,#b94a45,var(--bad))}
  .fill.good{background:linear-gradient(90deg,#3f9d72,var(--good))}

  .secnav{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:7px;flex-wrap:wrap;
    background:var(--panel);border:1px solid var(--line);border-radius:10px;
    padding:9px 12px;margin:0 0 16px}
  .navlabel{color:var(--faint);font-family:var(--mono);font-size:10px;letter-spacing:.06em;
    text-transform:uppercase;margin-right:4px}
  .navchip{display:inline-flex;align-items:center;gap:7px;padding:4px 11px;border-radius:6px;
    font-family:var(--mono);font-size:11.5px;color:var(--soft);border:1px solid var(--line-2);
    cursor:pointer;white-space:nowrap;transition:border-color .12s,color .12s}
  .navchip:hover{border-color:var(--accent);color:var(--ink)}
  .navchip .n{background:var(--line);border-radius:9px;padding:0 6px;font-size:10.5px}
  .navchip.t-bad{color:var(--bad);border-color:var(--bad-bd)}
  .navchip.t-bad .n{background:var(--bad-bg)}
  .navchip.t-warn{color:var(--old);border-color:var(--old-bd)}
  .navchip.t-warn .n{background:var(--old-bg)}
  .navchip.t-good{color:var(--good);border-color:var(--good-bd)}
  .navchip.t-good .n{background:var(--good-bg)}
  .navchip.empty{color:var(--faint);border:1px dashed var(--line);cursor:default}
  .navchip.empty:hover{border-color:var(--line);color:var(--faint)}
  .navchip.empty .n{background:none;padding:0}
  .navchip.active{background:var(--accent-dim);border-color:var(--accent);color:var(--ink)}
  body.hide-done tr.row-done{display:none}
  .gsep{display:inline-block;width:1px;height:18px;background:var(--line-2);margin:0 10px;vertical-align:middle}
  .gsel{background:var(--panel);color:var(--ink);border:1px solid var(--line-2);border-radius:6px;
    padding:4px 8px;font-family:var(--mono);font-size:11.5px;max-width:230px}
  .gtoggle{display:inline-flex;align-items:center;gap:6px;margin-left:14px;color:var(--soft);
    font-size:11.5px;font-family:var(--mono);cursor:pointer;user-select:none}
  .gtoggle input{accent-color:var(--accent);cursor:pointer}
  .coverage{margin-top:8px !important;font-family:var(--mono);font-size:11.5px}
  .coverage .warn{color:var(--old)}
  .coverage .ok{color:var(--good)}
  .fsep{width:1px;height:20px;background:var(--line-2);margin:0 4px;display:inline-block;vertical-align:middle}
.filters{display:flex;flex-wrap:wrap;gap:8px;padding:14px 20px;
    border-bottom:1px solid var(--line);align-items:center}
  #q{flex:1;min-width:220px;background:var(--bg);border:1px solid var(--line-2);
    border-radius:8px;color:var(--ink);padding:9px 12px;font-family:var(--sans);
    font-size:13.5px;outline:none}
  #q::placeholder{color:var(--faint)}
  #q:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
  .chip{cursor:pointer;font-family:var(--mono);font-size:12px;color:var(--soft);
    border:1px solid var(--line-2);border-radius:7px;padding:6px 11px;
    user-select:none;transition:all .12s;white-space:nowrap}
  .chip:hover{color:var(--ink);border-color:var(--faint)}
  .chip.on{background:var(--accent-dim);color:var(--accent);border-color:var(--accent)}

  .rangebar{display:flex;align-items:center;gap:8px;margin:0 0 14px}
  .rlabel{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--soft);
    text-transform:uppercase;letter-spacing:.05em;margin-right:4px}
  .rchip{cursor:pointer;font-family:var(--mono);font-size:12px;color:var(--soft);
    border:1px solid var(--line-2);border-radius:7px;padding:6px 12px;
    user-select:none;transition:all .12s;white-space:nowrap}
  .rchip:hover{color:var(--ink);border-color:var(--faint)}
  .rchip.on{background:var(--accent-dim);color:var(--accent);border-color:var(--accent)}

  .trend{display:flex;align-items:flex-end;gap:5px;padding:20px 20px 12px;min-height:120px}
  .tcol{flex:1;min-width:6px;display:flex;flex-direction:column;align-items:stretch}
  .tbar{display:flex;flex-direction:column;justify-content:flex-end;height:130px}
  .tseg{width:100%}
  .tseg.s1{background:var(--bad)}
  .tseg.s2{background:var(--old)}
  .tseg.s0{background:var(--line-2)}
  .tbar .tseg:first-child{border-radius:3px 3px 0 0}
  .tlab{font-family:var(--mono);font-size:10px;color:var(--faint);text-align:center;
    margin-top:6px;white-space:nowrap;overflow:visible;height:14px}
  .trend .empty{width:100%}

  .stsel{background:var(--bg);border:1px solid var(--line-2);border-radius:6px;color:var(--soft);
    font-family:var(--mono);font-size:11.5px;padding:4px 6px;outline:none;cursor:pointer}
  .stsel.st-arbeit{color:var(--old);border-color:var(--old-bd)}
  .stsel.st-erledigt{color:var(--good);border-color:var(--good-bd)}
  tr.row-done td{opacity:.55}
  .hintbtn{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;
    border-radius:50%;border:1px solid var(--line-2);color:var(--faint);font-family:var(--mono);
    font-size:11px;cursor:pointer;user-select:none;margin-left:7px;vertical-align:middle;flex:none}
  .hintbtn:hover,.hintbtn.on{color:var(--accent);border-color:var(--accent)}
  tr.hintrow td{background:var(--accent-dim);color:var(--soft);font-size:12.5px;line-height:1.55;
    padding:12px 18px;border-left:2px solid var(--accent);border-radius:0}
  tr.hintrow b{color:var(--ink);font-weight:600}

  tr.evrow{cursor:pointer}
  tr.evrow:hover td{background:rgba(255,255,255,.018)}
  tr.evrow .chev{display:inline-block;width:14px;color:var(--faint);font-size:10px;
    transition:transform .12s}
  tr.evrow.evopen td{border-bottom:none}
  tr.detrow td{background:var(--panel-2);padding:14px 18px 16px;
    border-left:2px solid var(--line-2)}
  .dhead{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--soft);
    text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}
  .dgrid{display:grid;grid-template-columns:170px 1fr;gap:5px 16px;max-width:720px}
  .dlab{font-family:var(--mono);font-size:11px;color:var(--faint);
    text-transform:uppercase;letter-spacing:.04em;padding-top:1px}
  .dval{font-family:var(--mono);font-size:12.5px;color:var(--ink);word-break:break-all}

  footer{margin-top:24px;text-align:center;color:var(--faint);font-size:12px;font-family:var(--mono)}

  @media(max-width:880px){.stats{grid-template-columns:repeat(3,1fr)}}
  @media(max-width:520px){.stats{grid-template-columns:repeat(2,1fr)}.wrap{padding:22px 14px 56px}}
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <div class="langbar"><span class="lchip on" data-l="de">DE</span><span class="lchip" data-l="en">EN</span></div>
    <h1 data-i18n="h1">NTLM-Analyzer</h1>
    <p data-i18n="intro">Who on the network still uses the legacy NTLM authentication – and what already runs securely over Kerberos. The goal is to phase NTLM out step by step.</p>
    <div class="live"><span class="dot"></span> <span data-i18n="live">Refreshes automatically · last</span> <span id="updated">–</span></div>
  </header>

  <div class="legend">
    <span class="goal" data-i18n="leg_goal">Color legend</span>
    <span class="key"><span class="swatch s-bad"></span> <span data-i18n="leg_bad">Red = insecure (NTLMv1)</span></span>
    <span class="key"><span class="swatch s-old"></span> <span data-i18n="leg_old">Yellow = outdated (NTLMv2)</span></span>
    <span class="key"><span class="swatch s-good"></span> <span data-i18n="leg_good">Green = secure (Kerberos)</span></span>
  </div>

  <div class="rangebar">
    <span class="rlabel" data-i18n="range">Time range</span>
    <span class="rchip" data-r="24h">24 h</span>
    <span class="rchip on" data-r="7d" data-i18n="r7d">7 days</span>
    <span class="rchip" data-r="30d" data-i18n="r30d">30 days</span>
    <span class="rchip" data-r="all" data-i18n="rall">All</span>
    <span class="gsep"></span>
    <span class="rlabel" data-i18n="g_machine">Machine</span>
    <select id="srcsel" class="gsel"><option value="" data-i18n="g_all_mach">All machines</option></select>
    <label class="gtoggle"><input type="checkbox" id="hidedone"><span data-i18n="g_hidedone">Hide done</span></label>
  </div>

  <nav class="secnav" id="secnav">
    <span class="navlabel" data-i18n="nav_label">Sections</span>
    <span class="navchip" data-sec="sec-programs"   data-tone="warn" data-i18n="nav_prog">Programs</span>
    <span class="navchip" data-sec="sec-heat"       data-tone="neut" data-i18n="nav_heat">Timing</span>
    <span class="navchip" data-sec="sec-why"        data-tone="warn" data-i18n="nav_why">Why NTLM</span>
    <span class="navchip" data-sec="sec-incoming"   data-tone="neut" data-i18n="nav_inc">Services</span>
    <span class="navchip" data-sec="sec-v1sso"      data-tone="bad"  data-i18n="nav_v1sso">NTLMv1 SSO</span>
    <span class="navchip" data-sec="sec-v1"         data-tone="bad"  data-i18n="nav_v1">NTLMv1</span>
    <span class="navchip" data-sec="sec-domain"     data-tone="neut" data-i18n="nav_dom">Domain</span>
    <span class="navchip" data-sec="sec-kerberos-accounts" data-tone="good" data-i18n="nav_krb">Kerberos</span>
    <span class="navchip" data-sec="sec-agents"     data-tone="neut" data-i18n="nav_mach">Machines</span>
    <span class="navchip" data-sec="sec-events"     data-tone="neut" data-i18n="nav_ev">Events</span>
  </nav>

  <div class="stats">
    <div class="stat clickable" tabindex="0" data-filter="all" data-scroll="#sec-events"
         data-i18n-title="tt_total" title="Show all events"><div class="num" id="s-total">–</div><div class="lab" data-i18n="lab_total">NTLM total</div><div class="sub" data-i18n="sub_total">recorded events</div></div>
    <div class="stat bad clickable" tabindex="0" data-filter="v1" data-scroll="#sec-events"
         data-i18n-title="tt_v1" title="Jump to insecure logons"><div class="num" id="s-v1">–</div><div class="lab" data-i18n="lab_v1">Insecure</div><div class="sub" data-i18n="sub_v1">NTLMv1 – replace first</div></div>
    <div class="stat old clickable" tabindex="0" data-filter="v2" data-scroll="#sec-events"
         data-i18n-title="tt_v2" title="Jump to outdated logons"><div class="num" id="s-v2">–</div><div class="lab" data-i18n="lab_v2">Outdated</div><div class="sub" data-i18n="sub_v2">NTLMv2 – better, but old</div></div>
    <div class="stat good clickable" tabindex="0" data-scroll="#sec-kerberos"
         data-i18n-title="tt_krb" title="Jump to the Kerberos overview"><div class="num" id="s-krb">–</div><div class="lab" data-i18n="lab_krb">Already secure</div><div class="sub" data-i18n="sub_krb">services via Kerberos</div></div>
    <div class="stat clickable" tabindex="0" data-scroll="#sec-domain"
         data-i18n-title="tt_src" title="Jump to the domain overview"><div class="num" id="s-src">–</div><div class="lab" data-i18n="lab_src">Computers involved</div><div class="sub" data-i18n="sub_src">sources & servers</div></div>
    <div class="stat clickable" tabindex="0" data-scroll="#sec-programs"
         data-i18n-title="tt_proc" title="Jump to programs"><div class="num" id="s-proc">–</div><div class="lab" data-i18n="lab_proc">Programs detected</div><div class="sub" data-i18n="sub_proc">that trigger NTLM</div></div>
  </div>

  <!-- Verlauf: NTLM ueber Zeit -->
  <section id="sec-trend">
    <div class="head">
      <h2 data-i18n="trend_h">Trend</h2>
      <p data-i18n="trend_p">NTLM activity in the selected time range – these bars should approach zero over the weeks. Red = NTLMv1, yellow = NTLMv2, gray = NTLM without version info (domain/outgoing). Kerberos is shown in the tooltip for context.</p>
    </div>
    <div class="trend" id="trend"></div>
  </section>

  <section id="sec-heat">
    <div class="head">
      <h2 data-i18n="heat_h">When NTLM happens</h2>
      <p data-i18n="heat_p">Weekday against hour of day. Batch jobs, maintenance windows and weekend scripts are the stragglers that break a shutdown — as a single figure they hide in the daily trend, as a pattern they stand out.</p>
    </div>
    <div id="heatwrap" class="heatwrap"></div>
    <p id="heathint" class="coverage"></p>
  </section>

  <!-- NTLMv1 SSO: hard October 2026 deadline (Server 2025 / Win11 24H2) -->
  <section id="sec-v1sso" style="display:none">
    <div class="head">
      <h2><span class="badge b-bad"><span class="d"></span><span data-i18n="b_deadline">Deadline</span></span> <span data-i18n="v1sso_h">NTLMv1 SSO – stops working in October 2026</span></h2>
      <p data-i18n="v1sso_p">Windows reports the use of NTLMv1-derived credentials here. In October 2026 Microsoft switches the default to blocking – these will then break on their own, regardless of your own policies.</p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_user4">User</th><th data-i18n="th_target4">Target</th><th data-i18n="th_count4">Count</th><th data-i18n="th_state4">State</th><th data-i18n="th_status4">Status</th><th data-i18n="th_last5">Last seen</th></tr></thead>
        <tbody id="v1sso"></tbody>
      </table>
    </div>
  </section>

  <!-- Programs using NTLM -->
  <section id="sec-programs">
    <div class="head">
      <h2><span class="badge b-bad"><span class="d"></span></span> <span data-i18n="prog_h">Programs still using NTLM</span></h2>
      <p data-i18n="prog_p">These programs authenticate outward via NTLM. Before disabling NTLM they should be reviewed or reconfigured. "Kernel: SMB/HTTP.sys" means the request came from kernel mode (PID 4) – file shares, but also WinRM, ADWS, SSRS or the Remote Desktop Gateway. No single program can be named there.</p>
      <button class="btn" onclick="toggleExc('out')" data-i18n="btn_exc">Generate exception list</button>
      <div id="excbox-out" class="excbox" style="display:none">
        <p class="soft"><span data-i18n="exc_gpo_out">Paste into: Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication</span> · <span class="exc-count mono">0</span> <span data-i18n="exc_entries">entries (open items only)</span></p>
        <textarea rows="6" readonly spellcheck="false"></textarea>
        <button class="btn" onclick="copyExc('out', this)" data-i18n="exc_copy">Copy</button>
        <p class="soft" data-i18n="exc_note">An exception is a stay of execution, not a fix — keep working the list down.</p>
      </div>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_prog">Program</th><th data-i18n="th_target">Target server</th><th data-i18n="th_count">Count</th><th data-i18n="th_trend2" data-i18n-title="tt_th_trend" title="">Trend</th><th data-i18n="th_users">Users</th><th data-i18n="th_comps">Computers (no.)</th><th data-i18n="th_status">Status</th><th data-i18n="th_last">Last seen</th></tr></thead>
        <tbody id="blockers"></tbody>
      </table>
    </div>
  </section>

  <!-- Wer nutzt NTLM, wohin (8004) -->
  <section id="sec-domain">
    <div class="head">
      <h2 data-i18n="dom_h">Who uses NTLM – and where to</h2>
      <p data-i18n="dom_p">Reported by the domain controller: which computer connects to which server via NTLM. The most reliable overall view – even when no program name can be determined.</p>
      <button class="btn" onclick="toggleExc('dom')" data-i18n="btn_exc">Generate exception list</button>
      <div id="excbox-dom" class="excbox" style="display:none">
        <p class="soft"><span data-i18n="exc_gpo_dom">Paste into: Network security: Restrict NTLM: Add server exceptions in this domain (on the DCs)</span> · <span class="exc-count mono">0</span> <span data-i18n="exc_entries">entries (open items only)</span></p>
        <textarea rows="6" readonly spellcheck="false"></textarea>
        <button class="btn" onclick="copyExc('dom', this)" data-i18n="exc_copy">Copy</button>
        <p class="soft" data-i18n="exc_note">An exception is a stay of execution, not a fix — keep working the list down.</p>
      </div>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_srccomp">Computer (source)</th><th data-i18n="th_target2">Target server</th><th data-i18n="th_users2">Users</th><th data-i18n="th_count2">Count</th><th data-i18n="th_status2">Status</th><th data-i18n="th_last2">Last seen</th></tr></thead>
        <tbody id="domain"></tbody>
      </table>
    </div>
  </section>

  <!-- Warum NTLM? Gruppierung nach Usage-ID der 40xx-Ereignisse -->
  <section id="sec-why" style="display:none">
    <div class="head">
      <h2 data-i18n="why_h">Why NTLM was used</h2>
      <p data-i18n="why_p">Windows reports the reason for every fallback (Server 2025 / Windows 11 24H2 only). Each cause has its own fix — this is the shortest path from finding to remedy.</p>
      <p id="relayline" class="coverage"></p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_reason">Reason</th><th data-i18n="th_fix">What helps</th><th data-i18n="th_count6">Count</th><th data-i18n="th_progs">Programs</th><th data-i18n="th_machines2">Machines</th><th data-i18n="th_last7">Last seen</th></tr></thead>
        <tbody id="reasons"></tbody>
      </table>
    </div>
  </section>

  <!-- Eingehender NTLM: welcher Dienst nimmt an (8002/8003) -->
  <section id="sec-incoming" style="display:none">
    <div class="head">
      <h2 data-i18n="inc_h">Services accepting NTLM</h2>
      <p data-i18n="inc_p">The other direction: which service on these machines accepts incoming NTLM. Needs the "Audit Incoming NTLM Traffic" policy — without it this section stays empty.</p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_mach2">Machine</th><th data-i18n="th_svc">Service / process</th><th data-i18n="th_count5">Count</th><th data-i18n="th_users5">Accounts</th><th data-i18n="th_status5">Status</th><th data-i18n="th_last6">Last seen</th></tr></thead>
        <tbody id="incoming"></tbody>
      </table>
    </div>
  </section>

  <!-- NTLMv1 by user -->
  <section id="sec-v1">
    <div class="head">
      <h2><span class="badge b-bad"><span class="d"></span><span data-i18n="b_insec">insecure</span></span> <span data-i18n="v1_h">Insecure logons by user</span></h2>
      <p data-i18n="v1_p">NTLMv1 is considered insecure and should be replaced first. These users or accounts still logged on with it.</p>
    </div>
    <div class="bars" id="v1-users"></div>
  </section>

  <!-- Kerberos -->
  <section id="sec-kerberos">
    <div class="head">
      <h2><span class="badge b-good"><span class="d"></span><span data-i18n="b_sec">secure</span></span> <span data-i18n="krb_h">Already running over Kerberos</span></h2>
      <p data-i18n="krb_p">These services already use modern, secure Kerberos – all good here. For information only. "RC4/DES" would be weaker encryption, "AES" is good.</p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_service">Service</th><th data-i18n="th_accounts">Accounts</th><th data-i18n="th_count3">Count</th><th data-i18n="th_enc">Encryption</th><th data-i18n="th_last3">Last seen</th></tr></thead>
        <tbody id="kerb"></tbody>
      </table>
    </div>
  </section>

  <!-- Kerberos by account: the safe side -->
  <section id="sec-kerberos-accounts">
    <div class="head">
      <h2><span class="badge b-good"><span class="d"></span><span data-i18n="b_sec2">secure</span></span> <span data-i18n="krba_h">Accounts already using Kerberos</span></h2>
      <p data-i18n="krba_p">The "safe side": these accounts have already authenticated successfully via Kerberos – with the services they use and the encryption. "AES" is good, "RC4/DES" would be weaker. For information only.</p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_account">Account</th><th data-i18n="th_services">Services</th><th data-i18n="th_tickets" data-i18n-title="tt_th_tickets" title="">Tickets</th><th data-i18n="th_enc2">Encryption</th><th data-i18n="th_last4">Last seen</th></tr></thead>
        <tbody id="kerb-accounts"></tbody>
      </table>
    </div>
  </section>

  <!-- Maschinen / Heartbeat + Auditing-Status -->
  <section id="sec-agents">
    <div class="head">
      <h2 data-i18n="ag_h">Machines & auditing status</h2>
      <p data-i18n="ag_p">Which agents report – and whether the required auditing is enabled there. A green dot means "reported recently". Red auditing badges explain why a machine may not deliver data.</p>
      <p id="coverage" class="coverage"></p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_machine">Machine</th><th data-i18n="th_type">Type</th><th data-i18n="th_status3">Status</th><th data-i18n-title="tt_th_aud" title="">Auditing</th><th data-i18n="th_lm" data-i18n-title="tt_th_lm" title="">NTLM level</th><th data-i18n="th_oct" data-i18n-title="tt_th_oct" title="">Oct 2026</th><th>Events</th><th data-i18n="th_lastrep">Last reported</th></tr></thead>
        <tbody id="agents"></tbody>
      </table>
    </div>
  </section>

  <!-- Letzte Ereignisse -->
  <section id="sec-events">
    <div class="head">
      <h2 data-i18n="ev_h">Recent events</h2>
      <p data-i18n="ev_p">The latest recorded activity. "Kerberos fallback" on a logon means Kerberos was attempted but failed – usually an SPN, DNS or clock-skew issue. Filter with the buttons or search above.</p>
    </div>
    <div class="filters">
      <input id="q" data-i18n-ph="search_ph" placeholder="Search: user, program, server, computer …">
      <span class="chip on" data-f="all" data-i18n="f_all">All</span>
      <span class="chip" data-f="v1" data-i18n="f_v1">Insecure only</span>
      <span class="chip" data-f="v2" data-i18n="f_v2">Outdated only</span>
      <span class="chip" data-f="outgoing" data-i18n="f_out">Programs</span>
      <span class="chip" data-f="domain" data-i18n="f_dom">Domain</span>
      <span class="fsep"></span>
      <span class="chip achip on" data-a="all" data-i18n="f_a_all"
            data-i18n-title="f_a_t" title="Filters the event list and the CSV export (not the metric cards above)">All accounts</span>
      <span class="chip achip" data-a="user" data-i18n="f_a_user">People only</span>
      <span class="chip achip" data-a="machine" data-i18n="f_a_mach">Computers only</span>
      <span class="rchip" id="csvbtn" data-i18n="csv" data-i18n-title="csv_t" title="Download the current selection as CSV">CSV-Export</span>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_time">Time</th><th data-i18n="th_kind">Kind</th><th data-i18n="th_users3">User</th><th data-i18n="th_prog2">Program</th><th data-i18n="th_tgtsrc">Target / source</th><th data-i18n="th_comp">Computer</th></tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </section>

  <footer id="foot"></footer>
</div>

<script>
// ---------------- Sprache / i18n ----------------
const I18N = {
de: {
  doc_title:'NTLM-Analyzer', h1:'NTLM-Analyzer',
  intro:'Wer im Netzwerk verwendet noch das ältere NTLM-Anmeldeverfahren – und was läuft bereits sicher über Kerberos. Ziel ist, NTLM nach und nach abzulösen.',
  live:'Aktualisiert sich automatisch · zuletzt',
  leg_goal:'Farbbedeutung', leg_bad:'Rot = unsicher (NTLMv1)', leg_old:'Gelb = veraltet (NTLMv2)', leg_good:'Grün = sicher (Kerberos)',
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
  exc_entries:'Einträge (nur offene)', exc_empty:'Keine offenen Einträge – nichts zu tun.',
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
  as_of:'Stand: '
},
en: {
  doc_title:'NTLM-Analyzer', h1:'NTLM-Analyzer',
  intro:'Who on the network still uses the legacy NTLM authentication – and what already runs securely over Kerberos. The goal is to phase NTLM out step by step.',
  live:'Refreshes automatically · last',
  leg_goal:'Color legend', leg_bad:'Red = insecure (NTLMv1)', leg_old:'Yellow = outdated (NTLMv2)', leg_good:'Green = secure (Kerberos)',
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
  exc_entries:'entries (open items only)', exc_empty:'No open items - nothing to do.',
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
  as_of:'As of: '
}};
let LANG = 'de';
try { LANG = localStorage.getItem('ntlm_lang') || 'de'; } catch(e) {}
if (!I18N[LANG]) LANG = 'de';
const t = k => (I18N[LANG] && I18N[LANG][k]) || I18N.de[k] || k;
// Like t(), but falls back to a caller-supplied string instead of the key -
// used for reason IDs, where an undocumented ID must not render as "rid_99".
const tOr = (k, fb) => (I18N[LANG] && I18N[LANG][k]) || I18N.de[k] || fb;
const LOCALE = () => LANG === 'de' ? 'de-DE' : 'en-GB';

function applyStatic(){
  document.documentElement.lang = LANG;
  document.title = t('doc_title');
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-title]').forEach(el => { el.title = t(el.dataset.i18nTitle); });
  document.querySelectorAll('.lchip').forEach(c => c.classList.toggle('on', c.dataset.l === LANG));
}
function setLang(l){
  if (!I18N[l] || l === LANG) return;
  LANG = l;
  try { localStorage.setItem('ntlm_lang', l); } catch(e) {}
  applyStatic();
  load();
}
document.querySelectorAll('.lchip').forEach(c => c.addEventListener('click', () => setLang(c.dataset.l)));

// ---------------- Zustand & Helfer ----------------
const state = {f:"all", q:"", r:"7d", a:"all", src:"", hidedone:false};
const $ = s => document.querySelector(s);
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const dash = '<span class="soft">–</span>';
// True when the target is (or contains) a bare IP address - also inside an SPN
// such as "TERMSRV/10.0.0.5" or "cifs/192.168.1.9".
function targetIsIp(v){
  if(!v) return false;
  const part = String(v).includes('/') ? String(v).split('/').pop() : String(v);
  const raw = part.replace(/^\\\\/,'').trim();
  // IPv6 first - it contains colons itself, so the port split below would ruin it
  if(/^\[?[0-9a-fA-F]*:[0-9a-fA-F:]*\]?$/.test(raw) && raw.includes('::') || /^\[[0-9a-fA-F:]+\]/.test(raw)) return true;
  const host = raw.split(':')[0];
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}
const when = s => esc((s||"").replace("T"," ").slice(0,16));
function userList(who){
  if(!who) return dash;
  const arr = String(who).split(',').map(s=>s.trim()).filter(Boolean);
  if(arr.length<=3) return esc(arr.join(', '));
  return esc(arr.slice(0,3).join(', ')) + ' <span class="soft">+'+(arr.length-3)+' '+t('more')+'</span>';
}

function artBadge(e){
  // Hovering the kind column explains the underlying event ID in one sentence.
  const ti = eidText(e.event_id) ? ' title="'+esc(e.event_id+' – '+eidText(e.event_id))+'"' : '';
  let fb = (e.auth_method=="Fallback") ? ' <span class="badge b-old" title="'+esc(t('tt_fb'))+'"><span class="d"></span>'+t('b_fb')+'</span>' : '';
  if(e.auth_method=="Downgrade") fb = ' <span class="badge b-bad" title="'+esc(t('tt_down'))+'"><span class="d"></span>'+t('b_down')+'</span>';
  if(e.ntlm_version=="NTLMv1") return '<span class="badge b-bad"'+ti+'><span class="d"></span>'+t('b_v1')+'</span>'+fb;
  if(e.ntlm_version=="NTLMv2") return '<span class="badge b-old"'+ti+'><span class="d"></span>'+t('b_v2')+'</span>'+fb;
  if(e.kind=="cgblock")        return '<span class="badge b-bad"'+ti+'><span class="d"></span>'+t('b_cg')+'</span>';
  if(e.kind=="krbfail")        return '<span class="badge b-old" title="'+esc(t('tt_krbfail')+(e.failure_code?' ('+e.failure_code+')':''))+'"><span class="d"></span>'+t('b_krbfail')+'</span>';
  if(e.kind=="kerberos")       return '<span class="badge b-good"'+ti+'><span class="d"></span>'+t('b_krb')+'</span>';
  if(e.kind=="domain")         return '<span class="badge b-neut"'+ti+'><span class="d"></span>'+t('b_dom')+'</span>';
  if(e.kind=="outgoing")       return '<span class="badge b-neut"'+ti+'><span class="d"></span>'+t('b_out')+'</span>';
  if(e.kind=="incoming")       return '<span class="badge b-neut"'+ti+'><span class="d"></span>'+t('b_in')+'</span>';
  return '<span class="soft"'+ti+'>NTLM</span>';
}
// LmCompatibilityLevel: which NTLM versions the machine still permits.
// 5 = NTLMv2 only (target state), 0-2 still accept the ancient LM/NTLMv1
// responses, 3/4 (and "unset", which behaves like 3) sit in between: they send
// NTLMv2 but would still accept weaker answers as a server.
// October 2026: Microsoft flips BlockNtlmv1SSO from audit to enforce. Machines
// with Credential Guard enabled are exempt - it already blocks NTLMv1
// cryptography - and machines already set to enforce have nothing left to come.
function octCell(a){
  const b = a.block_v1sso, cg = a.cred_guard;
  if(b===null || b===undefined || b==='') return dash;
  if(b==='enforce')
    return '<span class="badge b-good" title="'+esc(t('tt_oct_enf'))+'"><span class="d"></span>'+t('oct_enf')+'</span>';
  if(cg==='on')
    return '<span class="badge b-good" title="'+esc(t('tt_oct_cg'))+'"><span class="d"></span>'+t('oct_cg')+'</span>';
  if(cg==='off')
    return '<span class="badge b-old" title="'+esc(t('tt_oct_aff'))+'"><span class="d"></span>'+t('oct_aff')+'</span>';
  return '<span class="badge b-neut" title="'+esc(t('tt_oct_unk'))+'"><span class="d"></span>'+t('oct_unk')+'</span>';
}

// OS line under the machine type. Also decides whether the enhanced 40xx
// events can exist here at all - build 26100+ (Server 2025 / Win11 24H2).
function osLine(a){
  if(!a.os_version) return '';
  const m = String(a.os_version).match(/\((\d+)\)\s*$/);
  const build = m ? parseInt(m[1], 10) : null;
  const old = (build !== null && build < 26100);
  const hint = old ? ' <span class="badge b-neut" title="'+esc(t('tt_os_old'))+'">'+t('b_os_old')+'</span>' : '';
  return '<div class="soft mono" style="font-size:11.5px;margin-top:3px">'+esc(a.os_version)+hint+'</div>';
}

// Restriction (deny) policies - the counterpart to the audit badges. Only shown
// when something is actually restricted; "allow" everywhere needs no badge.
function restrictBadges(a){
  const map = [['restrict_out','r_out'], ['restrict_in','r_in'], ['restrict_dom','r_dom']];
  let out = '';
  map.forEach(([k, lbl]) => {
    const v = a[k];
    if(!v || v === 'allow') return;
    const cls = (v === 'deny-all') ? 'b-bad' : 'b-old';
    out += ' <span class="badge '+cls+'" title="'+esc(t('tt_restrict'))+'"><span class="d"></span>'
         + t(lbl) + ': ' + esc(v) + '</span>';
  });
  return out;
}

// Exception lists already configured in policy on this machine.
function excBadge(a){
  const n = ['exc_client','exc_dc'].reduce((acc, k) =>
      acc + (a[k] ? String(a[k]).split(',').filter(x => x.trim()).length : 0), 0);
  if(!n) return '';
  const all = ['exc_client','exc_dc'].map(k => a[k]).filter(Boolean).join(', ');
  return ' <span class="badge b-neut" title="'+esc(t('tt_exc_cfg')+' '+all)+'">'
       + t('b_exc_cfg').replace('{n}', n) + '</span>';
}

// NTLM/Operational log size: the OS default (~1 MB) rolls over quickly once
// incoming auditing is on - events would then be lost between two poll cycles.
// Credential Guard blocked NTLM on this machine: the regular audit events are
// never written in that case, so the machine's findings are incomplete by
// design. Saying so is more honest than showing an empty list.
function cgBadge(a){
  if(!a.cg) return '';
  return ' <span class="badge b-bad" title="'+esc(t('tt_cg_machine'))+'"><span class="d"></span>'
       + t('b_cg_machine').replace('{n}', a.cg) + '</span>';
}

function logSizeBadge(a){
  const v = a.ntlm_log_kb;
  if (v === null || v === undefined || v === '') return '';
  const kb = (v === 'unset') ? 1028 : parseInt(v, 10);
  if (isNaN(kb) || kb >= 16384) return '';
  const label = (v === 'unset') ? t('log_default') : Math.round(kb/1024*10)/10 + ' MB';
  return ' <span class="badge b-old" title="'+esc(t('tt_logsize'))+'"><span class="d"></span>'+t('b_logsize')+' ('+label+')</span>';
}

function lmCell(v){
  if(v===null || v===undefined || v==='') return dash;
  const n = String(v);
  if(n==='5')  return '<span class="badge b-good" title="'+esc(t('tt_lm5'))+'"><span class="d"></span>5 · '+t('lm_ok')+'</span>';
  if(n==='0'||n==='1'||n==='2')
    return '<span class="badge b-bad" title="'+esc(t('tt_lm_low'))+'"><span class="d"></span>'+esc(n)+' · '+t('lm_bad')+'</span>';
  if(n==='unset')
    return '<span class="badge b-old" title="'+esc(t('tt_lm_unset'))+'"><span class="d"></span>'+t('lm_unset')+'</span>';
  return '<span class="badge b-old" title="'+esc(t('tt_lm_mid'))+'"><span class="d"></span>'+esc(n)+' · '+t('lm_mid')+'</span>';
}

function heartbeat(lastSeen){
  if(!lastSeen) return '<span class="soft">–</span>';
  const ageMin = (Date.now() - new Date(lastSeen).getTime())/60000;
  const ok = ageMin < 60;   // <1h = alive
  const col = ok ? 'var(--good)' : 'var(--still)';
  const txt = ok ? t('hb_on') : t('hb_off');
  return '<span style="display:inline-flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:'+col+'"></span>'+txt+'</span>';
}
function auditCell(a){
  const ok = '<span class="badge b-good"><span class="d"></span>', bad='<span class="badge b-bad"><span class="d"></span>';
  const out = ['audit','deny'].includes(a.outgoing_audit) ? ok+t('au_out_on')+'</span>' : bad+t('au_out_off')+'</span>';
  let dom = '';
  if(a.is_dc) dom = (a.domain_audit=='an') ? ' '+ok+t('au_dom_on')+'</span>' : ' '+bad+t('au_dom_off')+'</span>';
  return out+dom;
}
function encCell(s){
  if(!s) return dash;
  return String(s).split(',').map(x=>{
    const tt=x.trim();
    if(/RC4|DES/i.test(tt)) return '<span class="badge b-old"><span class="d"></span>'+esc(tt)+'</span>';
    if(/AES/i.test(tt))     return '<span class="badge b-good"><span class="d"></span>'+esc(tt)+'</span>';
    return '<span class="soft">'+esc(tt)+'</span>';
  }).join(' ');
}
function bar(nm,n,max,bad){
  const w = max ? Math.max(4,Math.round(n/max*100)) : 0;
  return '<div class="bar"><div class="row"><span class="nm">'+esc(nm||'')+'</span>'+
    '<span class="ct">'+n+'×</span></div><div class="track"><div class="fill '+(bad?'bad':'good')+
    '" style="width:'+w+'%"></div></div></div>';
}

// ---- Bearbeitungsstatus & Was-tun-Hinweise ----
const openHints = new Set();   // opened hints survive the auto-refresh
const openEvents = new Set();  // expanded event rows survive the auto-refresh

// Detail view of an event row in the style of the Windows Event Viewer:
// property on the left, value on the right, everything the event carries.
// Logon type (4624) in plain text. Numbers alone say little; these are the
// values Windows documents for the event. 3 and 8 are the network ones that
// matter for NTLM, 9 is the classic runas /netonly.
function logonTypeText(v){
  if(v===null || v===undefined || v==='') return v;
  const n = String(v).trim();
  const k = {'2':'lt2','3':'lt3','4':'lt4','5':'lt5','7':'lt7','8':'lt8',
             '9':'lt9','10':'lt10','11':'lt11','12':'lt12','13':'lt13'}[n];
  return k ? n + ' – ' + t(k) : n;
}

// One-sentence explanation per event ID - shown in the detail view and as a
// hover on the kind badge, so nobody has to look IDs up elsewhere.
const eidText = id => tOr('eid_' + id, '');

function evDetailRow(e, id){
  if(!openEvents.has(id)) return '';
  const rows = [
    ['d_log',   e.log],
    ['d_eid',   e.event_id + (eidText(e.event_id) ? ' – ' + eidText(e.event_id) : '')],
    ['d_rid',   e.record_id],
    ['d_time',  (e.event_time||'').replace('T',' ')],
    ['d_comp',  e.source],
    ['d_user',  e.user],
    ['d_dom',   e.domain],
    ['d_kind',  e.kind],
    ['d_ver',   e.ntlm_version],
    ['d_auth',  e.auth_method],
    ['d_proc',  e.process],
    ['d_target',e.target_server],
    ['d_ws',    e.workstation],
    ['d_ip',    e.ip],
    ['d_lt',    logonTypeText(e.logon_type)],
    ['d_enc',   e.enc_type],
    ['d_reason',e.reason],
    ['d_mic',   e.mic],
    ['d_epa',   e.epa],
    ['d_os',    e.server_os],
    ['d_fcode', e.failure_code],
    ['d_ppath', e.process_path],
  ].filter(r => r[1] !== null && r[1] !== undefined && r[1] !== '');
  const grid = rows.map(r =>
    '<div class="dlab">'+t(r[0])+'</div><div class="dval">'+esc(r[1])+'</div>').join('');
  return '<tr class="detrow"><td colspan="6">'+
    '<div class="dhead">'+t('d_title')+' — '+esc(e.log)+' / '+esc(e.event_id)+'</div>'+
    '<div class="dgrid">'+grid+'</div></td></tr>';
}

function stSel(key, st){
  return '<select class="stsel st-'+esc(st)+'" data-key="'+esc(key)+'">'+
    ['offen','arbeit','erledigt'].map(s=>'<option value="'+s+'"'+(s===st?' selected':'')+'>'+t('st_'+s)+'</option>').join('')+
    '</select>';
}
function againBadge(row){
  if(row.st==='erledigt' && row.st_at && row.last_seen && row.last_seen > row.st_at)
    return ' <span class="badge b-bad"><span class="d"></span>'+t('again')+'</span>';
  return '';
}
function hintBtn(id){
  return '<span class="hintbtn'+(openHints.has(id)?' on':'')+'" data-h="'+esc(id)+'" title="'+t('what')+'">?</span>';
}
function hintRow(id, cols, text){
  return openHints.has(id) ? '<tr class="hintrow"><td colspan="'+cols+'">'+text+'</td></tr>' : '';
}
function procHint(b){
  return /SMB|Kernel/i.test(b.process||'') ? t('hint_smb') : t('hint_proc');
}

function renderTrend(tr, bucket){
  const el = $('#trend');
  if(!tr || !tr.length){
    el.innerHTML = '<div class="empty">'+t('trend_empty')+'</div>';
    return;
  }
  const max = Math.max(1, ...tr.map(x => x.v1 + x.v2 + x.other));
  const step = Math.max(1, Math.ceil(tr.length / 8));   // max. ~8 Beschriftungen
  const H = 130;
  el.innerHTML = tr.map((x, i) => {
    const h = v => (v ? Math.max(2, Math.round(v / max * H)) : 0);
    const lab = bucket === 'hour'
      ? (LANG === 'de' ? x.b.slice(11,13) + ' Uhr' : x.b.slice(11,13) + ':00')
      : (LANG === 'de' ? x.b.slice(5).replace('-', '.') : x.b.slice(5));
    const show = (i % step === 0 || i === tr.length - 1) ? lab : '';
    const tip = x.b + ' — NTLMv1: ' + x.v1 + ' · NTLMv2: ' + x.v2 +
                ' · ' + t('tip_nover') + ': ' + x.other + ' · Kerberos: ' + x.krb;
    return '<div class="tcol" title="' + esc(tip) + '"><div class="tbar">' +
      (x.other ? '<div class="tseg s0" style="height:' + h(x.other) + 'px"></div>' : '') +
      (x.v2    ? '<div class="tseg s2" style="height:' + h(x.v2)    + 'px"></div>' : '') +
      (x.v1    ? '<div class="tseg s1" style="height:' + h(x.v1)    + 'px"></div>' : '') +
      '</div><div class="tlab">' + show + '</div></div>';
  }).join('');
}

function buildParams(){
  const p = new URLSearchParams();
  if(state.f=="v1") p.set('version','NTLMv1');
  else if(state.f=="v2") p.set('version','NTLMv2');
  else if(state.f=="outgoing"||state.f=="domain") p.set('kind',state.f);
  if(state.q) p.set('q',state.q);
  if(state.a && state.a!="all") p.set('acct', state.a);
  if(state.src) p.set('source', state.src);
  p.set('range', state.r || 'all');
  return p;
}

// Badge helpers. Declared as hoisted functions on purpose: the render function
// renders sections top-down, and a const arrow defined further down would be in
// the temporal dead zone for the sections above it (that bug once killed
// everything below the incoming table).
function blockedBadge(v){
  if (!v) return '';
  const num = (typeof v === 'number') ? v + ' ' : '';
  return ' <span class="badge b-bad b-inline" title="'+esc(t('tt_blocked'))+'"><span class="d"></span>'
    + num + t('b_blocked') + '</span>';
}

function ipBadge(tgt){
  return targetIsIp(tgt)
    ? '<span class="badge b-bad b-inline" title="'+esc(t('tt_ip'))+'"><span class="d"></span>'+t('b_ip')+'</span>'
    : '';
}

function tgtCell(tgt){
  return targetIsIp(tgt)
    ? '<span class="tgtwrap"><span>'+esc(tgt)+'</span>'+ipBadge(tgt)+'</span>'
    : esc(tgt);
}

// Heatmap weekday x hour. Intensity is relative to the busiest cell, so a
// quiet environment still shows its pattern instead of a uniformly dark grid.
function renderHeat(heat){
  const wrap = document.getElementById('heatwrap');
  const hint = document.getElementById('heathint');
  const sec  = document.getElementById('sec-heat');
  if(!wrap) return;
  const rows = heat || [];
  const max = rows.reduce((m,r) => Math.max(m, ...r), 0);
  sec.style.display = max > 0 ? '' : 'none';
  if(!max){ wrap.innerHTML = ''; hint.textContent = ''; return; }

  const days = ['d_mon','d_tue','d_wed','d_thu','d_fri','d_sat','d_sun'];
  let html = '<div></div>';
  for(let h = 0; h < 24; h++) html += '<div class="hhr">' + (h % 6 === 0 ? h : '') + '</div>';
  rows.forEach((row, di) => {
    html += '<div class="hday">' + t(days[di]) + '</div>';
    row.forEach((n, h) => {
      const a = n ? (0.16 + (n / max) * 0.84).toFixed(2) : 0;
      const bg = n ? 'rgba(224,122,95,' + a + ')' : '';
      const ti = t('heat_cell').replace('{d}', t(days[di]))
                              .replace('{h}', String(h).padStart(2,'0'))
                              .replace('{n}', n);
      html += '<div class="hcell" style="' + (bg ? 'background:' + bg : '') + '" title="' + esc(ti) + '"></div>';
    });
  });
  wrap.innerHTML = html;

  // Name the single busiest slot - that is usually the batch job worth hunting.
  let bd = 0, bh = 0;
  rows.forEach((row, di) => row.forEach((n, h) => { if(n > rows[bd][bh]){ bd = di; bh = h; } }));
  const off = rows[bd][bh];
  hint.innerHTML = '<span class="warn">' + esc(t('heat_peak')
      .replace('{d}', t(days[bd])).replace('{h}', String(bh).padStart(2,'0'))
      .replace('{n}', off)) + '</span>';
}

// Sparkline for one program: shows whether this specific row is shrinking or
// growing. A rising line inside a falling overall trend is the row to attack.
function sparkline(series){
  if(!series || series.length < 2) return '';
  const vals = series.map(x => x[1]);
  const max = Math.max(...vals), w = 96, h = 20;
  const pts = vals.map((v, i) =>
      (i * (w / (vals.length - 1))).toFixed(1) + ',' + (h - (max ? v / max : 0) * (h - 3)).toFixed(1)
  ).join(' ');
  const delta = vals[vals.length - 1] - vals[0];
  const col = delta < 0 ? '#4ea87b' : (delta > 0 ? '#e0644f' : '#7c8b9d');
  const lbl = (delta > 0 ? '+' : '') + delta;
  const ti = t('spark_tt').replace('{n}', vals.length);
  return '<span class="sparkrow" title="' + esc(ti) + '">'
       + '<svg width="' + w + '" height="' + h + '" aria-hidden="true"><polyline fill="none" stroke="' + col
       + '" stroke-width="1.7" stroke-linejoin="round" stroke-linecap="round" points="' + pts + '"/></svg>'
       + '<span class="soft mono" style="color:' + col + ';font-size:12px">' + lbl + '</span></span>';
}

// --- GPO exception-list generator -------------------------------------------
// Turns the still-open rows into a paste-ready server list for the two
// "Restrict NTLM" exception policies. An exception is a stay of execution,
// not a fix - the note in the box says so.
function excName(target){
  if(!target) return null;
  let v = String(target).trim();
  if(v.startsWith('(')) return null;                 // placeholders
  const i = v.indexOf('/');
  if(i > 0) v = v.slice(i + 1);                      // strip SPN class (cifs/, TERMSRV/...)
  v = v.replace(/\\/g, '').trim();
  return v || null;
}

// Entries already present in Group Policy on any reporting machine - proposing
// them again would just inflate the list.
function alreadyExcepted(){
  const set = new Set();
  ((LAST && LAST.agents) || []).forEach(a => {
    ['exc_client', 'exc_dc'].forEach(k => {
      if(!a[k]) return;
      String(a[k]).split(',').map(x => x.trim().toLowerCase())
                  .filter(Boolean).forEach(x => set.add(x));
    });
  });
  return set;
}

function buildExceptions(which){
  if(!LAST) return [];
  const rows = (which === 'out') ? (LAST.blockers || []) : (LAST.domain || []);
  const have = alreadyExcepted();
  const seen = new Set(); const out = [];
  rows.forEach(r => {
    if(r.st === 'erledigt') return;                  // fixed -> no exception needed
    const n = excName(r.target);
    if(!n) return;
    const k = n.toLowerCase();
    if(seen.has(k) || have.has(k)) return;      // skip what policy already covers
    seen.add(k); out.push(n);
  });
  return out.sort((a, b) => a.localeCompare(b));
}

function toggleExc(which){
  const box = document.getElementById('excbox-' + which);
  if(box.style.display !== 'none'){ box.style.display = 'none'; return; }
  const list = buildExceptions(which);
  const ta = box.querySelector('textarea');
  ta.value = list.length ? list.join('\n') : t('exc_empty');
  box.querySelector('.exc-count').textContent = list.length;
  box.style.display = '';
}

function copyExc(which, btn){
  const ta = document.querySelector('#excbox-' + which + ' textarea');
  ta.select();
  const done = () => { btn.textContent = t('exc_copied');
                       setTimeout(() => { btn.textContent = t('exc_copy'); }, 1500); };
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(ta.value).then(done, () => { document.execCommand('copy'); done(); });
  } else { document.execCommand('copy'); done(); }
}

// Last successful API payload - the exception-list generator reads from it so
// it always reflects exactly what the tables show (same filters, same range).
let LAST = null;

async function load(){
  // Do not re-render while a status field is being operated
  const ae = document.activeElement;
  if(ae && ae.classList && ae.classList.contains('stsel')) return;
  const p = buildParams();

  let d;
  try {
    const r = await fetch('/api/data?'+p.toString());
    if(r.status===401){ window.location='/login'; return; }
    d = await r.json();
  }
  catch(e){ return; }
  LAST = d;

  $('#s-total').textContent = d.stats.total;
  $('#s-v1').textContent = d.stats.v1;
  $('#s-v2').textContent = d.stats.v2;
  $('#s-krb').textContent = d.stats.krb;
  $('#s-src').textContent = d.stats.sources;
  $('#s-proc').textContent = d.stats.procs;
  renderTrend(d.trend, d.trend_bucket);
  renderHeat(d.heat);

  // NTLMv1-SSO: Sektion nur einblenden, wenn es tatsaechlich Funde gibt
  const v1s = d.v1sso || [];
  document.getElementById('sec-v1sso').style.display = v1s.length ? '' : 'none';
  if (v1s.length) {
    $('#v1sso').innerHTML = v1s.map(x=>`<tr class="${x.st==='erledigt'?'row-done':''}">
        <td class="strong">${esc(x.user)}</td>
        <td>${esc(x.target)}</td>
        <td class="num-cell">${x.n}${blockedBadge(x.blocked)}</td>
        <td>${x.blocked
              ? '<span class="badge b-neut"><span class="d"></span>'+t('st_blocked')+'</span>'
              : '<span class="badge b-bad"><span class="d"></span>'+t('st_used')+'</span>'}</td>
        <td>${stSel(x.key,x.st)}${againBadge(x)}</td>
        <td class="soft mono">${when(x.last_seen)}</td></tr>`).join('');
  }

  // "Why NTLM?" - each cause gets a concrete remediation hint, because the
  // reason alone ("target name contains an IP address") does not say what to do.
  const rs = d.reasons || [];
  // Relay exposure: only the 40xx events carry MIC and channel-binding status,
  // so this is always a subset - stating the base makes that explicit.
  const rel = d.stats.relay || 0, relScope = d.stats.relay_scope || 0;
  const relEl = document.getElementById('relayline');
  if (relEl) {
    relEl.innerHTML = (rel > 0)
      ? '<span class="warn">'+t('relay_warn').replace('{n}', rel).replace('{t}', relScope)+'</span>'
      : (relScope > 0 ? '<span class="ok">'+t('relay_ok').replace('{t}', relScope)+'</span>' : '');
  }
  document.getElementById('sec-why').style.display = rs.length ? '' : 'none';
  if (rs.length) {
    $('#reasons').innerHTML = rs.map(r=>`<tr>
        <td class="strong">${esc(tOr('rid_'+r.rid, r.text))}</td>
        <td class="soft">${esc(tOr('fix_'+r.cat, ''))}</td>
        <td class="num-cell">${r.n}</td>
        <td class="soft">${r.procs}</td>
        <td class="soft">${r.machines}</td>
        <td class="soft mono">${when(r.last_seen)}</td></tr>`).join('');
  }

  // Incoming NTLM: only show the section when the incoming audit actually
  // produces events, so it does not sit there empty on every installation.
  const inc = d.incoming || [];
  document.getElementById('sec-incoming').style.display = inc.length ? '' : 'none';
  if (inc.length) {
    $('#incoming').innerHTML = inc.map(x=>`<tr class="${x.st==='erledigt'?'row-done':''}">
        <td class="strong">${esc(x.machine)}</td>
        <td>${esc(x.process)}</td>
        <td class="num-cell">${x.n}${blockedBadge(x.blocked)}</td>
        <td class="soft">${x.users}</td>
        <td>${stSel(x.key,x.st)}${againBadge(x)}</td>
        <td class="soft mono">${when(x.last_seen)}</td></tr>`).join('');
  }

  // A target given as an IP address is the single most common reason Kerberos
  // is skipped: it needs a name to look up an SPN. Works on any Windows
  // version - unlike the reason field, which only the 40xx events provide.
  // Target + badge share a flex wrapper: side by side on one line, and when
  // the cell is too narrow the badge wraps cleanly left-aligned underneath
  // instead of dangling indented.
  // Blocked events (enforce policy active): shown as a red badge behind the
  // count - these rows are an alarm/success signal, not a to-do anymore.
  $('#blockers').innerHTML = (d.blockers&&d.blockers.length)
    ? d.blockers.map(b=>`<tr class="${b.st==='erledigt'?'row-done':''}">
        <td class="strong">${esc(b.process)}${hintBtn(b.key)}</td>
        <td>${tgtCell(b.target)}</td>
        <td class="num-cell">${b.n}${blockedBadge(b.blocked)}</td>
        <td>${sparkline((LAST.spark||{})[b.process])}</td>
        <td>${userList(b.who)}</td>
        <td class="soft">${b.sources}</td>
        <td>${stSel(b.key,b.st)}${againBadge(b)}</td>
        <td class="soft mono">${when(b.last_seen)}</td></tr>`+hintRow(b.key,7,procHint(b))).join('')
    : '<tr><td colspan="8" class="empty">'+t('empty_blockers')+'</td></tr>';

  $('#domain').innerHTML = (d.domain&&d.domain.length)
    ? d.domain.map(x=>`<tr class="${x.st==='erledigt'?'row-done':''}">
        <td class="strong">${esc(x.workstation)}${hintBtn(x.key)}</td>
        <td>${tgtCell(x.target)}</td>
        <td>${userList(x.who)}</td>
        <td class="num-cell">${x.n}${blockedBadge(x.blocked)}</td>
        <td>${stSel(x.key,x.st)}${againBadge(x)}</td>
        <td class="soft mono">${when(x.last_seen)}</td></tr>`+hintRow(x.key,6,t('hint_dom'))).join('')
    : '<tr><td colspan="6" class="empty">'+t('empty_domain')+'</td></tr>';

  const umax = Math.max(1, ...d.v1_users.map(x=>x.n));
  $('#v1-users').innerHTML = d.v1_users.length
    ? d.v1_users.map(x=>bar(x.name,x.n,umax,true)).join('')
    : '<div class="empty">'+t('empty_v1')+'</div>';

  $('#kerb').innerHTML = (d.kerberos&&d.kerberos.length)
    ? d.kerberos.map(k=>`<tr>
        <td class="strong">${esc(k.service)}</td>
        <td class="soft">${k.accounts}</td>
        <td class="num-cell">${k.n}</td>
        <td>${encCell(k.enc)}${/RC4|DES/i.test(k.enc||'')?hintBtn('krbs|'+k.service):''}</td>
        <td class="soft mono">${when(k.last_seen)}</td></tr>`+
        (/RC4|DES/i.test(k.enc||'')?hintRow('krbs|'+k.service,5,t('hint_rc4')):'')).join('')
    : '<tr><td colspan="5" class="empty">'+t('empty_krb')+'</td></tr>';

  $('#kerb-accounts').innerHTML = (d.kerberos_accounts&&d.kerberos_accounts.length)
    ? d.kerberos_accounts.map(k=>`<tr>
        <td class="strong">${esc(k.account)}</td>
        <td>${userList(k.services)}</td>
        <td class="num-cell">${k.n}</td>
        <td>${encCell(k.enc)}${/RC4|DES/i.test(k.enc||'')?hintBtn('krba|'+k.account):''}</td>
        <td class="soft mono">${when(k.last_seen)}</td></tr>`+
        (/RC4|DES/i.test(k.enc||'')?hintRow('krba|'+k.account,5,t('hint_rc4')):'')).join('')
    : '<tr><td colspan="5" class="empty">'+t('empty_krba')+'</td></tr>';

  // Data basis: two weeks of normal operation is the widely recommended
  // minimum, so that weekly scheduled tasks and batch jobs have run at least
  // once. Below that, an empty finding list means little.
  const cd = d.stats.coverage_days, ct = d.stats.coverage_target || 14;
  const covEl = document.getElementById('coverage');
  if (covEl) {
    if (cd === null || cd === undefined) covEl.innerHTML = '';
    else if (cd >= ct)
      covEl.innerHTML = '<span class="ok">'+t('cov_ok').replace('{d}', cd)+'</span>';
    else
      covEl.innerHTML = '<span class="warn">'+t('cov_warn').replace('{d}', cd).replace('{t}', ct)+'</span>';
  }

  syncNav(d);
  syncMachines(d.agents);
  $('#agents').innerHTML = (d.agents&&d.agents.length)
    ? d.agents.map(a=>`<tr>
        <td class="strong">${esc(a.source)}</td>
        <td class="soft">${a.is_dc?t('type_dc'):t('type_member')}${osLine(a)}</td>
        <td>${heartbeat(a.last_seen)}</td>
        <td>${auditCell(a)}${logSizeBadge(a)}${cgBadge(a)}${restrictBadges(a)}${excBadge(a)}</td>
        <td>${lmCell(a.lm_level)}</td>
        <td>${octCell(a)}</td>
        <td class="num-cell">${a.events}</td>
        <td class="soft mono">${when(a.last_seen)}</td></tr>`).join('')
    : '<tr><td colspan="8" class="empty">'+t('empty_agents')+'</td></tr>';

  $('#rows').innerHTML = d.events.length
    ? d.events.map(e=>{
        const fid = 'fb|'+e.source+'|'+e.record_id;
        const eid = 'ev|'+e.source+'|'+e.log+'|'+e.record_id;
        const fb = e.auth_method==='Fallback';
        const open = openEvents.has(eid);
        return `<tr class="evrow${open?' evopen':''}" data-ev="${esc(eid)}">
        <td class="soft mono"><span class="chev">${open?'▾':'▸'}</span>${when(e.event_time)}</td>
        <td>${artBadge(e)}${fb?hintBtn(fid):''}</td>
        <td>${esc(e.user)||dash}</td>
        <td>${esc(e.process)||dash}</td>
        <td>${esc(e.target_server||e.workstation)||dash}</td>
        <td class="soft">${esc(e.source)}</td></tr>`
        + evDetailRow(e, eid)
        + (fb?hintRow(fid,6,t('hint_fb')):'');
      }).join('')
    : '<tr><td colspan="6" class="empty">'+t('empty_events')+'</td></tr>';

  const tm = new Date(d.generated_at);
  $('#updated').textContent = tm.toLocaleTimeString(LOCALE());
  $('#foot').textContent = t('as_of') + tm.toLocaleString(LOCALE());
}

// Two independent chip groups: kind/version (data-f) and account type (data-a).
// Each only clears the "on" state within its own group.
document.querySelectorAll('.chip:not(.achip)').forEach(c=>c.addEventListener('click',()=>{
  document.querySelectorAll('.chip:not(.achip)').forEach(x=>x.classList.remove('on'));
  c.classList.add('on'); state.f=c.dataset.f; load();
}));
document.querySelectorAll('.achip').forEach(c=>c.addEventListener('click',()=>{
  document.querySelectorAll('.achip').forEach(x=>x.classList.remove('on'));
  c.classList.add('on'); state.a=c.dataset.a; load();
}));

// Toggle hints and set status: delegated so it survives the 5s refresh
document.addEventListener('click', e=>{
  const h = e.target.closest('.hintbtn');
  if(h){ const id=h.dataset.h; openHints.has(id)?openHints.delete(id):openHints.add(id); load(); return; }
  const row = e.target.closest('tr.evrow');
  if(row){
    const id = row.dataset.ev;
    openEvents.has(id) ? openEvents.delete(id) : openEvents.add(id);
    load();
  }
});
document.addEventListener('change', e=>{
  const s = e.target.closest('.stsel');
  if(!s) return;
  s.blur();
  fetch('/item-status',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({key:s.dataset.key, status:s.value})})
    .then(r=>{ if(r.status===401) window.location='/login'; else load(); })
    .catch(()=>{});
});

document.getElementById('csvbtn').addEventListener('click', ()=>{
  window.location = '/api/export.csv?' + buildParams().toString();
});

// Section nav: one chip per section with its finding count. Sections with no
// findings stay visible but greyed out - "checked, nothing there" is the good
// news and worth showing, unlike hiding it entirely.
const NAV_COUNTS = {
  'sec-programs':          d => (d.blockers||[]).length,
  'sec-heat':              d => (d.heat||[]).reduce((a,r)=>a+r.reduce((x,y)=>x+(y>0?1:0),0),0),
  'sec-why':               d => (d.reasons||[]).length,
  'sec-incoming':          d => (d.incoming||[]).length,
  'sec-v1sso':             d => (d.v1sso||[]).length,
  'sec-v1':                d => (d.v1_users||[]).length,
  'sec-domain':            d => (d.domain||[]).length,
  'sec-kerberos-accounts': d => (d.kerberos_accounts||[]).length,
  'sec-agents':            d => (d.agents||[]).length,
  'sec-events':            d => (d.events||[]).length,
};
function syncNav(d){
  document.querySelectorAll('.navchip').forEach(c=>{
    const id = c.dataset.sec;
    const fn = NAV_COUNTS[id];
    const n = fn ? fn(d) : 0;
    const tone = c.dataset.tone || 'neut';
    c.classList.remove('t-bad','t-warn','t-good','empty');
    if(n > 0 && tone !== 'neut') c.classList.add('t-'+tone);
    if(n === 0) c.classList.add('empty');
    let badge = c.querySelector('.n');
    if(!badge){ badge = document.createElement('span'); badge.className = 'n'; c.appendChild(badge); }
    badge.textContent = n;
  });
}
document.querySelectorAll('.navchip').forEach(c=>c.addEventListener('click',()=>{
  const el = document.getElementById(c.dataset.sec);
  // Hidden sections (v1sso / incoming without findings) cannot be scrolled to
  if(!el || el.offsetParent === null) return;
  el.scrollIntoView({behavior:'smooth', block:'start'});
}));

// Highlight the section currently in view
if('IntersectionObserver' in window){
  const obs = new IntersectionObserver(entries=>{
    entries.forEach(e=>{
      const chip = document.querySelector('.navchip[data-sec="'+e.target.id+'"]');
      if(chip) chip.classList.toggle('active', e.isIntersecting);
    });
  }, {rootMargin:'-15% 0px -70% 0px'});
  document.querySelectorAll('section[id]').forEach(sec=>obs.observe(sec));
}

// Machine picker: filters every panel, not just the event list. The option list
// is rebuilt from the agent list on each load, keeping the current choice.
function syncMachines(agents){
  const sel = document.getElementById('srcsel');
  if(!sel) return;
  const names = (agents||[]).map(a=>a.source).sort();
  const sig = names.join('|');
  if(sel.dataset.sig === sig) return;
  sel.dataset.sig = sig;
  const cur = state.src;
  sel.innerHTML = '<option value="">'+t('g_all_mach')+'</option>' +
    names.map(n=>'<option value="'+esc(n)+'">'+esc(n)+'</option>').join('');
  sel.value = cur;
}
const srcsel = document.getElementById('srcsel');
if(srcsel) srcsel.addEventListener('change', ()=>{ state.src = srcsel.value; load(); });
const hd = document.getElementById('hidedone');
if(hd) hd.addEventListener('change', ()=>{
  state.hidedone = hd.checked;
  document.body.classList.toggle('hide-done', state.hidedone);
});

document.querySelectorAll('.rchip[data-r]').forEach(c=>c.addEventListener('click',()=>{
  document.querySelectorAll('.rchip[data-r]').forEach(x=>x.classList.remove('on'));
  c.classList.add('on'); state.r=c.dataset.r; load();
}));

// Metric cards: apply the filter (if any) and jump to the matching section
function applyFilter(f){
  state.f = f;
  document.querySelectorAll('.chip:not(.achip)').forEach(x=>x.classList.toggle('on', x.dataset.f===f));
  load();
}
function activateStat(c){
  if(c.dataset.filter) applyFilter(c.dataset.filter);
  const sel = c.dataset.scroll;
  if(sel){ const el=document.querySelector(sel); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); }
}
document.querySelectorAll('.stat.clickable').forEach(c=>{
  c.addEventListener('click', ()=>activateStat(c));
  c.addEventListener('keydown', e=>{ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); activateStat(c); } });
});
$('#q').addEventListener('input',e=>{ state.q=e.target.value; clearTimeout(window._t); window._t=setTimeout(load,300); });
applyStatic();
load(); setInterval(load,5000);
</script>
</body>
</html>"""


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

    conn = init_db(args.db)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)

    scheme = "http"
    if args.cert:
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
                cutoff = (datetime.now() - timedelta(days=args.retention_days)
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
