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
    last_seen       TEXT
);
"""

FIELDS = ("record_id", "log", "event_id", "kind", "event_time", "user",
          "domain", "ntlm_version", "process", "target_server",
          "workstation", "ip", "logon_type", "enc_type", "auth_method",
          "reason")


def init_db(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript(SCHEMA)
    # Migration: fehlende Spalten in bestehenden DBs nachziehen
    have = {r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
    for col in ("enc_type", "auth_method", "reason"):
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
                "incoming_audit,domain_audit,last_seen) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(source) DO UPDATE SET is_dc=excluded.is_dc, "
                "agent_version=excluded.agent_version, outgoing_audit=excluded.outgoing_audit, "
                "incoming_audit=excluded.incoming_audit, domain_audit=excluded.domain_audit, "
                "last_seen=excluded.last_seen",
                (source, 1 if p.get("is_dc") else 0, p.get("agent_version"),
                 p.get("outgoing_audit"), p.get("incoming_audit"),
                 p.get("domain_audit"), now))
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
                e.get("process"),
                e.get("target_server"),
                e.get("workstation"),
                e.get("ip"),
                e.get("logon_type"),
                e.get("enc_type"),
                e.get("auth_method"),
                e.get("reason"),
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
                "workstation", "ip", "logon_type", "enc_type", "reason"]
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
                    "Reason"])
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
        tf = "event_time >= ?" if cutoff else "1=1"    # fester String, kein User-Input
        tp = [cutoff] if cutoff else []
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
                "outbound": c.execute(f"SELECT COUNT(*) FROM events WHERE event_id IN (8001,4020,4021) AND {tf}", tp).fetchone()[0],
                "sources": c.execute(f"SELECT COUNT(DISTINCT source) FROM events WHERE {tf}", tp).fetchone()[0],
                "procs":   c.execute(f"SELECT COUNT(DISTINCT process) FROM events "
                                     f"WHERE process IS NOT NULL AND process NOT LIKE '(%' AND {tf}", tp).fetchone()[0],
                "krb":     c.execute(f"SELECT COUNT(DISTINCT target_server) FROM events WHERE kind='kerberos' AND {tf}", tp).fetchone()[0],
                "fallback": c.execute(f"SELECT COUNT(*) FROM events WHERE auth_method='Fallback' AND {tf}", tp).fetchone()[0],
                # Enhanced audits (Server 2025): NTLMv1-derived SSO credentials.
                # From October 2026 Windows blocks these by itself (BlockNtlmv1SSO).
                "v1sso": c.execute(f"SELECT COUNT(*) FROM events WHERE kind='ntlmv1sso' AND {tf}", tp).fetchone()[0],
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
            top_proc = [dict(name=r[0], n=r[1]) for r in c.execute(
                f"SELECT process, COUNT(*) "
                f"FROM events WHERE kind='outgoing' AND process IS NOT NULL AND {tf} "
                f"GROUP BY process ORDER BY COUNT(*) DESC LIMIT 15", tp).fetchall()]
            v1_users = [dict(name=r[0], n=r[1]) for r in c.execute(
                f"SELECT user, COUNT(*) FROM events WHERE ntlm_version='NTLMv1' AND {tf} "
                f"GROUP BY user ORDER BY COUNT(*) DESC LIMIT 15", tp).fetchall()]
            # Shutdown blockers: outgoing NTLM (8001) - breaks once the outgoing policy denies
            blockers = [with_status("proc", r[0], r[1],
                             dict(process=r[0], target=r[1], n=r[2],
                             users=r[3], sources=r[4], last_seen=r[5], who=r[6])) for r in c.execute(
                f"SELECT COALESCE(process,'(unbekannt)'), COALESCE(target_server,'(unbekannt)'), "
                f"COUNT(*), COUNT(DISTINCT user), COUNT(DISTINCT source), MAX(event_time), "
                f"GROUP_CONCAT(DISTINCT user) "
                f"FROM events WHERE event_id IN (8001,4020,4021) AND {tf} "
                f"GROUP BY process, target_server ORDER BY COUNT(*) DESC LIMIT 50", tp).fetchall()]
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
                           n=r[3], last_seen=r[4], who=r[5])) for r in c.execute(
                f"SELECT COALESCE(workstation,'(unbekannt)'), COALESCE(target_server,'(unbekannt)'), "
                f"COUNT(DISTINCT user), COUNT(*), MAX(event_time), GROUP_CONCAT(DISTINCT user) "
                f"FROM events WHERE event_id IN (8004,4022,4023,4030,4031,4032,4033) AND {tf} "
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
                           last_seen=r[6], events=r[7] or 0, last_event=r[8]) for r in c.execute(
                "SELECT a.source, a.is_dc, a.agent_version, a.outgoing_audit, a.incoming_audit, "
                "a.domain_audit, a.last_seen, "
                "(SELECT COUNT(*) FROM events e WHERE e.source=a.source), "
                "(SELECT MAX(event_time) FROM events e WHERE e.source=a.source) "
                "FROM agents a ORDER BY a.last_seen DESC").fetchall()]
            cols2 = ["source"] + list(FIELDS)
            rows = c.execute(
                f"SELECT {','.join(cols2)} FROM events{clause} "
                f"ORDER BY event_time DESC, id DESC LIMIT ?",
                params + [limit]).fetchall()
            events = [dict(zip(cols2, r)) for r in rows]

        return {"stats": stats, "v1sso": v1sso, "trend": trend, "trend_bucket": ("hour" if rng == "24h" else "day"),
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
  </div>

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
      <p data-i18n="prog_p">These programs authenticate outward via NTLM. Before disabling NTLM they should be reviewed or reconfigured. "SMB/Kernel" means file-share access – no single program can be named there.</p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_prog">Program</th><th data-i18n="th_target">Target server</th><th data-i18n="th_count">Count</th><th data-i18n="th_users">Users</th><th data-i18n="th_comps">Computers (no.)</th><th data-i18n="th_status">Status</th><th data-i18n="th_last">Last seen</th></tr></thead>
        <tbody id="blockers"></tbody>
      </table>
    </div>
  </section>

  <!-- Wer nutzt NTLM, wohin (8004) -->
  <section id="sec-domain">
    <div class="head">
      <h2 data-i18n="dom_h">Who uses NTLM – and where to</h2>
      <p data-i18n="dom_p">Reported by the domain controller: which computer connects to which server via NTLM. The most reliable overall view – even when no program name can be determined.</p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_srccomp">Computer (source)</th><th data-i18n="th_target2">Target server</th><th data-i18n="th_users2">Users</th><th data-i18n="th_count2">Count</th><th data-i18n="th_status2">Status</th><th data-i18n="th_last2">Last seen</th></tr></thead>
        <tbody id="domain"></tbody>
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
        <thead><tr><th data-i18n="th_account">Account</th><th data-i18n="th_services">Services</th><th data-i18n="th_tickets">Tickets</th><th data-i18n="th_enc2">Encryption</th><th data-i18n="th_last4">Last seen</th></tr></thead>
        <tbody id="kerb-accounts"></tbody>
      </table>
    </div>
  </section>

  <!-- Maschinen / Heartbeat + Auditing-Status -->
  <section id="sec-agents">
    <div class="head">
      <h2 data-i18n="ag_h">Machines & auditing status</h2>
      <p data-i18n="ag_p">Which agents report – and whether the required auditing is enabled there. A green dot means "reported recently". Red auditing badges explain why a machine may not deliver data.</p>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th data-i18n="th_machine">Machine</th><th data-i18n="th_type">Type</th><th data-i18n="th_status3">Status</th><th>Auditing</th><th>Events</th><th data-i18n="th_lastrep">Last reported</th></tr></thead>
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
  lab_total:'NTLM gesamt', sub_total:'erfasste Vorgänge', tt_total:'Alle Ereignisse anzeigen',
  lab_v1:'Unsicher', sub_v1:'NTLMv1 – zuerst ablösen', tt_v1:'Zu den unsicheren Anmeldungen springen',
  lab_v2:'Veraltet', sub_v2:'NTLMv2 – besser, aber alt', tt_v2:'Zu den veralteten Anmeldungen springen',
  lab_krb:'Schon sicher', sub_krb:'Dienste über Kerberos', tt_krb:'Zur Kerberos-Übersicht springen',
  lab_src:'Beteiligte Computer', sub_src:'Quellen & Server', tt_src:'Zur Domänen-Übersicht springen',
  lab_proc:'Erkannte Programme', sub_proc:'die NTLM auslösen', tt_proc:'Zu den Programmen springen',
  trend_h:'Verlauf',
  trend_p:'NTLM-Vorgänge im gewählten Zeitraum – diese Balken sollen über die Wochen gegen null gehen. Rot = NTLMv1, Gelb = NTLMv2, Grau = NTLM ohne Versionsangabe (Domäne/ausgehend). Kerberos steht zur Einordnung im Tooltip.',
  prog_h:'Programme, die noch NTLM verwenden',
  prog_p:'Diese Programme melden sich per NTLM nach außen an. Vor dem Abschalten von NTLM sollten sie geprüft oder umgestellt werden. „SMB/Kernel" bedeutet Dateifreigabe-Zugriff – dort lässt sich kein einzelnes Programm benennen.',
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
  lab_total:'NTLM total', sub_total:'recorded events', tt_total:'Show all events',
  lab_v1:'Insecure', sub_v1:'NTLMv1 – replace first', tt_v1:'Jump to insecure logons',
  lab_v2:'Outdated', sub_v2:'NTLMv2 – better, but old', tt_v2:'Jump to outdated logons',
  lab_krb:'Already secure', sub_krb:'services via Kerberos', tt_krb:'Jump to the Kerberos overview',
  lab_src:'Computers involved', sub_src:'sources & servers', tt_src:'Jump to the domain overview',
  lab_proc:'Programs detected', sub_proc:'that trigger NTLM', tt_proc:'Jump to programs',
  trend_h:'Trend',
  trend_p:'NTLM activity in the selected time range – these bars should approach zero over the weeks. Red = NTLMv1, yellow = NTLMv2, gray = NTLM without version info (domain/outgoing). Kerberos is shown in the tooltip for context.',
  prog_h:'Programs still using NTLM',
  prog_p:'These programs authenticate outward via NTLM. Before disabling NTLM they should be reviewed or reconfigured. "SMB/Kernel" means file-share access – no single program can be named there.',
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
const state = {f:"all", q:"", r:"7d"};
const $ = s => document.querySelector(s);
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const dash = '<span class="soft">–</span>';
const when = s => esc((s||"").replace("T"," ").slice(0,16));
function userList(who){
  if(!who) return dash;
  const arr = String(who).split(',').map(s=>s.trim()).filter(Boolean);
  if(arr.length<=3) return esc(arr.join(', '));
  return esc(arr.slice(0,3).join(', ')) + ' <span class="soft">+'+(arr.length-3)+' '+t('more')+'</span>';
}

function artBadge(e){
  let fb = (e.auth_method=="Fallback") ? ' <span class="badge b-old"><span class="d"></span>'+t('b_fb')+'</span>' : '';
  if(e.auth_method=="Downgrade") fb = ' <span class="badge b-bad"><span class="d"></span>'+t('b_down')+'</span>';
  if(e.ntlm_version=="NTLMv1") return '<span class="badge b-bad"><span class="d"></span>'+t('b_v1')+'</span>'+fb;
  if(e.ntlm_version=="NTLMv2") return '<span class="badge b-old"><span class="d"></span>'+t('b_v2')+'</span>'+fb;
  if(e.kind=="kerberos")       return '<span class="badge b-good"><span class="d"></span>'+t('b_krb')+'</span>';
  if(e.kind=="domain")         return '<span class="badge b-neut"><span class="d"></span>'+t('b_dom')+'</span>';
  if(e.kind=="outgoing")       return '<span class="badge b-neut"><span class="d"></span>'+t('b_out')+'</span>';
  return '<span class="soft">NTLM</span>';
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
function evDetailRow(e, id){
  if(!openEvents.has(id)) return '';
  const rows = [
    ['d_log',   e.log],
    ['d_eid',   e.event_id],
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
    ['d_lt',    e.logon_type],
    ['d_enc',   e.enc_type],
    ['d_reason',e.reason],
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
  p.set('range', state.r || 'all');
  return p;
}

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

  $('#s-total').textContent = d.stats.total;
  $('#s-v1').textContent = d.stats.v1;
  $('#s-v2').textContent = d.stats.v2;
  $('#s-krb').textContent = d.stats.krb;
  $('#s-src').textContent = d.stats.sources;
  $('#s-proc').textContent = d.stats.procs;
  renderTrend(d.trend, d.trend_bucket);

  // NTLMv1-SSO: Sektion nur einblenden, wenn es tatsaechlich Funde gibt
  const v1s = d.v1sso || [];
  document.getElementById('sec-v1sso').style.display = v1s.length ? '' : 'none';
  if (v1s.length) {
    $('#v1sso').innerHTML = v1s.map(x=>`<tr class="${x.st==='erledigt'?'row-done':''}">
        <td class="strong">${esc(x.user)}</td>
        <td>${esc(x.target)}</td>
        <td class="num-cell">${x.n}</td>
        <td>${x.blocked
              ? '<span class="badge b-neut"><span class="d"></span>'+t('st_blocked')+'</span>'
              : '<span class="badge b-bad"><span class="d"></span>'+t('st_used')+'</span>'}</td>
        <td>${stSel(x.key,x.st)}${againBadge(x)}</td>
        <td class="soft mono">${when(x.last_seen)}</td></tr>`).join('');
  }

  $('#blockers').innerHTML = (d.blockers&&d.blockers.length)
    ? d.blockers.map(b=>`<tr class="${b.st==='erledigt'?'row-done':''}">
        <td class="strong">${esc(b.process)}${hintBtn(b.key)}</td>
        <td>${esc(b.target)}</td>
        <td class="num-cell">${b.n}</td>
        <td>${userList(b.who)}</td>
        <td class="soft">${b.sources}</td>
        <td>${stSel(b.key,b.st)}${againBadge(b)}</td>
        <td class="soft mono">${when(b.last_seen)}</td></tr>`+hintRow(b.key,7,procHint(b))).join('')
    : '<tr><td colspan="7" class="empty">'+t('empty_blockers')+'</td></tr>';

  $('#domain').innerHTML = (d.domain&&d.domain.length)
    ? d.domain.map(x=>`<tr class="${x.st==='erledigt'?'row-done':''}">
        <td class="strong">${esc(x.workstation)}${hintBtn(x.key)}</td>
        <td>${esc(x.target)}</td>
        <td>${userList(x.who)}</td>
        <td class="num-cell">${x.n}</td>
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

  $('#agents').innerHTML = (d.agents&&d.agents.length)
    ? d.agents.map(a=>`<tr>
        <td class="strong">${esc(a.source)}</td>
        <td class="soft">${a.is_dc?t('type_dc'):t('type_member')}</td>
        <td>${heartbeat(a.last_seen)}</td>
        <td>${auditCell(a)}</td>
        <td class="num-cell">${a.events}</td>
        <td class="soft mono">${when(a.last_seen)}</td></tr>`).join('')
    : '<tr><td colspan="6" class="empty">'+t('empty_agents')+'</td></tr>';

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

document.querySelectorAll('.chip').forEach(c=>c.addEventListener('click',()=>{
  document.querySelectorAll('.chip').forEach(x=>x.classList.remove('on'));
  c.classList.add('on'); state.f=c.dataset.f; load();
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

document.querySelectorAll('.rchip[data-r]').forEach(c=>c.addEventListener('click',()=>{
  document.querySelectorAll('.rchip[data-r]').forEach(x=>x.classList.remove('on'));
  c.classList.add('on'); state.r=c.dataset.r; load();
}));

// Metric cards: apply the filter (if any) and jump to the matching section
function applyFilter(f){
  state.f = f;
  document.querySelectorAll('.chip').forEach(x=>x.classList.toggle('on', x.dataset.f===f));
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
