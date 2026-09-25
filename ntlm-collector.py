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

The Windows agents (ntlm-agent.exe) push their events via HTTP POST /ingest
as JSON. They are stored in a SQLite database; the dashboard at / shows them
live (auto-refresh).

Python standard library only - no dependencies, no pip required.

Start:
    python3 ntlm-collector.py --port 8080 --key SECRET123

Called by the agent:
    POST http://<server>:8080/ingest
    Header: X-Api-Key: SECRET123
    Body:   {"source":"DC01","events":[ {...}, ... ]}
"""
import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from html import escape as _h
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
SESSION_TTL = 12 * 60 * 60          # 12 hours
SESSIONS_LOCK = threading.Lock()


def int_param(value, default, lo, hi):
    """A number from the query string, never an exception and never outside
    lo..hi. "limit=-1" would otherwise mean "no limit at all" to SQLite."""
    try:
        n = int(str(value).strip()) if value not in (None, "") else default
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


def utc_now():
    """Wall-clock UTC without tzinfo.

    Windows writes SystemTime in the event XML as UTC, and that is what the
    agent stores - so every comparison against event_time has to happen in UTC,
    regardless of which timezone the collector host runs in.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

def hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256. Returns (salt, derived_key)."""
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
    kind          TEXT,            -- 'auth' (4624) | 'outgoing' (8001/4020) | 'incoming' (8002/8003/4022) | 'domain' (8004/4032) | 'kerberos' (4769)
    event_time    TEXT,
    user          TEXT,
    domain        TEXT,
    ntlm_version  TEXT,            -- NTLMv1 | NTLMv2 (kind=auth)
    process       TEXT,            -- exe (kind=outgoing)
    target_server TEXT,            -- SPN/service (kind=kerberos) or target server
    workstation   TEXT,
    ip            TEXT,
    logon_type    TEXT,
    enc_type      TEXT,            -- Kerberos encryption, e.g. AES256 / RC4
    auth_method   TEXT,            -- 'Direct' (the app uses NTLM) | 'Fallback' (Kerberos failed)
    received_at   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_dedup ON events(source, log, record_id);
CREATE INDEX IF NOT EXISTS ix_time ON events(event_time);
CREATE INDEX IF NOT EXISTS ix_kind ON events(kind);

CREATE TABLE IF NOT EXISTS agents (
    source          TEXT PRIMARY KEY,
    is_dc           INTEGER,
    agent_version   TEXT,
    outgoing_audit  TEXT,          -- off/audit/deny/unknown
    incoming_audit  TEXT,
    domain_audit    TEXT,          -- DC only: on/off
    logon_audit     TEXT,          -- "Audit Logon" (4624): success/failure/success_failure/none/unknown
    lm_level        TEXT,          -- LmCompatibilityLevel: which NTLM versions are allowed
    block_v1sso     TEXT,          -- BlockNtlmv1SSO: audit/enforce/unset
    cred_guard      TEXT,          -- Credential Guard: on/off/unknown (from the registry)
    ntlm_log_kb     TEXT,          -- maximum size of the NTLM/Operational log in KB
    os_version      TEXT,          -- product name + build of the reporting machine
    restrict_out    TEXT,          -- Deny policies: allow/deny-accounts/deny-all
    restrict_in     TEXT,
    restrict_dom    TEXT,
    exc_client      TEXT,          -- GPO exception lists already configured
    exc_dc          TEXT,
    domain_level    TEXT,          -- msDS-Behavior-Version of the domain (raw)
    forest_level    TEXT,          -- msDS-Behavior-Version of the forest
    last_seen       TEXT,
    first_seen      TEXT           -- first status ever received; start of observation
);

-- 4776 from the domain controllers: reference data only, never an event of its
-- own and never counted. One row per NTLM validation of a domain account. The
-- collector checks unconfirmed 8001s against it (see PHANTOM). user_key and
-- workstation are stored upper-cased and without domain part, so the lookup is
-- a plain index match.
CREATE TABLE IF NOT EXISTS dc_validations (
    dc          TEXT NOT NULL,
    record_id   INTEGER,
    event_time  TEXT NOT NULL,
    user_key    TEXT,
    workstation TEXT,
    status      TEXT,
    received_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_dcval ON dc_validations(dc, record_id);
CREATE INDEX IF NOT EXISTS ix_dcval_user ON dc_validations(user_key, event_time);
CREATE INDEX IF NOT EXISTS ix_dcval_ws ON dc_validations(workstation, user_key, event_time);
CREATE INDEX IF NOT EXISTS ix_dcval_dc ON dc_validations(dc, event_time);
-- Failed NTLM logons (4625) on the machine that was logged on to. Kept apart
-- from events like the 4776 above: a failure is an attempt, not NTLM in use,
-- and one password spray must not bend the NTLM share or the trend.
CREATE TABLE IF NOT EXISTS ntlm_failures (
    source       TEXT NOT NULL,
    record_id    INTEGER,
    event_time   TEXT NOT NULL,
    user         TEXT,
    user_key     TEXT,
    domain       TEXT,
    workstation  TEXT,
    ip           TEXT,
    logon_type   TEXT,
    process      TEXT,
    status       TEXT,
    ntlm_version TEXT,
    received_at  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_fail ON ntlm_failures(source, record_id);
CREATE INDEX IF NOT EXISTS ix_fail_time ON ntlm_failures(event_time);
CREATE INDEX IF NOT EXISTS ix_fail_user ON ntlm_failures(user_key, event_time);
-- SPN check (2.4): which service names clients asked for are registered in AD,
-- and on which account. A DC agent looks them up and reports back; see
-- "SPN check" further down. One row per SPN, stored lower-case.
CREATE TABLE IF NOT EXISTS spn_checks (
    spn          TEXT PRIMARY KEY,
    status       TEXT,             -- ok | missing | alias | duplicate | error; NULL = not checked yet
    detail       TEXT,             -- why, in one code word (see spn_verdict)
    account      TEXT,             -- the account the SPN belongs on, when known
    owners       TEXT,             -- JSON list: accounts that hold the SPN now
    canonical    TEXT,             -- DNS name the host resolves to, if it differs
    error        TEXT,
    dc           TEXT,             -- which DC agent checked it
    checked_at   TEXT,
    requested_at TEXT
);
"""

# Kerberos failure codes from failed 4769 requests: on systems without the
# 40xx events (2016/2019/2022) the only early warning of the causes behind an
# NTLM fallback. Category -> the same remedy texts as in the Why panel; unknown codes pass through as "unclear" with the raw code.
KRB_FAIL = {
    "0x6":  ("Kerberos: client account unknown", "unclear"),
    "0x7":  ("Kerberos: SPN not found (service principal unknown)", "spn"),
    "0xe":  ("Kerberos: encryption type not supported", "etype"),
    "0x12": ("Kerberos: account disabled, expired or locked out", "acct"),
    "0x1b": ("Kerberos: principal not allowed to delegate", "unclear"),
    "0x25": ("Kerberos: clock skew too great", "clock"),
}

# Usage IDs of the client log per KB5064479. Each cause has its own remedy -
# which is why findings are grouped by cause rather than only by program.
REASON_IDS = {
    "0":  ("Unknown reason", "unclear"),
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


# The reason text decides the category, not the number. Observed on a real
# Windows Server 2025 host: two 4020 events both carried Reason ID 10 - which
# KB5064479 defines as loopback - one with the text "The target name contains an
# IP address" (the target was indeed an IP) and one with "could not be resolved
# by Kerberos" (the target was indeed a DNS alias without an SPN). A Windows 11
# client wrote the same IP case correctly as ID 7. Grouping by the number filed
# both under loopback and recommended the wrong fix. Keywords, not full
# sentences, so a German-localised event text is recognised too. Order matters:
# the IP check runs before "could not be resolved". No match -> the number
# stands, since a text we do not recognise is no evidence against it.
REASON_TEXT_KEYS = (
    ("7",  ("ip address", "ip-adresse")),
    ("6",  ("could not be resolved", "nicht aufgel", "nicht aufl")),
    ("8",  ("duplicated", "doppelt", "dupliziert")),
    ("5",  ("missing or empty", "fehlte oder", "fehlt oder")),
    ("10", ("loopback",)),
    ("11", ("null session", "null-session", "nullsitzung")),
    ("9",  ("line of sight", "sichtverbindung")),
    ("4",  ("cloud account", "cloud-konto", "cloudkonto")),
    ("2",  ("local account", "lokalem konto", "lokales konto", "lokalen konto")),
    ("1",  ("called directly", "directly by the calling", "direkt auf", "direkt aufgerufen")),
    ("0",  ("unknown reason", "unbekannter grund")),
)


def canonical_reason_id(reason, rid):
    """Reason ID as the text says it is, falling back to the number sent.

    Only corrects an ID that is there. Events without one (4769 Kerberos
    failures carry a reason text but no Usage ID) must not have one invented
    for them, or they would appear in the reasons panel as a 4020 cause."""
    if rid is None or str(rid).strip() == "":
        return rid
    if reason:
        low = str(reason).lower()
        for key, words in REASON_TEXT_KEYS:
            if any(w in low for w in words):
                return key
    return rid


def normalize_process(p):
    """Normalises process names for grouping: different event sources report
    the same process sometimes with, sometimes without an extension ("lsass"
    from 8001, "lsass.exe" from 4020) - which produced duplicate rows in the
    program list. Conservative: bracketed labels ("(Kernel: SMB/HTTP.sys)",
    "(PID 4)"), values with a dot (they already have an extension) and
    placeholders are left untouched."""
    if not p:
        return p
    v = p.strip()
    if not v or v == "-" or v.startswith("(") or "." in v:
        return p
    # Pseudo names are accounts, not programs ("SYSTEM" from 8002 loopback);
    # real process names without an extension never contain spaces either.
    if " " in v or v.lower() in ("system", "anonymous logon"):
        return p
    return v + ".exe"


FIELDS = ("record_id", "log", "event_id", "kind", "event_time", "user",
          "domain", "ntlm_version", "process", "target_server",
          "workstation", "ip", "logon_type", "enc_type", "auth_method",
          "reason", "reason_id", "mic", "epa", "server_os", "failure_code",
          "process_path")


# Outgoing NTLM is logged twice on Windows 11 24H2 / Server 2025 when the
# classic audit is also on: 8001 (classic) and 4020 (enhanced). Verified on a
# real machine: a net use against an IP wrote 8001 + 4020 in the same second,
# plus a second 8001 from the other token of the elevated session - same target,
# no 4020 of its own. 4020 carries everything 8001 has and more (reason,
# version, MIC, channel binding, resolved target), so such an 8001 is left out
# of every count and list. Raw rows stay in the database.
#
# Matched per event, not per machine. The same machine also wrote an 8001 from
# lsass.exe to an LDAP SPN with no 4020 at all - a first version of this rule
# hid every 8001 on any machine that writes 4020 and would have swallowed that
# one. Now an 8001 only disappears if a 4020/4021 from the same machine names
# the same target within 10 seconds; anything without a partner stays visible.
# The prefix match covers 8001 appending the realm ("ldap/dc/dom@REALM") where
# the enhanced event may carry the short form ("ldap/dc").
NOT_SUPERSEDED = (
    "NOT (event_id = 8001 AND target_server IS NOT NULL AND EXISTS ("
    "SELECT 1 FROM events f WHERE f.event_id IN (4020, 4021) "
    "AND f.source = events.source "
    "AND f.event_time BETWEEN strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '-10 seconds') "
    "AND strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '+10 seconds') "
    "AND f.target_server IS NOT NULL "
    "AND (LOWER(f.target_server) = LOWER(events.target_server) "
    "OR LOWER(events.target_server) LIKE LOWER(f.target_server) || '/%' "
    "OR LOWER(events.target_server) LIKE LOWER(f.target_server) || '@%')))")


# An 8001 with no 4020 partner, on a machine that does write 4020 around that
# time. Checked against the domain controllers on a real network: two such
# 8001 events for one user had no 4776 (NTLM credential validation) on any of
# three DCs whose Security logs reached back days before - while 4776 was being
# logged there at 20+ per hour. So no NTLM logon happened; the 8001 was written
# while NTLM was on the table during negotiation, and Kerberos did the logon.
# These are not hidden: they are left out of every count and panel, and the
# event list offers them behind an explicit, labelled filter. Two events from
# one user is a small sample, which is exactly why they stay one click away.
UNCONFIRMED_RAW = (
    "(event_id = 8001 AND EXISTS (SELECT 1 FROM events g "
    "WHERE g.event_id IN (4020, 4021) AND g.source = events.source "
    "AND g.event_time BETWEEN strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '-1 day') "
    "AND strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '+1 day')))")

# ---- Settling them against the DCs' own record ------------------------------
# Every NTLM validation of a domain account is logged by a DC as 4776, with the
# account and the client's NetBIOS name (the same name the agent reports as
# source). So for each unconfirmed 8001:
#   * a 4776 for the same account from the same machine within two minutes
#     -> it was real NTLM after all: it leaves UNCONFIRMED and is counted;
#   * no 4776 for that account from any machine in that window, while every DC
#     agent demonstrably covered that moment -> PHANTOM, backed by evidence;
#   * anything in between (same account from another machine, a DC not yet
#     covering the moment, a local account no DC ever sees) stays unconfirmed.
# "Any machine" rather than "that machine" for the phantom verdict on purpose: a
# Citrix host has other users' 4776s every minute, and one that happened to be
# normalised differently must not turn a real logon into a phantom.
_T_LO = "strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '-120 seconds')"
_T_HI = "strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '+120 seconds')"
_UKEY = ("UPPER(CASE WHEN instr(events.user, '@') > 0 "
         "THEN substr(events.user, 1, instr(events.user, '@') - 1) "
         "WHEN instr(events.user, '\\') > 0 "
         "THEN substr(events.user, instr(events.user, '\\') + 1) "
         "ELSE events.user END)")
DCV_EXACT = ("EXISTS (SELECT 1 FROM dc_validations v WHERE v.workstation = UPPER(events.source) "
             f"AND v.user_key = {_UKEY} AND v.event_time BETWEEN {_T_LO} AND {_T_HI})")
DCV_USER = ("EXISTS (SELECT 1 FROM dc_validations v WHERE "
            f"v.user_key = {_UKEY} AND v.event_time BETWEEN {_T_LO} AND {_T_HI})")
# Every DC agent must have reported at least 30 minutes after the moment - a
# full later run, so the run that read that moment has finished sending - and
# must have 4776 data from before it. One DC short and nothing is concluded.
DC_COVERED = (
    "(EXISTS (SELECT 1 FROM agents WHERE is_dc = 1) AND NOT EXISTS ("
    "SELECT 1 FROM agents a WHERE a.is_dc = 1 AND NOT ("
    "a.last_seen >= strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '+30 minutes') "
    "AND EXISTS (SELECT 1 FROM dc_validations w WHERE w.dc = a.source "
    "AND w.event_time <= strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '-5 minutes')))))")
# Only domain accounts are validated by a DC. A local account shows the machine
# itself as its domain and would look like a phantom forever.
JUDGEABLE = (
    "(events.user IS NOT NULL AND TRIM(events.user) != '' "
    "AND events.domain IS NOT NULL AND TRIM(events.domain) != '' "
    "AND UPPER(events.domain) != UPPER(events.source) "
    "AND UPPER(events.domain) NOT IN ('NT AUTHORITY', 'WORKGROUP', '.', '(NULL)', '-'))")

UNCONFIRMED = f"({UNCONFIRMED_RAW} AND NOT {DCV_EXACT})"

# ---- 4624 on member servers ------------------------------------------------
# The classic NTLM events carry no version; a member server's 4624 does. The
# same logon is usually also its 8003 (or 8002/4022), which keeps the service
# that accepted it. So the 4624 hides behind that partner and hands it the
# version (see enrich_versions); without a partner - incoming audit off - the
# 4624 itself is the incoming event. Matched per logon: same machine, same
# account, same client (when both name one), within ten seconds.
ukey_of = lambda col: _UKEY.replace("events.user", col)
_SUP_4624 = (
    "(event_id = 4624 AND kind = 'incoming' AND EXISTS (SELECT 1 FROM events p "
    "WHERE p.event_id IN (8002, 8003, 4022, 4023) AND p.source = events.source "
    "AND p.event_time BETWEEN strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '-10 seconds') "
    "AND strftime('%Y-%m-%dT%H:%M:%S', events.event_time, '+10 seconds') "
    f"AND {ukey_of('p.user')} = {_UKEY} "
    "AND (p.workstation IS NULL OR events.workstation IS NULL "
    "OR UPPER(p.workstation) = UPPER(events.workstation))))")
NOT_SUPERSEDED = f"NOT ({NOT_SUPERSEDED[len('NOT '):]} OR {_SUP_4624})"
# Every query that sets duplicates aside looks at both kinds of twin.
_TWIN_IDS = "event_id IN (8001, 4624)"
PHANTOM = f"({UNCONFIRMED} AND {JUDGEABLE} AND {DC_COVERED} AND NOT {DCV_USER})"


def user_key(u):
    """Same normalisation as _UKEY, for the 4776 side at ingest."""
    u = (u or "").strip()
    if "@" in u:
        u = u.split("@", 1)[0]
    elif "\\" in u:
        u = u.split("\\", 1)[1]
    return u.upper() or None


# How many rows a list panel receives. Panels show ten and fold the rest
# behind "show all"; the cap only guards the page against a pathological
# domain. The jump bar says "500+" when it is reached.
PANEL_LIMIT = 500


# Work status of a program/domain row. Earlier versions stored German words;
# they are translated when read from a request and rewritten once in the
# database at start-up (see init_db).
LEGACY_STATUS = {"offen": "open", "arbeit": "in_progress", "erledigt": "done"}
# Audit state from agents before 2.3 ("aus" = off, "an" = on).
LEGACY_AUDIT = {"aus": "off", "an": "on"}


# ---- Ready to switch off -----------------------------------------------------
# Per machine and direction: can "Restrict NTLM ... Deny" be set there now?
#   ready   - auditing on, watched for the full 30 days, no counted NTLM in them
#   busy    - NTLM seen in the last 30 days (with who/what would break)
#   active  - already denied
#   young / noaudit / stale - not enough to say either way
# 30 days so a monthly job (payroll, month-end close) has had its chance to run -
# and all 30 must have been watched: 20 quiet days of a machine seen for 20 days
# say nothing about the job that runs on the 25th.
# Incoming evidence comes from three sides, so a server with its own auditing
# off still shows up when other machines or the DCs saw NTLM going to it: the
# machine's own incoming events, the DCs' domain view, and other machines'
# outgoing events naming it as target. Duplicates and phantom 8001s are not
# evidence. DCs get no incoming verdict: that is a domain-wide decision.
READY_QUIET_DAYS = 30
READY_MIN_OBS_DAYS = READY_QUIET_DAYS
AGENT_STALE_DAYS = 2
_ENHANCED_OS = re.compile(r"2600\d|2[6-9]\d{3}")   # Windows 11 24H2 / Server 2025 and later
_TS = "%Y-%m-%dT%H:%M:%S"


def host_key(target):
    """'cifs/FS01.corp.local', 'ldap/dc1/corp@REALM', 'FS01:445' -> 'FS01'."""
    if not target:
        return None
    t = str(target).strip()
    if "/" in t:
        t = t.split("/", 2)[1]
    t = t.split("@")[0].split(":")[0].strip("\\ ")
    if not t:
        return None
    if t.replace(".", "").isdigit():
        return t                       # an IP address stays as it is
    return t.split(".")[0].upper()[:15] or None


def _ts(v):
    try:
        return datetime.strptime(str(v)[:19], _TS)
    except (TypeError, ValueError):
        return None


# ---- Carrying the version across one logon ---------------------------------
# One NTLM logon to a member server can leave four traces: 8001 on the client,
# 8003 (or 8002/4022) and 4624 on the server, 8004 on the DC. Only the 4624 -
# and the enhanced 40xx events - say which version was used. When a batch
# arrives, each new 4624 hands its version to the traces of the same logon
# that lack one, and each new version-less trace looks for a 4624 to take it
# from: whichever arrives first. Same account and client, within ten seconds
# on the same machine and two minutes across machines (clock skew between
# domain members is small, Kerberos itself tolerates five). Nothing is
# counted differently by this - the traces just stop saying "unknown version".
_LOCAL_TWINS = (8002, 8003, 4022, 4023)
_DC_TWINS = (8004, 8005, 8006)


def enrich_versions(conn, source, received_at):
    def window(t, sec):
        d = _ts(t)
        return ((d - timedelta(seconds=sec)).strftime(_TS), (d + timedelta(seconds=sec)).strftime(_TS)) if d else (None, None)
    uk = ukey_of("user")
    fresh = conn.execute("SELECT id, event_id, kind, event_time, user, workstation, target_server, ntlm_version "
                         "FROM events WHERE source = ? AND received_at = ?", (source, received_at)).fetchall()
    me = (source or "").upper()[:15]
    for eid_, event_id, kind, t, user, ws, tgt, ver in fresh:
        ukey = user_key(user)
        if not ukey or not t:
            continue
        wsu = (ws or "").strip().lstrip("\\").upper() or None
        if event_id == 4624 and kind == "incoming" and ver:
            lo, hi = window(t, 10)
            conn.execute(f"UPDATE events SET ntlm_version = ? WHERE ntlm_version IS NULL AND source = ? "
                         f"AND event_id IN {_LOCAL_TWINS} AND event_time BETWEEN ? AND ? AND {uk} = ? "
                         "AND (workstation IS NULL OR ? IS NULL OR UPPER(workstation) = ?)",
                         (ver, source, lo, hi, ukey, wsu, wsu))
            lo, hi = window(t, 120)
            if wsu:
                for oid, otgt in conn.execute(
                        f"SELECT id, target_server FROM events WHERE ntlm_version IS NULL AND event_id IN {_DC_TWINS} "
                        f"AND event_time BETWEEN ? AND ? AND {uk} = ? AND UPPER(workstation) = ?",
                        (lo, hi, ukey, wsu)).fetchall():
                    if host_key(otgt) == me:
                        conn.execute("UPDATE events SET ntlm_version = ? WHERE id = ?", (ver, oid))
                for oid, otgt in conn.execute(
                        f"SELECT id, target_server FROM events WHERE ntlm_version IS NULL AND event_id = 8001 "
                        f"AND UPPER(source) = ? AND event_time BETWEEN ? AND ? AND {uk} = ?",
                        (wsu, lo, hi, ukey)).fetchall():
                    if host_key(otgt) == me:
                        conn.execute("UPDATE events SET ntlm_version = ? WHERE id = ?", (ver, oid))
        elif not ver and event_id in _LOCAL_TWINS:
            lo, hi = window(t, 10)
            got = conn.execute(f"SELECT ntlm_version FROM events WHERE source = ? AND event_id = 4624 "
                               f"AND ntlm_version IS NOT NULL AND event_time BETWEEN ? AND ? AND {uk} = ? "
                               "AND (workstation IS NULL OR ? IS NULL OR UPPER(workstation) = ?) LIMIT 1",
                               (source, lo, hi, ukey, wsu, wsu)).fetchone()
            if got:
                conn.execute("UPDATE events SET ntlm_version = ? WHERE id = ?", (got[0], eid_))
        elif not ver and (event_id in _DC_TWINS or event_id == 8001):
            server = host_key(tgt)
            client = wsu if event_id in _DC_TWINS else me
            if not server or not client:
                continue
            lo, hi = window(t, 120)
            got = conn.execute(f"SELECT ntlm_version FROM events WHERE UPPER(source) = ? AND event_id = 4624 "
                               f"AND ntlm_version IS NOT NULL AND event_time BETWEEN ? AND ? AND {uk} = ? "
                               "AND UPPER(workstation) = ? LIMIT 1",
                               (server, lo, hi, ukey, client)).fetchone()
            if got:
                conn.execute("UPDATE events SET ntlm_version = ? WHERE id = ?", (got[0], eid_))


def compute_readiness(c):
    now = utc_now()
    win = (now - timedelta(days=READY_QUIET_DAYS)).strftime(_TS)
    # 8001s that are duplicates, unconfirmed or phantoms are no evidence.
    c.execute("CREATE TEMP TABLE IF NOT EXISTS x_rdy (id INTEGER PRIMARY KEY)")
    c.execute("DELETE FROM temp.x_rdy")
    c.execute(f"INSERT INTO x_rdy (id) SELECT id FROM events WHERE {_TWIN_IDS} "
              f"AND event_time >= ? AND (NOT ({NOT_SUPERSEDED}) OR {UNCONFIRMED})", (win,))
    counted = "id NOT IN (SELECT id FROM temp.x_rdy)"

    def bump(d, key, item, n, last):
        e = d.setdefault(key, {"n": 0, "last": None, "items": {}})
        e["n"] += n
        if last and (not e["last"] or last > e["last"]):
            e["last"] = last
        e["items"][item] = e["items"].get(item, 0) + n

    out, inc = {}, {}
    for src, proc, tgt, user, n, last in c.execute(
            "SELECT source, process, target_server, user, COUNT(*), MAX(event_time) FROM events "
            f"WHERE kind = 'outgoing' AND event_time >= ? AND {counted} "
            "GROUP BY source, process, target_server, user", (win,)):
        bump(out, (src or "").upper()[:15], (proc or "", tgt or ""), n, last)
        h = host_key(tgt)
        if h:
            bump(inc, h, (user or "", (src or "").upper()), n, last)
    for src, user, ws, n, last in c.execute(
            "SELECT source, user, workstation, COUNT(*), MAX(event_time) FROM events "
            f"WHERE kind = 'incoming' AND event_time >= ? AND {counted} GROUP BY source, user, workstation", (win,)):
        bump(inc, (src or "").upper()[:15], (user or "", (ws or "").upper()), n, last)
    for tgt, user, ws, n, last in c.execute(
            "SELECT target_server, user, workstation, COUNT(*), MAX(event_time) FROM events "
            "WHERE kind = 'domain' AND event_time >= ? GROUP BY target_server, user, workstation", (win,)):
        h = host_key(tgt)
        if h:
            bump(inc, h, (user or "", (ws or "").upper()), n, last)
    # Last NTLM before the window, so a ready machine can say since when it is quiet.
    before = {(s or "").upper()[:15]: t for s, t in c.execute(
        "SELECT source, MAX(event_time) FROM events WHERE kind = 'outgoing' AND event_time < ? "
        "GROUP BY source", (win,))}

    rows = []
    for (src, is_dc, oa, ia, r_in, osv, last_seen, first_seen, first_ev) in c.execute(
            "SELECT a.source, a.is_dc, a.outgoing_audit, a.incoming_audit, a.restrict_in, "
            "a.os_version, a.last_seen, a.first_seen, "
            "(SELECT MIN(event_time) FROM events e WHERE e.source = a.source) FROM agents a"):
        key = (src or "").upper()[:15]
        starts = [t for t in (_ts(first_seen), _ts(first_ev)) if t]
        obs = (now - min(starts)).days if starts else 0
        seen = _ts(last_seen)
        stale = not seen or (now - seen).days >= AGENT_STALE_DAYS
        enhanced = bool(_ENHANCED_OS.search(osv or ""))

        def verdict(direction):
            if direction == "in" and is_dc:
                return {"st": "dc"}
            ev = (out if direction == "out" else inc).get(key)
            denied = (oa == "deny") if direction == "out" else (r_in in ("deny-accounts", "deny-all"))
            audit = (oa in ("audit", "deny") if direction == "out" else ia == "audit") or enhanced
            if denied:
                return {"st": "active"}
            if ev and ev["n"]:
                top = sorted(ev["items"].items(), key=lambda kv: -kv[1])[:3]
                return {"st": "busy", "n": ev["n"], "last": ev["last"], "who": len(ev["items"]),
                        "top": [[a, b, k] for (a, b), k in top]}
            if stale:
                return {"st": "stale"}
            if not audit:
                return {"st": "noaudit"}
            if obs < READY_MIN_OBS_DAYS:
                return {"st": "young", "d": obs}
            return {"st": "ready", "d": min(obs, READY_QUIET_DAYS) if not before.get(key) or direction == "in"
                    else (now - _ts(before[key])).days,
                    "since": before.get(key) if direction == "out" else None}

        rows.append({"machine": src, "is_dc": bool(is_dc), "obs": obs,
                     "out": verdict("out"), "in": verdict("in")})

    order = {"ready": 0, "busy": 1, "young": 2, "noaudit": 3, "stale": 4, "active": 5, "dc": 6}
    rows.sort(key=lambda r: (min(order[r["out"]["st"]], order[r["in"]["st"]]),
                             r["out"].get("n", 0) + r["in"].get("n", 0), r["machine"] or ""))
    return {"rows": rows, "quiet_days": READY_QUIET_DAYS, "min_obs": READY_MIN_OBS_DAYS,
            "out_ready": sum(1 for r in rows if r["out"]["st"] == "ready"),
            "in_ready": sum(1 for r in rows if r["in"]["st"] == "ready")}


# Both panels are 30-day (or whole-range) verdicts and cost a second or more on a
# busy domain, while the dashboard asks every minute. They are kept for five
# minutes: whether a server has been quiet for 30 days does not change in five,
# and it keeps the one-minute refresh cheap. A fresh collector start computes
# them anew.
_PANEL_CACHE = {}
_PANEL_TTL = 300


def cached(key, fn):
    hit = _PANEL_CACHE.get(key)
    if hit and time.time() - hit[0] < _PANEL_TTL:
        return hit[1]
    val = fn()
    _PANEL_CACHE[key] = (time.time(), val)
    return val


# ---- Key figures: this week against the week before -------------------------
# The tiles under the handover bar answer "are we getting better?": the last
# seven days against the seven before, and a daily line for the last fourteen.
# Counted exactly like the trend chart (same version buckets, duplicates and
# unconfirmed 8001s left out), independent of the range picked above so the
# comparison always means the same thing. Cached like the other two panels.
def compute_kpi(c, tzoff, src):
    now = utc_now()
    w14 = (now - timedelta(days=14)).strftime(_TS)
    w7 = (now - timedelta(days=7)).strftime(_TS)
    sw, sp = (" AND source = ?", [src]) if src else ("", [])
    c.execute("CREATE TEMP TABLE IF NOT EXISTS x_kpi (id INTEGER PRIMARY KEY)")
    c.execute("DELETE FROM temp.x_kpi")
    c.execute(f"INSERT INTO x_kpi (id) SELECT id FROM events WHERE {_TWIN_IDS} "
              f"AND event_time >= ?{sw} AND (NOT ({NOT_SUPERSEDED}) OR {UNCONFIRMED})", [w14] + sp)
    tzmod = f"{tzoff:+d} minutes"
    rows = c.execute(
        "SELECT substr(datetime(event_time, ?),1,10), CASE WHEN event_time >= ? THEN 1 ELSE 0 END, "
        "SUM(CASE WHEN ntlm_version='NTLMv1' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN ntlm_version='NTLMv2' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN kind!='kerberos' AND ntlm_version IS NULL THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN kind='kerberos' THEN 1 ELSE 0 END) "
        f"FROM events WHERE event_time >= ?{sw} AND id NOT IN (SELECT id FROM temp.x_kpi) "
        "GROUP BY 1, 2", [tzmod, w7, w14] + sp).fetchall()
    local_now = now + timedelta(minutes=tzoff)
    days = [(local_now - timedelta(days=13 - i)).strftime("%Y-%m-%d") for i in range(14)]
    per = {d: [0, 0, 0, 0] for d in days}
    week = {1: [0, 0, 0, 0], 0: [0, 0, 0, 0]}
    for b, cur, v1, v2, oth, krb in rows:
        vals = [v1 or 0, v2 or 0, oth or 0, krb or 0]
        if b in per:
            per[b] = [a + x for a, x in zip(per[b], vals)]
        week[cur] = [a + x for a, x in zip(week[cur], vals)]
    def share(v):
        n = v[0] + v[1] + v[2]
        return round(100.0 * n / (n + v[3]), 1) if (n + v[3]) else None
    fold = lambda v: {"v1": v[0], "v2": v[1], "ntlm": v[0] + v[1] + v[2], "krb": v[3], "share": share(v)}
    return {"days": days, "v1": [per[d][0] for d in days], "v2": [per[d][1] for d in days],
            "krb": [per[d][3] for d in days], "share": [share(per[d]) for d in days],
            "cur": fold(week[1]), "prev": fold(week[0])}


# ---- Failed NTLM attempts ------------------------------------------------------
# Two sides see a failure: the machine logged on to (4625, with its agent) and
# the DC that checked a domain account (4776 with a status). One failed logon to
# a member server shows up on both, so each (account, client) pair counts with
# the higher of the two numbers - never their sum - and says who saw it.
def norm_status(v):
    """NT status as one spelling: '0xc000006a' / '0xC000006A' -> '0xC000006A'; success -> None."""
    t = str(v or "").strip()
    if not t.lower().startswith("0x"):
        return None
    try:
        n = int(t, 16)
    except ValueError:
        return None
    return f"0x{n:08X}" if n else None


SPRAY_MIN_ACCOUNTS = 5      # one client failing for this many accounts looks like spraying


def compute_failures(c, cutoff, src):
    tw, tp = ("AND event_time >= ? ", [cutoff]) if cutoff else ("", [])
    pairs = {}

    def add(ukey, user, client, status, n, last, via, target=None):
        if not ukey:
            return
        k = (ukey, (client or "").upper())
        e = pairs.setdefault(k, {"key": ukey, "user": user or ukey, "from": (client or "").upper(),
                                 "to": set(), "codes": {}, "local": 0, "dc": 0, "last": None})
        e[via] += n
        if status:
            e["codes"][status] = e["codes"].get(status, 0) + n
        if target:
            e["to"].add(target.upper())
        if last and (not e["last"] or last > e["last"]):
            e["last"] = last

    sw, sp = (" AND (source = ? OR workstation = ?)", [src, (src or "").upper()]) if src else ("", [])
    for source, user, ukey, ws, st, n, last in c.execute(
            "SELECT source, MAX(user), user_key, workstation, status, COUNT(*), MAX(event_time) "
            f"FROM ntlm_failures WHERE 1=1 {tw}{sw} GROUP BY source, user_key, workstation, status", tp + sp):
        add(ukey, user, ws, st, n, last, "local", source)
    dw, dp = (" AND workstation = ?", [(src or "").upper()]) if src else ("", [])
    for ukey, ws, st, n, last in c.execute(
            "SELECT user_key, workstation, status, COUNT(*), MAX(event_time) FROM dc_validations "
            f"WHERE status IS NOT NULL AND status NOT IN ('0x0', '0x00000000') {tw}{dw} "
            "GROUP BY user_key, workstation, status", tp + dp):
        add(ukey, ukey, ws, norm_status(st), n, last, "dc")
    rows = []
    for e in pairs.values():
        n = max(e["local"], e["dc"])
        code = max(e["codes"].items(), key=lambda kv: kv[1])[0] if e["codes"] else None
        rows.append({"key": e["key"], "user": e["user"], "from": e["from"], "to": sorted(e["to"])[:4],
                     "code": code, "locked": "0xC0000234" in e["codes"], "n": n, "last": e["last"],
                     "via": "both" if e["local"] and e["dc"] else ("local" if e["local"] else "dc")})
    rows.sort(key=lambda r: (-r["n"], r["key"]))
    by_client = {}
    for r in rows:
        if r["from"]:
            b = by_client.setdefault(r["from"], {"accounts": set(), "n": 0})
            b["accounts"].add(r["key"]); b["n"] += r["n"]
    spray = sorted(([k, len(v["accounts"]), v["n"]] for k, v in by_client.items()
                    if len(v["accounts"]) >= SPRAY_MIN_ACCOUNTS), key=lambda x: -x[1])
    return {"rows": rows[:PANEL_LIMIT], "rows_all": rows, "total": len(rows), "n": sum(r["n"] for r in rows),
            "accounts": len({r["key"] for r in rows}), "spray": spray[:10]}


# ---- Accounts using NTLM --------------------------------------------------------
# One row per account across every direction: what the machines send, what the
# servers accept and what the DCs see. The same logon can be seen from several
# sides, so these are sightings rather than logons; the panel says so. Failed
# attempts and Kerberos use come from their own tables and sit alongside.
NTLM_USE_KINDS = "('outgoing', 'incoming', 'domain', 'auth', 'ntlmv1sso')"


def account_label(k):
    if not k:
        return ""
    return k if k.endswith("$") or k == "ANONYMOUS LOGON" else k.lower()


# One NTLM logon to a server can leave three traces with the same account: the
# client's 8001, the server's 8003 and the DC's 8004. Per account and server
# the side that saw most counts, never the sum - so "logons" means logons, and
# server names are unified ("cifs/fs04.corp.local" and "FS04" are one server).
_ACCT_COLS = ("SELECT {k} AS k, kind, UPPER(source), target_server, UPPER(workstation), "
              "SUM(CASE WHEN ntlm_version = 'NTLMv1' THEN 1 ELSE 0 END), "
              "SUM(CASE WHEN ntlm_version = 'NTLMv2' THEN 1 ELSE 0 END), COUNT(*), MAX(event_time) FROM events ")


def acct_rollup(rows):
    acc = {}
    for k, kind, src, tgt, ws, v1, v2, n, last in rows:
        if not k:
            continue
        a = acc.setdefault(k, {"sides": {}, "clients": set(), "targets": set(), "last": None})
        host = (src or "")[:15] if kind in ("incoming", "auth") else (host_key(tgt) or "")
        side = {"outgoing": "agent", "domain": "dc"}.get(kind, "server")
        e = a["sides"].setdefault(host, {}).setdefault(side, [0, 0, 0])
        e[0] += n; e[1] += v1 or 0; e[2] += v2 or 0
        client = src if kind == "outgoing" else ws
        if client:
            a["clients"].add(client.lstrip("\\")[:15])
        if host:
            a["targets"].add(host)
        if last and (not a["last"] or last > a["last"]):
            a["last"] = last
    out = {}
    for k, a in acc.items():
        n = v1 = v2 = 0
        for sides in a["sides"].values():
            best = max(sides.values(), key=lambda x: x[0])
            n += best[0]; v1 += best[1]; v2 += best[2]
        out[k] = {"n": n, "v1": v1, "v2": v2, "machines": len(a["clients"]),
                  "targets": len(a["targets"]), "last": a["last"]}
    return out


def compute_accounts(c, tf, tp, failures):
    rows = {}
    agg = acct_rollup(c.execute(
        _ACCT_COLS.format(k=_UKEY) +
        f"WHERE kind IN {NTLM_USE_KINDS} AND user IS NOT NULL AND TRIM(user) NOT IN ('', '-') AND {tf} "
        "GROUP BY 1, 2, 3, 4, 5", tp))
    for k, a in agg.items():
        rows[k] = dict(a, key=k, name=account_label(k), krb=0, failed=0)
    for f in failures.get("rows_all", []):
        r = rows.setdefault(f["key"], {"key": f["key"], "name": account_label(f["key"]), "n": 0, "v1": 0,
                                       "v2": 0, "machines": 0, "targets": 0, "last": f["last"], "krb": 0, "failed": 0})
        r["failed"] += f["n"]
        if f["last"] and (not r["last"] or f["last"] > r["last"]):
            r["last"] = f["last"]
    if rows:
        for k, n in c.execute(f"SELECT {_UKEY} AS k, COUNT(*) FROM events WHERE kind = 'kerberos' AND {tf} "
                              "GROUP BY k", tp):
            if k in rows:
                rows[k]["krb"] = n
    out = sorted(rows.values(), key=lambda r: (-(r["n"] + r["failed"]), r["key"]))
    return {"rows": out[:PANEL_LIMIT], "total": len(out),
            "v1": sum(1 for r in out if r["v1"]), "anon": any(r["key"] == "ANONYMOUS LOGON" for r in out)}


# ---- Machines without an agent -------------------------------------------------
# Every NTLM logon of a domain account is validated by a DC and logged as 4776
# with the client's name. Any such client that has no agent is a machine the
# dashboard otherwise never sees - often exactly the forgotten server.
def compute_agentless(c, cutoff):
    params, tw = [], ""
    if cutoff:
        tw = "AND event_time >= ? "
        params.append(cutoff)
    rows = []
    for ws, n, users, last, names in c.execute(
            "SELECT workstation, COUNT(*), COUNT(DISTINCT user_key), MAX(event_time), "
            "GROUP_CONCAT(DISTINCT user_key) FROM dc_validations "
            "WHERE workstation IS NOT NULL AND workstation NOT IN ('', '-', 'LOCALHOST', '::1', '127.0.0.1') "
            f"{tw}AND workstation NOT IN (SELECT UPPER(source) FROM agents) "
            "GROUP BY workstation ORDER BY COUNT(*) DESC LIMIT 100", params):
        who = [u.lower() for u in (names or "").split(",") if u][:4]
        rows.append({"machine": ws, "n": n, "users": users, "who": who, "last": last})
    dcs = c.execute("SELECT COUNT(DISTINCT dc) FROM dc_validations").fetchone()[0]
    total = c.execute(
        "SELECT COUNT(DISTINCT workstation) FROM dc_validations "
        "WHERE workstation IS NOT NULL AND workstation NOT IN ('', '-', 'LOCALHOST', '::1', '127.0.0.1') "
        f"{tw}AND workstation NOT IN (SELECT UPPER(source) FROM agents)", params).fetchone()[0]
    return {"rows": rows, "dcs": dcs, "total": total}


# ---- SPN check ------------------------------------------------------------
# Most "Kerberos failed, NTLM took over" cases come down to a service name
# (SPN) that is not registered in AD, is registered twice, or is registered
# under the real server name while clients use an alias. The events name the
# SPN a client asked for; whether AD knows it, only AD can say. So the
# collector hands the SPNs it has seen to a DC agent (2.4 or later) in the
# answer to its status report. The agent looks them up read-only (any domain
# account may read servicePrincipalName) and posts the facts to /spn; the
# verdict is made here. Nothing is ever changed in AD - the dashboard shows
# the setspn command an admin can run.
SPN_MIN_AGENT = (2, 4, 0)
SPN_BATCH = 50               # SPNs per status answer (the agent caps at the same)
SPN_RECHECK = timedelta(hours=24)
SPN_RETRY = timedelta(hours=1)   # handed out but no answer: give it to the next DC
SPN_WINDOW_DAYS = 30
# Windows' default sPNMappings: service classes that HOST/<name> stands in for.
# Used when the agent could not read the forest's own list.
SPN_DEFAULT_MAPPINGS = frozenset((
    "alerter,appmgmt,cisvc,clipsrv,browser,dhcp,dnscache,replicator,eventlog,"
    "eventsystem,policyagent,oakley,dmserver,dns,mcsvc,fax,msiserver,ias,"
    "messenger,netlogon,netman,netdde,netddedsm,nmagent,plugplay,"
    "protectedstorage,rasman,rpclocator,rpc,rpcss,remoteaccess,rsvp,samss,"
    "scardsvr,scesrv,seclogon,scm,dcom,cifs,spooler,snmp,schedule,tapisrv,"
    "trksvr,trkwks,ups,time,wins,www,http,w3svc,iisadmin,msdtc").split(","))
SPN_PROBLEMS = ("missing", "alias", "duplicate")
_SPN_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def version_tuple(v):
    """'2.4.0' -> (2, 4, 0); anything unreadable sorts before every release."""
    out = []
    for part in str(v or "").split(".")[:3]:
        m = re.match(r"\d+", part)
        out.append(int(m.group(0)) if m else 0)
    return tuple(out + [0] * (3 - len(out)))


def norm_spn(target):
    """The SPN a client asked for, in the form AD stores it - or None when
    there is nothing to look up. Takes 'svc/host[:port][/extra][@REALM]'.
    IP addresses are left out: Kerberos never works for them, and the Why
    panel already names that cause."""
    if not target or "/" not in target:
        return None
    t = target.strip().split("@", 1)[0]
    svc, rest = t.split("/", 1)
    host = rest.split("/", 1)[0]
    port = ""
    if ":" in host:
        host, port = host.split(":", 1)
    host = host.rstrip(".").lower()
    svc = svc.lower()
    if not _SPN_PART.match(svc) or not _SPN_PART.match(host):
        return None
    if svc == "krbtgt" or host in ("localhost", "127.0.0.1") or _IPV4.match(host):
        return None
    # SQL Server registers one SPN per port (or instance); for everything else
    # the port is not part of what the client looks up.
    if svc == "mssqlsvc" and port and re.match(r"^[A-Za-z0-9_$-]{1,64}$", port):
        return f"{svc}/{host}:{port.lower()}"
    return f"{svc}/{host}"


def spn_candidates(c, where="1=1", params=()):
    """{spn: {"n": NTLM count, "krb": failed Kerberos count, "last": time}}
    for the outgoing NTLM and failed Kerberos requests matching `where`."""
    out = {}
    for target, kind, n, last in c.execute(
            "SELECT target_server, kind, COUNT(*), MAX(event_time) FROM events "
            # Failed Kerberos only with 0x7 ("server not found in Kerberos
            # database"): clock skew or an etype mismatch says nothing about SPNs.
            "WHERE (kind = 'outgoing' OR (kind = 'krbfail' AND failure_code = '0x7')) "
            "AND target_server LIKE '%/%' "
            f"AND {where} GROUP BY target_server, kind", list(params)):
        spn = norm_spn(target)
        if not spn:
            continue
        r = out.setdefault(spn, {"n": 0, "krb": 0, "last": ""})
        r["n" if kind == "outgoing" else "krb"] += n
        r["last"] = max(r["last"], last or "")
    return out


def spn_verdict(res, mappings):
    """(status, detail, account) for one looked-up SPN.

    `res` holds what the DC agent found: owners (accounts holding the SPN),
    host_owners (holding HOST/<host>), canonical (the name DNS resolves the
    host to), canon_owners / canon_host_owners (the same two for that name),
    resolves, error. Account names come back without the trailing '$' of a
    computer account - the form setspn takes."""
    if res.get("error"):
        return "error", "error", None
    spn = res["spn"]
    svc, rest = spn.split("/", 1)
    host = rest.split(":", 1)[0]
    acct = lambda names: names[0].rstrip("$") if names else None
    owners = res.get("owners") or []
    if len(owners) > 1:
        return "duplicate", "dup", None
    if owners:
        return "ok", "registered", acct(owners)
    host_owners = res.get("host_owners") or []
    mapped = svc == "host" or svc in mappings
    if mapped and len(host_owners) > 1:
        return "duplicate", "dup_host", None
    if mapped and host_owners:
        return "ok", "via_host", acct(host_owners)
    canon = (res.get("canonical") or "").lower().rstrip(".")
    if canon and canon != host:
        for names in (res.get("canon_owners") or [], res.get("canon_host_owners") or []):
            if len(names) == 1:
                short = "." not in host and canon.split(".", 1)[0] == host
                return "alias", "short" if short else "cname", acct(names)
    if host_owners:
        return "missing", "unmapped", acct(host_owners)
    if res.get("resolves") is False:
        return "missing", "nores", None
    return "missing", "noacct", None


def spn_due(c, now=None):
    """Up to SPN_BATCH SPNs a DC agent should look up now: seen in the last 30
    days, not checked in the last day, not already out with another DC."""
    now = now or utc_now()
    cands = spn_candidates(c, "event_time >= ?",
                           [(now - timedelta(days=SPN_WINDOW_DAYS)).strftime(_TS)])
    if not cands:
        return []
    state = {r[0]: (r[1], r[2]) for r in c.execute(
        "SELECT spn, checked_at, requested_at FROM spn_checks")}
    fresh = (now - SPN_RECHECK).strftime(_TS)
    retry = (now - SPN_RETRY).strftime(_TS)
    due = []
    # Most-used first: with hundreds of names, the ones behind the most NTLM
    # get an answer in the first cycle.
    for spn in sorted(cands, key=lambda s: (-(cands[s]["n"] + cands[s]["krb"]), s)):
        checked, asked = state.get(spn, (None, None))
        if checked and checked >= fresh:
            continue
        if asked and asked >= retry:
            continue
        due.append(spn)
        if len(due) >= SPN_BATCH:
            break
    stamp = now.strftime(_TS)
    c.executemany(
        "INSERT INTO spn_checks (spn, requested_at) VALUES (?, ?) "
        "ON CONFLICT(spn) DO UPDATE SET requested_at = excluded.requested_at",
        [(s, stamp) for s in due])
    return due


def _names(v, limit=20):
    """A list of account names from an agent: strings only, bounded."""
    if not isinstance(v, list):
        return []
    return [str(x)[:256] for x in v if isinstance(x, str) and x.strip()][:limit]


def spn_store(c, dc, payload, now=None):
    """Takes a DC agent's answer. Only SPNs this collector handed out are
    accepted, so a key holder cannot fill the panel with invented names.
    Returns how many were stored."""
    now = (now or utc_now()).strftime(_TS)
    maps = payload.get("mappings")
    mappings = frozenset(m.strip().lower() for m in maps[:1000]
                         if isinstance(m, str) and m.strip()) if isinstance(maps, list) else frozenset()
    mappings = mappings or SPN_DEFAULT_MAPPINGS
    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("results must be a list")
    asked = {r[0] for r in c.execute("SELECT spn FROM spn_checks WHERE requested_at IS NOT NULL")}
    stored = 0
    for r in results[:500]:
        if not isinstance(r, dict) or not isinstance(r.get("spn"), str):
            continue
        spn = norm_spn(r["spn"])
        if not spn or spn not in asked:
            continue
        err = r.get("error")
        res = {"spn": spn, "error": str(err)[:300] if err else None,
               "owners": _names(r.get("owners")), "host_owners": _names(r.get("host_owners")),
               "canonical": str(r.get("canonical") or "")[:255],
               "canon_owners": _names(r.get("canon_owners")),
               "canon_host_owners": _names(r.get("canon_host_owners")),
               "resolves": r.get("resolves") if isinstance(r.get("resolves"), bool) else None}
        status, detail, account = spn_verdict(res, mappings)
        owners = res["owners"] or (res["host_owners"] if detail == "dup_host" else [])
        canon = res["canonical"].lower().rstrip(".")
        c.execute(
            "UPDATE spn_checks SET status=?, detail=?, account=?, owners=?, canonical=?, "
            "error=?, dc=?, checked_at=?, requested_at=NULL WHERE spn=?",
            (status, detail, account, json.dumps(owners), canon or None,
             res["error"], dc, now, spn))
        stored += 1
    return stored


def compute_spn(c, tf, tp):
    """The SPN panel: problems found, with the NTLM they cause in the range."""
    now = utc_now()
    recent = spn_candidates(c, "event_time >= ?",
                            [(now - timedelta(days=SPN_WINDOW_DAYS)).strftime(_TS)])
    in_range = spn_candidates(c, tf, tp)
    capable = sum(1 for (v,) in c.execute(
        "SELECT agent_version FROM agents WHERE is_dc = 1") if version_tuple(v) >= SPN_MIN_AGENT)
    rows, ok, checked = [], 0, 0
    for spn, status, detail, account, owners, canon, err, dc, at in c.execute(
            "SELECT spn, status, detail, account, owners, canonical, error, dc, checked_at "
            "FROM spn_checks WHERE status IS NOT NULL"):
        if spn not in recent:
            continue                    # no longer asked for - nothing to fix
        checked += 1
        if status == "ok":
            ok += 1
            continue
        if status not in SPN_PROBLEMS:
            continue
        try:
            owners = json.loads(owners or "[]")
        except ValueError:
            owners = []
        hit = in_range.get(spn, {"n": 0, "krb": 0, "last": None})
        rows.append({"spn": spn, "status": status, "detail": detail, "account": account,
                     "owners": [o.rstrip("$") for o in owners], "canonical": canon,
                     "n": hit["n"], "krb": hit["krb"], "last": hit["last"] or None,
                     "dc": dc, "checked_at": at})
    errors = c.execute("SELECT COUNT(*) FROM spn_checks WHERE status = 'error'").fetchone()[0]
    rows.sort(key=lambda x: (-(x["n"] + x["krb"]), x["spn"]))
    return {"rows": rows[:PANEL_LIMIT], "total": len(rows), "checked": checked, "ok": ok,
            "errors": errors, "pending": max(0, len(recent) - checked), "capable": capable}


def init_db(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript(SCHEMA)
    # Migration: add missing columns to existing databases
    have = {r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
    # Bring the agents table up to date (older installations lack lm_level)
    have_a = {r[1] for r in conn.execute("PRAGMA table_info(agents)")}
    for col in ("lm_level", "block_v1sso", "cred_guard", "ntlm_log_kb",
                "os_version", "restrict_out", "restrict_in", "restrict_dom",
                "exc_client", "exc_dc", "domain_level", "forest_level", "logon_audit"):
        if have_a and col not in have_a:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} TEXT")
    # first_seen: when observation of a machine began. Older databases never
    # recorded it; the earliest event from that machine is the best available
    # stand-in, otherwise the moment of this upgrade - conservative on purpose,
    # since "ready to switch off" must not be claimed for a machine nobody watched.
    if have_a and "first_seen" not in have_a:
        conn.execute("ALTER TABLE agents ADD COLUMN first_seen TEXT")
        conn.execute(
            "UPDATE agents SET first_seen = COALESCE("
            "(SELECT MIN(event_time) FROM events e WHERE e.source = agents.source), "
            "substr(last_seen, 1, 19))")
    # Existing data: align process names without an extension (takes effect
    # once; after that the WHERE finds nothing). Same rules as at ingest.
    conn.execute(
        "UPDATE events SET process = process || '.exe' "
        "WHERE process IS NOT NULL AND TRIM(process) != '' AND process != '-' "
        "AND process NOT LIKE '(%' AND process NOT LIKE '%.%' "
        "AND process NOT LIKE '% %' AND LOWER(process) != 'system'")
    # Undo: an earlier version of this migration wrongly turned the pseudo
    # name SYSTEM into SYSTEM.exe - there is no such process.
    conn.execute("UPDATE events SET process = substr(process, 1, length(process)-4) "
                 "WHERE LOWER(process) = 'system.exe'")
    for col in ("enc_type", "auth_method", "reason", "reason_id", "mic", "epa",
                "server_os", "failure_code", "process_path"):
        if col not in have:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
    # Stored 4022/4023 from older agents: same correction as at ingest. A no-op
    # once done - the WHERE finds nothing on the next start.
    conn.execute("UPDATE events SET kind = 'incoming' "
                 "WHERE event_id IN (4022, 4023) AND kind != 'incoming'")
    # Indexes for the dashboard queries (time-range filter, aggregates).
    # IF NOT EXISTS -> also runs cleanly against existing databases at startup.
    conn.executescript("""
    CREATE INDEX IF NOT EXISTS idx_ev_time   ON events(event_time);
    CREATE INDEX IF NOT EXISTS idx_ev_kind   ON events(kind, event_time);
    CREATE INDEX IF NOT EXISTS idx_ev_ver    ON events(ntlm_version, event_time);
    CREATE INDEX IF NOT EXISTS idx_ev_eid    ON events(event_id, event_time);
    CREATE INDEX IF NOT EXISTS idx_ev_source ON events(source);
    CREATE INDEX IF NOT EXISTS idx_ev_src_eid ON events(source, event_id, event_time);
    -- Work status for blocker/domain entries (open = no row)
    CREATE TABLE IF NOT EXISTS item_status (
        key        TEXT PRIMARY KEY,   -- 'proc|<process>|<target>' or 'dom|<source>|<target>'
        status     TEXT NOT NULL,      -- 'in_progress' | 'done' (open = no row)
        updated_at TEXT NOT NULL
    );
    """)
    conn.execute("DROP TABLE IF EXISTS enhanced_since")   # helper of a short-lived earlier rule
    # Agents before 2.3 reported audit state as German words; one-off rewrite.
    for col in ("outgoing_audit", "incoming_audit", "domain_audit"):
        for old_v, new_v in LEGACY_AUDIT.items():
            conn.execute(f"UPDATE agents SET {col} = ? WHERE {col} = ?", (new_v, old_v))
    # Status values were German words ('arbeit', 'erledigt') before 2.2; a
    # no-op once rewritten. 'open' is never stored - it is the missing row.
    for old_v, new_v in LEGACY_STATUS.items():
        if new_v == "open":
            conn.execute("DELETE FROM item_status WHERE status = ?", (old_v,))
        else:
            conn.execute("UPDATE item_status SET status = ? WHERE status = ?", (new_v, old_v))
    # Stored reasons: same correction as at ingest. Walks the distinct
    # (text, id) pairs only - a handful of rows, not every event.
    for reason, rid in conn.execute(
            "SELECT DISTINCT reason, reason_id FROM events "
            "WHERE reason IS NOT NULL AND reason != '' "
            "AND reason_id IS NOT NULL AND reason_id != ''").fetchall():
        fixed = canonical_reason_id(reason, rid)
        if fixed is not None and str(fixed) != str(rid):
            conn.execute("UPDATE events SET reason_id = ? WHERE reason = ? AND "
                         "(reason_id IS ? OR reason_id = ?)", (str(fixed), reason, rid, rid))
    conn.commit()
    return conn


# ---- Status report ---------------------------------------------------------------
# One printable page for the people who do not open the dashboard: where NTLM
# stands, whether it is going down, what has been done, what is left and what
# comes next. Rendered on the server as plain HTML with inline SVG - no
# script is needed to read it, the browser prints it to PDF as it is, and the
# static demo can store it as a file.
REPORT_RANGES = {"7d": 7, "30d": 30, "90d": 90}

_UI_TEXT = {}


def ui_text(lang, key, default=""):
    """A text from the dashboard's own translation table, so the report names
    reasons, fixes and status codes exactly as the dashboard does."""
    if not _UI_TEXT:
        src = DASHBOARD_HTML
        i = src.find("const I18N = {")
        de_at = src.find("\nde: {", i)
        en_at = src.find("\nen: {", de_at)
        end = src.find("\n}};", en_at)      # the English table closes the object
        pair = re.compile(r"(\w+):'((?:[^'\\]|\\.)*)'")
        for code, block in (("de", src[de_at:en_at]), ("en", src[en_at:end])):
            _UI_TEXT[code] = {k: v.replace("\\'", "'") for k, v in pair.findall(block)}
    return _UI_TEXT.get(lang, {}).get(key, default)


REPORT_TEXT = {
    "de": {
        "title": "NTLM-Statusbericht",
        "kicker": "Statusbericht",
        "range": "{d} Tage",
        "period": "Zeitraum {a} – {b}",
        "made": "Erstellt am {when}",
        "basis": "{a} Agenten · Daten seit {since}",
        "hero": "Noch <b>{p}</b> aller Anmeldungen laufen über NTLM.",
        "hero_zero": "Im Zeitraum lief <b>keine</b> Anmeldung mehr über NTLM.",
        "hero_none": "Für diesen Zeitraum liegen noch keine Anmeldungen vor.",
        "d_down": "{d} Prozentpunkte weniger als in den {n} Tagen davor.",
        "d_up": "{d} Prozentpunkte mehr als in den {n} Tagen davor.",
        "d_flat": "Praktisch unverändert gegenüber den {n} Tagen davor.",
        "d_none": "Für einen Vergleich mit den {n} Tagen davor reichen die Daten noch nicht.",
        "k_share": "NTLM-Anteil", "k_share_s": "aller Anmeldungen",
        "k_ntlm": "NTLM-Anmeldungen", "k_ntlm_s": "im Zeitraum",
        "k_v1": "davon NTLMv1", "k_v1_s": "unsicher, zuerst abstellen",
        "k_acc": "Konten mit NTLM", "k_acc_s": "{n} davon mit NTLMv1",
        "k_acc_s0": "keins davon mit NTLMv1",
        "vs": "vs. davor", "pp": "Pp",
        "s1": "Verlauf", "s1_sub": "NTLM-Anteil pro Woche – das Ziel ist die Nulllinie.",
        "goal": "Ziel 0 %", "wk": "KW", "last7": "letzte 7 Tage", "v1_week": "NTLMv1-Anmeldungen pro Woche",
        "few_weeks": "Für einen Verlauf braucht es mindestens zwei Wochen Daten.",
        "s2": "Fortschritt", "s2_sub": "Arbeitsliste aus dem Dashboard und Maschinen, die NTLM abschalten können.",
        "st_done": "erledigt", "st_prog": "in Arbeit", "st_open": "offen",
        "done_period": "{n} im Zeitraum erledigt",
        "by_area": "Noch nicht erledigt, nach Bereich",
        "a_blockers": "Programme (ausgehend)", "a_incoming": "Dienste (eingehend)",
        "a_domain": "Verbindungen (DC-Sicht)", "a_v1sso": "NTLMv1-SSO",
        "work_t": "Jede Zeile der Arbeitslisten im Dashboard ist ein Posten; „erledigt“ setzt, wer ihn abgestellt hat.",
        "reopened": "{n} wieder aktiv – nach „erledigt“ kam erneut NTLM",
        "no_items": "Noch keine Einträge in der Arbeitsliste.",
        "ready_h": "Bereit zum Abschalten",
        "ready_out": "ausgehend", "ready_in": "eingehend",
        "ready_of": "von {m} Maschinen",
        "ready_t": "Auditing an, {d} Tage beobachtet, in dieser Zeit kein NTLM: Hier kann „Restrict NTLM: Deny“ gesetzt werden.",
        "ready_none": "Noch keine Maschine erfüllt die Bedingungen.",
        "s3": "Was noch offen ist", "s3_sub": "Die größten Posten nach Anzahl Anmeldungen im Zeitraum.",
        "t_prog": "Programme, die NTLM senden", "t_acc": "Konten, die NTLM nutzen",
        "c_prog": "Programm → Ziel", "c_n": "Anmeld.", "c_st": "Status",
        "c_acc": "Konto", "c_mach": "von", "c_tgt": "zu",
        "c_mach_v": "{n} Rechnern", "c_tgt_v": "{n} Servern",
        "none_left": "Nichts offen.",
        "s4": "Risiken und Sichtbarkeit", "s4_sub": "Was zuerst Aufmerksamkeit braucht – und wo das Bild unvollständig ist.",
        "r_v1": "NTLMv1",
        "r_v1_bad": "{n} Anmeldungen mit NTLMv1 von {a} Konten, vor allem {top}. NTLMv1 lässt sich knacken und gehört zuerst abgestellt.",
        "r_v1_ok": "Keine NTLMv1-Anmeldung im Zeitraum.",
        "r_oct": "Oktober 2026",
        "r_oct_bad": "{n} Anmeldungen nutzen aus NTLMv1 abgeleitete Anmeldedaten. Mit der Umstellung im Oktober 2026 brechen sie von selbst.",
        "r_oct_warn": "{m} Maschinen sind von der Umstellung betroffen; betroffene Anmeldungen wurden bisher nicht gesehen.",
        "r_oct_ok": "Keine Maschine erkennbar betroffen.",
        "r_fail": "Fehlgeschlagene Anmeldungen",
        "r_fail_spray": "Verdacht auf Password Spraying: {c} ist mit {a} Konten gescheitert. Rechner und Ursache klären.",
        "r_fail_warn": "{n} Fehlversuche bei {a} Konten{locked}. Meist Dienste oder Aufgaben mit veraltetem Passwort.",
        "r_fail_locked": ", {n} davon gesperrt",
        "r_fail_ok": "Keine fehlgeschlagenen NTLM-Anmeldungen.",
        "r_vis": "Sichtbarkeit",
        "r_vis_warn": "Das Bild ist unvollständig: {parts}.",
        "r_vis_gap": "{n} Maschinen mit abgeschaltetem Auditing",
        "r_vis_stale": "{n} Agenten melden sich nicht mehr",
        "r_vis_noagent": "{n} Rechner nutzen NTLM ohne Agent",
        "r_vis_ok": "Alle Maschinen melden sich und auditieren vollständig.",
        "r_vis_none": "Noch meldet sich kein Agent – ohne Agenten gibt es keine Daten.",
        "r_relay": "Relay-Angriffe",
        "r_relay_warn": "{n} Sitzungen ohne MIC-Schutz oder Channel Binding – über NTLM-Relay angreifbar.",
        "r_relay_ok": "Keine ungeschützte Sitzung unter den {n} auswertbaren.",
        "lv_bad": "handeln", "lv_warn": "beobachten", "lv_ok": "in Ordnung",
        "s5": "Nächste Schritte", "s5_sub": "Aus den Daten abgeleitet, wichtigste zuerst.",
        "n_v1": "<b>NTLMv1 abstellen</b> bei {top}. Auf den Rechnern dahinter LmCompatibilityLevel 5 setzen und Geräte, die nur NTLMv1 können, ersetzen oder isolieren.",
        "n_oct": "<b>Vor Oktober 2026</b> die {n} Konten mit NTLMv1-abgeleiteten Anmeldedaten umstellen – sonst fallen sie mit der Umstellung aus.",
        "n_reason": "<b>Häufigste Ursache angehen:</b> {why} ({n}×). {fix}.",
        "n_ready": "<b>„Restrict NTLM: Deny“ setzen</b> auf {n} Maschinen, die seit {d} Tagen kein NTLM mehr nutzen: {names}.",
        "n_top": "<b>Größter offener Posten:</b> {proc} → {tgt} mit {n} Anmeldungen im Zeitraum.",
        "n_fail": "<b>Fehlversuche klären:</b> {user} von {src} – {why}.",
        "n_spray": "<b>Password Spraying prüfen:</b> {c} ist mit {a} Konten gescheitert.",
        "n_spn": "<b>Dienstnamen (SPN) in Ordnung bringen:</b> {n} fehlen oder sind falsch registriert, zuerst {top} – dahinter {c} NTLM-Verbindungen. Die setspn-Befehle stehen im Dashboard.",
        "n_vis": "<b>Sichtbarkeit herstellen:</b> Auditing auf {gaps} einschalten{noagent}.",
        "n_vis_noagent": "; Agent auf {names} installieren",
        "n_vis_only_noagent": "<b>Sichtbarkeit herstellen:</b> Agent auf {names} installieren.",
        "n_none": "Nichts Dringendes – den Verlauf weiter beobachten.",
        "more": "und {n} weitere",
        "method_h": "So wird gezählt",
        "method": "Grundlage sind die NTLM- und Anmeldeereignisse der Agenten und Domänencontroller. Dieselbe Anmeldung wird oft mehrfach gesehen – vom Client, vom Server und vom DC; sie zählt einmal. 8001-Einträge ohne Bestätigung durch einen DC zählen nicht. Der NTLM-Anteil ist NTLM geteilt durch NTLM plus Kerberos-Tickets. Fehlgeschlagene Anmeldungen zählen nicht zum Anteil.",
        "foot": "NTLM-Analyzer · {when}",
        "tb_back": "← Dashboard", "tb_print": "Drucken / als PDF", "tb_range": "Zeitraum",
    },
    "en": {
        "title": "NTLM status report",
        "kicker": "Status report",
        "range": "{d} days",
        "period": "Period {a} – {b}",
        "made": "Generated {when}",
        "basis": "{a} agents · data since {since}",
        "hero": "<b>{p}</b> of all logons still go through NTLM.",
        "hero_zero": "<b>No</b> logon went through NTLM in this period.",
        "hero_none": "There are no logons for this period yet.",
        "d_down": "{d} percentage points less than in the {n} days before.",
        "d_up": "{d} percentage points more than in the {n} days before.",
        "d_flat": "Practically unchanged from the {n} days before.",
        "d_none": "Not enough data yet to compare with the {n} days before.",
        "k_share": "NTLM share", "k_share_s": "of all logons",
        "k_ntlm": "NTLM logons", "k_ntlm_s": "in the period",
        "k_v1": "of which NTLMv1", "k_v1_s": "insecure, switch off first",
        "k_acc": "Accounts using NTLM", "k_acc_s": "{n} of them with NTLMv1",
        "k_acc_s0": "none of them with NTLMv1",
        "vs": "vs. before", "pp": "pp",
        "s1": "Trend", "s1_sub": "NTLM share per week - the goal is the zero line.",
        "goal": "goal 0 %", "wk": "Wk", "last7": "last 7 days", "v1_week": "NTLMv1 logons per week",
        "few_weeks": "A trend needs at least two weeks of data.",
        "s2": "Progress", "s2_sub": "The dashboard's work list, and machines that can switch NTLM off.",
        "st_done": "done", "st_prog": "in progress", "st_open": "open",
        "done_period": "{n} done in this period",
        "by_area": "Not done yet, by area",
        "a_blockers": "Programs (outgoing)", "a_incoming": "Services (incoming)",
        "a_domain": "Connections (DC view)", "a_v1sso": "NTLMv1 SSO",
        "work_t": "Each row of the dashboard's work lists is one item; whoever removes it marks it \"done\".",
        "reopened": "{n} active again - NTLM came back after \"done\"",
        "no_items": "No entries in the work list yet.",
        "ready_h": "Ready to switch off",
        "ready_out": "outgoing", "ready_in": "incoming",
        "ready_of": "of {m} machines",
        "ready_t": "Auditing on, watched for {d} days, no NTLM in that time: \"Restrict NTLM: Deny\" can be set here.",
        "ready_none": "No machine meets the conditions yet.",
        "s3": "What is left", "s3_sub": "The largest items by number of logons in the period.",
        "t_prog": "Programs sending NTLM", "t_acc": "Accounts using NTLM",
        "c_prog": "Program → target", "c_n": "Logons", "c_st": "Status",
        "c_acc": "Account", "c_mach": "from", "c_tgt": "to",
        "c_mach_v": "{n} machines", "c_tgt_v": "{n} servers",
        "none_left": "Nothing left.",
        "s4": "Risks and visibility", "s4_sub": "What needs attention first - and where the picture is incomplete.",
        "r_v1": "NTLMv1",
        "r_v1_bad": "{n} NTLMv1 logons from {a} accounts, mostly {top}. NTLMv1 can be cracked and should be switched off first.",
        "r_v1_ok": "No NTLMv1 logon in the period.",
        "r_oct": "October 2026",
        "r_oct_bad": "{n} logons use NTLMv1-derived credentials. They will break by themselves with the October 2026 change.",
        "r_oct_warn": "{m} machines are affected by the change; no affected logons have been seen so far.",
        "r_oct_ok": "No machine recognisably affected.",
        "r_fail": "Failed logons",
        "r_fail_spray": "Possible password spraying: {c} failed with {a} accounts. Find the machine and the cause.",
        "r_fail_warn": "{n} failed attempts for {a} accounts{locked}. Usually services or tasks with an old password.",
        "r_fail_locked": ", {n} of them locked out",
        "r_fail_ok": "No failed NTLM logons.",
        "r_vis": "Visibility",
        "r_vis_warn": "The picture is incomplete: {parts}.",
        "r_vis_gap": "{n} machines with auditing off",
        "r_vis_stale": "{n} agents no longer report",
        "r_vis_noagent": "{n} machines use NTLM without an agent",
        "r_vis_ok": "All machines report and audit completely.",
        "r_vis_none": "No agent reports yet - without agents there is no data.",
        "r_relay": "Relay attacks",
        "r_relay_warn": "{n} sessions without MIC protection or channel binding - open to NTLM relay.",
        "r_relay_ok": "No unprotected session among the {n} that can be judged.",
        "lv_bad": "act", "lv_warn": "watch", "lv_ok": "fine",
        "s5": "Next steps", "s5_sub": "Derived from the data, most important first.",
        "n_v1": "<b>Switch off NTLMv1</b> for {top}. Set LmCompatibilityLevel 5 on the machines behind it and replace or isolate devices that can only do NTLMv1.",
        "n_oct": "<b>Before October 2026</b> move the {n} accounts with NTLMv1-derived credentials - otherwise they fail with the change.",
        "n_reason": "<b>Tackle the most common cause:</b> {why} ({n}×). {fix}.",
        "n_ready": "<b>Set \"Restrict NTLM: Deny\"</b> on {n} machines that have not used NTLM for {d} days: {names}.",
        "n_top": "<b>Largest open item:</b> {proc} → {tgt} with {n} logons in the period.",
        "n_fail": "<b>Clear up failed logons:</b> {user} from {src} - {why}.",
        "n_spray": "<b>Check for password spraying:</b> {c} failed with {a} accounts.",
        "n_spn": "<b>Fix service names (SPN):</b> {n} are missing or registered wrongly, first {top} - {c} NTLM connections behind them. The setspn commands are in the dashboard.",
        "n_vis": "<b>Restore visibility:</b> switch auditing on for {gaps}{noagent}.",
        "n_vis_noagent": "; install the agent on {names}",
        "n_vis_only_noagent": "<b>Restore visibility:</b> install the agent on {names}.",
        "n_none": "Nothing urgent - keep watching the trend.",
        "more": "and {n} more",
        "method_h": "How it is counted",
        "method": "Based on the NTLM and logon events of the agents and domain controllers. The same logon is often seen several times - by the client, the server and the DC; it counts once. 8001 entries not confirmed by a DC do not count. The NTLM share is NTLM divided by NTLM plus Kerberos tickets. Failed logons do not count towards the share.",
        "foot": "NTLM-Analyzer · {when}",
        "tb_back": "← Dashboard", "tb_print": "Print / save as PDF", "tb_range": "Period",
    },
}


def period_counts(c, start, end):
    """NTLM (v1, v2, unversioned) and Kerberos between two UTC times, counted
    like the trend and the key-figure tiles: duplicate and unconfirmed 8001s
    and 4624 twins left out."""
    s, e = start.strftime(_TS), end.strftime(_TS)
    c.execute("CREATE TEMP TABLE IF NOT EXISTS x_rep (id INTEGER PRIMARY KEY)")
    c.execute("DELETE FROM temp.x_rep")
    c.execute(f"INSERT INTO x_rep (id) SELECT id FROM events WHERE {_TWIN_IDS} "
              f"AND event_time >= ? AND event_time < ? AND (NOT ({NOT_SUPERSEDED}) OR {UNCONFIRMED})", [s, e])
    r = c.execute(
        "SELECT SUM(CASE WHEN ntlm_version='NTLMv1' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN ntlm_version='NTLMv2' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN kind!='kerberos' AND ntlm_version IS NULL THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN kind='kerberos' THEN 1 ELSE 0 END) "
        "FROM events WHERE event_time >= ? AND event_time < ? "
        "AND id NOT IN (SELECT id FROM temp.x_rep)", [s, e]).fetchone()
    v1, v2, oth, krb = (x or 0 for x in r)
    ntlm = v1 + v2 + oth
    return {"v1": v1, "v2": v2, "ntlm": ntlm, "krb": krb,
            "share": (100.0 * ntlm / (ntlm + krb)) if (ntlm + krb) else None}


def compute_weekly(c, weeks, tzoff):
    """NTLM share and NTLMv1 per week for the last `weeks` weeks, oldest
    first; weeks before the first event are left out."""
    now = utc_now()
    start = now - timedelta(days=7 * weeks)
    s = start.strftime(_TS)
    c.execute("CREATE TEMP TABLE IF NOT EXISTS x_rep (id INTEGER PRIMARY KEY)")
    c.execute("DELETE FROM temp.x_rep")
    c.execute(f"INSERT INTO x_rep (id) SELECT id FROM events WHERE {_TWIN_IDS} "
              f"AND event_time >= ? AND (NOT ({NOT_SUPERSEDED}) OR {UNCONFIRMED})", [s])
    rows = c.execute(
        "SELECT CAST((julianday(substr(event_time,1,19)) - julianday(?)) / 7 AS INTEGER), "
        "SUM(CASE WHEN ntlm_version='NTLMv1' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN kind!='kerberos' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN kind='kerberos' THEN 1 ELSE 0 END) "
        "FROM events WHERE event_time >= ? AND id NOT IN (SELECT id FROM temp.x_rep) "
        "GROUP BY 1", [s, s]).fetchall()
    per = {w: (v1 or 0, n or 0, k or 0) for w, v1, n, k in rows if w is not None and 0 <= w < weeks}
    out = []
    for w in range(weeks):
        v1, n, k = per.get(w, (0, 0, 0))
        begin = start + timedelta(days=7 * w, minutes=tzoff)
        out.append({"start": begin, "v1": v1, "ntlm": n, "krb": k,
                    "share": (100.0 * n / (n + k)) if (n + k) else None})
    # Leading weeks with next to nothing in them (a stray event before
    # auditing really started) would show as a 100 % spike - left out too.
    vols = sorted(w["ntlm"] + w["krb"] for w in out if w["share"] is not None)
    floor = vols[len(vols) // 2] * 0.1 if vols else 0
    while out and (out[0]["share"] is None or out[0]["ntlm"] + out[0]["krb"] < floor):
        out.pop(0)
    return out


def _r_num(n, lang, dec=0):
    s = f"{n:,.{dec}f}"
    return s.replace(",", " ").replace(".", ",") if lang == "de" else s.replace(",", " ")


def _r_date(iso_or_dt, lang, tzoff, time_too=False):
    if not iso_or_dt:
        return "–"
    d = iso_or_dt
    if isinstance(d, str):
        try:
            d = datetime.strptime(d[:19], _TS) + timedelta(minutes=tzoff)
        except ValueError:
            return d[:10]
    if lang == "de":
        return d.strftime("%d.%m.%Y" + (", %H:%M" if time_too else ""))
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    return f"{d.day} {months[d.month - 1]} {d.year}" + (d.strftime(", %H:%M") if time_too else "")


def _r_list(names, lang, cap=4):
    names = [n for n in names if n]
    head = ", ".join(_h(n) for n in names[:cap])
    if len(names) > cap:
        head += " " + REPORT_TEXT[lang]["more"].format(n=len(names) - cap)
    return head


def _r_chart(weeks, lang):
    """Weekly NTLM share as an area line, NTLMv1 per week as bars below."""
    T = REPORT_TEXT[lang]
    if len(weeks) < 2:
        return f'<p class="muted">{_h(T["few_weeks"])}</p>'
    W, H, L, R, TOP, B = 700, 176, 44, 64, 34, 26
    n = len(weeks)
    hi = max(w["share"] or 0 for w in weeks)
    step = 5 if hi <= 20 else 10 if hi <= 50 else 25
    ymax = max(step, step * -(-hi // step))
    x = lambda i: L + (W - L - R) * i / (n - 1)
    y = lambda v: TOP + (H - TOP - B) * (1 - v / ymax)
    grid = []
    v = 0
    while v <= ymax + 0.01:
        yy = y(v)
        grid.append(f'<line x1="{L}" x2="{W - R}" y1="{yy:.1f}" y2="{yy:.1f}" class="{"g0" if v == 0 else "g"}"/>'
                    f'<text x="{L - 8}" y="{yy + 4:.1f}" class="ax" text-anchor="end">{_r_num(v, lang)} %</text>')
        v += step
    pts = [(x(i), y(w["share"])) for i, w in enumerate(weeks) if w["share"] is not None]
    line = " ".join(f"{a:.1f},{b:.1f}" for a, b in pts)
    area = f"M{pts[0][0]:.1f},{y(0):.1f} L" + " L".join(f"{a:.1f},{b:.1f}" for a, b in pts) + f" L{pts[-1][0]:.1f},{y(0):.1f} Z"
    last = weeks[-1]
    lx, ly = pts[-1]
    labels = []
    every = max(1, -(-n // 9))
    for i, w in enumerate(weeks):
        if i % every == 0 or i == n - 1:
            wk = w["start"].isocalendar()[1]
            labels.append(f'<text x="{x(i):.1f}" y="{H - 8}" class="ax" text-anchor="middle">{T["wk"]} {wk}</text>')
    dots = "".join(f'<circle cx="{a:.1f}" cy="{b:.1f}" r="2.6" class="dot"/>' for a, b in pts)
    main = (f'<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="{_h(T["s1"])}">'
            f'<defs><linearGradient id="ga" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#d9b84a" stop-opacity=".38"/>'
            f'<stop offset="1" stop-color="#d9b84a" stop-opacity=".02"/></linearGradient></defs>'
            + "".join(grid) +
            f'<text x="{W - R + 6}" y="{y(0) + 4:.1f}" class="goal">{_h(T["goal"])}</text>'
            f'<path d="{area}" fill="url(#ga)"/><polyline points="{line}" class="ln"/>{dots}'
            f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="5" class="end"/>'
            f'<text x="{lx + 8:.1f}" y="{ly - 12:.1f}" class="endv" text-anchor="end">{_r_num(last["share"] or 0, lang, 1)} %'
            f'<tspan class="ax" dx="6">{_h(T["last7"])}</tspan></text>'
            + "".join(labels) + '</svg>')
    vmax = max(w["v1"] for w in weeks)
    bars = ""
    if vmax:
        BH = 46
        bw = min(26, max(4, (W - L - R) / n * 0.5))
        for i, w in enumerate(weeks):
            h = BH * w["v1"] / vmax
            bars += (f'<rect x="{x(i) - bw / 2:.1f}" y="{BH - h + 16:.1f}" width="{bw:.1f}" height="{max(h, 0.8):.1f}" rx="2" class="{"v1b" if w["v1"] else "v1z"}"/>')
            if w["v1"] and (n <= 14 or w["v1"] == vmax or i == n - 1):
                bars += f'<text x="{x(i):.1f}" y="{BH - h + 12:.1f}" class="ax v1t" text-anchor="middle">{_r_num(w["v1"], lang)}</text>'
        bars = (f'<div class="sublab">{_h(T["v1_week"])}</div>'
                f'<svg class="chart v1c" viewBox="0 0 {W} {BH + 20}" aria-hidden="true">'
                f'<line x1="{L}" x2="{W - R}" y1="{BH + 16}" y2="{BH + 16}" class="g0"/>{bars}</svg>')
    return main + bars


REPORT_CSS = r"""
:root{--ink:#0f172a;--dim:#475569;--faint:#64748b;--line:#e3e8ef;--soft:#f5f7fa;
  --gold:#a8841e;--gold2:#d9b84a;--v1:#c62828;--amb:#b45309;--ok:#137a50;
  --text:'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,'Helvetica Neue',Arial,sans-serif;
  --disp:'Segoe UI Variable Display','Segoe UI',system-ui,-apple-system,'Helvetica Neue',Arial,sans-serif;
  --mono:'Cascadia Mono','IBM Plex Mono',ui-monospace,Consolas,'SF Mono',monospace}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:#e7ebf0;color:var(--ink);font-family:var(--text);font-size:13px;line-height:1.5}
.tb{position:sticky;top:0;z-index:5;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:center;
  padding:10px 16px;background:rgba(15,23,42,.92);color:#e2e8f0;font-size:13px}
.tb a,.tb button{color:#e2e8f0;text-decoration:none;border:1px solid rgba(226,232,240,.25);border-radius:8px;
  padding:6px 12px;background:transparent;font:inherit;cursor:pointer}
.tb a.on{background:#d9b84a;color:#0f172a;border-color:#d9b84a;font-weight:600}
.tb .grp{display:flex;gap:4px;align-items:center}
.tb .lbl{color:#94a3b8;margin-right:4px}
.tb .print{background:#d9b84a;color:#0f172a;border-color:#d9b84a;font-weight:600}
.sheet{width:210mm;max-width:100%;margin:24px auto 48px;background:#fff;padding:15mm 16mm 12mm;
  box-shadow:0 10px 40px rgba(15,23,42,.18);border-radius:4px}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding-bottom:12px;border-bottom:2px solid var(--ink)}
.brand{display:flex;align-items:center;gap:9px;font-family:var(--disp);font-weight:650;font-size:14px;letter-spacing:.01em}
.brand img{width:24px;height:24px;border-radius:6px}
.kick{font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);text-align:right}
h1{font-family:var(--disp);font-size:34px;line-height:1.1;margin:18px 0 6px;font-weight:700;letter-spacing:-.015em}
.meta{display:flex;flex-wrap:wrap;gap:4px 18px;color:var(--dim);font-size:12px}
.meta span+span::before{content:"";}
.hero{margin:18px 0 4px;font-family:var(--disp);font-size:25px;line-height:1.25;font-weight:500;letter-spacing:-.01em}
.hero b{color:var(--gold);font-weight:700}
.delta{display:flex;align-items:center;gap:8px;color:var(--dim);font-size:13.5px;margin-bottom:18px}
.arrow{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:50%;font-size:13px;font-weight:700;color:#fff}
.arrow.good{background:var(--ok)}.arrow.bad{background:var(--v1)}.arrow.flat{background:#94a3b8}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:6px 0 8px}
.kpi{border:1px solid var(--line);border-radius:12px;padding:12px 13px 11px;background:linear-gradient(180deg,#fff,var(--soft))}
.kpi .l{font-size:11px;color:var(--dim);font-weight:600}
.kpi .v{font-family:var(--disp);font-size:26px;font-weight:700;letter-spacing:-.02em;line-height:1.15;margin-top:4px}
.kpi .v.red{color:var(--v1)}
.kpi .s{font-size:10.5px;color:var(--faint);margin-top:2px}
.chip{display:inline-block;font-family:var(--mono);font-size:10px;font-weight:600;border-radius:999px;padding:1px 7px;margin-top:6px}
.chip.good{background:#e3f4ec;color:var(--ok)}.chip.bad{background:#fdeaea;color:var(--v1)}.chip.flat{background:#eef2f6;color:var(--faint)}
section{margin-top:22px;break-inside:avoid}
section.flow{break-inside:auto}
.sh{display:flex;align-items:baseline;gap:12px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-bottom:12px;break-after:avoid}
.sh .no{font-family:var(--mono);font-size:11px;color:var(--gold);font-weight:700;letter-spacing:.06em}
.sh h2{margin:0;font-family:var(--disp);font-size:18px;font-weight:650;letter-spacing:-.005em}
.sh p{margin:0 0 0 auto;color:var(--faint);font-size:11px;text-align:right;max-width:55%}
.chart{width:100%;height:auto;display:block}
.chart .g{stroke:#e8ecf2;stroke-width:1}.chart .g0{stroke:#94a3b8;stroke-width:1.2;stroke-dasharray:4 3}
.chart .ax{font-family:var(--mono);font-size:10px;fill:#7b8798}
.chart .goal{font-family:var(--mono);font-size:10px;fill:var(--ok);font-weight:700}
.chart .ln{fill:none;stroke:var(--gold2);stroke-width:2.6;stroke-linejoin:round;stroke-linecap:round}
.chart .dot{fill:#fff;stroke:var(--gold2);stroke-width:1.6}
.chart .end{fill:var(--gold2);stroke:#fff;stroke-width:2}
.chart .endv{font-family:var(--disp);font-size:13px;font-weight:700;fill:var(--ink)}
.chart .v1b{fill:var(--v1)}.chart .v1z{fill:#e8ecf2}.chart .v1t{fill:var(--v1);font-weight:700}
.sublab{font-size:10.5px;color:var(--faint);margin:10px 0 2px 44px;font-weight:600}
.muted{color:var(--faint)}
.prog{display:grid;grid-template-columns:1.25fr 1fr;gap:18px}
.bar{display:flex;height:14px;border-radius:999px;overflow:hidden;background:#eef2f6;margin:8px 0 10px}
.bar i{display:block;height:100%}
.bar .d{background:var(--ok)}.bar .p{background:var(--gold2)}.bar .o{background:#cbd5e1}
.legend i.lo{background:#cbd5e1}
.legend{display:flex;flex-wrap:wrap;gap:4px 16px;font-size:12px;color:var(--dim)}
.legend b{font-family:var(--disp);font-size:18px;color:var(--ink);margin-right:5px}
.legend i{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:5px;vertical-align:1px}
.note{font-size:11.5px;color:var(--dim);margin-top:8px}
.note.warn{color:var(--amb);font-weight:600}
.areas{margin-top:10px}
.areas .ah{font-size:10.5px;font-weight:600;color:var(--faint);margin-bottom:2px}
.ar{display:flex;justify-content:space-between;border-bottom:1px solid #eef1f5;padding:3px 0;font-size:11.5px}
.ar b{font-variant-numeric:tabular-nums}
.box{border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.box h3{margin:0 0 6px;font-size:12.5px;font-family:var(--disp)}
.rd{display:flex;gap:14px;margin:4px 0 6px}
.rd div{flex:1}
.rd b{display:block;font-family:var(--disp);font-size:20px}
.rd span{font-size:11px;color:var(--faint)}
.names{font-family:var(--mono);font-size:10.5px;color:var(--dim);margin-top:6px;word-break:break-word}
.two{display:grid;grid-template-columns:1fr 1fr;gap:18px}
table{width:100%;border-collapse:collapse;font-size:11.5px}
caption{text-align:left;font-family:var(--disp);font-weight:650;font-size:12.5px;padding-bottom:6px}
th{font-family:var(--mono);font-weight:600;font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);
  text-align:left;border-bottom:1px solid var(--line);padding:4px 6px 5px 0}
td{border-bottom:1px solid #eef1f5;padding:6px 6px 6px 0;vertical-align:top}
tr{break-inside:avoid}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td .sub{display:block;color:var(--faint);font-size:10.5px;font-weight:400;word-break:break-all}
td.nm{font-weight:600;word-break:break-word}
.tag{display:inline-block;font-family:var(--mono);font-size:9.5px;font-weight:700;border-radius:5px;padding:0 5px;margin-left:4px;vertical-align:1px}
.tag.v1{background:#fdeaea;color:var(--v1)}.tag.st-open{background:#eef2f6;color:var(--faint)}
.tag.st-in_progress{background:#fbf3dc;color:#8a6a12}.tag.st-done{background:#e3f4ec;color:var(--ok)}
.risks{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.risk{border:1px solid var(--line);border-left:4px solid #cbd5e1;border-radius:10px;padding:10px 12px;break-inside:avoid}
.risk.bad{border-left-color:var(--v1)}.risk.warn{border-left-color:#e0a106}.risk.ok{border-left-color:var(--ok)}
.risk .rh{display:flex;justify-content:space-between;align-items:center;gap:8px;font-weight:650;font-family:var(--disp);font-size:13px}
.lv{white-space:nowrap;flex:none;font-family:var(--mono);font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;border-radius:999px;padding:1px 8px}
.risk.bad .lv{background:#fdeaea;color:var(--v1)}.risk.warn .lv{background:#fdf3d7;color:var(--amb)}.risk.ok .lv{background:#e3f4ec;color:var(--ok)}
.risk p{margin:5px 0 0;color:var(--dim);font-size:11.5px}
ol.steps{list-style:none;counter-reset:s;margin:0;padding:0}
ol.steps li{counter-increment:s;position:relative;padding:8px 0 9px 38px;border-bottom:1px solid #eef1f5;break-inside:avoid;font-size:12.5px}
ol.steps li::before{content:counter(s);position:absolute;left:0;top:7px;width:25px;height:25px;border-radius:50%;
  background:var(--ink);color:#fff;font-family:var(--disp);font-weight:700;font-size:12px;display:grid;place-items:center}
ol.steps li:first-child::before{background:var(--gold2);color:var(--ink)}
.method{margin-top:24px;padding:10px 12px;background:var(--soft);border-radius:10px;font-size:10.5px;color:var(--dim);break-inside:avoid}
.method b{color:var(--ink)}
.foot{margin-top:14px;display:flex;justify-content:space-between;font-family:var(--mono);font-size:9.5px;color:var(--faint);
  border-top:1px solid var(--line);padding-top:8px}
/* On screen the report follows a dark system theme; printed or saved as PDF
   it is always the light paper version - print media never matches this. */
@media screen and (prefers-color-scheme:dark){
  :root{--ink:#e6ebf3;--dim:#aab4c3;--faint:#8591a3;--line:#253041;--soft:#151c28;
    --gold:#d9b84a;--v1:#ff6b6b;--amb:#f0b429;--ok:#3ddc97}
  body{background:#070b12}
  .sheet{background:#0f141d;box-shadow:0 10px 40px rgba(0,0,0,.55)}
  .kpi{background:linear-gradient(180deg,#141b27,#0f141d)}
  .chip.good,.tag.st-done,.risk.ok .lv{background:rgba(61,220,151,.14)}
  .chip.bad,.tag.v1,.risk.bad .lv{background:rgba(255,107,107,.14)}
  .chip.flat,.tag.st-open{background:#1b2331}
  .tag.st-in_progress{background:rgba(217,184,74,.15);color:#d9b84a}
  .risk.warn .lv{background:rgba(240,180,41,.14)}
  .risk{border-color:var(--line)}
  .arrow.flat{background:#3a4556}
  .chart .g,.chart .v1z{stroke:#1e2736;fill:#1e2736}
  .chart .g{fill:none}
  .chart .ax{fill:#7d889a}
  .chart .dot{fill:#0f141d}
  .chart .end{stroke:#0f141d}
  .bar{background:#1b2331}
  .bar .o,.legend i.lo{background:#3a4556}
  td,.ar,ol.steps li{border-bottom-color:#1b2331}
  ol.steps li::before{background:#e6ebf3;color:#0f141d}
  ol.steps li:first-child::before{background:var(--gold2);color:#0f141d}
}
@page{size:A4;margin:13mm 13mm 14mm}
@media print{
  body{background:#fff;font-size:12.5px}
  .tb{display:none}
  .sheet{width:auto;margin:0;padding:0;box-shadow:none;border-radius:0}
  .pb{break-before:page}
}
@media (max-width:760px){
  .sheet{padding:18px 16px;margin:0;border-radius:0}
  .kpis{grid-template-columns:1fr 1fr}
  .prog,.two,.risks{grid-template-columns:1fr}
  h1{font-size:27px}.hero{font-size:20px}
  .sh{flex-wrap:wrap}.sh p{margin:0;text-align:left;max-width:none}
}
"""


def render_report(ctx):
    lang, rng, tz = ctx["lang"], ctx["range"], ctx["tzoff"]
    T = REPORT_TEXT[lang]
    days = REPORT_RANGES[rng]
    data, cur, prev = ctx["data"], ctx["cur"], ctx["prev"]
    num = lambda v, d=0: _r_num(v, lang, d)
    now_local = utc_now() + timedelta(minutes=tz)
    start_local = now_local - timedelta(days=days)

    # Toolbar (screen only). The static demo has no server behind the links,
    # so there they point to the pre-rendered files.
    def link(lg, rg):
        return (f"report-{lg}-{rg}.html" if ctx["static"]
                else f"/report?range={rg}&lang={lg}&tzoff={tz}")
    back = "index.html" if ctx["static"] else "/"
    tb = (f'<nav class="tb"><a href="{back}">{_h(T["tb_back"])}</a>'
          f'<span class="grp"><span class="lbl">{_h(T["tb_range"])}</span>'
          + "".join(f'<a href="{link(lang, r)}" class="{"on" if r == rng else ""}">{_h(T["range"].format(d=d))}</a>'
                    for r, d in REPORT_RANGES.items()) +
          '</span><span class="grp">'
          + "".join(f'<a href="{link(lg, rng)}" class="{"on" if lg == lang else ""}">{lg.upper()}</a>' for lg in ("de", "en")) +
          f'</span><button type="button" class="print" id="print">{_h(T["tb_print"])}</button></nav>'
          '<script>document.getElementById("print").addEventListener("click",function(){window.print()});</script>')

    # Head and the one sentence that matters
    agents = data.get("agents") or []
    first = ctx["first_event"]
    meta = [T["period"].format(a=_r_date(start_local, lang, 0), b=_r_date(now_local, lang, 0)),
            T["basis"].format(a=num(len(agents)), since=_r_date(first, lang, tz)),
            T["made"].format(when=_r_date(now_local, lang, 0, True))]
    if cur["share"] is None:
        hero = T["hero_none"]
    elif cur["ntlm"] == 0:
        hero = T["hero_zero"]
    else:
        hero = T["hero"].format(p=num(cur["share"], 1) + " %")
    if cur["share"] is None or prev["share"] is None:
        delta, arrow = T["d_none"].format(n=days), ""
    else:
        dp = cur["share"] - prev["share"]
        if abs(dp) < 0.5:
            delta, arrow = T["d_flat"].format(n=days), '<span class="arrow flat">→</span>'
        elif dp < 0:
            delta, arrow = T["d_down"].format(d=num(-dp, 1), n=days), '<span class="arrow good">↓</span>'
        else:
            delta, arrow = T["d_up"].format(d=num(dp, 1), n=days), '<span class="arrow bad">↑</span>'

    def chip(c_, p_, pct=True, pp=False):
        if p_ is None or c_ is None:
            return ""
        if pp:
            d = c_ - p_
            if abs(d) < 0.05:
                return f'<span class="chip flat">±0 {T["pp"]} {T["vs"]}</span>'
            return (f'<span class="chip {"good" if d < 0 else "bad"}">{"−" if d < 0 else "+"}{num(abs(d), 1)} '
                    f'{T["pp"]} {T["vs"]}</span>')
        if not p_:
            return "" if not c_ else f'<span class="chip bad">+{num(c_)} {T["vs"]}</span>'
        d = 100.0 * (c_ - p_) / p_
        if abs(d) < 0.5:
            return f'<span class="chip flat">±0 % {T["vs"]}</span>'
        return f'<span class="chip {"good" if d < 0 else "bad"}">{"−" if d < 0 else "+"}{num(abs(d))} % {T["vs"]}</span>'

    acc_rows = [r for r in (data.get("accounts") or {}).get("rows") or [] if r.get("n")]
    acc_v1 = sum(1 for r in acc_rows if r.get("v1"))
    has_prev = prev["share"] is not None
    share_txt = num(cur["share"], 1) + "\u202f%" if cur["share"] is not None else "–"
    kpis = (
        f'<div class="kpi"><div class="l">{_h(T["k_share"])}</div><div class="v">{share_txt}</div>'
        f'<div class="s">{_h(T["k_share_s"])}</div>{chip(cur["share"], prev["share"], pp=True) if has_prev else ""}</div>'
        f'<div class="kpi"><div class="l">{_h(T["k_ntlm"])}</div><div class="v">{num(cur["ntlm"])}</div>'
        f'<div class="s">{_h(T["k_ntlm_s"])}</div>{chip(cur["ntlm"], prev["ntlm"]) if has_prev else ""}</div>'
        f'<div class="kpi"><div class="l">{_h(T["k_v1"])}</div><div class="v{" red" if cur["v1"] else ""}">{num(cur["v1"])}</div>'
        f'<div class="s">{_h(T["k_v1_s"])}</div>{chip(cur["v1"], prev["v1"]) if has_prev else ""}</div>'
        f'<div class="kpi"><div class="l">{_h(T["k_acc"])}</div><div class="v">{num(len(acc_rows))}</div>'
        f'<div class="s">{_h(T["k_acc_s"].format(n=num(acc_v1)) if acc_v1 else T["k_acc_s0"])}</div></div>')

    # 01 Trend
    s1 = _r_chart(ctx["weekly"], lang)

    # 02 Progress: work list and readiness
    items = [r for k in ("blockers", "incoming", "domain", "v1sso") for r in (data.get(k) or [])]
    n_open = sum(1 for r in items if r.get("st") == "open")
    n_prog = sum(1 for r in items if r.get("st") == "in_progress")
    n_done = ctx["done_total"]
    reopened = sum(1 for r in items if r.get("st") == "done" and r.get("st_at") and (r.get("last_seen") or "") > r["st_at"])
    tot = n_open + n_prog + n_done
    if tot:
        pc = lambda v: f"{100.0 * v / tot:.2f}%"
        work = (f'<div class="bar"><i class="d" style="width:{pc(n_done)}"></i><i class="p" style="width:{pc(n_prog)}"></i>'
                f'<i class="o" style="width:{pc(n_open)}"></i></div>'
                f'<div class="legend"><span><i style="background:var(--ok)"></i><b>{num(n_done)}</b>{_h(T["st_done"])}</span>'
                f'<span><i style="background:var(--gold2)"></i><b>{num(n_prog)}</b>{_h(T["st_prog"])}</span>'
                f'<span><i class="lo"></i><b>{num(n_open)}</b>{_h(T["st_open"])}</span></div>'
                + (f'<div class="note">{_h(T["done_period"].format(n=num(ctx["done_period"])))}</div>' if ctx["done_period"] else "")
                + (f'<div class="note warn">{_h(T["reopened"].format(n=num(reopened)))}</div>' if reopened else ""))
        areas = [(T["a_" + k], sum(1 for r in data.get(k) or [] if r.get("st") != "done"))
                 for k in ("blockers", "incoming", "domain", "v1sso")]
        work += (f'<div class="areas"><div class="ah">{_h(T["by_area"])}</div>'
                 + "".join(f'<div class="ar"><span>{_h(a)}</span><b>{num(v)}</b></div>' for a, v in areas if v)
                 + f'</div><div class="note">{_h(T["work_t"])}</div>')
    else:
        work = f'<p class="muted">{_h(T["no_items"])}</p>'
    rd = data.get("readiness") or {}
    rrows = rd.get("rows") or []
    judged_out = sum(1 for r in rrows if r["out"]["st"] != "dc")
    judged_in = sum(1 for r in rrows if r["in"]["st"] != "dc")
    ready_names = [r["machine"] for r in rrows if r["out"]["st"] == "ready" or r["in"]["st"] == "ready"]
    ready = (f'<div class="box"><h3>{_h(T["ready_h"])}</h3><div class="rd">'
             f'<div><b>{num(rd.get("out_ready", 0))}</b><span>{_h(T["ready_out"])} · {_h(T["ready_of"].format(n=num(rd.get("out_ready", 0)), m=num(judged_out)))}</span></div>'
             f'<div><b>{num(rd.get("in_ready", 0))}</b><span>{_h(T["ready_in"])} · {_h(T["ready_of"].format(n=num(rd.get("in_ready", 0)), m=num(judged_in)))}</span></div></div>'
             + (f'<div class="names">{_r_list(ready_names, lang, 8)}</div>'
                f'<div class="note">{_h(T["ready_t"].format(d=rd.get("quiet_days", 30)))}</div>'
                if ready_names else f'<div class="note">{_h(T["ready_none"])}</div>') + '</div>')
    s2 = f'<div class="prog"><div>{work}</div>{ready}</div>'

    # 03 What is left
    st_txt = {"open": T["st_open"], "in_progress": T["st_prog"], "done": T["st_done"]}
    progs = [r for r in data.get("blockers") or [] if not (r.get("st") == "done" and (r.get("last_seen") or "") <= (r.get("st_at") or ""))][:15]
    t_prog = (f'<table><caption>{_h(T["t_prog"])}</caption><thead><tr><th>{_h(T["c_prog"])}</th>'
              f'<th class="n">{_h(T["c_n"])}</th></tr></thead><tbody>'
              + "".join(f'<tr><td class="nm">{_h(r["process"])}<span class="tag st-{_h(r["st"])}">{_h(st_txt.get(r["st"], r["st"]))}</span>'
                        f'<span class="sub">→ {_h(r["target"])}</span></td><td class="n">{num(r["n"])}</td></tr>' for r in progs)
              + (f'<tr><td colspan="2" class="muted">{_h(T["none_left"])}</td></tr>' if not progs else "")
              + '</tbody></table>')
    accs = acc_rows[:15]
    t_acc = (f'<table><caption>{_h(T["t_acc"])}</caption><thead><tr><th>{_h(T["c_acc"])}</th>'
             f'<th class="n">{_h(T["c_n"])}</th></tr></thead><tbody>'
             + "".join(f'<tr><td class="nm">{_h(r["name"])}' + (f'<span class="tag v1">NTLMv1</span>' if r.get("v1") else "")
                       + f'<span class="sub">{_h(T["c_mach"])} {_h(T["c_mach_v"].format(n=num(r["machines"])))} '
                         f'{_h(T["c_tgt"])} {_h(T["c_tgt_v"].format(n=num(r["targets"])))}</span></td>'
                         f'<td class="n">{num(r["n"])}</td></tr>' for r in accs)
             + (f'<tr><td colspan="2" class="muted">{_h(T["none_left"])}</td></tr>' if not accs else "")
             + '</tbody></table>')
    s3 = f'<div class="two"><div>{t_prog}</div><div>{t_acc}</div></div>'

    # 04 Risks and visibility
    risks = []
    v1u = [u for u in data.get("v1_users") or [] if u.get("name")]
    v1n = cur["v1"]
    if v1n:
        risks.append(("bad", T["r_v1"], T["r_v1_bad"].format(n=num(v1n), a=num(len(v1u)), top=_r_list([u["name"] for u in v1u], lang, 3))))
    else:
        risks.append(("ok", T["r_v1"], _h(T["r_v1_ok"])))
    v1sso = data.get("v1sso") or []
    v1sso_n = sum(r.get("n", 0) for r in v1sso)
    oct_aff = [a["source"] for a in agents if a.get("cred_guard") != "on" and a.get("block_v1sso") != "deny"
               and a.get("lm_level") and str(a["lm_level"]).isdigit() and int(a["lm_level"]) >= 4]
    if v1sso_n:
        risks.append(("bad", T["r_oct"], _h(T["r_oct_bad"].format(n=num(v1sso_n)))))
    elif oct_aff:
        risks.append(("warn", T["r_oct"], _h(T["r_oct_warn"].format(m=num(len(oct_aff))))))
    else:
        risks.append(("ok", T["r_oct"], _h(T["r_oct_ok"])))
    fl = data.get("failures") or {}
    if fl.get("spray"):
        c0 = fl["spray"][0]
        risks.append(("bad", T["r_fail"], _h(T["r_fail_spray"].format(c=c0[0], a=num(c0[1])))))
    elif fl.get("n"):
        locked = sum(1 for r in fl.get("rows") or [] if r.get("locked"))
        risks.append(("warn", T["r_fail"], _h(T["r_fail_warn"].format(
            n=num(fl["n"]), a=num(fl.get("accounts", 0)),
            locked=T["r_fail_locked"].format(n=num(locked)) if locked else ""))))
    else:
        risks.append(("ok", T["r_fail"], _h(T["r_fail_ok"])))
    now = utc_now()
    gaps = [a["source"] for a in agents if a.get("outgoing_audit") == "off" or a.get("incoming_audit") == "off"
            or (a.get("is_dc") and a.get("domain_audit") == "off") or a.get("logon_audit") == "none"]
    stale = []
    for a in agents:
        try:
            seen = datetime.strptime((a.get("last_seen") or "")[:19], _TS)
        except ValueError:
            seen = None
        if not seen or (now - seen).days >= AGENT_STALE_DAYS:
            stale.append(a["source"])
    noag = data.get("agentless") or {}
    noag_rows = noag.get("rows") or []
    parts = []
    if gaps:
        parts.append(T["r_vis_gap"].format(n=num(len(gaps))))
    if stale:
        parts.append(T["r_vis_stale"].format(n=num(len(stale))))
    if noag_rows:
        parts.append(T["r_vis_noagent"].format(n=num(noag.get("total", len(noag_rows)))))
    if not agents:
        risks.append(("warn", T["r_vis"], _h(T["r_vis_none"])))
    elif parts:
        risks.append(("warn", T["r_vis"], _h(T["r_vis_warn"].format(parts=", ".join(parts)))))
    else:
        risks.append(("ok", T["r_vis"], _h(T["r_vis_ok"])))
    st = data.get("stats") or {}
    if st.get("relay_scope"):
        risks.append(("warn" if st.get("relay") else "ok", T["r_relay"],
                      _h(T["r_relay_warn"].format(n=num(st["relay"])) if st.get("relay")
                         else T["r_relay_ok"].format(n=num(st["relay_scope"])))))
    lv = {"bad": T["lv_bad"], "warn": T["lv_warn"], "ok": T["lv_ok"]}
    order = {"bad": 0, "warn": 1, "ok": 2}
    risks.sort(key=lambda r: order[r[0]])
    s4 = '<div class="risks">' + "".join(
        f'<div class="risk {k}"><div class="rh">{_h(title)}<span class="lv">{_h(lv[k])}</span></div><p>{body}</p></div>'
        for k, title, body in risks) + '</div>'

    # 05 Next steps - from the data, most important first, at most six
    steps = []
    if v1n and v1u:
        steps.append(T["n_v1"].format(top=_r_list([u["name"] for u in v1u], lang, 3)))
    if v1sso_n:
        steps.append(T["n_oct"].format(n=num(len({r.get("user") for r in v1sso}))))
    if fl.get("spray"):
        c0 = fl["spray"][0]
        steps.append(T["n_spray"].format(c=_h(c0[0]), a=num(c0[1])))
    spn_rows = (data.get("spn") or {}).get("rows") or []
    if spn_rows:
        steps.append(T["n_spn"].format(n=num(len(spn_rows)), top=_r_list([r["spn"] for r in spn_rows], lang, 3),
                                       c=num(sum(r["n"] for r in spn_rows))))
    reasons = [r for r in data.get("reasons") or [] if r.get("cat") not in ("unclear", "cloud", "acct")]
    if reasons:
        r0 = reasons[0]
        why = ui_text(lang, "rid_" + str(r0["rid"]), r0.get("text") or "")
        fix = ui_text(lang, "fix_" + str(r0.get("cat")), "")
        if why and fix:
            steps.append(T["n_reason"].format(why=_h(why), n=num(r0["n"]), fix=_h(fix.rstrip("."))))
    if ready_names:
        steps.append(T["n_ready"].format(n=num(len(ready_names)), d=rd.get("quiet_days", 30),
                                         names=_r_list(ready_names, lang, 4)))
    open_progs = [r for r in data.get("blockers") or [] if r.get("st") == "open"]
    if open_progs:
        r0 = open_progs[0]
        steps.append(T["n_top"].format(proc=_h(r0["process"]), tgt=_h(r0["target"]), n=num(r0["n"])))
    # Repeated failures of one account point at a stored old password.
    frows = [r for r in fl.get("rows") or [] if r.get("n", 0) >= 3]
    if frows:
        r0 = frows[0]
        why = ui_text(lang, "nt_" + str(r0.get("code") or "").lower(), str(r0.get("code") or ""))
        steps.append(T["n_fail"].format(user=_h(r0["user"]), src=_h(r0.get("from") or "–"), why=_h(why)))
    noag_names = [r.get("machine") or r.get("workstation") or r.get("name") for r in noag_rows]
    if gaps:
        steps.append(T["n_vis"].format(gaps=_r_list(gaps, lang, 4),
                                       noagent=T["n_vis_noagent"].format(names=_r_list(noag_names, lang, 3)) if noag_names else ""))
    elif noag_names:
        steps.append(T["n_vis_only_noagent"].format(names=_r_list(noag_names, lang, 3)))
    steps = steps[:6] or [_h(T["n_none"])]
    s5 = '<ol class="steps">' + "".join(f"<li>{s}</li>" for s in steps) + '</ol>'

    def sec(no, key, body, cls=""):
        return (f'<section class="{cls}"><div class="sh"><span class="no">{no}</span><h2>{_h(T[key])}</h2>'
                f'<p>{_h(T[key + "_sub"])}</p></div>{body}</section>')

    logo = ctx.get("logo") or ""
    title = f'{T["title"]} · {T["range"].format(d=days)}'
    return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{_h(title)}</title><style>{REPORT_CSS}</style></head><body>{tb}'
            f'<main class="sheet"><div class="top"><div class="brand">'
            + (f'<img src="{logo}" alt="">' if logo else "") +
            f'NTLM-Analyzer</div><div class="kick">{_h(T["kicker"])} · {_h(T["range"].format(d=days))}</div></div>'
            f'<h1>{_h(T["title"])}</h1><div class="meta">' + "".join(f"<span>{_h(m)}</span>" for m in meta) + '</div>'
            f'<p class="hero">{hero}</p><div class="delta">{arrow}<span>{_h(delta)}</span></div>'
            f'<div class="kpis">{kpis}</div>'
            # Printed: page one is the overview, page two what to do about
            # it, page three the detail lists for whoever does the work.
            + sec("01", "s1", s1) + sec("02", "s2", s2) + sec("03", "s4", s4, "pb")
            + sec("04", "s5", s5) + sec("05", "s3", s3, "flow pb") +
            f'<div class="method"><b>{_h(T["method_h"])}.</b> {_h(T["method"])}</div>'
            f'<div class="foot"><span>{_h(T["foot"].format(when=_r_date(now_local, lang, 0, True)))}</span>'
            f'<span>{_h(T["range"].format(d=days))}</span></div></main></body></html>')


class Handler(BaseHTTPRequestHandler):
    server_version = "NtlmCollector/1.0"
    sys_version = ""   # keep the Python version out of every response header

    # ---- Helpers ----------------------------------------------------------
    def _send(self, code, body, ctype="application/json", nonce=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers(nonce)
        self.end_headers()
        self.wfile.write(body)

    def _send_page(self, html):
        """An HTML page whose own scripts carry a fresh nonce. The CSP then only
        runs scripts with that nonce: should a value ever slip through the
        escaping into the page, an injected <script> or onerror= would not run."""
        nonce = secrets.token_urlsafe(16)
        html = re.sub(r"<script(?=[\s>])", '<script nonce="%s"' % nonce, html)
        self._send(200, html, "text/html; charset=utf-8", nonce=nonce)

    def _security_headers(self, nonce=None):
        """Defence in depth. Nothing here is currently exploitable - there are no
        third-party contents and every value is escaped - but these are free."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        # The dashboard is one self-contained file: inline script and style, no
        # external resources at all. Everything else is denied, so an injected
        # tag could neither load nor exfiltrate anything.
        # Scripts only with this response's nonce. 'unsafe-inline' is ignored
        # by every browser that understands nonces and only kept for the rest.
        scripts = ("'nonce-%s' 'unsafe-inline'" % nonce) if nonce else "'none'"
        if getattr(self.server, "tls", False):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; "
            "script-src " + scripts + "; "
            "style-src 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'")

    def log_message(self, fmt, *args):
        pass  # stay quiet; uncomment when needed

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
        if not self.server.pw_hash:        # login disabled -> let everything through
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
                if locked_until <= now:            # never overwrite an existing lock
                    fails += 1
                    if fails >= LOGIN_MAX_FAILS:
                        LOGIN_FAILS[ip] = [0, now + LOGIN_LOCK_SECS]
                    else:
                        LOGIN_FAILS[ip] = [fails, 0.0]
            time.sleep(1.0)                # slight brake against guessing
            self._redirect("/login?err=1")

    # ---- Routing ----------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/login":
            if not self.server.pw_hash or self._valid_session():
                self._redirect("/")
            else:
                self._send_page(LOGIN_HTML)
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
                self._send_page(page)
        elif u.path == "/report":
            if self._login_required():
                self._redirect("/login")
            else:
                self._send_page(self._report(parse_qs(u.query)))
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
        elif u.path == "/api/machine":
            if self._login_required():
                self._send(401, {"error": "login required"})
            else:
                self._send(200, self._query_machine(parse_qs(u.query)))
        elif u.path == "/api/account":
            if self._login_required():
                self._send(401, {"error": "login required"})
            else:
                self._send(200, self._query_account(parse_qs(u.query)))
        else:
            self._send(404, {"error": "not found"})

    def _cross_site(self):
        """True for a request another web page made the browser send.
        Browsers say so themselves (Sec-Fetch-Site); older ones at least send
        an Origin, which must then be this collector."""
        # Every current browser sends Sec-Fetch-Site, and it survives a reverse
        # proxy that rewrites the Host header - so it decides when present.
        site = (self.headers.get("Sec-Fetch-Site") or "").lower()
        if site:
            return site not in ("same-origin", "none")
        origin = self.headers.get("Origin")
        if origin is None:
            return False                   # agents, scripts, curl
        if origin == "null":
            return True
        hosts = {(self.headers.get(h) or "").lower() for h in ("Host", "X-Forwarded-Host")}
        return urlparse(origin).netloc.lower() not in hosts

    def _json_body(self):
        """Agents and the dashboard send JSON as such. A web page cannot send
        that cross-site without the browser asking first (CORS preflight),
        which this server never answers - so a foreign page cannot post here."""
        return (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() == "application/json"

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":          # browser login, uses NO API key
            if self._cross_site():
                self._send(403, {"error": "cross-site request"})
                return
            self._handle_login()
            return
        if u.path == "/item-status":    # browser action -> session, not API key
            if self._cross_site() or not self._json_body():
                self._send(403, {"error": "cross-site request"})
                return
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
            # Status values are English identifiers now. The German ones earlier
            # versions used are still accepted, so a dashboard tab left open
            # across the upgrade keeps working.
            status = LEGACY_STATUS.get(status, status)
            if not key or "|" not in key or status not in ("open", "in_progress", "done"):
                self._send(400, {"error": "bad key/status"})
                return
            # UTC, so the comparison against the agents' event timestamps (also
            # UTC) for "active again" has no timezone offset.
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            with DB_LOCK:
                if status == "open":      # open = default -> remove the row
                    self.server.conn.execute("DELETE FROM item_status WHERE key=?", (key,))
                else:
                    self.server.conn.execute(
                        "INSERT INTO item_status (key,status,updated_at) VALUES (?,?,?) "
                        "ON CONFLICT(key) DO UPDATE SET status=excluded.status, "
                        "updated_at=excluded.updated_at", (key, status, now))
                self.server.conn.commit()
            self._send(200, {"ok": True})
            return
        if u.path == "/spn-recheck":    # browser action, like /item-status
            if self._cross_site() or not self._json_body():
                self._send(403, {"error": "cross-site request"})
                return
            if self._login_required():
                self._send(401, {"error": "login required"})
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length < 0 or length > 8 * 1024:
                    raise ValueError("bad length")
                p = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(p, dict):
                    raise ValueError("not an object")
            except Exception:
                self._send(400, {"error": "bad request"})
                return
            # After a setspn the admin wants to see it confirmed, not wait a
            # day: clearing the check time hands the SPN to the next DC report.
            with DB_LOCK:
                if p.get("all") is True:
                    cur = self.server.conn.execute(
                        "UPDATE spn_checks SET checked_at = NULL, requested_at = NULL "
                        "WHERE status IS NOT NULL AND status != 'ok'")
                else:
                    spn = norm_spn(str(p.get("spn") or "")[:400])
                    cur = self.server.conn.execute(
                        "UPDATE spn_checks SET checked_at = NULL, requested_at = NULL "
                        "WHERE spn = ?", (spn,))
                self.server.conn.commit()
            self._send(200, {"ok": True, "queued": cur.rowcount})
            return
        if u.path not in ("/ingest", "/status", "/spn"):
            self._send(404, {"error": "not found"})
            return
        # Without an API key these endpoints are open by design - but only to
        # agents and scripts, never to a web page an admin happens to visit.
        if self._cross_site() or not self._json_body():
            self._send(415 if not self._json_body() else 403,
                       {"error": "send JSON with Content-Type: application/json"})
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
            answer = {"ok": ok}
            # A DC agent that can look SPNs up gets the next ones to check.
            if payload.get("is_dc") is True and \
                    version_tuple(payload.get("agent_version")) >= SPN_MIN_AGENT:
                with DB_LOCK:
                    answer["spn_check"] = spn_due(self.server.conn)
                    self.server.conn.commit()
            self._send(200, answer)
            return
        if u.path == "/spn":
            try:
                with DB_LOCK:
                    n = spn_store(self.server.conn, source, payload)
                    self.server.conn.commit()
            except (TypeError, ValueError) as exc:
                self._send(400, {"error": f"bad spn shape: {exc}"})
                return
            self._send(200, {"stored": n})
            return
        events = payload.get("events") or []
        if isinstance(events, dict):      # single-event push -> wrap in a list
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
        # 4624s that arrived before this machine's first status report (role
        # unknown then) are filed once it says it is not a DC.
        if not p.get("is_dc"):
            with DB_LOCK:
                self.server.conn.execute("UPDATE events SET kind = 'incoming' WHERE source = ? "
                                         "AND event_id = 4624 AND kind = 'auth'", (source,))
                self.server.conn.commit()

        def g(key):
            """Status fields are display strings; a nested value from a broken
            client must not raise InterfaceError inside the UPSERT."""
            v = p.get(key)
            if v is None or isinstance(v, (int, float, str)):
                return v
            if isinstance(v, bool):
                return int(v)
            return str(v)[:200]

        aud = lambda v: LEGACY_AUDIT.get(v, v)   # older agents send "aus"/"an"
        with DB_LOCK:
            self.server.conn.execute(
                "INSERT INTO agents (source,is_dc,agent_version,outgoing_audit,"
                "incoming_audit,domain_audit,lm_level,block_v1sso,cred_guard,ntlm_log_kb,"
                "os_version,restrict_out,restrict_in,restrict_dom,exc_client,exc_dc,"
                "domain_level,forest_level,last_seen,first_seen,logon_audit) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(source) DO UPDATE SET is_dc=excluded.is_dc, "
                "agent_version=excluded.agent_version, outgoing_audit=excluded.outgoing_audit, "
                "incoming_audit=excluded.incoming_audit, domain_audit=excluded.domain_audit, "
                "lm_level=excluded.lm_level, block_v1sso=excluded.block_v1sso, "
                "cred_guard=excluded.cred_guard, ntlm_log_kb=excluded.ntlm_log_kb, "
                "os_version=excluded.os_version, restrict_out=excluded.restrict_out, "
                "restrict_in=excluded.restrict_in, restrict_dom=excluded.restrict_dom, "
                "exc_client=excluded.exc_client, exc_dc=excluded.exc_dc, "
                "domain_level=excluded.domain_level, forest_level=excluded.forest_level, "
                "last_seen=excluded.last_seen, logon_audit=excluded.logon_audit, "
                "first_seen=COALESCE(agents.first_seen, excluded.first_seen)",
                (source, 1 if p.get("is_dc") else 0, g("agent_version"),
                 aud(g("outgoing_audit")), aud(g("incoming_audit")),
                 aud(g("domain_audit")), g("lm_level"), g("block_v1sso"),
                 g("cred_guard"), g("ntlm_log_kb"),
                 g("os_version"), g("restrict_out"), g("restrict_in"),
                 g("restrict_dom"), g("exc_client"), g("exc_dc"),
                 g("domain_level"), g("forest_level"), now,
                 utc_now().strftime("%Y-%m-%dT%H:%M:%S"), g("logon_audit")))
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
        dcv = []
        fails = []
        for e in events:
            if not isinstance(e, dict):
                continue                     # skip garbage entries, keep the rest
            e = {k: scalar(v) for k, v in e.items()}
            # 4776 from a DC is reference data for settling unconfirmed 8001s,
            # not an event: it goes to its own table and is never counted.
            if e.get("event_id") in (4776, "4776"):
                if e.get("event_time") and e.get("user"):
                    ws = (e.get("workstation") or "").strip().lstrip("\\").upper() or None
                    dcv.append((source, e.get("record_id"), e.get("event_time"),
                                user_key(e.get("user")), ws, norm_status(e.get("failure_code")), now))
                continue
            # A failed NTLM logon: its own table, never counted as NTLM in use.
            if e.get("event_id") in (4625, "4625"):
                if e.get("event_time") and e.get("user"):
                    ws = (e.get("workstation") or "").strip().lstrip("\\").upper() or None
                    fails.append((source, e.get("record_id"), e.get("event_time"), e.get("user"),
                                  user_key(e.get("user")), e.get("domain"), ws, e.get("ip"),
                                  e.get("logon_type"), normalize_process(e.get("process")),
                                  norm_status(e.get("failure_code")), e.get("ntlm_version"), now))
                continue
            # Anonymous logons (null sessions) carry no credential; Windows still
            # labels them "NTLM V1". Kept, but without that version.
            if str(e.get("user") or "").strip().upper() == "ANONYMOUS LOGON":
                e["ntlm_version"] = None
            # 4022/4023 are written on the server being accessed, not on the DC:
            # they belong with 8002/8003 as incoming NTLM. Agents up to 2.1.1
            # sent them as "domain", which put member-server logons into the
            # domain-controller panel and counted a domain logon twice there
            # (once from the server's 4022, once from the DC's 8004/4032).
            # Normalised here so already-deployed agents are right immediately.
            if e.get("event_id") in (4022, 4023, "4022", "4023"):
                e["kind"] = "incoming"
            if e.get("reason_id") not in (None, ""):
                e["reason_id"] = str(canonical_reason_id(e.get("reason"), e.get("reason_id")))
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
        if not rows and not dcv and not fails:
            return 0
        cols = "source," + ",".join(FIELDS) + ",received_at"
        placeholders = ",".join(["?"] * (len(FIELDS) + 2))
        sql = f"INSERT OR IGNORE INTO events ({cols}) VALUES ({placeholders})"
        with DB_LOCK:
            n = 0
            if rows:
                # A member server's 4624 is an incoming NTLM logon on that
                # server; on a DC it keeps its old meaning. Agents report their
                # status before their events, so the role is known here.
                dc = self.server.conn.execute("SELECT is_dc FROM agents WHERE source = ?", (source,)).fetchone()
                if dc is not None and not dc[0]:
                    rows = [r[:4] + ("incoming",) + r[5:] if str(r[3]) == "4624" else r for r in rows]
                n += self.server.conn.executemany(sql, rows).rowcount
                enrich_versions(self.server.conn, source, now)
            if dcv:
                n += self.server.conn.executemany(
                    "INSERT OR IGNORE INTO dc_validations (dc, record_id, event_time, "
                    "user_key, workstation, status, received_at) VALUES (?,?,?,?,?,?,?)",
                    dcv).rowcount
            if fails:
                n += self.server.conn.executemany(
                    "INSERT OR IGNORE INTO ntlm_failures (source, record_id, event_time, user, user_key, "
                    "domain, workstation, ip, logon_type, process, status, ntlm_version, received_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", fails).rowcount
            self.server.conn.commit()
            return n

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
                  "30d": timedelta(days=30), "90d": timedelta(days=90)}
        cutoff = None
        if rng in deltas:
            cutoff = (utc_now() - deltas[rng]).strftime("%Y-%m-%dT%H:%M:%S")

        # Unconfirmed 8001 are either the whole list (explicit filter) or not in
        # it at all - never mixed in, or a drill-down would list more rows than
        # the panel row it came from counts.
        where, params = [NOT_SUPERSEDED], []
        where.append(UNCONFIRMED if one("unconf") == "1" else "NOT " + UNCONFIRMED)
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
        """Filtered event list as CSV (Excel-friendly: BOM + semicolon)."""
        one, _rng, _cutoff, where, params = self._event_filters(qs)
        limit = int_param(one("limit"), 50000, 1, 200000)
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
            # guard against formula injection in spreadsheets
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
        body = "\ufeff" + buf.getvalue()   # BOM -> Excel recognises UTF-8
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition",
                         'attachment; filename="ntlm-events.csv"')
        self.send_header("Content-Length", str(len(data)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def _report(self, qs):
        """The printable status report (see render_report)."""
        def one(name, default=None):
            v = qs.get(name, [default])
            return v[0] if v else default
        rng = one("range", "30d")
        rng = rng if rng in REPORT_RANGES else "30d"
        lang = "en" if one("lang") == "en" else "de"
        try:
            tzoff = max(-840, min(840, int(one("tzoff") or 0)))
        except (TypeError, ValueError):
            tzoff = 0
        data = self._query_data({"range": [rng], "tzoff": [str(tzoff)], "limit": ["1"]})
        days = REPORT_RANGES[rng]
        now = utc_now()
        cur_start = now - timedelta(days=days)
        with DB_LOCK:
            c = self.server.conn
            cur = period_counts(c, cur_start, now)
            prev = period_counts(c, cur_start - timedelta(days=days), cur_start)
            first = c.execute("SELECT MIN(event_time) FROM events").fetchone()[0]
            # The previous period only compares if the data reaches back that far.
            if not first or first[:19] > (cur_start - timedelta(days=days)).strftime(_TS):
                prev = {"v1": None, "v2": None, "ntlm": None, "krb": None, "share": None}
            weekly = compute_weekly(c, 26 if days > 30 else 12, tzoff)
            done_total = c.execute("SELECT COUNT(*) FROM item_status WHERE status = 'done'").fetchone()[0]
            done_period = c.execute("SELECT COUNT(*) FROM item_status WHERE status = 'done' AND updated_at >= ?",
                                    (cur_start.strftime(_TS),)).fetchone()[0]
        m = re.search(r'class="mark" alt="" width="28" height="28" src="(data:image/png;base64,[A-Za-z0-9+/=]+)"', DASHBOARD_HTML)
        return render_report({"lang": lang, "range": rng, "tzoff": tzoff, "static": one("static") == "1",
                              "data": data, "cur": cur, "prev": prev, "weekly": weekly,
                              "first_event": first, "done_total": done_total, "done_period": done_period,
                              "logo": m.group(1) if m else ""})

    def _query_account(self, qs):
        """Everything about one account for the detail drawer: where it uses
        NTLM from, with which programs, to which servers, in which version, how
        often it failed, and whether it already gets Kerberos tickets."""
        one = lambda k, d="": (qs.get(k) or [d])[0]
        key = user_key(str(one("name"))[:256]) or ""
        rng = one("range", "30d")
        try:
            tzoff = max(-840, min(840, int(one("tzoff") or 0)))
        except (TypeError, ValueError):
            tzoff = 0
        tzmod = f"{tzoff:+d} minutes"
        deltas = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
        now = utc_now()
        cutoff = (now - deltas[rng]).strftime(_TS) if rng in deltas else None
        cut, cp = ("event_time >= ?", [cutoff]) if cutoff else ("1=1", [])
        hourly = rng == "24h"
        blen = 13 if hourly else 10
        mine = f"{_UKEY} = ?"
        with DB_LOCK:
            c = self.server.conn
            c.execute("CREATE TEMP TABLE IF NOT EXISTS x_acct (id INTEGER PRIMARY KEY)")
            c.execute("DELETE FROM temp.x_acct")
            c.execute(f"INSERT INTO x_acct (id) SELECT id FROM events WHERE {_TWIN_IDS} AND {mine} "
                      f"AND {cut} AND (NOT ({NOT_SUPERSEDED}) OR {UNCONFIRMED})", [key] + cp)
            use = f"kind IN {NTLM_USE_KINDS} AND {mine} AND {cut} AND id NOT IN (SELECT id FROM temp.x_acct)"
            first, last = c.execute(f"SELECT MIN(event_time), MAX(event_time) FROM events WHERE {use}",
                                    [key] + cp).fetchone()
            ru = acct_rollup(c.execute(_ACCT_COLS.format(k=_UKEY) + f"WHERE {use} GROUP BY 1, 2, 3, 4, 5",
                                       [key] + cp)).get(key, {})
            n, v1, v2 = ru.get("n", 0), ru.get("v1", 0), ru.get("v2", 0)
            krb = c.execute(f"SELECT COUNT(*) FROM events WHERE kind = 'kerberos' AND {mine} AND {cut}",
                            [key] + cp).fetchone()[0]
            fails_local = c.execute("SELECT COUNT(*) FROM ntlm_failures WHERE user_key = ? "
                                    + ("AND event_time >= ?" if cutoff else ""), [key] + cp).fetchone()[0]
            known = n or krb or fails_local or c.execute(
                "SELECT 1 FROM dc_validations WHERE user_key = ? LIMIT 1", (key,)).fetchone()
            if not key or not known:
                return {"name": account_label(key), "key": key, "unknown": True}
            # Where it comes from: the sending machine for outgoing, the client
            # for incoming and the DC view. Each counts with its best side.
            frm = {}
            for m, kind, cnt in c.execute(
                    "SELECT UPPER(CASE WHEN kind = 'outgoing' THEN source ELSE workstation END), kind, COUNT(*) "
                    f"FROM events WHERE {use} GROUP BY 1, 2", [key] + cp):
                if not m:
                    continue
                side = {"outgoing": "agent", "domain": "dc"}.get(kind, "server")
                e = frm.setdefault(m, {"agent": 0, "server": 0, "dc": 0})
                e[side] += cnt
            from_rows = sorted(([m, max(v.values()), max(v, key=v.get)] for m, v in frm.items()),
                               key=lambda x: -x[1])
            # One logon to a server can be seen three times - the client's 8001,
            # the server's 8003, the DC's 8004 - so per server the side that saw
            # most counts, not the sum of all three.
            to = {}
            for kind, src_, tgt, cnt in c.execute(
                    f"SELECT kind, source, target_server, COUNT(*) FROM events WHERE {use} "
                    "GROUP BY kind, source, target_server", [key] + cp):
                h = (src_ or "").upper()[:15] if kind in ("incoming", "auth") else host_key(tgt)
                if h:
                    side = {"outgoing": "agent", "domain": "dc"}.get(kind, "server")
                    e = to.setdefault(h, {"agent": 0, "server": 0, "dc": 0})
                    e[side] += cnt
            to_rows = sorted(([h, max(v.values())] for h, v in to.items()), key=lambda x: -x[1])
            progs = [[p or "", t or "", (m or "").upper(), k, a or 0] for p, t, m, k, a in c.execute(
                "SELECT process, target_server, source, COUNT(*), "
                "SUM(CASE WHEN ntlm_version = 'NTLMv1' THEN 1 ELSE 0 END) FROM events "
                f"WHERE kind = 'outgoing' AND {use} GROUP BY process, target_server, source "
                "ORDER BY COUNT(*) DESC LIMIT 8", [key] + cp)]
            series = dict(c.execute(
                f"SELECT substr(datetime(event_time, ?), 1, {blen}), COUNT(*) FROM events WHERE {use} GROUP BY 1",
                [tzmod, key] + cp).fetchall())
            fl = compute_failures(c, cutoff, None)["rows_all"]
        fl = [f for f in fl if f["key"] == key]
        local_now = now + timedelta(minutes=tzoff)
        if hourly:
            buckets = [(local_now - timedelta(hours=23 - i)).strftime("%Y-%m-%d %H") for i in range(24)]
        else:
            start = _ts(cutoff) if cutoff else (_ts(first) or now)
            days = max(1, min(400, (now - start).days + 1))
            buckets = [(local_now - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d") for i in range(days)]
        return {"name": account_label(key), "key": key, "range": rng, "first": first, "last": last,
                "n": n or 0, "v1": v1 or 0, "v2": v2 or 0, "krb": krb,
                "machine_account": key.endswith("$"), "anonymous": key == "ANONYMOUS LOGON",
                "from": from_rows[:8], "from_total": len(from_rows), "to": to_rows[:8], "to_total": len(to_rows),
                "programs": progs, "failed": {"n": sum(f["n"] for f in fl), "rows": fl[:10]},
                "series": {"b": buckets, "n": [series.get(b, 0) for b in buckets]}}

    def _query_machine(self, qs):
        """Everything about one machine for the detail drawer.

        Outgoing is what the machine itself sent (duplicates and unconfirmed
        8001s left out, as everywhere). Incoming is gathered from three sides -
        the machine's own incoming events, the DCs' domain view, and other
        machines' outgoing events naming it - and one logon can show up in all
        three. So each (account, source machine) pair counts with the highest
        of its three numbers, never their sum, and says which side saw it.
        """
        one = lambda k, d="": (qs.get(k) or [d])[0]
        name = str(one("name"))[:64]
        rng = one("range", "30d")
        try:
            tzoff = int(one("tzoff") or 0)
        except (TypeError, ValueError):
            tzoff = 0
        tzoff = max(-840, min(840, tzoff))
        tzmod = f"{tzoff:+d} minutes"
        deltas = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
        now = utc_now()
        cutoff = (now - deltas[rng]).strftime(_TS) if rng in deltas else None
        cut, cp = ("event_time >= ?", [cutoff]) if cutoff else ("1=1", [])
        key = name.upper()[:15]
        hourly = rng == "24h"
        blen = 13 if hourly else 10
        with DB_LOCK:
            c = self.server.conn
            known = c.execute("SELECT 1 FROM agents WHERE source = ? UNION SELECT 1 FROM events "
                              "WHERE source = ? LIMIT 1", (name, name)).fetchone()
            if not name or not known:
                return {"name": name, "unknown": True}
            c.execute("CREATE TEMP TABLE IF NOT EXISTS x_mach (id INTEGER PRIMARY KEY)")
            c.execute("DELETE FROM temp.x_mach")
            c.execute(f"INSERT INTO x_mach (id) SELECT id FROM events WHERE source = ? AND {_TWIN_IDS} "
                      f"AND {cut} AND (NOT ({NOT_SUPERSEDED}) OR {UNCONFIRMED})", [name] + cp)
            counted = "id NOT IN (SELECT id FROM temp.x_mach)"
            o = c.execute(
                "SELECT COUNT(*), SUM(CASE WHEN ntlm_version='NTLMv1' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN ntlm_version='NTLMv2' THEN 1 ELSE 0 END) FROM events "
                f"WHERE source = ? AND kind = 'outgoing' AND {cut} AND {counted}", [name] + cp).fetchone()
            top = [[p or "", t or "", n, v1 or 0] for p, t, n, v1 in c.execute(
                "SELECT process, target_server, COUNT(*), SUM(CASE WHEN ntlm_version='NTLMv1' THEN 1 ELSE 0 END) "
                f"FROM events WHERE source = ? AND kind = 'outgoing' AND {cut} AND {counted} "
                "GROUP BY process, target_server ORDER BY COUNT(*) DESC LIMIT 8", [name] + cp)]
            users = [[u or "", n] for u, n in c.execute(
                f"SELECT user, COUNT(*) FROM events WHERE source = ? AND kind = 'outgoing' AND {cut} AND {counted} "
                "GROUP BY user ORDER BY COUNT(*) DESC LIMIT 6", [name] + cp)]
            pairs = {}
            def add(user, frm, n, via):
                k = ((user or "").lower(), (frm or "").upper())
                e = pairs.setdefault(k, {"user": user or "", "from": (frm or "").upper(), "local": 0, "dc": 0, "cli": 0})
                e[via] += n
            n_local = 0
            for user, ws, n in c.execute(
                    f"SELECT user, workstation, COUNT(*) FROM events WHERE source = ? AND kind = 'incoming' AND {cut} "
                    f"AND {counted} GROUP BY user, workstation", [name] + cp):
                add(user, ws, n, "local"); n_local += n
            like = [f"%{name}%"]
            for tgt, user, ws, n in c.execute(
                    "SELECT target_server, user, workstation, COUNT(*) FROM events WHERE kind = 'domain' "
                    f"AND target_server LIKE ? AND {cut} GROUP BY target_server, user, workstation", like + cp):
                if host_key(tgt) == key:
                    add(user, ws, n, "dc")
            # The machine's own outgoing NTLM to itself counts too: denying
            # incoming NTLM there would break that as well (the readiness
            # verdict counts it the same way, so both numbers agree).
            for src, tgt, user, n in c.execute(
                    "SELECT source, target_server, user, COUNT(*) FROM events WHERE kind = 'outgoing' "
                    f"AND target_server LIKE ? AND {cut} GROUP BY source, target_server, user",
                    like + cp):
                if host_key(tgt) == key:
                    add(user, src, n, "cli")
            inc = []
            for e in pairs.values():
                via = max(("local", "dc", "cli"), key=lambda v: e[v])
                inc.append([e["user"], e["from"], e[via], via])
            inc.sort(key=lambda x: -x[2])
            series_out = dict(c.execute(
                f"SELECT substr(datetime(event_time, ?), 1, {blen}), COUNT(*) FROM events "
                f"WHERE source = ? AND kind = 'outgoing' AND {cut} AND {counted} GROUP BY 1",
                [tzmod, name] + cp).fetchall())
            series_in = dict(c.execute(
                f"SELECT substr(datetime(event_time, ?), 1, {blen}), COUNT(*) FROM events "
                f"WHERE source = ? AND kind = 'incoming' AND {cut} AND {counted} GROUP BY 1",
                [tzmod, name] + cp).fetchall())
            first, last = c.execute("SELECT MIN(event_time), MAX(event_time) FROM events WHERE source = ?",
                                    (name,)).fetchone()
        # A continuous axis, empty buckets included, so a quiet week looks quiet.
        local_now = now + timedelta(minutes=tzoff)
        if hourly:
            buckets = [(local_now - timedelta(hours=23 - i)).strftime("%Y-%m-%d %H") for i in range(24)]
        else:
            start = _ts(cutoff) if cutoff else (_ts(first) or now)
            days = max(1, min(400, (now - start).days + 1))
            buckets = [(local_now - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d") for i in range(days)]
        return {"name": name, "range": rng, "first": first, "last": last,
                "out": {"n": o[0] or 0, "v1": o[1] or 0, "v2": o[2] or 0, "top": top, "users": users},
                "inc": {"local": n_local, "who": len(inc), "pairs": inc[:8]},
                "series": {"b": buckets, "out": [series_out.get(b, 0) for b in buckets],
                           "inc": [series_in.get(b, 0) for b in buckets]}}

    def _query_data(self, qs):
        one, rng, cutoff, where, params = self._event_filters(qs)
        limit = int_param(one("limit"), 300, 1, 2000)
        # tf/tp are the shared filter of ALL aggregates. Besides the time range
        # the machine selection applies here too - so it filters globally, not
        # only the event list. The clause stays a fixed string; user input only
        # ever goes in as parameters.
        # Browser UTC offset in minutes (east positive). Everything is stored in
        # UTC; the day/hour buckets below have to be shifted into the viewer's
        # local time, otherwise "peak on Sunday at 03:00" names the wrong hour.
        try:
            tzoff = int(one("tzoff") or 0)
        except (TypeError, ValueError):
            tzoff = 0
        tzoff = max(-840, min(840, tzoff))          # -14h .. +14h
        tzmod = f"{tzoff:+d} minutes"               # built from an int, never from input

        base_parts, tp = [], []
        if cutoff:
            base_parts.append("event_time >= ?"); tp.append(cutoff)
        src = one("source")
        if src:
            base_parts.append("source = ?"); tp.append(src)
        # 8001 classification is evaluated ONCE per request into temp.x_cls
        # (1 = duplicate of a 4020, 2 = unconfirmed, 3 = phantom settled by the
        # DCs), and every query below only looks it up. Written inline into the
        # shared filter, the correlated subqueries ran again in each of ~30
        # queries: 6 s for a month of a busy domain before the DC check, 9 s
        # with it. Once, it is a fraction of that.
        base_where = " AND ".join(base_parts) if base_parts else "1=1"
        cls_sql = (
            "INSERT INTO x_cls (id, cls) SELECT id, CASE "
            f"WHEN NOT ({NOT_SUPERSEDED}) THEN 1 "
            f"WHEN {JUDGEABLE} AND {DC_COVERED} AND NOT {DCV_USER} THEN 3 "
            "ELSE 2 END FROM events "
            f"WHERE {_TWIN_IDS} AND {base_where} "
            f"AND (NOT ({NOT_SUPERSEDED}) OR {UNCONFIRMED})")
        # Every aggregate leaves out both duplicate and unconfirmed 8001s.
        tf = " AND ".join(["id NOT IN (SELECT id FROM temp.x_cls)"] + base_parts)
        # Same range and machine, only the unconfirmed ones / only the phantoms -
        # for the hint above the event list.
        tf_unconf = " AND ".join(["id IN (SELECT id FROM temp.x_cls WHERE cls >= 2)"] + base_parts)
        tf_phantom = " AND ".join(["id IN (SELECT id FROM temp.x_cls WHERE cls = 3)"] + base_parts)
        # The event list filter (shared with the CSV export, where it stays in its
        # expanded form) uses the same lookup here.
        lookup = {NOT_SUPERSEDED: "id NOT IN (SELECT id FROM temp.x_cls WHERE cls = 1)",
                  UNCONFIRMED: "id IN (SELECT id FROM temp.x_cls WHERE cls >= 2)",
                  "NOT " + UNCONFIRMED: "id NOT IN (SELECT id FROM temp.x_cls WHERE cls >= 2)"}
        where = [lookup.get(w, w) for w in where]
        clause = (" WHERE " + " AND ".join(where)) if where else ""

        with DB_LOCK:
            c = self.server.conn
            c.execute("CREATE TEMP TABLE IF NOT EXISTS x_cls (id INTEGER PRIMARY KEY, cls INTEGER)")
            c.execute("DELETE FROM temp.x_cls")
            c.execute(cls_sql, tp)
            # Work status (open/in progress/done) for blocker and domain rows
            st_map = {r[0]: (r[1], r[2]) for r in
                      c.execute("SELECT key, status, updated_at FROM item_status").fetchall()}
            def with_status(prefix, a, b, row):
                key = f"{prefix}|{a}|{b}"
                st, st_at = st_map.get(key, ("open", None))
                row.update(key=key, st=st, st_at=st_at)
                return row
            stats = {
                "total":  c.execute(f"SELECT COUNT(*) FROM events WHERE {tf}", tp).fetchone()[0],
                "v1":     c.execute(f"SELECT COUNT(*) FROM events WHERE ntlm_version='NTLMv1' AND {tf}", tp).fetchone()[0],
                "v2":     c.execute(f"SELECT COUNT(*) FROM events WHERE ntlm_version='NTLMv2' AND {tf}", tp).fetchone()[0],
                "outbound": c.execute(f"SELECT COUNT(*) FROM events WHERE event_id IN (8001,4001,4020,4021,4013) AND {tf}", tp).fetchone()[0],
                "unconfirmed": c.execute(f"SELECT COUNT(*) FROM events WHERE {tf_unconf}", tp).fetchone()[0],
                "phantom": c.execute(f"SELECT COUNT(*) FROM events WHERE {tf_phantom}", tp).fetchone()[0],
                # Which DCs the phantom verdict was checked against - shown with it.
                "dcs": [r[0] for r in c.execute(
                    "SELECT source FROM agents WHERE is_dc = 1 ORDER BY source").fetchall()],
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
                f"GROUP BY user ORDER BY COUNT(*) DESC LIMIT {PANEL_LIMIT}", tp).fetchall()]
            # Shutdown blockers: outgoing NTLM (8001) - breaks once the outgoing policy denies
            blockers = [with_status("proc", r[0], r[1],
                             dict(process=r[0], target=r[1], n=r[2], blocked=r[3],
                             users=r[4], sources=r[5], last_seen=r[6], who=r[7])) for r in c.execute(
                f"SELECT COALESCE(process,'(unknown)'), COALESCE(target_server,'(unknown)'), "
                f"COUNT(*), SUM(CASE WHEN event_id IN (4001,4002,4003,4004,4005,4006,4013) THEN 1 ELSE 0 END), COUNT(DISTINCT user), COUNT(DISTINCT source), MAX(event_time), "
                f"GROUP_CONCAT(DISTINCT user) "
                f"FROM events WHERE event_id IN (8001,4001,4020,4021,4013) AND {tf} "
                f"GROUP BY process, target_server ORDER BY COUNT(*) DESC LIMIT {PANEL_LIMIT}", tp).fetchall()]
            # "Why NTLM?" - grouped by the Usage ID of the enhanced 40xx events.
            # This is the actual worklist: each cause has its own remediation,
            # so the same program can appear under two different reasons.
            reasons = [dict(rid=r[0],
                            text=REASON_IDS.get(r[0], ("Unknown reason", "unclear"))[0],
                            cat=REASON_IDS.get(r[0], ("", "unclear"))[1],
                            n=r[1], procs=r[2], machines=r[3], last_seen=r[4],
                            sample=r[5]) for r in c.execute(
                f"SELECT reason_id, COUNT(*), COUNT(DISTINCT process), "
                f"COUNT(DISTINCT source), MAX(event_time), "
                f"MAX(COALESCE(target_server,'')) "
                f"FROM events WHERE reason_id IS NOT NULL AND reason_id != '' AND {tf} "
                f"GROUP BY reason_id ORDER BY COUNT(*) DESC", tp).fetchall()]
            # Second source: failed Kerberos requests (4769). On systems
            # without the 40xx events the only early warning - 0x7 (SPN
            # missing) is the classic harbinger of a fallback. Same table,
            # same remedy column; rid gets a "k" prefix so the i18n keys do
            # not collide with the usage IDs.
            reasons += [dict(rid="k" + r[0],
                             text=KRB_FAIL.get(r[0], ("Kerberos failure " + r[0], "unclear"))[0],
                             cat=KRB_FAIL.get(r[0], ("", "unclear"))[1],
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

            # Incoming NTLM (8002/8003, and 4022/4023 on Server 2025): which local service accepts NTLM, and
            # which remote accounts come in. 8002 carries the calling process,
            # 8003 the remote account - grouped per machine + process.
            incoming = [with_status("inc", r[0], r[1],
                          dict(machine=r[0], process=r[1], n=r[2], blocked=r[3],
                               users=r[4], sources=r[5], last_seen=r[6])) for r in c.execute(
                f"SELECT source, COALESCE(process,'(unknown)'), COUNT(*), "
                f"SUM(CASE WHEN event_id IN (4002,4003) THEN 1 ELSE 0 END), "
                f"COUNT(DISTINCT user), COUNT(DISTINCT workstation), MAX(event_time) "
                f"FROM events WHERE kind='incoming' AND {tf} "
                f"GROUP BY source, process ORDER BY COUNT(*) DESC LIMIT {PANEL_LIMIT}", tp).fetchall()]
            # NTLMv1 SSO (4024/4025): its own blocker with a hard October 2026 deadline
            v1sso = [with_status("v1sso", r[0], r[1],
                          dict(user=r[0], target=r[1], n=r[2], sources=r[3],
                               last_seen=r[4], blocked=bool(r[5]))) for r in c.execute(
                f"SELECT COALESCE(user,'(unknown)'), COALESCE(target_server,'(unknown)'), "
                f"COUNT(*), COUNT(DISTINCT source), MAX(event_time), "
                f"MAX(CASE WHEN event_id=4025 THEN 1 ELSE 0 END) "
                f"FROM events WHERE kind='ntlmv1sso' AND {tf} "
                f"GROUP BY user, target_server ORDER BY COUNT(*) DESC LIMIT {PANEL_LIMIT}", tp).fetchall()]
            # NTLM inside the domain (8004 and 4030-4033, from the DC only): most reliable
            # source->target view. 4022/4023 are deliberately not here - see ingest.
            domain = [with_status("dom", r[0], r[1],
                           dict(workstation=r[0], target=r[1], users=r[2],
                           n=r[3], blocked=r[4], last_seen=r[5], who=r[6])) for r in c.execute(
                f"SELECT COALESCE(workstation,'(unknown)'), COALESCE(target_server,'(unknown)'), "
                f"COUNT(DISTINCT user), COUNT(*), "
                f"SUM(CASE WHEN event_id IN (4004,4005,4006) THEN 1 ELSE 0 END), "
                f"MAX(event_time), GROUP_CONCAT(DISTINCT user) "
                f"FROM events WHERE event_id IN (8004,8005,8006,4004,4005,4006,4030,4031,4032,4033) AND {tf} "
                f"GROUP BY workstation, target_server ORDER BY COUNT(*) DESC LIMIT {PANEL_LIMIT}", tp).fetchall()]
            # Kerberos (informational): which services/SPNs already use Kerberos
            kerberos = [dict(service=r[0], accounts=r[1], n=r[2],
                             enc=r[3], last_seen=r[4]) for r in c.execute(
                f"SELECT COALESCE(target_server,'(unknown)'), COUNT(DISTINCT user), COUNT(*), "
                f"       GROUP_CONCAT(DISTINCT enc_type), MAX(event_time) "
                f"FROM events WHERE kind='kerberos' AND {tf} "
                f"GROUP BY target_server ORDER BY COUNT(*) DESC LIMIT {PANEL_LIMIT}", tp).fetchall()]
            # Kerberos by account: the "safe side" - which accounts already use Kerberos
            kerberos_accounts = [dict(account=r[0], services=r[1], svc_count=r[2], n=r[3],
                                      enc=r[4], last_seen=r[5]) for r in c.execute(
                f"SELECT COALESCE(user,'(unknown)'), GROUP_CONCAT(DISTINCT target_server), "
                f"       COUNT(DISTINCT target_server), COUNT(*), "
                f"       GROUP_CONCAT(DISTINCT enc_type), MAX(event_time) "
                f"FROM events WHERE kind='kerberos' AND user IS NOT NULL AND user<>'' AND {tf} "
                f"GROUP BY user ORDER BY COUNT(*) DESC LIMIT {PANEL_LIMIT}", tp).fetchall()]
            srcs = [r[0] for r in c.execute(
                "SELECT DISTINCT source FROM events ORDER BY source").fetchall()]
            # Machines: heartbeat (last_seen) + audit status + event count per source
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
                           dcval=r[22] or 0, dcval_last=r[23], logon_audit=r[24],
                           cg=cg_by_src.get(r[0], 0)) for r in c.execute(
                "SELECT a.source, a.is_dc, a.agent_version, a.outgoing_audit, a.incoming_audit, "
                "a.domain_audit, a.last_seen, "
                "(SELECT COUNT(*) FROM events e WHERE e.source=a.source), "
                "(SELECT MAX(event_time) FROM events e WHERE e.source=a.source), "
                "a.lm_level, "
                "(SELECT MIN(event_time) FROM events e WHERE e.source=a.source), "
                "a.block_v1sso, a.cred_guard, a.ntlm_log_kb, a.os_version, "
                "a.restrict_out, a.restrict_in, a.restrict_dom, a.exc_client, a.exc_dc, "
                "a.domain_level, a.forest_level, "
                # Per DC: does it deliver 4776? One DC without them blocks every
                # phantom verdict, so the machines panel has to say which one.
                "(SELECT COUNT(*) FROM dc_validations v WHERE v.dc = a.source), "
                "(SELECT MAX(event_time) FROM dc_validations v WHERE v.dc = a.source), "
                "a.logon_audit "
                "FROM agents a ORDER BY a.last_seen DESC").fetchall()]

            # Data basis: since when are there any events at all? Two weeks of
            # normal operation count as the minimum, so that weekly tasks and
            # batch jobs have run at least once.
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
            sel = ",".join(cols2)
            if one("unconf") == "1":
                # Per row: settled as phantom, or still open.
                cols2 = cols2 + ["verdict"]
                sel += ", CASE WHEN id IN (SELECT id FROM temp.x_cls WHERE cls = 3) THEN 'phantom' ELSE '' END"
            rows = c.execute(
                f"SELECT {sel} FROM events{clause} "
                f"ORDER BY event_time DESC, id DESC LIMIT ?",
                params + [limit]).fetchall()
            events = [dict(zip(cols2, r)) for r in rows]
            # The list is capped, the count must not be: without this the panel
            # reports the cap ("300") as if it were the result, which is plainly
            # wrong once a filter matches more than that.
            events_total = c.execute(
                f"SELECT COUNT(*) FROM events{clause}", params).fetchone()[0]

            failures = compute_failures(c, cutoff, src)
            accounts = compute_accounts(c, tf, tp, failures)
            failures.pop("rows_all", None)
            # Which machines would log a failed logon at all ("Audit Logon: Failure").
            failures["blind"] = c.execute(
                "SELECT COUNT(*) FROM agents WHERE logon_audit IN ('success', 'none')").fetchone()[0]
            spn = compute_spn(c, tf, tp)
            readiness = cached("ready", lambda: compute_readiness(c))
            kpi = cached(("kpi", tzoff, src or ""), lambda: compute_kpi(c, tzoff, src))
            agentless = cached(("noagent", rng), lambda: compute_agentless(c, cutoff))

        return {"readiness": readiness, "agentless": agentless, "kpi": kpi,
                "failures": failures, "accounts": accounts, "spn": spn,
                "stats": stats, "v1sso": v1sso, "incoming": incoming, "reasons": reasons, "trend": trend, "trend_bucket": ("hour" if rng == "24h" else "day"), "heat": heat, "spark": spark,
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
<script>
// Before first paint: a remembered theme choice, so the page never flashes in
// the other one. Without a choice the stylesheet follows the system setting.
try { var th = localStorage.getItem('ntlm.theme');
      if(th === 'light' || th === 'dark') document.documentElement.setAttribute('data-theme', th); } catch(e){}
</script>
<!-- Embedded rather than a separate file: the dashboard is one
     self-contained page with no external requests, and the CSP allows
     data: for images. A browser tab with the generic globe next to a
     security tool looks unfinished. Two sizes because 16 is what most
     tabs use and 32 what pinned tabs and bookmarks pick. -->
<link rel="icon" type="image/png" sizes="32x32" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAFJ0lEQVR42sWXa4hVVRiGn7X2PveZOc7o5DilYqmJl2G8IN6C6fJDsiyDDLMkCvth+qMYkoqkIsNKEsUgSSsJRElFw0itIOjijzItLbxikaOk45w5M3Mue85e6+vHPmM6zc0Y7YMNZx/W5f3e7/3Wu7ZqaGiIV1VVrROR+UAEUFzfEMATke2NjY3LVKFQ2OC67tP8D+H7/iZljMloraPFzNUN2lsAsdZ6rtZaAH2Dk7+crNvbSGNtgLcYWiuU6p4oay0i/2zj6J5z6xVAbwt0Dn2N492eRWI4ePgIhYKP1opCwae2ZixlpSVBgl0w8dPho2SyOZRShEIuk2sn4LpOD2oQaZNOYa0VEZFUKi0ja+tkwC21UnXbVIkOGiNPPbNcRER835eu5k276yEpHTJeKoZNlJG1dZJKpa9a88owxmR75EspRSIepyQRJxaLUj1kMDt27+Xz/V/jOA7GmH/NicejlCQSlCTiJOLxHvVCX9Rvrb3qiUYjrFi5hta2DEopRKTTeLlqfK+auRbBFHyfeCzGiZNnWL3ufbTWfdqkXwBYEZJlpVhrKS9PsuGDLRz65bduS9GvABxHk8lkmDF1EhNrxpLN5RArvPTq6uLm6gYwYAWtFUsWP47ntZNMlvLtgR/48ONPcBwdHFjXC4AIhFyXc+cvcM+dM5k5bQrNzS2UD0iyas0GzjacRyv1n/Sg++odWmsy2RwAL9YvwVhLOBziUlOKV95Y22u79UsXCIIxhlnTp/DwvHu52NhE5aAKdny6l31ffYPjOFf5Rr8D6HAYEWHF8mUMrhxEPt9OJBxm5dvr8X2fRCJ+TaXQnSy6D2YTAKgeMpgX6pfQnE6TLCvl0M+/smvPF1RXVVLw/T6XRHdh0X1yPGMMixbMo+6OaaSa0yQScTZu3kY25+E4DlorHC0gfvBgewFg0kjhLzCtARNiemVEa83KFfW4rks0EubYidP8eOgIZSUx0i1ZmjNRCJWDckE5XYLQFOtlL27G/P4cNv0lKB1MUJFuQXScgBPG3c6SxY/RlErjOA65XIaWjGXWtBrW1seJnF+KOfsa5E8X87WdABQ5UInJ6IoHQSkkdxya9yDeaZQKdwuiwwueXfok48aMIp/Pkc3D/Dnj2f3meebOriKcnAQI5tQj2NSuAISYKy4ktvhf+9kApXIgPAK8UyADUcpFqcCaOwtLKYW1QiIe5/UV9cxbsJhRo2tYtfgcumIR/oCFl288UvkE5tQCVHwSKjK0GxEqBTqMTe1BbB4I4bV7eF47ntdOe3uhS58wxnB33Qzm3vcAY4e1UHZzNSa5EFcKQbbWQ0WGoyvmIandRbHbIgMdJQgPQRBQIXTEQYlHSWwQ2z5ah1/IISLEYtEu20trjYjl3XdeJvXnZ5j8AbQSEFUUH0EnhIcj+ZOd7oTFEti2g5A7GgAYOB/TvB/VtJOam0ZCZCi0fgemgE09ii6/P8isuHgHqGRpjOTY2fgntgYNrdxiCwa/JXMIVTr9irYXlBjThtYJ/BRic6A0SpeAzSJYrISChWwWhUKHkqBjXR/VNgAlF99Dcsdwhq4EnQi67NIW7KXtuKN3XgZvrc0pEWkDEv33zRFQai9sRNq+B7cS/FTAIgLeHzi3bgIkAGCMadNax6y1Svf1/OxtmFhQGjFZ8M6AW44KVyOmFf/YHIiMkNDIzWKtzWOMWSvXJWy37+b4bJHsWimIrFciEvZ9/y2t9QKtdaz/P1DtFR1vAEes9XK2ed/WMxVzn/8bwdMQhJ+OrhgAAAAASUVORK5CYII=">
<link rel="icon" type="image/png" sizes="16x16" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACPElEQVR42n2TTUiUURSGn3u/zxnLn2ZM+4UkGYgWEkrYIhkKWtUu2mRaRCFtMggCFyFEghBhuIgQo1wktIkWLYsyKpKCdi2CFi2i0NEZR3N+v3tOC8fJUfMsD+997jnnPcc45x4B3YCx1hoRMWwS1loVEQUUmDAiosb8eyMiqIK1hrX5EqACaJxzeWttaKPfVLUCsjZEpOgDZUU2m2No+AGJ2SR9Vy5w8EAMBVwQMHjnPvlCnoH+PrZUV5cLwDlX0FKkUmltaY0rtfv11JlLGgSBOhHN5nIaO3Rc98Q6dD69sCJX51yxoiFjDPV1dcRamnn34RPjE8+wxiBOiEa2EY1G1rVUCbCGP0sZmvftJd7ZwcDgMNMzs4TDYYKgiHNuvSsbTA6AG9d6ScwmuTU0gufZlfT/AFKyFXzfYy6ZIn60g96LZxkbf8rLN+/Z3hBBxFVoVwFsyQwtz8I5x0D/VXbtbOLuyBgijkzeoqa+QmvBoulXEMyArcbzDL7vk88X2NHUyO2b15n6/IVv338TbwsRyrxAg/kyxAJo4ScsTiILUyTTBVLpDNbzUVXOd52mve0Ix9odE6M9hLfWIInH4FJgPXwQMD6a+0FIAy6fO0HIL+LbAEwV1sC9oX6Yewi1Xctlmyhkv0Jt5/Iqm8XXITUhjGYx9REIUmAOg9+IaoAxPmTeIkWwNa1I8jk2ehKp2l1cf0wb+KuqGASWPoJbXIa6X9DQjXHOjVq0B7BYVq2Zt9lVK0uTEmSnn/wFk2waSHeruqoAAAAASUVORK5CYII=">
<style>
:root{
  /* Tells the browser to draw native controls - select popups, scrollbars,
     focus rings - in the matching variant. */
  color-scheme:dark;
  --void:#0a0f1c;
  --card:#121a2b;
  --card2:#18233a;
  --ink:#eef2f8;
  --dim:#a3b0c6;
  --faint:#7c8aa5;
  --v1:#ff6b6b;
  --v2:#f5b841;
  --krb:#3ddc97;
  --pol:#a78bfa;
  --grey:#4a5872;
  --gold:#d9b84a;
  --gold-ink:#1b1704;
  --hi-rgb:255,255,255;
  --gold-rgb:217,184,74;
  --v1-rgb:255,107,107;
  --v2-rgb:245,184,65;
  --krb-rgb:61,220,151;
  --line-rgb:158,180,225;
  --hdr-rgb:10,15,28;
  --shade-rgb:0,0,0;
  --pol-rgb:167,139,250;
  --scrim-rgb:6,9,16;
  --tip:#1d2637;
  --tip-sel:#26314a;
  --tip-sel-ink:#ffffff;
  --v1-hi:#ffb3b3;
  --v2-hi:#ffd894;
  --krb-hi:#9ff0cb;
  --gold-hi:#ffe9a8;
  --v1-deep:#c94a4a;
  --v2-deep:#c08b2c;
  --drawer:#141c2d;
  --code:#0b1019;
  --bar-v1:#ff5a5a;
  --bar-v2:#f5b841;
  --bar-krb:#2fc98a;
  --shadow:0 1px 0 rgba(255,255,255,.035) inset, 0 16px 36px rgba(0,0,0,.32);
  --edge:rgba(var(--line-rgb),.12); --edge2:rgba(var(--line-rgb),.22);
  /* Brand accent (same muted gold as the logo and the project page), used only
     for interactive chrome - focus rings, active pills, toggle states. Never
     for data: v1/v2/krb keep meaning "insecure / outdated / safe" everywhere,
     and this must not blur into that. */
  --disp:'Segoe UI Variable Display','Segoe UI',system-ui,-apple-system,sans-serif;
  --text:'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,sans-serif;
  --mono:'Cascadia Mono','IBM Plex Mono',ui-monospace,Consolas,'SF Mono',monospace;
  /* Soft surfaces with depth instead of hairline boxes: rounder corners and a
     shadow carry the separation the borders used to. */
  --r:16px; --pad:clamp(20px,2.8vw,52px);
}
/* Light theme: follows the system unless the viewer picked one (data-theme on
   <html>, remembered per browser). Every colour above that differs is set
   again here - including the channel values, so each rgba(var(--x-rgb),a)
   in the rules below turns into the light equivalent without a second rule. */
:root[data-theme="light"]{
  color-scheme:light;
  --void:#f3f5f9;
  --card:#ffffff;
  --card2:#f6f8fb;
  --ink:#0f172a;
  --dim:#475569;
  --faint:#5b6b82;
  --v1:#c62828;
  --v2:#a15c07;
  --krb:#137a50;
  --pol:#6d28d9;
  --grey:#94a3b8;
  --gold:#8a6a12;
  --gold-ink:#fffdf5;
  --hi-rgb:15,23,42;
  --gold-rgb:168,132,30;
  --v1-rgb:220,38,38;
  --v2-rgb:217,119,6;
  --krb-rgb:5,150,105;
  --line-rgb:15,23,42;
  --hdr-rgb:255,255,255;
  --shade-rgb:15,23,42;
  --pol-rgb:124,58,237;
  --scrim-rgb:15,23,42;
  --tip:#ffffff;
  --tip-sel:#e8edf5;
  --tip-sel-ink:#0f172a;
  --v1-hi:#b91c1c;
  --v2-hi:#92400e;
  --krb-hi:#065f46;
  --gold-hi:#6b5310;
  --v1-deep:#ef4444;
  --v2-deep:#f59e0b;
  --drawer:#ffffff;
  --code:#f1f4f9;
  --bar-v1:#e04545;
  --bar-v2:#e3a21a;
  --bar-krb:#23a874;
  --shadow:0 1px 2px rgba(15,23,42,.05), 0 12px 28px rgba(15,23,42,.07);
}
@media (prefers-color-scheme: light){
  :root:not([data-theme="dark"]){
    color-scheme:light;
    --void:#f3f5f9;
    --card:#ffffff;
    --card2:#f6f8fb;
    --ink:#0f172a;
    --dim:#475569;
    --faint:#5b6b82;
    --v1:#c62828;
    --v2:#a15c07;
    --krb:#137a50;
    --pol:#6d28d9;
    --grey:#94a3b8;
    --gold:#8a6a12;
    --gold-ink:#fffdf5;
    --hi-rgb:15,23,42;
    --gold-rgb:168,132,30;
    --v1-rgb:220,38,38;
    --v2-rgb:217,119,6;
    --krb-rgb:5,150,105;
    --line-rgb:15,23,42;
    --hdr-rgb:255,255,255;
    --shade-rgb:15,23,42;
    --pol-rgb:124,58,237;
    --scrim-rgb:15,23,42;
    --tip:#ffffff;
    --tip-sel:#e8edf5;
    --tip-sel-ink:#0f172a;
    --v1-hi:#b91c1c;
    --v2-hi:#92400e;
    --krb-hi:#065f46;
    --gold-hi:#6b5310;
    --v1-deep:#ef4444;
    --v2-deep:#f59e0b;
    --drawer:#ffffff;
    --code:#f1f4f9;
    --bar-v1:#e04545;
    --bar-v2:#e3a21a;
    --bar-krb:#23a874;
    --shadow:0 1px 2px rgba(15,23,42,.05), 0 12px 28px rgba(15,23,42,.07);
  }
}

*{box-sizing:border-box}
html{scroll-behavior:smooth}
/* No overflow-x:hidden here. It was added against 4 px of sideways scroll on
   phones and silently broke position:sticky for the whole page - an ancestor
   with overflow hidden becomes the scroll container, so the header stopped
   pinning on every screen size. The overflow itself is fixed at its source now
   (scrollable tables, scrollable heatmap). */
body{margin:0;background:var(--void);color:var(--ink);font-family:var(--text);font-size:18px;
  line-height:1.5;-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(1200px 600px at 10% -8%,rgba(var(--v1-rgb),.05),transparent 62%),
             radial-gradient(1200px 700px at 90% 108%,rgba(var(--gold-rgb),.042),transparent 62%)}
.stage{position:relative;z-index:1}
::selection{background:rgba(var(--gold-rgb),.30)}
:focus-visible{outline:2px solid var(--gold);outline-offset:2px;border-radius:6px}
button{font:inherit}
a{color:inherit}

header{position:sticky;top:0;z-index:60;backdrop-filter:blur(18px) saturate(1.4);
  background:rgba(var(--hdr-rgb),.80);border-bottom:1px solid var(--edge)}
.hin{padding:0 var(--pad);height:66px;display:flex;align-items:center;gap:16px}
/* The controls scrolled sideways out of view on a phone: the language toggle
   and the CSV button were simply unreachable. Wrapping costs a second row and
   keeps everything within reach. */
.logo{display:flex;align-items:center;gap:11px;font-family:var(--disp);font-size:17px;font-weight:600;
  letter-spacing:-.02em;white-space:nowrap}
.orb{width:9px;height:9px;border-radius:50%;background:var(--krb);position:relative;flex:none}
.orb::after{content:"";position:absolute;inset:-5px;border-radius:50%;border:1px solid var(--krb);
  opacity:.35;animation:ping 3.2s cubic-bezier(.2,.7,.3,1) infinite}
.orb.stale{background:var(--v2)} .orb.stale::after{border-color:var(--v2)}
@keyframes ping{0%{transform:scale(.6);opacity:.5}70%,100%{transform:scale(1.5);opacity:0}}
.tools{display:flex;align-items:center;gap:8px;margin-left:12px;flex-wrap:wrap;justify-content:flex-end}
/* Quick search: the button in the header, and the dialog it opens (Ctrl+K) */
.searchbtn{display:inline-flex;align-items:center;gap:8px;margin-left:auto;height:36px;padding:0 8px 0 12px;border-radius:10px;
  border:1px solid var(--edge);background:var(--card);color:var(--dim);font-family:var(--mono);font-size:13px;cursor:pointer;flex:none}
.searchbtn kbd,.palin kbd{font-family:var(--mono);font-size:11px;padding:2px 6px;border-radius:5px;border:1px solid var(--edge2);color:var(--faint)}
.searchbtn:hover{border-color:var(--gold);color:var(--ink)}
.pal{position:fixed;inset:0;z-index:300;background:rgba(var(--scrim-rgb),.55);backdrop-filter:blur(4px);
  display:flex;justify-content:center;align-items:flex-start;padding:12vh 16px 16px}
.pal[hidden]{display:none}
.palbox{width:min(660px,100%);background:var(--card);border:1px solid var(--edge2);border-radius:16px;
  box-shadow:0 30px 80px rgba(var(--shade-rgb),.45);overflow:hidden;display:flex;flex-direction:column;max-height:72vh}
.palin{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--edge);color:var(--dim)}
.palin input{flex:1;min-width:0;background:none;border:0;outline:none;color:var(--ink);font:inherit;font-size:17px}
.palin input::-webkit-search-cancel-button{display:none}
#palres{list-style:none;margin:0;padding:6px;overflow-y:auto}
#palres li{display:flex;align-items:center;gap:12px;padding:9px 10px;border-radius:9px;cursor:pointer;min-height:40px}
#palres li[aria-selected="true"]{background:rgba(var(--gold-rgb),.14)}
.pty{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);min-width:92px;flex:none}
.plb{color:var(--ink);font-size:15px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.psb{margin-left:auto;color:var(--faint);font-family:var(--mono);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:45%;flex:none}
#palres mark{background:none;color:var(--gold);font-weight:650}
.palfoot{border-top:1px solid var(--edge);padding:8px 16px;font-family:var(--mono);font-size:11.5px;color:var(--faint)}
.palnone{padding:18px 16px;color:var(--dim);list-style:none}
.pill{display:flex;background:rgba(var(--hi-rgb),.035);border:1px solid var(--edge);border-radius:9px;
  padding:2px;gap:2px}
.pill button{background:none;border:0;color:var(--dim);font-family:var(--mono);font-size:12.5px;
  padding:5px 11px;border-radius:7px;cursor:pointer;transition:.18s;white-space:nowrap}
.pill button:hover{color:var(--ink)}
.pill button[aria-pressed=true]{background:rgba(var(--gold-rgb),.16);color:var(--gold);
  box-shadow:inset 0 0 0 1px rgba(var(--gold-rgb),.4)}
select,.ghost{background:rgba(var(--hi-rgb),.035);border:1px solid var(--edge);color:var(--ink);
  border-radius:9px;padding:6px 10px;font-family:var(--mono);font-size:12.5px;cursor:pointer;transition:.18s}
select:hover,.ghost:hover{border-color:var(--edge2);background:rgba(var(--hi-rgb),.06)}
select option,.sel-st option{background:var(--tip);color:var(--ink)}
select option:checked,.sel-st option:checked{background:var(--tip-sel);color:var(--tip-sel-ink)}
.ghost[aria-pressed=true]{background:rgba(var(--gold-rgb),.14);border-color:rgba(var(--gold-rgb),.4);color:var(--gold)}

.herotop{display:flex;gap:clamp(24px,4vw,70px);align-items:flex-start}
.herotext{flex:1 1 auto;min-width:0}
.osdon{flex:0 0 auto;width:330px;border:1px solid var(--edge);border-radius:var(--r);
  background:rgba(var(--hi-rgb),.02);padding:16px 18px}
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
.jump{position:sticky;top:66px;z-index:55;backdrop-filter:blur(14px);background:rgba(var(--hdr-rgb),.76);
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
/* overflow-x:clip instead of visible: the segments' percentage widths plus the
   2 px gaps add up to slightly over 100 % on a narrow screen, and the last one
   stuck 4 px past the viewport. "clip" trims that without creating a scroll
   container - so position:sticky elsewhere on the page keeps working, which
   plain "hidden" would have broken. overflow-y stays visible so the hover card
   above the bar is not cut off. */
.handbar{position:relative;overflow-x:clip;overflow-y:visible}
.seg:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.seg.on{filter:brightness(1.45)}
.handbar:hover .seg:not(:hover){filter:brightness(.72)}
.segtip{position:absolute;bottom:calc(100% + 14px);left:0;transform:translateX(-50%) translateY(4px);
  background:var(--tip);border:1px solid var(--edge2);border-radius:12px;padding:13px 16px;
  box-shadow:0 18px 40px rgba(var(--shade-rgb),.45);pointer-events:none;opacity:0;visibility:hidden;
  transition:opacity .16s,transform .16s;z-index:30;white-space:nowrap}
.segtip.on{opacity:1;visibility:visible;transform:translateX(-50%) translateY(0)}
.segtip::after{content:"";position:absolute;top:100%;left:50%;margin-left:-6px;
  border:6px solid transparent;border-top-color:var(--tip)}
.segtip .th{font-family:var(--disp);font-size:15px;font-weight:600;color:var(--ink);
  margin-bottom:9px;display:flex;align-items:center;gap:8px}
.segtip .th i{width:10px;height:10px;border-radius:3px;flex:none}
.segtip .tr{display:flex;align-items:baseline;justify-content:space-between;gap:22px;
  font-size:13px;color:var(--dim);padding:2px 0}
.segtip .tr b{font-family:var(--mono);font-size:14px;color:var(--ink);font-weight:600;
  font-variant-numeric:tabular-nums}
.segtip .tf{margin-top:9px;padding-top:8px;border-top:1px solid var(--edge);
  font-family:var(--mono);font-size:11.5px;color:var(--faint)}
.seg.s1{background:linear-gradient(180deg,rgba(var(--v1-rgb),.30),rgba(var(--v1-rgb),.16))}
.seg.s2{background:linear-gradient(180deg,rgba(var(--v2-rgb),.28),rgba(var(--v2-rgb),.14))}
.seg.s3{background:linear-gradient(180deg,rgba(var(--krb-rgb),.26),rgba(var(--krb-rgb),.13))}
.seg::after{content:"";position:absolute;left:0;top:0;bottom:0;width:2px}
.seg.s1::after{background:var(--v1)}.seg.s2::after{background:var(--v2)}.seg.s3::after{background:var(--krb)}
.seg b{font-family:var(--mono);font-size:15px;font-weight:500;white-space:nowrap;opacity:0;
  transition:opacity .5s .8s}
.seg.s1 b{color:var(--v1-hi)}.seg.s2 b{color:var(--v2-hi)}.seg.s3 b{color:var(--krb-hi)}
.seg:hover{filter:brightness(1.3)}
.handkey{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px}
.kk{display:flex;align-items:baseline;gap:9px;padding:9px 14px;border:1px solid var(--edge);
  border-radius:10px;background:rgba(var(--hi-rgb),.02);font-size:14px;color:var(--dim)}
.kk i{width:9px;height:9px;border-radius:3px;flex:none;align-self:center}
.kk b{font-family:var(--mono);font-size:17px;font-weight:600;color:var(--ink);
  font-variant-numeric:tabular-nums}
.kk em{font-family:var(--mono);font-size:13px;font-style:normal;color:var(--faint);
  font-variant-numeric:tabular-nums}
.kk.nil{opacity:.55}
.kk.nil b{color:var(--dim)}
.deadline{display:flex;align-items:center;gap:16px;margin-top:26px;padding:15px 19px;
  border:1px solid var(--edge);border-radius:var(--r);background:rgba(var(--v1-rgb),.045);max-width:700px}
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
/* Two columns only from 1400 px. At 1000 px each panel was about 480 px wide,
   which a seven-column table does not fit into - the card clipped the rest and
   220 cells were unreachable at laptop width. One wide column reads better than
   two truncated ones. */
@media(min-width:1400px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(min-width:2900px){.grid{grid-template-columns:repeat(3,1fr)}}
.c2{grid-column:span 2}.call{grid-column:1/-1}
@media(max-width:1399px){.c2{grid-column:span 1}}
@media(max-width:1399px){.c2,.call{grid-column:span 1}}
.card{border:1px solid var(--edge);border-radius:var(--r);scroll-margin-top:calc(var(--stick, 118px) + 12px);
  background:linear-gradient(180deg,rgba(var(--hi-rgb),.022),transparent 40%),var(--card);
  overflow:hidden;opacity:0;transform:translateY(16px);
  transition:opacity .6s cubic-bezier(.16,1,.3,1),transform .6s cubic-bezier(.16,1,.3,1),border-color .25s}
.card.in{opacity:1;transform:none}
.card:hover{border-color:var(--edge2)}
.ch{display:flex;align-items:center;gap:12px;padding:20px 22px 16px;flex-wrap:wrap}
/* Short explanation under a panel title - what the panel's verdict rests on. */
/* Header: brand mark, live dot after the name */
.mark{width:28px;height:28px;border-radius:7px;flex:none;display:block;box-shadow:0 0 0 1px var(--edge)}
/* Theme button: shows where it leads - the sun in dark, the moon in light */
.themebtn{display:inline-grid;place-items:center;min-width:36px;padding-left:8px;padding-right:8px}
.themebtn .i-moon{display:none}
:root[data-theme="light"] .themebtn .i-sun{display:none}
:root[data-theme="light"] .themebtn .i-moon{display:block}
@media (prefers-color-scheme: light){
  :root:not([data-theme="dark"]) .themebtn .i-sun{display:none}
  :root:not([data-theme="dark"]) .themebtn .i-moon{display:block}
}
.logo .orb{margin-left:2px}
.menu{display:none}
/* "?" in a panel header, and the answer it opens */
.hlp{margin-left:10px;flex:none;width:30px;height:30px;border-radius:50%;border:1px solid var(--edge);
  background:none;color:var(--dim);cursor:pointer;font-family:var(--mono);font-size:13px;font-weight:600}
.hlp:hover,.hlp[aria-expanded=true]{color:var(--gold);border-color:var(--gold)}
.hlp + .fold{margin-left:6px}
/* The two header buttons always sit at the right edge, whether or not the
   panel has a meta line (which carries the auto margin when it is there). */
.ch .hlp, .ch .fold{margin-left:auto}
.ch .meta + .hlp, .ch .meta + .fold{margin-left:10px}
.ch .hlp + .fold{margin-left:6px}
.cnote.help{border-left:2px solid var(--gold);margin:0 22px 14px;padding:8px 12px;background:rgba(var(--gold-rgb),.05)}
/* Machine detail in the side drawer */
.md{padding:6px 24px 30px}
.md-load,.md-none{color:var(--dim);font-size:14px;padding:6px 0}
.md-live{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13.5px;color:var(--dim)}
.md-dot{width:8px;height:8px;border-radius:50%;background:var(--krb);box-shadow:0 0 0 4px rgba(var(--krb-rgb),.15);flex:none}
.md-dot.off{background:var(--v1);box-shadow:0 0 0 4px rgba(var(--v1-rgb),.15)}
.md-sep{color:var(--faint)}
.md-sec{margin-top:22px}
.md-h{font-family:var(--mono);font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);margin:0 0 10px}
.md-kpis{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.md-k{background:var(--card2);border:1px solid var(--edge);border-radius:12px;padding:12px 14px;display:flex;flex-direction:column;gap:6px;align-items:flex-start}
.md-k span{font-size:12.5px;color:var(--dim)}
.md-k b{font-family:var(--disp);font-size:30px;font-weight:650;line-height:1;color:var(--ink);font-variant-numeric:tabular-nums}
.md-k em{font-style:normal;font-family:var(--mono);font-size:11.5px;color:var(--faint)}
.md-chart{margin-top:14px}
.md-chart svg{display:block;width:100%;height:80px}
.md-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--dim);margin-top:6px}
.md-legend i{display:inline-block;width:12px;height:3px;border-radius:2px;margin-right:6px;vertical-align:middle}
.md-axis{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--faint)}
.md-rdy{display:grid;grid-template-columns:auto 1fr;gap:10px 14px;align-items:start;font-size:13.5px}
.md-list{display:flex;flex-direction:column}
.md-row{display:flex;justify-content:space-between;align-items:baseline;gap:12px;padding:9px 0;border-top:1px solid var(--edge);
  font-size:14px;text-align:left;background:none;border-left:0;border-right:0;border-bottom:0;color:var(--ink);font-family:inherit;width:100%}
.md-list > .md-row:first-child{border-top:0}
button.md-row{cursor:pointer}
button.md-row:hover{color:var(--gold)}
.md-row .n{font-family:var(--mono);color:var(--dim);white-space:nowrap}
.md-via{font-family:var(--mono);font-size:11px;color:var(--faint);white-space:nowrap}
.md-more{font-size:12.5px;color:var(--faint);padding-top:8px}
.md-chips{display:flex;gap:8px;flex-wrap:wrap}
.md-chip{background:rgba(var(--hi-rgb),.05);border:1px solid var(--edge);border-radius:999px;padding:5px 11px;color:var(--ink);
  font-family:var(--mono);font-size:12.5px;cursor:pointer}
.md-chip b{color:var(--dim);font-weight:400;margin-left:4px}
.md-chip:hover{border-color:var(--gold)}
.md-tags{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.md-acts{display:flex;gap:8px;flex-wrap:wrap;margin-top:26px}
.v1blind{display:block;width:calc(100% - 44px);margin:0 22px 12px;padding:9px 12px;text-align:left;cursor:pointer;
  font:inherit;font-size:13.5px;line-height:1.45;color:var(--v2-hi);background:rgba(var(--v2-rgb),.10);
  border:1px solid rgba(var(--v2-rgb),.35);border-radius:10px}
.v1blind:hover{border-color:var(--v2)}
.v1blind.bad{color:var(--v1-hi);background:rgba(var(--v1-rgb),.10);border-color:rgba(var(--v1-rgb),.40);cursor:default}
.md-k3{grid-template-columns:repeat(3,minmax(0,1fr))}
.md-link{background:none;border:0;padding:0;font:inherit;color:inherit;cursor:pointer;text-decoration:underline;
  text-decoration-color:var(--edge2);text-underline-offset:3px}
.md-link:hover{color:var(--gold)}
@media(max-width:420px){.md-k3{grid-template-columns:1fr 1fr}}
/* Block headings between the panel groups */
.blk{grid-column:1/-1;padding:26px 2px 2px;scroll-margin-top:calc(var(--stick, 118px) + 4px)}
.blk h2{margin:0;font-family:var(--mono);font-size:13px;font-weight:600;letter-spacing:.16em;
  text-transform:uppercase;color:var(--gold)}
.blk p{margin:6px 0 0;color:var(--faint);font-size:14.5px}
/* Fold button: a chevron at the end of every panel header */
.fold{margin-left:10px;flex:none;width:30px;height:30px;border-radius:7px;border:1px solid var(--edge);
  background:none;color:var(--dim);cursor:pointer;display:grid;place-items:center}
.fold::before{content:"";width:7px;height:7px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;
  transform:translateY(-2px) rotate(45deg);transition:transform .18s}
.fold:hover{color:var(--ink);border-color:var(--gold)}
.card.folded .fold::before{transform:translateY(1px) rotate(-135deg)}
.card.folded > :not(.ch){display:none!important}
.card.folded .ch{padding-bottom:20px}
tr.clip,.brow.clip{display:none!important}
.showall{display:block;margin:12px 22px 18px;background:none;border:1px dashed var(--edge2);color:var(--dim);
  font-family:var(--mono);font-size:12.5px;border-radius:7px;padding:8px 14px;cursor:pointer;min-height:36px}
.showall:hover{color:var(--ink);border-color:var(--gold)}
/* Jump bar: group labels, and the section being read */
.jg{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--gold);
  opacity:.75;align-self:center;margin:0 2px 0 12px;white-space:nowrap}
.jg:first-child{margin-left:0}
.jl.on{color:var(--ink);border-color:var(--edge2);background:rgba(var(--hi-rgb),.04)}
@media(max-width:760px){.fold{width:40px;height:40px}}
.cnote{padding:0 22px 14px;color:var(--dim);font-size:13.5px;line-height:1.55;max-width:90ch}
.rdd{font-size:12.5px;color:var(--dim);margin-top:5px;line-height:1.5}
.ch h2{margin:0;font-family:var(--disp);font-size:18.5px;font-weight:580;letter-spacing:-.012em}
.ch .meta{margin-left:auto;font-family:var(--mono);font-size:14px;color:var(--faint)}
.flag{font-family:var(--mono);font-size:12.5px;letter-spacing:.09em;text-transform:uppercase;
  padding:2px 7px;border-radius:5px;border:1px solid var(--edge2);color:var(--dim)}
.flag.due{color:var(--v1);border-color:rgba(var(--v1-rgb),.35);background:rgba(var(--v1-rgb),.07)}
.flag.ok{color:var(--krb);border-color:rgba(var(--krb-rgb),.3);background:rgba(var(--krb-rgb),.06)}
.mini{background:rgba(var(--hi-rgb),.04);border:1px solid var(--edge);color:var(--dim);border-radius:7px;
  padding:3px 9px;font-family:var(--mono);font-size:12px;cursor:pointer;transition:.16s}
.mini:hover{color:var(--ink);border-color:var(--gold)}

table{width:100%;border-collapse:collapse}
.tw{overflow-x:auto}
/* Stacked rows need no scrolling - and a stray scrollbar there looks broken. */
@media(max-width:760px){.tw{overflow-x:visible}}
/* The header row used to sit at the same weight and near the same tone as the
   data, so a table read as one undifferentiated block. It is now a band: its
   own slightly lighter surface, a firm bottom edge, brighter and heavier type.
   Contrast against that band goes from 4.69:1 to 6.98:1. */
thead th{background:rgba(var(--line-rgb),.055);border-bottom:1px solid var(--edge2);
  position:relative;cursor:pointer;user-select:none}
thead th:hover{color:var(--ink)}
thead th[aria-sort=ascending]::after{content:" \2191";color:var(--gold)}
thead th[aria-sort=descending]::after{content:" \2193";color:var(--gold)}
th{font-family:var(--mono);font-size:12.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--dim);font-weight:600;text-align:left;padding:12px 22px 12px;white-space:nowrap}
/* First data row needs no line of its own - the band already draws it. */
thead + tbody tr:first-child td{border-top:0}
td{padding:14px 22px;border-top:1px solid rgba(var(--line-rgb),.11);font-size:16.5px;line-height:1.45}
tbody tr{transition:background .16s}
tbody tr:nth-child(even){background:rgba(var(--line-rgb),.028)}
tbody tr.click{cursor:pointer}
tbody tr.click:hover{background:rgba(var(--line-rgb),.06)}
tbody tr.on{background:rgba(var(--gold-rgb),.10);box-shadow:inset 3px 0 0 var(--gold)}
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
.tag.v1{color:var(--v1);border-color:rgba(var(--v1-rgb),.32);background:rgba(var(--v1-rgb),.07)}
.tag.v2{color:var(--v2);border-color:rgba(var(--v2-rgb),.32);background:rgba(var(--v2-rgb),.07)}
.tag.krb{color:var(--krb);border-color:rgba(var(--krb-rgb),.3);background:rgba(var(--krb-rgb),.06)}
.tag.pol{color:var(--pol);border-color:rgba(var(--pol-rgb),.32);background:rgba(var(--pol-rgb),.07)}
.tag.n{color:var(--faint);border-color:var(--edge2)}
.restn{color:var(--faint);font-family:var(--mono);font-size:12px;margin-left:6px}
.sel-st{background:rgba(var(--hi-rgb),.04);border:1px solid var(--edge);color:var(--dim);border-radius:7px;
  padding:3px 8px;font-family:var(--mono);font-size:13px}
.done td{opacity:.42}
.cmd{display:inline-block;font-family:var(--mono);font-size:12.5px;background:var(--code);border:1px solid var(--edge);
  border-radius:6px;padding:3px 7px;white-space:nowrap;user-select:all}
.cmdb{margin-top:6px;display:flex;gap:6px}
.cpy{background:rgba(var(--hi-rgb),.04);border:1px solid var(--edge);color:var(--dim);border-radius:7px;
  padding:2px 9px;font-family:var(--text);font-size:12px;cursor:pointer}
.cpy:hover:not(:disabled){color:var(--ink);border-color:var(--edge2)}
.cpy:disabled{cursor:default;opacity:.7}
.empty{padding:34px 20px;text-align:center;color:var(--faint);font-size:15.5px}
.empty b{display:block;color:var(--dim);font-size:15.5px;margin-bottom:5px;font-weight:500}

.bar{display:flex;align-items:center;gap:9px;flex-wrap:wrap;padding:2px 22px 14px}
.search{flex:1 1 240px;min-width:160px;background:rgba(var(--hi-rgb),.035);border:1px solid var(--edge);
  color:var(--ink);border-radius:9px;padding:7px 11px;font-family:var(--mono);font-size:13px}
.search::placeholder{color:var(--faint)}
.search:focus{outline:none;border-color:var(--edge2);background:rgba(var(--hi-rgb),.06)}
.chipset{display:flex;gap:5px;flex-wrap:wrap}
.chip{background:rgba(var(--hi-rgb),.035);border:1px solid var(--edge);color:var(--dim);border-radius:8px;
  padding:5px 11px;font-family:var(--mono);font-size:13px;cursor:pointer;transition:.16s;white-space:nowrap}
.chip:hover{color:var(--ink);border-color:var(--edge2)}
.chip[aria-pressed=true]{background:rgba(var(--hi-rgb),.09);color:var(--ink);border-color:var(--edge2)}
.active{display:flex;gap:6px;flex-wrap:wrap;padding:0 17px 11px}
.afl{display:inline-flex;align-items:center;gap:7px;background:rgba(var(--gold-rgb),.12);
  border:1px solid rgba(var(--gold-rgb),.32);color:var(--gold-hi);border-radius:8px;padding:4px 8px;
  font-family:var(--mono);font-size:12px}
.afl button{background:none;border:0;color:inherit;cursor:pointer;opacity:.7;padding:0 0 0 2px;font-size:15px}
.afl button:hover{opacity:1}
/* Unconfirmed 8001s: dashed and muted on purpose - they are shown, not
   asserted, and must not read like the solid NTLM tags next to them. */
.tag.unc{border-style:dashed;color:var(--dim);background:transparent}
.tag.unc.ph{color:var(--krb);border-color:rgba(var(--krb-rgb),.35)}
.expl.unc{border-style:dashed}
.unchint{background:none;border:1px dashed var(--edge2);color:var(--dim);font-family:var(--mono);
  font-size:12px;border-radius:7px;padding:5px 10px;cursor:pointer;margin-left:6px}
.unchint:hover{color:var(--ink);border-color:var(--gold)}
.clearall{background:none;border:0;color:var(--faint);font-family:var(--mono);font-size:12px;
  cursor:pointer;text-decoration:underline;text-underline-offset:3px}
.clearall:hover{color:var(--ink)}
.more{display:block;width:100%;background:rgba(var(--hi-rgb),.03);border:0;border-top:1px solid var(--edge);
  color:var(--dim);font-family:var(--mono);font-size:12.5px;padding:11px;cursor:pointer;transition:.16s}
.more:hover{background:rgba(var(--hi-rgb),.06);color:var(--ink)}

.bars{padding:14px 22px 20px}
.brow{margin-bottom:10px;cursor:pointer}
.brow:last-child{margin-bottom:0}
.brow:hover .blab{color:var(--ink)}
.blab{display:flex;justify-content:space-between;gap:10px;font-size:15.5px;margin-bottom:4px;
  color:var(--dim);transition:color .16s}
.blab .bn{font-family:var(--mono);font-size:12.5px;color:var(--faint);flex:none}
.blab .btx{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btr{height:4px;background:rgba(var(--line-rgb),.09);border-radius:3px;overflow:hidden}
.bfl{height:100%;width:0;border-radius:3px;transition:width 1s cubic-bezier(.16,1,.3,1)}
.bfl.red{background:linear-gradient(90deg,var(--v1-deep),var(--v1))}
.bfl.amb{background:linear-gradient(90deg,var(--v2-deep),var(--v2))}

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
/* 24 hours across 390 px leaves 4 px per cell - neither readable nor tappable.
   Scroll the grid instead and keep the cells usable. */
@media(max-width:760px){
  .hm{overflow-x:auto;padding-left:14px;padding-right:14px}
  .hr{min-width:560px}
}
.hr .lb{font-family:var(--mono);font-size:12px;color:var(--faint)}
.hc{aspect-ratio:1;border-radius:2px;background:rgba(var(--line-rgb),.05);transform:scale(.4);opacity:0;
  transition:transform .5s cubic-bezier(.16,1,.3,1),opacity .5s}
.hc.in{transform:scale(1);opacity:1}
.hc{cursor:pointer}
.hc:hover{outline:1px solid var(--ink);outline-offset:1px}
.hc.on{outline:2px solid var(--gold);outline-offset:1px}
.bcol{cursor:pointer}
.bcol:hover span{filter:brightness(1.25)}
.bcol.on span{filter:brightness(1.5)}
.bcol.on{outline:1px solid var(--gold);outline-offset:1px;border-radius:2px}
.hnote{font-family:var(--mono);font-size:14px;color:var(--dim);margin-top:11px;padding-top:10px;
  border-top:1px solid var(--edge)}
.hnote b{color:var(--v2);font-weight:500}

.scrim{position:fixed;inset:0;background:rgba(var(--scrim-rgb),.60);backdrop-filter:blur(3px);opacity:0;
  pointer-events:none;transition:opacity .3s;z-index:70}
.scrim.on{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(540px,100%);background:var(--drawer);
  border-left:1px solid var(--edge2);z-index:80;transform:translateX(100%);
  transition:transform .42s cubic-bezier(.16,1,.3,1);display:flex;flex-direction:column;
  box-shadow:-30px 0 70px rgba(var(--shade-rgb),.45)}
.drawer.on{transform:none}
.dh{padding:20px 22px 15px;border-bottom:1px solid var(--edge);display:flex;align-items:flex-start;gap:12px}
.dh h3{margin:0 0 6px;font-family:var(--disp);font-size:22px;font-weight:580;letter-spacing:-.02em}
.dh .when{font-family:var(--mono);font-size:14.5px;color:var(--faint)}
.x{background:rgba(var(--hi-rgb),.05);border:1px solid var(--edge);color:var(--dim);border-radius:8px;
  width:34px;height:34px;cursor:pointer;margin-left:auto;flex:none;transition:.16s;font-size:17px}
.x:hover{color:var(--ink);border-color:var(--edge2)}
.dbody{overflow-y:auto;padding:4px 0 26px;flex:1}
.expl{margin:15px 22px;padding:13px 15px;border:1px solid var(--edge);border-radius:11px;
  background:rgba(var(--line-rgb),.04);font-size:16px;color:var(--dim);line-height:1.6}
.expl b{display:block;color:var(--ink);font-weight:600;margin-bottom:4px}
.grp{margin:17px 22px 0}
.grp .gk{font-family:var(--mono);font-size:12.5px;letter-spacing:.11em;text-transform:uppercase;
  color:var(--faint);padding-bottom:8px;border-bottom:1px solid var(--edge);margin-bottom:4px}
.fr{display:grid;grid-template-columns:150px 1fr;gap:14px;padding:9px 0;font-size:16px;
  border-bottom:1px solid rgba(var(--line-rgb),.05)}
.fr:last-child{border-bottom:0}
.fr .fk{color:var(--faint);font-family:var(--mono);font-size:14px;padding-top:2px}
.fr .fv{font-family:var(--mono);font-size:15.5px;word-break:break-word}
.fr .fv.none{color:var(--faint)}
.dact{display:flex;gap:8px;flex-wrap:wrap;margin:19px 22px 0}
.dact button{flex:1 1 auto;background:rgba(var(--hi-rgb),.04);border:1px solid var(--edge);color:var(--dim);
  border-radius:9px;padding:10px 14px;font-family:var(--mono);font-size:14px;cursor:pointer;transition:.18s}
.dact button:hover{color:var(--ink);border-color:var(--gold);background:rgba(var(--gold-rgb),.09)}
.code{margin:15px 22px;background:var(--code);border:1px solid var(--edge);border-radius:10px;padding:13px 15px;
  font-family:var(--mono);font-size:15px;color:var(--dim);white-space:pre-wrap;word-break:break-all;
  max-height:360px;overflow-y:auto}

@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
  .card{opacity:1;transform:none}.hc{opacity:1;transform:none}
}
/* Below this width a seven-column table cannot work. The card clips whatever
   does not fit, so five of seven columns were simply unreachable - not even by
   swiping. Each row becomes a small block instead, with the column name in
   front of its value. The labels are filled in by JS from the table's own
   header, so every table on the page gets this without being told about it. */
@media(max-width:760px){
  table.srt thead{position:absolute;left:-9999px}      /* kept for screen readers */
  table.srt tr{display:block;padding:12px 4px;border-top:1px solid rgba(var(--line-rgb),.11)}
  table.srt tbody tr:first-child{border-top:0}
  /* wrap: cells holding several tags side by side (the machine panel) would
     otherwise keep them on one line and push past the card edge. */
  table.srt td{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:baseline;
    border:0;padding:3px 18px;font-size:15px}
  table.srt td::before{content:attr(data-label);flex:0 0 38%;max-width:38%;color:var(--faint);
    font-family:var(--mono);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
  table.srt td.r{text-align:left}
  table.srt td:empty{display:none}
  /* The first cell carries the row's identity - give it weight. */
  table.srt td:first-child{font-size:16.5px;font-weight:620;padding-bottom:6px}
  table.srt td:first-child::before{display:none}
}
/* After the base header rules so these win: media queries add no specificity. */
@media(max-width:760px){
  .hin{height:auto;flex-wrap:wrap;padding-top:10px;padding-bottom:10px;gap:10px}
  .tools{margin-left:0;width:100%;justify-content:flex-start}
  /* Wrapping makes the header three rows tall - 175 px, and pinned it would
     hold a quarter of the screen hostage for the whole page. It scrolls away
     here; the section bar takes over as the thing that stays, which is the
     part that is actually useful while reading. */
  header{position:static}
  .jump{top:0}
  /* Comfortable to hit with a thumb. Seven controls were under 32 px tall,
     which is below every platform's guidance. */
  .hin button, .hin select, .hin a{min-height:40px}
  #range button{padding-top:9px;padding-bottom:9px}
}

@media(max-width:720px){
  .hin{gap:10px;overflow-x:auto}.hero{padding:30px var(--pad) 20px}
  .fr{grid-template-columns:1fr;gap:2px}.jump{overflow-x:auto;flex-wrap:nowrap}
}

/* Placed after the 720 px block on purpose: that one sets .hero padding too,
   and being later in the file it won. Same width, later position, so these
   take effect. */
@media(max-width:760px){
  .hero{padding:26px var(--pad) 26px}
  .thesis{font-size:30px;line-height:1.12}
  .sub{font-size:15px;margin-bottom:22px}
  .deadline{margin-top:20px;padding:13px 15px}
  .dnum{font-size:30px}
  .focus{padding-bottom:20px;gap:10px}
  .fc{padding:14px 16px}
}

/* Long unbroken values - SPNs, UNC paths - still pushed a stacked cell past
   the card edge, which is what clipped them in the first place. */
@media(max-width:760px){
  table.srt td{overflow-wrap:anywhere;word-break:break-word}
  table.srt td .cut{max-width:none;white-space:normal;overflow:visible}
}
/* ===== The modern look: soft surfaces, key-figure tiles, slim bar ===== */
.card,.fc,.osdon,.kpi{background:var(--card);border:1px solid var(--edge);border-radius:var(--r);box-shadow:var(--shadow)}
.drawer{box-shadow:none}
.drawer.on{box-shadow:-30px 0 70px rgba(var(--shade-rgb),.35)}
.herotop{display:flex;gap:clamp(24px,4vw,56px);align-items:flex-start}
.heroside{flex:0 0 380px;display:flex;flex-direction:column;gap:16px}
.deadline .dtxt{font-size:13.5px;line-height:1.45}
.deadline .dtxt b{font-size:15px}
.heroside .osdon{width:auto}
.deadline{margin:0;max-width:none;padding:20px 22px;border-radius:var(--r);
  background:rgba(var(--v1-rgb),.10);border:1px solid rgba(var(--v1-rgb),.28)}
.dnum{font-size:52px;font-weight:700;line-height:1}
@media(max-width:1250px){
  .herotop{flex-direction:column;align-items:stretch}
  .heroside{flex:none;max-width:700px}
}
.handcap{display:flex;justify-content:space-between;gap:12px;margin-top:6px;font-family:var(--mono);font-size:12px;
  letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.handbar{height:16px;border-radius:999px;gap:3px;background:transparent;margin-top:10px}
.seg{border-radius:0}
.seg.s1{background:var(--bar-v1)}.seg.s2{background:var(--bar-v2)}.seg.s3{background:var(--bar-krb)}
.seg.on{filter:none;box-shadow:inset 0 0 0 2px var(--ink)}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-top:22px}
@media(max-width:1100px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
.kpi{display:flex;flex-direction:column;gap:12px;padding:18px 20px;text-align:left;font:inherit;color:inherit;min-width:0}
button.kpi{cursor:pointer;transition:border-color .15s,transform .15s}
button.kpi:hover{border-color:var(--edge2);transform:translateY(-1px)}
.kpi.on{box-shadow:0 0 0 2px var(--gold),var(--shadow)}
.kh{display:flex;align-items:center;gap:8px;font-size:13.5px;color:var(--dim)}
.kh i{width:8px;height:8px;border-radius:50%;flex:none}
.kb{display:flex;align-items:flex-end;justify-content:space-between;gap:10px;min-width:0}
.kb b{font-family:var(--disp);font-size:clamp(30px,2.6vw,40px);font-weight:650;line-height:1;letter-spacing:-.03em;
  color:var(--ink);font-variant-numeric:tabular-nums;white-space:nowrap}
.ksp{flex:0 1 110px;min-width:28px;width:auto}
.kd{display:flex;align-items:center;gap:8px 10px;flex-wrap:wrap}
.dlt{font-style:normal;font-family:var(--mono);font-size:12px;padding:3px 9px;border-radius:999px;white-space:nowrap}
.dlt.good{color:var(--krb);background:rgba(var(--krb-rgb),.14)}
.dlt.bad{color:var(--v1);background:rgba(var(--v1-rgb),.14)}
.dlt.flat{color:var(--dim);background:rgba(var(--hi-rgb),.06)}
.kd small{font-family:var(--mono);font-size:11.5px;color:var(--faint)}
.focus{gap:16px}
.fc{display:flex;gap:16px;align-items:flex-start;padding:20px 22px;text-align:left}
.fc:hover{border-color:var(--edge2)}
.fi{width:38px;height:38px;border-radius:11px;background:rgba(var(--hi-rgb),.05);display:grid;place-items:center;flex:none}
.ft{min-width:0}
.tchart{position:relative;padding:14px 22px 2px}
.tchart svg{display:block;width:100%;height:190px;overflow:visible}
.tgrid{stroke:rgba(var(--line-rgb),.12);stroke-width:1}
.tgoal{stroke:var(--krb);stroke-width:1.5;stroke-dasharray:6 5}
.tgoaltxt{position:absolute;left:30px;bottom:10px;font-family:var(--mono);font-size:11.5px;color:var(--krb);
  background:var(--card);padding:1px 7px;border-radius:6px;border:1px solid rgba(var(--krb-rgb),.35)}
.thit{fill:transparent;cursor:pointer}
.thit:hover{fill:rgba(var(--hi-rgb),.05)}
.thit.on{fill:rgba(var(--gold-rgb),.16)}
td{padding:12px 22px;font-size:15.5px}
.sel-st{-webkit-appearance:none;appearance:none;border-radius:999px;padding:6px 30px 6px 13px;font-family:var(--mono);
  font-size:12.5px;cursor:pointer;min-height:32px;
  background-image:linear-gradient(45deg,transparent 50%,currentColor 50%),linear-gradient(135deg,currentColor 50%,transparent 50%);
  background-position:calc(100% - 15px) 55%,calc(100% - 10px) 55%;background-size:5px 5px,5px 5px;background-repeat:no-repeat}
.sel-st.st-open{background-color:rgba(var(--hi-rgb),.05);color:var(--dim);border:1px solid var(--edge2)}
.sel-st.st-in_progress{background-color:rgba(var(--v2-rgb),.14);color:var(--v2-hi);border:1px solid rgba(var(--v2-rgb),.40)}
.sel-st.st-done{background-color:rgba(var(--krb-rgb),.14);color:var(--krb-hi);border:1px solid rgba(var(--krb-rgb),.40)}
/* Very narrow phones: the mark alone says whose dashboard this is. */
@media(max-width:379px){#brand{display:none}}
/* Below 380 px two tiles side by side leave no room for the line next to a
   five-digit number; the change and the comparison line carry the point. */
@media(max-width:380px){.ksp{display:none}}
td .blkd{margin-top:5px}
td.nw{white-space:nowrap}
@media(max-width:760px){
  .kpis{gap:12px}
  .kpi .kq{display:none}
  .kd small{font-size:11px}
  .kpi{padding:14px 16px}
  .dnum{font-size:42px}
  .deadline{padding:16px 18px}
}

/* Phone header: one row - brand plus a button that says what is set. The
   controls took three rows (about 200 px) before any content; now they open
   below on demand. Last in the file so these rules win over the ones above. */
@media(max-width:760px){
  .hin{flex-wrap:wrap;row-gap:10px}
  .menu{display:inline-flex;align-items:center;gap:8px;margin-left:auto;min-height:40px;padding:6px 12px;
    background:rgba(var(--hi-rgb),.04);border:1px solid var(--edge);border-radius:9px;color:var(--ink);
    font-family:var(--mono);font-size:13px;cursor:pointer;max-width:60vw}
  .menu span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .menu i{width:7px;height:7px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;
    transform:translateY(-2px) rotate(45deg);transition:transform .18s;flex:none}
  header.open .menu i{transform:translateY(1px) rotate(-135deg)}
  header.open .menu{border-color:var(--gold)}
  .tools{display:none}
  header.open .tools{display:flex;flex-wrap:wrap;gap:8px}
  .searchbtn{margin-left:auto;width:44px;height:44px;padding:0;justify-content:center}
  /* brand, search and the selection button have to share one row */
  .logo{gap:8px}
  #brand{font-size:15px}
  .menu{padding:6px 10px}
  .searchbtn span,.searchbtn kbd{display:none}
  .menu{margin-left:8px}
  .pal{padding:8px}
  .palbox{max-height:86vh}
  .psb{display:none}
  .pty{min-width:74px}
  .hlp{width:40px;height:40px}
  .mark{width:26px;height:26px}
  .eyebrow{font-size:12.5px;letter-spacing:.1em;margin-bottom:10px}
}
</style>
</head>
<body>
<a class="skip" href="#sec-events">Skip to the event list</a>
<div class="stage">
<header><div class="hin">
  <div class="logo"><img class="mark" alt="" width="28" height="28" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAA/1BMVEX+/v4dKDohLD0PGy4uOEn5yQtUXWv99M774Xn72U/855L70y+UmaL///773mj766n///yPlJoAAACDiZOkqK7n6OpcY3H//v44Q1hja3d0e4extbokLkBETVz///++wcb4zSL+87gBDiJpcHx6gIucoam3u8HKzNDR09fe4OP/0grm3Kf////EvJjAvary34r/4DL/4EsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB9fbMYAAAAQHRSTlP+//////7/////////1///DP8A/////4f///////8o//7//////////////33//////wAAAAAAAAAAAAAAAAAAJ9C2nAAAAihJREFUeNrtl2lzozAMhn1gHNuAQ4DcPdLu1XbP///n1gcQTJNmLH/b2XcmQBz0IMtCsdBytdyUCKRyY4zR6h5o7hD3K7RMsDeEJfqOkrRBZRog0fy//lkVdWFVP8zGD268Lm7Zd5h6kS78IX9yw7i7RcgwscroLhxf46MZxhm6DfAi9EvoASV2OAIwuzcaYFxo0gBG39IAhOaJHhD6OXEKOOugAJJ7F3ZAAKHt3SwZYgGH1hoQvIUCiuGiAQIaVHiLIRliAfvxKgcDXBRsPEEAu353mJyTIRawNpcPvQvPEICb+a4n2PK2hgA64ivDdoRFAvqltFmBnkGASRz3MMDXsTh9ggEGuyOqgQBb5l1paaGAgzfcFlDAkAB5X6PiAS9kWiXJRSOpjPgVwPhem2DQ7f4KQAhxFTAkA6FZ++sPY0roqCmckyF/+82YEMocZkZcaq0lR/ZzAeCy0LwR+pVJd3vFVAhYMCtxsuhLAPefj3+qRz7Mee4Dt7IndBlwoEeaLxifPJJ/uME44vV8e4FrNX0qq4JVYIME8lucp9AD9ILpj9dp8EUQBS0qLyFR3dRGTTvfYzVvgdcVi96+8RAQeMAXVhqZg6yk/ybfEdh0KAhIv4wVdyel/ekdYDptzjQCzOHsglKQTawcCeJ6GtwgCM1N4jMlhQQRuHDxWZiI2gOMwZ33p5EA7du4J5TwxpM/WsImofU1hFOZ1Hxz6Zpv0/6DG2dj/BcWBhsxYHO2PQAAAABJRU5ErkJggg=="><span id="brand">NTLM-Analyzer</span><span class="orb" id="orb"></span></div>
  <button type="button" class="searchbtn" id="searchbtn" aria-haspopup="dialog"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg><span id="searchlbl"></span><kbd id="searchkbd"></kbd></button>
  <button type="button" class="menu" id="menu" aria-expanded="false" aria-controls="tools"></button>
  <div class="tools" id="tools">
    <div class="pill" id="range"></div>
    <select id="mach"></select>
    <button class="ghost" id="hide"></button>
    <button class="ghost" id="report"></button>
    <button class="ghost" id="csv">CSV</button>
    <button class="ghost" id="logout" hidden>Logout</button>
    <button type="button" class="ghost themebtn" id="theme"><svg class="i-sun" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2M12 19.5v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M2.5 12h2M19.5 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4"/></svg><svg class="i-moon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg></button>
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
    <aside class="heroside">
      <div class="deadline">
        <div class="dnum" id="days">0</div>
        <div class="dtxt"><b id="ddl_t"></b><span id="ddl_b"></span></div>
      </div>
      <div class="osdon" id="osdon"></div>
    </aside>
  </div>
  <div class="handcap"><span id="hc_l"></span><span id="hc_r"></span></div>
  <div class="handbar" id="handbar"></div>
  <div class="kpis" id="handkey"></div>
</section>

<div class="focus" id="focus"></div>
<div class="grid" id="grid"></div>
</div>

<div class="pal" id="pal" hidden role="dialog" aria-modal="true" aria-label="Search">
  <div class="palbox">
    <div class="palin"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
      <input id="palq" type="search" autocomplete="off" spellcheck="false" role="combobox" aria-expanded="true" aria-controls="palres" aria-autocomplete="list"><kbd>Esc</kbd></div>
    <ul id="palres" role="listbox"></ul>
    <div class="palfoot" id="palfoot"></div>
  </div>
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
  unconf_hint:'{n} unbestätigte Einträge ausgeblendet – anzeigen',
  unconf_chip:'Nur unbestätigte 8001',
  unconf_tag:'unbestätigt',
  unconf_expl:'Diese Maschine schreibt das erweiterte Ereignis 4020, zu diesem 8001 aber keins. Ob dahinter eine NTLM-Anmeldung stand, ist noch nicht geklärt: Dafür müssen alle Domänencontroller für diesen Zeitpunkt ihre 4776-Prüfungen geliefert haben, und das Konto muss ein Domänenkonto sein. Bis dahin zählt der Eintrag in keiner Kennzahl mit.',
  unconf_hint_ph:'{n} unbestätigte Einträge ausgeblendet, davon {p} vom DC als Phantom belegt – anzeigen',
  phantom_tag:'Phantom (DC-geprüft)',
  phantom_expl:'Kein Domänencontroller hat in den zwei Minuten um diesen Zeitpunkt eine NTLM-Anmeldung dieses Kontos geprüft – geprüft gegen {dcs}. Windows hat das 8001 geschrieben, weil NTLM beim Aushandeln in Frage kam; angemeldet hat Kerberos.',
  tip_events:'Ereignisse', tip_share:'Anteil', tip_click:'klicken, um danach zu filtern',
  fl_dom:'Domänenebene', fl_for:'Gesamtstruktur', fl_raw:'Ebene {n}',
  fl_split_t:'Die Agenten melden unterschiedliche Werte',
  osdon_mid:'Agenten', osdon_old:'{n} vor Server 2019 – dort fehlen die 40xx-Ereignisse', osbar_tip:'Gezählt werden nur Maschinen mit Agent, nicht die gesamte Domäne',
  leg_goal:'Farbbedeutung', leg_bad:'NTLMv1 · unsicher', leg_old:'NTLMv2 · veraltet', leg_good:'Kerberos · sicher',
  range:'Zeitraum', r24h:'24 Std.', trend_hourly:'pro Stunde', r7d:'7 Tage', r30d:'30 Tage', rall:'Alles',
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
  fix_unclear:'Ursache prüfen – Windows meldet hier keine bekannte ID',
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
  g_report:'Bericht', g_report_t:'Statusbericht zum Drucken oder als PDF – für alle, die das Dashboard nicht öffnen',
  more:'weitere', b_v1:'NTLMv1 · unsicher', b_v2:'NTLMv2 · veraltet', b_krb:'Kerberos · sicher',
  b_dom:'NTLM (Domäne)', b_out:'NTLM ausgehend', b_fb:'Kerberos-Fallback',
  hb_on:'aktiv', hb_off:'still',
  au_out_on:'Ausgehend', au_out_off:'Ausgehend aus', au_dom_on:'Domäne', au_dom_off:'Domäne aus',
  st_open:'offen', st_in_progress:'in Arbeit', st_done:'erledigt', again:'wieder aktiv', what:'Was tun?',
  search_btn:'Suchen', search_kbd:'Strg K', pal_ph:'Maschine, Programm, Konto, Ziel oder Panel …',
  pal_foot:'↑ ↓ wählen · Enter öffnen · Esc schließen · Maschinen öffnen die Detailansicht, alles andere filtert die Ereignisse',
  pal_none:'Nichts gefunden für „{q}".', pal_machine:'Maschine', pal_noagent:'Rechner', pal_prog:'Programm',
  pal_acct:'Konto', pal_target:'Ziel', pal_panel:'Panel', pal_panel_sub:'springen',
  pal_noagent_sub:'ohne Agent · {n}× NTLM', pal_dom_sub:'Domänensicht · {n}×', pal_target_sub:'{n}× NTLM',
  nav_spn:'SPN', spn_h:'Kerberos-Konfiguration (SPN)', spn_badge:'{n} Befunde', spn_ok_badge:'sauber registriert',
  spn_meta:'{c} geprüft · {o} in Ordnung', spn_th:'Dienstname (SPN)', spn_th_find:'Befund', spn_th_fix:'Behebung',
  spn_st_missing:'fehlt', spn_st_alias:'Alias', spn_st_duplicate:'doppelt',
  spn_d_noacct:'Kein Konto im Forest trägt diesen Namen – Kerberos kann kein Ticket ausstellen. Geräte ohne Domänenkonto (NAS, Appliance) bleiben bei NTLM, bis sie in die Domäne kommen oder ein Konto mit diesem SPN bekommen.',
  spn_d_nores:'Der Name löst im DNS nicht auf und ist nirgends registriert. Veralteter Name in einer Freigabe, einem Skript oder einer Verknüpfung?',
  spn_d_unmapped:'HOST/{h} ist auf {a} registriert, deckt diesen Dienst aber nicht ab. Läuft der Dienst unter einem eigenen Konto, gehört der SPN dorthin.',
  spn_d_cname:'Der Name ist ein Alias für {c}. Dort ist der SPN registriert, unter dem Alias nicht – wer den Alias verwendet, fällt auf NTLM zurück.',
  spn_d_short:'Registriert ist nur der volle Name {c}, die Clients verwenden den Kurznamen.',
  spn_d_dup:'Mehrere Konten tragen diesen SPN: {o}. Der KDC verweigert dann das Ticket. Bei allen Konten entfernen (setspn -D) außer dem, unter dem der Dienst läuft.',
  spn_d_dup_host:'HOST/{h} ist auf mehreren Konten registriert: {o}. Nur das Computerkonto des Servers darf ihn tragen.',
  spn_acct_ph:'<Dienstkonto>', spn_copy:'Kopieren', spn_copied:'kopiert', spn_recheck:'Neu prüfen', spn_queued:'vorgemerkt',
  spn_recheck_t:'Beim nächsten Durchlauf eines DC-Agents erneut nachschlagen – etwa nachdem der Befehl ausgeführt wurde.',
  spn_krb_t:'{n} fehlgeschlagene Kerberos-Anfragen für diesen Namen (4769)',
  spn_nodc:'Noch kein Domänencontroller mit Agent 2.4 oder neuer – der schlägt die Namen im AD nach. Den Agent auf mindestens einem DC aktualisieren.',
  spn_pending:'{n} Namen warten noch auf die Prüfung – ein DC-Agent schlägt pro Durchlauf bis zu 50 nach.',
  spn_errors:'{n} Namen konnten nicht geprüft werden – das Protokoll des DC-Agents nennt den Grund.',
  spn_empty:'Alle {n} geprüften Dienstnamen sind im AD sauber registriert.', spn_none:'Noch keine Dienstnamen geprüft.',
  help_spn:'Für jeden Dienstnamen (SPN), bei dem Clients auf NTLM ausgewichen sind oder Kerberos mit „SPN nicht gefunden" scheiterte, schlägt ein DC-Agent im Active Directory nach, ob und bei wem er registriert ist – nur lesend, das darf jedes Domänenkonto. Das Tool ändert nichts im AD; die Spalte „Behebung" zeigt den setspn-Befehl, den ein Admin ausführt. setspn -S prüft vor dem Anlegen auf Duplikate. In Forests mit mehreren Domänen setspn in der Domäne des Kontos ausführen. Ziele in fremden Forests lassen sich nicht prüfen und erscheinen als „fehlt".',
  nav_fail:'Fehlversuche', nav_acc:'Konten', pal_failed:'{n}× fehlgeschlagen',
  fail_h:'Fehlgeschlagene NTLM-Versuche', fail_badge_spray:'Spraying?',
  fail_meta:'{n} Versuche · {a} Konten',
  fail_from:'Von', fail_to:'Auf', fail_why:'Grund', fail_locked:'gesperrt',
  fail_to_dc:'über DC', fail_to_dc_t:'Nur vom Domänencontroller gesehen (4776) – der Zielserver hat keinen Agent oder kein Fehler-Audit.',
  fail_spray:'Viele Konten von einem Rechner: {l}. So sieht Password Spraying aus – oder ein Skript mit veralteten Zugangsdaten. Prüfen.',
  fail_spray_n:'{n} Konten',
  fail_blind:'Auf {n} Maschinen ist „Anmelden überwachen: Fehler" nicht aktiv – Fehlanmeldungen dort erscheinen nur, wenn ein DC sie prüft.',
  fail_empty:'Keine fehlgeschlagenen NTLM-Anmeldungen im gewählten Zeitraum.',
  fv_local:'auf dem Server gesehen', fv_dc:'vom DC gesehen', fv_both:'Server und DC',
  nt_0xc000006a:'falsches Passwort', nth_0xc000006a:'Meist ein Dienst, eine geplante Aufgabe oder ein Laufwerk mit altem Passwort auf dem Quellrechner.',
  nt_0xc0000064:'Konto existiert nicht', nth_0xc0000064:'Vertippter oder gelöschter Kontoname – oder jemand probiert Namen durch.',
  nt_0xc0000234:'Konto gesperrt', nth_0xc0000234:'Das Konto ist gesperrt. Die Quelle finden, die es mit falschem Passwort immer wieder versucht.',
  nt_0xc0000072:'Konto deaktiviert', nth_0xc0000072:'Ein deaktiviertes Konto wird noch benutzt – Dienst, Aufgabe oder Skript suchen.',
  nt_0xc0000193:'Konto abgelaufen', nth_0xc0000193:'Das Konto ist abgelaufen, wird aber noch verwendet.',
  nt_0xc0000071:'Passwort abgelaufen', nth_0xc0000071:'Passwort abgelaufen – bei Dienstkonten: Kennwort erneuern oder auf gMSA umstellen.',
  nt_0xc0000224:'Passwort muss geändert werden', nth_0xc0000224:'Das Konto muss bei der nächsten Anmeldung sein Passwort ändern.',
  nt_0xc000006f:'außerhalb der Anmeldezeiten', nth_0xc000006f:'Anmeldung zu einer gesperrten Uhrzeit.',
  nt_0xc0000070:'Arbeitsstation nicht erlaubt', nth_0xc0000070:'Das Konto darf sich an diesem Rechner nicht anmelden (userWorkstations).',
  nt_0xc000015b:'Anmeldetyp nicht erlaubt', nth_0xc000015b:'Das Benutzerrecht für diesen Anmeldetyp fehlt (z. B. „Zugriff vom Netzwerk").',
  nt_0xc000006d:'Anmeldung fehlgeschlagen', nth_0xc000006d:'Allgemeiner Fehlschlag ohne genaueren Grund.',
  nt_0xc0000133:'Uhrzeit weicht ab', nth_0xc0000133:'Die Uhr des Rechners weicht zu stark vom DC ab.',
  nt_0xc0000413:'Authentifizierungs-Firewall', nth_0xc0000413:'Selektive Authentifizierung einer Vertrauensstellung hat die Anmeldung abgelehnt.',
  acc_h:'Konten, die NTLM nutzen', acc_meta:'{n} Konten · {v} mit NTLMv1',
  acc_logons:'NTLM-Anmeldungen', acc_ver:'Version', acc_mach:'Rechner', acc_tgt:'Ziele', acc_failed:'Fehlgeschlagen', acc_krb:'Kerberos',
  acc_krb_t:'Dieses Konto bekommt bereits Kerberos-Tickets – nur ein Teil läuft noch über NTLM.',
  acc_nover:'unbekannt', acc_nover_t:'Die Ereignisse nennen keine Version (8001/8003/8004 ohne passendes 4624 oder 40xx).',
  acc_anon:'anonym', acc_anon_t:'Anonyme NTLM-Verbindung (Null-Session): keine Anmeldedaten, oft alte Drucker, Samba/Linux-Abfragen oder Aufzählungen. Windows kennzeichnet sie als „NTLM V1" – das ist hier kein echtes NTLMv1. Aufrufer über die Quellrechner finden und anonymen Zugriff einschränken.',
  acc_machine:'Computerkonto', acc_machine_t:'Ein Computerkonto meldet sich per NTLM an – meist Dienste, die als SYSTEM laufen und Kerberos nicht nutzen können (z. B. Ziel per IP-Adresse oder fehlender SPN).',
  acd_user:'Benutzer- oder Dienstkonto', acd_last:'zuletzt {when}', acd_none:'Für dieses Konto liegen im Zeitraum keine NTLM-Daten vor.',
  acd_failed_sub:'Server und DCs', acd_mixed:'teils schon Kerberos', acd_krb_only:'nur Kerberos', acd_no_krb:'kein Kerberos gesehen',
  acd_via_agent:'Agent', acd_via_server:'vom Server gesehen', acd_via_dc:'vom DC gesehen',
  acd_from:'Von welchen Rechnern', acd_to:'Auf welche Server', acd_fails:'Fehlgeschlagene Versuche', acd_more:'… und {n} weitere',
  acd_events:'Ereignisse dieses Kontos',
  help_failed:'Fehlgeschlagene NTLM-Anmeldungen: auf den Servern mit Agent (4625) und an den Domänencontrollern (4776). Dieselbe Fehlanmeldung wird dabei einmal gezählt. Häufigste Ursachen: veraltete Passwörter in Diensten oder Aufgaben – und Password Spraying, wenn ein Rechner viele Konten durchprobiert. Fehlschläge zählen nicht zum NTLM-Anteil.',
  help_accounts:'Jedes Konto, das NTLM nutzt, aus allen Richtungen: was die Rechner senden (8001/4020), was die Server annehmen (8003/4022/4624) und was die DCs sehen (8004/4030). Dieselbe Anmeldung wird einmal gezählt. Ein Klick öffnet das Konto mit Rechnern, Servern, Programmen und Fehlschlägen.',
  b_out_off:'ausgehend aus', b_out_off_t:'„Ausgehender NTLM-Datenverkehr zu Remoteservern" steht nicht auf „Alle überwachen" – diese Maschine schreibt kein 8001. Welches Programm und Konto von hier NTLM nutzt, bleibt unsichtbar.',
  b_in_off:'eingehend aus', b_in_off_t:'„Eingehenden NTLM-Datenverkehr überwachen" ist aus – kein 8002/8003. Welcher Dienst hier NTLM annimmt, bleibt offen; die Anmeldungen selbst sieht man weiter über 4624 und den DC.',
  b_dom_off:'Domäne aus', b_dom_off_t:'„NTLM-Authentifizierung in dieser Domäne überwachen" ist auf diesem DC aus – kein 8004. Die Domänensicht fehlt für alles, was dieser DC prüft.',
  ag_gaps:'Auf {n} Maschinen fehlt NTLM-Auditing in mindestens einer Richtung – dort bleibt NTLM ganz oder teilweise unsichtbar. Die roten und gelben Abzeichen nennen die Richtlinie.',
  r_logon:'Anmeldungen', r_logon_t:'„Anmelden überwachen: Erfolg" ist aktiv – diese Maschine schreibt 4624, NTLMv1 wird hier erkannt.',
  b_logon_off:'4624 fehlt', b_logon_off_t:'„Anmelden überwachen" steht auf „Keine Überwachung" oder nur „Fehler". Ohne erfolgreiche 4624 bleibt NTLMv1 auf dieser Maschine unsichtbar. GPO: Erweiterte Überwachungsrichtlinienkonfiguration → An-/Abmelden → Anmelden überwachen: Erfolg.',
  b_agent_sec:'Agent {v}: Sicherheitsupdate', b_agent_sec_t:'Agent-Versionen vor {s} haben bekannte Sicherheitslücken (u. a. im Umgang mit dem Datenordner). Bitte auf {s} oder neuer aktualisieren.',
  b_agent_old:'Agent vor 2.3', b_agent_old_t:'Dieser Agent sammelt 4624 nur auf DCs – NTLMv1 bleibt auf dieser Maschine unsichtbar, bis der Agent auf 2.3.0 oder neuer aktualisiert ist.',
  b_logon_unk:'Anmelde-Audit unbekannt', b_logon_unk_t:'Der Agent konnte die Auditrichtlinie nicht lesen (auditpol). Ob NTLMv1 hier erkannt wird, ist offen.',
  v1_blind:'Auf {n} Maschinen ist NTLMv1 unsichtbar – {a} ohne Anmelde-Audit, {b} mit Agent vor 2.3. Zum Maschinen-Panel →',
  md_loading:'Lädt …', md_err:'Konnte nicht geladen werden.', md_out:'Ausgehend', md_in:'Eingehend',
  md_in_local:'Eingehend (auf der Maschine)', md_srcs_lbl:'Quellen', md_local:'{n} selbst protokolliert',
  md_v1:'{n} davon NTLMv1', md_v1none:'kein NTLMv1', md_ready:'Abschalten · letzte 30 Tage', md_progs:'Programme → Ziele',
  md_from:'Wer per NTLM zugreift', md_users:'Konten', md_audit:'Auditing',
  md_none_out:'Kein ausgehendes NTLM im gewählten Zeitraum.', md_none_in:'Kein eingehendes NTLM im gewählten Zeitraum gesehen.',
  md_via_local:'selbst protokolliert', md_via_dc:'vom DC gesehen', md_via_cli:'vom Client gemeldet',
  md_more:'… und {n} weitere Quellen', md_seen:'zuletzt gemeldet {when}', md_since:'Daten seit {when}',
  md_stale:'meldet sich nicht', md_agent:'Agent {v}', md_type_srv:'Server', md_type_cli:'Client',
  md_filter:'Dashboard auf diese Maschine filtern', md_events:'Ereignisse dieser Maschine',
  svc_logon:'Anmeldung ohne Dienstangabe (4624)', blk_short:'blockiert', kpi_share:'NTLM-Anteil', kpi_vs:'zur Vorwoche', kpi_sub:'7 Tage: {a} · Vorwoche: {b}', kpi_new:'neu', kpi_pts:'Pkt.',
  hc_l:'Ablöse · {r}', hc_r:'Ziel: 100 % Kerberos', goal0:'Ziel: 0',
  theme_light:'Helles Design', theme_dark:'Dunkles Design',
  help_lbl:'Was zeigt das?', menu_lbl:'Auswahl', orb_t:'Live – aktualisiert sich jede Minute',
  help_trend:'NTLM-Vorgänge im gewählten Zeitraum – diese Balken sollen über die Wochen gegen null gehen. Rot = NTLMv1, Gelb = NTLMv2, Grau = NTLM ohne Versionsangabe. Kerberos steht zur Einordnung im Tooltip. Ein Klick auf einen Balken zeigt die Ereignisse dahinter.',
  help_programs:'Die Arbeitsliste: jedes Programm, das per NTLM auf ein Ziel zugreift, aus den Client-Ereignissen 8001 und 4020. Status setzen, sobald ein Eintrag behoben oder bewusst akzeptiert ist. Die Linie zeigt den Verlauf der letzten Tage, die rote Zahl bereits blockierte Versuche.',
  help_why:'Warum Windows NTLM statt Kerberos gewählt hat – aus dem Grund, den die erweiterten Ereignisse 4020 bis 4023 mitliefern, und aus Kerberos-Fehlern (4769). Zu jedem Grund steht die übliche Behebung; ein Klick zeigt die betroffenen Ereignisse.',
  help_heat:'Wann NTLM passiert, nach Wochentag und Stunde. Helle Zellen außerhalb der Arbeitszeit sind meist geplante Aufgaben, Dienste oder Skripte – oft die am leichtesten übersehenen Posten. Ein Klick auf eine Zelle zeigt genau diese Stunde.',
  help_v1:'Konten, die sich noch mit NTLMv1 anmelden – erkannt an den Anmeldungen auf Servern und DCs (4624) und an den erweiterten Ereignissen von Windows 11 24H2 / Server 2025. NTLMv1 lässt sich mit wenig Aufwand knacken und sollte als Erstes verschwinden – meist hilft ein LmCompatibilityLevel von 5 auf dem Client oder ein Update des Geräts.',
  help_v1sso:'Anmeldungen mit aus NTLMv1 abgeleiteten Anmeldedaten (Ereignis 4024), häufig WLAN oder VPN mit MS-CHAPv2. Ab Oktober 2026 blockiert Windows das standardmäßig – was hier steht, bricht dann.',
  help_noagent:'Rechner, an denen sich Domänenkonten per NTLM angemeldet haben, die aber keinen Agent haben – aus den NTLM-Prüfungen der Domänencontroller (4776). Oft Drucker, Geräte oder vergessene Server.',
  help_incoming:'Welche Dienste auf welchen Servern NTLM annehmen – aus den eingehenden Ereignissen 8002, 8003 und 4022 auf den Servern selbst. Das Gegenstück zu den Programmen: hier setzt man an, um NTLM serverseitig abzuschalten.',
  help_domain:'NTLM-Anmeldungen von Domänenkonten, wie die Domänencontroller sie sehen (8004, 4030–4033): von welchem Rechner zu welchem Server. Erfasst auch Rechner ohne Agent.',
  help_top:'Die Server, die am häufigsten per NTLM angesprochen werden. Ein Ziel weit oben lohnt oft einen Blick auf SPN und DNS – ein einziger Fix kann viele Einträge auf einmal erledigen.',
  help_kerberos:'Dienste, die bereits Kerberos-Tickets bekommen (4769 auf den Domänencontrollern), mit der ausgehandelten Verschlüsselung. Zeigt, was schon funktioniert – und wo noch RC4 statt AES läuft.',
  help_kacc:'Konten, die bereits Kerberos nutzen. Hilfreich als Gegenprobe: Taucht ein Konto hier und zugleich bei NTLM auf, läuft meist nur ein Teil seiner Zugriffe noch über NTLM.',
  help_agents:'Jeder Rechner mit Agent: Betriebssystem, welches Auditing dort aktiv ist, und ob er sich meldet. Wo Auditing fehlt, sieht das Dashboard NTLM auf diesem Rechner nicht.',
  help_events:'Die einzelnen Ereignisse hinter allen Zahlen. Filter aus den anderen Panels landen hier; ein Klick auf eine Zeile zeigt alle Felder mit Erklärung.',
  blk_lage:'Lage', blk_lage_p:'Wo NTLM noch läuft und warum.',
  blk_act:'Handeln', blk_act_p:'Was sich jetzt abschalten oder beheben lässt.',
  blk_det:'Details', blk_det_p:'Wer, wohin, wann – zum Nachschlagen.',
  nav_top:'Ziele', nav_kacc:'Kerberos-Konten',
  fold_open:'Aufklappen', fold_close:'Zuklappen',
  show_all:'Alle {n} anzeigen', show_less:'Weniger anzeigen',
  rdy_h:'Abschaltbereit', rdy_badge:'nächster Schritt', nav_rdy:'Abschaltbereit',
  rdy_meta:'{o} ausgehend · {i} eingehend bereit',
  rdy_intro:'Bereit heißt: Auditing an, {d} Tage beobachtet und in diesen {d} Tagen kein NTLM – dann lässt sich dort „Restrict NTLM" auf „Deny" stellen. Eingehend zählt auch, was andere Rechner und die Domänencontroller an NTLM zu dieser Maschine gesehen haben; Doppelungen und Phantome zählen nicht.',
  rdy_th_out:'Ausgehend', rdy_th_in:'Eingehend', rdy_th_obs:'Beobachtet', rdy_days:'{d} Tage',
  rdy_ready:'bereit', rdy_since:'letztes NTLM {when}', rdy_quiet:'seit {d} Tagen kein NTLM',
  rdy_busy_out:'{n}× NTLM', rdy_busy_in:'NTLM aus {w} Quellen', rdy_from:'von', rdy_last:'zuletzt {when}',
  rdy_active:'bereits gesperrt', rdy_young:'noch {r} Tage beobachten', rdy_young1:'noch 1 Tag beobachten',
  rdy_days1:'1 Tag', na_more:'… und {n} weitere, nach Anzahl sortiert – die häufigsten stehen oben.', rdy_noaudit:'Auditing aus',
  rdy_noaudit_t_out:'Ohne „Outgoing NTLM traffic: Audit all" (oder Windows 11 24H2 / Server 2025) lässt sich nicht sagen, ob ausgehend NTLM läuft.',
  rdy_noaudit_t_in:'Ohne „Audit Incoming NTLM Traffic" (oder Server 2025) lässt sich nicht sagen, ob eingehend NTLM läuft. NTLM, das andere Rechner oder die DCs zu dieser Maschine sehen, wird trotzdem erkannt.',
  rdy_stale:'Agent meldet sich nicht', rdy_stale_t:'Seit mehr als zwei Tagen keine Meldung – ohne aktuelle Daten keine Bewertung.',
  rdy_dc:'domänenweit entscheiden',
  na_h:'Rechner ohne Agent', na_badge:'aus 4776', nav_na:'Ohne Agent',
  na_intro:'Aus den NTLM-Prüfungen der Domänencontroller (4776): Rechner, an denen sich Domänenkonten per NTLM angemeldet haben, die aber keinen Agent haben. Oft genau die vergessenen Server und Geräte.',
  na_empty:'Kein NTLM von Rechnern ohne Agent im gewählten Zeitraum.',
  na_nodc:'Noch keine NTLM-Prüfungen (4776) von den Domänencontrollern – dafür braucht der Agent auf den DCs Version 2.2.0.',
  type_dc:'Domänencontroller', type_member:'Server/Client',
  b_dcval_ok:'4776 kommt an', b_dcval_ok_t:'Liefert NTLM-Prüfungen (4776) für den Phantom-Abgleich, zuletzt {when}.',
  b_dcval_none:'keine 4776', b_dcval_none_t:'Dieser DC liefert keine NTLM-Prüfungen (4776). Solange auch nur ein DC fehlt, wird kein 8001 als Phantom belegt – den Agent auf Version 2.2.0 oder neuer aktualisieren; „Anmeldeinformationen überprüfen" muss im Audit aktiv sein.',
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
  unconf_hint:'{n} unconfirmed entries hidden - show',
  unconf_chip:'Unconfirmed 8001 only',
  unconf_tag:'unconfirmed',
  unconf_expl:'This machine writes the enhanced event 4020, but none for this 8001. Whether an NTLM logon stood behind it is not settled yet: that needs every domain controller to have delivered its 4776 validations for this moment, and the account to be a domain account. Until then it is not counted in any figure.',
  unconf_hint_ph:'{n} unconfirmed entries hidden, {p} of them shown to be phantoms by the DCs - show',
  phantom_tag:'Phantom (checked by DC)',
  phantom_expl:'No domain controller validated an NTLM logon for this account within two minutes of this moment - checked against {dcs}. Windows wrote the 8001 because NTLM was on the table during negotiation; Kerberos did the logon.',
  tip_events:'Events', tip_share:'Share', tip_click:'click to filter by this',
  fl_dom:'Domain level', fl_for:'Forest level', fl_raw:'level {n}',
  fl_split_t:'Agents report different values',
  osdon_mid:'agents', osdon_old:'{n} predate Server 2019 – no 40xx events there', osbar_tip:'Counts reporting machines only, not the whole domain',
  leg_goal:'Color legend', leg_bad:'NTLMv1 · insecure', leg_old:'NTLMv2 · outdated', leg_good:'Kerberos · secure',
  range:'Time range', r24h:'24 hours', trend_hourly:'per hour', r7d:'7 days', r30d:'30 days', rall:'All',
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
  fix_unclear:'Investigate - Windows reported no known ID here',
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
  g_report:'Report', g_report_t:'Status report to print or save as PDF - for everyone who does not open the dashboard',
  more:'more', b_v1:'NTLMv1 · insecure', b_v2:'NTLMv2 · outdated', b_krb:'Kerberos · secure',
  b_dom:'NTLM (domain)', b_out:'NTLM outgoing', b_fb:'Kerberos fallback',
  hb_on:'active', hb_off:'quiet',
  au_out_on:'Outgoing', au_out_off:'Outgoing off', au_dom_on:'Domain', au_dom_off:'Domain off',
  st_open:'open', st_in_progress:'in progress', st_done:'done', again:'active again', what:'What to do?',
  search_btn:'Search', search_kbd:'Ctrl K', pal_ph:'Machine, program, account, target or panel …',
  pal_foot:'↑ ↓ select · Enter open · Esc close · machines open their detail, everything else filters the events',
  pal_none:'Nothing found for "{q}".', pal_machine:'Machine', pal_noagent:'Computer', pal_prog:'Program',
  pal_acct:'Account', pal_target:'Target', pal_panel:'Panel', pal_panel_sub:'jump',
  pal_noagent_sub:'no agent · {n}× NTLM', pal_dom_sub:'domain view · {n}×', pal_target_sub:'{n}× NTLM',
  nav_spn:'SPN', spn_h:'Kerberos configuration (SPN)', spn_badge:'{n} findings', spn_ok_badge:'all registered',
  spn_meta:'{c} checked · {o} fine', spn_th:'Service name (SPN)', spn_th_find:'Finding', spn_th_fix:'Fix',
  spn_st_missing:'missing', spn_st_alias:'alias', spn_st_duplicate:'duplicate',
  spn_d_noacct:'No account in the forest holds this name - Kerberos cannot issue a ticket. Devices without a domain account (NAS, appliances) stay on NTLM until they join the domain or get an account with this SPN.',
  spn_d_nores:'The name does not resolve in DNS and is registered nowhere. A stale name in a share, a script or a shortcut?',
  spn_d_unmapped:'HOST/{h} is registered on {a} but does not cover this service. If the service runs under its own account, the SPN belongs there.',
  spn_d_cname:'The name is an alias for {c}. The SPN is registered there but not under the alias - clients using the alias fall back to NTLM.',
  spn_d_short:'Only the full name {c} is registered; clients use the short name.',
  spn_d_dup:'Several accounts hold this SPN: {o}. The KDC then refuses the ticket. Remove it (setspn -D) from all but the account the service runs as.',
  spn_d_dup_host:'HOST/{h} is registered on several accounts: {o}. Only the server\'s computer account may hold it.',
  spn_acct_ph:'<service account>', spn_copy:'Copy', spn_copied:'copied', spn_recheck:'Check again', spn_queued:'queued',
  spn_recheck_t:'Look it up again in the next cycle of a DC agent - for instance after running the command.',
  spn_krb_t:'{n} failed Kerberos requests for this name (4769)',
  spn_nodc:'No domain controller runs agent 2.4 or later yet - it is what looks the names up in AD. Update the agent on at least one DC.',
  spn_pending:'{n} names are still waiting to be checked - a DC agent looks up to 50 per cycle.',
  spn_errors:'{n} names could not be checked - the DC agent\'s log says why.',
  spn_empty:'All {n} service names checked are registered correctly in AD.', spn_none:'No service names checked yet.',
  help_spn:'For every service name (SPN) where clients fell back to NTLM, or Kerberos failed with "SPN not found", a DC agent looks up in Active Directory whether and where it is registered - read-only, which any domain account may do. The tool changes nothing in AD; the Fix column shows the setspn command for an admin to run. setspn -S checks for duplicates before adding. In multi-domain forests run setspn in the account\'s domain. Targets in other forests cannot be checked and show as missing.',
  nav_fail:'Failed attempts', nav_acc:'Accounts', pal_failed:'{n}× failed',
  fail_h:'Failed NTLM attempts', fail_badge_spray:'Spraying?',
  fail_meta:'{n} attempts · {a} accounts',
  fail_from:'From', fail_to:'To', fail_why:'Reason', fail_locked:'locked',
  fail_to_dc:'via DC', fail_to_dc_t:'Only seen by the domain controller (4776) - the target server has no agent or no failure auditing.',
  fail_spray:'Many accounts from one machine: {l}. That is what password spraying looks like - or a script with stale credentials. Check it.',
  fail_spray_n:'{n} accounts',
  fail_blind:'On {n} machines "Audit Logon: Failure" is off - failed logons there only show up when a DC checks them.',
  fail_empty:'No failed NTLM logons in the selected range.',
  fv_local:'seen on the server', fv_dc:'seen by a DC', fv_both:'server and DC',
  nt_0xc000006a:'wrong password', nth_0xc000006a:'Usually a service, scheduled task or mapped drive with an old password on the source machine.',
  nt_0xc0000064:'no such account', nth_0xc0000064:'A mistyped or deleted account name - or someone trying names.',
  nt_0xc0000234:'account locked out', nth_0xc0000234:'The account is locked out. Find the source that keeps trying with a wrong password.',
  nt_0xc0000072:'account disabled', nth_0xc0000072:'A disabled account is still in use - look for the service, task or script.',
  nt_0xc0000193:'account expired', nth_0xc0000193:'The account has expired but is still being used.',
  nt_0xc0000071:'password expired', nth_0xc0000071:'Password expired - for service accounts: renew it or move to a gMSA.',
  nt_0xc0000224:'password must change', nth_0xc0000224:'The account has to change its password at the next logon.',
  nt_0xc000006f:'outside logon hours', nth_0xc000006f:'Logon at a restricted time.',
  nt_0xc0000070:'workstation not allowed', nth_0xc0000070:'The account may not log on from this machine (userWorkstations).',
  nt_0xc000015b:'logon type not granted', nth_0xc000015b:'The user right for this logon type is missing (e.g. "Access this computer from the network").',
  nt_0xc000006d:'logon failure', nth_0xc000006d:'A generic failure without a more specific reason.',
  nt_0xc0000133:'clock skew', nth_0xc0000133:'The machine clock is too far off the DC.',
  nt_0xc0000413:'authentication firewall', nth_0xc0000413:'Selective authentication on a trust rejected the logon.',
  acc_h:'Accounts using NTLM', acc_meta:'{n} accounts · {v} with NTLMv1',
  acc_logons:'NTLM logons', acc_ver:'Version', acc_mach:'Machines', acc_tgt:'Targets', acc_failed:'Failed', acc_krb:'Kerberos',
  acc_krb_t:'This account already gets Kerberos tickets - only part of it still runs over NTLM.',
  acc_nover:'unknown', acc_nover_t:'The events name no version (8001/8003/8004 without a matching 4624 or 40xx).',
  acc_anon:'anonymous', acc_anon_t:'Anonymous NTLM connection (null session): no credentials, often old printers, Samba/Linux queries or enumeration. Windows labels it "NTLM V1" - that is not real NTLMv1 here. Find the caller through the source machines and restrict anonymous access.',
  acc_machine:'computer account', acc_machine_t:'A computer account signs in over NTLM - usually services running as SYSTEM that cannot use Kerberos (e.g. target by IP address or a missing SPN).',
  acd_user:'user or service account', acd_last:'last seen {when}', acd_none:'There is no NTLM data for this account in the selected range.',
  acd_failed_sub:'servers and DCs', acd_mixed:'partly on Kerberos already', acd_krb_only:'Kerberos only', acd_no_krb:'no Kerberos seen',
  acd_via_agent:'agent', acd_via_server:'seen by the server', acd_via_dc:'seen by a DC',
  acd_from:'From which machines', acd_to:'To which servers', acd_fails:'Failed attempts', acd_more:'… and {n} more',
  acd_events:'Events of this account',
  help_failed:'Failed NTLM logons: on the servers with an agent (4625) and at the domain controllers (4776). One failed logon is counted once. Most common causes: stale passwords in services or tasks - and password spraying when one machine tries many accounts. Failures do not count towards the NTLM share.',
  help_accounts:'Every account that uses NTLM, from all directions: what the machines send (8001/4020), what the servers accept (8003/4022/4624) and what the DCs see (8004/4030). One logon is counted once. A click opens the account with its machines, servers, programs and failures.',
  b_out_off:'outgoing off', b_out_off_t:'"Outgoing NTLM traffic to remote servers" is not set to "Audit all" - this machine writes no 8001. Which program and account use NTLM from here stays invisible.',
  b_in_off:'incoming off', b_in_off_t:'"Audit Incoming NTLM Traffic" is off - no 8002/8003. Which service accepts NTLM here stays unknown; the logons themselves are still seen through 4624 and the DC.',
  b_dom_off:'domain off', b_dom_off_t:'"Audit NTLM authentication in this domain" is off on this DC - no 8004. The domain view is missing for everything this DC validates.',
  ag_gaps:'{n} machines lack NTLM auditing in at least one direction - NTLM stays wholly or partly invisible there. The red and amber badges name the policy.',
  r_logon:'logons', r_logon_t:'"Audit Logon: Success" is on - this machine writes 4624, NTLMv1 is recognised here.',
  b_logon_off:'no 4624', b_logon_off_t:'"Audit Logon" is set to "No Auditing" or failures only. Without successful 4624s NTLMv1 stays invisible on this machine. GPO: Advanced Audit Policy Configuration → Logon/Logoff → Audit Logon: Success.',
  b_agent_sec:'agent {v}: security update', b_agent_sec_t:'Agent versions before {s} have known security issues (among them the handling of the data folder). Please update to {s} or later.',
  b_agent_old:'agent before 2.3', b_agent_old_t:'This agent collects 4624 on DCs only - NTLMv1 stays invisible on this machine until the agent is updated to 2.3.0 or later.',
  b_logon_unk:'logon audit unknown', b_logon_unk_t:'The agent could not read the audit policy (auditpol). Whether NTLMv1 is recognised here is open.',
  v1_blind:'NTLMv1 is invisible on {n} machines - {a} without logon auditing, {b} with an agent before 2.3. To the machines panel →',
  md_loading:'Loading …', md_err:'Could not be loaded.', md_out:'Outgoing', md_in:'Incoming',
  md_in_local:'Incoming (on the machine)', md_srcs_lbl:'sources', md_local:'{n} logged here',
  md_v1:'{n} of them NTLMv1', md_v1none:'no NTLMv1', md_ready:'Switching off · last 30 days', md_progs:'Programs → targets',
  md_from:'Who reaches it over NTLM', md_users:'Accounts', md_audit:'Auditing',
  md_none_out:'No outgoing NTLM in the selected range.', md_none_in:'No incoming NTLM seen in the selected range.',
  md_via_local:'logged here', md_via_dc:'seen by a DC', md_via_cli:'reported by the client',
  md_more:'… and {n} more sources', md_seen:'last report {when}', md_since:'data since {when}',
  md_stale:'not reporting', md_agent:'agent {v}', md_type_srv:'Server', md_type_cli:'Client',
  md_filter:'Filter the dashboard to this machine', md_events:'Events of this machine',
  svc_logon:'logon, no service named (4624)', blk_short:'blocked', kpi_share:'NTLM share', kpi_vs:'vs last week', kpi_sub:'Last 7 days: {a} · week before: {b}', kpi_new:'new', kpi_pts:'pts',
  hc_l:'Handover · {r}', hc_r:'Goal: 100 % Kerberos', goal0:'Goal: 0',
  theme_light:'Light theme', theme_dark:'Dark theme',
  help_lbl:'What does this show?', menu_lbl:'Selection', orb_t:'Live - refreshes every minute',
  help_trend:'NTLM activity in the selected range - these bars should approach zero over the weeks. Red = NTLMv1, yellow = NTLMv2, grey = NTLM without version info. Kerberos is in the tooltip for context. Click a bar for the events behind it.',
  help_programs:'The work list: every program that reaches a target over NTLM, from the client events 8001 and 4020. Set a status once an entry is fixed or knowingly accepted. The line shows the last days, the red number attempts that were already blocked.',
  help_why:'Why Windows chose NTLM over Kerberos - from the reason the enhanced events 4020 to 4023 carry, and from Kerberos failures (4769). Each reason comes with the usual fix; click for the events concerned.',
  help_heat:'When NTLM happens, by weekday and hour. Bright cells outside working hours are mostly scheduled tasks, services or scripts - often the easiest ones to overlook. Click a cell for exactly that hour.',
  help_v1:'Accounts still signing in with NTLMv1 - recognised from the logons on servers and DCs (4624) and from the enhanced events of Windows 11 24H2 / Server 2025. NTLMv1 is cheap to crack and should go first - usually LmCompatibilityLevel 5 on the client or an update of the device fixes it.',
  help_v1sso:'Sign-ins with credentials derived from NTLMv1 (event 4024), often Wi-Fi or VPN with MS-CHAPv2. From October 2026 Windows blocks this by default - whatever is listed here will break then.',
  help_noagent:'Machines where domain accounts signed in with NTLM but that run no agent - from the domain controllers\' NTLM validations (4776). Often printers, devices or forgotten servers.',
  help_incoming:'Which services on which servers accept NTLM - from the incoming events 8002, 8003 and 4022 on the servers themselves. The counterpart to the programs: this is where NTLM gets switched off server-side.',
  help_domain:'NTLM sign-ins of domain accounts as the domain controllers see them (8004, 4030-4033): from which machine to which server. Covers machines without an agent too.',
  help_top:'The servers reached over NTLM most often. A target near the top is usually worth a look at SPN and DNS - a single fix can clear many entries at once.',
  help_kerberos:'Services already getting Kerberos tickets (4769 on the domain controllers), with the negotiated encryption. Shows what already works - and where RC4 still runs instead of AES.',
  help_kacc:'Accounts already using Kerberos. Useful as a cross-check: an account that appears here and under NTLM usually has only part of its access still on NTLM.',
  help_agents:'Every machine with an agent: operating system, which auditing is on there, and whether it reports in. Where auditing is missing, the dashboard cannot see NTLM on that machine.',
  help_events:'The individual events behind every number. Filters from the other panels land here; click a row for all fields with an explanation.',
  blk_lage:'Situation', blk_lage_p:'Where NTLM still runs and why.',
  blk_act:'Act', blk_act_p:'What can be switched off or fixed now.',
  blk_det:'Details', blk_det_p:'Who, where to, when - for looking things up.',
  nav_top:'Targets', nav_kacc:'Kerberos accounts',
  fold_open:'Expand', fold_close:'Collapse',
  show_all:'Show all {n}', show_less:'Show fewer',
  rdy_h:'Ready to switch off', rdy_badge:'next step', nav_rdy:'Ready',
  rdy_meta:'{o} outgoing · {i} incoming ready',
  rdy_intro:'Ready means: auditing on, watched for {d} days and no NTLM in those {d} days - then "Restrict NTLM" can be set to "Deny" there. Incoming also counts what other machines and the domain controllers saw going to this machine; duplicates and phantoms do not count.',
  rdy_th_out:'Outgoing', rdy_th_in:'Incoming', rdy_th_obs:'Watched', rdy_days:'{d} days',
  rdy_ready:'ready', rdy_since:'last NTLM {when}', rdy_quiet:'no NTLM for {d} days',
  rdy_busy_out:'{n}× NTLM', rdy_busy_in:'NTLM from {w} sources', rdy_from:'from', rdy_last:'latest {when}',
  rdy_active:'already denied', rdy_young:'{r} more days to watch', rdy_young1:'1 more day to watch',
  rdy_days1:'1 day', na_more:'… and {n} more, sorted by count - the most frequent are on top.', rdy_noaudit:'auditing off',
  rdy_noaudit_t_out:'Without "Outgoing NTLM traffic: Audit all" (or Windows 11 24H2 / Server 2025) there is no telling whether outgoing NTLM happens.',
  rdy_noaudit_t_in:'Without "Audit Incoming NTLM Traffic" (or Server 2025) there is no telling whether incoming NTLM happens. NTLM that other machines or the DCs see going to this machine is still caught.',
  rdy_stale:'agent silent', rdy_stale_t:'No report for more than two days - no verdict without current data.',
  rdy_dc:'a domain-wide decision',
  na_h:'Machines without an agent', na_badge:'from 4776', nav_na:'No agent',
  na_intro:'From the domain controllers\' NTLM validations (4776): machines where domain accounts logged on with NTLM but that run no agent. Often exactly the forgotten servers and devices.',
  na_empty:'No NTLM from machines without an agent in the selected range.',
  na_nodc:'No NTLM validations (4776) from the domain controllers yet - the agent on the DCs needs version 2.2.0 for that.',
  type_dc:'Domain controller', type_member:'Server/client',
  b_dcval_ok:'4776 arriving', b_dcval_ok_t:'Delivers NTLM validations (4776) for the phantom check, latest {when}.',
  b_dcval_none:'no 4776', b_dcval_none_t:'This DC delivers no NTLM validations (4776). While even one DC is missing, no 8001 is shown to be a phantom - update the agent to 2.2.0 or later; "Audit Credential Validation" has to be on.',
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

// ---- State ---------------------------------------------------------------
const S = {range:'30d', mach:'', hideDone:false, q:'', kind:'', acct:'all', shown:25,
           bucket:'', wd:'', hr:'', pick:'', rsn:'', unconf:''};
           // bucket/wd/hr: drill-down from the charts, pick: from the handover bar,
           // unconf: list only the unconfirmed 8001s (never counted anywhere)
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
  unconf: v => v === '1' ? v : null,
  bucket: v => /^\d{4}-\d{2}-\d{2}(T\d{2})?$/.test(v) ? v : null,
  wd:     v => /^[0-6]$/.test(v) ? v : null,
  hr:     v => /^([0-9]|1[0-9]|2[0-3])$/.test(v) ? v : null
};

// Absent parameters reset to their default rather than being left alone -
// otherwise going Back to the unfiltered view would keep the old filter in S
// while the URL claims there is none.
const URL_DEFAULTS = {range: '30d', mach: '', q: '', kind: '', acct: 'all',
                      pick: '', rsn: '', bucket: '', wd: '', hr: '', unconf: ''};

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
  // Text search runs in the database, so the list holds every match rather
  // than the matches among the newest few hundred rows.
  if(S.q) p.set('q', S.q);
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
  if(S.unconf) p.set('unconf', '1');
  if(extra) for(const k in extra) if(extra[k]) p.set(k, extra[k]);
  return p;
}
// Only the newest request may paint: when the range is switched quickly or a
// search is typed, an older answer arriving late must not overwrite a newer one.
let LOAD_SEQ = 0;
async function load(){
  const my = ++LOAD_SEQ;
  let r;
  try { r = await fetch('/api/data?' + params().toString()); }
  catch(e){ return; }
  if(r.status === 401 || r.status === 403){ window.location = '/login'; return; }
  const d = await r.json();
  if(my !== LOAD_SEQ) return;
  DATA = d;
  render();
}

// ---- Building blocks ---------------------------------------------------
const tag = (cls, txt, ti) => '<span class="tag ' + cls + '"' +
  (ti ? ' title="' + esc(ti) + '"' : '') + '>' + esc(txt) + '</span>';
const emptyBox = (a, b) => '<div class="empty"><b>' + esc(a) + '</b>' + esc(b || '') + '</div>';
// Every table on the page goes through here, so sorting added once applies to
// all of them. Sorting happens on the rendered rows rather than on the data:
// each panel shapes its own rows, and re-sorting the source would mean
// teaching this helper about a dozen different record shapes.
// Wrapped in a scroll container: between the stacked phone layout and a screen
// wide enough for all columns there is a band - roughly 760 to 1400 px - where
// the widest tables simply do not fit. The card clipped them and the data was
// unreachable. Above 1400 px nothing overflows and no scrollbar appears.
const tbl = (heads, rows) => '<div class="tw"><table class="srt"><thead><tr>' + heads.map((h, i) =>
  '<th tabindex="0" role="button" aria-sort="none" data-col="' + i + '"' +
  (h[1] ? ' class="' + h[1] + '"' : '') + '>' + esc(h[0]) + '</th>').join('') +
  '</tr></thead><tbody>' + rows + '</tbody></table></div>';

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
  clipOne(table);   // the first ten after sorting, not the first ten before
}

// On a narrow screen each row is stacked and every value needs its column name
// in front of it. Read from the table's own header rather than passed in, so
// this works for all nine tables without any of them knowing about it. Runs
// after every render because the panels rebuild their rows each time.
function labelCells(){
  document.querySelectorAll('table.srt').forEach(function(t){
    const heads = [...t.querySelectorAll('thead th')].map(h => h.textContent.trim());
    t.querySelectorAll('tbody tr').forEach(function(tr){
      [...tr.cells].forEach(function(td, i){
        if(heads[i] !== undefined) td.setAttribute('data-label', heads[i]);
      });
    });
  });
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
  '<section class="card ' + (cls || '') + (FOLDED.has(id) ? ' folded' : '') + '" id="' + id + '"><div class="ch"><h2>' + esc(title) + '</h2>' +
  (flag ? '<span class="flag ' + (flag[1] || '') + '">' + esc(flag[0]) + '</span>' : '') +
  (extra || '') + (meta ? '<span class="meta">' + esc(meta) + '</span>' : '') +
  (hasHelp(id) ? '<button type="button" class="hlp" data-help="' + id + '" aria-expanded="' + HELPOPEN.has(id) +
    '" aria-label="' + esc(t('help_lbl') + ': ' + title) + '" title="' + esc(t('help_lbl')) + '">?</button>' : '') +
  '<button type="button" class="fold" data-fold="' + id + '" aria-expanded="' + !FOLDED.has(id) + '" aria-label="' +
  esc(t(FOLDED.has(id) ? 'fold_open' : 'fold_close') + ': ' + title) + '"></button>' +
  '</div>' + (hasHelp(id) ? '<div class="cnote help" id="help-' + id + '"' + (HELPOPEN.has(id) ? '' : ' hidden') + '>' +
    esc(t(helpKey(id))) + '</div>' : '') + body + '</section>';
// "What does this show?" - a short answer per panel, one click away, so the
// dashboard also works for a colleague who has not followed the project.
const helpKey = id => 'help_' + id.replace('sec-', '');
const hasHelp = id => !!(I18N[LANG] && I18N[LANG][helpKey(id)]);
const HELPOPEN = new Set();

// ---- Folding and shortening ------------------------------------------------
// The page had grown to 13.6 screen heights on a desktop and 53 on a phone. Any
// panel folds from its header, and the choice is remembered per browser; on a
// phone that has never chosen, only the panels that say what to do are open.
// Long tables show their first ten rows with "show all n" below.
const FOLD_KEY = 'ntlm.folded';
const FOLDED = (() => {
  try {
    const v = localStorage.getItem(FOLD_KEY);
    if(v !== null) return new Set(JSON.parse(v));
  } catch(e){}
  return new Set(innerWidth <= 760 ? ['sec-why', 'sec-heat', 'sec-v1', 'sec-v1sso', 'sec-noagent',
    'sec-incoming', 'sec-domain', 'sec-top', 'sec-kerberos', 'sec-kacc', 'sec-agents'] : []);
})();
function saveFolded(){ try { localStorage.setItem(FOLD_KEY, JSON.stringify([...FOLDED])); } catch(e){} }
function setFold(id, fold){
  if(fold) FOLDED.add(id); else FOLDED.delete(id);
  saveFolded();
  const c = document.getElementById(id); if(!c) return;
  c.classList.toggle('folded', fold);
  const b = c.querySelector('.fold');
  if(b){ b.setAttribute('aria-expanded', String(!fold));
    b.setAttribute('aria-label', t(fold ? 'fold_open' : 'fold_close') + ': ' + c.querySelector('h2').textContent); }
}
const CLIP_AT = 10, CLIP_MIN = 13;   // fewer than 13 rows: not worth a button
const EXPANDED = new Set();
function clipOne(table){
  const card = table.closest('.card');
  if(!card || card.id === 'sec-events' || !table.tBodies[0]) return;
  clipRows(card, [...table.tBodies[0].rows], table.closest('.tw') || table);
}
// Bar lists (NTLMv1 accounts, targets) fold the same way as tables.
function clipBars(box){
  const card = box.closest('.card');
  if(card) clipRows(card, [...box.children], box);
}
function clipCard(card){
  const tb = card.querySelector('table'); if(tb){ clipOne(tb); return; }
  const b = card.querySelector('.bars'); if(b) clipBars(b);
}
function clipRows(card, rows, after){
  let btn = card.querySelector('.showall');
  if(rows.length < CLIP_MIN){ rows.forEach(r => r.classList.remove('clip')); if(btn) btn.remove(); return; }
  const open = EXPANDED.has(card.id);
  rows.forEach((r, i) => r.classList.toggle('clip', !open && i >= CLIP_AT));
  if(!btn){
    btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'showall'; btn.dataset.showall = card.id;
    after.insertAdjacentElement('afterend', btn);
  }
  btn.textContent = open ? t('show_less') : t('show_all', {n: rows.length});
  btn.setAttribute('aria-expanded', String(open));
}
function clipTables(){ document.querySelectorAll('#grid .card').forEach(c => { if(c.id !== 'sec-events') clipCard(c); }); }
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
const stSel = (key, st) => '<select class="sel-st st-' + esc(st || 'open') + '" data-key="' + esc(key) + '" aria-label="' + esc(t('th_status')) + '">' +
  ['open','in_progress','done'].map(v => '<option value="' + v + '"' +
    ((st || 'open') === v ? ' selected' : '') + '>' + esc(t('st_' + v)) + '</option>').join('') + '</select>';
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

// ---- Header area -------------------------------------------------------
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
  $('#range').innerHTML = [['24h', t('r24h')], ['7d', t('r7d')], ['30d', t('r30d')], ['all', t('rall')]]
    .map(r => '<button data-r="' + r[0] + '"' + (S.range === r[0] ? ' aria-pressed="true"' : '') + '>' +
      esc(r[1]) + '</button>').join('');
  // Phone: the controls live behind one button that still says what is set,
  // so the current range and machine stay visible without opening it.
  const rl = {'24h': t('r24h'), '7d': t('r7d'), '30d': t('r30d'), 'all': t('rall')}[S.range] || '';
  const mb = $('#menu');
  if(mb){ mb.innerHTML = '<span>' + esc(rl + (S.mach ? ' \u00b7 ' + S.mach : '')) + '</span><i></i>';
    mb.setAttribute('aria-label', t('menu_lbl') + ': ' + rl + (S.mach ? ', ' + S.mach : '')); }
  const orbEl = $('#orb'); if(orbEl) orbEl.title = t('orb_t');
  const sb = $('#searchbtn');
  if(sb){ $('#searchlbl').textContent = t('search_btn'); $('#searchkbd').textContent = IS_MAC ? '\u2318K' : t('search_kbd');
    sb.setAttribute('aria-label', t('search_btn') + ' (' + (IS_MAC ? 'Cmd' : 'Ctrl') + '+K)'); }
  const thb = $('#theme');
  if(thb){ const lbl = t(effTheme() === 'light' ? 'theme_dark' : 'theme_light');
    thb.setAttribute('aria-label', lbl); thb.title = lbl; }
  const src = (DATA && DATA.sources) || [];
  $('#mach').innerHTML = '<option value="">' + esc(t('g_all_mach')) + '</option>' +
    src.map(s => '<option' + (S.mach === s ? ' selected' : '') + '>' + esc(s) + '</option>').join('');
  $('#hide').textContent = t('g_hidedone');
  $('#report').textContent = t('g_report');
  $('#report').title = t('g_report_t');
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
  if(FOLDED.has('sec-events')) setFold('sec-events', false);
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
      '<circle cx="60" cy="60" r="' + R + '" fill="none" style="stroke:rgba(var(--line-rgb),.10)" stroke-width="17"/>' +
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
  // Key-figure tiles: the count for the range picked above, and how the last
  // seven days compare with the seven before - the question everyone asks
  // first. v1/v2/Kerberos filter the dashboard like the bar segments do.
  const K = DATA.kpi || null;
  const loc = LOCALE();
  const fmtN = v => (v == null ? '\u2013' : Number(v).toLocaleString(loc));
  const delta = (cur, prev, lowerIsBetter, pts) => {
    if(cur == null || prev == null) return {txt: '\u2013', cls: 'flat'};
    if(pts){ const d = Math.round((cur - prev) * 10) / 10;
      return {txt: (d > 0 ? '+' : d < 0 ? '\u2212' : '\u00b1') + Math.abs(d).toLocaleString(loc) + ' ' + t('kpi_pts'),
              cls: d === 0 ? 'flat' : ((d < 0) === lowerIsBetter ? 'good' : 'bad')}; }
    if(!prev) return cur ? {txt: t('kpi_new'), cls: lowerIsBetter ? 'bad' : 'good'} : {txt: '\u00b10 %', cls: 'flat'};
    const d = Math.round((cur - prev) / prev * 100);
    return {txt: (d > 0 ? '+' : d < 0 ? '\u2212' : '\u00b1') + Math.abs(d) + ' %',
            cls: d === 0 ? 'flat' : ((d < 0) === lowerIsBetter ? 'good' : 'bad')};
  };
  const tiles = [
    {lbl: t('kpi_share'), col: '--gold', big: pct + ' %', pick: null, series: K && K.share,
     d: K ? delta(K.cur.share, K.prev.share, true, true) : null,
     sub: K ? t('kpi_sub', {a: fmtN(K.cur.share) + ' %', b: fmtN(K.prev.share) + ' %'}) : ''},
    {lbl: t('leg_bad'), col: '--v1', big: fmtN(st.v1), pick: 'NTLMv1', series: K && K.v1,
     d: K ? delta(K.cur.v1, K.prev.v1, true) : null, sub: K ? t('kpi_sub', {a: fmtN(K.cur.v1), b: fmtN(K.prev.v1)}) : ''},
    {lbl: t('leg_old'), col: '--v2', big: fmtN(st.v2), pick: 'NTLMv2', series: K && K.v2,
     d: K ? delta(K.cur.v2, K.prev.v2, true) : null, sub: K ? t('kpi_sub', {a: fmtN(K.cur.v2), b: fmtN(K.prev.v2)}) : ''},
    {lbl: t('leg_good'), col: '--krb', big: fmtN(krb), pick: 'kerberos', series: K && K.krb,
     d: K ? delta(K.cur.krb, K.prev.krb, false) : null, sub: K ? t('kpi_sub', {a: fmtN(K.cur.krb), b: fmtN(K.prev.krb)}) : ''}];
  $('#handkey').innerHTML = tiles.map(x => {
    const tag0 = x.pick ? 'button type="button" data-pick="' + esc(x.pick) + '"' : 'div';
    const tag1 = x.pick ? 'button' : 'div';
    return '<' + tag0 + ' class="kpi' + (x.pick && S.pick === x.pick ? ' on' : '') + '">' +
      '<span class="kh"><i style="background:var(' + x.col + ')"></i>' + esc(x.lbl.split(' \u00b7 ')[0]) +
        (x.lbl.indexOf(' \u00b7 ') > 0 ? '<span class="kq"> \u00b7 ' + esc(x.lbl.split(' \u00b7 ')[1]) + '</span>' : '') + '</span>' +
      '<span class="kb"><b>' + esc(x.big) + '</b>' + kspark(x.series, x.col) + '</span>' +
      (x.d ? '<span class="kd"><em class="dlt ' + x.d.cls + '">' + esc(x.d.txt) + '<span class="kq"> ' + esc(t('kpi_vs')) + '</span></em>' +
        '<small>' + esc(x.sub) + '</small></span>' : '') + '</' + tag1 + '>';
  }).join('');
  const rl = {'24h': t('r24h'), '7d': t('r7d'), '30d': t('r30d'), 'all': t('rall')}[S.range] || '';
  $('#hc_l').textContent = t('hc_l', {r: rl});
  $('#hc_r').textContent = t('hc_r');
  $('#ddl_t').textContent = t('hero_ddl_t');
  $('#ddl_b').textContent = t('hero_ddl_b');
  countTo($('#pct'), pct);
  countTo($('#days'), Math.max(0, Math.round((new Date(2026, 9, 14) - new Date()) / 864e5)));
  const orb = $('#orb'); if(orb) orb.className = 'orb';
}
// A small line for a key-figure tile: the last fourteen days, one point each.
function kspark(v, col){
  if(!v || v.length < 2) return '';
  const vals = v.map(x => x == null ? 0 : x), mx = Math.max.apply(null, vals) || 1, W = 110, H = 34;
  const pts = vals.map((x, i) => (i * W / (vals.length - 1)).toFixed(1) + ',' + (H - 3 - x / mx * (H - 8)).toFixed(1)).join(' ');
  return '<svg class="ksp" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" aria-hidden="true">' +
    '<polygon points="0,' + H + ' ' + pts + ' ' + W + ',' + H + '" style="fill:var(' + col + ');opacity:.12"/>' +
    '<polyline points="' + pts + '" fill="none" style="stroke:var(' + col + ')" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}
const FICON = {
  big: '<path d="M4 20h16M7 16V9M12 16V5M17 16v-4"/>',
  win: '<path d="M13 3 5 14h6l-1 7 8-11h-6l1-7z"/>',
  due: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 2M9 2h6"/>',
  odd: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>'};
const ficon = (k, col) => '<span class="fi"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" ' +
  'style="stroke:var(' + col + ')" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  FICON[k] + '</svg></span>';
function renderFocus(){
  const bl = DATA.blockers || [], v1u = DATA.v1_users || [], out = [];
  if(bl.length) out.push('<button class="fc" data-prog="' + esc(bl[0].process) + '">' + ficon('big', '--gold') + '<div class="ft"><div class="k">' +
    esc(t('foc_big')) + '</div><div class="v">' + esc(bl[0].process) + '</div><div class="w">' +
    esc(t('foc_big_w', {n: bl[0].n, m: bl[0].sources})) + '</div></div></button>');
  const ip = bl.filter(b => /\d+\.\d+\.\d+\.\d+/.test(b.target || ''))[0];
  if(ip) out.push('<button class="fc" data-prog="' + esc(ip.process) + '">' + ficon('win', '--krb') + '<div class="ft"><div class="k">' +
    esc(t('foc_win')) + '</div><div class="v">' + esc(ip.process) + '</div><div class="w">' +
    esc(t('foc_win_w', {n: ip.n})) + '</div></div></button>');
  if(v1u.length) out.push('<button class="fc" data-q="' + esc(v1u[0].name) + '">' + ficon('due', '--v1') + '<div class="ft"><div class="k">' +
    esc(t('foc_due')) + '</div><div class="v">' + esc(v1u[0].name) + '</div><div class="w">' +
    esc(t('foc_due_w', {n: v1u[0].n})) + '</div></div></button>');
  let pd = -1, ph = 0, pv = 0;
  (DATA.heat || []).forEach((row, d) => row.forEach((v, h) => { if(v > pv){ pv = v; pd = d; ph = h; } }));
  // HW(pd) is the real weekday: 0 Sunday, 6 Saturday.
  if(pd >= 0 && (HW(pd) === 0 || HW(pd) === 6 || ph < 6 || ph > 19))
    out.push('<button class="fc" data-go="sec-heat">' + ficon('odd', '--v2') + '<div class="ft"><div class="k">' + esc(t('foc_odd')) +
      '</div><div class="v">' + esc(DN()[HW(pd)] + ', ' + String(ph).padStart(2, '0') + ':00') +
      '</div><div class="w">' + esc(t('foc_odd_w', {n: pv})) + '</div></div></button>');
  $('#focus').innerHTML = out.join('');
}

// ---- Panels --------------------------------------------------------------
function secTrend(){
  const tr = DATA.trend || [];
  if(!tr.length) return CARD('sec-trend', t('trend_h'), [t('leg_goal')], '',
    emptyBox(t('trend_empty'), ''), 'c2');
  // Stacked area instead of bars: NTLMv1 at the bottom, NTLMv2 and version-less
  // NTLM above, and the dashed line at zero is the goal. The shapes scale to the
  // card's width; a transparent column per bucket keeps the click-through.
  const n = tr.length, W = 1000, H = 190, top = 8;
  const tot = tr.map(b => b.v1 + b.v2 + b.other), mx = Math.max.apply(null, tot) * 1.12 || 1;
  const X = i => n === 1 ? W / 2 : i * W / (n - 1);
  const Y = v => (H - (v / mx) * (H - top)).toFixed(1);
  const layer = (lo, hi, col, op) => {
    const up = tr.map((b, i) => X(i).toFixed(1) + ',' + Y(hi(b))).join(' ');
    const dn = tr.map((b, i) => X(i).toFixed(1) + ',' + Y(lo(b))).reverse().join(' ');
    const pts = n === 1 ? ('0,' + Y(hi(tr[0])) + ' ' + W + ',' + Y(hi(tr[0])) + ' ' + W + ',' + Y(lo(tr[0])) + ' 0,' + Y(lo(tr[0]))) : (up + ' ' + dn);
    const ln = n === 1 ? ('0,' + Y(hi(tr[0])) + ' ' + W + ',' + Y(hi(tr[0]))) : up;
    return '<polygon points="' + pts + '" style="fill:var(' + col + ');opacity:' + op + '"/>' +
      '<polyline points="' + ln + '" fill="none" style="stroke:var(' + col + ')" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>';
  };
  const step = n === 1 ? W : W / (n - 1);
  const hits = tr.map((b, i) => {
    const x0 = Math.max(0, X(i) - step / 2), x1 = Math.min(W, X(i) + step / 2);
    return '<rect class="thit' + (S.bucket === b.b ? ' on' : '') + '" data-bucket="' + esc(b.b) + '" x="' + x0.toFixed(1) +
      '" y="0" width="' + (x1 - x0).toFixed(1) + '" height="' + H + '"><title>' +
      esc(b.b + ' \u00b7 ' + (b.v1 + b.v2 + b.other) + ' \u2013 ' + t('drill_hint')) + '</title></rect>';
  }).join('');
  const body = '<div class="tchart"><svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="' +
      esc(t('trend_h')) + '">' +
      [.33, .66].map(g => '<line x1="0" x2="' + W + '" y1="' + (H - g * (H - top)).toFixed(1) + '" y2="' + (H - g * (H - top)).toFixed(1) +
        '" class="tgrid" vector-effect="non-scaling-stroke"/>').join('') +
      layer(b => b.v1 + b.v2, b => b.v1 + b.v2 + b.other, '--grey', .35) +
      layer(b => b.v1, b => b.v1 + b.v2, '--v2', .22) +
      layer(b => 0, b => b.v1, '--v1', .30) +
      '<line x1="0" x2="' + W + '" y1="' + (H - 1) + '" y2="' + (H - 1) + '" class="tgoal" vector-effect="non-scaling-stroke"/>' +
      hits + '</svg><span class="tgoaltxt">' + esc(t('goal0')) + '</span></div>' +
    '<div class="axis">' + [0, .33, .66, 1].map(p => '<span>' + esc(tr[Math.round(p * (n - 1))].b) + '</span>').join('') + '</div>';
  return CARD('sec-trend', t('trend_h'), null, DATA.trend_bucket === 'day' ? '' : t('trend_hourly'), body, 'c2');
}
function secPrograms(){
  let bl = (DATA.blockers || []).slice();
  if(S.hideDone) bl = bl.filter(b => b.st !== 'done');
  const body = bl.length ? tbl([[t('th_prog')], [t('th_target')], [t('th_count'), 'r'],
      [t('th_trend2')], [t('th_users')], [t('th_status')]],
    bl.map(b => '<tr class="click' + (b.st === 'done' ? ' done' : '') +
      '" data-prog="' + esc(b.process) + '"><td class="nm">' + esc(b.process) + '</td>' +
      '<td class="mn dm"><span class="cut">' + esc(b.target || '\u2013') + '</span>' +
      (/\d+\.\d+\.\d+\.\d+/.test(b.target || '') ? ' ' + tag('v1', t('b_ip')) : '') + '</td>' +
      '<td class="r">' + b.n + (b.blocked ? '<div class="blkd">' + tag('v1', b.blocked + ' ' + t('blk_short'), t('tt_blocked')) + '</div>' : '') + '</td>' +
      '<td class="nw">' + spark((DATA.spark || {})[b.process]) + '</td>' +
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
  const rows = (DATA.v1_users || []).map(u => [u.name, u.n]);
  // An empty list only means something if every machine can see NTLMv1. Say
  // how many cannot, so "no NTLMv1" is never mistaken for "all clear".
  const ag = DATA.agents || [];
  const off = ag.filter(m => v1Sight(m) === 'off').length, old = ag.filter(m => v1Sight(m) === 'old').length;
  const blind = off || old ? '<button type="button" class="v1blind" data-go="sec-agents">' +
    esc(t('v1_blind', {n: off + old, a: off, b: old})) + '</button>' : '';
  return CARD('sec-v1', t('v1_h'), [t('b_deadline'), 'due'], '',
    blind + (bars(rows, 'red', n => 'data-q="' + esc(n) + '"') || emptyBox(t('empty_v1'), '')));
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
    d.map(x => '<tr class="click" data-q="' + esc(x.workstation) + '">' +
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
    i.map(x => '<tr class="click" data-machine="' + esc(x.machine) + '"><td class="nm">' + esc(x.machine) +
      '</td><td class="dm">' + esc(x.process === '(unknown)' ? t('svc_logon') : x.process) + '</td><td class="r">' + x.n + '</td>' +
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
    k.map(x => '<tr class="click" data-q="' + esc(x.account) + '">' +
      '<td class="mn"><span class="cut">' + esc(x.account) + '</span></td>' +
      '<td class="r dm">' + x.svc_count + '</td><td class="r">' + x.n + '</td>' +
      '<td>' + encTags(x.enc) + '</td></tr>').join(''))
    : emptyBox(t('empty_krba'), '');
  return CARD('sec-kacc', t('krba_h'), [t('leg_good'), 'ok'], '', body, 'c2');
}
// Can this machine show NTLMv1 at all? It needs 4624s: from agent 2.3 on every
// machine, before that only on DCs - and "Audit Logon: Success" either way.
//   ok  - logon auditing on        off - off or failures only
//   old - agent before 2.3 on a non-DC (sends no 4624 from here)
//   unk - agent 2.3+ that could not read the policy
// Oldest agent without known security issues.
const AGENT_SECURE = '2.3.1';
function verLt(a, b){
  const p = s => String(s || '0').split('.').map(x => parseInt(x, 10) || 0);
  const x = p(a), y = p(b);
  for(let i = 0; i < 3; i++){ if((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0); }
  return false;
}
function v1Sight(m){
  if(m.logon_audit === 'success' || m.logon_audit === 'success_failure') return 'ok';
  if(m.logon_audit === 'none' || m.logon_audit === 'failure') return 'off';
  if(!m.is_dc && verLt(m.agent_version, '2.3.0')) return 'old';
  if(m.logon_audit === 'unknown') return 'unk';
  return '';
}
// Audit badges, LmCompat and the October verdict of one agent - shared by the
// machines panel and the machine detail, so both always say the same.
function agentBadges(m){
  const au = [];
  // Each missing audit is named: a machine without it sends nothing for that
  // direction, and an absent green badge alone is too easy to overlook.
  if(m.outgoing_audit === 'off') au.push(tag('v1', t('b_out_off'), t('b_out_off_t')));
  else if(m.outgoing_audit) au.push(tag('krb', t('r_out')));
  if(m.incoming_audit === 'off') au.push(tag('v2', t('b_in_off'), t('b_in_off_t')));
  else if(m.incoming_audit) au.push(tag('krb', t('r_in')));
  if(m.is_dc && m.domain_audit === 'off') au.push(tag('v1', t('b_dom_off'), t('b_dom_off_t')));
  else if(m.domain_audit === 'on') au.push(tag('krb', t('r_dom')));
  // Logon auditing decides whether NTLMv1 is visible on this machine at all.
  const v1 = v1Sight(m);
  if(v1 === 'ok') au.push(tag('krb', t('r_logon'), t('r_logon_t')));
  else if(v1 === 'off') au.push(tag('v1', t('b_logon_off'), t('b_logon_off_t')));
  else if(v1 === 'old') au.push(tag('v2', t('b_agent_old'), t('b_agent_old_t')));
  else if(v1 === 'unk') au.push(tag('n', t('b_logon_unk'), t('b_logon_unk_t')));
  if(m.cg) au.push(tag('v1', t('b_cg_machine', {n: m.cg})));
  // Agents before AGENT_SECURE have known security issues (see SECURITY.md
  // and the release notes) - the badge is how an admin finds them.
  if(m.agent_version && verLt(m.agent_version, AGENT_SECURE))
    au.push(tag('v1', t('b_agent_sec', {v: m.agent_version}), t('b_agent_sec_t', {s: AGENT_SECURE})));
  // A DC that sends no 4776 blocks every phantom verdict - say which one.
  if(m.is_dc) au.push(m.dcval
    ? tag('krb', t('b_dcval_ok'), t('b_dcval_ok_t', {when: when(m.dcval_last)}))
    : tag('v2', t('b_dcval_none'), t('b_dcval_none_t')));
  if(m.ntlm_log_kb && +m.ntlm_log_kb < 20480) au.push(tag('v2', t('b_logsize')));
  const lm = m.lm_level;
  const oct = m.cred_guard === 'on' ? tag('krb', t('oct_cg'))
    : m.block_v1sso === 'deny' ? tag('krb', t('oct_enf'))
    : lm && +lm >= 4 ? tag('v2', t('oct_aff')) : tag('n', t('oct_unk'));
  const lmTag = lm ? tag(+lm >= 5 ? 'krb' : +lm >= 3 ? 'v2' : 'v1', 'LmCompat ' + lm) : '';
  return {au: au, oct: oct, lm: lmTag};
}
// Machines whose auditing leaves NTLM unseen in some direction.
function auditGaps(m){
  const g = [];
  if(m.outgoing_audit === 'off') g.push('out');
  if(m.incoming_audit === 'off') g.push('in');
  if(m.is_dc && m.domain_audit === 'off') g.push('dom');
  if(v1Sight(m) === 'off') g.push('logon');
  return g;
}
function secAgents(){
  const a = DATA.agents || [];
  const gaps = a.filter(m => auditGaps(m).length).length;
  const body = a.length ? tbl([[t('th_machine')], [t('th_type')], [t('th_status2')], ['LmCompat'],
      [t('th_oct')], [t('th_count'), 'r'], [t('th_last')]],
    a.map(m => {
      const b = agentBadges(m), au = b.au, lm = m.lm_level, oct = b.oct;
      return '<tr class="click" data-machine="' + esc(m.source) + '"><td class="nm">' + esc(m.source) +
        ' ' + (m.is_dc ? tag('n', t('type_dc')) : '') + '</td>' +
        '<td class="dm">' + esc(m.os_version || '\u2013') +
        (m.os_version && !/2600\d|2[6-9]\d{3}/.test(m.os_version) ? ' ' + tag('n', t('b_os_old')) : '') + '</td>' +
        '<td>' + (au.join(' ') || '<span class="dm">\u2013</span>') + '</td>' +
        '<td>' + (lm ? tag(+lm >= 5 ? 'krb' : +lm >= 3 ? 'v2' : 'v1', lm) : '<span class="dm">\u2013</span>') + '</td>' +
        '<td>' + oct + '</td><td class="r">' + (m.events || 0) + '</td>' +
        '<td class="mn dm">' + when(m.last_seen) + '</td></tr>'; }).join(''))
    : emptyBox(t('empty_agents'), '');
  return CARD('sec-agents', t('ag_h'), null,
    t('cov_ok', {d: DATA.stats.coverage_days}), (gaps ? '<div class="v1blind" style="cursor:default">' + esc(t('ag_gaps', {n: gaps})) + '</div>' : '') + body, 'c2');
}
// ---- Ready to switch off -----------------------------------------------
function rdyCell(v, dir, compact){
  if(!v) return '<span class="dm">\u2013</span>';
  const note = x => '<div class="rdd">' + x + '</div>';
  switch(v.st){
    case 'ready':
      return tag('krb', t('rdy_ready')) +
        note(esc(v.since ? t('rdy_since', {when: when(v.since)}) : t('rdy_quiet', {d: v.d})));
    case 'busy': {
      // Some events name no source machine or process - leave the gap out
      // rather than print a placeholder.
      const dash = v => v ? esc(v) : '\u2013';
      const items = (v.top || []).map(x => dir === 'out'
        ? dash(x[0]) + ' \u2192 ' + dash(x[1]) + ' <span class="dm">(' + x[2] + ')</span>'
        : dash(x[0]) + (x[1] ? ' <span class="dm">' + esc(t('rdy_from')) + '</span> ' + esc(x[1]) : '') +
          ' <span class="dm">(' + x[2] + ')</span>');
      // compact: the machine detail lists the programs right below, so the
      // verdict there needs only the status and when NTLM was last seen.
      return tag('v2', dir === 'out' ? t('rdy_busy_out', {n: v.n}) : t('rdy_busy_in', {w: v.who})) +
        (compact ? '' : note(items.join('<br>'))) + note(esc(t('rdy_last', {when: when(v.last)})));
    }
    case 'active':  return tag('krb', t('rdy_active'));
    case 'young': {
      const r = Math.max(1, ((DATA.readiness || {}).quiet_days || 30) - v.d);
      return tag('n', r === 1 ? t('rdy_young1') : t('rdy_young', {r: r}));
    }
    case 'noaudit': return tag('n', t('rdy_noaudit'), t('rdy_noaudit_t_' + dir));
    case 'stale':   return tag('v1', t('rdy_stale'), t('rdy_stale_t'));
    case 'dc':      return '<span class="rdd" style="margin:0">' + esc(t('rdy_dc')) + '</span>';
  }
  return '<span class="dm">\u2013</span>';
}
function secReady(){
  const r = DATA.readiness || {rows: []}, rows = r.rows || [];
  const body = rows.length
    ? '<div class="cnote">' + esc(t('rdy_intro', {d: r.quiet_days || 30})) + '</div>' +
      tbl([[t('th_machine')], [t('rdy_th_out')], [t('rdy_th_in')], [t('rdy_th_obs'), 'r']],
        rows.map(x => '<tr class="click" data-machine="' + esc(x.machine) + '">' +
          '<td class="nm">' + esc(x.machine) + (x.is_dc ? ' ' + tag('n', t('type_dc')) : '') + '</td>' +
          '<td>' + rdyCell(x.out, 'out') + '</td><td>' + rdyCell(x['in'], 'in') + '</td>' +
          '<td class="r dm">' + esc(x.obs === 1 ? t('rdy_days1') : t('rdy_days', {d: x.obs})) + '</td></tr>').join(''))
    : emptyBox(t('empty_agents'), '');
  return CARD('sec-ready', t('rdy_h'), [t('rdy_badge'), 'ok'],
    t('rdy_meta', {o: r.out_ready || 0, i: r.in_ready || 0}), body, 'c2');
}
// ---- Machines without an agent --------------------------------------------
function secAgentless(){
  const a = DATA.agentless || {rows: [], dcs: 0}, rows = a.rows || [];
  const body = rows.length
    ? tbl([[t('th_comp')], [t('th_users')], [t('th_count3'), 'r'], [t('th_last')]],
        rows.map(x => '<tr><td class="nm">' + esc(x.machine) + '</td>' +
          '<td class="dm">' + nameList((x.who || []).join(','), 3) +
          (x.users > (x.who || []).length ? ' <span class="dm">+' + (x.users - x.who.length) + '</span>' : '') + '</td>' +
          '<td class="r">' + x.n + '</td><td class="mn dm">' + when(x.last) + '</td></tr>').join('')) +
      ((a.total || rows.length) > rows.length ? '<div class="cnote" style="padding-top:12px">' +
        esc(t('na_more', {n: a.total - rows.length})) + '</div>' : '')
    : emptyBox(a.dcs ? t('na_empty') : t('na_nodc'), '');
  return CARD('sec-noagent', t('na_h'), [t('na_badge')], String(a.total || rows.length), body);
}
const blk = k => '<div class="blk" id="blk-' + k + '"><h2>' + esc(t('blk_' + k)) + '</h2><p>' +
  esc(t('blk_' + k + '_p')) + '</p></div>';
// ---- Failed NTLM attempts ----------------------------------------------
// NT status as text, with what usually lies behind it.
const ntText = c => c ? (I18N[LANG]['nt_' + String(c).toLowerCase()] ? t('nt_' + String(c).toLowerCase()) : c) : '–';
const ntHint = c => c && I18N[LANG]['nth_' + String(c).toLowerCase()] ? t('nth_' + String(c).toLowerCase()) : '';
const viaTxt = v => t('fv_' + v);
function secFailed(){
  const F = DATA.failures || {rows: [], spray: []}, rows = F.rows || [];
  const fmt = n => Number(n || 0).toLocaleString(LOCALE());
  const notes = (F.spray || []).length
    ? '<div class="v1blind bad">' + esc(t('fail_spray', {l: F.spray.map(x => x[0] + ' (' + t('fail_spray_n', {n: x[1]}) + ')').join(', ')})) + '</div>' : '';
  const blind = F.blind ? '<div class="v1blind" style="cursor:default">' + esc(t('fail_blind', {n: F.blind})) + '</div>' : '';
  const body = rows.length
    ? notes + blind + tbl([[t('th_account')], [t('fail_from')], [t('fail_to')], [t('fail_why')], [t('th_count'), 'r'], [t('th_last')]],
        rows.map(x => '<tr class="click" data-account="' + esc(x.key) + '"><td class="nm">' + esc(x.user) +
          (x.locked ? ' ' + tag('v1', t('fail_locked'), t('nth_0xc0000234')) : '') + '</td>' +
          '<td class="mn">' + esc(x.from || '–') + '</td>' +
          '<td class="mn dm">' + (x.to.length ? esc(x.to.join(', ')) : '<span title="' + esc(t('fail_to_dc_t')) + '">' + esc(t('fail_to_dc')) + '</span>') + '</td>' +
          '<td><span title="' + esc(ntHint(x.code) + (x.code ? ' (' + x.code + ')' : '')) + '">' + esc(ntText(x.code)) + '</span>' +
          '<div class="rdd">' + esc(viaTxt(x.via)) + '</div></td>' +
          '<td class="r">' + fmt(x.n) + '</td><td class="mn dm">' + when(x.last) + '</td></tr>').join(''))
    : blind + emptyBox(t('fail_empty'), '');
  return CARD('sec-failed', t('fail_h'), (F.spray || []).length ? [t('fail_badge_spray'), 'due'] : null,
    F.total ? t('fail_meta', {n: fmt(F.n), a: fmt(F.accounts)}) : '', body, 'c2');
}
// ---- Kerberos configuration (SPN) ------------------------------------------
// Service names clients asked for, looked up in AD by a DC agent. The fix is
// built here rather than on the server so its placeholder is in the viewer's
// language; the collector never runs it, it only shows it.
const spnHost = spn => spn.split('/')[1].split(':')[0];
function spnFix(x){
  if(x.status === 'duplicate') return 'setspn -Q ' + (x.detail === 'dup_host' ? 'HOST/' + spnHost(x.spn) : x.spn);
  return 'setspn -S ' + x.spn + ' ' + (x.account || t('spn_acct_ph'));
}
function secSpn(){
  const P = DATA.spn || {rows: []}, rows = P.rows || [];
  const fmt = n => Number(n || 0).toLocaleString(LOCALE());
  const cls = {missing: 'v1', duplicate: 'v1', alias: 'v2'};
  let notes = '';
  if(!P.capable) notes += '<div class="v1blind" style="cursor:default">' + esc(t('spn_nodc')) + '</div>';
  if(P.errors) notes += '<div class="v1blind" style="cursor:default">' + esc(t('spn_errors', {n: fmt(P.errors)})) + '</div>';
  if(P.capable && P.pending) notes += '<div class="cnote">' + esc(t('spn_pending', {n: fmt(P.pending)})) + '</div>';
  const body = rows.length
    ? notes + tbl([[t('spn_th')], [t('spn_th_find')], [t('th_account')], [t('th_count'), 'r'], [t('spn_th_fix')]],
        rows.map(x => { const cmd = spnFix(x);
          return '<tr><td class="mn">' + esc(x.spn) + '</td>' +
          '<td>' + tag(cls[x.status] || 'n', t('spn_st_' + x.status)) +
          '<div class="rdd">' + esc(t('spn_d_' + x.detail, {h: spnHost(x.spn), a: x.account || '', c: x.canonical || '',
            o: (x.owners || []).join(', ')})) + '</div></td>' +
          '<td class="mn dm">' + esc(x.account || (x.owners || []).join(', ') || '–') + '</td>' +
          '<td class="r">' + fmt(x.n) + (x.krb ? ' ' + tag('v2', 'krb ' + fmt(x.krb), t('spn_krb_t', {n: x.krb})) : '') + '</td>' +
          '<td><code class="cmd">' + esc(cmd) + '</code><div class="cmdb">' +
          '<button type="button" class="cpy" data-copy="' + esc(cmd) + '">' + esc(t('spn_copy')) + '</button>' +
          '<button type="button" class="cpy" data-recheck="' + esc(x.spn) + '" title="' + esc(t('spn_recheck_t')) + '">' +
          esc(t('spn_recheck')) + '</button></div></td></tr>'; }).join(''))
    : notes + emptyBox(P.checked ? t('spn_empty', {n: fmt(P.checked)}) : t('spn_none'), '');
  const flag = rows.length ? [t('spn_badge', {n: fmt(P.total || rows.length)}), 'due']
    : P.checked ? [t('spn_ok_badge'), 'ok'] : null;
  return CARD('sec-spn', t('spn_h'), flag, P.checked ? t('spn_meta', {c: fmt(P.checked), o: fmt(P.ok)}) : '', body, 'c2');
}
// ---- Accounts using NTLM ------------------------------------------------
function secAccounts(){
  const A = DATA.accounts || {rows: []}, rows = A.rows || [];
  const fmt = n => Number(n || 0).toLocaleString(LOCALE());
  const body = rows.length
    ? tbl([[t('th_account')], [t('acc_logons'), 'r'], [t('acc_ver')], [t('acc_mach'), 'r'], [t('acc_tgt'), 'r'],
          [t('acc_failed'), 'r'], [t('acc_krb'), 'r'], [t('th_last')]],
        rows.map(x => '<tr class="click" data-account="' + esc(x.key) + '"><td class="nm">' + esc(x.name) +
          (x.key === 'ANONYMOUS LOGON' ? ' ' + tag('v2', t('acc_anon'), t('acc_anon_t'))
            : /\$$/.test(x.key) ? ' ' + tag('n', t('acc_machine'), t('acc_machine_t')) : '') + '</td>' +
          '<td class="r">' + fmt(x.n) + '</td>' +
          '<td>' + (x.v1 ? tag('v1', 'v1 ' + fmt(x.v1)) + ' ' : '') + (x.v2 ? tag('v2', 'v2 ' + fmt(x.v2)) : '') +
            (!x.v1 && !x.v2 && x.n ? '<span class="dm" title="' + esc(t('acc_nover_t')) + '">' + esc(t('acc_nover')) + '</span>' : '') + '</td>' +
          '<td class="r dm">' + fmt(x.machines) + '</td><td class="r dm">' + fmt(x.targets) + '</td>' +
          '<td class="r">' + (x.failed ? '<span style="color:var(--v1)">' + fmt(x.failed) + '</span>' : '<span class="dm">0</span>') + '</td>' +
          '<td class="r">' + (x.krb ? '<span style="color:var(--krb)" title="' + esc(t('acc_krb_t')) + '">' + fmt(x.krb) + '</span>' : '<span class="dm">0</span>') + '</td>' +
          '<td class="mn dm">' + when(x.last) + '</td></tr>').join(''))
    : emptyBox(t('empty_events'), '');
  return CARD('sec-accounts', t('acc_h'), [t('nav_label')], t('acc_meta', {n: fmt(A.total || 0), v: fmt(A.v1 || 0)}), body, 'c2');
}
function secEvents(){
  return CARD('sec-events', t('ev_h'), null, '\u2013',
    '<div class="bar"><input class="search" id="q" placeholder="' + esc(t('search_ph')) + '">' +
    '<div class="chipset" id="kinds"></div></div><div class="active" id="active"></div>' +
    '<div id="events"></div>', 'call');
}
// The phantom verdict names the DCs it was checked against, so a reader can
// tell at once whether one is missing from the list.
function dcText(key){
  const dcs = (DATA && DATA.stats && DATA.stats.dcs) || [];
  return t(key, {dcs: dcs.length ? dcs.join(', ') : '\u2013'});
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
  if(S.unconf) act.push(['unconf', t('unconf_chip')]);
  if(S.pick) act.push(['pick', S.pick === 'kerberos' ? 'Kerberos' : S.pick]);
  if(S.bucket) act.push(['bucket', t('f_day') + ': ' + S.bucket]);
  if(S.wd !== '' || S.hr !== ''){
    const nm = DN();
    act.push(['when', (S.wd !== '' ? nm[+S.wd] + ' ' : '') +
                      (S.hr !== '' ? String(S.hr).padStart(2, '0') + ':00' : '')]);
  }
  // Unconfirmed 8001s are never counted, and never mixed into this list: the
  // hint says how many exist in the current range and offers them on their own.
  const nUnc = (DATA.stats && DATA.stats.unconfirmed) || 0;
  const nPh = (DATA.stats && DATA.stats.phantom) || 0;
  const fmt = v => v.toLocaleString(LANG === 'de' ? 'de-DE' : 'en-GB');
  const hint = (!S.unconf && nUnc > 0)
    ? '<button class="unchint" data-unconf="1" title="' + esc(t('unconf_expl')) + '">' +
      esc(nPh > 0 ? t('unconf_hint_ph', {n: fmt(nUnc), p: fmt(nPh)}) : t('unconf_hint', {n: fmt(nUnc)})) +
      '</button>'
    : '';
  $('#active').innerHTML = (act.length ? act.map(a => '<span class="afl">' + esc(a[1]) +
    '<button data-clr="' + a[0] + '">&times;</button></span>').join('') +
    '<button class="clearall" data-clr="all">' + esc(t('again')) + '</button>' : '') + hint;
  if(!list.length){ $('#events').innerHTML = emptyBox(t('empty_events'), ''); return; }
  $('#events').innerHTML = tbl([[t('th_time')], [t('th_kind')], [t('th_users')], [t('th_prog')],
      [t('th_target')], [t('th_comp')], ['ID', 'r']],
    list.slice(0, S.shown).map((e, i) => '<tr class="click" data-ev="' + i + '">' +
      '<td class="mn dm">' + when(e.event_time) + '</td>' +
      '<td>' + tag(KINDC[e.kind] || 'n', kindName(e.kind)) +
        (e.ntlm_version ? ' ' + tag(e.ntlm_version === 'NTLMv1' ? 'v1' : 'v2', e.ntlm_version) : '') +
        (S.unconf ? ' ' + (e.verdict === 'phantom'
          ? tag('unc ph', t('phantom_tag'), dcText('phantom_expl'))
          : tag('unc', t('unconf_tag'), t('unconf_expl'))) : '') + '</td>' +
      '<td>' + esc(e.user || '\u2013') + '</td>' +
      '<td class="dm">' + esc(e.process || '\u2013') + '</td>' +
      '<td class="mn dm"><span class="cut">' + esc(e.target_server || e.workstation || '\u2013') + '</span></td>' +
      '<td class="dm">' + esc(e.source) + '</td>' +
      '<td class="r dm">' + e.event_id + '</td></tr>').join('')) +
    (list.length > S.shown ? '<button class="more" id="more">' + esc(t('more')) + '</button>' : '');
  window.__EVLIST = list;
}
function renderJump(){
  // Counts are what is there, not how much was fetched: lists are capped at 50
  // rows server-side and the event list loads 300 - "Events 300" next to 5,533
  // real ones was simply wrong.
  const cap = v => v >= 500 ? '500+' : v;
  const R = DATA.readiness || {}, A = DATA.agentless || {};
  const groups = [
    ['lage', [['sec-trend', 'trend_h', null], ['sec-programs', 'nav_prog', cap((DATA.blockers || []).length)],
      ['sec-why', 'nav_why', (DATA.reasons || []).length], ['sec-heat', 'nav_heat', null]]],
    ['act', [['sec-ready', 'nav_rdy', (R.rows || []).filter(x => x.out.st === 'ready' || x['in'].st === 'ready').length],
      ['sec-v1', 'nav_v1', cap((DATA.v1_users || []).length)], ['sec-v1sso', 'nav_v1sso', (DATA.v1sso || []).length],
      ['sec-failed', 'nav_fail', (DATA.failures || {}).total || 0],
      ['sec-spn', 'nav_spn', (DATA.spn || {}).total || 0],
      ['sec-noagent', 'nav_na', A.total || 0], ['sec-incoming', 'nav_inc', cap((DATA.incoming || []).length)]]],
    ['det', [['sec-accounts', 'nav_acc', (DATA.accounts || {}).total || 0],
      ['sec-domain', 'nav_dom', cap((DATA.domain || []).length)], ['sec-top', 'nav_top', null],
      ['sec-kerberos', 'nav_krb', cap((DATA.kerberos || []).length)],
      ['sec-kacc', 'nav_kacc', cap((DATA.kerberos_accounts || []).length)],
      ['sec-agents', 'nav_mach', (DATA.agents || []).length],
      ['sec-events', 'nav_ev', DATA.events_total != null ? DATA.events_total : (DATA.events || []).length]]]];
  const fmt = v => typeof v === 'number' ? v.toLocaleString(LOCALE()) : v;
  $('#jump').innerHTML = groups.map(g => '<span class="jg">' + esc(t('blk_' + g[0])) + '</span>' +
    g[1].map(x => '<button class="jl' + (x[2] === 0 ? ' nil' : '') + '" data-go="' + x[0] + '">' + esc(t(x[1])) +
      (x[2] === null ? '' : ' <b>' + fmt(x[2]) + '</b>') + '</button>').join('')).join('');
}
// Mark the section being read in the bar, so it doubles as "where am I": the
// panel whose top edge last passed under the pinned bars. An IntersectionObserver
// band was ambiguous - the panel before was often still inside it.
// --stick is the real height of what is pinned (the bar wraps to two rows on
// many screens), so jumping to a panel no longer hides its title underneath.
function stickH(){
  const hd = document.querySelector('header'), jp = $('#jump');
  const h = (hd && getComputedStyle(hd).position === 'sticky' ? hd.offsetHeight : 0) + (jp ? jp.offsetHeight : 0);
  document.documentElement.style.setProperty('--stick', h + 'px');
  return h;
}
let SPY_Y = 150, SPY_RAF = 0;
function spyUpdate(){
  SPY_RAF = 0;
  let cur = null;
  for(const c of document.querySelectorAll('#grid .card')){
    if(c.getBoundingClientRect().top <= SPY_Y) cur = c.id;
  }
  document.querySelectorAll('#jump .jl').forEach(b => b.classList.toggle('on', b.dataset.go === cur));
}
function spy(){ SPY_Y = stickH() + 24; spyUpdate(); }
addEventListener('scroll', () => { if(!SPY_RAF) SPY_RAF = requestAnimationFrame(spyUpdate); }, {passive: true});
addEventListener('resize', () => { SPY_Y = stickH() + 24; });

// ---- Drawer ------------------------------------------------------------
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
    (S.unconf ? (e.verdict === 'phantom'
      ? '<div class="expl unc ph"><b>' + esc(t('phantom_tag')) + '</b>' + esc(dcText('phantom_expl')) + '</div>'
      : '<div class="expl unc"><b>' + esc(t('unconf_tag')) + '</b>' + esc(t('unconf_expl')) + '</div>') : '') +
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
      '<button data-machine="' + esc(e.source) + '">' + esc(e.source) + '</button>' +
      '<button data-kind="' + esc(e.kind) + '">' + esc(kindName(e.kind)) + '</button></div>';
  openDrawer();
}
function openExceptions(){
  const rows = (DATA.blockers || []).filter(b => b.st !== 'done' && b.target);
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
// ---- Machine detail -------------------------------------------------------
// One machine at a glance, in the side drawer: what it sends, who reaches it,
// whether it is ready to switch off, and how it is audited. Filtering the whole
// dashboard to it is one button away rather than the only thing a click did.
let MD_TOK = 0;
function openMachine(name){
  const tok = ++MD_TOK; ++AC_TOK;
  $('#dtitle').textContent = name;
  $('#dwhen').textContent = '';
  $('#dbody').innerHTML = '<div class="md"><div class="md-load">' + esc(t('md_loading')) + '</div></div>';
  openDrawer();
  const q = new URLSearchParams({name: name, range: S.range, tzoff: String(TZOFF())});
  fetch('/api/machine?' + q.toString(), {credentials: 'same-origin'})
    .then(r => r.json())
    .then(d => { if(tok === MD_TOK) renderMachine(d); })
    .catch(() => { if(tok === MD_TOK) $('#dbody').innerHTML = '<div class="md"><div class="md-load">' + esc(t('md_err')) + '</div></div>'; });
}
let AC_TOK = 0;
// Same normalisation as user_key() on the server: "DOM\\user" and
// "user@dom" become "USER". The detail is always asked for by that key, so
// every panel and the search reach the same answer.
function acctKey(u){
  u = String(u || '').trim();
  if(u.indexOf('@') > -1) u = u.split('@')[0];
  else if(u.indexOf('\\') > -1) u = u.split('\\')[1];
  return u.toUpperCase();
}
function openAccount(name){
  const tok = ++AC_TOK; ++MD_TOK;
  $('#dtitle').textContent = name;
  name = acctKey(name);
  $('#dwhen').textContent = '';
  $('#dbody').innerHTML = '<div class="md"><div class="md-load">' + esc(t('md_loading')) + '</div></div>';
  openDrawer();
  const q = new URLSearchParams({name: name, range: S.range, tzoff: String(TZOFF())});
  fetch('/api/account?' + q.toString(), {credentials: 'same-origin'})
    .then(r => r.json())
    .then(d => { if(tok === AC_TOK) renderAccount(d); })
    .catch(() => { if(tok === AC_TOK) $('#dbody').innerHTML = '<div class="md"><div class="md-load">' + esc(t('md_err')) + '</div></div>'; });
}
function renderAccount(d){
  if(!d || d.unknown){ $('#dbody').innerHTML = '<div class="md"><div class="md-load">' + esc(t('acd_none')) + '</div></div>'; return; }
  $('#dtitle').textContent = d.name;
  // Last activity of any kind: an account that only fails still has a "last seen".
  const last = [d.last].concat(d.failed.rows.map(x => x.last)).filter(Boolean).sort().pop();
  $('#dwhen').textContent = [d.anonymous ? t('acc_anon') : d.machine_account ? t('acc_machine') : t('acd_user'),
    last ? t('acd_last', {when: when(last)}) : ''].filter(Boolean).join(' · ');
  const sec = (h, inner) => '<div class="md-sec"><div class="md-h">' + esc(h) + '</div>' + inner + '</div>';
  const fmt = v => Number(v || 0).toLocaleString(LOCALE());
  const known = new Set((DATA.agents || []).map(a => String(a.source).toUpperCase()));
  const mach = m => known.has(String(m).toUpperCase())
    ? '<button type="button" class="md-link" data-machine="' + esc(m) + '">' + esc(m) + '</button>' : esc(m);
  const note = d.anonymous ? '<div class="cnote help" style="margin:14px 0 0">' + esc(t('acc_anon_t')) + '</div>'
    : d.machine_account ? '<div class="cnote help" style="margin:14px 0 0">' + esc(t('acc_machine_t')) + '</div>' : '';
  const kpis = '<div class="md-kpis md-k3">' +
    '<div class="md-k"><span>' + esc(t('acc_logons')) + '</span><b>' + fmt(d.n) + '</b>' +
      (d.v1 ? tag('v1', t('md_v1', {n: fmt(d.v1)})) : '<em>' + esc(d.n ? t('md_v1none') : '–') + '</em>') + '</div>' +
    '<div class="md-k"><span>' + esc(t('acc_failed')) + '</span><b' + (d.failed.n ? ' style="color:var(--v1)"' : '') + '>' +
      fmt(d.failed.n) + '</b><em>' + esc(t('acd_failed_sub')) + '</em></div>' +
    '<div class="md-k"><span>' + esc(t('acc_krb')) + '</span><b' + (d.krb ? ' style="color:var(--krb)"' : '') + '>' + fmt(d.krb) + '</b><em>' +
      esc(d.krb && d.n ? t('acd_mixed') : d.krb ? t('acd_krb_only') : t('acd_no_krb')) + '</em></div></div>';
  const chart = (d.series && d.series.n && Math.max.apply(null, d.series.n) > 0)
    ? mdChart({b: d.series.b, out: d.series.n, label: t('acc_logons')}) : '';
  const via = {agent: t('acd_via_agent'), server: t('acd_via_server'), dc: t('acd_via_dc')};
  const list = (rows, fn, more) => rows.length ? '<div class="md-list">' + rows.map(fn).join('') +
    (more > rows.length ? '<div class="md-more">' + esc(t('acd_more', {n: more - rows.length})) + '</div>' : '') + '</div>'
    : '<div class="md-none">–</div>';
  const from = sec(t('acd_from'), list(d.from, x => '<div class="md-row"><span>' + mach(x[0]) +
    ' <span class="md-via">' + esc(via[x[2]] || '') + '</span></span><span class="n">' + fmt(x[1]) + '</span></div>', d.from_total));
  const to = sec(t('acd_to'), list(d.to, x => '<div class="md-row"><span>' + mach(x[0]) + '</span><span class="n">' + fmt(x[1]) + '</span></div>', d.to_total));
  const progs = d.programs.length ? sec(t('md_progs'), '<div class="md-list">' + d.programs.map(x =>
      '<button type="button" class="md-row" data-prog="' + esc(x[0]) + '"><span>' + esc(x[0] || '–') +
      ' <span class="dm">→ ' + esc(x[1] || '–') + ' · ' + esc(x[2]) + '</span>' + (x[4] ? ' ' + tag('v1', 'NTLMv1') : '') +
      '</span><span class="n">' + fmt(x[3]) + '</span></button>').join('') + '</div>') : '';
  const fails = d.failed.rows.length ? sec(t('acd_fails'), '<div class="md-list">' + d.failed.rows.map(x =>
      '<div class="md-row"><span>' + esc(ntText(x.code)) + ' <span class="dm">' + esc(t('rdy_from')) + ' ' + esc(x.from || '–') +
      (x.to.length ? ' → ' + esc(x.to.join(', ')) : '') + '</span> <span class="md-via">' + esc(viaTxt(x.via)) + '</span>' +
      (x.locked ? ' ' + tag('v1', t('fail_locked'), t('nth_0xc0000234')) : '') +
      (ntHint(x.code) ? '<div class="rdd">' + esc(ntHint(x.code)) + '</div>' : '') +
      '</span><span class="n">' + fmt(x.n) + '</span></div>').join('') + '</div>') : '';
  const acts = '<div class="md-acts"><button type="button" class="ghost" data-q="' + esc(d.name) + '">' + esc(t('acd_events')) + '</button></div>';
  $('#dbody').innerHTML = '<div class="md">' + note + '<div class="md-sec">' + kpis + chart + '</div>' +
    fails + from + to + progs + acts + '</div>';
}
function mdChart(sr){
  if(!sr || !sr.b || sr.b.length < 2) return '';
  // Without an "inc" series (the account view) only the one line is drawn.
  const inc = sr.inc || null;
  const all = sr.out.concat(inc || []), mx = Math.max.apply(null, all) || 0;
  if(!mx) return '';
  const W = 480, H = 80, n = sr.b.length;
  const line = (v, col) => '<polyline points="' + v.map((x, i) => (i * W / (n - 1)).toFixed(1) + ',' +
    (H - 3 - x / mx * (H - 10)).toFixed(1)).join(' ') + '" fill="none" style="stroke:var(' + col + ')" ' +
    'stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/>';
  return '<div class="md-chart"><svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" aria-hidden="true">' +
    line(sr.out, '--gold') + (inc ? line(inc, '--pol') : '') + '</svg>' +
    '<div class="md-legend"><span><i style="background:var(--gold)"></i>' + esc(sr.label || t('md_out')) + '</span>' +
    (inc ? '<span><i style="background:var(--pol)"></i>' + esc(t('md_in_local')) + '</span>' : '') +
    '<span class="md-axis">' + esc(sr.b[0]) + ' \u2013 ' + esc(sr.b[n - 1]) + '</span></div></div>';
}
function renderMachine(d){
  if(!d || d.unknown){ $('#dbody').innerHTML = '<div class="md"><div class="md-load">' + esc(t('md_err')) + '</div></div>'; return; }
  const ag = (DATA.agents || []).find(a => a.source === d.name) || null;
  const rd = ((DATA.readiness || {}).rows || []).find(r => r.machine === d.name) || null;
  const type = ag ? (ag.is_dc ? t('type_dc') : /server/i.test(ag.os_version || '') ? t('md_type_srv') : t('md_type_cli')) : '';
  $('#dwhen').textContent = [type, ag && ag.os_version, ag && ag.agent_version ? t('md_agent', {v: ag.agent_version}) : '']
    .filter(Boolean).join(' \u00b7 ');
  const sec = (h, inner) => '<div class="md-sec"><div class="md-h">' + esc(h) + '</div>' + inner + '</div>';
  const loc = LOCALE(), fmt = v => Number(v || 0).toLocaleString(loc);
  let live = '';
  if(ag){
    const age = (Date.now() - new Date(String(ag.last_seen).slice(0, 19) + 'Z').getTime()) / 864e5;
    live = '<div class="md-live"><span class="md-dot' + (age >= 2 ? ' off' : '') + '"></span>' +
      esc(t('md_seen', {when: when(ag.last_seen)})) + (age >= 2 ? ' ' + tag('v1', t('md_stale')) : '') +
      (d.first ? '<span class="md-sep">\u00b7</span>' + esc(t('md_since', {when: when(d.first)})) : '') + '</div>';
  }
  const kpis = '<div class="md-kpis">' +
    '<div class="md-k"><span>' + esc(t('md_out')) + '</span><b>' + fmt(d.out.n) + '</b>' +
      (d.out.v1 ? tag('v1', t('md_v1', {n: fmt(d.out.v1)})) : '<em>' + esc(t('md_v1none')) + '</em>') + '</div>' +
    '<div class="md-k"><span>' + esc(t('md_in')) + '</span><b>' + fmt(d.inc.who) + '</b><em>' +
      esc(t('md_srcs_lbl')) + (d.inc.local ? ' \u00b7 ' + esc(t('md_local', {n: fmt(d.inc.local)})) : '') + '</em></div></div>';
  const ready = rd ? sec(t('md_ready'), '<div class="md-rdy"><span class="dm">' + esc(t('rdy_th_out')) + '</span><div>' +
      rdyCell(rd.out, 'out', true) + '</div><span class="dm">' + esc(t('rdy_th_in')) + '</span><div>' + rdyCell(rd['in'], 'in', true) + '</div></div>') : '';
  const progs = sec(t('md_progs'), d.out.top.length ? '<div class="md-list">' + d.out.top.map(x =>
      '<button type="button" class="md-row" data-prog="' + esc(x[0]) + '"><span>' + esc(x[0] || '\u2013') +
      ' <span class="dm">\u2192 ' + esc(x[1] || '\u2013') + '</span>' + (x[3] ? ' ' + tag('v1', 'NTLMv1') : '') +
      '</span><span class="n">' + fmt(x[2]) + '</span></button>').join('') + '</div>'
    : '<div class="md-none">' + esc(t('md_none_out')) + '</div>');
  const via = {local: t('md_via_local'), dc: t('md_via_dc'), cli: t('md_via_cli')};
  const inc = sec(t('md_from'), d.inc.pairs.length ? '<div class="md-list">' + d.inc.pairs.map(x =>
      '<div class="md-row"><span>' + esc(x[0] || '\u2013') + (x[1] ? ' <span class="dm">' + esc(t('rdy_from')) + ' ' + esc(x[1]) + '</span>' : '') +
      ' <span class="md-via">' + esc(via[x[3]] || '') + '</span></span><span class="n">' + fmt(x[2]) + '</span></div>').join('') +
      (d.inc.who > d.inc.pairs.length ? '<div class="md-more">' + esc(t('md_more', {n: d.inc.who - d.inc.pairs.length})) + '</div>' : '') +
      '</div>'
    : '<div class="md-none">' + esc(t('md_none_in')) + '</div>');
  const users = d.out.users.length ? sec(t('md_users'), '<div class="md-chips">' + d.out.users.map(u =>
      '<button type="button" class="md-chip" data-q="' + esc(u[0]) + '">' + esc(u[0] || '\u2013') + ' <b>' + fmt(u[1]) + '</b></button>').join('') + '</div>') : '';
  let audit = '';
  if(ag){ const b = agentBadges(ag);
    audit = sec(t('md_audit'), '<div class="md-tags">' + (b.au.join(' ') || '<span class="dm">\u2013</span>') +
      (b.lm ? ' ' + b.lm : '') + '</div><div class="md-tags" style="margin-top:8px"><span class="dm">' +
      esc(t('th_oct')) + '</span> ' + b.oct + '</div>'); }
  const acts = '<div class="md-acts"><button type="button" class="ghost" data-mach="' + esc(d.name) + '">' +
    esc(t('md_filter')) + '</button><button type="button" class="ghost" data-mach-ev="' + esc(d.name) + '">' +
    esc(t('md_events')) + '</button></div>';
  $('#dbody').innerHTML = '<div class="md">' + live + '<div class="md-sec">' + kpis + mdChart(d.series) + '</div>' +
    ready + progs + inc + users + audit + acts + '</div>';
}
const openDrawer = () => { $('#drawer').classList.add('on'); $('#scrim').classList.add('on');
  $('#dclose').focus(); };
const closeDrawer = () => { $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on'); };

// ---- Drawing -----------------------------------------------------------
function render(){
  if(!DATA) return;
  writeUrlState();
  setTimeout(labelCells, 0);   // after the panels have written their rows
  renderChrome(); renderOsDonut(); renderHero(); renderFocus();
  // Three blocks in the order the work goes: what the situation is, what can be
  // done now, and the detail to look things up in.
  $('#grid').innerHTML = [blk('lage'), secTrend(), secPrograms(), secWhy(), secHeat(),
    blk('act'), secReady(), secV1(), secSso(), secFailed(), secSpn(), secAgentless(), secIncoming(),
    blk('det'), secAccounts(), secDomain(), secTargets(), secKrb(), secKrbAcc(), secAgents(), secEvents()].join('');
  fillHeat(); renderEvents(); renderJump(); clipTables(); spy();
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

// ---- Events --------------------------------------------------------------
document.addEventListener('click', function(ev){
  const el = ev.target;
  // The status dropdown sits inside a clickable row: choosing a status must
  // not also drill into the row.
  if(el.closest && el.closest('select.sel-st')) return;
  if(el.id === 'scrim' || el.id === 'dclose'){ closeDrawer(); return; }
  if(el.id === 'excbtn'){ openExceptions(); return; }
  if(el.id === 'more'){ S.shown += 50; renderEvents(); return; }
  const cp = el.closest('[data-copy]');
  if(cp){ const done = () => { cp.textContent = t('spn_copied'); setTimeout(() => { cp.textContent = t('spn_copy'); }, 1600); };
    // The clipboard API needs a secure context; over plain http the command
    // is selected instead, so Ctrl+C still works.
    if(navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(cp.dataset.copy).then(done, function(){});
    else { const c = cp.closest('td').querySelector('code'); const r = document.createRange(); r.selectNodeContents(c);
      const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); }
    return; }
  const rc = el.closest('[data-recheck]');
  if(rc){ rc.disabled = true;
    fetch('/spn-recheck', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({spn: rc.dataset.recheck})})
      .then(function(r){ if(r.ok) rc.textContent = t('spn_queued'); else rc.disabled = false; })
      .catch(function(){ rc.disabled = false; });
    return; }
  if(el.id === 'report'){
    // The report knows 7, 30 and 90 days; 24 hours is too short for a trend
    // and "all" too long to compare against, so both open the 30-day report.
    const rg = S.range === '7d' ? '7d' : '30d';
    window.open(window.STATIC_REPORT ? window.STATIC_REPORT(LANG, rg)
      : '/report?' + new URLSearchParams({range: rg, lang: LANG, tzoff: String(TZOFF())}).toString(), '_blank', 'noopener');
    return;
  }
  if(el.id === 'csv'){ window.location = '/api/export.csv?' + params({q: S.q, kind: S.kind}).toString(); return; }
  if(el.id === 'logout'){ window.location = '/logout'; return; }
  if(el.id === 'hide'){ S.hideDone = !S.hideDone; render(); return; }
  const lang = el.closest('[data-l]');
  if(lang){
    LANG = lang.dataset.l;
    try { localStorage.setItem('ntlm.lang', LANG); } catch(e){}
    render(); return; }
  if(el.closest('#menu')){ toggleMenu(); return; }
  if(el.closest('#theme')){ toggleTheme(); return; }
  if(el.closest('#searchbtn')){ palOpen(); return; }
  const r = el.closest('[data-r]');
  if(r){ S.range = r.dataset.r; toggleMenu(false); load(); return; }
  const hb = el.closest('[data-help]');
  if(hb){ const id = hb.dataset.help, open = !HELPOPEN.has(id);
    if(open) HELPOPEN.add(id); else HELPOPEN.delete(id);
    const box = document.getElementById('help-' + id); if(box) box.hidden = !open;
    hb.setAttribute('aria-expanded', String(open));
    if(open && FOLDED.has(id)) setFold(id, false);   // asking what a folded panel shows opens it
    return; }
  const fold = el.closest('[data-fold]');
  if(fold){ setFold(fold.dataset.fold, !FOLDED.has(fold.dataset.fold)); return; }
  const sa = el.closest('[data-showall]');
  if(sa){ const id = sa.dataset.showall, card = document.getElementById(id);
    if(EXPANDED.has(id)) EXPANDED.delete(id); else EXPANDED.add(id);
    if(card) clipCard(card);
    // collapsing a long list leaves the reader far below it - bring the panel back
    if(!EXPANDED.has(id) && card && card.getBoundingClientRect().top < 0)
      card.scrollIntoView({block: 'start'});
    return; }
  const go = el.closest('[data-go]');
  if(go){ const c = document.getElementById(go.dataset.go);
    if(c){ if(FOLDED.has(c.id)) setFold(c.id, false);   // jumping to a folded panel opens it
      c.scrollIntoView({behavior: 'smooth', block: 'start'}); } return; }
  const evrow = el.closest('[data-ev]');
  if(evrow){ openEvent(+evrow.dataset.ev); return; }
  const clr = el.closest('[data-clr]');
  if(clr){ const k = clr.dataset.clr;
    if(k === 'all'){ S.q = ''; S.kind = ''; S.mach = ''; S.bucket = ''; S.wd = ''; S.hr = '';
      S.pick = ''; S.rsn = ''; S.unconf = ''; load(); }
    else if(k === 'unconf'){ S.unconf = ''; S.shown = 25; load(); }
    else if(k === 'pick'){ S.pick = ''; load(); }
    else if(k === 'rsn'){ S.rsn = ''; load(); }
    else if(k === 'mach'){ S.mach = ''; load(); }
    else if(k === 'bucket'){ S.bucket = ''; load(); }
    else if(k === 'when'){ S.wd = ''; S.hr = ''; load(); }
    else if(k === 'q'){ S.q = ''; load(); }
    else { S[k] = ''; render(); }
    return; }
  // Drill-down out of the two charts. Both are server-side filters, so the
  // whole payload is refetched - a day three weeks back is not in the event
  // list the page happens to be holding.
  const unc = el.closest('[data-unconf]');
  if(unc){ S.unconf = '1'; S.shown = 25; load().then(goEvents); return; }
  const rw = el.closest('[data-rsn]');
  if(rw){
    S.rsn = S.rsn === rw.dataset.rsn ? '' : rw.dataset.rsn;
    S.pick = ''; S.shown = 25;
    load().then(function(){ if(S.rsn) goEvents(); });
    return; }
  // Bar segments and the key-figure tiles pick the same filter.
  const sg = el.closest('#handbar .seg, .kpi[data-pick]');
  if(sg){
    S.pick = S.pick === sg.dataset.pick ? '' : sg.dataset.pick;
    // Mutually exclusive with the reason filter in both directions: both want
    // the 'kind' parameter, and a chip that is displayed but ignored would be
    // worse than no chip at all.
    S.rsn = ''; S.shown = 25;
    load().then(function(){ if(S.pick) goEvents(); });
    return; }
  const bar = el.closest('[data-bucket]');
  if(bar){
    S.bucket = S.bucket === bar.dataset.bucket ? '' : bar.dataset.bucket;
    S.wd = ''; S.hr = ''; S.shown = 25;
    load().then(() => { if(S.bucket) goEvents(); });
    return; }
  const cell = el.closest('[data-wd]');
  if(cell){
    const same = String(S.wd) === cell.dataset.wd && String(S.hr) === cell.dataset.hr;
    S.wd = same ? '' : cell.dataset.wd;
    S.hr = same ? '' : cell.dataset.hr;
    S.bucket = ''; S.shown = 25;
    load().then(() => { if(S.wd !== '') goEvents(); });
    return; }
  const chip = el.closest('.chip');
  if(chip){ if(chip.dataset.k !== undefined) S.kind = chip.dataset.k;
    if(chip.dataset.a) S.acct = chip.dataset.a;
    S.shown = 25; renderEvents(); return; }
  const aco = el.closest('[data-account]');
  if(aco){ openAccount(aco.dataset.account); return; }
  const mdo = el.closest('[data-machine]');
  if(mdo){ openMachine(mdo.dataset.machine); return; }
  const mev = el.closest('[data-mach-ev]');
  if(mev){ S.mach = mev.dataset.machEv; S.shown = 25; closeDrawer(); load().then(goEvents); return; }
  const jd = el.closest('[data-prog],[data-q],[data-mach],[data-kind]');
  if(jd){
    if(jd.dataset.mach){ S.mach = jd.dataset.mach; closeDrawer(); load(); return; }
    const qBefore = S.q;
    if(jd.dataset.prog) S.q = jd.dataset.prog;
    if(jd.dataset.q) S.q = jd.dataset.q;
    if(jd.dataset.kind) S.kind = jd.dataset.kind;
    S.shown = 25; closeDrawer();
    if(S.q !== qBefore){ load().then(goEvents); return; }
    render();
    const c = document.getElementById('sec-events');
    if(c) setTimeout(function(){ c.scrollIntoView({behavior: 'smooth', block: 'start'}); }, 50);
  }
});
// Typing filters the loaded rows at once, then asks the database after a short
// pause. Reloading rebuilds the list with its search field, so focus and caret
// are put back where they were.
let Q_TIMER = 0;
document.addEventListener('input', function(e){
  if(e.target.id !== 'q') return;
  S.q = e.target.value; S.shown = 25; renderEvents();
  clearTimeout(Q_TIMER);
  Q_TIMER = setTimeout(function(){
    const qi = $('#q'), had = qi && document.activeElement === qi, pos = qi ? qi.selectionStart : 0;
    load().then(function(){
      const n = $('#q');
      if(had && n){ n.focus(); try { n.setSelectionRange(pos, pos); } catch(err){} }
    });
  }, 450);
});
// Opens and closes the control drawer on a phone; closes by itself once a range
// or machine is picked, so the choice shows straight away.
// The theme actually showing: the viewer's choice if there is one, else the system's.
function effTheme(){
  const a = document.documentElement.getAttribute('data-theme');
  return a || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
}
function toggleTheme(){
  const nx = effTheme() === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', nx);
  try { localStorage.setItem('ntlm.theme', nx); } catch(e){}
  renderChrome();
}
// ---- Quick search (Ctrl+K, / or the header button) --------------------------
// One box over everything the dashboard currently shows: machines open their
// detail, programs, accounts and targets filter the event list, panels are
// jumped to. Built from DATA when opened, so it always matches the range.
let PAL_ITEMS = [], PAL_HITS = [], PAL_SEL = 0, PAL_OPENER = null;
const palNorm = v => String(v || '').toLowerCase();
function palIndex(){
  const out = [], seen = new Set();
  const add = (type, label, sub, act, w) => {
    if(!label) return;
    const k = type + '|' + palNorm(label);
    if(seen.has(k)) return; seen.add(k);
    out.push({type: type, label: String(label), sub: sub || '', act: act, w: w});
  };
  const splitU = v => String(v || '').split(',').map(x => x.trim()).filter(Boolean);
  const fmt = n => Number(n || 0).toLocaleString(LOCALE());
  const agents = DATA.agents || [];
  const known = new Set(agents.map(a => palNorm(a.source)));
  agents.forEach(a => add('machine', a.source,
    [a.is_dc ? t('type_dc') : /server/i.test(a.os_version || '') ? t('md_type_srv') : t('md_type_cli'), a.os_version].filter(Boolean).join(' \u00b7 '),
    () => openMachine(a.source), 5));
  ((DATA.agentless || {}).rows || []).forEach(x => { if(!known.has(palNorm(x.machine)))
    add('noagent', x.machine, t('pal_noagent_sub', {n: fmt(x.n)}), () => palFilter(x.machine), 3); });
  (DATA.domain || []).forEach(x => { if(!known.has(palNorm(x.workstation)))
    add('noagent', x.workstation, t('pal_dom_sub', {n: fmt(x.n)}), () => palFilter(x.workstation), 2); });
  (DATA.blockers || []).forEach(b => {
    add('prog', b.process, (b.target || '') + ' \u00b7 ' + fmt(b.n) + '\u00d7', () => palFilter(b.process), 4);
    add('target', b.target, t('pal_target_sub', {n: fmt(b.n)}), () => palFilter(b.target), 2);
  });
  (DATA.incoming || []).forEach(x => add('prog', x.process, x.machine + ' \u00b7 ' + t('md_in'), () => palFilter(x.process), 3));
  (DATA.domain || []).forEach(x => add('target', x.target, t('pal_target_sub', {n: fmt(x.n)}), () => palFilter(x.target), 2));
  ((DATA.accounts || {}).rows || []).forEach(a => add('acct', a.name,
    [a.v1 ? 'NTLMv1' : a.n ? 'NTLM' : '', a.failed ? t('pal_failed', {n: fmt(a.failed)}) : ''].filter(Boolean).join(' \u00b7 '),
    () => openAccount(a.key), a.v1 ? 5 : 4));
  (DATA.v1_users || []).forEach(u => add('acct', u.name, 'NTLMv1 \u00b7 ' + fmt(u.n) + '\u00d7', () => openAccount(u.name), 4));
  (DATA.blockers || []).concat(DATA.domain || [], DATA.incoming || []).forEach(x =>
    splitU(x.users).forEach(u => add('acct', u, 'NTLM', () => openAccount(u), 3)));
  (DATA.kerberos_accounts || []).forEach(k => add('acct', k.account, 'Kerberos', () => openAccount(k.account), 2));
  document.querySelectorAll('#grid .card').forEach(c => {
    const h = c.querySelector('h2'); if(!h) return;
    add('panel', h.textContent, t('pal_panel_sub'), () => { if(FOLDED.has(c.id)) setFold(c.id, false);
      c.scrollIntoView({behavior: calm ? 'auto' : 'smooth', block: 'start'}); }, 1);
  });
  return out;
}
function palFilter(v){ S.q = v; S.shown = 25; closeDrawer(); load().then(goEvents); }
function palScore(it, q){
  const l = palNorm(it.label);
  if(!q) return it.type === 'machine' || it.type === 'panel' ? it.w : -1;
  let sc = -1;
  if(l === q) sc = 1000;
  else if(l.startsWith(q)) sc = 600;
  else { const i = l.indexOf(q);
    if(i > 0) sc = /[\s\\/._@-]/.test(l[i - 1]) ? 400 : 200 - Math.min(i, 100); }
  if(sc < 0 && palNorm(it.sub).includes(q)) sc = 50;
  return sc < 0 ? -1 : sc + it.w;
}
function palMark(label, q){
  const l = palNorm(label), i = q ? l.indexOf(q) : -1;
  if(i < 0) return esc(label);
  return esc(label.slice(0, i)) + '<mark>' + esc(label.slice(i, i + q.length)) + '</mark>' + esc(label.slice(i + q.length));
}
function palRender(){
  const q = palNorm($('#palq').value.trim());
  PAL_HITS = PAL_ITEMS.map(it => [palScore(it, q), it]).filter(x => x[0] >= 0)
    .sort((a, b) => b[0] - a[0] || a[1].label.localeCompare(b[1].label)).slice(0, 40).map(x => x[1]);
  PAL_SEL = Math.min(PAL_SEL, Math.max(0, PAL_HITS.length - 1));
  const box = $('#palres');
  box.innerHTML = PAL_HITS.length ? PAL_HITS.map((it, i) =>
      '<li role="option" id="pal-' + i + '" data-pal="' + i + '" aria-selected="' + (i === PAL_SEL) + '">' +
      '<span class="pty">' + esc(t('pal_' + it.type)) + '</span><span class="plb">' + palMark(it.label, q) + '</span>' +
      (it.sub ? '<span class="psb">' + esc(it.sub) + '</span>' : '') + '</li>').join('')
    : '<li class="palnone">' + esc(t('pal_none', {q: $('#palq').value.trim()})) + '</li>';
  $('#palq').setAttribute('aria-activedescendant', PAL_HITS.length ? 'pal-' + PAL_SEL : '');
  const cur = document.getElementById('pal-' + PAL_SEL); if(cur) cur.scrollIntoView({block: 'nearest'});
}
function palOpen(){
  if(!DATA) return;
  PAL_ITEMS = palIndex(); PAL_SEL = 0; PAL_OPENER = document.activeElement;
  toggleMenu(false);
  $('#pal').hidden = false; $('#palq').value = ''; $('#palq').placeholder = t('pal_ph');
  $('#palfoot').textContent = t('pal_foot');
  palRender(); $('#palq').focus();
}
function palClose(){
  $('#pal').hidden = true;
  if(PAL_OPENER && PAL_OPENER.focus) PAL_OPENER.focus();
}
function palRun(i){ const it = PAL_HITS[i]; if(!it) return; palClose(); it.act(); }
const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform || '');
document.addEventListener('keydown', e => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || '') || (e.target && e.target.isContentEditable);
  if((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 'k' || e.key === 'K')){
    e.preventDefault(); if($('#pal').hidden) palOpen(); else palClose(); return; }
  if(e.key === '/' && !typing && !e.ctrlKey && !e.metaKey && !e.altKey && $('#pal').hidden){ e.preventDefault(); palOpen(); }
});
$('#palq').addEventListener('input', () => { PAL_SEL = 0; palRender(); });
$('#palq').addEventListener('keydown', e => {
  if(e.key === 'ArrowDown'){ e.preventDefault(); PAL_SEL = Math.min(PAL_SEL + 1, PAL_HITS.length - 1); palRender(); }
  else if(e.key === 'ArrowUp'){ e.preventDefault(); PAL_SEL = Math.max(PAL_SEL - 1, 0); palRender(); }
  else if(e.key === 'Enter'){ e.preventDefault(); palRun(PAL_SEL); }
  else if(e.key === 'Escape'){ e.preventDefault(); e.stopPropagation(); palClose(); }
  else if(e.key === 'Tab'){ e.preventDefault(); }   // one field and a list: focus stays here
});
$('#pal').addEventListener('mousedown', e => {
  const li = e.target.closest('[data-pal]');
  if(li){ e.preventDefault(); palRun(+li.dataset.pal); return; }
  if(!e.target.closest('.palbox')) palClose();
});
$('#palres').addEventListener('mousemove', e => {
  const li = e.target.closest('[data-pal]');
  if(li && +li.dataset.pal !== PAL_SEL){ PAL_SEL = +li.dataset.pal; palRender(); }
});
function toggleMenu(open){
  const h = document.querySelector('header'), b = $('#menu'); if(!h || !b) return;
  const on = open === undefined ? !h.classList.contains('open') : open;
  h.classList.toggle('open', on); b.setAttribute('aria-expanded', String(on));
}
document.addEventListener('keydown', e => { if(e.key === 'Escape') toggleMenu(false); });
document.addEventListener('change', function(e){
  if(e.target && e.target.id === 'mach') toggleMenu(false);
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
                    help="Shared secret; agents send it as X-Api-Key")
    ap.add_argument("--password", default=os.environ.get("NTLM_DASHBOARD_PASSWORD", ""),
                    help="Password for the dashboard login. Empty = login OFF (open). "
                         "Better set via the environment variable NTLM_DASHBOARD_PASSWORD than as an argument.")
    ap.add_argument("--secure-cookie", action="store_true",
                    help="Mark the session cookie as 'Secure' (sent over HTTPS only). "
                         "On automatically when --cert/--tlskey are set.")
    ap.add_argument("--cert", default="",
                    help="Path to the TLS certificate (PEM). Together with --tlskey this enables HTTPS.")
    ap.add_argument("--tlskey", default="",
                    help="Path to the private TLS key (PEM).")
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
    httpd.tls = scheme == "https"
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
                        conn.execute(
                            "DELETE FROM dc_validations WHERE event_time < ?", (cutoff,))
                        conn.execute(
                            "DELETE FROM ntlm_failures WHERE event_time < ?", (cutoff,))
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
