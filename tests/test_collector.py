"""Tests for the collector's counting rules.

Every rule that decides whether an event counts, counts once, or carries a
version gets a test here. Each test starts a real collector on its own
database and port, pushes events over HTTP exactly as an agent does, and reads
the answer through the same endpoints the dashboard uses.

Standard library only, like the collector itself:

    python -m unittest discover -s tests -v
"""
import importlib.util
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.join(HERE, os.pardir, "ntlm-collector.py")

_spec = importlib.util.spec_from_file_location("ntlm_collector", COLLECTOR)
col = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(col)


def ts(minutes_ago=0, seconds=0):
    """An event time as the agents send it: UTC, ISO, no zone."""
    t = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes_ago) + timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Collector:
    """A collector on a temporary database, reachable over HTTP."""

    def __init__(self, key="", password=""):
        self.dir = tempfile.mkdtemp(prefix="ntlm-test-")
        self.conn = col.init_db(os.path.join(self.dir, "t.db"))
        col._PANEL_CACHE.clear()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), col.Handler)
        self.httpd.conn = self.conn
        self.httpd.api_key = key
        self.httpd.sessions = {}
        self.httpd.cookie_secure = False
        self.httpd.pw_hash = col.hash_password(password) if password else None
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        self.key = key
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.rid = 1000

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.conn.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    # -- HTTP -------------------------------------------------------------
    def request(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Content-Type": "application/json"}
        if self.key:
            h["X-Api-Key"] = self.key
        h.update(headers or {})
        req = urllib.request.Request(self.url + path, data=data, headers=h, method=method)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def post(self, path, body):
        code, raw = self.request("POST", path, body)
        return code, json.loads(raw or b"{}")

    def get(self, path, **params):
        q = urllib.parse.urlencode(params)
        code, raw = self.request("GET", path + ("?" + q if q else ""))
        return code, raw

    def data(self, **params):
        params.setdefault("range", "30d")
        params.setdefault("limit", "300")
        col._PANEL_CACHE.clear()
        code, raw = self.get("/api/data", **params)
        assert code == 200, raw
        return json.loads(raw)

    # -- Agents and events -------------------------------------------------
    def agent(self, source, is_dc=False, **kw):
        body = {"source": source, "is_dc": is_dc, "agent_version": "2.3.0",
                "outgoing_audit": "audit", "incoming_audit": "audit",
                "domain_audit": "on" if is_dc else "off", "logon_audit": "success_failure",
                "os_version": "Windows Server 2022 Standard (20348)", "lm_level": "5"}
        body.update(kw)
        code, r = self.post("/status", body)
        assert code == 200, r

    def push(self, source, *events):
        evs = []
        for e in events:
            e = dict(e)
            if "record_id" not in e:
                self.rid += 1
                e["record_id"] = self.rid
            evs.append(e)
        code, r = self.post("/ingest", {"source": source, "events": evs})
        assert code == 200, r
        return r


def ev(event_id, kind, when, **kw):
    log = "Security" if event_id in (4624, 4625, 4776, 4769) else "Microsoft-Windows-NTLM/Operational"
    e = {"event_id": event_id, "kind": kind, "event_time": when, "log": log, "domain": "CORP"}
    e.update(kw)
    return e


def events_of(data, event_id):
    return [e for e in data["events"] if e["event_id"] == event_id]


class CollectorTest(unittest.TestCase):
    key = ""
    password = ""

    def setUp(self):
        self.c = Collector(key=self.key, password=self.password)

    def tearDown(self):
        self.c.close()


# ---------------------------------------------------------------------------
class Helpers(unittest.TestCase):
    def test_norm_status(self):
        self.assertEqual(col.norm_status("0xc000006a"), "0xC000006A")
        self.assertEqual(col.norm_status("0xC000006A"), "0xC000006A")
        self.assertIsNone(col.norm_status("0x0"))
        self.assertIsNone(col.norm_status(""))
        self.assertIsNone(col.norm_status("wrong"))

    def test_user_key(self):
        self.assertEqual(col.user_key("CORP\\alice"), "ALICE")
        self.assertEqual(col.user_key("alice@corp.local"), "ALICE")
        self.assertEqual(col.user_key(" Alice "), "ALICE")
        self.assertIsNone(col.user_key(""))

    def test_host_key(self):
        self.assertEqual(col.host_key("cifs/FS01.corp.local"), "FS01")
        self.assertEqual(col.host_key("ldap/dc1.corp.local/corp.local@CORP.LOCAL"), "DC1")
        self.assertEqual(col.host_key("FS01:445"), "FS01")
        self.assertEqual(col.host_key("fs01"), "FS01")
        self.assertEqual(col.host_key("cifs/10.1.2.3"), "10.1.2.3")
        self.assertIsNone(col.host_key(""))

    def test_normalize_process(self):
        self.assertEqual(col.normalize_process("lsass"), "lsass.exe")
        self.assertEqual(col.normalize_process("lsass.exe"), "lsass.exe")
        self.assertEqual(col.normalize_process("(Kernel: SMB/HTTP.sys)"), "(Kernel: SMB/HTTP.sys)")
        self.assertEqual(col.normalize_process("SYSTEM"), "SYSTEM")

    def test_reason_follows_the_text(self):
        # Seen on a real Server 2025: Reason ID 10 (loopback) with the IP text.
        self.assertEqual(col.canonical_reason_id("The target name contains an IP address.", "10"), "7")
        self.assertEqual(col.canonical_reason_id("Something new", "3"), "3")
        self.assertIsNone(col.canonical_reason_id("anything", None))


class Translations(unittest.TestCase):
    def test_german_and_english_have_the_same_keys(self):
        col.ui_text("de", "x")
        de, en = set(col._UI_TEXT["de"]), set(col._UI_TEXT["en"])
        self.assertEqual(sorted(de - en), [], "only in German")
        self.assertEqual(sorted(en - de), [], "only in English")

    def test_report_texts_match(self):
        de, en = set(col.REPORT_TEXT["de"]), set(col.REPORT_TEXT["en"])
        self.assertEqual(de, en)

    def test_comments_are_english(self):
        """Code and comments are English. German stays where it has to: the
        German UI texts and the German Windows labels that are matched - both
        are string values, not comments, so only comments are checked here,
        plus the module docstring."""
        words = re.compile(r"\b(und|nicht|oder|wird|werden|wurde|für|ist|mit|auf|der|die|das|dem|den|"
                           r"ein|eine|einen|sind|auch|noch|wenn|dann|bei|nach|über|ohne|hier|weil|"
                           r"Aufruf|Echtzeit|Ereignis|Ereignisse|Rechner|Benutzer)\b")
        with open(COLLECTOR, encoding="utf-8") as f:
            src = f.read()
        head = src[:src.index('"""', src.index('"""') + 3)]
        bad = ["docstring: " + l.strip() for l in head.split("\n") if words.search(l)]
        for n, line in enumerate(src.split("\n"), 1):
            s = line.strip()
            if s.startswith(("#", "//", "/*", "* ")) and words.search(s):
                bad.append("%d: %s" % (n, s[:100]))
        self.assertEqual(bad, [])


# ---------------------------------------------------------------------------
class Ingest(CollectorTest):
    def test_duplicate_push_is_stored_once(self):
        self.c.agent("WKS1")
        e = ev(8001, "outgoing", ts(10), user="alice", target_server="cifs/fs01", record_id=7)
        self.assertEqual(self.c.push("WKS1", e)["inserted"], 1)
        self.assertEqual(self.c.push("WKS1", e)["inserted"], 0)
        self.assertEqual(self.c.data()["stats"]["outbound"], 1)

    def test_malformed_input_gets_a_clean_answer(self):
        self.assertEqual(self.c.post("/ingest", ["not", "an", "object"])[0], 400)
        self.assertEqual(self.c.post("/ingest", {"source": "X", "events": "nope"})[0], 400)
        code, r = self.c.post("/ingest", {"source": "X", "events": [
            "garbage", ev(8001, "outgoing", ts(1), user="a", target_server="cifs/x")]})
        self.assertEqual((code, r["inserted"]), (200, 1))

    def test_legacy_audit_words_are_translated(self):
        self.c.agent("OLD1", outgoing_audit="aus", incoming_audit="an")
        a = [x for x in self.c.data()["agents"] if x["source"] == "OLD1"][0]
        self.assertEqual((a["outgoing_audit"], a["incoming_audit"]), ("off", "on"))

    def test_legacy_work_status_is_translated(self):
        code, _ = self.c.post("/item-status", {"key": "proc|a.exe|cifs/x", "status": "erledigt"})
        self.assertEqual(code, 200)
        row = self.c.conn.execute("SELECT status FROM item_status").fetchone()
        self.assertEqual(row[0], "done")

    def test_server_side_search_finds_every_match(self):
        self.c.agent("WKS1")
        self.c.push("WKS1", *[ev(8001, "outgoing", ts(i + 1), user="u%d" % i, process="p%d.exe" % i,
                                 target_server="cifs/fs01") for i in range(20)])
        d = self.c.data(q="p17.exe", limit="5")
        self.assertEqual(d["events_total"], 1)
        self.assertEqual(d["events"][0]["process"], "p17.exe")


class Security(CollectorTest):
    key = "k3y"
    password = "secret"

    def test_ingest_needs_the_api_key(self):
        code, raw = self.c.request("POST", "/ingest", {"source": "X", "events": []}, {"X-Api-Key": "wrong"})
        self.assertEqual(code, 401)
        code, _ = self.c.post("/ingest", {"source": "X", "events": []})
        self.assertEqual(code, 200)

    def test_dashboard_needs_the_login(self):
        self.assertEqual(self.c.get("/api/data")[0], 401)
        self.assertEqual(self.c.get("/api/account", name="a")[0], 401)
        self.assertEqual(self.c.get("/api/machine", name="a")[0], 401)
        self.assertEqual(self.c.get("/report")[0], 302)
        self.assertEqual(self.c.get("/")[0], 302)


# ---------------------------------------------------------------------------
class OutgoingDuplicates(CollectorTest):
    def setUp(self):
        super().setUp()
        self.c.agent("WKS1", os_version="Windows 11 Enterprise (26100)")

    def test_8001_with_its_4020_counts_once(self):
        t = ts(30)
        self.c.push("WKS1",
                    ev(8001, "outgoing", t, user="alice", target_server="cifs/fs01.corp.local"),
                    ev(4020, "outgoing", t, user="alice", target_server="cifs/fs01.corp.local",
                       ntlm_version="NTLMv2", process="explorer.exe"))
        s = self.c.data()["stats"]
        # A duplicate, not a doubtful entry: it must not land among the unconfirmed.
        self.assertEqual((s["outbound"], s["unconfirmed"]), (1, 0))

    def test_realm_suffix_still_matches(self):
        t = ts(30)
        self.c.push("WKS1",
                    ev(8001, "outgoing", t, user="alice", target_server="ldap/dc01.corp.local/corp.local@CORP.LOCAL"),
                    ev(4020, "outgoing", t, user="alice", target_server="ldap/dc01.corp.local", ntlm_version="NTLMv2"))
        s = self.c.data()["stats"]
        self.assertEqual((s["outbound"], s["unconfirmed"]), (1, 0))

    def test_8001_without_partner_is_unconfirmed(self):
        self.c.push("WKS1",
                    ev(4020, "outgoing", ts(60), user="bob", target_server="cifs/other", ntlm_version="NTLMv2"),
                    ev(8001, "outgoing", ts(30), user="alice", target_server="cifs/fs01"))
        s = self.c.data()["stats"]
        self.assertEqual((s["outbound"], s["unconfirmed"]), (1, 1))

    def test_dc_validation_confirms_it(self):
        self.c.agent("DC01", is_dc=True)
        self.c.push("WKS1",
                    ev(4020, "outgoing", ts(60), user="bob", target_server="cifs/other", ntlm_version="NTLMv2"),
                    ev(8001, "outgoing", ts(30), user="alice", target_server="cifs/fs01"))
        self.c.push("DC01", ev(4776, "dcval", ts(30, 20), user="alice", workstation="WKS1", failure_code="0x0"))
        s = self.c.data()["stats"]
        self.assertEqual((s["outbound"], s["unconfirmed"]), (2, 0))

    def test_no_validation_on_any_dc_is_a_phantom(self):
        self.c.agent("DC01", is_dc=True)
        # The DC covers the moment: it has 4776s from before, and reported after.
        self.c.push("DC01", ev(4776, "dcval", ts(300), user="carol", workstation="PC9", failure_code="0x0"))
        self.c.push("WKS1",
                    ev(4020, "outgoing", ts(200), user="bob", target_server="cifs/other", ntlm_version="NTLMv2"),
                    ev(8001, "outgoing", ts(120), user="alice", target_server="cifs/fs01"))
        s = self.c.data()["stats"]
        self.assertEqual((s["outbound"], s["unconfirmed"], s["phantom"]), (1, 1, 1))

    def test_local_account_is_never_a_phantom(self):
        self.c.agent("DC01", is_dc=True)
        self.c.push("DC01", ev(4776, "dcval", ts(300), user="carol", workstation="PC9", failure_code="0x0"))
        self.c.push("WKS1",
                    ev(4020, "outgoing", ts(200), user="bob", target_server="cifs/other", ntlm_version="NTLMv2"),
                    ev(8001, "outgoing", ts(120), user="admin", domain="WKS1", target_server="cifs/fs01"))
        self.assertEqual(self.c.data()["stats"]["phantom"], 0)


# ---------------------------------------------------------------------------
class MemberServerLogons(CollectorTest):
    """4624 on a member server: one count per logon, and the version travels."""

    def setUp(self):
        super().setUp()
        self.c.agent("FS01")

    def test_4624_and_8003_count_once_and_share_the_version(self):
        t = ts(20)
        self.c.push("FS01", ev(8003, "incoming", t, user="alice", workstation="WKS1", process="System"))
        self.c.push("FS01", ev(4624, "auth", t, user="alice", workstation="WKS1", ntlm_version="NTLMv1",
                               logon_type="3", auth_method="Direct"))
        d = self.c.data()
        self.assertEqual(d["stats"]["inbound"], 1)
        self.assertEqual(d["stats"]["v1"], 1)
        self.assertEqual(events_of(d, 8003)[0]["ntlm_version"], "NTLMv1")

    def test_order_of_arrival_does_not_matter(self):
        t = ts(20)
        self.c.push("FS01", ev(4624, "auth", t, user="alice", workstation="WKS1", ntlm_version="NTLMv1"))
        self.c.push("FS01", ev(8003, "incoming", t, user="alice", workstation="WKS1", process="System"))
        d = self.c.data()
        self.assertEqual((d["stats"]["inbound"], d["stats"]["v1"]), (1, 1))

    def test_4624_alone_is_the_incoming_event(self):
        self.c.push("FS01", ev(4624, "auth", ts(20), user="alice", workstation="WKS1", ntlm_version="NTLMv2"))
        s = self.c.data()["stats"]
        self.assertEqual((s["inbound"], s["v2"]), (1, 1))

    def test_different_client_is_a_different_logon(self):
        t = ts(20)
        self.c.push("FS01", ev(8003, "incoming", t, user="alice", workstation="WKS1"),
                    ev(4624, "auth", t, user="alice", workstation="WKS2", ntlm_version="NTLMv2"))
        self.assertEqual(self.c.data()["stats"]["inbound"], 2)

    def test_version_reaches_the_dc_and_the_client(self):
        self.c.agent("DC01", is_dc=True)
        self.c.agent("WKS1")
        t = ts(20)
        self.c.push("DC01", ev(8004, "domain", t, user="alice", workstation="WKS1", target_server="FS01"))
        self.c.push("WKS1", ev(8001, "outgoing", t, user="alice", target_server="cifs/fs01.corp.local"))
        self.c.push("FS01", ev(4624, "auth", t, user="alice", workstation="WKS1", ntlm_version="NTLMv1"))
        d = self.c.data()
        self.assertEqual(events_of(d, 8004)[0]["ntlm_version"], "NTLMv1")
        self.assertEqual(events_of(d, 8001)[0]["ntlm_version"], "NTLMv1")

    def test_4624_before_the_first_status_is_filed_later(self):
        self.c.push("NEW1", ev(4624, "auth", ts(5), user="alice", workstation="WKS1", ntlm_version="NTLMv2"))
        self.assertEqual(self.c.data()["stats"]["inbound"], 0)
        self.c.agent("NEW1")
        self.assertEqual(self.c.data()["stats"]["inbound"], 1)

    def test_4022_counts_as_incoming_not_domain(self):
        self.c.push("FS01", ev(4022, "domain", ts(5), user="alice", workstation="WKS1", ntlm_version="NTLMv2"))
        d = self.c.data()
        self.assertEqual(d["stats"]["inbound"], 1)
        self.assertEqual(d["domain"], [])

    def test_anonymous_logon_carries_no_version(self):
        self.c.push("FS01", ev(4624, "auth", ts(5), user="ANONYMOUS LOGON", domain="NT AUTHORITY",
                               workstation="MFP1", ntlm_version="NTLMv1"))
        d = self.c.data()
        self.assertEqual(d["stats"]["v1"], 0)
        self.assertTrue(d["accounts"]["anon"])


# ---------------------------------------------------------------------------
class FailedLogons(CollectorTest):
    def setUp(self):
        super().setUp()
        self.c.agent("FS01")
        self.c.agent("DC01", is_dc=True)

    def fail(self, user, ws, code, minutes, server=True, dc=True):
        if server:
            self.c.push("FS01", ev(4625, "failed", ts(minutes), user=user, workstation=ws, failure_code=code,
                                   logon_type="3"))
        if dc:
            self.c.push("DC01", ev(4776, "dcval", ts(minutes, 1), user=user, workstation=ws, failure_code=code))

    def test_failures_are_not_ntlm_in_use(self):
        self.fail("bob", "WKS2", "0xc000006a", 10)
        d = self.c.data()
        self.assertEqual(d["stats"]["total"], 0)
        self.assertEqual(d["failures"]["n"], 1)

    def test_seen_by_server_and_dc_counts_once(self):
        for m in (10, 20, 30):
            self.fail("bob", "WKS2", "0xC000006A", m)
        rows = self.c.data()["failures"]["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["n"], rows[0]["via"], rows[0]["code"]), (3, "both", "0xC000006A"))

    def test_the_side_that_saw_more_counts(self):
        self.fail("bob", "WKS2", "0xC000006A", 10)
        self.fail("bob", "WKS2", "0xC000006A", 20, server=False)
        self.fail("bob", "WKS2", "0xC000006A", 30, server=False)
        self.assertEqual(self.c.data()["failures"]["rows"][0]["n"], 3)

    def test_locked_account_is_flagged(self):
        self.fail("carol", "NB1", "0xC000006A", 12)
        self.fail("carol", "NB1", "0xC0000234", 10)
        self.assertTrue(self.c.data()["failures"]["rows"][0]["locked"])

    def test_one_machine_many_accounts_is_spraying(self):
        for i, u in enumerate(["a1", "a2", "a3", "a4", "a5"]):
            self.fail(u, "EVIL", "0xC0000064", 10 + i)
        spray = self.c.data()["failures"]["spray"]
        self.assertEqual(spray[0][:2], ["EVIL", 5])

    def test_four_accounts_are_not_yet_spraying(self):
        for i, u in enumerate(["a1", "a2", "a3", "a4"]):
            self.fail(u, "PC1", "0xC0000064", 10 + i)
        self.assertEqual(self.c.data()["failures"]["spray"], [])

    def test_failures_show_up_on_the_account(self):
        self.fail("bob", "WKS2", "0xC000006A", 10)
        rows = {r["key"]: r for r in self.c.data()["accounts"]["rows"]}
        self.assertEqual(rows["BOB"]["failed"], 1)
        self.assertEqual(rows["BOB"]["n"], 0)


# ---------------------------------------------------------------------------
class Accounts(CollectorTest):
    def test_one_logon_seen_three_times_counts_once(self):
        self.c.agent("WKS1")
        self.c.agent("FS04")
        self.c.agent("DC01", is_dc=True)
        t = ts(15)
        self.c.push("WKS1", ev(8001, "outgoing", t, user="alice", target_server="cifs/fs04.corp.local"))
        self.c.push("FS04", ev(8003, "incoming", t, user="alice", workstation="WKS1"))
        self.c.push("DC01", ev(8004, "domain", t, user="alice", workstation="WKS1", target_server="FS04"))
        rows = {r["key"]: r for r in self.c.data()["accounts"]["rows"]}
        a = rows["ALICE"]
        self.assertEqual((a["n"], a["machines"], a["targets"]), (1, 1, 1))
        code, raw = self.c.get("/api/account", name="CORP\\alice", range="30d")
        d = json.loads(raw)
        self.assertEqual(d["n"], 1)
        self.assertEqual([x[0] for x in d["to"]], ["FS04"])

    def test_unknown_account(self):
        code, raw = self.c.get("/api/account", name="nobody", range="30d")
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(raw).get("unknown"))


# ---------------------------------------------------------------------------
class Readiness(CollectorTest):
    def verdict(self, machine):
        rows = self.c.data()["readiness"]["rows"]
        return [r for r in rows if r["machine"] == machine][0]

    def test_quiet_for_thirty_days_is_ready(self):
        self.c.agent("OLD1")
        self.c.push("OLD1", ev(8001, "outgoing", ts(40 * 24 * 60), user="svc", target_server="cifs/fs01"))
        self.assertEqual(self.verdict("OLD1")["out"]["st"], "ready")

    def test_recent_ntlm_is_busy(self):
        self.c.agent("BUSY1")
        self.c.push("BUSY1", ev(8001, "outgoing", ts(40 * 24 * 60), user="svc", target_server="cifs/fs01"),
                    ev(8001, "outgoing", ts(60), user="svc", target_server="cifs/fs01"))
        self.assertEqual(self.verdict("BUSY1")["out"]["st"], "busy")

    def test_auditing_off_is_not_ready(self):
        self.c.agent("BLIND1", outgoing_audit="off")
        self.c.push("BLIND1", ev(8001, "outgoing", ts(40 * 24 * 60), user="svc", target_server="cifs/fs01"))
        self.assertEqual(self.verdict("BLIND1")["out"]["st"], "noaudit")

    def test_short_watch_is_not_ready(self):
        self.c.agent("NEW1")
        self.assertEqual(self.verdict("NEW1")["out"]["st"], "young")


class MachinesWithoutAgent(CollectorTest):
    def test_client_seen_only_by_the_dc_is_listed(self):
        self.c.agent("DC01", is_dc=True)
        self.c.agent("WKS1")
        self.c.push("DC01", ev(4776, "dcval", ts(10), user="alice", workstation="NOAGENT1", failure_code="0x0"),
                    ev(4776, "dcval", ts(11), user="alice", workstation="WKS1", failure_code="0x0"))
        names = [r["machine"] for r in self.c.data()["agentless"]["rows"]]
        self.assertEqual(names, ["NOAGENT1"])


# ---------------------------------------------------------------------------
class Report(CollectorTest):
    def test_renders_in_every_language_and_range(self):
        self.c.agent("WKS1")
        self.c.push("WKS1", ev(8001, "outgoing", ts(30), user="alice", target_server="cifs/fs01"))
        for lang, title in (("de", "NTLM-Statusbericht"), ("en", "NTLM status report")):
            for rng in ("7d", "30d", "90d"):
                col._PANEL_CACHE.clear()
                code, raw = self.c.get("/report", lang=lang, range=rng, tzoff="120")
                self.assertEqual(code, 200)
                html = raw.decode("utf-8")
                self.assertIn("<h1>%s</h1>" % title, html)
                self.assertNotIn("Traceback", html)

    def test_empty_database(self):
        code, raw = self.c.get("/report")
        self.assertEqual(code, 200)
        self.assertIn("noch keine Anmeldungen", raw.decode("utf-8"))

    def test_no_comparison_without_enough_history(self):
        self.c.agent("WKS1")
        self.c.push("WKS1", ev(8001, "outgoing", ts(30), user="alice", target_server="cifs/fs01"))
        code, raw = self.c.get("/report", lang="en", range="30d")
        self.assertIn("Not enough data yet to compare", raw.decode("utf-8"))

    def test_static_links_point_to_files(self):
        code, raw = self.c.get("/report", lang="en", range="7d", static="1")
        html = raw.decode("utf-8")
        self.assertIn('href="report-de-7d.html"', html)
        self.assertNotIn('href="/report?', html)


class Pages(CollectorTest):
    def test_dashboard_and_machine_detail_answer(self):
        self.c.agent("FS01")
        self.c.push("FS01", ev(8003, "incoming", ts(5), user="alice", workstation="WKS1"))
        self.assertEqual(self.c.get("/")[0], 200)
        code, raw = self.c.get("/api/machine", name="FS01", range="30d")
        self.assertEqual(code, 200)
        self.assertFalse(json.loads(raw).get("unknown"))
        code, raw = self.c.get("/api/export.csv", range="30d")
        self.assertEqual(code, 200)
        self.assertIn(b"alice", raw)


if __name__ == "__main__":
    unittest.main()
