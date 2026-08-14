// NTLM-Analyzer - find out who still uses NTLM in your Active Directory.
// Copyright (C) 2026  Nobrac / Carbon / NoPCAP
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! One collection cycle: push status (heartbeat + audit state), read the event
//! logs, map them and push them to the collector. Watermarks are kept per
//! purpose (4624/4769/8001/8004 and the enhanced 40xx queries).

use serde::Serialize;
use std::collections::HashMap;

use crate::config::{self, Config, AGENT_VERSION};
use crate::eventlog::{self, RawEvent};

// 4624 ueber LmPackageName filtern -> faengt auch Negotiate->NTLM-Fallback.
const DATA_4624: &str = "(*[EventData[Data[@Name='LmPackageName']='NTLM V1']] or *[EventData[Data[@Name='LmPackageName']='NTLM V2']])";

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
const LSA_ROOT: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const NTLM_CHANNEL: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NTLM/Operational";
const DEVGUARD_CG: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard";
const NETLOGON: &str = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters";
const WINNT_CV: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

// ----------------------------- Datenmodelle -----------------------------

#[derive(Serialize, Default)]
pub struct Event {
    pub record_id: i64,
    pub log: String,
    pub event_id: i64,
    pub kind: String,
    pub event_time: String,
    pub user: Option<String>,
    pub domain: Option<String>,
    pub ntlm_version: Option<String>,
    pub process: Option<String>,
    pub target_server: Option<String>,
    pub workstation: Option<String>,
    pub ip: Option<String>,
    pub logon_type: Option<String>,
    pub enc_type: Option<String>,
    pub auth_method: Option<String>,
    /// Only for the enhanced 40xx events (Server 2025 / Win11 24H2): plain-text
    /// reason why NTLM was used instead of Kerberos.
    pub reason: Option<String>,
    /// Numeric Usage ID behind `reason` (KB5064479, 0-11). Kept separately so
    /// findings can be grouped by cause - each ID has its own remediation.
    pub reason_id: Option<String>,
    /// MIC status: "Protected" / "Unprotected". An unprotected message integrity
    /// code is one of the things that makes an NTLM session relay-able.
    pub mic: Option<String>,
    /// Channel binding (Extended Protection for Authentication):
    /// "Supported" / "Not Supported". Missing EPA is the other relay enabler.
    pub epa: Option<String>,
    /// Target operating system as reported by 4032 - outdated server OSes are
    /// a finding of their own.
    pub server_os: Option<String>,
    /// Kerberos failure code from unsuccessful 4769 events (e.g. 0x7 = SPN not
    /// found). On systems without the enhanced 40xx events this is the only
    /// early warning for the causes behind NTLM fallback. None on success.
    pub failure_code: Option<String>,
    /// Full image path when Windows reported one. Grouping still happens by
    /// file name (see base_name), but for generic names like svchost.exe the
    /// path is what actually identifies the application. None when the event
    /// only carried a bare name.
    pub process_path: Option<String>,
}

#[derive(Serialize)]
struct AgentStatus {
    source: String,
    is_dc: bool,
    agent_version: String,
    outgoing_audit: String,
    incoming_audit: String,
    domain_audit: String,
    /// LmCompatibilityLevel: which NTLM versions the machine still *permits*.
    /// Config-side evidence - a machine can show no NTLMv1 for months and still
    /// allow it. 5 = NTLMv2 only, which is the target state.
    lm_level: String,
    /// BlockNtlmv1SSO: 0 = audit (default), 1 = enforce. Microsoft flips the
    /// default to enforce in October 2026.
    block_v1sso: String,
    /// Configured maximum size of the NTLM/Operational log in KB. The default
    /// is only ~1 MB - with incoming auditing enabled the log can roll over
    /// between two poll cycles, silently losing events. "unset" = OS default.
    ntlm_log_kb: String,
    /// Credential Guard state. Machines with Credential Guard enabled are NOT
    /// affected by the BlockNtlmv1SSO change - it already prevents NTLMv1
    /// cryptography. Read from the registry, so this is the *configured*
    /// value, not proof that it is actually running.
    cred_guard: String,
    /// Product name and build of the reporting machine. Decides which events
    /// this machine can produce at all - without it the dashboard cannot tell
    /// "no 40xx data because too old" from "because auditing is off".
    os_version: String,
    /// Restriction (deny) policies, as opposed to the audit ones above:
    /// allow / deny-accounts / deny-all. Shows which machines already run in
    /// enforce mode instead of inferring it from blocked events appearing.
    restrict_out: String,
    restrict_in: String,
    restrict_dom: String,
    /// Exception lists already configured in policy. The generator can then
    /// point out what is already covered instead of proposing duplicates.
    exc_client: Option<String>,
    exc_dc: Option<String>,
}

#[derive(Serialize)]
struct IngestBody<'a> {
    source: &'a str,
    events: &'a [Event],
}

// ----------------------------- Hauptzyklus -----------------------------

pub fn run_cycle(cfg: &Config) -> Result<(), String> {
    if cfg.enable_outgoing_audit {
        if let Err(e) = enable_outgoing_audit() {
            config::log(&format!(
                "Could not enable outgoing audit (admin rights?): {e}"
            ));
        }
    }

    let me = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());
    let dc = is_dc();

    // 1) Status/heartbeat (independent of events, on every run)
    let status = AgentStatus {
        source: me.clone(),
        is_dc: dc,
        agent_version: AGENT_VERSION.to_string(),
        outgoing_audit: outgoing_audit(),
        incoming_audit: incoming_audit(),
        domain_audit: domain_audit(),
        lm_level: lm_level(),
        block_v1sso: block_v1sso(),
        cred_guard: cred_guard(),
        ntlm_log_kb: ntlm_log_kb(),
        os_version: os_version(),
        restrict_out: restrict_state(LSA, "RestrictSendingNTLMTraffic"),
        restrict_in: restrict_state(LSA, "RestrictReceivingNTLMTraffic"),
        restrict_dom: restrict_state(NETLOGON, "RestrictNTLMInDomain"),
        exc_client: read_multi_sz(LSA, "ClientAllowedNTLMServers"),
        exc_dc: read_multi_sz(NETLOGON, "DCAllowedNTLMServers"),
    };
    let status_url = format!("{}/status", cfg.collector_url.trim_end_matches('/'));
    match serde_json::to_string(&status) {
        Ok(body) => {
            if let Err(e) = post_json(&status_url, &cfg.api_key, &body) {
                config::log(&format!("[{me}] status push failed: {e}"));
            }
        }
        Err(e) => config::log(&format!("[{me}] status JSON: {e}")),
    }

    // 2) Events sammeln
    let mut state = config::load_state();
    let mut new_seen: HashMap<String, i64> = HashMap::new();
    let mut collected: Vec<Event> = Vec::new();
    let window_ms = cfg.days_back as i64 * 24 * 60 * 60 * 1000;

    if dc {
        gather(
            "Security",
            "Security#4624",
            "EventID=4624",
            DATA_4624,
            window_ms,
            &state,
            &me,
            map_4624,
            &mut collected,
            &mut new_seen,
            false,
        );
        if !cfg.skip_kerberos {
            gather(
                "Security",
                "Security#4769",
                "EventID=4769",
                "",
                window_ms,
                &state,
                &me,
                map_4769,
                &mut collected,
                &mut new_seen,
                false,
            );
        }
        gather(
            "Microsoft-Windows-NTLM/Operational", "NTLM#8004",
            "(EventID=8004 or EventID=8005 or EventID=8006 or EventID=4004 or EventID=4005 or EventID=4006)", "", window_ms,
            &state, &me, map_dc_ntlm, &mut collected, &mut new_seen, false,
        );
        // Enhanced DC audits (Server 2025): they carry the NTLM version straight
        // from the DC log - on older systems the query simply returns nothing.
        gather(
            "Microsoft-Windows-NTLM/Operational",
            "NTLM#40dc",
            "(EventID=4030 or EventID=4031 or EventID=4032 or EventID=4033)",
            "",
            window_ms,
            &state,
            &me,
            map_enhanced,
            &mut collected,
            &mut new_seen,
            true,
        );
    }
    gather(
        "Microsoft-Windows-NTLM/Operational",
        "NTLM#8001",
        "(EventID=8001 or EventID=4001)",
        "",
        window_ms,
        &state,
        &me,
        map_8001,
        &mut collected,
        &mut new_seen,
        false,
    );
    // Incoming NTLM: 8002 names the local service that accepts it, 8003 the
    // remote account that came in. Both need the "Audit Incoming NTLM Traffic"
    // policy; without it the queries simply return nothing.
    gather(
        "Microsoft-Windows-NTLM/Operational",
        "NTLM#8002",
        "(EventID=8002 or EventID=4002)",
        "",
        window_ms,
        &state,
        &me,
        map_8002,
        &mut collected,
        &mut new_seen,
        false,
    );
    gather(
        "Microsoft-Windows-NTLM/Operational",
        "NTLM#8003",
        "(EventID=8003 or EventID=4003)",
        "",
        window_ms,
        &state,
        &me,
        map_8003,
        &mut collected,
        &mut new_seen,
        false,
    );
    // Erweiterte Client-/Server-Audits + NTLMv1-SSO (Server 2025 / Win11 24H2).
    // 4024/4025 are the time-critical part: NTLMv1-derived credentials stop
    // working in October 2026 (BlockNtlmv1SSO switches to enforce).
    gather(
        "Microsoft-Windows-NTLM/Operational", "NTLM#40cs",
        "(EventID=4020 or EventID=4021 or EventID=4022 or EventID=4023 or EventID=4024 or EventID=4025)",
        "", window_ms,
        &state, &me, map_enhanced, &mut collected, &mut new_seen, true,
    );

    // 3) Nothing to send: still advance the watermarks (don't re-read noise)
    if collected.is_empty() {
        merge_watermarks(&mut state, new_seen);
        config::save_state(&state)?;
        config::log(&format!("[{me}] Keine neuen NTLM-Events."));
        return Ok(());
    }

    // 4) Push in batches; only store watermarks after a successful push
    let ingest_url = format!("{}/ingest", cfg.collector_url.trim_end_matches('/'));
    let batch_size = 500usize;
    let mut total = 0usize;
    let mut idx = 0usize;
    while idx < collected.len() {
        let end = (idx + batch_size).min(collected.len());
        let body = serde_json::to_string(&IngestBody {
            source: &me,
            events: &collected[idx..end],
        })
        .map_err(|e| e.to_string())?;
        post_json(&ingest_url, &cfg.api_key, &body)
            .map_err(|e| format!("[{me}] push failed: {e}"))?;
        total += end - idx;
        idx = end;
    }

    merge_watermarks(&mut state, new_seen);
    config::save_state(&state)?;
    config::log(&format!("[{me}] {total} Events gesendet."));
    Ok(())
}

fn merge_watermarks(state: &mut HashMap<String, i64>, new_seen: HashMap<String, i64>) {
    for (k, v) in new_seen {
        let cur = *state.get(&k).unwrap_or(&0);
        if v > cur {
            state.insert(k, v);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn gather(
    log: &str,
    key: &str,
    id_clause: &str,
    data_clause: &str,
    window_ms: i64,
    state: &HashMap<String, i64>,
    me: &str,
    mapper: fn(&RawEvent) -> Option<Event>,
    collected: &mut Vec<Event>,
    new_seen: &mut HashMap<String, i64>,
    rendered: bool,
) {
    let last = state.get(key).copied();
    match eventlog::collect(log, id_clause, data_clause, window_ms, last, rendered) {
        Ok((raw, seen)) => {
            new_seen.insert(key.to_string(), seen);
            for e in &raw {
                if let Some(ev) = mapper(e) {
                    collected.push(ev);
                }
            }
        }
        Err(e) => config::log(&format!("[{me}] reading '{log}' ({key}) failed: {e}")),
    }
}

// ----------------------------- Event-Mapping -----------------------------

fn map_4624(e: &RawEvent) -> Option<Event> {
    let u = e.named.get("TargetUserName").cloned().unwrap_or_default();
    if u.trim().is_empty() || u == "-" || u == "ANONYMOUS LOGON" {
        return None;
    }
    let lm = e
        .named
        .get("LmPackageName")
        .map(|s| s.as_str())
        .unwrap_or("");
    let ver = if lm.contains("V1") {
        "NTLMv1"
    } else if lm.contains("V2") {
        "NTLMv2"
    } else {
        return None;
    };
    let apkg = e
        .named
        .get("AuthenticationPackageName")
        .map(|s| s.as_str())
        .unwrap_or("");
    let auth_method = if apkg == "Negotiate" {
        "Fallback"
    } else {
        "Direct"
    };

    Some(Event {
        record_id: e.record_id,
        log: "Security".to_string(),
        event_id: e.event_id,
        kind: "auth".to_string(),
        event_time: e.time.clone(),
        user: Some(u),
        domain: e.named.get("TargetDomainName").cloned(),
        ntlm_version: Some(ver.to_string()),
        workstation: e.named.get("WorkstationName").cloned(),
        ip: e.named.get("IpAddress").cloned(),
        logon_type: e.named.get("LogonType").cloned(),
        auth_method: Some(auth_method.to_string()),
        ..Default::default()
    })
}

/// Normalises a Kerberos status ("0x00000007" -> "0x7") so the dashboard can
/// group identical codes reported in different widths.
fn norm_krb_status(st: &str) -> String {
    let t = st.trim().to_lowercase();
    let hex = t.strip_prefix("0x").unwrap_or(&t).trim_start_matches('0');
    format!("0x{}", if hex.is_empty() { "0" } else { hex })
}

fn map_4769(e: &RawEvent) -> Option<Event> {
    let u = e.named.get("TargetUserName").cloned().unwrap_or_default();
    let svc = e.named.get("ServiceName").cloned().unwrap_or_default();
    if svc.is_empty() || svc == "krbtgt" || svc.starts_with("krbtgt") {
        return None;
    }
    // Failed requests are kept as their own kind: on systems without the 40xx
    // events (2016/2019/2022) the failure code is the only early warning for
    // NTLM-fallback causes such as a missing SPN (0x7). Machine accounts are
    // kept for failures - a computer account with an SPN problem matters -
    // while successes keep the old person-only rule to limit noise.
    let failure = e
        .named
        .get("Status")
        .filter(|st| !is_success_status(st))
        .map(|st| norm_krb_status(st));
    if failure.is_none() && (u.trim().is_empty() || u.ends_with('$')) {
        return None;
    }
    if u.trim().is_empty() {
        return None;
    }
    let enc = map_enc(
        e.named
            .get("TicketEncryptionType")
            .map(|s| s.as_str())
            .unwrap_or(""),
    );
    let ip = e
        .named
        .get("IpAddress")
        .map(|s| s.trim_start_matches("::ffff:").to_string());

    Some(Event {
        record_id: e.record_id,
        log: "Security".to_string(),
        event_id: e.event_id,
        kind: if failure.is_some() {
            "krbfail"
        } else {
            "kerberos"
        }
        .to_string(),
        failure_code: failure,
        event_time: e.time.clone(),
        user: Some(u),
        domain: e.named.get("TargetDomainName").cloned(),
        target_server: Some(svc),
        ip,
        enc_type: Some(enc),
        ..Default::default()
    })
}

/// DC-side NTLM credential validation (plus the 4004-4006 enforce twins with
/// identical layout - 4004 is also what fires for the MS-CHAPv2 blind spot).
/// Microsoft splits the audit side across three IDs,
/// all with the same field layout - collecting only 8004 leaves two blind spots:
///   8004  request from a domain member over the secure channel (the common case)
///   8005  NTLM straight to the DC itself (e.g. a type 3 logon to the DC)
///   8006  request from a *trusted domain* over the secure channel
/// Under enforcement these turn into 4004/4005/4006 respectively.
fn map_dc_ntlm(e: &RawEvent) -> Option<Event> {
    let p = &e.positional;
    let u = p.get(1).cloned().unwrap_or_default();
    if u.trim().is_empty() || u == "-" || u == "ANONYMOUS LOGON" {
        return None;
    }
    // Machine accounts are kept on purpose: machine accounts falling back to
    // NTLM is a finding in itself, and the dashboard can filter them out.
    Some(Event {
        record_id: e.record_id,
        log: "NTLM/Operational".to_string(),
        event_id: e.event_id,
        kind: "domain".to_string(),
        event_time: e.time.clone(),
        user: Some(u),
        domain: p.get(2).cloned(),
        // 8005 has no secure channel (the DC itself is the target), so the
        // field may be empty - that is fine, the source machine still tells
        // the story.
        target_server: p.first().cloned().filter(|s| !s.trim().is_empty()),
        workstation: p.get(3).cloned(),
        ..Default::default()
    })
}

/// Splits a process path into its bare file name ("C:\\...\\w3wp.exe" -> "w3wp.exe").
/// Keeps a value only if it looks like a real path (contains a separator).
/// A bare "lsass.exe" carries no extra information and is dropped so the
/// detail view does not show a redundant line.
fn full_path(n: &str) -> Option<String> {
    let v = n.trim();
    if v.len() > 3 && (v.contains('\\') || v.contains('/')) && !v.starts_with('(') {
        Some(v.to_string())
    } else {
        None
    }
}

fn base_name(n: &str) -> String {
    n.rsplit(['\\', '/']).next().unwrap_or(n).to_string()
}

/// Picks the process name out of an event: a value that looks like an
/// executable wins, regardless of its position - the field order of the NTLM
/// events is not officially documented.
/// Same selection logic as sniff_process, but returns the raw value so the
/// full path survives. Kept as its own function to avoid changing the many
/// existing sniff_process call sites.
fn sniff_process_raw(e: &RawEvent, fallback_idx: usize) -> Option<String> {
    let looks_exe = |v: &str| {
        let l = v.to_lowercase();
        l.ends_with(".exe") || l.ends_with(".dll") || l.contains('\\')
    };
    e.named
        .values()
        .chain(e.positional.iter())
        .map(|s| s.trim())
        .find(|s| !s.is_empty() && *s != "-" && looks_exe(s))
        .map(|s| s.to_string())
        .or_else(|| {
            e.positional
                .get(fallback_idx)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && *s != "-")
                .map(|s| s.to_string())
        })
}

fn sniff_process(e: &RawEvent, fallback_idx: usize) -> Option<String> {
    let looks_exe = |v: &str| {
        let l = v.to_lowercase();
        l.ends_with(".exe") || l.ends_with(".dll") || l.contains('\\')
    };
    e.named
        .values()
        .chain(e.positional.iter())
        .map(|s| s.trim())
        .find(|s| !s.is_empty() && *s != "-" && looks_exe(s))
        .map(|s| base_name(s))
        .or_else(|| {
            e.positional
                .get(fallback_idx)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && *s != "-")
                .map(base_name)
        })
}

/// 8002 - incoming NTLM on this machine. The valuable part is the *calling
/// process*: it names the local service that accepts NTLM (IIS, SQL, svchost
/// and friends). Requires the "Audit Incoming NTLM Traffic" policy.
/// Documented field order: PID, process name, LUID, user identity, domain.
fn map_8002(e: &RawEvent) -> Option<Event> {
    let p = &e.positional;
    let nonempty = |i: usize| p.get(i).cloned().filter(|s| !s.trim().is_empty());
    let pid = p.first().cloned().unwrap_or_default();

    // The identity here is the identity of the *calling process*, not the
    // remote user - do not present it as the authenticating account.
    let process_path = sniff_process_raw(e, 1).as_deref().and_then(full_path);
    let process = sniff_process(e, 1).or_else(|| {
        // PID 4 = kernel mode. Not only SMB: HTTP.sys also runs there, which
        // covers WinRM, ADWS, SSRS and the Remote Desktop Gateway.
        Some(if pid == "4" {
            "(Kernel: SMB/HTTP.sys)".to_string()
        } else if pid.is_empty() {
            "(unknown)".to_string()
        } else {
            format!("(PID {pid})")
        })
    });

    Some(Event {
        record_id: e.record_id,
        log: "NTLM/Operational".to_string(),
        event_id: e.event_id,
        kind: "incoming".to_string(),
        event_time: e.time.clone(),
        process,
        process_path,
        user: nonempty(3),
        domain: nonempty(4),
        ..Default::default()
    })
}

/// 8003 - incoming NTLM including the remote account. Complements 8002:
/// 8002 says which local service accepted it, 8003 says who came in.
/// Documented field order: user, domain, workstation, PID, process, logon type.
fn map_8003(e: &RawEvent) -> Option<Event> {
    let p = &e.positional;
    let nonempty = |i: usize| p.get(i).cloned().filter(|s| !s.trim().is_empty());
    let user = nonempty(0)?;
    if user == "-" || user == "ANONYMOUS LOGON" {
        return None;
    }
    let pid = p.get(3).cloned().unwrap_or_default();
    let process_path = sniff_process_raw(e, 4).as_deref().and_then(full_path);
    let process = sniff_process(e, 4).or_else(|| {
        if pid == "4" {
            Some("(Kernel: SMB/HTTP.sys)".to_string())
        } else {
            None
        }
    });

    Some(Event {
        record_id: e.record_id,
        log: "NTLM/Operational".to_string(),
        event_id: e.event_id,
        kind: "incoming".to_string(),
        event_time: e.time.clone(),
        user: Some(user),
        domain: nonempty(1),
        workstation: nonempty(2),
        process,
        logon_type: nonempty(5).filter(|s| s.chars().all(|c| c.is_ascii_digit())),
        ..Default::default()
    })
}

fn map_8001(e: &RawEvent) -> Option<Event> {
    let p = &e.positional;
    let nonempty = |i: usize| p.get(i).cloned().filter(|s| !s.is_empty());

    let target = nonempty(0);
    let pid = p.get(3).cloned().unwrap_or_default();
    let pname = nonempty(4);
    let user = nonempty(6).or_else(|| nonempty(1));
    let domain = nonempty(7).or_else(|| nonempty(2));

    // Keep the full path alongside the grouped file name: for generic names
    // like svchost.exe the path is what identifies the actual application.
    let process_path = pname.as_deref().and_then(full_path);
    let process_val = match &pname {
        Some(n) => {
            let base = n
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(n.as_str())
                .to_string();
            Some(base)
        }
        None => Some(if pid == "4" {
            "(Kernel: SMB/HTTP.sys)".to_string()
        } else {
            format!("(PID {pid})")
        }),
    };

    Some(Event {
        record_id: e.record_id,
        log: "NTLM/Operational".to_string(),
        event_id: e.event_id,
        kind: "outgoing".to_string(),
        event_time: e.time.clone(),
        user,
        domain,
        process: process_val,
        process_path,
        target_server: target,
        ..Default::default()
    })
}

// ------------------- Erweiterte NTLM-Audits (Server 2025 / Win11 24H2) -------------------
// Dokumentiert in KB5064479. Jedes Log existiert doppelt: gerade ID = Information
// (Standard-NTLM, i.d.R. NTLMv2), ungerade ID = Warning (Downgrade, z.B. NTLMv1,
// missing EPA or a missing MIC). Microsoft does NOT document the exact XML field
// names, so lookups here are tolerant: first by name fragment, then by value
// pattern. Whatever is not found simply stays empty - the event is never lost.

/// Reason-IDs des Client-Logs (4020/4021) laut KB5064479.
fn reason_text(id: &str) -> Option<String> {
    let t = match id.trim() {
        "0" => "Unknown reason",
        "1" => "NTLM called directly by the application",
        "2" => "Local account logon",
        "4" => "Cloud account logon",
        "5" => "Target name was missing or empty",
        "6" => "Target name could not be resolved by Kerberos",
        "7" => "Target name contains an IP address",
        "8" => "Target name is duplicated in Active Directory",
        "9" => "No line of sight to a domain controller",
        "10" => "NTLM called over loopback",
        "11" => "NTLM called with a null session",
        _ => return None,
    };
    Some(t.to_string())
}

/// Finds a value whose field name contains all given fragments
/// (case-insensitive, z.B. ["target","ip"] -> "TargetIp"/"Target_IP"/...).
fn find_named(e: &RawEvent, parts: &[&str]) -> Option<String> {
    for (k, v) in &e.named {
        let lk = k.to_lowercase();
        if parts.iter().all(|p| lk.contains(p)) {
            let v = v.trim();
            if !v.is_empty() && v != "-" {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Like find_named, but with an EXACT field name. Needed e.g. for "Status": a
/// substring search would otherwise also match "SessionKeyStatus" or
/// "ChannelBindingStatus".
fn find_named_exact(e: &RawEvent, name: &str) -> Option<String> {
    for (k, v) in &e.named {
        if k.trim().eq_ignore_ascii_case(name) {
            let v = v.trim();
            if !v.is_empty() && v != "-" {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Searches ALL values (named + positional) for a pattern.
fn find_value<F: Fn(&str) -> bool>(e: &RawEvent, pred: F) -> Option<String> {
    e.named
        .values()
        .chain(e.positional.iter())
        .map(|s| s.trim())
        .find(|s| !s.is_empty() && *s != "-" && pred(s))
        .map(|s| s.to_string())
}

fn looks_like_ip(s: &str) -> bool {
    let core = s.trim_start_matches("::ffff:");
    (core.split('.').count() == 4
        && core
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
        || (s.contains(':') && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':'))
}

/// Version aus einem beliebigen Feldwert lesen: "NTLMv1"/"NTLM V1"/"NTLMv2"...
fn sniff_version(e: &RawEvent) -> Option<String> {
    let v = find_value(e, |s| {
        let l = s.to_lowercase().replace(' ', "");
        l.starts_with("ntlmv1") || l.starts_with("ntlmv2") || l == "v1" || l == "v2"
    })?;
    let l = v.to_lowercase().replace(' ', "");
    if l.contains("v1") {
        Some("NTLMv1".to_string())
    } else {
        Some("NTLMv2".to_string())
    }
}

/// Reads a value from the rendered message text by its label. The labels come
/// from KB5064479; since the text is localized, English AND German variants are
/// tried. Line format: "Label: value".
fn from_message(e: &RawEvent, labels: &[&str]) -> Option<String> {
    let msg = e.message.as_deref()?;
    for line in msg.lines() {
        let line = line.trim();
        let (lab, val) = match line.split_once(':') {
            Some(x) => x,
            None => continue,
        };
        let lab_norm = lab.trim().to_lowercase();
        if labels.iter().any(|l| lab_norm == l.to_lowercase()) {
            let v = val.trim();
            // Ignore placeholders and empty values
            if !v.is_empty() && v != "-" && !(v.starts_with('<') && v.ends_with('>')) {
                return Some(v.to_string());
            }
        }
    }
    None
}

// Beschriftungen laut KB5064479 (en) + gaengige deutsche Entsprechungen.
const L_PROCESS: &[&str] = &["Process Name", "Prozessname", "Name des Prozesses"];
const L_USER: &[&str] = &[
    "Username",
    "User Name",
    "Benutzername",
    "Client Name",
    "Clientname",
];
const L_DOMAIN: &[&str] = &[
    "Domain",
    "Domäne",
    "Domaene",
    "Client Domain",
    "Clientdomäne",
];
const L_TARGET_RES: &[&str] = &["Target Resource", "Zielressource", "Service Binding"];
const L_TARGET_MACHINE: &[&str] = &[
    "Target Machine",
    "Zielcomputer",
    "Server Name",
    "Servername",
];
// For outgoing events (4020/4021) "Target IP" is the remote end; for
// server-/DC-side events (4022+) it is the client IP of the source.
const L_IP_OUT: &[&str] = &["Target IP", "Ziel-IP"];
const L_IP_IN: &[&str] = &["Client IP", "Client-IP", "Server IP"];
const L_CLIENT_MACHINE: &[&str] = &["Client Machine", "Clientcomputer", "Hostname"];
const L_VERSION: &[&str] = &["NTLM Version", "NTLM-Version"];
const L_REASON: &[&str] = &["Reason", "Grund"];
const L_REASON_ID: &[&str] = &["Reason ID", "Grund-ID"];
const L_MIC: &[&str] = &["MIC Status", "MIC-Status"];
const L_SRV_OS: &[&str] = &["Server OS", "Serverbetriebssystem"];
const L_EPA: &[&str] = &["Channel Binding", "Kanalbindung"];

fn map_enhanced(e: &RawEvent) -> Option<Event> {
    let id = e.event_id;
    // gerade = Information, ungerade = Warning (Downgrade/unsicher)
    let downgrade = matches!(id, 4021 | 4023 | 4031 | 4033);

    let kind = match id {
        4020 | 4021 => "outgoing", // client: outgoing NTLM incl. process
        // Server side: carries the source (client machine + IP), target SPN and
        // version - the same statement as 8004, hence "domain".
        4022 | 4023 => "domain",
        4030..=4033 => "domain",    // DC-Sicht
        4024 | 4025 => "ntlmv1sso", // NTLMv1-derived SSO credentials
        _ => return None,
    };

    // Version: 1) gerenderter Text (dokumentierte Beschriftung, zuverlaessigste
    // source), 2) value pattern in the XML, 3) semantics of the event ID.
    let version = from_message(e, L_VERSION)
        .map(|v| {
            if v.to_lowercase().replace(' ', "").contains("v1") {
                "NTLMv1".to_string()
            } else {
                "NTLMv2".to_string()
            }
        })
        .or_else(|| sniff_version(e))
        .or_else(|| match id {
            // 4024/4025 are NTLMv1-derived by definition.
            4024 | 4025 => Some("NTLMv1".to_string()),
            _ => None,
        });

    // Reason (client log 4020/4021 only): 1) plain text from the rendered text,
    // 2) translate the reason ID from the text, 3) XML field "reason".
    let mut reason = from_message(e, L_REASON)
        .or_else(|| from_message(e, L_REASON_ID).and_then(|id| reason_text(&id)))
        .or_else(|| {
            find_named(e, &["reason"]).and_then(|v| {
                if v.chars().all(|c| c.is_ascii_digit()) {
                    reason_text(&v)
                } else {
                    Some(v)
                }
            })
        });
    if reason.is_none() && downgrade {
        reason = Some("Downgrade detected (NTLMv1, missing EPA or missing MIC)".into());
    }

    // The numeric Usage ID is kept alongside the text so the dashboard can group
    // findings by cause. Only 0-11 are defined (KB5064479); anything else is
    // dropped rather than shown as a bogus category.
    let reason_id = from_message(e, L_REASON_ID)
        .or_else(|| find_named(e, &["reason", "id"]))
        .or_else(|| find_named(e, &["usage", "id"]))
        .map(|v| v.trim().to_string())
        .filter(|v| reason_text(v).is_some());

    // Relay indicators. Both are plain words in the rendered text; normalised to
    // a small fixed vocabulary so the dashboard does not have to guess.
    let norm_mic = |v: String| {
        let l = v.to_lowercase();
        if l.contains("unprotected") || l.contains("ungeschützt") {
            Some("Unprotected".to_string())
        } else if l.contains("protected") || l.contains("geschützt") {
            Some("Protected".to_string())
        } else {
            None
        }
    };
    let norm_epa = |v: String| {
        let l = v.to_lowercase();
        if l.contains("not supported") || l.contains("nicht unterstützt") {
            Some("Not Supported".to_string())
        } else if l.contains("supported") || l.contains("unterstützt") {
            Some("Supported".to_string())
        } else {
            None
        }
    };
    let mic = from_message(e, L_MIC)
        .or_else(|| find_named(e, &["mic"]))
        .and_then(norm_mic);
    let epa = from_message(e, L_EPA)
        .or_else(|| find_named(e, &["channel", "binding"]))
        .and_then(norm_epa);

    // 4032 names the target's operating system - outdated server OSes are a
    // finding of their own (they often cannot do anything better than NTLM).
    let server_os = from_message(e, L_SRV_OS)
        .or_else(|| find_named(e, &["server", "os"]))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v != "-");
    if reason.is_none() && id == 4024 {
        reason = Some("NTLMv1-derived SSO credentials - blocked from October 2026".into());
    }
    if reason.is_none() && id == 4025 {
        reason = Some("NTLMv1-derived SSO credentials were already blocked".into());
    }

    // Surface failed logons: the status field is 0x0 on success. Real-world
    // example: 0xc000006d = bad user name or bad credentials.
    let status = find_named_exact(e, "Status").unwrap_or_default();
    let failed = !status.is_empty()
        && status != "0x0"
        && status != "0"
        && !status.eq_ignore_ascii_case("STATUS_SUCCESS");
    if failed {
        let detail = from_message(e, &["Status Message", "Statusmeldung"])
            .filter(|m| !m.eq_ignore_ascii_case("STATUS_SUCCESS") && m != "0")
            .unwrap_or_else(|| format!("Status {status}"));
        reason = Some(match reason {
            Some(r) => format!("{r} | logon failed: {detail}"),
            None => format!("logon failed: {detail}"),
        });
    }

    // Jeweils: gerenderter Text -> XML-Feldname -> Wertmuster.
    let process_raw = from_message(e, L_PROCESS)
        .or_else(|| find_named(e, &["process"]))
        .or_else(|| find_named(e, &["image"]))
        .or_else(|| find_value(e, |s| s.to_lowercase().ends_with(".exe")));
    let process_path = process_raw.as_deref().and_then(full_path);
    let process = process_raw.as_deref().map(base_name);

    // Target: an SPN is the most informative value (e.g. "TERMSRV/192.0.2.10"
    // zeigt sofort: RDP per IP-Adresse -> deshalb NTLM statt Kerberos).
    // Microsoft stores the SPN sometimes in "Target Resource", sometimes in
    // "Target Domain", hence the additional pattern search.
    let spn = find_value(e, |v| {
        v.contains('/') && !v.contains(' ') && !v.starts_with("http") && v.len() < 256
    });
    let target = spn
        .or_else(|| from_message(e, L_TARGET_RES))
        .or_else(|| from_message(e, L_TARGET_MACHINE))
        .or_else(|| find_named(e, &["target", "resource"]))
        .or_else(|| find_named(e, &["target", "machine"]))
        .or_else(|| find_named(e, &["server", "name"]))
        .or_else(|| find_named(e, &["target"]));

    let workstation = from_message(e, L_CLIENT_MACHINE)
        .or_else(|| find_named(e, &["client", "machine"]))
        .or_else(|| find_named(e, &["hostname"]))
        .or_else(|| find_named(e, &["workstation"]));

    let ip = from_message(
        e,
        if matches!(id, 4020 | 4021) {
            L_IP_OUT
        } else {
            L_IP_IN
        },
    )
    .or_else(|| find_named(e, &["client", "ip"]))
    .or_else(|| find_named(e, &["ip"]))
    .or_else(|| find_value(e, looks_like_ip));

    Some(Event {
        record_id: e.record_id,
        log: "NTLM/Operational".into(),
        event_id: id,
        kind: kind.into(),
        event_time: e.time.clone(),
        user: from_message(e, L_USER)
            .or_else(|| find_named(e, &["user"]))
            .or_else(|| find_named(e, &["client", "name"])),
        domain: from_message(e, L_DOMAIN).or_else(|| find_named(e, &["domain"])),
        ntlm_version: version,
        process,
        target_server: target,
        workstation,
        ip,
        logon_type: None,
        enc_type: None,
        auth_method: if downgrade {
            Some("Downgrade".into())
        } else {
            Some("Direct".into())
        },
        reason,
        reason_id,
        mic,
        epa,
        server_os,
        failure_code: None,
        process_path,
    })
}

fn is_success_status(st: &str) -> bool {
    let s = st.trim().to_ascii_lowercase();
    if s.is_empty() {
        return true;
    }
    let digits = s.trim_start_matches("0x").trim_start_matches('0');
    digits.is_empty()
}

fn map_enc(code: &str) -> String {
    let c = code.trim().to_ascii_lowercase();
    let label = match c.as_str() {
        "0x1" => "DES-CRC",
        "0x3" => "DES-MD5",
        "0x11" => "AES128",
        "0x12" => "AES256",
        "0x17" => "RC4",
        "0x18" => "RC4-EXP",
        "0x0" | "0xffffffff" => "-",
        _ => {
            return if code.is_empty() {
                String::new()
            } else {
                code.to_string()
            }
        }
    };
    label.to_string()
}

// ----------------------------- HTTP -----------------------------

fn post_json(url: &str, api_key: &str, body: &str) -> Result<(), String> {
    // Overall timeout so that a hanging collector cannot block the cycle - and
    // with it a service stop.
    let mut req = ureq::post(url)
        .timeout(std::time::Duration::from_secs(15))
        .set("Content-Type", "application/json");
    if !api_key.is_empty() {
        req = req.set("X-Api-Key", api_key);
    }
    match req.send_string(body) {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
        Err(e) => Err(e.to_string()),
    }
}

// ----------------------------- Registry / Audit -----------------------------

#[cfg(windows)]
fn read_dword(path: &str, name: &str) -> Option<u32> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(path)
        .ok()
        .and_then(|k| k.get_value::<u32, _>(name).ok())
}

#[cfg(not(windows))]
fn read_dword(_path: &str, _name: &str) -> Option<u32> {
    None
}

#[cfg(windows)]
fn read_sz(path: &str, name: &str) -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(path)
        .ok()
        .and_then(|k| k.get_value::<String, _>(name).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(not(windows))]
fn read_sz(_path: &str, _name: &str) -> Option<String> {
    None
}

/// Reads a REG_MULTI_SZ (the exception lists are stored that way) and joins the
/// entries with a comma. Falls back to REG_SZ, because policy editors have been
/// known to write a single string.
#[cfg(windows)]
fn read_multi_sz(path: &str, name: &str) -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let key = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(path).ok()?;
    let joined = match key.get_value::<Vec<String>, _>(name) {
        Ok(v) => v.join(","),
        Err(_) => key.get_value::<String, _>(name).ok()?,
    };
    let t = joined.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

#[cfg(not(windows))]
fn read_multi_sz(_path: &str, _name: &str) -> Option<String> {
    None
}

/// Restriction policies (as opposed to the audit ones): 0/absent = allow,
/// 1 = deny for accounts, 2 = deny all. Knowing which machines already run in
/// enforce mode turns the blocked events from a surprise into expected progress.
fn restrict_state(path: &str, name: &str) -> String {
    match read_dword(path, name) {
        None | Some(0) => "allow".to_string(),
        Some(1) => "deny-accounts".to_string(),
        Some(2) => "deny-all".to_string(),
        Some(v) => format!("unknown({v})"),
    }
}

/// Product name plus build, e.g. "Windows Server 2019 (17763)". The build is
/// what decides whether the enhanced 40xx events can exist at all, so the
/// dashboard can tell "no data because too old" from "no data because unaudited".
fn os_version() -> String {
    let name = read_sz(WINNT_CV, "ProductName").unwrap_or_else(|| "unknown".to_string());
    match read_sz(WINNT_CV, "CurrentBuildNumber") {
        Some(b) => format!("{name} ({b})"),
        None => name,
    }
}

fn outgoing_audit() -> String {
    match read_dword(LSA, "RestrictSendingNTLMTraffic").unwrap_or(0) {
        1 => "audit",
        2 => "deny",
        _ => "aus",
    }
    .to_string()
}

fn incoming_audit() -> String {
    if read_dword(LSA, "AuditReceivingNTLMTraffic").unwrap_or(0) >= 1 {
        "audit"
    } else {
        "aus"
    }
    .to_string()
}

/// LmCompatibilityLevel as plain text. Unset behaves like level 3 on every
/// currently supported Windows, so it is reported as such rather than as 0.
fn lm_level() -> String {
    match read_dword(LSA_ROOT, "LmCompatibilityLevel") {
        Some(v @ 0..=5) => v.to_string(),
        Some(v) => format!("{v}?"),
        None => "unset".to_string(),
    }
}

/// BlockNtlmv1SSO under Lsa\MSV1_0: 0 = audit (default), 1 = enforce/block.
fn block_v1sso() -> String {
    match read_dword(LSA, "BlockNtlmv1SSO") {
        Some(0) => "audit".to_string(),
        Some(1) => "enforce".to_string(),
        Some(v) => format!("{v}?"),
        None => "unset".to_string(),
    }
}

/// Credential Guard, read from the registry: the DeviceGuard scenario key wins,
/// LsaCfgFlags is the older equivalent (1 = with UEFI lock, 2 = without).
/// Returns "unknown" when neither is present - modern Windows can enable it by
/// default without either value being set, so absence is not proof of absence.
/// Max size of the NTLM/Operational channel in KB, read from the channel's
/// registry config. Absent value = OS default (~1028 KB on current builds).
fn ntlm_log_kb() -> String {
    match read_dword(NTLM_CHANNEL, "MaxSize") {
        Some(v) => (v / 1024).to_string(),
        None => "unset".to_string(),
    }
}

fn cred_guard() -> String {
    if let Some(v) = read_dword(DEVGUARD_CG, "Enabled") {
        return if v >= 1 { "on" } else { "off" }.to_string();
    }
    match read_dword(LSA_ROOT, "LsaCfgFlags") {
        Some(0) => "off".to_string(),
        Some(1) | Some(2) => "on".to_string(),
        Some(_) => "unknown".to_string(),
        None => "unknown".to_string(),
    }
}

fn domain_audit() -> String {
    if read_dword(NETLOGON, "AuditNTLMInDomain").unwrap_or(0) >= 1 {
        "an"
    } else {
        "aus"
    }
    .to_string()
}

#[cfg(windows)]
fn is_dc() -> bool {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\ProductOptions")
        .ok()
        .and_then(|k| k.get_value::<String, _>("ProductType").ok())
        .map(|v| v.eq_ignore_ascii_case("LanmanNT"))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_dc() -> bool {
    false
}

#[cfg(windows)]
fn enable_outgoing_audit() -> Result<(), String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey(LSA).map_err(|e| e.to_string())?;
    key.set_value("RestrictSendingNTLMTraffic", &1u32)
        .map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn enable_outgoing_audit() -> Result<(), String> {
    Err("nur unter Windows".to_string())
}
