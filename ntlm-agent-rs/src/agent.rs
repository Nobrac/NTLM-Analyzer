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
const NETLOGON: &str = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters";

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
}

#[derive(Serialize)]
struct AgentStatus {
    source: String,
    is_dc: bool,
    agent_version: String,
    outgoing_audit: String,
    incoming_audit: String,
    domain_audit: String,
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
            "Microsoft-Windows-NTLM/Operational",
            "NTLM#8004",
            "EventID=8004",
            "",
            window_ms,
            &state,
            &me,
            map_8004,
            &mut collected,
            &mut new_seen,
            false,
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
        "EventID=8001",
        "",
        window_ms,
        &state,
        &me,
        map_8001,
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

fn map_4769(e: &RawEvent) -> Option<Event> {
    let u = e.named.get("TargetUserName").cloned().unwrap_or_default();
    if u.trim().is_empty() || u.ends_with('$') {
        return None;
    }
    let svc = e.named.get("ServiceName").cloned().unwrap_or_default();
    if svc.is_empty() || svc == "krbtgt" || svc.starts_with("krbtgt") {
        return None;
    }
    // Only successful tickets (status 0x0 / 0x00000000); drop real error codes.
    if let Some(st) = e.named.get("Status") {
        if !is_success_status(st) {
            return None;
        }
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
        kind: "kerberos".to_string(),
        event_time: e.time.clone(),
        user: Some(u),
        domain: e.named.get("TargetDomainName").cloned(),
        target_server: Some(svc),
        ip,
        enc_type: Some(enc),
        ..Default::default()
    })
}

fn map_8004(e: &RawEvent) -> Option<Event> {
    let p = &e.positional;
    let u = p.get(1).cloned().unwrap_or_default();
    if u.trim().is_empty() || u.ends_with('$') {
        return None;
    }
    Some(Event {
        record_id: e.record_id,
        log: "NTLM/Operational".to_string(),
        event_id: 8004,
        kind: "domain".to_string(),
        event_time: e.time.clone(),
        user: Some(u),
        domain: p.get(2).cloned(),
        target_server: p.first().cloned(), // secure channel = target server
        workstation: p.get(3).cloned(),    // source (client)
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

    let process_val = match pname {
        Some(n) => {
            let base = n
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(n.as_str())
                .to_string();
            Some(base)
        }
        None => Some(if pid == "4" {
            "(SMB/Kernel)".to_string()
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
        "9" => "Keine Verbindung zu einem Domaenencontroller",
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
    let process = from_message(e, L_PROCESS)
        .or_else(|| find_named(e, &["process"]))
        .or_else(|| find_named(e, &["image"]))
        .or_else(|| find_value(e, |s| s.to_lowercase().ends_with(".exe")));

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
