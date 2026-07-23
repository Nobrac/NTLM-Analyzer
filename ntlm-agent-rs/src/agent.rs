//! Ein Sammelzyklus: Status pushen (Heartbeat + Audit), Event-Logs lesen,
//! mappen und an den Collector pushen. Watermark pro Zweck (4624/4769/8001/8004).

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
            config::log(&format!("Ausgehendes Audit nicht gesetzt (Adminrechte?): {e}"));
        }
    }

    let me = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());
    let dc = is_dc();

    // 1) Status/Heartbeat (unabhaengig von Events, jeder Lauf)
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
                config::log(&format!("[{me}] Status-Push fehlgeschlagen: {e}"));
            }
        }
        Err(e) => config::log(&format!("[{me}] Status-JSON: {e}")),
    }

    // 2) Events sammeln
    let mut state = config::load_state();
    let mut new_seen: HashMap<String, i64> = HashMap::new();
    let mut collected: Vec<Event> = Vec::new();
    let window_ms = cfg.days_back as i64 * 24 * 60 * 60 * 1000;

    if dc {
        gather(
            "Security", "Security#4624", "EventID=4624", DATA_4624, window_ms,
            &state, &me, map_4624, &mut collected, &mut new_seen,
        );
        if !cfg.skip_kerberos {
            gather(
                "Security", "Security#4769", "EventID=4769", "", window_ms,
                &state, &me, map_4769, &mut collected, &mut new_seen,
            );
        }
        gather(
            "Microsoft-Windows-NTLM/Operational", "NTLM#8004", "EventID=8004", "", window_ms,
            &state, &me, map_8004, &mut collected, &mut new_seen,
        );
    }
    gather(
        "Microsoft-Windows-NTLM/Operational", "NTLM#8001", "EventID=8001", "", window_ms,
        &state, &me, map_8001, &mut collected, &mut new_seen,
    );

    // 3) Nichts zu senden: Wasserzeichen trotzdem fortschreiben (Rauschen nicht neu lesen)
    if collected.is_empty() {
        merge_watermarks(&mut state, new_seen);
        config::save_state(&state)?;
        config::log(&format!("[{me}] Keine neuen NTLM-Events."));
        return Ok(());
    }

    // 4) In Batches pushen; nur bei Erfolg Wasserzeichen speichern
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
            .map_err(|e| format!("[{me}] Push fehlgeschlagen: {e}"))?;
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
) {
    let last = state.get(key).copied();
    match eventlog::collect(log, id_clause, data_clause, window_ms, last) {
        Ok((raw, seen)) => {
            new_seen.insert(key.to_string(), seen);
            for e in &raw {
                if let Some(ev) = mapper(e) {
                    collected.push(ev);
                }
            }
        }
        Err(e) => config::log(&format!("[{me}] Lesen aus '{log}' ({key}) fehlgeschlagen: {e}")),
    }
}

// ----------------------------- Event-Mapping -----------------------------

fn map_4624(e: &RawEvent) -> Option<Event> {
    let u = e.named.get("TargetUserName").cloned().unwrap_or_default();
    if u.trim().is_empty() || u == "-" || u == "ANONYMOUS LOGON" {
        return None;
    }
    let lm = e.named.get("LmPackageName").map(|s| s.as_str()).unwrap_or("");
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
    let auth_method = if apkg == "Negotiate" { "Fallback" } else { "Direct" };

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
    // Nur erfolgreiche Tickets (Status 0x0 / 0x00000000); echte Fehlercodes raus.
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
        target_server: p.get(0).cloned(), // Secure Channel = Zielserver
        workstation: p.get(3).cloned(),   // Quelle (Client)
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
                .rsplit(|c| c == '\\' || c == '/')
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
    // Gesamttimeout, damit ein haengender Collector den Zyklus - und damit auch
    // einen Dienst-Stop - nicht blockiert. Entspricht dem -TimeoutSec 15 des PS-Agents.
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
