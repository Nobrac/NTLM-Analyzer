//! Konfiguration, Statusdatei (Wasserzeichen) und einfaches Datei-Logging.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Version, die beim Status-Push mitgesendet wird (Dashboard-Anzeige).
pub const AGENT_VERSION: &str = "1.1-rs";

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub collector_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "def_interval")]
    pub interval_minutes: u32,
    #[serde(default = "def_days")]
    pub days_back: u32,
    #[serde(default)]
    pub skip_kerberos: bool,
    #[serde(default)]
    pub enable_outgoing_audit: bool,
    /// Dienstkonto fuer die Installation (z.B. "DOM\\svc-ntlm" oder gMSA
    /// "DOM\\gmsa-ntlm$"). Wird NICHT in config.json gespeichert - die
    /// Zugangsdaten verwaltet der Windows-Dienst-Manager selbst.
    #[serde(skip)]
    pub service_account: Option<String>,
    /// Passwort zum Dienstkonto. Bei gMSA/virtuellen Konten entfaellt es.
    /// Wird NICHT in config.json gespeichert.
    #[serde(skip)]
    pub service_password: Option<String>,
}

fn def_interval() -> u32 {
    15
}
fn def_days() -> u32 {
    1
}

impl Default for Config {
    fn default() -> Self {
        Config {
            collector_url: String::new(),
            api_key: String::new(),
            interval_minutes: 15,
            days_back: 1,
            skip_kerberos: false,
            enable_outgoing_audit: false,
            service_account: None,
            service_password: None,
        }
    }
}

pub fn data_dir() -> PathBuf {
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| String::from(r"C:\ProgramData"));
    PathBuf::from(pd).join("NtlmAgent")
}
pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}
pub fn state_path() -> PathBuf {
    data_dir().join("state.json")
}
pub fn log_path() -> PathBuf {
    data_dir().join("agent.log")
}

/// Absoluter Pfad zu einer Windows-Systemdatei in System32. Verhindert, dass ein
/// als LocalSystem laufender Dienst Hilfsprogramme (wevtutil, sc) ueber den Suchpfad
/// oder das Arbeitsverzeichnis aufloest (Schutz gegen Binary-Planting).
/// Annahme: 64-Bit-Build (Standard der MSVC-Toolchain) - dann ist System32 das echte
/// 64-Bit-Verzeichnis ohne WOW64-Umleitung.
pub fn system32(exe: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
    PathBuf::from(root).join("System32").join(exe)
}

impl Config {
    pub fn load() -> Result<Config, String> {
        let p = config_path();
        let s = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        serde_json::from_str(&s).map_err(|e| e.to_string())
    }

    pub fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(data_dir()).map_err(|e| e.to_string())?;
        let s = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(config_path(), s).map_err(|e| e.to_string())
    }

    /// Konfiguration aus CLI-Argumenten bauen (fuer `install`).
    pub fn from_args(args: &[String]) -> Result<Config, String> {
        let mut c = Config::default();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--collector-url" => {
                    i += 1;
                    c.collector_url = args
                        .get(i)
                        .cloned()
                        .ok_or("--collector-url braucht einen Wert")?;
                }
                "--api-key" => {
                    i += 1;
                    c.api_key = args.get(i).cloned().ok_or("--api-key braucht einen Wert")?;
                }
                "--interval" => {
                    i += 1;
                    c.interval_minutes = args
                        .get(i)
                        .ok_or("--interval braucht einen Wert")?
                        .parse()
                        .map_err(|_| "--interval erwartet eine Zahl")?;
                }
                "--days-back" => {
                    i += 1;
                    c.days_back = args
                        .get(i)
                        .ok_or("--days-back braucht einen Wert")?
                        .parse()
                        .map_err(|_| "--days-back erwartet eine Zahl")?;
                }
                "--skip-kerberos" => c.skip_kerberos = true,
                "--enable-outgoing-audit" => c.enable_outgoing_audit = true,
                "--service-account" => {
                    i += 1;
                    c.service_account = Some(
                        args.get(i)
                            .cloned()
                            .ok_or("--service-account braucht einen Wert")?,
                    );
                }
                "--service-password" => {
                    i += 1;
                    c.service_password = Some(
                        args.get(i)
                            .cloned()
                            .ok_or("--service-password braucht einen Wert")?,
                    );
                }
                other => return Err(format!("unbekanntes Argument: {other}")),
            }
            i += 1;
        }
        if c.collector_url.trim().is_empty() {
            return Err("--collector-url ist erforderlich".into());
        }
        // Dienstkonto-Plausibilitaet frueh pruefen, nicht erst beim SCM-Aufruf.
        if c.service_password.is_some() && c.service_account.is_none() {
            return Err("--service-password ohne --service-account ergibt keinen Sinn".into());
        }
        if let Some(acct) = &c.service_account {
            let passwordless = acct.trim_end().ends_with('$')
                || acct.to_ascii_lowercase().starts_with("nt service\\")
                || acct.to_ascii_lowercase().starts_with("nt authority\\");
            if passwordless && c.service_password.is_some() {
                return Err("gMSA- und virtuelle Konten haben kein Passwort - \
                     bitte --service-password weglassen"
                    .into());
            }
            if !passwordless && c.service_password.is_none() {
                return Err("--service-account braucht --service-password \
                     (Ausnahme: gMSA mit '$' am Ende, z.B. DOM\\gmsa-ntlm$)"
                    .into());
            }
        }
        Ok(c)
    }

    /// Fuer `run`: ohne Argumente die gespeicherte Konfiguration laden, sonst aus Argumenten.
    pub fn load_or_args(args: &[String]) -> Result<Config, String> {
        if args.is_empty() {
            Config::load()
        } else {
            Config::from_args(args)
        }
    }
}

pub fn load_state() -> HashMap<String, i64> {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_state(s: &HashMap<String, i64>) -> Result<(), String> {
    std::fs::create_dir_all(data_dir()).map_err(|e| e.to_string())?;
    let body = serde_json::to_string(s).map_err(|e| e.to_string())?;
    // Atomar: erst in Temp-Datei schreiben, dann umbenennen. So kann ein
    // Stromausfall mitten im Schreiben keine halb geschriebene (und damit
    // unlesbare) state.json hinterlassen - die Wasserzeichen blieben sonst weg
    // und der Agent wuerde alles erneut senden.
    let tmp = data_dir().join("state.json.tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, state_path()).map_err(|e| e.to_string())
}

/// Einfaches Logging in C:\ProgramData\NtlmAgent\agent.log (+ stderr).
pub fn log(msg: &str) {
    let _ = std::fs::create_dir_all(data_dir());
    // Rotation: waechst agent.log ueber ~5 MB, wird es zu agent.log.1 (eine
    // Generation, aeltere wird ersetzt). Der Dienst laeuft dauerhaft - ohne
    // Deckel wuerde die Datei ueber Monate beliebig gross.
    if let Ok(md) = std::fs::metadata(log_path()) {
        if md.len() > 5 * 1024 * 1024 {
            let _ = std::fs::rename(log_path(), data_dir().join("agent.log.1"));
        }
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    {
        use std::io::Write;
        let _ = writeln!(f, "[{ts}] {msg}");
    }
    eprintln!("{msg}");
}
