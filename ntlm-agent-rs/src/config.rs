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

//! Configuration, state file (watermarks) and simple file logging.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Version reported with every status push (shown in the dashboard).
pub const AGENT_VERSION: &str = "1.7.0";

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
    /// Service account used at install time (e.g. "DOM\\svc-ntlm" or the gMSA
    /// "DOM\\gmsa-ntlm$"). NOT stored in config.json - the credentials are
    /// managed by the Windows service manager itself.
    #[serde(skip)]
    pub service_account: Option<String>,
    /// Password for the service account; omitted for gMSA/virtual accounts.
    /// NOT stored in config.json.
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

/// Absolute path to a Windows system binary in System32. Prevents a service
/// running as LocalSystem from resolving helper programs (wevtutil, sc) via the
/// search path or the working directory (protection against binary planting).
/// Assumes a 64-bit build (the MSVC toolchain default) - then System32 is the
/// real 64-bit directory without WOW64 redirection.
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

    /// Build the configuration from CLI arguments (used by `install`).
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
                        .ok_or("--collector-url requires a value")?;
                }
                "--api-key" => {
                    i += 1;
                    c.api_key = args.get(i).cloned().ok_or("--api-key requires a value")?;
                }
                "--interval" => {
                    i += 1;
                    c.interval_minutes = args
                        .get(i)
                        .ok_or("--interval requires a value")?
                        .parse()
                        .map_err(|_| "--interval expects a number")?;
                }
                "--days-back" => {
                    i += 1;
                    c.days_back = args
                        .get(i)
                        .ok_or("--days-back requires a value")?
                        .parse()
                        .map_err(|_| "--days-back expects a number")?;
                }
                "--skip-kerberos" => c.skip_kerberos = true,
                "--enable-outgoing-audit" => c.enable_outgoing_audit = true,
                "--service-account" => {
                    i += 1;
                    c.service_account = Some(
                        args.get(i)
                            .cloned()
                            .ok_or("--service-account requires a value")?,
                    );
                }
                "--service-password" => {
                    i += 1;
                    c.service_password = Some(
                        args.get(i)
                            .cloned()
                            .ok_or("--service-password requires a value")?,
                    );
                }
                other => return Err(format!("unbekanntes Argument: {other}")),
            }
            i += 1;
        }
        if c.collector_url.trim().is_empty() {
            return Err("--collector-url is required".into());
        }
        // Validate the service account early instead of failing at the SCM call.
        if c.service_password.is_some() && c.service_account.is_none() {
            return Err("--service-password ohne --service-account ergibt keinen Sinn".into());
        }
        if let Some(acct) = &c.service_account {
            let passwordless = acct.trim_end().ends_with('$')
                || acct.to_ascii_lowercase().starts_with("nt service\\")
                || acct.to_ascii_lowercase().starts_with("nt authority\\");
            if passwordless && c.service_password.is_some() {
                return Err("gMSA and virtual accounts have no password - \
                     please omit --service-password"
                    .into());
            }
            if !passwordless && c.service_password.is_none() {
                return Err("--service-account requires --service-password \
                     (exception: a gMSA, i.e. a trailing '$', e.g. DOM\\gmsa-ntlm$)"
                    .into());
            }
        }
        Ok(c)
    }

    /// For `run`: load the stored configuration when no arguments are given.
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
    // Atomic: write to a temp file first, then rename. That way a power loss
    // in the middle of a write cannot leave a half-written (and therefore
    // unreadable) state.json behind - the watermarks would be lost and the
    // agent would resend everything.
    let tmp = data_dir().join("state.json.tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, state_path()).map_err(|e| e.to_string())
}

/// Einfaches Logging in C:\ProgramData\NtlmAgent\agent.log (+ stderr).
pub fn log(msg: &str) {
    let _ = std::fs::create_dir_all(data_dir());
    // Rotation: once agent.log grows past ~5 MB it becomes agent.log.1 (a
    // single generation, the older one is replaced). The service runs
    // permanently - without a cap the file would grow without bound.
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
