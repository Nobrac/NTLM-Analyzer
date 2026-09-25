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
pub const AGENT_VERSION: &str = "2.3.2";

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
    /// Accept an http:// collector URL. Off by default: over plain HTTP the
    /// API key and every reported logon cross the network readable.
    #[serde(default)]
    pub allow_http: bool,
    /// Whether this run was given a key at all (--api-key / --api-key-env).
    /// Without one, `configure` keeps the key already stored, so changing
    /// the URL or an MSI upgrade does not silently wipe it.
    #[serde(skip)]
    pub api_key_given: bool,
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
            allow_http: false,
            api_key_given: false,
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
/// Reads a line from stdin with terminal echo turned off (Windows console
/// API, declared directly to avoid pulling in another crate). Falls back to a
/// visible read with a warning when no console is attached (e.g. piped input).
pub fn prompt_password(prompt: &str) -> Result<String, String> {
    use std::io::Write;
    print!("{prompt}");
    let _ = std::io::stdout().flush();

    #[cfg(windows)]
    {
        type Handle = *mut core::ffi::c_void;
        const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // (DWORD)-10
        const ENABLE_ECHO_INPUT: u32 = 0x0004;
        extern "system" {
            fn GetStdHandle(kind: u32) -> Handle;
            fn GetConsoleMode(h: Handle, mode: *mut u32) -> i32;
            fn SetConsoleMode(h: Handle, mode: u32) -> i32;
        }
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode: u32 = 0;
            if !h.is_null() && GetConsoleMode(h, &mut mode) != 0 {
                SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
                let line = read_trimmed_line();
                SetConsoleMode(h, mode); // always restore, even on empty input
                println!();
                return line;
            }
        }
        eprintln!("(no console detected - input will be visible)");
    }
    read_trimmed_line()
}

fn read_trimmed_line() -> Result<String, String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("reading input: {e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

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

    /// The data folder must exist already: `prepare_data_dir` creates it with
    /// its protection. Creating it here would give it ProgramData's defaults.
    pub fn save(&self) -> Result<(), String> {
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
                    let v = args.get(i).cloned().ok_or("--api-key requires a value")?;
                    // "*" = prompt without echo. A key typed on the command line
                    // lands in the shell history, the process list and - with
                    // command-line auditing - in event 4688.
                    c.api_key = if v == "*" { prompt_password("API key: ")? } else { v };
                    // An empty value (what the MSI passes when no key was entered)
                    // means "not given": the stored key stays.
                    c.api_key_given = !c.api_key.is_empty();
                }
                "--api-key-env" => {
                    i += 1;
                    let name = args.get(i).cloned().ok_or("--api-key-env requires a variable name")?;
                    c.api_key = std::env::var(&name)
                        .map_err(|_| format!("environment variable {name} is not set"))?;
                    if c.api_key.is_empty() {
                        return Err(format!("environment variable {name} is empty"));
                    }
                    c.api_key_given = true;
                }
                "--clear-api-key" => {
                    c.api_key.clear();
                    c.api_key_given = true;
                }
                "--allow-http" => c.allow_http = true,
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
                    let v = args
                        .get(i)
                        .cloned()
                        .ok_or("--service-password requires a value")?;
                    // "*" = prompt without echo. A password given inline would
                    // end up in the admin's PowerShell history and - where
                    // command-line auditing (4688) is on - in the Security log.
                    // For an NTLM auditing tool of all things, that would be an
                    // own goal; gMSA (trailing '$', no password) avoids the
                    // question entirely and stays the recommended path.
                    let pw = if v == "*" {
                        prompt_password("Password for the service account: ")?
                    } else {
                        v
                    };
                    if pw.is_empty() {
                        return Err("empty password - aborting".into());
                    }
                    c.service_password = Some(pw);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
            i += 1;
        }
        if c.collector_url.trim().is_empty() {
            return Err("--collector-url is required".into());
        }
        check_url(&c.collector_url, c.allow_http)?;
        // Validate the service account early instead of failing at the SCM call.
        if c.service_password.is_some() && c.service_account.is_none() {
            return Err("--service-password without --service-account makes no sense".into());
        }
        if let Some(acct) = &c.service_account {
            let passwordless = acct.trim_end().ends_with('$')
                || acct.to_ascii_lowercase().starts_with("nt service\\")
                || acct.to_ascii_lowercase().starts_with("nt authority\\");
            if passwordless && c.service_password.is_some() {
                return Err(
                    "gMSA and virtual accounts have no password - \
                     please omit --service-password"
                        .into(),
                );
            }
            if !passwordless && c.service_password.is_none() {
                return Err(
                    "--service-account requires --service-password \
                     (exception: a gMSA, i.e. a trailing '$', e.g. DOM\\gmsa-ntlm$)"
                        .into(),
                );
            }
        }
        Ok(c)
    }

    /// For install/configure: keep the stored key when this run was given none.
    pub fn keep_stored_key(&mut self) {
        if !self.api_key_given {
            if let Ok(old) = Config::load() {
                self.api_key = old.api_key;
            }
        }
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

/// https:// always; http:// only when asked for; anything else is a typo.
pub fn check_url(url: &str, allow_http: bool) -> Result<(), String> {
    let u = url.trim().to_ascii_lowercase();
    if u.starts_with("https://") && u.len() > "https://".len() {
        Ok(())
    } else if u.starts_with("http://") {
        if allow_http {
            Ok(())
        } else {
            Err("the collector URL uses http:// - the API key and all findings would \
                 travel unencrypted. Use https://, or add --allow-http to accept that."
                .into())
        }
    } else {
        Err(format!("the collector URL must start with https:// (got '{url}')"))
    }
}

pub fn load_state() -> HashMap<String, i64> {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_state(s: &HashMap<String, i64>) -> Result<(), String> {
    let body = serde_json::to_string(s).map_err(|e| e.to_string())?;
    // Atomic: write to a temp file first, then rename. That way a power loss
    // in the middle of a write cannot leave a half-written (and therefore
    // unreadable) state.json behind - the watermarks would be lost and the
    // agent would resend everything.
    let tmp = data_dir().join("state.json.tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, state_path()).map_err(|e| e.to_string())
}

/// Simple logging to C:\ProgramData\NtlmAgent\agent.log (+ stderr).
/// Never creates the data folder (see `save`): without it, only stderr.
pub fn log(msg: &str) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn https_is_required_unless_allowed() {
        assert!(Config::from_args(&args(&["--collector-url", "https://c:8443"])).is_ok());
        assert!(Config::from_args(&args(&["--collector-url", "http://c:8080"])).is_err());
        assert!(Config::from_args(&args(&["--collector-url", "http://c:8080", "--allow-http"])).is_ok());
        assert!(Config::from_args(&args(&["--collector-url", "c:8080"])).is_err());
        assert!(Config::from_args(&args(&["--collector-url", "https://"])).is_err());
    }

    #[test]
    fn key_from_the_environment() {
        std::env::set_var("NTLM_TEST_KEY_1", "s3cret");
        let c = Config::from_args(&args(&["--collector-url", "https://c", "--api-key-env", "NTLM_TEST_KEY_1"])).unwrap();
        assert_eq!(c.api_key, "s3cret");
        assert!(c.api_key_given);
        assert!(Config::from_args(&args(&["--collector-url", "https://c", "--api-key-env", "NTLM_TEST_UNSET_9"])).is_err());
    }

    #[test]
    fn an_empty_key_means_not_given() {
        let c = Config::from_args(&args(&["--collector-url", "https://c", "--api-key", ""])).unwrap();
        assert!(!c.api_key_given);
        let c = Config::from_args(&args(&["--collector-url", "https://c", "--api-key", "k"])).unwrap();
        assert!(c.api_key_given);
        let c = Config::from_args(&args(&["--collector-url", "https://c", "--clear-api-key"])).unwrap();
        assert!(c.api_key_given && c.api_key.is_empty());
    }

    #[test]
    fn switches_that_the_service_does_not_need_are_not_stored() {
        let c = Config::from_args(&args(&["--collector-url", "https://c", "--api-key", "k"])).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("api_key_given"));
        assert!(json.contains("\"allow_http\":false"));
    }
}
