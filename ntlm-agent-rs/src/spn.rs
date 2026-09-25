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

//! SPN check (DCs, 2.4 and later).
//!
//! The collector answers a DC agent's status report with the service names
//! (SPNs) clients asked for when they fell back to NTLM. This module looks
//! them up in Active Directory and reports what it found: who holds the SPN,
//! who holds HOST/<name>, and what DNS name the host really is. The verdict
//! (missing, alias, duplicate) is made by the collector.
//!
//! Read-only: servicePrincipalName is readable by every domain account, and
//! nothing here writes to AD. The query runs in PowerShell through ADSI, which
//! every domain-joined Windows has (no RSAT, no AD module). The script is a
//! constant; the SPNs reach it through an environment variable, never through
//! the command line, and each one is checked against a strict pattern first.

// Off Windows the lookup itself is not built; the helpers stay for the tests.
#![cfg_attr(not(windows), allow(dead_code))]

use serde::{Deserialize, Serialize};

/// SPNs per cycle. The collector hands out the same number.
pub const MAX_SPNS: usize = 50;
/// The script stops starting new lookups after 75 s and reports what it has;
/// the rest is handed out again later. This bounds how long a service stop
/// can wait for a cycle.
#[cfg(windows)]
const TIMEOUT_SECS: u64 = 100;
const MAX_NAMES: usize = 20;
const MAX_FIELD: usize = 256;

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(default)]
pub struct SpnResult {
    pub spn: String,
    pub owners: Vec<String>,
    pub host_owners: Vec<String>,
    pub canonical: String,
    pub resolves: Option<bool>,
    pub canon_owners: Vec<String>,
    pub canon_host_owners: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub struct SpnReport {
    /// Service classes HOST/<name> stands in for (the forest's sPNMappings).
    pub mappings: Vec<String>,
    pub results: Vec<SpnResult>,
    #[serde(skip_serializing)]
    pub error: Option<String>,
}

#[derive(Serialize)]
struct SpnBody<'a> {
    source: &'a str,
    mappings: &'a [String],
    results: &'a [SpnResult],
}

/// `svc/host` or `svc/host:port`, nothing else. What the collector sends is
/// already in this form; anything else is dropped, so no character with a
/// meaning in LDAP filters or PowerShell ever reaches the lookup.
pub fn valid_spn(s: &str) -> bool {
    fn part(p: &str, extra: &[char]) -> bool {
        !p.is_empty()
            && p.len() <= 128
            && p.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || extra.contains(&c))
    }
    if s.len() > MAX_FIELD {
        return false;
    }
    let Some((svc, rest)) = s.split_once('/') else { return false };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    part(svc, &[]) && part(host, &[]) && port.is_none_or(|p| part(p, &['$']))
}

/// The SPNs in a status answer, validated, de-duplicated and capped.
pub fn requested(status_answer: &str) -> Vec<String> {
    let v: serde_json::Value = match serde_json::from_str(status_answer) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    if let Some(list) = v.get("spn_check").and_then(|l| l.as_array()) {
        for s in list.iter().filter_map(|x| x.as_str()) {
            let s = s.to_ascii_lowercase();
            if valid_spn(&s) && !out.contains(&s) {
                out.push(s);
                if out.len() >= MAX_SPNS {
                    break;
                }
            }
        }
    }
    out
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(MAX_FIELD).collect()
}

fn clean_names(v: &[String]) -> Vec<String> {
    v.iter().map(|s| clean(s)).filter(|s| !s.trim().is_empty()).take(MAX_NAMES).collect()
}

/// Reads the script's output: one line `SPNJSON:{...}`. Only results for SPNs
/// that were asked for are kept, each once, with bounded fields.
pub fn parse_output(out: &str, asked: &[String]) -> Result<SpnReport, String> {
    let json = out
        .lines()
        .find_map(|l| l.trim().strip_prefix("SPNJSON:"))
        .ok_or_else(|| "no result from the lookup script".to_string())?;
    let raw: SpnReport = serde_json::from_str(json).map_err(|e| format!("lookup output: {e}"))?;
    if let Some(e) = raw.error.as_deref().filter(|e| !e.is_empty()) {
        return Err(format!("AD lookup failed: {}", clean(e)));
    }
    let mut results: Vec<SpnResult> = Vec::new();
    for r in raw.results {
        let Some(spn) = asked.iter().find(|a| a.eq_ignore_ascii_case(&r.spn)) else { continue };
        if results.iter().any(|x| &x.spn == spn) {
            continue;
        }
        results.push(SpnResult {
            spn: spn.clone(),
            owners: clean_names(&r.owners),
            host_owners: clean_names(&r.host_owners),
            canonical: clean(&r.canonical),
            resolves: r.resolves,
            canon_owners: clean_names(&r.canon_owners),
            canon_host_owners: clean_names(&r.canon_host_owners),
            error: r.error.as_deref().filter(|e| !e.is_empty()).map(clean),
        });
    }
    let mappings = raw
        .mappings
        .iter()
        .map(|m| clean(m).to_ascii_lowercase())
        .filter(|m| !m.is_empty() && m.len() <= 64)
        .take(1000)
        .collect();
    Ok(SpnReport { mappings, results, error: None })
}

/// Standard base64 (RFC 4648, with padding).
pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

/// What `powershell -EncodedCommand` takes: the script as UTF-16LE, base64.
/// Encoded, the script needs no quoting on the command line at all.
pub fn encoded_command(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64(&bytes)
}

/// The lookup. Input: $env:NTLM_AGENT_SPNS, a JSON list of validated SPNs.
/// Output: `SPNJSON:` and one JSON object, pure ASCII (anything else escaped),
/// so the console code page cannot garble an account name.
/// - owners: accounts holding exactly this SPN, searched forest-wide in the
///   global catalog (a duplicate in another domain breaks Kerberos as well)
/// - host_owners: holders of HOST/<host>, which covers the service classes in
///   sPNMappings (cifs, http, ...)
/// - canonical: the name DNS resolves the host to - an alias (CNAME) whose own
///   SPN is missing is the classic cause of NTLM for a renamed file server
pub const SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$deadline = (Get-Date).AddSeconds(75)
function Esc([string]$s) { $s -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' }
function Emit([object]$o) {
  $j = ConvertTo-Json -InputObject $o -Depth 6 -Compress
  $j = [regex]::Replace($j, '[^\x20-\x7E]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
  [Console]::Out.Write('SPNJSON:' + $j)
}
try {
  # -InputObject, not the pipeline: Windows PowerShell 5.1 passes a parsed
  # array down a pipeline as one object.
  $spns = ConvertFrom-Json -InputObject $env:NTLM_AGENT_SPNS
  $root = [ADSI]'LDAP://RootDSE'
  $forest = [string]$root.rootDomainNamingContext
  $config = [string]$root.configurationNamingContext
  $gc = New-Object System.DirectoryServices.DirectoryEntry("GC://$forest")
  $maps = @()
  try {
    $ds = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$config"
    foreach ($m in @($ds.sPNMappings)) {
      $kv = ([string]$m).Split('=', 2)
      if ($kv.Count -eq 2 -and $kv[0].Trim() -eq 'host') {
        $maps += @($kv[1].Split(',') | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
      }
    }
  } catch { }
  function Owners([string]$spn) {
    $s = New-Object System.DirectoryServices.DirectorySearcher($gc)
    $s.Filter = '(servicePrincipalName=' + (Esc $spn) + ')'
    $s.SizeLimit = 20
    [void]$s.PropertiesToLoad.Add('samaccountname')
    $r = $s.FindAll()
    try {
      foreach ($x in $r) { $n = $x.Properties['samaccountname']; if ($n.Count) { [string]$n[0] } }
    } finally { $r.Dispose() }
  }
  $results = @()
  foreach ($item in $spns) {
    if ((Get-Date) -gt $deadline) { break }
    $spn = [string]$item
    try {
      $svc, $rest = $spn.Split('/', 2)
      $hp = $rest.Split(':', 2)
      $h = $hp[0]
      $port = ''
      if ($hp.Count -eq 2) { $port = ':' + $hp[1] }
      $o = @(Owners $spn)
      $ho = @(); $co = @(); $cho = @(); $canon = ''; $res = $null
      if ($o.Count -eq 0) {
        if ($svc -ne 'host') { $ho = @(Owners "HOST/$h") }
        if ($ho.Count -ne 1) {
          try { $canon = ([System.Net.Dns]::GetHostEntry($h).HostName).ToLower().TrimEnd('.'); $res = $true }
          catch { $res = $false }
          if ($canon -and $canon -ne $h.ToLower()) {
            $co = @(Owners ("$svc/$canon" + $port))
            if ($co.Count -eq 0) { $cho = @(Owners "HOST/$canon") }
          }
        }
      }
      $results += @{ spn = $spn; owners = $o; host_owners = $ho; canonical = $canon; resolves = $res;
                     canon_owners = $co; canon_host_owners = $cho }
    } catch {
      $results += @{ spn = $spn; error = [string]$_.Exception.Message }
    }
  }
  Emit @{ mappings = @($maps); results = @($results) }
} catch {
  Emit @{ error = [string]$_.Exception.Message }
}
"#;

/// Looks the SPNs up in AD (Windows only).
#[cfg(windows)]
pub fn check(spns: &[String]) -> Result<SpnReport, String> {
    let spns: Vec<String> = spns.iter().filter(|s| valid_spn(s)).take(MAX_SPNS).cloned().collect();
    if spns.is_empty() {
        return Ok(SpnReport::default());
    }
    if std::env::var("USERDNSDOMAIN").is_err() {
        return Err("this machine is not in a domain".to_string());
    }
    let input = serde_json::to_string(&spns).map_err(|e| e.to_string())?;
    let ps = crate::config::system32(r"WindowsPowerShell\v1.0\powershell.exe");
    let cmd = encoded_command(SCRIPT);
    let out = crate::agent::run_capped(
        &ps,
        &["-NoProfile", "-NonInteractive", "-EncodedCommand", &cmd],
        &[("NTLM_AGENT_SPNS", &input)],
        TIMEOUT_SECS,
    )?;
    parse_output(&out, &spns)
}

#[cfg(not(windows))]
pub fn check(_spns: &[String]) -> Result<SpnReport, String> {
    Err("the SPN check runs on Windows only".to_string())
}

/// One round in the service cycle: look up what the collector asked for and
/// post the facts to /spn. Errors are logged, never fatal - the SPN check is
/// an extra, the event push must not depend on it.
pub fn run(cfg: &crate::config::Config, me: &str, spns: &[String]) {
    if spns.is_empty() {
        return;
    }
    let report = match check(spns) {
        Ok(r) => r,
        Err(e) => {
            crate::config::log(&format!("[{me}] SPN check: {e}"));
            return;
        }
    };
    let body = SpnBody { source: me, mappings: &report.mappings, results: &report.results };
    let body = match serde_json::to_string(&body) {
        Ok(b) => b,
        Err(e) => {
            crate::config::log(&format!("[{me}] SPN check JSON: {e}"));
            return;
        }
    };
    let url = format!("{}/spn", cfg.collector_url.trim_end_matches('/'));
    match crate::agent::post_json(&url, &cfg.api_key, &body) {
        Ok(_) => crate::config::log(&format!("[{me}] SPN check: {} names looked up.", report.results.len())),
        Err(e) => crate::config::log(&format!("[{me}] SPN check push failed: {e}")),
    }
}

/// `ntlm-agent.exe spn-check <SPN>...`: the same lookup by hand, printed
/// instead of sent. Needs no configuration and no admin rights - any domain
/// account on any domain-joined machine can run it.
pub fn cli(args: &[String]) -> i32 {
    let mut spns = Vec::new();
    for a in args {
        let s = a.trim().to_ascii_lowercase();
        if !valid_spn(&s) {
            eprintln!("Not an SPN of the form service/host[:port]: {a}");
            return 2;
        }
        if !spns.contains(&s) {
            spns.push(s);
        }
    }
    if spns.is_empty() {
        eprintln!("Usage: ntlm-agent.exe spn-check <service/host[:port]>...   e.g. spn-check cifs/fs01 HTTP/intranet");
        return 2;
    }
    if spns.len() > MAX_SPNS {
        eprintln!("At most {MAX_SPNS} SPNs at a time.");
        return 2;
    }
    match check(&spns) {
        Ok(r) => {
            for x in &r.results {
                println!("{}", x.spn);
                if let Some(e) = &x.error {
                    println!("  error:              {e}");
                    continue;
                }
                let list = |v: &[String]| if v.is_empty() { "-".to_string() } else { v.join(", ") };
                println!("  registered on:      {}", list(&x.owners));
                if x.owners.is_empty() {
                    println!("  HOST/ registered on: {}", list(&x.host_owners));
                    if !x.canonical.is_empty() {
                        println!("  DNS name:           {}", x.canonical);
                        println!("    its SPN on:       {}", list(&x.canon_owners));
                        println!("    its HOST/ on:     {}", list(&x.canon_host_owners));
                    } else if x.resolves == Some(false) {
                        println!("  DNS name:           does not resolve");
                    }
                }
            }
            if r.results.len() < spns.len() {
                println!("({} not looked up - time limit reached)", spns.len() - r.results.len());
            }
            println!();
            println!("HOST/ stands in for: {}", if r.mappings.is_empty() { "(could not be read)".to_string() } else { r.mappings.join(",") });
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_spns_pass() {
        for ok in ["cifs/fs01", "http/intranet.corp.local", "mssqlsvc/sql01.corp.local:1433", "mssqlsvc/sql01:inst$2"] {
            assert!(valid_spn(ok), "{ok}");
        }
        for bad in ["", "fs01", "cifs/", "/fs01", "cifs/fs01)(x=*", "cifs/fs 01", "cifs/fs01\n", "cifs/-x",
                    "cifs/fs01/corp", "cifs/fs01:", "cifs/fs\u{e4}", "cifs/fs01;calc", "'x'/y", "cifs/fs01:14`33"] {
            assert!(!valid_spn(bad), "{bad:?}");
        }
        assert!(!valid_spn(&format!("cifs/{}", "a".repeat(300))));
    }

    #[test]
    fn requested_list_is_cleaned() {
        let a = r#"{"ok":true,"spn_check":["HTTP/Intranet","http/intranet","cifs/x)(a=*",5,"cifs/nas01"]}"#;
        assert_eq!(requested(a), vec!["http/intranet", "cifs/nas01"]);
        assert!(requested(r#"{"ok":true}"#).is_empty());
        assert!(requested("not json").is_empty());
        let many: Vec<String> = (0..80).map(|i| format!("\"cifs/h{i}\"")).collect();
        assert_eq!(requested(&format!("{{\"spn_check\":[{}]}}", many.join(","))).len(), MAX_SPNS);
    }

    #[test]
    fn output_is_matched_to_the_question() {
        let asked = vec!["cifs/nas01".to_string(), "http/intranet".to_string()];
        let out = "WARNING: noise\r\nSPNJSON:{\"mappings\":[\"cifs\",\"HTTP\"],\"results\":[\
            {\"spn\":\"CIFS/nas01\",\"owners\":[],\"host_owners\":[],\"canonical\":\"nas01.corp.local\",\"resolves\":true,\
             \"canon_owners\":[],\"canon_host_owners\":[]},\
            {\"spn\":\"cifs/nas01\",\"owners\":[\"dup\"]},\
            {\"spn\":\"cifs/other\",\"owners\":[\"x\"]},\
            {\"spn\":\"http/intranet\",\"owners\":[\"svc_web\\u00e4\",\"a\\u0007b\"],\"error\":\"\"}]}";
        let r = parse_output(out, &asked).unwrap();
        assert_eq!(r.mappings, vec!["cifs", "http"]);
        assert_eq!(r.results.len(), 2);
        assert_eq!(r.results[0].spn, "cifs/nas01");
        assert_eq!(r.results[0].canonical, "nas01.corp.local");
        assert_eq!(r.results[0].resolves, Some(true));
        assert!(r.results[0].owners.is_empty());
        assert_eq!(r.results[1].owners, vec!["svc_web\u{e4}", "ab"]);
        assert_eq!(r.results[1].error, None);
    }

    #[test]
    fn script_failure_is_an_error() {
        let asked = vec!["cifs/x".to_string()];
        assert!(parse_output("SPNJSON:{\"error\":\"The server is not operational.\"}", &asked).is_err());
        assert!(parse_output("", &asked).is_err());
        assert!(parse_output("SPNJSON:{broken", &asked).is_err());
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // PowerShell's own example: [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('dir'))
        assert_eq!(encoded_command("dir"), "ZABpAHIA");
    }

    #[test]
    fn script_takes_no_input_from_the_command_line() {
        assert!(SCRIPT.contains("$env:NTLM_AGENT_SPNS"));
        assert!(!SCRIPT.contains("$args"));
        // Fits a Windows command line with room to spare once encoded.
        assert!(encoded_command(SCRIPT).len() < 16_000);
    }
}
