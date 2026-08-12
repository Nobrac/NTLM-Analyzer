# NTLM-Analyzer Agent (Rust, Windows service)

The telemetry agent as a **native Windows service**: runs as `LocalSystem` (or a
dedicated service account / gMSA, see below) with
auto-start, controllable via `services.msc` or `sc start|stop NtlmAgent`, with
automatic restart on crash. Collects the relevant NTLM/Kerberos events on the
machine and pushes them to the central collector (`/ingest` + `/status`).

> **Note:** This project was **not** compiled in the environment in which it was
> written (no Windows, no Rust toolchain available there). It is written against
> the documented API of `windows-service` 0.7 / `winreg` 0.52 and was statically
> checked (brackets, symbol consistency); it has since compiled successfully with
> a standard MSVC toolchain. If a crate version differs, minor adjustments (e.g.
> a struct field name) may occasionally be needed — the structure is complete.

## What it collects

- **4624** (DC): NTLM logons including v1/v2 and `auth_method` = `Direct`
  (application uses NTLM directly) or `Fallback` (Kerberos attempted, failed).
  Filtered via `LmPackageName`, so it also catches Negotiate→NTLM fallbacks.
- **4769** (DC, informational): Kerberos service tickets including encryption
  (can be disabled with `--skip-kerberos`).
- **8004** (DC): NTLM within the domain (user + source + target).
- **8001** (all machines): outgoing NTLM including the originating process.
- **8002/8003** (needs *Audit Incoming NTLM Traffic*): **incoming** NTLM.
  8002 fires for authentication that needs no DC to validate it (local accounts,
  loopback) and carries the calling process; 8003 fires on member servers for
  domain accounts and carries the remote account, client machine, logon type and
  the process that was accessed. Without the policy these queries return nothing.
- **8005/8006** (DCs): NTLM straight to the domain controller (8005, e.g. a
  type 3 logon to the DC) and requests from a **trusted domain** (8006). Same
  field layout as 8004; collected through the same query.
- **/status**: heartbeat + auditing state (registry) + agent version.

**Enhanced auditing** (Windows 11 24H2 / Windows Server 2025, KB5064479) — these
queries simply return nothing on older systems, so the same binary works everywhere:

- **4020/4021** (all machines): outgoing NTLM with process, **NTLM version** and
  the **reason** Kerberos was not used (reason IDs 0–11 are translated to plain
  text, e.g. "target name contains an IP address"). Odd event IDs mark a
  downgrade (NTLMv1, missing EPA or missing MIC).
- **4022/4023** (all machines): incoming NTLM with source machine, client IP,
  target SPN and version — feeds the same view as 8004.
- **4030–4033** (DC): domain-wide NTLM with the version straight from the DC log.
- **4024/4025**: NTLMv1-derived SSO credentials used (4024) or already blocked
  (4025) — the finding that stops working when Microsoft enforces the block in
  **October 2026**.

Event logs are read via `wevtutil` (XPath-filtered) and the resulting XML is parsed
with `roxmltree`. The classic events use `/f:xml`; the enhanced ones use
`/f:RenderedXml`, because their XML field names are undocumented — values are
resolved from the rendered message labels first (English and German), then from
named XML fields, then by value pattern, so nothing is lost if a label differs.
Watermarks are kept **per source/purpose** (`Security#4624`, `Security#4769`,
`NTLM#8001`, `NTLM#8002`, `NTLM#8003`, `NTLM#8004` (covers 8004-8006), `NTLM#40dc`, `NTLM#40cs`).

## Building (on Windows)

Prerequisite: Rust toolchain (`rustup`, MSVC target).

```cmd
cargo build --release
```

Result: `target\release\ntlm-agent.exe` (a single, dependency-free EXE).

## Install / uninstall

In a **command prompt running as Administrator**:

```cmd
:: writes the configuration, copies the EXE to C:\Program Files\NtlmAgent,
:: creates the service from there (auto-start, LocalSystem) and starts it
ntlm-agent.exe install --collector-url https://collector.example.local:8443
```

> **Security:** `install` copies the EXE itself to `C:\Program Files\NtlmAgent\`
> and registers the service from there — so the SYSTEM service never runs from a
> user-writable folder (e.g. Downloads). It therefore does not matter where you
> run `install` from. In addition, `install` automatically restricts the ACL of
> `C:\ProgramData\NtlmAgent\` to SYSTEM + Administrators (SID-based, locale-independent)
> so regular users cannot tamper with `config.json`. For production, the collector
> should be reachable over **HTTPS**; with `http://`, `install` prints a warning
> because telemetry and API key would otherwise travel in cleartext.

```cmd
:: more options:
ntlm-agent.exe install --collector-url https://collector.example.local:8443 ^
    --api-key SECRET123 --interval 15 --days-back 1 ^
    --skip-kerberos --enable-outgoing-audit

:: stop and remove the service
ntlm-agent.exe uninstall
```

The configuration lives in `C:\ProgramData\NtlmAgent\config.json`; watermarks in
`state.json`, log in `agent.log` (same directory, log rotates at ~5 MB).

## Controlling the service

Via `services.msc` (service "NTLM-Analyzer Agent", start/stop/restart) or:

```cmd
sc start NtlmAgent
sc stop NtlmAgent
sc query NtlmAgent
```

The service runs continuously and performs a collect/push cycle every `interval`
minutes. An error or panic within a cycle is caught and logged — the service keeps
running. On a real crash, Windows restarts it after 60 s (set via `sc failure`).

## Testing without the service

```cmd
:: one-off run in the console (uses the stored config.json)
ntlm-agent.exe run

:: or one-off with arguments, without installing anything
ntlm-agent.exe run --collector-url https://collector.example.local:8443
```

On a DC, reading the Security log (4624/4769) requires elevated rights — as a
service the agent runs as `LocalSystem` and has them automatically.

## Project structure

| File | Contents |
|---|---|
| `Cargo.toml` | Dependencies (serde, ureq, roxmltree; windows-service + winreg Windows-only) |
| `src/main.rs` | CLI entry point: `install` / `uninstall` / `run` / `service` |
| `src/config.rs` | Configuration, watermark file, logging |
| `src/eventlog.rs` | Reading event logs via `wevtutil` + XML parsing |
| `src/agent.rs` | One collect/push cycle (4624/4769/8004/8001 + status) |
| `src/service.rs` | Windows service: dispatcher, control handler, install/uninstall |

## Running under a service account or gMSA (least privilege)

By default the service runs as **LocalSystem**. For least-privilege setups it can
run under a dedicated account instead:

```cmd
:: classic service account
ntlm-agent.exe install --collector-url https://collector:8443 --api-key KEY ^
    --service-account "DOM\svc-ntlm" --service-password "..."

:: group managed service account (gMSA) - no password, Windows retrieves it from AD
ntlm-agent.exe install --collector-url https://collector:8443 --api-key KEY ^
    --service-account "DOM\gmsa-ntlm$"
```

A trailing `$` marks the account as a gMSA (no password allowed); virtual accounts
(`NT SERVICE\...`, `NT AUTHORITY\...`) are also accepted without a password.
Credentials are handed to the Windows service manager and are **never** written
to `config.json`.

**The account needs, on every monitored machine:**

1. **Log on as a service** — grant via GPO under *Computer Configuration →
   Windows Settings → Security Settings → Local Policies → User Rights Assignment*.
2. **Event Log Readers** membership — without it the account cannot read the
   Security log, so 4624/4769 collection silently yields nothing (the
   NTLM/Operational log still works).
3. **gMSA only:** the machine's **computer account** must be allowed to
   retrieve the password (`PrincipalsAllowedToRetrieveManagedPassword`) —
   that alone is sufficient; the service manager fetches the password from AD
   at start. `Install-ADServiceAccount` is *not* required for running a
   service, but `Test-ADServiceAccount` is a handy check when the service
   won't start. After changing the group membership, reboot the machine so
   its Kerberos ticket picks up the change.

The installer grants the account *Modify* on `C:\ProgramData\NtlmAgent\`
automatically (watermarks + log). One limitation: `--enable-outgoing-audit`
writes to HKLM and therefore does nothing under a non-admin service account —
set the audit policy via GPO instead (see the main README).

Creating a gMSA (once, on a DC):

```powershell
New-ADServiceAccount gmsa-ntlm -DNSHostName gmsa-ntlm.example.local `
    -PrincipalsAllowedToRetrieveManagedPassword "NTLM-Agent-Servers"
Add-ADGroupMember "Event Log Readers" gmsa-ntlm$
```

where `NTLM-Agent-Servers` is a group containing the computer accounts of all
monitored machines.
