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

- **4624** (every machine): NTLM logons including v1/v2 and `auth_method` = `Direct`
  (application uses NTLM directly) or `Fallback` (Kerberos attempted, failed).
  Filtered via `LmPackageName`, so it also catches Negotiate→NTLM fallbacks.
  On a member server this is what tells NTLMv1 from NTLMv2 before Server 2025.
  Anonymous logons (null sessions) are kept but sent without a version: they
  carry no credential, and Windows' "NTLM V1" label on them means nothing.
- **4625** (every machine, needs *Audit Logon: Failure*): **failed** NTLM
  logons — account, source machine and IP, logon type, process and the NT
  status (`SubStatus` when `Status` is the generic `0xC000006D`).
- **4776** (DC): every NTLM validation, successful or failed, with its status.
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
cargo build --release --locked
cargo test --release --locked
```

`--locked` builds exactly the dependency versions in `Cargo.lock`.

Result: `target\release\ntlm-agent.exe` (a single, dependency-free EXE).

## Install / uninstall

In a **command prompt running as Administrator**:

```cmd
:: writes the configuration, copies the EXE to C:\Program Files\NtlmAgent,
:: creates the service from there (auto-start, LocalSystem) and starts it
ntlm-agent.exe install --collector-url https://collector.example.local:8443
```

> **Security:** `install` copies the EXE itself to `C:\Program Files\NtlmAgent\`
> and registers the service from there, so the SYSTEM service never runs from a
> user-writable folder (e.g. Downloads). The data folder
> `C:\ProgramData\NtlmAgent\` is made safe **before** anything is written to it:
> a folder that someone else created beforehand (any user may create folders in
> ProgramData) or that is a link is moved aside, and a fresh one is created that
> belongs to Administrators and is accessible to SYSTEM and Administrators only.
> If that cannot be done, installation stops. The service checks the same when
> it starts and refuses to run from a folder that is not safe.
>
> The collector URL must use **https://**. `http://` is refused unless you add
> `--allow-http` (MSI: `ALLOWHTTP=1`), because the API key and every reported
> logon would otherwise cross the network unencrypted. Configurations from
> before 2.3.1 that use http:// keep working; the log warns at every start.

```cmd
:: more options (--api-key * asks for the key without showing it):
ntlm-agent.exe install --collector-url https://collector.example.local:8443 ^
    --api-key * --interval 15 --days-back 1 ^
    --skip-kerberos --enable-outgoing-audit

:: stop and remove the service
ntlm-agent.exe uninstall
```

### The API key

A key typed on a command line ends up in the shell history, in the process
list and - where command-line auditing is on - in event 4688. So there are two
ways to hand it over without that:

- `--api-key *` asks for it, without showing what you type.
- `--api-key-env NAME` reads it from an environment variable - for scripts and
  software distribution, where the variable comes from a secret store.

`configure` without any key option keeps the key already stored, so changing
the URL or upgrading the MSI does not wipe it. `--clear-api-key` removes it.

**Installer.** The wizard's key field is masked, the property is hidden, and the
action that writes the configuration hides its command line from the install
log, so a verbose log (`msiexec /l*v`) does not contain the key. On an msiexec
command line (`APIKEY=...`) the key is still visible in the process list while
the installer runs. For unattended rollouts, install without it and set it
afterwards:

```cmd
msiexec /i ntlm-agent.msi /qn COLLECTORURL=https://collector.example.local:8443
"C:\Program Files\NtlmAgent\ntlm-agent.exe" configure ^
    --collector-url https://collector.example.local:8443 --api-key-env NTLM_API_KEY
sc stop NtlmAgent && sc start NtlmAgent
```

If the collector runs without `--key`, no key is checked and none is needed.

```cmd
:: write or change the configuration only - no file copy, no service changes.
:: Useful to correct the collector URL or the API key on an installed machine.
ntlm-agent.exe configure --collector-url https://collector.example.local:8443 --api-key *
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

Reading the Security log (4624 on every machine, 4769 on DCs) requires elevated rights — as a
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
| `src/secure_dir.rs` | Makes the data folder safe before use (owner, links, ACL) |

## Running under a service account or gMSA (least privilege)

By default the service runs as **LocalSystem**. For least-privilege setups it can
run under a dedicated account instead:

```cmd
:: classic service account
ntlm-agent.exe install --collector-url https://collector:8443 --api-key * ^
    --service-account "DOM\svc-ntlm" --service-password *

:: group managed service account (gMSA) - no password, Windows retrieves it from AD
ntlm-agent.exe install --collector-url https://collector:8443 --api-key * ^
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
