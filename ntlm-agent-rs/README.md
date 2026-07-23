# NTLM-Analyzer Agent (Rust, Windows service)

The telemetry agent as a **native Windows service**: runs as `LocalSystem` with
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
- **/status**: heartbeat + auditing state (registry) + agent version (`1.1-rs`).

Event logs are read via `wevtutil` (XPath-filtered) and the
resulting XML is parsed with `roxmltree`. Watermarks are kept **per source/purpose**
(`Security#4624`, `Security#4769`, `NTLM#8001`, `NTLM#8004`).

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
