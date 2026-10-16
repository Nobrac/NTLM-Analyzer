<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-wordmark-light.png">
  <img src="assets/logo-wordmark-dark.png" width="420" alt="NTLM-Analyzer">
</picture>

### Find out who still uses NTLM in your Active Directory, so you can retire it for Kerberos.

A Windows agent and a central collector with a web dashboard. It shows which
users, computers and programs still authenticate over NTLM, which of them fell
back from Kerberos and can be fixed, and whether usage is going down. The
collector is one Python file with no dependencies; the agent is one
self-installing EXE.

[![Live demo](https://img.shields.io/badge/live%20demo-open%20dashboard-3ddc97?logo=githubpages&logoColor=white)](https://nobrac.github.io/NTLM-Analyzer/demo/)
&nbsp;
![Collector: Python 3.7+](https://img.shields.io/badge/collector-Python%203.7%2B-3776AB?logo=python&logoColor=white)
&nbsp;
![Agent: Rust](https://img.shields.io/badge/agent-Rust-CE422B?logo=rust&logoColor=white)
&nbsp;
![Platform: Windows + Linux](https://img.shields.io/badge/platform-Windows%20%2B%20Linux-0078D6)
&nbsp;
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
&nbsp;
[![Tests](https://github.com/Nobrac/NTLM-Analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/Nobrac/NTLM-Analyzer/actions/workflows/tests.yml)

[Live demo](https://nobrac.github.io/NTLM-Analyzer/demo/) (the real dashboard
on synthetic lab data) · [Project page](https://nobrac.github.io/NTLM-Analyzer/)

</div>

> [!NOTE]
> Most of the code was written by Claude (Anthropic) in a pair-programming
> workflow. I defined the requirements and reviewed and tested everything in a
> real AD environment. Review it before production use, as you would any code
> you did not write.

## Screenshots

![Overview with headline share, deadline countdown and trend](screenshots/01-overview.png)

![Program list with sparklines](screenshots/02-programs.png)

<details>
<summary>More screenshots</summary>
<br>

Most-used targets
![Most-used targets](screenshots/03-targets-users.png)

When NTLM happens (the bright cell on Sunday 05:00 is the backup job nobody remembers)
![Timing heatmap](screenshots/04-timing.png)

Why NTLM was used, with a remedy per cause
![Cause analysis](screenshots/05-why.png)

Who uses NTLM and where to, from the domain controller
![Domain-wide view](screenshots/06-domain.png)

Services accepting NTLM
![Incoming NTLM per machine](screenshots/07-services.png)

NTLMv1 SSO, which stops working in October 2026
![NTLMv1 SSO panel](screenshots/08-v1sso.png)

Already on Kerberos, including weak-encryption findings
![Kerberos services and accounts](screenshots/09-kerberos.png)

Machines and auditing status
![Machine list](screenshots/10-machines.png)

Recent events
![Event list](screenshots/11-events.png)

Event detail
![Event detail drawer](screenshots/12-event-detail.png)

Ready to switch off, per machine and direction
![Ready to switch off](screenshots/13-ready.png)

NTLMv1 by user
![NTLMv1 by account](screenshots/14-ntlmv1.png)

Failed NTLM attempts
![Failed NTLM attempts](screenshots/15-failed.png)

SPN check with the `setspn` command to fix each finding
![SPN check](screenshots/23-spn.png)

Accounts using NTLM
![Accounts using NTLM](screenshots/16-accounts.png)

Account and machine detail
![Account detail](screenshots/17-account-detail.png) ![Machine detail](screenshots/18-machine-detail.png)

Machines without an agent, seen only through the domain controllers
![Machines without an agent](screenshots/19-no-agent.png)

Search (Ctrl+K)
![Search](screenshots/20-search.png)

Status report
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="screenshots/21-report-dark.png">
  <img alt="Status report" src="screenshots/21-report.png">
</picture>

Light theme
![Light theme](screenshots/22-light.png)

</details>

## Quick start

### 1. Enable auditing (GPO)

Nothing is collected without it, and events are only written from the moment
auditing is on. The settings are under
`Computer Configuration → Policies → Windows Settings → Security Settings`:

| Where | Setting | Value |
| --- | --- | --- |
| All machines · *Local Policies → Security Options* | Restrict NTLM: Outgoing NTLM traffic to remote servers | `Audit all` (not `Deny all`) |
| All machines · *Local Policies → Security Options* | Restrict NTLM: Audit Incoming NTLM Traffic | `Enable auditing for domain accounts` |
| DCs · *Local Policies → Security Options* | Restrict NTLM: Audit NTLM authentication in this domain | `Enable all` |
| DCs and member servers · *Advanced Audit Policy → Logon/Logoff* | Audit Logon | `Success and Failure`. Before Server 2025, Success is the only source of the NTLMv1/v2 distinction (on by default on Windows Server); Failure shows failed NTLM logons. |
| DCs · *Advanced Audit Policy → Account Logon* (optional) | Audit Kerberos Service Ticket Operations | `Success and Failure`. Failures feed the *Why NTLM?* panel. |

Then run `gpupdate /force`. The badges in the dashboard's Machines & auditing
status panel turn green once the policy has reached each machine.

### 2. Install the collector (Linux)

```bash
sudo ./install.sh
```

The script detects Debian or RHEL, creates a hardened systemd service, keeps the
password and API key off the command line and prints the agent install command.
To start it by hand: `python3 ntlm-collector.py --help` (no pip packages needed).

### 3. Install the agent (each Windows machine, elevated)

Download `ntlm-agent.msi` from the [latest release](../../releases/latest) and
double-click it, or install unattended:

```cmd
msiexec /i ntlm-agent.msi /qn COLLECTORURL=https://collector.example.local:8443
```

With the bare EXE: `ntlm-agent.exe install --collector-url https://… --api-key *`
(prompts for the key). It copies itself to Program Files, secures its data
folder and registers and starts the service. The URL must be `https://`; plain
`http://` needs `--allow-http` (MSI: `ALLOWHTTP=1`).

### 4. Open the dashboard

Go to `https://collector.example.local:8443/`. The Machines panel should list
every agent with a green heartbeat.

## Good to know

- The dashboard makes no external requests, uses a `default-src 'none'` CSP,
  requires login on every endpoint and has XSS-tested rendering. Run the
  collector with TLS (`--cert`/`--tlskey`) and `--password`; use plain HTTP
  for testing only.
- The agent can run as a gMSA instead of LocalSystem. The
  [agent README](ntlm-agent-rs/README.md) covers that, the MSI properties and
  handling the API key in unattended rollouts.
- The enhanced 40xx events (process names for NTLM) exist only on Windows 11
  24H2 and Server 2025. Older systems deliver everything else, and the
  dashboard tells you when data is missing for that reason.
- A domain controller running agent 2.4 or later looks up in AD each service
  name that clients fell back to NTLM for (read-only, no extra rights). The
  dashboard lists names that are missing, duplicated or registered only for
  the real server behind an alias, with the `setspn` command to fix them. The
  tool never changes AD.
- The Report button produces a printable status page (save as PDF from the
  browser) with trend, progress, risks and next steps, in German or English.
- All CLI options: `python3 ntlm-collector.py --help` and `ntlm-agent.exe --help`.
- The [operations guide](docs/OPERATIONS.md) has component details, every CLI
  flag, troubleshooting and the checklist for turning NTLM off.
- Changes per version: [CHANGELOG](CHANGELOG.md) and
  [Releases](https://github.com/Nobrac/NTLM-Analyzer/releases).

## License

GPL-3.0, see [LICENSE](LICENSE).
