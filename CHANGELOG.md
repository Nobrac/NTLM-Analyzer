# Changelog

Every release with its full notes, installers and downloads is on the
[Releases page](https://github.com/Nobrac/NTLM-Analyzer/releases). This file
carries the latest release in full and a one-line summary of each earlier one.

## v2.4.0 — The SPN check

Most "Kerberos failed, NTLM took over" cases have a boring cause: the service
name (SPN) the client asked for is not registered in Active Directory, is
registered on two accounts, or is registered for the real server name while
clients use an alias. The events already name the SPN; now the tool also asks
AD about it.

- **New panel "Kerberos configuration (SPN)"** in the Act block. Every SPN
  clients fell back to NTLM for, or that failed Kerberos with 0x7 ("server not
  found in Kerberos database"), is looked up in AD. The panel lists what is
  wrong, how much NTLM it causes, and the `setspn` command that fixes it, with
  a copy button and "Check again" for after the fix:
  - **missing** — no account holds the name (for instance a NAS that never
    joined the domain, or a stale name in a script)
  - **alias** — the name is a DNS alias (CNAME) or a short name; the SPN is
    registered for the real server, and the command registers it for the alias
  - **duplicate** — several accounts hold it, so the KDC refuses the ticket
  `HOST/` registrations are taken into account through the forest's
  sPNMappings, so `cifs/` or `http/` on a computer account is not reported.
- **Who looks it up:** a domain controller running **agent 2.4.0**. The
  collector hands it up to 50 names in the answer to its status report; the
  agent queries the global catalog through ADSI and reports what it found.
  Read-only - any domain account may read `servicePrincipalName`, so no extra
  rights are needed. The tool never changes anything in AD; the command is
  for an admin to run. Each name is checked again after a day.
- **`ntlm-agent.exe spn-check <service/host>...`** runs the same lookup by
  hand and prints the result, on any domain-joined machine.
- **Status report:** SPN problems become a next step.

### Security notes

The lookup runs a fixed PowerShell script (`-EncodedCommand`); the names reach
it through an environment variable, never the command line, and each is
checked against a strict `service/host[:port]` pattern first - no character
with a meaning in LDAP filters or PowerShell gets through. Results are only
accepted for names the collector actually handed out, and `/spn` needs the
API key like `/ingest`. "Check again" is a dashboard action with the same
cross-site protection as the work status.

### Tests

- Collector: 14 more tests (67 in all) - SPN normalisation, every verdict,
  handing out and accepting only asked names, re-check, the report step.
- Agent: 6 more tests (34 in all) - input validation, output parsing, the
  encoding of the script.

### Upgrading

1. **Collector:** replace `ntlm-collector.py`, restart, hard-refresh.
2. **Agent 2.4.0 on at least one domain controller** - that is where the
   lookup runs. Other machines gain nothing new; updating them is optional.

The AD lookup could only be tested against a simulated directory before
release. If a name shows up wrongly, `ntlm-agent.exe spn-check <spn>` on a DC
shows exactly what AD answered - please open an issue with its output.

## Earlier releases

- **[v2.3.2](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v2.3.2)** — Security fixes for the collector and dashboard
- **[v2.3.1](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v2.3.1)** — Security fixes for the agent
- **[v2.3.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v2.3.0)** — Every account, every attempt, and a report for everyone else
- **[v2.2.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v2.2.0)** — Numbers you can trust
- **[v2.1.1](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v2.1.1)** — Usable on phones
- **[v2.1.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v2.1.0)** — Installer, live demo, shareable views
- **[v2.0.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v2.0.0)** — New dashboard
- **[v1.9.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.9.0)** — New dashboard
- **[v1.8.2](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.8.2)** — Enterprise operations hardening
- **[v1.8.1](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.8.1)** — Timezone correction and HTTP hardening
- **[v1.8.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.8.0)** — Seven more event sources, found by asking Windows instead of the docs
- **[v1.7.1](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.7.1)** — Dashboard fix and the Credential Guard blind spot
- **[v1.7.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.7.0)** — Patterns, paths, and machine configuration
- **[v1.6.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.6.0)** — Exception-list generator
- **[v1.5.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.5.0)** — Enforcement visibility, cause analysis for older Windows, richer explanations
- **[v1.4.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.4.0)** — "Why NTLM?", relay exposure, and cleaner process grouping
- **[v1.3.0](https://github.com/Nobrac/NTLM-Analyzer/releases/tag/v1.3.0)** — Incoming NTLM, DC blind spots, October 2026 readiness
