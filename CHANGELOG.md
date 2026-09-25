# Changelog

Every release with its full notes, installers and downloads is on the
[Releases page](https://github.com/Nobrac/NTLM-Analyzer/releases). This file
carries the latest release in full and a one-line summary of each earlier one.

## v2.3.1 — Security fixes for the agent

Security fixes for the agent, from a review of its code, installer and build.
**Update every agent** - the dashboard now marks machines that still run an
older one ("security update"). Update the collector first, as always.

### Security fixes

- **Data folder taken over before installation (high).** Any user may create
  folders under `C:\ProgramData`. Whoever created `NtlmAgent` before the agent
  was installed stayed its owner and could give himself access back at any
  time: read the API key, redirect the collector, silence the agent, or plant
  links that turned the service's own file writes into writes anywhere on the
  system - as SYSTEM. Now the folder is made safe before anything is written:
  a folder that is not ours (someone else's, a link, a file) is moved aside, a
  fresh one is created with a protected ACL from its first moment and owned by
  Administrators, and the service refuses to start from a folder that is not
  safe. Most relevant on terminal servers, where many users log on.
- **API key readable after a failed lockdown (medium).** The configuration
  with the key was written before the folder's ACL was restricted, and a
  failing `icacls` was only logged. Now nothing is written unless the lockdown
  worked.
- **NTLMv1 could be disguised as NTLMv2 (medium).** On Server 2025 and
  Windows 11 24H2 the agent reads the NTLM version from the event's message
  text, which also contains names chosen by the remote client. A name with a
  line break and a fake "NTLM Version: NTLMv2" line was read before the real
  one. Values with line breaks are now flattened before the text is read.
- **An attacker could make an agent go silent (medium).** Values from the
  network were not all capped, and batches were limited by count, not size. A
  batch over the collector's 10 MB limit was refused and retried every cycle -
  nothing more arrived from that machine. Every field is capped now, batches
  stay under 2 MB, and a refused batch is split so only an oversized event is
  skipped.
- **API key in the install log (medium).** The installer handed the key to a
  helper that logged the whole command line. The configuration is now written
  by the agent itself with its command line hidden from the log, which the
  build checks on every run. New `--api-key *` (asks without echo) and
  `--api-key-env NAME` keep the key out of shell history and event 4688.
- **HTTPS required (low).** `install`/`configure` refuse an `http://` collector
  unless `--allow-http` (MSI: `ALLOWHTTP=1`) is given. Existing configurations
  keep working and warn at every service start.
- **Build supply chain (low).** `Cargo.lock` is committed and every build uses
  exactly those versions (`--locked`); GitHub Actions are pinned to commits;
  known vulnerabilities in dependencies are checked on every push and weekly
  (`cargo audit`); Dependabot proposes updates. No dependency had a known
  vulnerability.

### Also fixed

- The MSI did not start the service after installing it - it only ran after
  the next reboot. It starts right away now.
- `configure` without a key no longer wipes the stored one, so changing the URL
  or upgrading silently keeps it (`--clear-api-key` removes it on purpose).
- New [SECURITY.md](https://github.com/Nobrac/NTLM-Analyzer/blob/main/SECURITY.md): how to report a vulnerability privately.

### Tests

- **Collector:** every counting rule has a test that runs against a real
  collector on a throwaway database - 8001/4020 duplicates, unconfirmed and
  phantom 8001s, 4624 twins and the NTLM version travelling across one logon,
  failed logons counted once, spraying, anonymous logons, one logon seen three
  times per account, readiness, machines without an agent, the report, login
  and API key. They run on every push on Python 3.7 and 3.13, with a syntax
  check of the dashboard's JavaScript.
- **Agent:** 28 unit tests, now part of every build, including the fixes
  above. The MSI build installs the package with a key and checks that the key
  is not in the log, that the data folder belongs to Administrators with
  access for SYSTEM and Administrators only, that the service is running, and
  that `http://` is refused.

### Smaller changes

- The status report follows a dark system theme on screen; printed or saved as
  PDF it stays white.
- Remaining German text in the collector's description and one agent message
  is English now; a test keeps the collector's comments that way.

### Upgrading

1. **Collector:** replace `ntlm-collector.py`, restart, hard-refresh.
2. **Agents:** install the new MSI over the old one with the collector URL
   (`COLLECTORURL=https://...`) - the stored API key is kept. Installed with
   the bare EXE? `ntlm-agent.exe uninstall`, then `ntlm-agent.exe install
   --collector-url https://...` with the new EXE - the key is kept there too. The dashboard shows which machines are
   still on an older version.
3. Collector on plain HTTP? Use `https://` - or add `ALLOWHTTP=1` (MSI) /
   `--allow-http` (EXE) to keep HTTP knowingly.

## Earlier releases

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
