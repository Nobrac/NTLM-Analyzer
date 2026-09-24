# Changelog

Every release with its full notes, installers and downloads is on the
[Releases page](https://github.com/Nobrac/NTLM-Analyzer/releases). This file
carries the latest release in full and a one-line summary of each earlier one.

## v2.3.0 — Every account, every attempt, and a report for everyone else

The biggest release so far. 2.2 made the numbers right; 2.3 makes them
complete, and turns them into things to do. NTLMv1 is now visible where it
used to be hidden, failed and anonymous logons are no longer dropped, every
account has its own view, the dashboard names the machines it cannot see into,
and a printable status report carries all of it to people who never open the
dashboard.

### Highlights

- **NTLMv1 on member servers.** The agent collects 4624 on every machine, so a
  Server 2016–2022 file server finally says which NTLM version each logon used.
- **Accounts using NTLM**, with an **account detail view**: from which
  machines, to which servers, with which programs.
- **Failed NTLM attempts** (4625 + failed 4776) with the reason in plain words,
  locked-out accounts and **password-spraying detection**.
- **Anonymous logons** (null sessions) are kept and labelled, instead of being
  dropped or miscounted as NTLMv1.
- **Auditing gaps are named** per machine instead of showing up as silence.
- **Ready to switch off** and **machines without an agent** — the two lists
  that turn findings into a plan.
- **Machine detail**, **Ctrl+K search** over everything, and a reworked,
  faster-reading dashboard with a **light theme**.
- **Status report** to print or save as PDF, with risks and next steps.

---

### NTLMv1 where it was invisible

The classic NTLM events (8001, 8003, 8004) never say which NTLM version a
logon used. Before Server 2025 the only place a member server records it is
its **4624**, and the agent collected that on domain controllers only. An
NTLMv1 logon to a Server 2022 file server showed up as "NTLM, version
unknown".

- **The agent now collects 4624 on every machine.** The filter keeps it to
  NTLM logons, so the volume stays small.
- **One logon, one count.** A member server usually writes both an 8003 and a
  4624 for the same logon. They are matched per logon — same machine, same
  account, same client, within ten seconds — and only the 8003 counts, since
  it names the service that accepted the logon. Without an 8003 (incoming
  audit off) the 4624 itself is the incoming event.
- **The version travels.** The 4624's version is handed to every trace of the
  same logon that lacks one: the 8003 on the server, the 8004 on the DC and
  the 8001 on the client. So NTLMv1 now shows up in the domain view and in the
  program list — which program on which client still speaks NTLMv1 —
  whichever of the events reaches the collector first.
- **Logon auditing is checked.** The agent reads "Audit Logon" (via
  `auditpol /backup`, whose numeric column is the same in every Windows
  language) and the machines panel shows per machine: **logons** (NTLMv1 is
  recognised here), **no 4624** (auditing off — NTLMv1 stays invisible, GPO
  path in the tooltip) or **agent before 2.3**. The NTLMv1 panel says how many
  machines are blind that way, so an empty list is never read as "all clear".

### Every account, every attempt

- **Accounts using NTLM.** One row per account: NTLM logons, v1/v2, from how
  many machines to how many servers, failed attempts, and whether it already
  uses Kerberos elsewhere. The same logon is often seen three times — by the
  client (8001), the server (8003) and the DC (8004); per account and server
  the side that saw the most counts, never the sum.
- **Account detail.** A click on an account (or Ctrl+K) opens it in the side
  drawer: trend, from which machines, to which servers, with which programs,
  and its failed attempts with the reason in plain words.
- **Failed NTLM attempts.** The agent now also collects **4625** (failed NTLM
  logons) on every machine; the DCs' failed **4776** were already there. One
  failure seen by both the server and the DC counts once.
  - The reason is spelled out: wrong password, no such account, locked out,
    expired, disabled, outside logon hours, …
  - A stale password in a service or scheduled task is named as the likely
    cause, where it is.
  - **Password spraying** is flagged when one machine fails with five or more
    accounts.
  - Failures live in their own table and never count towards the NTLM share.
- **Anonymous logons** (null sessions) are no longer dropped. They carry no
  credential, so Windows' "NTLM V1" label on them is ignored — they show up as
  *anonymous* instead of inflating the NTLMv1 figures.
- **Auditing gaps are named.** A machine with outgoing, incoming or (on a DC)
  domain NTLM auditing off gets a red or amber badge, and the machines panel
  says how many are affected.
- **No more cut-off lists.** Panels ended at 50 rows (NTLMv1 accounts at 15).
  They now receive up to 500 and fold to ten with *show all*; the jump bar says
  "500+" when the cap is reached.

### Act on it

- **Ready to switch off.** Per machine and direction: auditing on, watched for
  30 days, no NTLM in those 30 days — then "Restrict NTLM: Deny" can be set.
  Otherwise it names what would break. Incoming counts what other machines and
  the DCs saw going to the machine too, so a server with its own auditing off
  is still caught.
- **Machines without an agent.** Every NTLM logon of a domain account is
  validated by a DC (4776, collected since 2.2.0). Any client in there without
  an agent is listed — often the forgotten server or device.
- **Machine detail.** A click on a machine opens everything about it in one
  place: outgoing and incoming NTLM with its trend, readiness, programs and
  targets, who reaches it and from where, its accounts and its auditing.

### Status report

A **Report** button in the header opens a status report for everyone who does
not open the dashboard: a page to print or save as PDF, in German or English,
over 7, 30 or 90 days.

- **Page one, the overview:** the NTLM share and its change against the period
  before, key figures, the weekly trend towards zero with NTLMv1 per week, the
  work list (done, in progress, open) and the machines ready to switch off.
- **Page two, what to do:** risks rated *act / watch / fine* — NTLMv1, the
  October 2026 change, failed logons and spraying, gaps in visibility, relay
  exposure — and up to six next steps derived from the data, with names.
- **Page three, the detail:** the largest programs and accounts still using
  NTLM, and how everything is counted.

Rendered on the server as plain HTML; no script needed to read it.

### Quick search

**Ctrl+K** (⌘K on a Mac), **/** or the search button in the header opens one
box over everything the dashboard shows: machines and accounts open their
detail; programs and targets filter the event list; panels are jumped to. Full
keyboard use, screen-reader labels, and a single button on phones.

Text search in the event list now runs in the database. Before, it filtered
only the newest few hundred loaded rows — a program with 171 logons could show
11. Typing waits for a short pause and keeps the cursor where it was, and a
late answer can no longer overwrite a newer one.

### A dashboard that reads faster

- Three blocks in the order the work goes: **Situation**, **Act**, **Details**.
  Panels fold, long tables show ten rows with "show all", and the jump bar
  shows real counts and marks where you are.
- **Key-figure tiles** with the change against the week before; the trend as
  an area with the goal line at zero; work status as coloured chips.
- **Light theme**, following the system or picked in the header.
- A **"What does this show?"** answer on every panel, a compact phone header,
  the brand mark in the header.
- Fixed: a stray brace in the stylesheet had silently dropped two rules (the
  live dot and the data-basis line); the 24-hour button was labelled "Time
  range"; the jump bar showed fetch limits ("Events 300") instead of counts.

### Live demo

The [live demo](https://nobrac.github.io/NTLM-Analyzer/demo/) has all of the
above: machine and account details, failed attempts including a spraying burst
and a locked-out account, an anonymous printer, a machine with auditing off,
a work list in progress, and the status report in both languages.

### Under the hood

- Code, comments and identifiers are English throughout. Work status values
  are now `open`, `in_progress` and `done`; audit states reported by the agent
  are `on`/`off` instead of `an`/`aus`. Existing databases are rewritten once
  on start, and the old values are still accepted from older agents and pages.
  The German UI translation and the German Windows labels the agent and
  collector recognise stay German — they have to.
- New table `ntlm_failures`; 4776 status codes are stored in one spelling
  (`0xC000006A`). Retention cleans both.
- New endpoints `/api/machine`, `/api/account` and `/report`, all behind the
  dashboard login.
- Agent: 12 unit tests for the audit-policy parser and the new event mappings.

### Upgrading

1. **Collector:** replace `ntlm-collector.py`, restart, hard-refresh
   (Ctrl+F5). Database changes happen on start, nothing to do by hand.
2. **Agent — member servers first.** They are the ones that now send the
   4624s that carry the version, and the 4625s. Then everything else. The MSI
   upgrades in place and keeps the configuration.
3. **GPO: "Audit Logon" to *Success and Failure*** on DCs and member servers
   (*Advanced Audit Policy → Logon/Logoff*). Success gives the NTLM version,
   Failure the failed attempts; the dashboard shows where either is missing.

### Compatibility

- **Agent 2.2.x with collector 2.3:** works; those machines just send no
  member-server 4624 (so no NTLMv1 there) and no 4625.
- **Agent 2.3 with collector 2.2.x:** don't. The older collector would count
  the failed logons as NTLM in use. **Update the collector first.**

## Earlier releases

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
