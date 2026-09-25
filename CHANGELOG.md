# Changelog

Every release with its full notes, installers and downloads is on the
[Releases page](https://github.com/Nobrac/NTLM-Analyzer/releases). This file
carries the latest release in full and a one-line summary of each earlier one.

## v2.3.2 — Security fixes for the collector and dashboard

After the agent in 2.3.1, the collector and its dashboard went through the
same review. **Update the collector**; the agent is unchanged apart from its
version number, so agents on 2.3.1 need nothing.

The review included an attack test: every field of every event,
machine and account filled with script code, then every panel, detail view,
hover card, search, report and link state opened in a browser. Nothing ran -
the escaping held everywhere. Found and fixed:

- **Other web pages could use an admin's browser against the collector
  (medium).** Without a dashboard password and API key - the defaults - a page
  the admin merely visited could mark work items as done, inject fake events
  and invent machines, all through the admin's own browser. Browser requests
  from other sites are now refused, and the agent endpoints only accept real
  JSON, which a foreign page cannot send without the browser asking first.
  With a password and an API key this was already blocked.
- **"limit=-1" meant no limit (low).** A negative or malformed number in the
  query returned the whole database or dropped the connection. Numbers are
  now bounded.
- **Scripts need a per-page key (hardening).** Each dashboard, login and report
  page gives its own scripts a random nonce, and the browser runs no other
  script - so even a value that slipped past the escaping could not execute.
  HTTPS responses also send HSTS.

Still recommended, as before: run the collector with `--password` and
`--key` (the Linux installer sets both). Without a password, anyone who can
reach the collector can read the dashboard.

### Tests

- Four more collector tests, 53 in all: foreign pages cannot post, the
  dashboard itself still can, query numbers stay bounded, and every page runs
  only its own scripts.

### Upgrading

1. **Collector:** replace `ntlm-collector.py`, restart, hard-refresh.
   Own scripts that post to `/ingest` or `/status` must send
   `Content-Type: application/json` - the agent always does.
2. **Agents:** nothing to do if they run 2.3.1. Older ones: see 2.3.1.

## Earlier releases

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
