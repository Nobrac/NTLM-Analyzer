# Security policy

NTLM-Analyzer runs with high privileges: the agent as a Windows service under
LocalSystem, the collector with the logon data of a whole domain. Reports about
weaknesses in either are very welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on
[this repository](https://github.com/Nobrac/NTLM-Analyzer/security/advisories/new).

Helpful to include:

- the affected part (agent, collector, installer, dashboard) and version
- what an attacker needs beforehand (network access, a local account, ...)
- steps to reproduce, or a proof of concept

You will get an answer within a week. Fixes are released as a new version with
the issue described in its release notes once an update is available.

## Supported versions

Only the latest release receives fixes. The agent reports its version to the
collector, and the dashboard's machine list shows which machines run an older
one.

## Scope notes

- All agents share one API key. Anyone with administrator rights on a machine
  running the agent can read that key and send data in the name of any machine.
  That is a known limit of the design, not a vulnerability.
- The collector's dashboard is meant for an internal network behind TLS and a
  password (`--cert`, `--tlskey`, `--password`).
