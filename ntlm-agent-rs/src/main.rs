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

//! NTLM-Analyzer agent as a native Windows service.
//!
//! Collects NTLM usage data of the local machine (event logs via wevtutil) and
//! pushes it to the central collector. Runs as a service (LocalSystem or a
//! dedicated account, auto-start), controllable via services.msc / sc.
//!
//! Subcommands:
//!   install    write the configuration, then create and start the service
//!   uninstall  stop and remove the service
//!   run        one-off cycle in the console (for testing)
//!   service    invoked by the service control manager (not manually)

mod agent;
mod config;
mod eventlog;
mod service;

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let rest: &[String] = if args.len() > 2 { &args[2..] } else { &[] };

    match cmd {
        "service" => {
            // Vom SCM gestartet -> Dispatcher
            if let Err(e) = service::run() {
                config::log(&format!("service dispatcher: {e}"));
                exit(1);
            }
        }
        "install" => match config::Config::from_args(rest) {
            Ok(cfg) => {
                if cfg
                    .collector_url
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("http://")
                {
                    eprintln!(
                        "WARNING: --collector-url uses HTTP (unencrypted). \
                         Telemetry and API key travel over the network in clear \
                         text. Recommendation: switch the collector to HTTPS."
                    );
                }
                if let Err(e) = cfg.save() {
                    eprintln!("Saving the configuration failed: {e}");
                    exit(1);
                }
                match service::install(&cfg) {
                    Ok(()) => {
                        println!(
                            "Service 'NtlmAgent' installed and started. Control it via services.msc."
                        );
                        if let Some(acct) = &cfg.service_account {
                            println!();
                            println!("Service account: {acct} - please make sure:");
                            println!(
                                "  1. The account has 'Log on as a service' (GPO: User Rights Assignment)."
                            );
                            println!(
                                "  2. It is a member of 'Event Log Readers' - without that it \
                                 cannot read the Security log (4624/4769 will be missing)."
                            );
                            println!(
                                "  3. For a gMSA: this machine's COMPUTER ACCOUNT must be listed in \
                                 PrincipalsAllowedToRetrieveManagedPassword \
                                 (verify with Test-ADServiceAccount)."
                            );
                            println!(
                                "  4. --enable-outgoing-audit has no effect under a service account \
                                 (no registry write access) - set the audit policy via GPO."
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Installation failed: {e}");
                        exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Argumentfehler: {e}\n");
                print_usage();
                exit(2);
            }
        },
        // Write the configuration only - no file copy, no service. This is what
        // the MSI calls: the installer owns the payload and the service entry,
        // so the agent must not create a second copy of either. Everything else
        // (argument parsing, the HTTP warning, locking down the data folder) is
        // shared with `install`.
        "configure" => match config::Config::from_args(rest) {
            Ok(cfg) => {
                if cfg
                    .collector_url
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("http://")
                {
                    eprintln!(
                        "WARNING: --collector-url uses HTTP (unencrypted). \
                         Telemetry and API key travel over the network in clear \
                         text. Recommendation: switch the collector to HTTPS."
                    );
                }
                if let Err(e) = cfg.save() {
                    eprintln!("Saving the configuration failed: {e}");
                    exit(1);
                }
                service::harden_data_dir();
                println!(
                    "Configuration written to {}.",
                    config::config_path().display()
                );
            }
            Err(e) => {
                eprintln!("{e}");
                exit(2);
            }
        },
        "uninstall" => match service::uninstall() {
            Ok(()) => println!("Service 'NtlmAgent' removed."),
            Err(e) => {
                eprintln!("Uninstall failed: {e}");
                exit(1);
            }
        },
        "run" => match config::Config::load_or_args(rest) {
            Ok(cfg) => {
                if let Err(e) = agent::run_cycle(&cfg) {
                    eprintln!("Run failed: {e}");
                    exit(1);
                }
                println!("One-off run finished.");
            }
            Err(e) => {
                eprintln!("Config/arguments: {e}");
                exit(2);
            }
        },
        _ => print_usage(),
    }
}

fn print_usage() {
    println!(
        "NTLM-Analyzer agent (Windows service)

Usage:
  ntlm-agent.exe install --collector-url <URL> [--api-key <KEY>]
                         [--interval <MIN>] [--days-back <N>]
                         [--skip-kerberos] [--enable-outgoing-audit]
                         [--service-account <ACCOUNT> [--service-password <PW|*>]]
        Writes the configuration (C:\\ProgramData\\NtlmAgent\\config.json),
        creates the service (auto-start) and starts it.
        Without --service-account the service runs as LocalSystem.
        With --service-account it runs under that account; a gMSA is detected
        by the trailing '$' and needs no password
        (e.g. --service-account \"DOM\\gmsa-ntlm$\").

  ntlm-agent.exe uninstall      Stop and remove the service.
  ntlm-agent.exe run [args]     One-off cycle in the console (for testing).
  ntlm-agent.exe service        Invoked by the service control manager.

Afterwards control it via services.msc or:
  sc start NtlmAgent   /   sc stop NtlmAgent   /   (restart in services.msc)"
    );
}
