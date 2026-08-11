//! NTLM-Analyzer Agent als nativer Windows-Dienst.
//!
//! Sammelt NTLM-Nutzungsdaten der lokalen Maschine (Event-Logs via wevtutil) und
//! pusht sie an den zentralen Collector. Laeuft als Dienst (LocalSystem, Autostart),
//! steuerbar ueber services.msc / sc (start/stop/restart).
//!
//! Unterbefehle:
//!   install    Konfiguration schreiben + Dienst einrichten und starten
//!   uninstall  Dienst stoppen + entfernen
//!   run        Einmaliger Lauf in der Konsole (zum Testen)
//!   service    Wird vom Dienst-Manager aufgerufen (nicht manuell)

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
                config::log(&format!("Dienst-Dispatcher: {e}"));
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
                        "WARNUNG: --collector-url verwendet HTTP (unverschluesselt). \
                         Telemetrie und API-Key gehen im Klartext ueber das Netz. \
                         Empfehlung: den Collector auf HTTPS umstellen."
                    );
                }
                if let Err(e) = cfg.save() {
                    eprintln!("Konfiguration speichern fehlgeschlagen: {e}");
                    exit(1);
                }
                match service::install(&cfg) {
                    Ok(()) => {
                        println!(
                            "Dienst 'NtlmAgent' installiert und gestartet. Steuerung ueber services.msc."
                        );
                        if let Some(acct) = &cfg.service_account {
                            println!();
                            println!("Dienstkonto: {acct} - bitte sicherstellen:");
                            println!(
                                "  1. 'Anmelden als Dienst' fuer das Konto (GPO: Zuweisen von Benutzerrechten)."
                            );
                            println!(
                                "  2. Mitglied in 'Ereignisprotokollleser' (Event Log Readers) - \
                                 sonst kein Zugriff auf das Security-Log (4624/4769 fehlen dann)."
                            );
                            println!(
                                "  3. Bei gMSA: Das COMPUTERKONTO dieser Maschine muss in \
                                 PrincipalsAllowedToRetrieveManagedPassword stehen \
                                 (pruefbar mit Test-ADServiceAccount)."
                            );
                            println!(
                                "  4. --enable-outgoing-audit wirkt unter einem Dienstkonto nicht \
                                 (Registry-Schreibrecht fehlt) - das Audit per GPO setzen."
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Installation fehlgeschlagen: {e}");
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
        "uninstall" => match service::uninstall() {
            Ok(()) => println!("Dienst 'NtlmAgent' entfernt."),
            Err(e) => {
                eprintln!("Deinstallation fehlgeschlagen: {e}");
                exit(1);
            }
        },
        "run" => match config::Config::load_or_args(rest) {
            Ok(cfg) => {
                if let Err(e) = agent::run_cycle(&cfg) {
                    eprintln!("Lauf fehlgeschlagen: {e}");
                    exit(1);
                }
                println!("Einmaliger Lauf abgeschlossen.");
            }
            Err(e) => {
                eprintln!("Konfig/Argumente: {e}");
                exit(2);
            }
        },
        _ => print_usage(),
    }
}

fn print_usage() {
    println!(
        "NTLM-Analyzer Agent (Windows-Dienst)

Verwendung:
  ntlm-agent.exe install --collector-url <URL> [--api-key <KEY>]
                         [--interval <MIN>] [--days-back <N>]
                         [--skip-kerberos] [--enable-outgoing-audit]
                         [--service-account <KONTO> [--service-password <PW>]]
        Schreibt die Konfiguration (C:\\ProgramData\\NtlmAgent\\config.json)
        und richtet den Dienst ein (Autostart) und startet ihn.
        Ohne --service-account laeuft der Dienst als LocalSystem.
        Mit --service-account laeuft er unter dem angegebenen Konto;
        eine gMSA wird am '$' am Ende erkannt und braucht kein Passwort
        (z.B. --service-account \"DOM\\gmsa-ntlm$\").

  ntlm-agent.exe uninstall      Dienst stoppen und entfernen.
  ntlm-agent.exe run [args]     Einmaliger Lauf in der Konsole (zum Testen).
  ntlm-agent.exe service        Wird vom Dienst-Manager aufgerufen (nicht manuell).

Danach steuerbar ueber services.msc oder:
  sc start NtlmAgent   /   sc stop NtlmAgent   /   (Neustart in services.msc)"
    );
}
