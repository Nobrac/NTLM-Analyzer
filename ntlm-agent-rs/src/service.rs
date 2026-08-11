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

//! Windows-Dienst: SCM-Dispatcher, Steuerungs-Handler und Installation/Deinstallation.
//!
//! Der Dienst laeuft als LocalSystem im Autostart und ist ueber services.msc bzw.
//! `sc start|stop NtlmAgent` steuerbar. Bei Absturz wird er automatisch neu gestartet
//! (Wiederherstellungsaktionen, gesetzt via sc.exe failure).
//!
//! Die eigentliche Windows-Implementierung haengt an den Crates `windows-service`
//! und `winreg` und wird nur fuer das Windows-Target kompiliert. Fuer andere Targets
//! gibt es Stubs mit identischer Signatur, damit das Projekt ueberall typcheckt.

const SERVICE_NAME: &str = "NtlmAgent";
const DISPLAY_NAME: &str = "NTLM-Analyzer Agent";

#[cfg(not(windows))]
pub use stub_impl::{install, run, uninstall};
#[cfg(windows)]
pub use windows_impl::{install, run, uninstall};

#[cfg(windows)]
mod windows_impl {
    use super::{DISPLAY_NAME, SERVICE_NAME};
    use crate::{agent, config};
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    type R = Result<(), Box<dyn std::error::Error>>;

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    // Erzeugt das FFI-Einsprungspunkt-Paar fuer den Dienst-Manager.
    define_windows_service!(ffi_service_main, service_main);

    /// Wird von `main` beim Unterbefehl `service` aufgerufen: uebergibt die Kontrolle
    /// an den SCM. Blockiert, bis der Dienst stoppt.
    pub fn run() -> R {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    /// Vom SCM aufgerufen (ueber das von define_windows_service! erzeugte FFI).
    fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            config::log(&format!("Dienst beendet mit Fehler: {e}"));
        }
    }

    fn run_service() -> R {
        // Stop-Signal: der Steuerungs-Handler (anderer Thread) sendet, die Schleife wartet.
        let (tx, rx) = mpsc::channel::<()>();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        let set_state = |state: ServiceState, accept: ServiceControlAccept| -> R {
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;
            Ok(())
        };

        set_state(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        )?;
        config::log("Dienst gestartet.");

        // Konfiguration einmalig laden. Ohne gueltige Konfiguration kann der Dienst
        // nichts Sinnvolles tun -> sauber stoppen statt in einer Fehlerschleife zu laufen.
        let cfg = match config::Config::load() {
            Ok(c) => c,
            Err(e) => {
                config::log(&format!("Konfiguration nicht ladbar: {e} - Dienst stoppt."));
                set_state(ServiceState::Stopped, ServiceControlAccept::empty())?;
                return Ok(());
            }
        };

        let interval = Duration::from_secs(u64::from(cfg.interval_minutes.max(1)) * 60);

        loop {
            // Einen Sammel-/Push-Zyklus ausfuehren. Panik abfangen, damit ein einzelner
            // Fehlerlauf den Dienst nicht beendet (er soll dauerhaft laufen).
            let res =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| agent::run_cycle(&cfg)));
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => config::log(&format!("Zyklus-Fehler: {e}")),
                Err(_) => config::log("Zyklus-Panik abgefangen - Dienst laeuft weiter."),
            }

            // Bis zum naechsten Intervall warten ODER sofort aufwachen, wenn Stop kam.
            match rx.recv_timeout(interval) {
                Ok(()) => break, // Stop/Shutdown
                Err(mpsc::RecvTimeoutError::Timeout) => continue, // naechster Zyklus
                Err(mpsc::RecvTimeoutError::Disconnected) => break, // Sender weg
            }
        }

        config::log("Dienst stoppt.");
        set_state(ServiceState::Stopped, ServiceControlAccept::empty())?;
        Ok(())
    }

    /// Geschuetzter Installationsort fuer die EXE. Die Standard-ACL von
    /// C:\Program Files erlaubt nur Administratoren/SYSTEM Schreibzugriff - damit
    /// laeuft der SYSTEM-Dienst nicht aus einem benutzerbeschreibbaren Ordner
    /// (z.B. Downloads), was sonst eine lokale Rechteausweitung ermoeglichen wuerde.
    fn install_dir() -> std::path::PathBuf {
        let pf =
            std::env::var("ProgramFiles").unwrap_or_else(|_| String::from(r"C:\Program Files"));
        std::path::PathBuf::from(pf).join("NtlmAgent")
    }

    /// True, wenn beide Pfade auf dieselbe Datei zeigen (Re-Install aus dem Zielordner).
    fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
        match (a.canonicalize(), b.canonicalize()) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    /// Beschraenkt die ACL von C:\ProgramData\NtlmAgent auf SYSTEM und Administratoren
    /// (per SID, funktioniert unabhaengig von der Systemsprache). Verhindert, dass
    /// normale Benutzer die config.json - und damit das Ziel der Telemetrie - umbiegen.
    /// Nicht fatal: schlaegt icacls fehl, wird geloggt und die Installation laeuft weiter.
    fn harden_data_dir() {
        let dir = config::data_dir();
        let _ = std::fs::create_dir_all(&dir);
        let status = std::process::Command::new(config::system32("icacls.exe"))
            .arg(&dir)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F", // SYSTEM
                "*S-1-5-32-544:(OI)(CI)F", // BUILTIN\Administratoren
            ])
            .status();
        match status {
            Ok(s) if s.success() => {
                config::log("ACL des Datenordners auf SYSTEM + Administratoren beschraenkt.")
            }
            Ok(s) => config::log(&format!(
                "icacls beendet mit Status {s} - ACL des Datenordners bitte manuell pruefen."
            )),
            Err(e) => config::log(&format!(
                "icacls nicht ausfuehrbar: {e} - ACL des Datenordners bitte manuell setzen."
            )),
        }
    }

    /// Dienst anlegen (Autostart, LocalSystem), Auto-Neustart setzen und starten.
    pub fn install(cfg: &config::Config) -> R {
        // Datenordner (config.json/state.json/agent.log) gegen Manipulation durch
        // normale Benutzer absichern - laeuft hier, weil install Adminrechte hat.
        harden_data_dir();
        // Ein eigenes Dienstkonto braucht Schreibrechte auf den Datenordner
        // (state.json, agent.log) - SYSTEM+Administratoren reichen dann nicht.
        if let Some(acct) = &cfg.service_account {
            let dir = config::data_dir();
            let status = std::process::Command::new(config::system32("icacls.exe"))
                .arg(&dir)
                .args(["/grant", &format!("{acct}:(OI)(CI)M")])
                .status();
            match status {
                Ok(st) if st.success() => config::log(&format!(
                    "Datenordner-ACL: Modify fuer Dienstkonto '{acct}' ergaenzt."
                )),
                _ => config::log(&format!(
                    "WARNUNG: Konnte '{acct}' keine Rechte auf {} geben - \
                     bitte manuell Modify gewaehren, sonst kann der Dienst \
                     weder Wasserzeichen noch Log schreiben.",
                    dir.display()
                )),
            }
        }
        // EXE an den geschuetzten Ort kopieren und den Dienst von dort registrieren.
        let target_exe = install_dir().join("ntlm-agent.exe");
        let current = std::env::current_exe()?;
        if !same_file(&current, &target_exe) {
            std::fs::create_dir_all(install_dir())
                .map_err(|e| format!("Zielordner {} anlegen: {e}", install_dir().display()))?;
            std::fs::copy(&current, &target_exe).map_err(|e| {
                format!(
                    "EXE nach {} kopieren fehlgeschlagen: {e} \
                     (laeuft evtl. noch ein alter Dienst? Dann zuerst 'uninstall')",
                    target_exe.display()
                )
            })?;
            config::log(&format!("EXE installiert nach {}", target_exe.display()));
        }

        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|e| format!("Verbindung zum Dienst-Manager fehlgeschlagen: {e:?}"))?;

        // Existiert der Dienst schon? Dann klar sagen, statt an create_service mit
        // einem generischen winapi-Fehler zu scheitern.
        if let Ok(existing) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            let state = existing
                .query_status()
                .map(|s| format!("{:?}", s.current_state))
                .unwrap_or_else(|_| String::from("unbekannt"));
            return Err(format!(
                "Der Dienst '{SERVICE_NAME}' existiert bereits (Status: {state}). \
                 Bitte zuerst 'ntlm-agent.exe uninstall' ausfuehren und dann erneut installieren. \
                 Hinweis: Wurde gerade deinstalliert und der Dienst haengt auf \
                 'zum Loeschen markiert', ein offenes services.msc-Fenster schliessen \
                 und kurz warten."
            )
            .into());
        }

        // Dienstkonto: Standard bleibt LocalSystem. Mit --service-account laeuft
        // der Dienst unter einem normalen Konto oder einer gMSA ('$' am Ende,
        // ohne Passwort - das Passwort holt Windows selbst aus dem AD).
        // Lokale Namen ohne Domaenenteil bekommen ".\" vorangestellt, sonst
        // interpretiert der SCM sie nicht.
        let account_name: Option<OsString> = cfg.service_account.as_ref().map(|a| {
            let a = a.trim();
            if a.contains('\\') || a.contains('@') {
                OsString::from(a)
            } else {
                OsString::from(format!(".\\{a}"))
            }
        });
        let account_password: Option<OsString> =
            cfg.service_password.as_ref().map(OsString::from);

        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: target_exe,
            launch_arguments: vec![OsString::from("service")],
            dependencies: vec![],
            account_name, // None = LocalSystem
            account_password,
        };

        let service = manager
            .create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|e| format!("Dienst anlegen fehlgeschlagen: {e:?}"))?;
        let _ = service.set_description(
            "Sammelt NTLM-Nutzungsdaten der Maschine und meldet sie an den NTLM-Analyzer-Collector.",
        );

        // Automatischer Neustart bei Absturz. Ueber sc.exe gesetzt - das ist robuster und
        // weniger versionsabhaengig als die Failure-Actions-API der Crate.
        //   reset=   Zaehler nach 86400 s (1 Tag) zuruecksetzen
        //   actions= bei jedem der ersten Abstuerze nach 60 s neu starten
        let _ = std::process::Command::new(config::system32("sc.exe"))
            .args([
                "failure",
                SERVICE_NAME,
                "reset=",
                "86400",
                "actions=",
                "restart/60000/restart/60000/restart/60000",
            ])
            .status();

        let no_args: Vec<OsString> = Vec::new();
        let acct_hint = if cfg.service_account.is_some() {
            " Bei einem Dienstkonto sind die haeufigsten Ursachen: (1) Dem Konto \
             fehlt das Recht 'Anmelden als Dienst' (Fehler 1069; per GPO unter \
             Computerkonfiguration > Windows-Einstellungen > Sicherheitseinstellungen > \
             Lokale Richtlinien > Zuweisen von Benutzerrechten vergeben). \
             (2) gMSA: Die Maschine darf das Passwort nicht abrufen - das \
             Computerkonto fehlt in PrincipalsAllowedToRetrieveManagedPassword \
             (Diagnose: Test-ADServiceAccount; nach Gruppenaenderung Reboot noetig)."
        } else {
            ""
        };
        service.start(&no_args).map_err(|e| {
            format!(
                "Dienst wurde angelegt, aber das Starten schlug fehl: {e:?} - \
                 Details in C:\\ProgramData\\NtlmAgent\\agent.log bzw. der \
                 Ereignisanzeige (System). Start manuell: 'sc start {SERVICE_NAME}'.{acct_hint}"
            )
        })?;

        let acct_txt = cfg
            .service_account
            .clone()
            .unwrap_or_else(|| String::from("LocalSystem"));
        config::log(&format!(
            "Dienst '{SERVICE_NAME}' installiert und gestartet \
             (Konto: {acct_txt}, Intervall {} min).",
            cfg.interval_minutes
        ));
        Ok(())
    }

    /// Dienst stoppen (falls noch laufend) und entfernen.
    pub fn uninstall() -> R {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .map_err(|e| format!("Verbindung zum Dienst-Manager fehlgeschlagen: {e:?}"))?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|e| {
                format!(
                    "Dienst '{SERVICE_NAME}' nicht gefunden oder nicht zugreifbar: {e:?} \
                     (ist er ueberhaupt installiert? 'sc query {SERVICE_NAME}' pruefen; \
                     Adminrechte noetig)"
                )
            })?;

        if service.query_status()?.current_state != ServiceState::Stopped {
            let _ = service.stop();
            std::thread::sleep(Duration::from_secs(2));
        }
        service
            .delete()
            .map_err(|e| format!("Dienst loeschen fehlgeschlagen: {e:?}"))?;
        Ok(())
    }
}

#[cfg(not(windows))]
mod stub_impl {
    use crate::config;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn not_supported() -> R {
        Err("Der Windows-Dienst ist nur unter Windows verfuegbar.".into())
    }

    pub fn run() -> R {
        not_supported()
    }
    pub fn install(_cfg: &config::Config) -> R {
        not_supported()
    }
    pub fn uninstall() -> R {
        not_supported()
    }
}
