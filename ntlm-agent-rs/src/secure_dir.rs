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

//! The data folder (C:\ProgramData\NtlmAgent) holds the API key, the
//! collector URL and the watermarks, and the service writes to it as SYSTEM.
//!
//! Every user may create folders under ProgramData. Someone who creates
//! `NtlmAgent` before the agent is installed stays its owner - and an owner can
//! always give himself the access back, whatever the ACL says. With that he
//! could read the key, redirect the collector, silence the agent, or plant
//! junctions that turn the service's own file writes into writes anywhere on
//! the system. So the folder is only used when it is ours:
//!
//!   * install/configure (elevated): a folder that is a link, not a folder, or
//!     owned by anyone but SYSTEM, Administrators or the installing admin is
//!     moved aside; a fresh one is created with a protected ACL from the first
//!     moment, owned by Administrators. Nothing is written before that holds,
//!     and a failure stops the installation instead of carrying on unprotected.
//!   * service start: the same check, strictly. A folder that is not ours
//!     stops the service before it writes a single byte there.

// Outside Windows only the decision (judge) is exercised, by the tests.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::{Path, PathBuf};

/// SIDs that may own the data folder.
const TRUSTED_OWNERS: [&str; 3] = [
    "S-1-5-18",     // SYSTEM
    "S-1-5-32-544", // BUILTIN\Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
];

/// What was found at the data folder's path.
#[derive(Debug, PartialEq, Eq)]
pub enum Found {
    Missing,
    Trusted,
    Untrusted(String),
}

/// The decision, kept free of Windows calls so it can be tested anywhere.
/// `owner` is None when the owner could not be read (e.g. the ACL denies us) -
/// that alone is reason enough not to trust the folder.
pub fn judge(
    exists: bool,
    is_link: bool,
    is_dir: bool,
    owner: Option<&str>,
    installer: Option<&str>,
) -> Found {
    if !exists {
        return Found::Missing;
    }
    if is_link {
        return Found::Untrusted("it is a link (junction or symbolic link)".into());
    }
    if !is_dir {
        return Found::Untrusted("it is a file, not a folder".into());
    }
    match owner {
        None => Found::Untrusted("its owner cannot be read".into()),
        Some(o) if TRUSTED_OWNERS.contains(&o) => Found::Trusted,
        Some(o) if installer == Some(o) => Found::Trusted,
        Some(o) => Found::Untrusted(format!("it is owned by {o}")),
    }
}

fn inspect(dir: &Path, installer: Option<&str>) -> Result<Found, String> {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Found::Missing);
        }
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    // On Windows is_symlink() covers symbolic links and junctions alike.
    let is_link = meta.file_type().is_symlink();
    let owner = if is_link || !meta.is_dir() {
        None
    } else {
        win::owner_sid(dir).ok()
    };
    Ok(judge(true, is_link, meta.is_dir(), owner.as_deref(), installer))
}

/// Install/configure: make the data folder ours before anything goes in.
pub fn prepare(dir: &Path) -> Result<(), String> {
    let me = win::current_user_sid().ok();
    match inspect(dir, me.as_deref())? {
        Found::Trusted => {}
        Found::Missing => create(dir)?,
        Found::Untrusted(why) => {
            let aside = set_aside(dir)?;
            // Not into agent.log: that file lives in the folder being replaced.
            eprintln!(
                "WARNING: {} was not safe to use ({why}). It was moved to {} - \
                 check who created it. A fresh folder is used instead.",
                dir.display(),
                aside.display()
            );
            create(dir)?;
        }
    }
    harden(dir)?;
    remove_links_inside(dir)
}

/// Service start: use the folder only if it is ours. Owned by SYSTEM,
/// Administrators or TrustedInstaller - install/configure set that.
pub fn check(dir: &Path) -> Result<(), String> {
    match inspect(dir, None)? {
        Found::Trusted => Ok(()),
        Found::Missing => Err(format!("{} does not exist - run 'configure' again", dir.display())),
        Found::Untrusted(why) => Err(format!(
            "{} is not safe to use ({why}) - run 'ntlm-agent.exe configure' as \
             administrator to replace it",
            dir.display()
        )),
    }
}

fn create(dir: &Path) -> Result<(), String> {
    // Created with its final ACL in one step: between a plain create and a
    // later icacls, any user could drop a link into the new folder.
    win::create_protected_dir(dir)
        .map_err(|e| format!("creating {} failed: {e}", dir.display()))
}

fn set_aside(dir: &Path) -> Result<PathBuf, String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = format!(
        "{}.untrusted-{stamp}",
        dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    );
    let aside = dir.with_file_name(name);
    if std::fs::rename(dir, &aside).is_ok() {
        return Ok(aside);
    }
    // The owner may have locked administrators out. Take ownership of the
    // entry itself (never of what a link points to: /L) and try again.
    let is_link = std::fs::symlink_metadata(dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let with_link = |rest: &[&'static str]| -> Vec<&'static str> {
        let mut v: Vec<&'static str> = if is_link { vec!["/L"] } else { Vec::new() };
        v.extend_from_slice(rest);
        v
    };
    let _ = icacls(dir, &with_link(&["/setowner", "*S-1-5-32-544", "/C", "/Q"]));
    let _ = icacls(dir, &with_link(&["/grant", "*S-1-5-32-544:F", "/C", "/Q"]));
    std::fs::rename(dir, &aside)
        .map(|_| aside)
        .map_err(|e| format!("{} is not safe and could not be moved aside: {e}", dir.display()))
}

/// Protected ACL (SYSTEM + Administrators only, nothing inherited) and
/// Administrators as owner. Both must hold, or nothing is written.
fn harden(dir: &Path) -> Result<(), String> {
    icacls(
        dir,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/Q",
        ],
    )?;
    icacls(dir, &["/setowner", "*S-1-5-32-544", "/Q"])
}

/// A folder that was already ours may still hold links from an earlier, less
/// careful version. Links are removed, never followed.
fn remove_links_inside(dir: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_link = std::fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if is_link {
            // A directory link is removed with remove_dir, a file link with
            // remove_file; neither touches the target.
            if std::fs::remove_dir(&path).is_err() {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("could not remove link {}: {e}", path.display()))?;
            }
            eprintln!("Removed a link from the data folder: {}", path.display());
        }
    }
    Ok(())
}

fn icacls(dir: &Path, args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new(crate::config::system32("icacls.exe"))
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("could not run icacls: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "icacls {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout).trim()
        ))
    }
}

// ----------------------------------------------------------------------------
// The few Windows calls this needs, declared directly (as config.rs does for the
// console) rather than pulling in another crate.

#[cfg(windows)]
mod win {
    use core::ffi::c_void;
    use std::path::Path;
    use std::ptr::null_mut;

    type Handle = *mut c_void;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    const SE_FILE_OBJECT: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 1;
    const SDDL_REVISION_1: u32 = 1;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    // Protected DACL: SYSTEM and Administrators full control, inherited by
    // files and subfolders; nothing comes in from ProgramData.
    const DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_sd: *const u16,
            revision: u32,
            sd: *mut *mut c_void,
            sd_size: *mut u32,
        ) -> i32;
        fn GetNamedSecurityInfoW(
            object_name: *const u16,
            object_type: u32,
            security_info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            sd: *mut *mut c_void,
        ) -> u32;
        fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            len: u32,
            ret_len: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateDirectoryW(path: *const u16, sa: *const SecurityAttributes) -> i32;
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(h: Handle) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn path_wide(p: &Path) -> Vec<u16> {
        wide(&p.to_string_lossy())
    }

    /// Reads a NUL-terminated UTF-16 string.
    unsafe fn read_wide(p: *const u16) -> String {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }

    unsafe fn sid_string(sid: *mut c_void) -> Result<String, String> {
        let mut s: *mut u16 = null_mut();
        if ConvertSidToStringSidW(sid, &mut s) == 0 || s.is_null() {
            return Err(format!("ConvertSidToStringSid: {}", std::io::Error::last_os_error()));
        }
        let out = read_wide(s);
        LocalFree(s as *mut c_void);
        Ok(out)
    }

    pub fn owner_sid(p: &Path) -> Result<String, String> {
        let name = path_wide(p);
        let mut owner: *mut c_void = null_mut();
        let mut sd: *mut c_void = null_mut();
        unsafe {
            let rc = GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            );
            if rc != 0 || owner.is_null() {
                return Err(format!("GetNamedSecurityInfo: error {rc}"));
            }
            let out = sid_string(owner);
            LocalFree(sd);
            out
        }
    }

    pub fn current_user_sid() -> Result<String, String> {
        unsafe {
            let mut token: Handle = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(format!("OpenProcessToken: {}", std::io::Error::last_os_error()));
            }
            let mut len: u32 = 0;
            GetTokenInformation(token, TOKEN_USER_CLASS, null_mut(), 0, &mut len);
            // u64 storage keeps the buffer pointer-aligned for the SID pointer
            // at its start (TOKEN_USER begins with SID_AND_ATTRIBUTES.Sid).
            let mut buf: Vec<u64> = vec![0; (len as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                buf.as_mut_ptr() as *mut c_void,
                len,
                &mut len,
            );
            CloseHandle(token);
            if ok == 0 {
                return Err(format!("GetTokenInformation: {}", std::io::Error::last_os_error()));
            }
            let sid = *(buf.as_ptr() as *const *mut c_void);
            sid_string(sid)
        }
    }

    pub fn create_protected_dir(p: &Path) -> Result<(), String> {
        let sddl = wide(DIR_SDDL);
        let name = path_wide(p);
        unsafe {
            let mut sd: *mut c_void = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            ) == 0
            {
                return Err(format!("security descriptor: {}", std::io::Error::last_os_error()));
            }
            let sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: sd,
                b_inherit_handle: 0,
            };
            let ok = CreateDirectoryW(name.as_ptr(), &sa);
            let err = std::io::Error::last_os_error();
            LocalFree(sd);
            if ok == 0 {
                return Err(err.to_string());
            }
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod win {
    use std::path::Path;

    pub fn owner_sid(_p: &Path) -> Result<String, String> {
        Err("Windows only".into())
    }
    pub fn current_user_sid() -> Result<String, String> {
        Err("Windows only".into())
    }
    pub fn create_protected_dir(p: &Path) -> Result<(), String> {
        std::fs::create_dir(p).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_folder_is_created() {
        assert_eq!(judge(false, false, false, None, None), Found::Missing);
    }

    #[test]
    fn system_and_administrators_are_trusted() {
        assert_eq!(judge(true, false, true, Some("S-1-5-18"), None), Found::Trusted);
        assert_eq!(judge(true, false, true, Some("S-1-5-32-544"), None), Found::Trusted);
    }

    #[test]
    fn a_users_folder_is_not() {
        let f = judge(true, false, true, Some("S-1-5-21-1-2-3-1105"), Some("S-1-5-21-1-2-3-500"));
        assert!(matches!(f, Found::Untrusted(_)));
    }

    #[test]
    fn the_installing_admin_is_trusted_at_install_only() {
        let admin = "S-1-5-21-1-2-3-500";
        assert_eq!(judge(true, false, true, Some(admin), Some(admin)), Found::Trusted);
        // The service checks without an installer: only SYSTEM/Administrators.
        assert!(matches!(judge(true, false, true, Some(admin), None), Found::Untrusted(_)));
    }

    #[test]
    fn links_and_files_are_never_trusted() {
        assert!(matches!(judge(true, true, true, Some("S-1-5-18"), None), Found::Untrusted(_)));
        assert!(matches!(judge(true, false, false, Some("S-1-5-18"), None), Found::Untrusted(_)));
    }

    #[test]
    fn unreadable_owner_is_not_trusted() {
        assert!(matches!(judge(true, false, true, None, None), Found::Untrusted(_)));
    }

    // These run on the Windows build runner (elevated), against the real API.
    #[cfg(windows)]
    #[test]
    fn protected_dir_gets_a_readable_trusted_owner() {
        let base = std::env::temp_dir().join(format!("ntlm-agent-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.join("data");
        win::create_protected_dir(&dir).unwrap();
        let me = win::current_user_sid().unwrap();
        assert!(me.starts_with("S-1-5-"), "{me}");
        let owner = win::owner_sid(&dir).unwrap();
        assert!(owner == me || TRUSTED_OWNERS.contains(&owner.as_str()), "{owner} / {me}");
        harden(&dir).unwrap();
        assert_eq!(win::owner_sid(&dir).unwrap(), "S-1-5-32-544");
        check(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn prepare_is_repeatable() {
        let base = std::env::temp_dir().join(format!("ntlm-agent-prep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.join("data");
        prepare(&dir).unwrap();
        std::fs::write(dir.join("config.json"), "{}").unwrap();
        prepare(&dir).unwrap();
        assert!(dir.join("config.json").exists(), "a trusted folder keeps its content");
        let _ = std::fs::remove_dir_all(&base);
    }
}
