//! Embeds the icon and version information into the Windows binary.
//!
//! Two reasons this exists. The obvious one: without it the service shows up in
//! Task Manager and services.msc with the generic executable icon. The less
//! obvious one: a Rust binary carries no version resource at all by default,
//! which is why the installer could not read a version off the EXE and had to
//! be told one separately. With this, `ntlm-agent.exe` reports its own version
//! in the file properties dialog like any other Windows program.
//!
//! Non-Windows targets skip it entirely, so `cargo build` still works on Linux
//! for syntax checking.

fn main() {
    #[cfg(windows)]
    {
        // Path is relative to the crate root, not to this file.
        let icon = "../assets/ntlm-agent.ico";
        if std::path::Path::new(icon).exists() {
            let mut res = winresource::WindowsResource::new();
            res.set_icon(icon);
            res.set("ProductName", "NTLM-Analyzer Agent");
            res.set(
                "FileDescription",
                "Collects NTLM usage data for the NTLM-Analyzer",
            );
            res.set("CompanyName", "NTLM-Analyzer");
            res.set("LegalCopyright", "GPL-3.0-or-later");
            if let Err(e) = res.compile() {
                // A missing resource compiler must not break the build - the
                // agent works fine without an icon.
                println!("cargo:warning=could not embed icon/version: {e}");
            }
        } else {
            println!("cargo:warning=icon not found at {icon}, building without one");
        }
        println!("cargo:rerun-if-changed={icon}");
    }
}
