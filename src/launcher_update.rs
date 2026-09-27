use std::path::Path;

use crate::client_manifest::LauncherPackage;
use crate::{download_file, get_sha256_hash_of_file, info, Client, LauncherResult};

pub fn parse_version(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    if parts.next().is_some() { return None; }
    Some(version)
}

pub async fn maybe_update(
    client: &Client,
    package: Option<&LauncherPackage>,
    launcher_directory: &Path,
    arguments: &[String],
) -> LauncherResult<bool> {
    let Some(package) = package else { return Ok(false) };
    let installed = parse_version(env!("CARGO_PKG_VERSION"))
        .ok_or_else(|| "the installed launcher version is invalid".to_string())?;
    let offered = parse_version(&package.version)
        .ok_or_else(|| "the offered launcher version is invalid".to_string())?;
    if offered <= installed { return Ok(false); }

    #[cfg(target_os = "windows")]
    let filename = format!("SeashellPlayerLauncher-{}.exe", package.version);
    #[cfg(not(target_os = "windows"))]
    let filename = format!("SeashellPlayerLauncher-{}", package.version);
    let target = launcher_directory.join(filename);
    let downloaded_now = !target.exists();
    if downloaded_now {
        download_file(client, &package.url, &target).await?;
    }
    let digest = get_sha256_hash_of_file(&target)?;
    if !digest.eq_ignore_ascii_case(&package.sha256) {
        if downloaded_now { let _ = std::fs::remove_file(&target); }
        return Err(format!(
            "the launcher update at {} failed its SHA-256 check; the current launcher was left unchanged",
            target.display()
        ));
    }
    info(&format!("Starting verified launcher update {}", package.version));
    std::process::Command::new(&target)
        .args(arguments.iter().skip(1))
        .spawn()
        .map_err(|e| format!("could not start launcher update {}: {}", target.display(), e))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_numeric_and_do_not_downgrade() {
        assert!(parse_version("1.10.0") > parse_version("1.9.9"));
        assert!(parse_version("1.6.0") == parse_version("1.6.0"));
        for invalid in ["", "1", "1.2", "1.2.3.4", "1.2.x", "../1.2.3"] {
            assert!(parse_version(invalid).is_none());
        }
    }
}
