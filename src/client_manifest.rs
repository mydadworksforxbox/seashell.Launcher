use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::StreamExt;

use crate::{
    create_folder_if_not_exists, download_file, extract_zip, get_sha256_hash_of_file,
    info, is_valid_version, Client, LauncherResult,
};

// This key was generated on the owner's PC. The private half must never be copied to the VPS
// or checked into source control. A compromised website cannot authorize a launcher update.
const MANIFEST_PUBLIC_KEY_HEX: &str = "08327221a68294c2414ab310bdd96897b9cd4952e6f7ac358a298963a2341237";
const MAX_MANIFEST_BYTES: usize = 1_048_576;

#[derive(Debug)]
pub struct ClientManifest {
    clients: HashMap<String, ClientPackage>,
    pub launcher: Option<LauncherPackage>,
}

#[derive(Debug)]
pub struct LauncherPackage {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Debug)]
pub struct ClientPackage {
    url: String,
    sha256: String,
    executable: String,
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

impl ClientManifest {
    pub fn parse(body: &str) -> LauncherResult<Self> {
        let json: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| format!("the client manifest is invalid JSON: {}", e))?;
        let schema_version = json
            .get("schemaVersion")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if schema_version != 1 {
            return Err(format!(
                "unsupported client manifest schema {}",
                schema_version
            ));
        }
        let entries = json
            .get("clients")
            .and_then(|v| v.as_object())
            .ok_or_else(|| "the manifest needs a clients object".to_string())?;
        let mut clients = HashMap::new();
        for (version, value) in entries {
            let url = value
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("the package for {} needs a URL", version))?
                .to_string();
            let sha256 = value
                .get("sha256")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("the package for {} needs a SHA-256 digest", version))?
                .to_string();
            let executable = value
                .get("executable")
                .and_then(|v| v.as_str())
                .unwrap_or("RobloxPlayerBeta.exe")
                .to_string();
            let package = ClientPackage {
                url,
                sha256,
                executable,
            };
            if !is_valid_version(version) {
                return Err(format!(
                    "the manifest contains an invalid client version '{}'",
                    version
                ));
            }
            let url = reqwest::Url::parse(&package.url)
                .map_err(|e| format!("invalid package URL for {}: {}", version, e))?;
            if url.scheme() != "https" || url.host_str().is_none() {
                return Err(format!("the package URL for {} must use HTTPS", version));
            }
            if package.sha256.len() != 64 || !package.sha256.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(format!(
                    "the package for {} needs a 64-character SHA-256 digest",
                    version
                ));
            }
            if !safe_relative_path(&package.executable) {
                return Err(format!(
                    "the package for {} has an unsafe executable path",
                    version
                ));
            }
            clients.insert(version.clone(), package);
        }
        let launcher = match json.get("launcher") {
            Some(value) => {
                let version = value.get("version").and_then(|v| v.as_str())
                    .ok_or_else(|| "the launcher update needs a version".to_string())?;
                if crate::launcher_update::parse_version(version).is_none() {
                    return Err("the launcher update has an invalid version".to_string());
                }
                let url = value.get("url").and_then(|v| v.as_str())
                    .ok_or_else(|| "the launcher update needs a URL".to_string())?;
                let parsed = reqwest::Url::parse(url)
                    .map_err(|e| format!("invalid launcher update URL: {}", e))?;
                if parsed.scheme() != "https" || parsed.host_str().is_none() {
                    return Err("the launcher update URL must use HTTPS".to_string());
                }
                let sha256 = value.get("sha256").and_then(|v| v.as_str())
                    .ok_or_else(|| "the launcher update needs a SHA-256 digest".to_string())?;
                if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("the launcher update needs a 64-character SHA-256 digest".to_string());
                }
                Some(LauncherPackage { version: version.to_string(), url: url.to_string(), sha256: sha256.to_string() })
            }
            None => None,
        };
        Ok(Self { clients, launcher })
    }

    pub fn package(&self, version: &str) -> LauncherResult<&ClientPackage> {
        self.clients.get(version).ok_or_else(|| {
            format!("no Windows client package is published for {} yet; this Play link cannot be launched", version)
        })
    }

    fn require_manifest_origin(&self, manifest_url: &reqwest::Url) -> LauncherResult<()> {
        let same_origin = |value: &str| -> bool {
            reqwest::Url::parse(value).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.origin() == manifest_url.origin()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
            })
        };
        if self.launcher.as_ref().is_some_and(|package| !same_origin(&package.url)) {
            return Err("the launcher update must come from the signed manifest's HTTPS origin".into());
        }
        if self.clients.values().any(|package| !same_origin(&package.url)) {
            return Err("client packages must come from the signed manifest's HTTPS origin".into());
        }
        Ok(())
    }
}

fn hex_key(hex: &str) -> LauncherResult<[u8; 32]> {
    if hex.len() != 64 { return Err("invalid embedded manifest public key".to_string()); }
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid embedded manifest public key".to_string())?;
    }
    Ok(key)
}

fn verify_signed_bytes(body: &[u8], signature: &[u8], public_key_hex: &str) -> LauncherResult<()> {
    let key = VerifyingKey::from_bytes(&hex_key(public_key_hex)?)
        .map_err(|_| "invalid embedded manifest public key".to_string())?;
    let signature = Signature::from_slice(signature)
        .map_err(|_| "the manifest signature is not 64 bytes".to_string())?;
    key.verify_strict(body, &signature)
        .map_err(|_| "the client manifest signature is invalid; no downloaded code was started".to_string())
}

async fn fetch_limited(client: &Client, url: &str, limit: usize) -> LauncherResult<Vec<u8>> {
    let response = client.get(url).send().await
        .map_err(|e| format!("could not reach {}: {}", url, e))?;
    if !response.status().is_success() {
        return Err(format!("{} answered HTTP {}", url, response.status()));
    }
    if response.content_length().is_some_and(|length| length > limit as u64) {
        return Err(format!("{} exceeds the size limit", url));
    }
    let mut result = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("could not read {}: {}", url, e))?;
        if result.len().saturating_add(chunk.len()) > limit {
            return Err(format!("{} exceeds the size limit", url));
        }
        result.extend_from_slice(&chunk);
    }
    Ok(result)
}

pub async fn fetch_manifest(client: &Client, url: &str) -> LauncherResult<ClientManifest> {
    let manifest_url =
        reqwest::Url::parse(url).map_err(|e| format!("invalid client manifest URL: {}", e))?;
    if manifest_url.scheme() != "https" || manifest_url.query().is_some() || manifest_url.fragment().is_some() {
        return Err("the client manifest URL must use HTTPS".to_string());
    }
    let mut signature_url = manifest_url.clone();
    signature_url.set_path(&format!("{}.sig", manifest_url.path()));
    let body = fetch_limited(client, url, MAX_MANIFEST_BYTES).await?;
    let signature = fetch_limited(client, signature_url.as_str(), 64).await?;
    verify_signed_bytes(&body, &signature, MANIFEST_PUBLIC_KEY_HEX)?;
    let text = std::str::from_utf8(&body)
        .map_err(|_| "the client manifest is not UTF-8".to_string())?;
    let manifest = ClientManifest::parse(text)?;
    manifest.require_manifest_origin(&manifest_url)?;
    Ok(manifest)
}

fn package_directory(install_root: &Path, version: &str, sha256: &str) -> PathBuf {
    install_root.join(version).join(sha256.to_ascii_lowercase())
}

pub async fn install_package(
    client: &Client,
    package: &ClientPackage,
    version: &str,
    install_root: &Path,
    downloads_root: &Path,
    base_url: &str,
) -> LauncherResult<PathBuf> {
    let app_settings = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Settings>\n  <ContentFolder>content</ContentFolder>\n  <BaseUrl>https://{}</BaseUrl>\n</Settings>\n",
        base_url
    );
    let final_directory = package_directory(install_root, version, &package.sha256);
    let client_directory_name = format!("Client{}", version);
    let executable_path = final_directory
        .join(&client_directory_name)
        .join(&package.executable);
    let marker_path = final_directory.join(".package-sha256");
    if marker_path.exists() && executable_path.is_file() {
        let installed_digest = std::fs::read_to_string(&marker_path)
            .map_err(|e| format!("could not read {}: {}", marker_path.display(), e))?;
        if installed_digest.trim().eq_ignore_ascii_case(&package.sha256) {
            let settings_path = executable_path.parent().unwrap().join("AppSettings.xml");
            if std::fs::read_to_string(&settings_path).ok().as_deref() != Some(app_settings.as_str()) {
                std::fs::write(&settings_path, &app_settings)
                    .map_err(|e| format!("could not restore {}: {}", settings_path.display(), e))?;
            }
            return Ok(executable_path);
        }
    }
    if final_directory.exists() {
        return Err(format!(
            "the {} client install is incomplete at {}; move it aside and retry",
            version,
            final_directory.display()
        ));
    }

    create_folder_if_not_exists(downloads_root)?;
    let zip_path = downloads_root.join(format!("{}.zip", package.sha256.to_ascii_lowercase()));
    if zip_path.exists()
        && !get_sha256_hash_of_file(&zip_path)?.eq_ignore_ascii_case(&package.sha256)
    {
        return Err(format!(
            "cached download {} failed its SHA-256 check",
            zip_path.display()
        ));
    }
    if !zip_path.exists() {
        download_file(client, &package.url, &zip_path).await?;
    }
    let actual_sha256 = get_sha256_hash_of_file(&zip_path)?;
    if !actual_sha256.eq_ignore_ascii_case(&package.sha256) {
        let _ = std::fs::remove_file(&zip_path);
        return Err(format!(
            "client package {} failed its SHA-256 check",
            version
        ));
    }

    let version_root = install_root.join(version);
    create_folder_if_not_exists(&version_root)?;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("could not get the current time: {}", e))?
        .as_nanos();
    let staging_directory =
        version_root.join(format!(".install-{}-{}", std::process::id(), unique));
    std::fs::create_dir(&staging_directory)
        .map_err(|e| format!("could not create {}: {}", staging_directory.display(), e))?;
    let staged_client_directory = staging_directory.join(&client_directory_name);
    let result = (|| -> LauncherResult<()> {
        create_folder_if_not_exists(&staged_client_directory)?;
        extract_zip(&zip_path, &staged_client_directory)?;
        let staged_executable = staged_client_directory.join(&package.executable);
        if !staged_executable.is_file() {
            return Err(format!(
                "the {} client package does not contain {}",
                version, package.executable
            ));
        }
        // The player reads AppSettings.xml beside RobloxPlayerBeta.exe, not from
        // the version root that contains the package marker.
        std::fs::write(staged_client_directory.join("AppSettings.xml"), app_settings)
            .map_err(|e| format!("could not write AppSettings.xml: {}", e))?;
        std::fs::write(
            staging_directory.join(".package-sha256"),
            package.sha256.to_ascii_lowercase(),
        )
        .map_err(|e| format!("could not write package marker: {}", e))?;
        std::fs::rename(&staging_directory, &final_directory)
            .map_err(|e| format!("could not complete the {} client install: {}", version, e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging_directory);
    }
    result?;
    info(&format!(
        "Installed {} client at {}",
        version,
        final_directory.display()
    ));
    Ok(executable_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn signed_manifest_rejects_tampering_and_wrong_signer() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key_hex: String = signing_key.verifying_key().to_bytes()
            .iter().map(|byte| format!("{:02x}", byte)).collect();
        let body = br#"{"schemaVersion":1,"clients":{}}"#;
        let signature = signing_key.sign(body).to_bytes();
        assert!(verify_signed_bytes(body, &signature, &public_key_hex).is_ok());
        assert!(verify_signed_bytes(br#"{"schemaVersion":1,"clients":{"2020L":{}}}"#, &signature, &public_key_hex).is_err());
        assert!(verify_signed_bytes(body, &signature, MANIFEST_PUBLIC_KEY_HEX).is_err());
        assert!(verify_signed_bytes(body, &signature[..63], &public_key_hex).is_err());
    }

    #[test]
    fn offline_signing_key_matches_embedded_public_key() {
        let body = include_bytes!("../tests/signed-manifest-v2.json");
        let signature = include_bytes!("../tests/signed-manifest-v2.json.sig");
        verify_signed_bytes(body, signature, MANIFEST_PUBLIC_KEY_HEX).unwrap();
        let mut altered = body.to_vec();
        altered[0] ^= 1;
        assert!(verify_signed_bytes(&altered, signature, MANIFEST_PUBLIC_KEY_HEX).is_err());
    }

    #[test]
    fn validates_a_multi_version_manifest() {
        let json = format!(
            r#"{{"schemaVersion":1,"clients":{{"2017L":{{"url":"https://example.com/2017.zip","sha256":"{}"}},"2021M":{{"url":"https://example.com/2021.zip","sha256":"{}","executable":"bin/RobloxPlayerBeta.exe"}}}}}}"#,
            HASH, HASH
        );
        let manifest = ClientManifest::parse(&json).unwrap();
        assert_eq!(
            manifest.package("2017L").unwrap().executable,
            "RobloxPlayerBeta.exe"
        );
        assert_eq!(
            manifest.package("2021M").unwrap().executable,
            "bin/RobloxPlayerBeta.exe"
        );
        assert!(manifest.package("2018L").is_err());
        assert!(manifest.launcher.is_none());
    }

    #[test]
    fn package_urls_must_match_signed_manifest_origin() {
        let first_party = reqwest::Url::parse("https://seashell.rocks/client-downloads/manifest-v2.json").unwrap();
        let good = ClientManifest::parse(&format!(
            r#"{{"schemaVersion":1,"launcher":{{"version":"1.6.5","url":"https://seashell.rocks/client-downloads/launcher.exe","sha256":"{}"}},"clients":{{}}}}"#,
            HASH
        )).unwrap();
        good.require_manifest_origin(&first_party).unwrap();
        let external = ClientManifest::parse(&format!(
            r#"{{"schemaVersion":1,"launcher":{{"version":"1.6.5","url":"https://other.example/launcher.exe","sha256":"{}"}},"clients":{{}}}}"#,
            HASH
        )).unwrap();
        assert!(external.require_manifest_origin(&first_party).is_err());
    }

    #[test]
    fn validates_launcher_updates() {
        let json = format!(
            r#"{{"schemaVersion":1,"launcher":{{"version":"1.6.1","url":"https://seashell.rocks/client-downloads/SeashellPlayerLauncher-1.6.1.exe","sha256":"{}"}},"clients":{{}}}}"#,
            HASH
        );
        let manifest = ClientManifest::parse(&json).unwrap();
        assert_eq!(manifest.launcher.unwrap().version, "1.6.1");
        for update in [
            r#"{"version":"../1.6.1","url":"https://seashell.rocks/update.exe","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            r#"{"version":"1.6.1","url":"http://seashell.rocks/update.exe","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            r#"{"version":"1.6.1","url":"https://seashell.rocks/update.exe","sha256":"bad"}"#,
        ] {
            let body = format!(r#"{{"schemaVersion":1,"launcher":{},"clients":{{}}}}"#, update);
            assert!(ClientManifest::parse(&body).is_err());
        }
    }

    #[test]
    fn rejects_unsafe_or_unverified_packages() {
        for (url, digest, executable) in [
            (
                "http://example.com/client.zip",
                HASH,
                "RobloxPlayerBeta.exe",
            ),
            (
                "https://example.com/client.zip",
                "bad",
                "RobloxPlayerBeta.exe",
            ),
            (
                "https://example.com/client.zip",
                HASH,
                "../RobloxPlayerBeta.exe",
            ),
        ] {
            let json = format!(
                r#"{{"schemaVersion":1,"clients":{{"2017L":{{"url":"{}","sha256":"{}","executable":"{}"}}}}}}"#,
                url, digest, executable
            );
            assert!(ClientManifest::parse(&json).is_err());
        }
    }

    #[test]
    fn different_versions_have_separate_directories() {
        let root = Path::new("clients");
        assert_ne!(
            package_directory(root, "2017L", HASH),
            package_directory(root, "2021M", HASH)
        );
    }

    #[tokio::test]
    async fn installs_two_clients_without_removing_either() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "seashell-launcher-test-{}-{}",
            std::process::id(),
            unique
        ));
        let downloads = root.join("downloads");
        let clients = root.join("clients");
        std::fs::create_dir_all(&downloads).unwrap();
        let raw_zip = root.join("package.zip");
        let file = std::fs::File::create(&raw_zip).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("RobloxPlayerBeta.exe", zip::write::FileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut writer, b"test client").unwrap();
        writer.finish().unwrap();
        let hash = get_sha256_hash_of_file(&raw_zip).unwrap();
        std::fs::rename(&raw_zip, downloads.join(format!("{}.zip", hash))).unwrap();
        let package = ClientPackage {
            url: "https://example.com/client.zip".to_string(),
            sha256: hash,
            executable: "RobloxPlayerBeta.exe".to_string(),
        };
        let client = Client::new();
        let first = install_package(
            &client,
            &package,
            "2017L",
            &clients,
            &downloads,
            "seashell.rocks",
        )
        .await
        .unwrap();
        let second = install_package(
            &client,
            &package,
            "2021M",
            &clients,
            &downloads,
            "seashell.rocks",
        )
        .await
        .unwrap();
        assert!(first.is_file());
        assert!(second.is_file());
        assert_ne!(first, second);
        assert!(first
            .parent()
            .unwrap()
            .join("AppSettings.xml")
            .is_file());
        let _ = std::fs::remove_dir_all(&root);
    }
}
