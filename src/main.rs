use colored::*;
use futures_util::StreamExt;
use reqwest::Client;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

type LauncherResult<T> = Result<T, String>;

fn info( message : &str ) {
    let time = chrono::Local::now().format("%H:%M:%S").to_string();
    println!("[{}] [{}] {}", time.bold().blue(), "INFO".bold().green(), message);
}

fn error( message : &str ) {
    let time = chrono::Local::now().format("%H:%M:%S").to_string();
    println!("[{}] [{}] {}", time.bold().blue(), "ERROR".bold().red(), message);
}

#[cfg(debug_assertions)]
fn debug( message : &str ) {
    let time = chrono::Local::now().format("%H:%M:%S").to_string();
    println!("[{}] [{}] {}", time.bold().blue(), "DEBUG".bold().yellow(), message);
}

#[cfg(not(debug_assertions))]
fn debug( _message : &str ) {}

async fn http_get( client: &Client, url: &str ) -> LauncherResult<String> {
    debug(&format!("{} {}", "GET".green(), url.bright_blue()));
    let response = client.get(url).send().await.map_err(|e| format!("could not reach {}: {}", url, e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{} answered HTTP {}", url, status));
    }
    response.text().await.map_err(|e| format!("could not read the response from {}: {}", url, e))
}

async fn download_file( client: &Client, url: &str, path: &Path ) -> LauncherResult<()> {
    debug(&format!("{} {}", "GET".green(), url.bright_blue()));
    let response = client.get(url).send().await.map_err(|e| format!("could not reach {}: {}", url, e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("downloading {} failed with HTTP {}", url, status));
    }
    let expected_length = response.content_length();
    debug(&format!("Content Length: {:?}", expected_length));

    info(&format!("Downloading {}", url.bright_blue()));
    let progress_bar = match expected_length {
        Some(length) => {
            let bar = indicatif::ProgressBar::new(length);
            bar.set_style(indicatif::ProgressStyle::default_bar()
                .template("                {spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"));
            bar
        },
        None => {
            // Some proxies drop the length header; show a byte counter instead of a bar.
            let bar = indicatif::ProgressBar::new_spinner();
            bar.set_style(indicatif::ProgressStyle::default_spinner()
                .template("                {spinner:.green} {bytes} downloaded")
                .unwrap());
            bar
        }
    };

    // Write to a temporary file first so an interrupted download never looks complete.
    let partial_path = path.with_extension("part");
    let file = std::fs::File::create(&partial_path).map_err(|e| format!("could not create {}: {}", partial_path.display(), e))?;
    let mut writer = std::io::BufWriter::new(file);
    let mut downloaded : u64 = 0;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("the download of {} was interrupted: {}", url, e))?;
        writer.write_all(&chunk).map_err(|e| format!("could not write {}: {}", partial_path.display(), e))?;
        downloaded += chunk.len() as u64;
        progress_bar.set_position(downloaded);
    }
    writer.flush().map_err(|e| format!("could not write {}: {}", partial_path.display(), e))?;
    drop(writer);
    progress_bar.finish();

    let incomplete = match expected_length {
        Some(length) => downloaded != length,
        None => downloaded == 0,
    };
    if incomplete {
        let _ = std::fs::remove_file(&partial_path);
        return Err(format!("the download of {} stopped early ({} bytes received)", url, downloaded));
    }
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| format!("could not replace {}: {}", path.display(), e))?;
    }
    std::fs::rename(&partial_path, path).map_err(|e| format!("could not save {}: {}", path.display(), e))?;
    info(&format!("Finished downloading {}", url.green()));
    Ok(())
}

async fn download_file_prefix( client: &Client, url: &str, path_prefix : &Path ) -> LauncherResult<PathBuf> {
    let path = path_prefix.join(format!("{:x}", md5::compute(url.as_bytes())));
    download_file_verified(client, url, &path).await?;
    Ok(path)
}

fn create_folder_if_not_exists( path: &Path ) -> LauncherResult<()> {
    if !path.exists() {
        info(&format!("Creating folder {}", path.display().to_string().bright_blue()));
        std::fs::create_dir_all(path).map_err(|e| format!("could not create {}: {}", path.display(), e))?;
    }
    Ok(())
}

fn get_sha1_hash_of_file( path: &Path ) -> LauncherResult<String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("could not open {}: {}", path.display(), e))?;
    let mut hasher = Sha1::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| format!("could not read {}: {}", path.display(), e))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn get_sha256_hash_of_file( path: &Path ) -> LauncherResult<String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("could not open {}: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| format!("could not read {}: {}", path.display(), e))?;
    Ok(format!("{:x}", hasher.finalize()))
}

// Integrity verification is optional and backwards compatible: if the setup server does not
// publish a "<file>.sha256" sidecar (404), older deployments keep working unverified. Any other
// failure (bad status, malformed digest) is treated as an error rather than silently skipped, so
// a misconfigured sidecar doesn't quietly disable verification.
async fn fetch_expected_sha256( client: &Client, file_url: &str ) -> LauncherResult<Option<String>> {
    let hash_url = format!("{}.sha256", file_url);
    debug(&format!("{} {}", "GET".green(), hash_url.bright_blue()));
    let response = client.get(&hash_url).send().await.map_err(|e| format!("could not reach {}: {}", hash_url, e))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!("{} answered HTTP {}", hash_url, response.status()));
    }
    let body = response.text().await.map_err(|e| format!("could not read {}: {}", hash_url, e))?;
    let digest = body.trim().to_ascii_lowercase();
    let looks_like_sha256 = digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit());
    if !looks_like_sha256 {
        return Err(format!("{} did not contain a SHA-256 hex digest", hash_url));
    }
    Ok(Some(digest))
}

// Downloads `url` to `path` via `download_file`, then verifies it against an optional
// "<url>.sha256" sidecar. See `fetch_expected_sha256` for the backwards-compatibility behavior
// when the sidecar is missing.
async fn download_file_verified( client: &Client, url: &str, path: &Path ) -> LauncherResult<()> {
    download_file(client, url, path).await?;
    match fetch_expected_sha256(client, url).await? {
        Some(expected_hash) => {
            let actual_hash = get_sha256_hash_of_file(path)?;
            if actual_hash.eq_ignore_ascii_case(&expected_hash) {
                info(&format!("Verified SHA-256 checksum of {}", path.display().to_string().bright_blue()));
            } else {
                let _ = std::fs::remove_file(path);
                return Err(format!(
                    "checksum mismatch for {} (expected {}, got {}); the download may be corrupted or tampered with",
                    url, expected_hash, actual_hash
                ));
            }
        },
        None => {
            debug(&format!("No {}.sha256 published; proceeding without integrity verification", url));
        }
    }
    Ok(())
}

fn get_installation_directory() -> LauncherResult<PathBuf> {
    dirs::data_local_dir()
        .map(|directory| directory.join("Seashell"))
        .ok_or_else(|| "could not find the local application data folder".to_string())
}

// The version names a folder and part of a download URL, so only accept plain version text
// (an error page from a proxy must never become a folder name).
fn is_valid_version( version: &str ) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

#[cfg(target_os = "windows")]
fn install_player_protocol( launcher_path: &Path ) -> std::io::Result<()> {
    let classes = RegKey::predef(HKEY_CURRENT_USER).create_subkey("Software\\Classes")?.0;
    let quoted_path = format!("\"{}\"", launcher_path.to_string_lossy());
    // Keep the old scheme as a compatibility alias for bookmarks and cached pages.
    for scheme in ["seashell-player", "syntax-player"] {
        let protocol = classes.create_subkey(scheme)?.0;
        protocol.set_value("", &"URL: Seashell Player Protocol")?;
        protocol.set_value("URL Protocol", &"")?;
        protocol.create_subkey("DefaultIcon")?.0.set_value("", &format!("{},0", quoted_path))?;
        protocol.create_subkey("shell\\open\\command")?.0.set_value("", &format!("{} \"%1\"", quoted_path))?;
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn install_desktop_entry( launcher_path: &Path ) -> LauncherResult<()> {
    let desktop_file_content = format!("[Desktop Entry]
Name=Seashell Launcher
Exec={} %u
Icon={}
Type=Application
Terminal=true
Version={}
MimeType=x-scheme-handler/seashell-player;
", launcher_path.display(), launcher_path.display(), env!("CARGO_PKG_VERSION"));
    let applications_directory = dirs::data_local_dir()
        .ok_or_else(|| "could not find the local application data folder".to_string())?
        .join("applications");
    create_folder_if_not_exists(&applications_directory)?;
    let desktop_file_path = applications_directory.join("seashell-player.desktop");
    std::fs::write(&desktop_file_path, desktop_file_content).map_err(|e| format!("could not write {}: {}", desktop_file_path.display(), e))
}

fn print_banner( base_url: &str ) {
    let build_date = include_str!(concat!(env!("OUT_DIR"), "/build_date.txt"));
    let banner = format!("SEASHELL Bootstrapper | {} | Build Date: {} | Version: {}", base_url, build_date, env!("CARGO_PKG_VERSION"));
    let terminal_width = term_size::dimensions().map(|(width, _)| width).unwrap_or(80);
    let padding = " ".repeat(terminal_width.saturating_sub(banner.len()) / 2);
    println!("\n{}{}\n", padding, banner.magenta().cyan().italic().on_black());
}

async fn fetch_latest_version( client: &Client, setup_url: &str ) -> LauncherResult<String> {
    let url = format!("https://{}/version", setup_url);
    let mut last_error = String::new();
    for attempt in 1..=3 {
        match http_get(client, &url).await {
            Ok(body) => {
                let version = body.trim().to_string();
                if is_valid_version(&version) {
                    return Ok(version);
                }
                return Err(format!("the setup server sent something that is not a client version ({} characters). Is {} reaching the Seashell website?", version.len(), setup_url));
            },
            Err(e) => {
                last_error = e;
                if attempt < 3 {
                    error(&format!("Could not fetch the latest client version (attempt {} of 3): {}", attempt, last_error));
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }
    Err(format!("could not fetch the latest client version: {}. Are you connected to the internet?", last_error))
}

// Windows PowerShell's Compress-Archive writes "\" separators, including on folder entries, and
// zip readers that only recognise "/" turn those folders into empty files. Accept both.
fn extract_zip( zip_path: &Path, target_directory: &Path ) -> LauncherResult<()> {
    let zip_file = std::fs::File::open(zip_path).map_err(|e| format!("could not open {}: {}", zip_path.display(), e))?;
    let mut archive = zip::ZipArchive::new(zip_file).map_err(|e| format!("the client download is not a valid zip: {}", e))?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|e| format!("could not read the client zip: {}", e))?;
        let name = entry.name().replace('\\', "/");
        let mut relative_path = PathBuf::new();
        for part in name.split('/') {
            match part {
                "" | "." => continue,
                ".." => return Err(format!("the client zip contains an unsafe path: {}", entry.name())),
                _ if part.contains(':') => return Err(format!("the client zip contains an unsafe path: {}", entry.name())),
                _ => relative_path.push(part),
            }
        }
        if relative_path.as_os_str().is_empty() {
            continue;
        }
        let output_path = target_directory.join(&relative_path);
        if name.ends_with('/') {
            create_folder_if_not_exists(&output_path)?;
            continue;
        }
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("could not create {}: {}", parent.display(), e))?;
        }
        let mut output_file = std::fs::File::create(&output_path).map_err(|e| format!("could not create {}: {}", output_path.display(), e))?;
        std::io::copy(&mut entry, &mut output_file).map_err(|e| format!("could not extract {}: {}", output_path.display(), e))?;
    }
    Ok(())
}

fn remove_other_versions( versions_directory: &Path, current_version_directory: &Path ) {
    let Ok(entries) = std::fs::read_dir(versions_directory) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path != current_version_directory {
            if let Err(e) = std::fs::remove_dir_all(&path) {
                info(&format!("Could not remove the old client folder {} ({}); it will be removed after the next update.", path.display(), e));
            }
        }
    }
}

async fn install_client(
    client: &Client,
    setup_url: &str,
    base_url: &str,
    version: &str,
    versions_directory: &Path,
    current_version_directory: &Path,
    latest_bootstrapper_path: &Path,
    temp_downloads_directory: &Path,
) -> LauncherResult<()> {
    info("Downloading the latest client files, this may take a while.");
    // Start from a clean folder, keeping only the launcher itself.
    let entries = std::fs::read_dir(current_version_directory).map_err(|e| format!("could not open {}: {}", current_version_directory.display(), e))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let result = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else if path != latest_bootstrapper_path {
            std::fs::remove_file(&path)
        } else {
            Ok(())
        };
        result.map_err(|e| format!("could not clean up {}: {}. Close Seashell if it is running and try again.", path.display(), e))?;
    }

    create_folder_if_not_exists(temp_downloads_directory)?;
    let zip_url = format!("https://{}/{}-2016client.zip", setup_url, version);
    let zip_path = download_file_prefix(client, &zip_url, temp_downloads_directory).await?;

    let client_directory = current_version_directory.join("Client2016");
    create_folder_if_not_exists(&client_directory)?;
    info(&format!("Extracting {} to {}", zip_path.display().to_string().bright_blue(), client_directory.display().to_string().bright_blue()));
    extract_zip(&zip_path, &client_directory)?;
    if !client_directory.join("RobloxPlayerBeta.exe").exists() {
        return Err("the downloaded client does not contain RobloxPlayerBeta.exe".to_string());
    }
    info("Finished extracting files, cleaning up.");
    let _ = std::fs::remove_dir_all(temp_downloads_directory);

    // AppSettings.xml marks the install as complete, so it is written last.
    let app_settings_xml = format!(
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<Settings>
	<ContentFolder>content</ContentFolder>
	<BaseUrl>https://{}</BaseUrl>
</Settings>", base_url
    );
    let app_settings_path = current_version_directory.join("AppSettings.xml");
    std::fs::write(&app_settings_path, app_settings_xml).map_err(|e| format!("could not write {}: {}", app_settings_path.display(), e))?;

    remove_other_versions(versions_directory, current_version_directory);
    Ok(())
}

// Field names used by the seashell-player/syntax-player launch URI, e.g.
// "1+launchmode:play+gameinfo:TICKET+placelauncherurl:https://.../placelauncher.ashx?placeId=660&t=TICKET+k:l+clientyear:2016".
const LAUNCH_URI_KNOWN_KEYS: [&str; 6] = ["launchmode", "gameinfo", "placelauncherurl", "browsertrackerid", "k", "clientyear"];

// Splits the argument portion of a launch URI (everything after the scheme) into key/value
// pairs. A naive `split('+')` corrupts any field whose value itself contains a literal '+'
// (which can happen in an authentication ticket, or in an un-encoded query string), because the
// whole string is joined with '+' between fields. Instead, a '+' is only treated as a field
// separator when it is immediately followed by one of the known field names and a ':' -- any
// other '+' is left alone as part of the current field's value. This can still misfire if a
// value happens to contain the literal text "+<knownkey>:", but that is far less likely than a
// value simply containing '+'.
fn parse_launch_arguments( raw: &str ) -> Vec<(String, String)> {
    let mut segment_starts: Vec<usize> = vec![0];
    for (index, character) in raw.char_indices() {
        if character != '+' {
            continue;
        }
        let after = &raw[index + 1..];
        let starts_known_field = LAUNCH_URI_KNOWN_KEYS.iter()
            .any(|key| after.starts_with(key) && after[key.len()..].starts_with(':'));
        if starts_known_field {
            segment_starts.push(index + 1);
        }
    }
    segment_starts.sort_unstable();
    segment_starts.dedup();

    let mut pairs = Vec::new();
    for (position, &start) in segment_starts.iter().enumerate() {
        // Each segment ends right before the '+' that starts the next segment (or at the end of
        // the string for the last segment).
        let end = segment_starts.get(position + 1).map(|next_start| next_start - 1).unwrap_or(raw.len());
        let segment = &raw[start..end];
        if segment.is_empty() {
            continue;
        }
        let (key, value) = segment.split_once(':').unwrap_or((segment, ""));
        pairs.push((key.to_string(), value.to_string()));
    }
    pairs
}

async fn run() -> LauncherResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let base_url : &str = option_env!("SEASHELL_DOMAIN").unwrap_or("www.seashell.rocks");
    let setup_url : &str = option_env!("SEASHELL_SETUP_HOST").unwrap_or("www.seashell.rocks/client-downloads");
    #[cfg(target_os = "windows")]
    let bootstrapper_filename = "SeashellPlayerLauncher.exe";
    #[cfg(not(target_os = "windows"))]
    let bootstrapper_filename = "SyntaxPlayerLinuxLauncher";
    print_banner(base_url);

    let http_client : Client = reqwest::Client::builder()
        .no_gzip()
        .build()
        .map_err(|e| format!("could not start the HTTP client: {}", e))?;
    debug(&format!("Setup Server: {} | Base Server: {}", setup_url.bright_blue(), base_url.bright_blue()));

    let latest_client_version = fetch_latest_version(&http_client, setup_url).await?;
    info(&format!("Latest Client Version: {}", latest_client_version.cyan().underline()));

    let installation_directory = get_installation_directory()?;
    let versions_directory = installation_directory.join("Versions");
    let temp_downloads_directory = installation_directory.join("Downloads");
    let current_version_directory = versions_directory.join(&latest_client_version);
    debug(&format!("Current Version Directory: {}", current_version_directory.display().to_string().bright_blue()));
    create_folder_if_not_exists(&current_version_directory)?;

    let latest_bootstrapper_path = current_version_directory.join(bootstrapper_filename);
    let latest_bootstrapper_url = format!("https://{}/{}-{}", setup_url, latest_client_version, bootstrapper_filename);
    let current_exe_path = std::env::current_exe().map_err(|e| format!("could not find the running launcher: {}", e))?;
    // Outside the current version folder, hand over to that version's launcher (downloading it if needed).
    if !current_exe_path.starts_with(&current_version_directory) {
        if !latest_bootstrapper_path.exists() {
            info("Downloading the latest bootstrapper");
            download_file_verified(&http_client, &latest_bootstrapper_url, &latest_bootstrapper_path).await?;
        }

        // Only hand over when the copy actually differs; antivirus software dislikes a
        // launcher that keeps re-running itself.
        let latest_bootstrapper_hash = get_sha1_hash_of_file(&latest_bootstrapper_path)?;
        let current_exe_hash = get_sha1_hash_of_file(&current_exe_path)?;
        debug(&format!("Latest Bootstrapper Hash: {}", latest_bootstrapper_hash.bright_blue()));
        debug(&format!("Current Bootstrapper Hash: {}", current_exe_hash.bright_blue()));

        if latest_bootstrapper_hash != current_exe_hash {
            info("Starting latest bootstrapper");
            #[cfg(target_os = "windows")]
            {
                if let Err(e) = std::process::Command::new(&latest_bootstrapper_path).args(&args[1..]).spawn() {
                    debug(&format!("Bootstrapper errored with error {}", e));
                    info("Found bootstrapper was corrupted! Downloading...");
                    download_file_verified(&http_client, &latest_bootstrapper_url, &latest_bootstrapper_path).await?;
                    std::process::Command::new(&latest_bootstrapper_path)
                        .args(&args[1..])
                        .spawn()
                        .map_err(|e| format!("could not start the updated launcher {}: {}", latest_bootstrapper_path.display(), e))?;
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                std::process::Command::new("chmod")
                    .arg("+x")
                    .arg(&latest_bootstrapper_path)
                    .status()
                    .map_err(|e| format!("could not make {} executable: {}", latest_bootstrapper_path.display(), e))?;
                install_desktop_entry(&latest_bootstrapper_path)?;
                info("Please launch Seashell from the website to continue with the update process.");
                std::thread::sleep(std::time::Duration::from_secs(20));
            }
            return Ok(());
        }
    }

    // AppSettings.xml is written after a complete install; without it the folder is new or damaged.
    let app_settings_path = current_version_directory.join("AppSettings.xml");
    if !app_settings_path.exists() {
        install_client(
            &http_client,
            setup_url,
            base_url,
            &latest_client_version,
            &versions_directory,
            &current_version_directory,
            &latest_bootstrapper_path,
            &temp_downloads_directory,
        ).await?;
        #[cfg(not(target_os = "windows"))]
        {
            install_desktop_entry(&latest_bootstrapper_path)?;
        }
    }

    // Repair the play-button protocol every run, even when client files already
    // exist (registry cleaners and copied profiles can remove it independently).
    #[cfg(target_os = "windows")]
    {
        info("Installing seashell-player scheme");
        if let Err(e) = install_player_protocol(&latest_bootstrapper_path) {
            error(&format!("Could not register the seashell-player protocol: {}", e));
        }
    }

    // Started without a Play link: the install is done, so just open the website.
    if args.len() == 1 {
        info("Seashell is installed. Opening the games page...");
        let games_url = format!("https://{}/games", base_url);
        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("cmd")
                .args(["/c", "start", "", games_url.as_str()])
                .spawn()
                .map_err(|e| format!("could not open {}: {}", games_url, e))?;
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::process::Command::new("xdg-open")
                .arg(&games_url)
                .spawn()
                .map_err(|e| format!("could not open {}: {}", games_url, e))?;
        }
        return Ok(());
    }

    // Looks like "seashell-player://1+launchmode:play+gameinfo:TICKET+placelauncherurl:https://www.seashell.rocks/Game/placelauncher.ashx?placeId=660&t=TICKET+k:l+clientyear:2016"
    debug(&format!("Arguments Passed: {}", args.join(" ").bright_blue()));
    let launch_arguments = args[1]
        .replace("seashell-player://", "")
        .replace("syntax-player://", "");

    let mut launch_mode = String::new();
    let mut authentication_ticket = String::new();
    let mut join_script = String::new();
    let mut client_year = String::new();
    for (key, value) in parse_launch_arguments(&launch_arguments) {
        debug(&format!("{}: {}", key.bright_blue(), value.bright_blue()));
        match key.as_str() {
            "launchmode" => launch_mode = value,
            "gameinfo" => authentication_ticket = value,
            "placelauncherurl" => join_script = value,
            "clientyear" => client_year = value,
            _ => {}
        }
    }
    debug(&format!("Client year: {}", client_year));

    let client_executable_path = current_version_directory.join("Client2016").join("RobloxPlayerBeta.exe");
    if !client_executable_path.exists() {
        // Removing the marker makes the next launch download the client again.
        let _ = std::fs::remove_file(&app_settings_path);
        return Err("RobloxPlayerBeta.exe is missing (antivirus software may have removed it). Press Play again to redownload the client.".to_string());
    }
    if launch_mode != "play" {
        return Err(format!("unknown launch mode '{}'", launch_mode));
    }
    if authentication_ticket.is_empty() || join_script.is_empty() {
        return Err("the Play link was incomplete. Press Play on the website again.".to_string());
    }

    info("Launching Seashell");
    let authentication_url = format!("https://{}/Login/Negotiate.ashx", base_url);
    let client_arguments = [
        "--play",
        "--authenticationUrl", authentication_url.as_str(),
        "--authenticationTicket", authentication_ticket.as_str(),
        "--joinScriptUrl", join_script.as_str(),
    ];
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new(&client_executable_path)
            .args(client_arguments)
            .spawn()
            .map_err(|e| format!("could not start {}: {}", client_executable_path.display(), e))?;
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    #[cfg(not(target_os = "windows"))]
    {
        // A specific wine binary can be chosen with installation_directory/winepath.txt
        let wine_path_file = installation_directory.join("winepath.txt");
        let wine = match std::fs::read_to_string(&wine_path_file) {
            Ok(path) if !path.trim().is_empty() => {
                info(&format!("Using custom wine binary: {}", path.trim().bright_blue()));
                path.trim().to_string()
            },
            _ => {
                info(&format!("Using the default wine command. To use another wine binary, put its path in {}", wine_path_file.display()));
                "wine".to_string()
            }
        };
        // We must wait for the game to exit before exiting the bootstrapper
        let mut child = std::process::Command::new(&wine)
            .arg(&client_executable_path)
            .args(client_arguments)
            .spawn()
            .map_err(|e| format!("could not start {} through {}: {}", client_executable_path.display(), wine, e))?;
        let _ = child.wait();
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    // The launcher usually runs in a console window opened by the browser, which closes as soon
    // as the process ends. Keep it open after a failure so the player can read what went wrong.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        println!("\nThe launcher crashed. Press Enter to close this window.");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }));

    // Clear the terminal before printing the startup text
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd").args(["/c", "cls"]).status();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::process::Command::new("clear").status();
    }

    if let Err(message) = run().await {
        error(&message);
        println!("\nPress Enter to close this window.");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_of<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
        pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn parses_a_typical_launch_uri() {
        let raw = "1+launchmode:play+gameinfo:TICKET123+placelauncherurl:https://www.seashell.rocks/Game/placelauncher.ashx?placeId=660&t=TICKET123+k:l+clientyear:2016";
        let pairs = parse_launch_arguments(raw);
        assert_eq!(value_of(&pairs, "launchmode"), Some("play"));
        assert_eq!(value_of(&pairs, "gameinfo"), Some("TICKET123"));
        assert_eq!(
            value_of(&pairs, "placelauncherurl"),
            Some("https://www.seashell.rocks/Game/placelauncher.ashx?placeId=660&t=TICKET123")
        );
        assert_eq!(value_of(&pairs, "k"), Some("l"));
        assert_eq!(value_of(&pairs, "clientyear"), Some("2016"));
    }

    #[test]
    fn preserves_literal_plus_characters_inside_field_values() {
        // A ticket or URL that legitimately contains a literal '+' (e.g. an un-encoded space in a
        // query string) must survive intact, since it isn't followed by a recognised "key:".
        let raw = "1+launchmode:play+gameinfo:TICKET+WITH+PLUS/chars==+placelauncherurl:https://www.seashell.rocks/Game/placelauncher.ashx?placeId=660&t=A+B&x=1+k:l+clientyear:2016";
        let pairs = parse_launch_arguments(raw);
        assert_eq!(value_of(&pairs, "gameinfo"), Some("TICKET+WITH+PLUS/chars=="));
        assert_eq!(
            value_of(&pairs, "placelauncherurl"),
            Some("https://www.seashell.rocks/Game/placelauncher.ashx?placeId=660&t=A+B&x=1")
        );
        assert_eq!(value_of(&pairs, "clientyear"), Some("2016"));
    }

    #[test]
    fn ignores_the_leading_non_keyed_segment_harmlessly() {
        // "seashell-player:1+..." has no "//" for `.replace(...)` to strip, so the leading "1"
        // (with no ':') remains as its own segment and must not clobber a real key.
        let raw = "1+launchmode:play+gameinfo:TICKET+placelauncherurl:https://example.com/x+k:l+clientyear:2016";
        let pairs = parse_launch_arguments(raw);
        assert_eq!(value_of(&pairs, "1"), Some(""));
        assert_eq!(value_of(&pairs, "launchmode"), Some("play"));
    }

    #[test]
    fn handles_a_missing_optional_field() {
        let raw = "1+launchmode:play+gameinfo:TICKET+placelauncherurl:https://example.com/x+clientyear:2016";
        let pairs = parse_launch_arguments(raw);
        assert_eq!(value_of(&pairs, "k"), None);
        assert_eq!(value_of(&pairs, "gameinfo"), Some("TICKET"));
    }
}
