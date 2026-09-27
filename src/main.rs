use colored::*;
use futures_util::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

mod client_manifest;
#[cfg(target_os = "windows")]
mod client_patch;
mod launcher_update;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::Shell::ShellExecuteW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

#[cfg(target_os = "windows")]
fn open_games_page(url: &str) -> LauncherResult<()> {
    use std::os::windows::ffi::OsStrExt;
    let wide_url: Vec<u16> = std::ffi::OsStr::new(url).encode_wide().chain(Some(0)).collect();
    let open: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
    let result = unsafe {
        ShellExecuteW(0, open.as_ptr(), wide_url.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL)
    };
    if result as isize <= 32 {
        return Err(format!("could not open {} (Windows ShellExecute error {})", url, result as isize));
    }
    Ok(())
}

type LauncherResult<T> = Result<T, String>;
const MAX_CLIENT_ZIP_BYTES: u64 = 2_000_000_000;
const MAX_EXTRACTED_BYTES: u64 = 4_000_000_000;

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

async fn download_file( client: &Client, url: &str, path: &Path ) -> LauncherResult<()> {
    debug(&format!("{} {}", "GET".green(), url.bright_blue()));
    let response = client.get(url).send().await.map_err(|e| format!("could not reach {}: {}", url, e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("downloading {} failed with HTTP {}", url, status));
    }
    let expected_length = response.content_length();
    if expected_length.is_some_and(|length| length > MAX_CLIENT_ZIP_BYTES) {
        return Err(format!("{} is larger than the client download limit", url));
    }
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
        if downloaded > MAX_CLIENT_ZIP_BYTES {
            drop(writer);
            let _ = std::fs::remove_file(&partial_path);
            return Err(format!("{} exceeded the client download limit", url));
        }
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

fn create_folder_if_not_exists( path: &Path ) -> LauncherResult<()> {
    if !path.exists() {
        info(&format!("Creating folder {}", path.display().to_string().bright_blue()));
        std::fs::create_dir_all(path).map_err(|e| format!("could not create {}: {}", path.display(), e))?;
    }
    Ok(())
}

fn get_sha256_hash_of_file( path: &Path ) -> LauncherResult<String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("could not open {}: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| format!("could not read {}: {}", path.display(), e))?;
    Ok(format!("{:x}", hasher.finalize()))
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

// Windows PowerShell's Compress-Archive writes "\" separators, including on folder entries, and
// zip readers that only recognise "/" turn those folders into empty files. Accept both.
fn extract_zip( zip_path: &Path, target_directory: &Path ) -> LauncherResult<()> {
    let zip_file = std::fs::File::open(zip_path).map_err(|e| format!("could not open {}: {}", zip_path.display(), e))?;
    let mut archive = zip::ZipArchive::new(zip_file).map_err(|e| format!("the client download is not a valid zip: {}", e))?;
    let mut extracted_bytes = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|e| format!("could not read the client zip: {}", e))?;
        extracted_bytes = extracted_bytes.checked_add(entry.size())
            .ok_or_else(|| "the client zip is too large".to_string())?;
        if extracted_bytes > MAX_EXTRACTED_BYTES {
            return Err("the client zip exceeds the extraction size limit".to_string());
        }
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

// Field names used by the seashell-player/syntax-player launch URI, e.g.
// "1+launchmode:play+gameinfo:TICKET+placelauncherurl:https://.../placelauncher.ashx?placeId=660&t=TICKET+k:l+clientyear:2016".
const LAUNCH_URI_KNOWN_KEYS: [&str; 7] = ["launchmode", "gameinfo", "placelauncherurl", "browsertrackerid", "k", "clientyear", "clientversion"];

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

struct LaunchRequest {
    client_version: String,
    authentication_ticket: String,
    join_script: String,
}

fn version_from_legacy_year(year: &str) -> Option<&'static str> {
    match year {
        "2016" => Some("2016"),
        "2017" => Some("2017L"),
        "2018" => Some("2018L"),
        "2020" => Some("2020L"),
        "2021" => Some("2021M"),
        _ => None,
    }
}

fn parse_launch_request(uri: &str, base_url: &str) -> LauncherResult<LaunchRequest> {
    let payload = ["seashell-player://", "seashell-player:", "syntax-player://", "syntax-player:"]
        .iter()
        .find_map(|prefix| uri.strip_prefix(prefix))
        .ok_or_else(|| "this is not a Seashell Play link".to_string())?;
    let mut launch_mode = String::new();
    let mut authentication_ticket = String::new();
    let mut join_script = String::new();
    let mut client_version = String::new();
    let mut client_year = String::new();
    for (key, value) in parse_launch_arguments(payload) {
        match key.as_str() {
            "launchmode" => launch_mode = value,
            "gameinfo" => authentication_ticket = value,
            "placelauncherurl" => join_script = value,
            "clientversion" => client_version = value,
            "clientyear" => client_year = value,
            _ => {}
        }
    }
    if launch_mode != "play" {
        return Err(format!("unknown launch mode '{}'", launch_mode));
    }
    if client_version.is_empty() {
        client_version = version_from_legacy_year(&client_year)
            .ok_or_else(|| "the Play link did not specify a supported client version".to_string())?
            .to_string();
    }
    if !is_valid_version(&client_version) {
        return Err("the Play link contains an invalid client version".to_string());
    }
    if authentication_ticket.is_empty() || join_script.is_empty() {
        return Err("the Play link was incomplete. Press Play on the website again.".to_string());
    }
    let url = reqwest::Url::parse(&join_script)
        .map_err(|_| "the Play link has an invalid join URL".to_string())?;
    let expected_domain = base_url.trim_start_matches("www.");
    let host = url.host_str().unwrap_or("").trim_start_matches("www.");
    if url.scheme() != "https" || host != expected_domain || !url.path().eq_ignore_ascii_case("/Game/PlaceLauncher.ashx") {
        return Err("the Play link points outside Seashell's game join endpoint".to_string());
    }
    Ok(LaunchRequest { client_version, authentication_ticket, join_script })
}

async fn run() -> LauncherResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let base_url : &str = option_env!("SEASHELL_DOMAIN").unwrap_or("seashell.rocks");
    let manifest_url: &str = option_env!("SEASHELL_CLIENT_MANIFEST_URL")
        .unwrap_or("https://seashell.rocks/client-downloads/manifest-v2.json");
    #[cfg(target_os = "windows")]
    let bootstrapper_filename = format!("SeashellPlayerLauncher-{}.exe", env!("CARGO_PKG_VERSION"));
    #[cfg(not(target_os = "windows"))]
    let bootstrapper_filename = format!("SeashellPlayerLauncher-{}", env!("CARGO_PKG_VERSION"));
    print_banner(base_url);

    let http_client : Client = reqwest::Client::builder()
        .no_gzip()
        // Every signed manifest URL names the exact first-party artifact. A redirect
        // could silently fetch bytes from a different host, so require direct HTTPS.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("could not start the HTTP client: {}", e))?;
    let installation_directory = get_installation_directory()?;
    let launcher_directory = installation_directory.join("Launcher");
    create_folder_if_not_exists(&launcher_directory)?;
    let installed_launcher_path = launcher_directory.join(bootstrapper_filename);
    let current_exe_path = std::env::current_exe().map_err(|e| format!("could not find the running launcher: {}", e))?;
    if current_exe_path != installed_launcher_path && !installed_launcher_path.exists() {
        std::fs::copy(&current_exe_path, &installed_launcher_path)
            .map_err(|e| format!("could not install the launcher at {}: {}", installed_launcher_path.display(), e))?;
    }

    // Check the same HTTPS manifest used for client packages on each launch. The update is
    // downloaded to a new versioned path and verified before it gets control or registration.
    let manifest = match client_manifest::fetch_manifest(&http_client, manifest_url).await {
        Ok(manifest) => Some(manifest),
        Err(message) if args.len() == 1 => {
            error(&format!("Could not check for updates: {}", message));
            None
        }
        Err(message) => return Err(message),
    };
    if let Some(manifest) = manifest.as_ref() {
        if launcher_update::maybe_update(
            &http_client, manifest.launcher.as_ref(), &launcher_directory, &args,
        ).await? {
            return Ok(());
        }
    }

    // Register a stable, versioned copy; never point the browser at a temporary download path.
    #[cfg(target_os = "windows")]
    {
        info("Installing seashell-player scheme");
        if let Err(e) = install_player_protocol(&installed_launcher_path) {
            error(&format!("Could not register the seashell-player protocol: {}", e));
        }
    }
    #[cfg(not(target_os = "windows"))]
    install_desktop_entry(&installed_launcher_path)?;

    // Opening the launcher directly only registers the protocol and opens Seashell.
    if args.len() == 1 {
        info("Seashell is installed. Opening the games page...");
        let games_url = format!("https://{}/games", base_url);
        #[cfg(target_os = "windows")]
        {
            open_games_page(&games_url)?;
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

    let launch = parse_launch_request(&args[1], base_url)?;
    info(&format!("Selected {} client", launch.client_version));
    let manifest = manifest.ok_or_else(|| "could not load the client manifest".to_string())?;
    let package = manifest.package(&launch.client_version)?;
    let client_executable_path = client_manifest::install_package(
        &http_client,
        package,
        &launch.client_version,
        &installation_directory.join("Clients"),
        &installation_directory.join("Downloads"),
        base_url,
    ).await?;

    info("Launching Seashell");
    let authentication_url = format!("https://{}/Login/Negotiate.ashx", base_url);
    let client_arguments = [
        "--play",
        "--authenticationUrl", authentication_url.as_str(),
        "--authenticationTicket", launch.authentication_ticket.as_str(),
        "--joinScriptUrl", launch.join_script.as_str(),
    ];
    #[cfg(target_os = "windows")]
    {
        if launch.client_version == "2020L" {
            client_patch::spawn_verified_2020(&client_executable_path, &client_arguments)?;
        } else {
            let working_directory = client_executable_path.parent()
                .ok_or_else(|| "client executable has no parent directory".to_string())?;
            std::process::Command::new(&client_executable_path)
                .args(client_arguments)
                .current_dir(working_directory)
                .spawn()
                .map_err(|e| format!("could not start {}: {}", client_executable_path.display(), e))?;
        }
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

    #[test]
    fn accepts_live_multi_version_play_links() {
        for version in ["2017L", "2018L", "2020L", "2021M"] {
            let uri = format!("seashell-player:1+launchmode:play+clientversion:{}+gameinfo:TICKET+placelauncherurl:https://seashell.rocks/Game/PlaceLauncher.ashx?request=RequestGame&placeId=660&isTeleport=true+k:l+client", version);
            let launch = parse_launch_request(&uri, "www.seashell.rocks").unwrap();
            assert_eq!(launch.client_version, version);
            assert_eq!(launch.authentication_ticket, "TICKET");
        }
    }

    #[test]
    fn maps_older_clientyear_links() {
        let uri = "seashell-player://1+launchmode:play+gameinfo:TICKET+placelauncherurl:https://www.seashell.rocks/Game/PlaceLauncher.ashx?placeId=660+clientyear:2018";
        assert_eq!(parse_launch_request(uri, "seashell.rocks").unwrap().client_version, "2018L");
    }

    #[test]
    fn rejects_join_urls_outside_seashell() {
        let uri = "seashell-player:1+launchmode:play+clientversion:2017L+gameinfo:TICKET+placelauncherurl:https://evil.example/Game/PlaceLauncher.ashx?placeId=660";
        assert!(parse_launch_request(uri, "seashell.rocks").is_err());
    }
}
