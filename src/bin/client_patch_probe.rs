#[path = "../client_patch.rs"]
mod client_patch;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), String> {
    let executable = std::env::args().nth(1).map(PathBuf::from).ok_or("expected verified test client path")?;
    let arguments = [
        "--play",
        "--authenticationUrl", "https://seashell.rocks/Login/Negotiate.ashx",
        "--authenticationTicket", "TEST_ONLY",
        "--joinScriptUrl", "https://seashell.rocks/Game/PlaceLauncher.ashx?request=RequestGame&placeId=685",
    ];
    let mut child = client_patch::spawn_verified_2020(&executable, &arguments)?;
    println!("RUST_PATCHED pid={}", child.id());
    thread::sleep(Duration::from_secs(8));
    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
        println!("CLIENT_EXITED {status}");
    } else {
        child.kill().map_err(|e| e.to_string())?;
        child.wait().map_err(|e| e.to_string())?;
        println!("DIAGNOSTIC_CLIENT_STOPPED");
    }
    Ok(())
}
