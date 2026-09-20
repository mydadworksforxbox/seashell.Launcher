use std::fs;
use std::env;
use winres::WindowsResource;
fn main() {
    // Get the current build date and time
    let build_date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // Write the build date to a file
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = format!("{}/build_date.txt", out_dir);
    fs::write(&dest_path, &build_date).unwrap();

    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // Add a version resource to the executable
        let mut res = WindowsResource::new();
        res.set_icon("assets/Bootstrapper.ico");
        res.set_language(0x0409); // US English
        res.set("FileVersion", env!("CARGO_PKG_VERSION"));
        res.set("FileDescription", "Seashell Windows Bootstrapper");
        res.set("ProductName", "Seashell Bootstrapper");
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        res.set("InternalName", "Seashell Bootstrapper");
        res.set("OriginalFilename", "SeashellPlayerLauncher.exe");
        res.set("CompanyName", "Seashell");
        res.set("LegalCopyright", "Copyright (c) 2023");
        res.compile().unwrap();
    }

    println!("cargo:rerun-if-changed=build.rs");
    // SEASHELL_DOMAIN/SEASHELL_SETUP_HOST are read via option_env! in main.rs, which bakes the
    // values in at compile time. Without these, changing the env vars and rebuilding would not
    // trigger a recompile, silently shipping a launcher pointed at a stale domain.
    println!("cargo:rerun-if-env-changed=SEASHELL_DOMAIN");
    println!("cargo:rerun-if-env-changed=SEASHELL_SETUP_HOST");
}
