//! Exact-build, process-local trust-domain substitution for the 2020 player.
//! We never alter the archived Roblox executable on disk, and we refuse any
//! binary other than the one independently obtained for RCC 0.450.0.411923.

use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_READWRITE};

const CLIENT_SHA256: &str = "abc03fdf88ebe30e5e9c66af81f62ae6d00609a2c74c73e604d1c81cacf35817";
const DOMAIN_OFFSET: usize = 0x199644C;
const ORIGINAL_DOMAIN: &[u8; 15] = b"robloxlabs.com\0";
const SEASHELL_DOMAIN: &[u8; 15] = b"seashell.rocks\0";
// The exact-build signature-2 public-key std::string, not executable code.
const JOIN_KEY_OBJECT_OFFSET: usize = 0x1F56FA0;
const ORIGINAL_JOIN_KEY: &str = concat!(
    "-----BEGIN PUBLIC KEY-----\n",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsI9zRp2OSccqdFx2+S57\n",
    "OcugCo/c9g8a3kwrBtYovqVKoHMDMoDd0u9Mc5CIyRqyu0IGS99A0jeEXRj7aofQ\n",
    "0oyuA2vPgYlhgtIfaRB/gkhPGZKl8y6RXadfJMffKMAgK/DhufyEeFO7U33Tv7vk\n",
    "Jba5qWkYU5nARYZm1gQVP/93zHV+T0QAWNcgRdAzOKj8pi5wAlnsdoumgAtB1J7d\n",
    "oBd+5R50Ozs8xYCf2Q05p4gHyX++C4bSNk9EO+VogpHgQ70F57MdFiBApyJwNSBk\n",
    "UZ4US0Rc+jz/zcweyBL17qL9koPpyChCHbWVgSXbfxynzBupojeOEiuqDuGX0BFl\n",
    "jQIDAQAB\n-----END PUBLIC KEY-----\n"
);
const SEASHELL_JOIN_SPKI: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwD2eQYDjx98HwbYShknIUmLFTFgsxl/2i4vZvi9Z8ncu/hSbZRDlXqYXP7vyFwzU4PqZtU2EYFJMMgthVE8hmWtJZHINbHVUSevKhfwbHZ54Q7W3j8NsosgjJk/4pc3Otwx1LXqhDu3MDGqwBZskyE0BqkTlDb8OOQHYjoxCO1APqDwfnf9LS4NSdDWfyabDpGQfUiMgD7ftlWAbkbGr5Qz4vdx35HGUrNmPDKy75hHB6FFqOKXv+AXtxWe0dOqL3TRS7TQ93kNG88JetUknxYcCBQdMLYoN9eiYeUiwmtXeuxQyMqkqKhwQI/o1tdYmYPng95Nm47ooZHWLDQ71eQIDAQAB";

fn seashell_join_key() -> Vec<u8> {
    let mut key = b"-----BEGIN PUBLIC KEY-----\n".to_vec();
    for line in SEASHELL_JOIN_SPKI.as_bytes().chunks(64) {
        key.extend_from_slice(line);
        key.push(b'\n');
    }
    key.extend_from_slice(b"-----END PUBLIC KEY-----\n");
    key
}

struct Snapshot(HANDLE);
impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0); }
    }
}

fn verified_client(path: &Path) -> Result<(), String> {
    let mut file = File::open(path).map_err(|e| format!("could not open the 2020 client: {e}"))?;
    let mut hasher = Sha256::new();
    let mut block = [0u8; 65536];
    loop {
        let size = file.read(&mut block).map_err(|e| format!("could not hash the 2020 client: {e}"))?;
        if size == 0 { break; }
        hasher.update(&block[..size]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != CLIENT_SHA256 {
        return Err("the 2020 client is not the verified 0.450.0.411923 binary; launch refused".into());
    }
    Ok(())
}

fn executable_base(pid: u32) -> Option<usize> {
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if raw == INVALID_HANDLE_VALUE { return None; }
    let snapshot = Snapshot(raw);
    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut found = unsafe { Module32FirstW(snapshot.0, &mut entry) } != 0;
    while found {
        let end = entry.szModule.iter().position(|value| *value == 0).unwrap_or(entry.szModule.len());
        if String::from_utf16_lossy(&entry.szModule[..end]).eq_ignore_ascii_case("RobloxPlayerBeta.exe") {
            return Some(entry.modBaseAddr as usize);
        }
        found = unsafe { Module32NextW(snapshot.0, &mut entry) } != 0;
    }
    None
}

fn try_patch(handle: HANDLE, base: usize) -> Result<bool, String> {
    if !patch_verified_bytes(handle, base + DOMAIN_OFFSET, ORIGINAL_DOMAIN, SEASHELL_DOMAIN)? {
        return Ok(false);
    }
    let mut object = [0u8; 24];
    let mut count = 0;
    if unsafe { ReadProcessMemory(handle, (base + JOIN_KEY_OBJECT_OFFSET) as *const c_void, object.as_mut_ptr().cast(), object.len(), &mut count) } == 0 || count != object.len() {
        return Ok(false);
    }
    let pointer = u32::from_le_bytes(object[0..4].try_into().unwrap()) as usize;
    let length = u32::from_le_bytes(object[16..20].try_into().unwrap()) as usize;
    let capacity = u32::from_le_bytes(object[20..24].try_into().unwrap()) as usize;
    if length != ORIGINAL_JOIN_KEY.len() || capacity < length || capacity > 4096 || pointer < 65536 {
        return Ok(false);
    }
    patch_verified_bytes(handle, pointer, ORIGINAL_JOIN_KEY.as_bytes(), &seashell_join_key())
}

fn patch_verified_bytes(handle: HANDLE, address: usize, original: &[u8], replacement: &[u8]) -> Result<bool, String> {
    if original.len() != replacement.len() { return Err("Client compatibility data length mismatch".into()); }
    let target = address as *const c_void;
    let mut observed = vec![0u8; original.len()];
    let mut count = 0usize;
    let read_ok = unsafe {
        ReadProcessMemory(handle, target, observed.as_mut_ptr().cast(), observed.len(), &mut count)
    } != 0;
    if !read_ok || count != observed.len() {
        return Ok(false);
    }
    if observed == replacement { return Ok(true); }
    if observed != original { return Ok(false); }
    let mut old_protection = 0u32;
    if unsafe { VirtualProtectEx(handle, target, observed.len(), PAGE_READWRITE, &mut old_protection) } == 0 {
        return Err(format!("could not protect 2020 client domain slot: {}", std::io::Error::last_os_error()));
    }
    let mut written = 0usize;
    let wrote = unsafe {
        WriteProcessMemory(handle, target, replacement.as_ptr().cast(), replacement.len(), &mut written)
    } != 0;
    let mut unused = 0u32;
    let restored = unsafe { VirtualProtectEx(handle, target, observed.len(), old_protection, &mut unused) } != 0;
    if !wrote || written != replacement.len() || !restored {
        return Err("could not safely write and restore the 2020 client domain slot".into());
    }
    count = 0;
    let readback = unsafe {
        ReadProcessMemory(handle, target, observed.as_mut_ptr().cast(), observed.len(), &mut count)
    } != 0;
    if !readback || count != observed.len() || observed != replacement {
        return Err("2020 client domain substitution failed its readback check".into());
    }
    Ok(true)
}

pub fn spawn_verified_2020(executable: &Path, arguments: &[&str]) -> Result<Child, String> {
    verified_client(executable)?;
    let working_directory = executable.parent().ok_or("2020 client path has no directory")?;
    if !working_directory.join("AppSettings.xml").is_file() {
        return Err("2020 client is missing AppSettings.xml beside RobloxPlayerBeta.exe".into());
    }
    let mut child = Command::new(executable)
        .args(arguments)
        .current_dir(working_directory)
        .spawn()
        .map_err(|e| format!("could not start the verified 2020 client: {e}"))?;
    let handle = child.as_raw_handle() as HANDLE;
    let deadline = Instant::now() + Duration::from_secs(15);
    let result = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break Err(format!("2020 client exited before its trust-domain patch: {status}"));
        }
        if let Some(base) = executable_base(child.id()) {
            match try_patch(handle, base) {
                Ok(true) => break Ok(()),
                Ok(false) => (),
                Err(message) => break Err(message),
            }
        }
        if Instant::now() >= deadline {
            break Err("verified 2020 client never exposed its expected domain slot".into());
        }
        thread::sleep(Duration::from_millis(1));
    };
    if let Err(message) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(message);
    }
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_build_hash_is_pinned() {
        assert_eq!(CLIENT_SHA256.len(), 64);
        assert_eq!(ORIGINAL_DOMAIN.len(), SEASHELL_DOMAIN.len());
        assert_eq!(DOMAIN_OFFSET, 0x199644C);
        assert_eq!(ORIGINAL_JOIN_KEY.len(), 451);
        assert_eq!(seashell_join_key().len(), ORIGINAL_JOIN_KEY.len());
    }
}
