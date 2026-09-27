use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let seed_path = PathBuf::from(args.next().ok_or("expected private seed path")?);
    let manifest_arg = args.next().ok_or("expected manifest path or --public-key")?;
    if args.next().is_some() { return Err("too many arguments".into()); }
    let seed: [u8; 32] = fs::read(&seed_path)
        .map_err(|e| format!("could not read private seed: {e}"))?
        .try_into()
        .map_err(|_| "private seed must be exactly 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public = signing_key.verifying_key().to_bytes();
    let public_hex: String = public.iter().map(|byte| format!("{byte:02x}")).collect();
    if manifest_arg == "--public-key" {
        println!("PUBLIC_KEY={public_hex}");
        return Ok(());
    }
    let manifest_path = PathBuf::from(manifest_arg);
    let manifest = fs::read(&manifest_path).map_err(|e| format!("could not read manifest: {e}"))?;
    let signature = signing_key.sign(&manifest);
    let signature_path = PathBuf::from(format!("{}.sig", manifest_path.display()));
    if signature_path.exists() { return Err("signature already exists; refusing overwrite".into()); }
    fs::write(&signature_path, signature.to_bytes()).map_err(|e| format!("could not write signature: {e}"))?;
    println!("PUBLIC_KEY={public_hex}");
    println!("SIGNATURE_WRITTEN={}", signature_path.display());
    Ok(())
}
