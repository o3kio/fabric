//! WireGuard key hygiene.
//!
//! One keypair per host per fabric domain. The private key:
//!
//! - is generated with `wg genkey` if absent, stored 0600 via atomic
//!   create (temp file + rename) under the provider state root;
//! - is adopted as-is when a valid key already exists (so control-plane
//!   records of the public key stay valid) and is **never** overwritten;
//! - is only ever referenced by file path in commands (`wg set <if>
//!   private-key <path>`) or piped via stdin (`wg pubkey`), never placed in
//!   argv;
//! - intentionally survives fabric teardown.

use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use fabric_plan::PublicKey;

use crate::error::FabricError;
use crate::runner::FabricCommand;

/// Private-key file mode: owner read/write only.
const PRIVATE_KEY_MODE: u32 = 0o600;

/// Ensure a host-local WireGuard private key exists. Returns its path.
pub fn ensure_private_key(
    key_path: &Path,
    runner: &mut impl FabricCommand,
) -> Result<PathBuf, FabricError> {
    if key_path.exists() {
        let existing = fs::read_to_string(key_path)?;
        if existing.trim().is_empty() {
            return Err(FabricError::Invalid(format!(
                "existing private key {} is empty; refusing to overwrite foreign state",
                key_path.display()
            )));
        }
        return Ok(key_path.to_path_buf());
    }

    let output = runner.run("wg", &["genkey"])?;
    if !output.success {
        return Err(FabricError::Command(
            "wg genkey failed to generate a host key".to_string(),
        ));
    }
    let key = output.stdout.trim();
    if key.is_empty() {
        return Err(FabricError::Command(
            "wg genkey produced an empty key".to_string(),
        ));
    }
    atomic_write_private(key_path, key)?;
    Ok(key_path.to_path_buf())
}

/// Derive the public key for private key material.
///
/// The private key is passed via stdin only. The returned public key is safe
/// to distribute through authenticated control-plane state.
pub fn derive_public_key(
    runner: &mut impl FabricCommand,
    private_key: &str,
) -> Result<PublicKey, FabricError> {
    let output = runner.run_with_stdin("wg", &["pubkey"], private_key)?;
    if !output.success {
        return Err(FabricError::Command(
            "wg pubkey failed to derive the public key".to_string(),
        ));
    }
    PublicKey::new(output.stdout.trim())
        .map_err(|e| FabricError::Invalid(format!("derived public key is invalid: {e}")))
}

/// Atomic private write: temp file, fsync, chmod 0600, rename.
fn atomic_write_private(path: &Path, contents: &str) -> Result<(), FabricError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    fs::set_permissions(&tmp, Permissions::from_mode(PRIVATE_KEY_MODE))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    #[test]
    fn generates_key_once_and_adopts_existing() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("adopt-key")?;
        let key_path = root.join("wireguard-private.key");

        let mut runner = RecordingRunner::new();
        let path = ensure_private_key(&key_path, &mut runner)?;
        assert!(path.exists());
        let first = fs::read_to_string(&key_path)?;
        assert_eq!(first.trim(), "fabric-test-private-key-material");
        assert!(
            runner
                .calls()
                .iter()
                .any(|c| c.program == "wg" && c.args.first().map(String::as_str) == Some("genkey"))
        );

        // A fresh runner over the same key path adopts the existing key and
        // never runs genkey again.
        let mut second = RecordingRunner::new();
        let _again = ensure_private_key(&key_path, &mut second)?;
        assert!(
            !second
                .calls()
                .iter()
                .any(|c| c.program == "wg" && c.args.first().map(String::as_str) == Some("genkey"))
        );

        // Permissions are 0600.
        let mode = fs::metadata(&key_path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        cleanup(&root);
        Ok(())
    }

    #[test]
    fn public_key_derivation_uses_stdin_not_argv() -> Result<(), Box<dyn std::error::Error>> {
        let mut runner = RecordingRunner::new();
        let public = derive_public_key(&mut runner, "secret-private-material")?;
        assert!(!public.as_str().is_empty());
        let call = runner
            .calls()
            .iter()
            .find(|c| c.program == "wg" && c.args.first().map(String::as_str) == Some("pubkey"))
            .cloned()
            .ok_or_else(|| FabricError::Invalid("expected a wg pubkey call".to_string()))?;
        assert!(!call.joined().contains("secret-private-material"));
        assert_eq!(call.stdin.as_deref(), Some("secret-private-material"));
        Ok(())
    }

    // Small helpers so tests avoid unwrap/expect.
    fn test_root(tag: &str) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!(
            "fabric-keys-{tag}-{}-{}",
            std::process::id(),
            nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    fn cleanup(root: &Path) {
        let _unused = fs::remove_dir_all(root);
    }
}
