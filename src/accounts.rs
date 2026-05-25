use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use argon2::Argon2;
use base64::Engine;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::paths;

const SESSION_ENVELOPE_VERSION: u32 = 1;
const SESSION_KEY_BYTES: usize = 32;
const SESSION_SALT_BYTES: usize = 16;
const SESSION_NONCE_BYTES: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAccount {
    pub email: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFileInfo {
    pub email: Option<String>,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedSessionEnvelope {
    version: u32,
    email: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub fn default_account_path(email: &str) -> Result<PathBuf> {
    Ok(paths::default_account_dir(email)?.join(paths::account_file_name(email)))
}

pub fn list_accounts(dir: &Path) -> Result<Vec<StoredAccount>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut accounts = Vec::new();
    for entry in
        fs::read_dir(dir).with_context(|| format!("read account directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("read account entry in {}", dir.display()))?;
        let path = entry.path();
        let path = if path.is_dir() {
            let candidate = path.join(paths::account_file_name(""));
            if candidate.is_file() {
                candidate
            } else {
                continue;
            }
        } else {
            continue;
        };

        let fallback_email =
            inferred_email_from_path(&path).unwrap_or_else(|| path.display().to_string());
        let email = fs::read(&path)
            .ok()
            .and_then(|bytes| inspect_session_bytes(&path, &bytes))
            .and_then(|info| info.email)
            .unwrap_or(fallback_email);
        accounts.push(StoredAccount { email, path });
    }

    accounts.sort_by(|left, right| {
        left.email
            .to_lowercase()
            .cmp(&right.email.to_lowercase())
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(accounts)
}

pub fn inspect_session_file(path: &Path) -> Result<SessionFileInfo> {
    let bytes = fs::read(path).with_context(|| format!("read session file {}", path.display()))?;
    Ok(
        inspect_session_bytes(path, &bytes).unwrap_or(SessionFileInfo {
            email: inferred_email_from_path(path),
            encrypted: false,
        }),
    )
}

pub fn inspect_session_bytes(path: &Path, bytes: &[u8]) -> Option<SessionFileInfo> {
    match serde_json::from_slice::<EncryptedSessionEnvelope>(bytes) {
        Ok(envelope) if envelope.version == SESSION_ENVELOPE_VERSION => Some(SessionFileInfo {
            email: Some(envelope.email),
            encrypted: true,
        }),
        _ => inferred_email_from_path(path).map(|email| SessionFileInfo {
            email: Some(email),
            encrypted: false,
        }),
    }
}

pub fn encrypt_session_bytes(email: &str, password: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SESSION_SALT_BYTES];
    let mut nonce = [0u8; SESSION_NONCE_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_session_key(password, &salt)?;
    let cipher = Aes256GcmSiv::new_from_slice(&key).context("initialize session cipher")?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: email.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("encrypt saved Proton session"))?;

    serde_json::to_vec(&EncryptedSessionEnvelope {
        version: SESSION_ENVELOPE_VERSION,
        email: email.to_owned(),
        salt: base64::engine::general_purpose::STANDARD.encode(salt),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    })
    .context("serialize encrypted session envelope")
}

pub fn decrypt_session_bytes(path: &Path, bytes: &[u8], password: Option<&str>) -> Result<Vec<u8>> {
    let envelope = match serde_json::from_slice::<EncryptedSessionEnvelope>(bytes) {
        Ok(envelope) if envelope.version == SESSION_ENVELOPE_VERSION => envelope,
        _ => return Ok(bytes.to_vec()),
    };

    let password = password.ok_or_else(|| {
        anyhow!(
            "encrypted Proton session {} requires the account password",
            path.display()
        )
    })?;
    let salt = decode_component(path, "salt", &envelope.salt)?;
    let nonce = decode_component(path, "nonce", &envelope.nonce)?;
    let ciphertext = decode_component(path, "ciphertext", &envelope.ciphertext)?;
    if nonce.len() != SESSION_NONCE_BYTES {
        bail!(
            "encrypted Proton session {} uses nonce length {} instead of {}",
            path.display(),
            nonce.len(),
            SESSION_NONCE_BYTES
        );
    }

    let key = derive_session_key(password, &salt)?;
    let cipher = Aes256GcmSiv::new_from_slice(&key).context("initialize session cipher")?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad: envelope.email.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("decrypt encrypted Proton session {}", path.display()))
}

fn derive_session_key(password: &str, salt: &[u8]) -> Result<[u8; SESSION_KEY_BYTES]> {
    let mut key = [0u8; SESSION_KEY_BYTES];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .context("derive saved-session key")?;
    Ok(key)
}

fn decode_component(path: &Path, field: &str, value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .with_context(|| format!("decode encrypted session {field} for {}", path.display()))
}

fn inferred_email_from_path(path: &Path) -> Option<String> {
    let is_session_json = path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("session.json"));
    if is_session_json {
        return path
            .parent()
            .and_then(|value| value.file_name())
            .and_then(|value| value.to_str())
            .map(str::to_owned);
    }
    path.file_stem()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use anyhow::Result;
    use base64::Engine;
    use tempfile::TempDir;

    use super::{
        EncryptedSessionEnvelope, SESSION_ENVELOPE_VERSION, SESSION_SALT_BYTES, StoredAccount,
        decrypt_session_bytes, default_account_path, encrypt_session_bytes, inspect_session_bytes,
        inspect_session_file, list_accounts,
    };

    #[test]
    fn encrypted_session_round_trip() -> Result<()> {
        let path = Path::new("/tmp/user@example.com.json");
        const PLAINTEXT: &[u8] = br#"{"AccessToken":"abc"}"#;
        let ciphertext = encrypt_session_bytes(
            "user@example.com",
            "correct horse battery staple",
            PLAINTEXT,
        )?;
        let plaintext =
            decrypt_session_bytes(path, &ciphertext, Some("correct horse battery staple"))?;
        assert_eq!(plaintext, PLAINTEXT);
        Ok(())
    }

    #[test]
    fn decrypt_requires_password_for_encrypted_sessions() -> Result<()> {
        let path = Path::new("/tmp/user@example.com.json");
        let ciphertext = encrypt_session_bytes("user@example.com", "secret", b"{}")?;
        let error = decrypt_session_bytes(path, &ciphertext, None)
            .expect_err("password should be required");
        assert!(error.to_string().contains("requires the account password"));
        Ok(())
    }

    #[test]
    fn inspect_and_list_accounts_prefer_email_metadata() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let alpha = temp_dir
            .path()
            .join("zeta@example.com")
            .join("session.json");
        let beta = temp_dir
            .path()
            .join("alpha@example.com")
            .join("session.json");
        fs::create_dir_all(alpha.parent().expect("alpha parent"))?;
        fs::create_dir_all(beta.parent().expect("beta parent"))?;
        let alpha_session = encrypt_session_bytes("zeta@example.com", "secret", b"{}")?;
        let beta_session = encrypt_session_bytes("alpha@example.com", "secret", b"{}")?;
        fs::write(&alpha, alpha_session)?;
        fs::write(&beta, beta_session)?;

        let info = inspect_session_file(&alpha)?;
        assert_eq!(info.email.as_deref(), Some("zeta@example.com"));
        assert!(info.encrypted);

        let listed = list_accounts(temp_dir.path())?;
        assert_eq!(
            listed,
            vec![
                StoredAccount {
                    email: "alpha@example.com".to_owned(),
                    path: beta,
                },
                StoredAccount {
                    email: "zeta@example.com".to_owned(),
                    path: alpha,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn inspect_session_bytes_falls_back_to_file_stem_for_plain_json() {
        let path = Path::new("/tmp/plain@example.com/session.json");
        let info = inspect_session_bytes(path, br#"{"UID":"u"}"#).expect("info");
        assert_eq!(info.email.as_deref(), Some("plain@example.com"));
        assert!(!info.encrypted);
    }

    #[test]
    fn inspect_session_bytes_marks_encrypted_envelopes() -> Result<()> {
        let path = Path::new("/tmp/secure@example.com/session.json");
        let ciphertext = encrypt_session_bytes("secure@example.com", "secret", b"{}")?;
        let info = inspect_session_bytes(path, &ciphertext).expect("info");
        assert_eq!(info.email.as_deref(), Some("secure@example.com"));
        assert!(info.encrypted);
        Ok(())
    }

    #[test]
    fn inspect_session_file_falls_back_to_parent_directory_for_plain_json() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir
            .path()
            .join("plain@example.com")
            .join("session.json");
        fs::create_dir_all(path.parent().expect("parent"))?;
        fs::write(&path, br#"{"UID":"plain"}"#)?;

        let info = inspect_session_file(&path)?;
        assert_eq!(info.email.as_deref(), Some("plain@example.com"));
        assert!(!info.encrypted);
        Ok(())
    }

    #[test]
    fn inspect_session_file_falls_back_for_invalid_session_bytes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir
            .path()
            .join("broken@example.com")
            .join("session.json");
        fs::create_dir_all(path.parent().expect("parent"))?;
        fs::write(&path, b"not json")?;

        let info = inspect_session_file(&path)?;
        assert_eq!(info.email.as_deref(), Some("broken@example.com"));
        assert!(!info.encrypted);
        Ok(())
    }

    #[test]
    fn decrypt_session_bytes_passes_through_plain_json() -> Result<()> {
        let path = Path::new("/tmp/plain@example.com/session.json");
        let plaintext = br#"{"AccessToken":"abc"}"#;
        assert_eq!(decrypt_session_bytes(path, plaintext, None)?, plaintext);
        Ok(())
    }

    #[test]
    fn decrypt_session_bytes_rejects_wrong_password() -> Result<()> {
        let path = Path::new("/tmp/user@example.com.json");
        let ciphertext = encrypt_session_bytes("user@example.com", "secret", b"{}")?;
        let error = decrypt_session_bytes(path, &ciphertext, Some("wrong"))
            .expect_err("wrong password should fail");
        assert!(
            error
                .to_string()
                .contains("decrypt encrypted Proton session")
        );
        Ok(())
    }

    #[test]
    fn decrypt_session_bytes_rejects_invalid_nonce_length() {
        let path = Path::new("/tmp/user@example.com.json");
        let envelope = EncryptedSessionEnvelope {
            version: SESSION_ENVELOPE_VERSION,
            email: "user@example.com".to_owned(),
            salt: base64::engine::general_purpose::STANDARD.encode([0u8; SESSION_SALT_BYTES]),
            nonce: base64::engine::general_purpose::STANDARD.encode([0u8; 4]),
            ciphertext: base64::engine::general_purpose::STANDARD.encode([0u8; 16]),
        };
        let bytes = serde_json::to_vec(&envelope).expect("serialize");
        let error = decrypt_session_bytes(path, &bytes, Some("secret"))
            .expect_err("invalid nonce length should fail");
        assert!(error.to_string().contains("nonce length"));
    }

    #[test]
    fn list_accounts_returns_empty_for_missing_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let listed = list_accounts(&temp_dir.path().join("missing"))?;
        assert!(listed.is_empty());
        Ok(())
    }

    #[test]
    fn list_accounts_ignores_entries_without_session_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        fs::create_dir_all(temp_dir.path().join("missing@example.com"))?;
        fs::write(temp_dir.path().join("README.txt"), b"ignore me")?;

        let session_path = temp_dir
            .path()
            .join("user@example.com")
            .join("session.json");
        fs::create_dir_all(session_path.parent().expect("parent"))?;
        fs::write(&session_path, br#"{"UID":"plain"}"#)?;

        let listed = list_accounts(temp_dir.path())?;
        assert_eq!(
            listed,
            vec![StoredAccount {
                email: "user@example.com".to_owned(),
                path: session_path,
            }]
        );
        Ok(())
    }

    #[test]
    fn list_accounts_falls_back_to_directory_name_for_invalid_session_bytes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let session_path = temp_dir
            .path()
            .join("fallback@example.com")
            .join("session.json");
        fs::create_dir_all(session_path.parent().expect("parent"))?;
        fs::write(&session_path, b"broken json")?;

        let listed = list_accounts(temp_dir.path())?;
        assert_eq!(
            listed,
            vec![StoredAccount {
                email: "fallback@example.com".to_owned(),
                path: session_path,
            }]
        );
        Ok(())
    }

    #[test]
    fn default_account_path_uses_email_file_name() -> Result<()> {
        let path = default_account_path("user@example.com")?;
        assert_eq!(
            path.parent()
                .and_then(|value| value.file_name())
                .and_then(|value| value.to_str()),
            Some("user@example.com")
        );
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("session.json")
        );
        Ok(())
    }
}
