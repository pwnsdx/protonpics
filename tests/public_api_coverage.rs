use std::fs;
use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use tempfile::TempDir;

use protonpics::accounts::{
    decrypt_session_bytes, encrypt_session_bytes, inspect_session_file, list_accounts,
};
use protonpics::backend::manifest::ManifestBackend;
use protonpics::backend::{self, PhotoSource};
use protonpics::cli::{
    Cli, Command, ExportCommand, ManifestSourceArgs, ProgressMode, SourceCommand, StateCommand,
};
use protonpics::export::{self, ExportOptions};
use protonpics::progress;
use protonpics::state::{StoredObject, SyncState};
use protonpics::types::{RemoteEntry, RemoteFile};

fn write_manifest(temp_dir: &TempDir, source_name: &str, source_bytes: &[u8]) -> Result<PathBuf> {
    let source = temp_dir.path().join(source_name);
    fs::write(&source, source_bytes)?;
    let manifest = temp_dir.path().join("manifest.json");
    fs::write(
        &manifest,
        format!(
            r#"{{
  "root_id": "root",
  "children": [
    {{
      "kind": "file",
      "id": "file-1",
      "name": "{source_name}",
      "revision_id": "rev-1",
      "size": {size},
      "modified_at_ns": 1700000000000000000,
      "source_path": "{}"
    }}
  ]
}}"#,
            source.display(),
            size = source_bytes.len(),
        ),
    )?;
    Ok(manifest)
}

#[test]
fn public_accounts_api_lists_and_decrypts_sessions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let accounts_dir = temp_dir.path().join("accounts");
    let alpha_dir = accounts_dir.join("alpha@example.com");
    let beta_dir = accounts_dir.join("beta@example.com");
    fs::create_dir_all(&alpha_dir)?;
    fs::create_dir_all(&beta_dir)?;
    fs::create_dir_all(accounts_dir.join("ignored-empty"))?;
    fs::write(accounts_dir.join("ignored-file"), b"skip")?;

    let alpha_path = alpha_dir.join("session.json");
    let beta_path = beta_dir.join("session.json");
    let ciphertext = encrypt_session_bytes("alpha@example.com", "secret", br#"{"UID":"alpha"}"#)?;
    fs::write(&alpha_path, &ciphertext)?;
    fs::write(&beta_path, br#"{"UID":"beta"}"#)?;

    let alpha_info = inspect_session_file(&alpha_path)?;
    let beta_info = inspect_session_file(&beta_path)?;
    assert_eq!(alpha_info.email.as_deref(), Some("alpha@example.com"));
    assert!(alpha_info.encrypted);
    assert_eq!(beta_info.email.as_deref(), Some("beta@example.com"));
    assert!(!beta_info.encrypted);

    let decrypted = decrypt_session_bytes(&alpha_path, &ciphertext, Some("secret"))?;
    assert_eq!(decrypted, br#"{"UID":"alpha"}"#);
    assert_eq!(
        decrypt_session_bytes(&beta_path, br#"{"UID":"beta"}"#, None)?,
        br#"{"UID":"beta"}"#
    );

    let listed = list_accounts(&accounts_dir)?;
    assert_eq!(
        listed
            .iter()
            .map(|account| account.email.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha@example.com", "beta@example.com"]
    );
    Ok(())
}

#[test]
fn public_manifest_backend_and_backend_open_read_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let manifest = write_manifest(&temp_dir, "photo.jpg", b"jpeg")?;

    let backend = ManifestBackend::from_path(&manifest)?;
    assert_eq!(backend.backend_name(), "manifest");
    assert_eq!(backend.root_id(), "root");
    assert_eq!(backend.list_children("root")?.len(), 1);
    let mut bytes = Vec::new();
    backend.open_file("file-1")?.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"jpeg");

    let opened = backend::open(
        &SourceCommand::Manifest(ManifestSourceArgs {
            manifest: manifest.clone(),
        }),
        progress::Mode::Quiet,
    )?;
    assert!(opened.default_state_db.is_none());
    assert_eq!(opened.source.backend_name(), "manifest");
    assert_eq!(opened.source.root_id(), "root");
    assert_eq!(opened.source.list_children("root")?.len(), 1);
    let mut opened_bytes = Vec::new();
    opened
        .source
        .open_file("file-1")?
        .read_to_end(&mut opened_bytes)?;
    assert_eq!(opened_bytes, b"jpeg");
    Ok(())
}

#[test]
fn public_run_execute_and_state_apis_work_end_to_end() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let manifest = write_manifest(&temp_dir, "photo.jpg", b"jpeg")?;
    let output_dir = temp_dir.path().join("out");
    let state_db = temp_dir.path().join("state.sqlite");

    protonpics::run(Cli {
        command: Command::Export(ExportCommand {
            to: output_dir.clone(),
            state_db: Some(state_db.clone()),
            dry_run: false,
            delete_missing: false,
            download_concurrency: 1,
            progress: ProgressMode::Off,
            source: SourceCommand::Manifest(ManifestSourceArgs {
                manifest: manifest.clone(),
            }),
        }),
    })?;
    assert_eq!(fs::read(output_dir.join("photo.jpg"))?, b"jpeg");

    protonpics::run(Cli {
        command: Command::State(StateCommand {
            state_db: state_db.clone(),
        }),
    })?;

    let state = SyncState::open_existing(&state_db)?;
    assert_eq!(state.summary()?.object_count, 1);

    let dry_state_db = temp_dir.path().join("dry.sqlite");
    let opened = backend::open(
        &SourceCommand::Manifest(ManifestSourceArgs { manifest }),
        progress::Mode::Quiet,
    )?;
    let dry_report = export::execute(
        opened.source.as_ref(),
        &ExportOptions {
            to_dir: temp_dir.path().join("dry-out"),
            state_db: dry_state_db,
            dry_run: true,
            delete_missing: false,
            download_concurrency: 1,
            progress_mode: progress::Mode::Quiet,
        },
    )?;
    assert_eq!(dry_report.would_download, 1);

    state.upsert_object(&StoredObject {
        path: "stale.jpg".to_owned(),
        remote_id: "stale".to_owned(),
        revision_id: "rev-stale".to_owned(),
        size: 1,
        modified_at_ns: 1,
        sha1: None,
    })?;
    assert_eq!(state.list_object_paths()?.len(), 2);

    let file = RemoteFile {
        revision_id: "rev-1".to_owned(),
        size: 4,
        modified_at_ns: 1,
        sha1: None,
    };
    let entry = RemoteEntry::file("file-2", "other.jpg", file);
    assert_eq!(entry.id, "file-2");
    Ok(())
}
