use std::fs;
use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;
use tempfile::TempDir;

use protonpics::accounts::{
    decrypt_session_bytes, default_account_path, inspect_session_file, list_accounts,
};
use protonpics::backend::manifest::ManifestBackend;
use protonpics::cli::{
    Cli, Command, ExportCommand, ManifestSourceArgs, ProgressMode, SourceCommand, StateCommand,
};
use protonpics::export::{self, ExportOptions};
use protonpics::progress;
use protonpics::state::SyncState;
use protonpics::types::{RemoteEntry, RemoteFile};

fn write_manifest(
    temp_dir: &TempDir,
    source_name: &str,
    source_bytes: &[u8],
) -> Result<std::path::PathBuf> {
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

#[derive(Default)]
struct SingleFileSource;

impl protonpics::backend::PhotoSource for SingleFileSource {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    fn root_id(&self) -> &str {
        "root"
    }

    fn list_children(&self, folder_id: &str) -> Result<Vec<RemoteEntry>> {
        if folder_id == "root" {
            Ok(vec![RemoteEntry::file(
                "file-1",
                "photo.jpg",
                RemoteFile {
                    revision_id: "rev-1".to_owned(),
                    size: 4,
                    modified_at_ns: 1,
                    sha1: None,
                },
            )])
        } else {
            Ok(Vec::new())
        }
    }

    fn open_file(&self, _file_id: &str) -> Result<Box<dyn std::io::Read + Send>> {
        Ok(Box::new(std::io::Cursor::new(b"jpeg".to_vec())))
    }
}

#[test]
fn public_accounts_api_covers_default_path_and_fallbacks() -> Result<()> {
    let missing_dir = TempDir::new()?.path().join("missing");
    assert!(list_accounts(&missing_dir)?.is_empty());

    let default_path = default_account_path("user@example.com")?;
    assert!(default_path.ends_with(Path::new("user@example.com").join("session.json")));

    let temp_dir = TempDir::new()?;
    let plain_path = temp_dir.path().join("alias.json");
    fs::write(&plain_path, br#"{"UID":"plain"}"#)?;
    let plain_info = inspect_session_file(&plain_path)?;
    assert_eq!(plain_info.email.as_deref(), Some("alias"));
    assert!(!plain_info.encrypted);

    assert_eq!(
        decrypt_session_bytes(&plain_path, br#"{"UID":"plain"}"#, None)?,
        br#"{"UID":"plain"}"#
    );
    Ok(())
}

#[test]
fn public_state_api_covers_missing_and_schema_mismatch_paths() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let missing = temp_dir.path().join("missing.sqlite");
    let error = SyncState::open_existing(&missing)
        .err()
        .expect("missing db should fail");
    assert!(error.to_string().contains("state DB not found"));

    let mismatch = temp_dir.path().join("mismatch.sqlite");
    let connection = Connection::open(&mismatch)?;
    connection.execute_batch(
        r#"
        CREATE TABLE sync_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            schema_version INTEGER NOT NULL,
            backend_name TEXT,
            root_id TEXT,
            updated_unix INTEGER
        );
        CREATE TABLE objects (
            path TEXT PRIMARY KEY,
            remote_id TEXT NOT NULL,
            revision_id TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL DEFAULT 0,
            modified_at_ns INTEGER NOT NULL DEFAULT 0,
            sha1 TEXT,
            downloaded_unix INTEGER
        );
        INSERT INTO sync_state (id, schema_version, updated_unix) VALUES (1, 99, 0);
        "#,
    )?;
    let error = SyncState::open_existing(&mismatch)
        .err()
        .expect("schema mismatch should fail");
    assert!(error.to_string().contains("schema_version"));
    Ok(())
}

#[test]
fn public_run_covers_missing_state_db_errors() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let manifest = write_manifest(&temp_dir, "photo.jpg", b"jpeg")?;

    let export_error = protonpics::run(Cli {
        command: Command::Export(ExportCommand {
            to: temp_dir.path().join("out"),
            state_db: None,
            dry_run: false,
            delete_missing: false,
            download_concurrency: 1,
            progress: ProgressMode::Off,
            source: SourceCommand::Manifest(ManifestSourceArgs {
                manifest: manifest.clone(),
            }),
        }),
    })
    .expect_err("manifest export should require an explicit state db");
    assert!(
        export_error
            .to_string()
            .contains("`--state-db` is required")
    );

    let state_error = protonpics::run(Cli {
        command: Command::State(StateCommand {
            state_db: temp_dir.path().join("still-missing.sqlite"),
        }),
    })
    .expect_err("missing state db should fail");
    assert!(state_error.to_string().contains("state DB not found"));
    Ok(())
}

#[test]
fn public_manifest_and_export_errors_are_reported() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let missing = temp_dir.path().join("missing.json");
    let read_error = ManifestBackend::from_path(&missing).expect_err("missing manifest");
    assert!(read_error.to_string().contains("read"));

    let bad_manifest = temp_dir.path().join("bad.json");
    fs::write(&bad_manifest, "{not-json")?;
    let parse_error = ManifestBackend::from_path(&bad_manifest).expect_err("bad manifest");
    assert!(parse_error.to_string().contains("parse"));

    let output_file = temp_dir.path().join("out");
    fs::write(&output_file, b"not a directory")?;
    let execute_error = export::execute(
        &SingleFileSource,
        &ExportOptions {
            to_dir: output_file,
            state_db: temp_dir.path().join("state.sqlite"),
            dry_run: false,
            delete_missing: false,
            download_concurrency: 1,
            progress_mode: progress::Mode::Quiet,
        },
    )
    .expect_err("output path file should fail");
    assert!(
        execute_error
            .to_string()
            .contains("create export directory")
    );
    Ok(())
}
