use std::fs;

use anyhow::Result;
use protonpics::backend::manifest::ManifestBackend;
use protonpics::export::{ExportOptions, execute};
use protonpics::progress;
use protonpics::state::SyncState;
use tempfile::TempDir;

#[test]
fn export_manifest_downloads_skips_and_deletes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let source_dir = temp_dir.path().join("source");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&source_dir)?;

    let first_source = source_dir.join("beach-a.jpg");
    let second_source = source_dir.join("beach-b.jpg");
    fs::write(&first_source, b"aaa")?;
    fs::write(&second_source, b"bbbb")?;

    let manifest_path = temp_dir.path().join("photos.json");
    fs::write(
        &manifest_path,
        format!(
            r#"{{
  "root_id": "photos-root",
  "children": [
    {{
      "kind": "folder",
      "id": "folder-2026",
      "name": "2026",
      "children": [
        {{
          "kind": "file",
          "id": "photo-a",
          "name": "beach.jpg",
          "revision_id": "rev-a",
          "size": 3,
          "modified_at_ns": 1767225600000000000,
          "source_path": "{}"
        }},
        {{
          "kind": "file",
          "id": "photo-b",
          "name": "beach.jpg",
          "revision_id": "rev-b",
          "size": 4,
          "modified_at_ns": 1767225601000000000,
          "source_path": "{}"
        }}
      ]
    }}
  ]
}}"#,
            protonpics::paths::path_to_json_string(&first_source),
            protonpics::paths::path_to_json_string(&second_source),
        ),
    )?;

    let backend = ManifestBackend::from_path(&manifest_path)?;
    let state_db = output_dir.join("state.sqlite");
    let options = ExportOptions {
        to_dir: output_dir.clone(),
        state_db: state_db.clone(),
        dry_run: false,
        delete_missing: false,
        download_concurrency: 1,
        progress_mode: progress::Mode::Quiet,
    };

    let report = execute(&backend, &options)?;
    assert_eq!(report.downloaded, 2);
    assert!(output_dir.join("2026/beach.jpg").exists());
    assert!(output_dir.join("2026/beach_photo-b.jpg").exists());
    assert_eq!(fs::read(output_dir.join("2026/beach.jpg"))?, b"aaa");
    assert_eq!(
        fs::read(output_dir.join("2026/beach_photo-b.jpg"))?,
        b"bbbb"
    );

    let second_report = execute(&backend, &options)?;
    assert_eq!(second_report.downloaded, 0);
    assert_eq!(second_report.skipped, 2);

    fs::write(
        &manifest_path,
        format!(
            r#"{{
  "root_id": "photos-root",
  "children": [
    {{
      "kind": "folder",
      "id": "folder-2026",
      "name": "2026",
      "children": [
        {{
          "kind": "file",
          "id": "photo-a",
          "name": "beach.jpg",
          "revision_id": "rev-a",
          "size": 3,
          "modified_at_ns": 1767225600000000000,
          "source_path": "{}"
        }}
      ]
    }}
  ]
}}"#,
            protonpics::paths::path_to_json_string(&first_source),
        ),
    )?;

    let backend = ManifestBackend::from_path(&manifest_path)?;
    let delete_report = execute(
        &backend,
        &ExportOptions {
            delete_missing: true,
            ..options
        },
    )?;
    assert_eq!(delete_report.deleted, 1);
    assert!(!output_dir.join("2026/beach_photo-b.jpg").exists());

    let state = SyncState::open_existing(&state_db)?;
    let summary = state.summary()?;
    assert_eq!(summary.object_count, 1);

    Ok(())
}
