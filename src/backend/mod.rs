pub mod manifest;
pub mod proton;

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;

use crate::cli::SourceCommand;
use crate::progress;
use crate::types::RemoteEntry;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    /// Test-only override that asks `open` to load the manifest backend in
    /// lazy mode (no source-file validation). Tests use this to observe
    /// per-file failures during the export phase rather than at manifest
    /// construction time.
    static TEST_MANIFEST_LAZY: RefCell<bool> = const { RefCell::new(false) };
}

#[cfg(test)]
pub(crate) fn with_test_lazy_manifest<T>(f: impl FnOnce() -> T) -> T {
    let previous = TEST_MANIFEST_LAZY.with(|value| value.replace(true));
    let result = f();
    TEST_MANIFEST_LAZY.with(|value| {
        value.replace(previous);
    });
    result
}

#[cfg(test)]
fn open_manifest(args: &crate::cli::ManifestSourceArgs) -> Result<manifest::ManifestBackend> {
    if TEST_MANIFEST_LAZY.with(|value| *value.borrow()) {
        manifest::ManifestBackend::from_path_lazy(&args.manifest)
    } else {
        manifest::ManifestBackend::from_path(&args.manifest)
    }
}

#[cfg(not(test))]
fn open_manifest(args: &crate::cli::ManifestSourceArgs) -> Result<manifest::ManifestBackend> {
    manifest::ManifestBackend::from_path(&args.manifest)
}

pub trait PhotoSource: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn root_id(&self) -> &str;
    fn list_children(&self, folder_id: &str) -> Result<Vec<RemoteEntry>>;
    fn open_file(&self, file_id: &str) -> Result<Box<dyn Read + Send>>;
}

pub struct OpenedSource {
    pub source: Box<dyn PhotoSource>,
    pub default_state_db: Option<PathBuf>,
}

pub fn open(spec: &SourceCommand, progress_mode: progress::Mode) -> Result<OpenedSource> {
    match spec {
        SourceCommand::Manifest(args) => Ok(OpenedSource {
            source: Box::new(open_manifest(args)?),
            default_state_db: None,
        }),
        SourceCommand::Proton(args) => proton::from_args(args, progress_mode),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use tempfile::TempDir;

    use super::open;
    use crate::cli::{ManifestSourceArgs, ProtonSourceArgs, SourceCommand, TreeCacheMode};
    use crate::progress::Mode;

    #[test]
    fn open_manifest_backend() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = temp_dir.path().join("photo.jpg");
        let manifest = temp_dir.path().join("manifest.json");
        fs::write(&source, b"jpeg")?;
        let manifest_json = format!(
            r#"{{
  "root_id": "root",
  "children": [
    {{
      "kind": "file",
      "id": "file-1",
      "name": "photo.jpg",
      "revision_id": "rev-1",
      "size": 4,
      "modified_at_ns": 1,
      "source_path": "{}"
    }}
  ]
}}"#,
            crate::paths::path_to_json_string(&source),
        );
        fs::write(&manifest, manifest_json)?;

        let command = SourceCommand::Manifest(ManifestSourceArgs {
            manifest: manifest.clone(),
        });
        let opened = open(&command, Mode::Quiet)?;
        assert_eq!(opened.source.backend_name(), "manifest");
        assert_eq!(opened.source.root_id(), "root");
        assert!(opened.default_state_db.is_none());
        Ok(())
    }

    #[test]
    fn open_proton_backend_propagates_credentials_errors() {
        let temp_dir = TempDir::new().expect("tempdir");
        let credentials = temp_dir.path().join("missing.json");
        let error = open(
            &SourceCommand::Proton(ProtonSourceArgs {
                credentials: Some(credentials.clone()),
                account_password: None,
                share_name: "PhotosRoot".to_owned(),
                share_id: None,
                app_version: None,
                user_agent: None,
                scan_concurrency: 4,
                tree_cache: TreeCacheMode::Refresh,
                no_input: true,
            }),
            Mode::Quiet,
        )
        .err()
        .expect("missing credentials should fail");

        assert!(
            error
                .to_string()
                .contains(&credentials.display().to_string())
        );
    }

    #[test]
    fn with_test_lazy_manifest_routes_through_lazy_backend() -> Result<()> {
        let temp_dir = TempDir::new()?;
        // Manifest points at a missing source. Eager open() fails, lazy
        // open() succeeds.
        let manifest = temp_dir.path().join("manifest.json");
        let manifest_json = r#"{
  "root_id": "root",
  "children": [
    {
      "kind": "file",
      "id": "file-1",
      "name": "photo.jpg",
      "revision_id": "rev-1",
      "size": 999,
      "modified_at_ns": 1,
      "source_path": "/nonexistent/source.jpg"
    }
  ]
}"#;
        fs::write(&manifest, manifest_json)?;
        let command = SourceCommand::Manifest(ManifestSourceArgs {
            manifest: manifest.clone(),
        });

        // Default eager mode: must error on construction.
        let eager_error = match open(&command, Mode::Quiet) {
            Ok(_) => panic!("eager mode should fail when source is missing"),
            Err(error) => error,
        };
        assert!(eager_error.to_string().contains("read metadata"));

        // Inside the lazy override: same call must succeed.
        let opened = super::with_test_lazy_manifest(|| open(&command, Mode::Quiet))?;
        assert_eq!(opened.source.backend_name(), "manifest");
        assert_eq!(opened.source.root_id(), "root");

        // Verify the override is restored to its prior state on exit.
        let after_error = match open(&command, Mode::Quiet) {
            Ok(_) => panic!("eager mode must be restored after the override exits"),
            Err(error) => error,
        };
        assert!(after_error.to_string().contains("read metadata"));
        Ok(())
    }
}
