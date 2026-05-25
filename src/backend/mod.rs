pub mod manifest;
pub mod proton;

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;

use crate::cli::SourceCommand;
use crate::progress;
use crate::types::RemoteEntry;

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
            source: Box::new(manifest::ManifestBackend::from_path(&args.manifest)?),
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
            source.display(),
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
}
