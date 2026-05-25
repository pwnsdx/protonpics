use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::backend::PhotoSource;
use crate::types::{RemoteEntry, RemoteFile};

#[derive(Debug)]
pub struct ManifestBackend {
    root_id: String,
    folders: HashMap<String, Vec<RemoteEntry>>,
    files: HashMap<String, PathBuf>,
}

#[derive(Debug, Deserialize)]
struct ManifestDocument {
    root_id: String,
    children: Vec<ManifestNode>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ManifestNode {
    Folder {
        id: String,
        name: String,
        children: Vec<ManifestNode>,
    },
    File {
        id: String,
        name: String,
        revision_id: String,
        size: i64,
        modified_at_ns: i64,
        sha1: Option<String>,
        source_path: PathBuf,
    },
}

impl ManifestBackend {
    pub fn from_path(path: &Path) -> Result<Self> {
        let manifest_text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let document: ManifestDocument = serde_json::from_str(&manifest_text)
            .with_context(|| format!("parse {}", path.display()))?;

        let manifest_dir = path
            .parent()
            .ok_or_else(|| anyhow!("manifest has no parent directory: {}", path.display()))?;

        let mut folders = HashMap::new();
        let mut files = HashMap::new();
        index_children(
            &document.root_id,
            document.children,
            manifest_dir,
            &mut folders,
            &mut files,
        )?;

        Ok(Self {
            root_id: document.root_id,
            folders,
            files,
        })
    }
}

impl PhotoSource for ManifestBackend {
    fn backend_name(&self) -> &'static str {
        "manifest"
    }

    fn root_id(&self) -> &str {
        &self.root_id
    }

    fn list_children(&self, folder_id: &str) -> Result<Vec<RemoteEntry>> {
        self.folders
            .get(folder_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder id {folder_id}"))
    }

    fn open_file(&self, file_id: &str) -> Result<Box<dyn Read + Send>> {
        let path = self
            .files
            .get(file_id)
            .ok_or_else(|| anyhow!("unknown file id {file_id}"))?;
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        Ok(Box::new(file))
    }
}

fn index_children(
    parent_id: &str,
    children: Vec<ManifestNode>,
    manifest_dir: &Path,
    folders: &mut HashMap<String, Vec<RemoteEntry>>,
    files: &mut HashMap<String, PathBuf>,
) -> Result<()> {
    let mut entries = Vec::new();

    for child in children {
        match child {
            ManifestNode::Folder { id, name, children } => {
                if folders.contains_key(&id) {
                    bail!("duplicate folder id {id}");
                }
                entries.push(RemoteEntry::folder(id.clone(), name));
                index_children(&id, children, manifest_dir, folders, files)?;
            }
            ManifestNode::File {
                id,
                name,
                revision_id,
                size,
                modified_at_ns,
                sha1,
                source_path,
            } => {
                if size < 0 {
                    bail!("file {id} has negative size");
                }
                let resolved_path = if source_path.is_absolute() {
                    source_path
                } else {
                    manifest_dir.join(source_path)
                };
                let metadata = std::fs::metadata(&resolved_path)
                    .with_context(|| format!("read metadata for {}", resolved_path.display()))?;
                let disk_size =
                    i64::try_from(metadata.len()).context("manifest source file size overflow")?;
                if disk_size != size {
                    bail!(
                        "manifest file {id} size mismatch: metadata says {size}, disk says {disk_size}"
                    );
                }
                if files.insert(id.clone(), resolved_path).is_some() {
                    bail!("duplicate file id {id}");
                }
                entries.push(RemoteEntry::file(
                    id,
                    name,
                    RemoteFile {
                        revision_id,
                        size,
                        modified_at_ns,
                        sha1,
                    },
                ));
            }
        }
    }

    folders.insert(parent_id.to_owned(), entries);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use tempfile::TempDir;

    use super::ManifestBackend;
    use crate::backend::PhotoSource;

    fn write_manifest(temp_dir: &TempDir, body: &str) -> Result<std::path::PathBuf> {
        let manifest = temp_dir.path().join("manifest.json");
        fs::write(&manifest, body)?;
        Ok(manifest)
    }

    #[test]
    fn manifest_backend_reads_relative_sources() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = temp_dir.path().join("photo.jpg");
        fs::write(&source, b"jpeg")?;
        const MANIFEST_JSON: &str = r#"{
  "root_id": "root",
  "children": [
    {
      "kind": "file",
      "id": "file-1",
      "name": "photo.jpg",
      "revision_id": "rev-1",
      "size": 4,
      "modified_at_ns": 1,
      "source_path": "photo.jpg"
    }
  ]
}"#;
        let manifest = write_manifest(&temp_dir, MANIFEST_JSON)?;

        let backend = ManifestBackend::from_path(&manifest)?;
        assert_eq!(backend.backend_name(), "manifest");
        assert_eq!(backend.root_id(), "root");
        assert_eq!(backend.list_children("root")?.len(), 1);
        let mut reader = backend.open_file("file-1")?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"jpeg");
        Ok(())
    }

    #[test]
    fn list_children_errors_for_unknown_folder() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = temp_dir.path().join("photo.jpg");
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
        let manifest = write_manifest(&temp_dir, &manifest_json)?;

        let backend = ManifestBackend::from_path(&manifest)?;
        let error = backend
            .list_children("missing-folder")
            .expect_err("unknown folder should fail");
        assert!(error.to_string().contains("unknown folder id"));
        Ok(())
    }

    #[test]
    fn open_file_errors_for_unknown_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = temp_dir.path().join("photo.jpg");
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
        let manifest = write_manifest(&temp_dir, &manifest_json)?;

        let backend = ManifestBackend::from_path(&manifest)?;
        let error = backend
            .open_file("missing-file")
            .err()
            .expect("unknown file should fail");
        assert!(error.to_string().contains("unknown file id"));
        Ok(())
    }

    #[test]
    fn manifest_backend_rejects_duplicate_folder_ids() -> Result<()> {
        let temp_dir = TempDir::new()?;
        const MANIFEST_JSON: &str = r#"{
  "root_id": "root",
  "children": [
    {
      "kind": "folder",
      "id": "folder-1",
      "name": "A",
      "children": []
    },
    {
      "kind": "folder",
      "id": "folder-1",
      "name": "B",
      "children": []
    }
  ]
}"#;
        let manifest = write_manifest(&temp_dir, MANIFEST_JSON)?;

        let error = ManifestBackend::from_path(&manifest).expect_err("duplicate folder");
        assert!(error.to_string().contains("duplicate folder id"));
        Ok(())
    }

    #[test]
    fn manifest_backend_rejects_duplicate_file_ids() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let first = temp_dir.path().join("a.jpg");
        let second = temp_dir.path().join("b.jpg");
        fs::write(&first, b"aaaa")?;
        fs::write(&second, b"bbbb")?;
        let manifest_json = format!(
            r#"{{
  "root_id": "root",
  "children": [
    {{
      "kind": "file",
      "id": "file-1",
      "name": "a.jpg",
      "revision_id": "rev-1",
      "size": 4,
      "modified_at_ns": 1,
      "source_path": "{}"
    }},
    {{
      "kind": "file",
      "id": "file-1",
      "name": "b.jpg",
      "revision_id": "rev-2",
      "size": 4,
      "modified_at_ns": 2,
      "source_path": "{}"
    }}
  ]
}}"#,
            first.display(),
            second.display(),
        );
        let manifest = write_manifest(&temp_dir, &manifest_json)?;

        let error = ManifestBackend::from_path(&manifest).expect_err("duplicate file");
        assert!(error.to_string().contains("duplicate file id"));
        Ok(())
    }

    #[test]
    fn manifest_backend_rejects_negative_sizes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = temp_dir.path().join("photo.jpg");
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
      "size": -1,
      "modified_at_ns": 1,
      "source_path": "{}"
    }}
  ]
}}"#,
            source.display(),
        );
        let manifest = write_manifest(&temp_dir, &manifest_json)?;

        let error = ManifestBackend::from_path(&manifest).expect_err("negative size");
        assert!(error.to_string().contains("negative size"));
        Ok(())
    }

    #[test]
    fn manifest_backend_rejects_size_mismatch() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = temp_dir.path().join("photo.jpg");
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
      "size": 99,
      "modified_at_ns": 1,
      "source_path": "{}"
    }}
  ]
}}"#,
            source.display(),
        );
        let manifest = write_manifest(&temp_dir, &manifest_json)?;

        let error = ManifestBackend::from_path(&manifest).expect_err("size mismatch");
        assert!(error.to_string().contains("size mismatch"));
        Ok(())
    }
}
