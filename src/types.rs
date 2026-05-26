use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub id: String,
    pub name: String,
    pub kind: EntryKind,
    pub file: Option<RemoteFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    Folder,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteFile {
    pub revision_id: String,
    pub size: i64,
    /// Server-side last-modified time. For Proton, this is the upload time.
    /// Kept for backward compatibility and as a fallback when the original
    /// metadata cannot be decrypted.
    pub modified_at_ns: i64,
    pub sha1: Option<String>,
    /// Original file modification time, taken from the Proton XAttr blob
    /// (`Common.ModificationTime`). Reflects the user's local mtime at the
    /// moment of upload, which is what we want to restore on disk.
    #[serde(default)]
    pub original_modified_at_ns: Option<i64>,
    /// Original capture time when the file is a photo or a video, taken
    /// from the Proton XAttr blob (`Camera.CaptureTime`). Used to set the
    /// macOS birthtime when available.
    #[serde(default)]
    pub capture_time_ns: Option<i64>,
}

impl RemoteEntry {
    pub fn folder(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            kind: EntryKind::Folder,
            file: None,
        }
    }

    pub fn file(id: impl Into<String>, name: impl Into<String>, file: RemoteFile) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            kind: EntryKind::File,
            file: Some(file),
        }
    }
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Folder => f.write_str("folder"),
            Self::File => f.write_str("file"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EntryKind, RemoteEntry, RemoteFile};

    #[test]
    fn folder_constructor_sets_folder_fields() {
        let entry = RemoteEntry::folder("folder-1", "Trips");
        assert_eq!(entry.id, "folder-1");
        assert_eq!(entry.name, "Trips");
        assert_eq!(entry.kind, EntryKind::Folder);
        assert_eq!(entry.file, None);
    }

    #[test]
    fn file_constructor_sets_file_fields() {
        let entry = RemoteEntry::file(
            "file-1",
            "photo.jpg",
            RemoteFile {
                revision_id: "rev-1".to_owned(),
                size: 42,
                modified_at_ns: 99,
                sha1: Some("abc".to_owned()),
                original_modified_at_ns: None,
                capture_time_ns: None,
            },
        );
        assert_eq!(entry.id, "file-1");
        assert_eq!(entry.name, "photo.jpg");
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(
            entry.file,
            Some(RemoteFile {
                revision_id: "rev-1".to_owned(),
                size: 42,
                modified_at_ns: 99,
                sha1: Some("abc".to_owned()),
                original_modified_at_ns: None,
                capture_time_ns: None,
            })
        );
    }

    #[test]
    fn entry_kind_display_uses_wire_labels() {
        assert_eq!(EntryKind::Folder.to_string(), "folder");
        assert_eq!(EntryKind::File.to_string(), "file");
    }
}
