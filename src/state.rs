use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA_VERSION: i64 = 2;
const INIT_SQL: &str = r#"
            CREATE TABLE IF NOT EXISTS sync_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version INTEGER NOT NULL,
                backend_name TEXT,
                root_id TEXT,
                updated_unix INTEGER
            );

            CREATE TABLE IF NOT EXISTS objects (
                path TEXT PRIMARY KEY,
                remote_id TEXT NOT NULL,
                revision_id TEXT NOT NULL DEFAULT '',
                size INTEGER NOT NULL DEFAULT 0,
                modified_at_ns INTEGER NOT NULL DEFAULT 0,
                sha1 TEXT,
                downloaded_unix INTEGER,
                original_modified_at_ns INTEGER,
                capture_time_ns INTEGER
            );
            "#;
const INSERT_STATE_SQL: &str =
    "INSERT INTO sync_state (id, schema_version, updated_unix) VALUES (1, ?, ?)";
const UPDATE_STATE_SQL: &str =
    "UPDATE sync_state SET backend_name = ?, root_id = ?, updated_unix = ? WHERE id = 1";
const UPSERT_OBJECT_SQL: &str = r#"
            INSERT INTO objects (path, remote_id, revision_id, size, modified_at_ns, sha1, downloaded_unix, original_modified_at_ns, capture_time_ns)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                remote_id = excluded.remote_id,
                revision_id = excluded.revision_id,
                size = excluded.size,
                modified_at_ns = excluded.modified_at_ns,
                sha1 = excluded.sha1,
                downloaded_unix = excluded.downloaded_unix,
                original_modified_at_ns = excluded.original_modified_at_ns,
                capture_time_ns = excluded.capture_time_ns
            "#;
const SUMMARY_SQL: &str = "SELECT backend_name, root_id, updated_unix FROM sync_state WHERE id = 1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    pub path: String,
    pub remote_id: String,
    pub revision_id: String,
    pub size: i64,
    pub modified_at_ns: i64,
    pub sha1: Option<String>,
    pub original_modified_at_ns: Option<i64>,
    pub capture_time_ns: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSummary {
    pub backend_name: Option<String>,
    pub root_id: Option<String>,
    pub object_count: i64,
    pub updated_unix: Option<i64>,
}

pub struct SyncState {
    connection: Connection,
}

impl SyncState {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create state DB parent {}", parent.display()))?;
        }
        let connection =
            Connection::open(path).with_context(|| format!("open state DB {}", path.display()))?;
        Self::configure(connection)
    }

    pub fn open_existing(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("state DB not found: {}", path.display());
        }
        let connection =
            Connection::open(path).with_context(|| format!("open state DB {}", path.display()))?;
        Self::configure(connection)
    }

    fn configure(connection: Connection) -> Result<Self> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;

        connection.execute_batch(INIT_SQL)?;

        let version = connection
            .query_row(
                "SELECT schema_version FROM sync_state WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        match version {
            Some(value) if value > SCHEMA_VERSION => {
                bail!(
                    "state DB schema_version {value} is newer than supported {SCHEMA_VERSION}; downgrade is not safe"
                );
            }
            Some(value) if value < SCHEMA_VERSION => {
                migrate_to_current(&connection, value)?;
            }
            Some(_) => {}
            None => {
                connection.execute(INSERT_STATE_SQL, params![SCHEMA_VERSION, now_unix()?])?;
            }
        }

        Ok(Self { connection })
    }

    pub fn update_run_state(&self, backend_name: &str, root_id: &str) -> Result<()> {
        self.connection.execute(
            UPDATE_STATE_SQL,
            params![backend_name, root_id, now_unix()?],
        )?;
        Ok(())
    }

    pub fn get_object(&self, path: &str) -> Result<Option<StoredObject>> {
        self.connection
            .query_row(
                "SELECT path, remote_id, revision_id, size, modified_at_ns, sha1, original_modified_at_ns, capture_time_ns FROM objects WHERE path = ?",
                [path],
                |row| {
                    Ok(StoredObject {
                        path: row.get(0)?,
                        remote_id: row.get(1)?,
                        revision_id: row.get(2)?,
                        size: row.get(3)?,
                        modified_at_ns: row.get(4)?,
                        sha1: row.get(5)?,
                        original_modified_at_ns: row.get(6)?,
                        capture_time_ns: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn upsert_object(&self, object: &StoredObject) -> Result<()> {
        let params = params![
            object.path,
            object.remote_id,
            object.revision_id,
            object.size,
            object.modified_at_ns,
            object.sha1,
            now_unix()?,
            object.original_modified_at_ns,
            object.capture_time_ns,
        ];
        self.connection.execute(UPSERT_OBJECT_SQL, params)?;
        Ok(())
    }

    /// Iterate over every stored object, useful for repair-style commands.
    pub fn list_objects(&self) -> Result<Vec<StoredObject>> {
        let mut statement = self.connection.prepare(
            "SELECT path, remote_id, revision_id, size, modified_at_ns, sha1, original_modified_at_ns, capture_time_ns FROM objects",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(StoredObject {
                path: row.get(0)?,
                remote_id: row.get(1)?,
                revision_id: row.get(2)?,
                size: row.get(3)?,
                modified_at_ns: row.get(4)?,
                sha1: row.get(5)?,
                original_modified_at_ns: row.get(6)?,
                capture_time_ns: row.get(7)?,
            })
        })?;
        let mut objects = Vec::new();
        for row in rows {
            objects.push(row?);
        }
        Ok(objects)
    }

    pub fn list_object_paths(&self) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare("SELECT path FROM objects")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut paths = Vec::new();
        for row in rows {
            paths.push(row?);
        }
        Ok(paths)
    }

    pub fn delete_object(&self, path: &str) -> Result<()> {
        self.connection
            .execute("DELETE FROM objects WHERE path = ?", [path])?;
        Ok(())
    }

    pub fn summary(&self) -> Result<StateSummary> {
        let (backend_name, root_id, updated_unix): (Option<String>, Option<String>, Option<i64>) =
            self.connection.query_row(SUMMARY_SQL, [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;

        let object_count =
            self.connection
                .query_row("SELECT COUNT(*) FROM objects", [], |row| {
                    row.get::<_, i64>(0)
                })?;

        Ok(StateSummary {
            backend_name,
            root_id,
            object_count,
            updated_unix,
        })
    }
}

fn now_unix() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow!("system clock before unix epoch: {error}"))?;
    i64::try_from(duration.as_secs()).context("unix seconds overflow")
}

/// Apply forward-only migrations that bring the schema from `from_version`
/// up to `SCHEMA_VERSION`. The function is idempotent and tolerant of
/// columns that already exist (which can happen when `INIT_SQL` has just
/// added them via `CREATE TABLE IF NOT EXISTS` on an empty database).
fn migrate_to_current(connection: &Connection, from_version: i64) -> Result<()> {
    if from_version < 2 {
        // 0.1.2 added two nullable columns to `objects` to track the
        // original modification time and original capture time decrypted
        // from the Proton XAttr blob. Both default to NULL so existing
        // rows simply lose access to the new fields until the next sync
        // refills them.
        add_column_if_missing(connection, "objects", "original_modified_at_ns", "INTEGER")?;
        add_column_if_missing(connection, "objects", "capture_time_ns", "INTEGER")?;
    }
    connection.execute(
        "UPDATE sync_state SET schema_version = ?, updated_unix = ? WHERE id = 1",
        params![SCHEMA_VERSION, now_unix()?],
    )?;
    Ok(())
}

fn add_column_if_missing(
    connection: &Connection,
    table: &str,
    column: &str,
    sql_type: &str,
) -> Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(());
        }
    }
    connection
        .execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {sql_type}"),
            [],
        )
        .with_context(|| format!("add column {column} to {table}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use rusqlite::{Connection, params};
    use tempfile::TempDir;

    use super::{SCHEMA_VERSION, StoredObject, SyncState};

    #[test]
    fn open_initializes_empty_state_database() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state_db = temp_dir.path().join("nested").join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        let summary = state.summary()?;

        assert!(state_db.exists());
        assert_eq!(summary.backend_name, None);
        assert_eq!(summary.root_id, None);
        assert_eq!(summary.object_count, 0);
        assert!(summary.updated_unix.is_some());
        Ok(())
    }

    #[test]
    fn open_existing_errors_for_missing_database() {
        let temp_dir = TempDir::new().expect("tempdir");
        let state_db = temp_dir.path().join("missing.sqlite");
        let error = SyncState::open_existing(&state_db)
            .err()
            .expect("missing db should fail");
        assert!(error.to_string().contains("state DB not found"));
    }

    #[test]
    fn open_existing_rejects_schema_mismatch() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state_db = temp_dir.path().join("state.sqlite");
        let connection = Connection::open(&state_db)?;
        const SCHEMA_SQL: &str = r#"
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
            "#;
        connection.execute_batch(SCHEMA_SQL)?;
        connection.execute(
            "INSERT INTO sync_state (id, schema_version, updated_unix) VALUES (1, ?, 0)",
            params![SCHEMA_VERSION + 1],
        )?;

        let error = SyncState::open_existing(&state_db)
            .err()
            .expect("schema mismatch should fail");
        assert!(error.to_string().contains("schema_version"));
        Ok(())
    }

    #[test]
    fn state_supports_update_upsert_list_delete_and_summary() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        state.update_run_state("proton", "photos-root")?;

        let object = StoredObject {
            path: "2026/photo.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "rev-1".to_owned(),
            size: 42,
            modified_at_ns: 1700000000000000000,
            sha1: Some("abc".to_owned()),
            original_modified_at_ns: None,
            capture_time_ns: None,
        };
        state.upsert_object(&object)?;
        assert_eq!(state.get_object(&object.path)?, Some(object.clone()));
        assert_eq!(state.list_object_paths()?, vec![object.path.clone()]);

        let summary = state.summary()?;
        assert_eq!(summary.backend_name.as_deref(), Some("proton"));
        assert_eq!(summary.root_id.as_deref(), Some("photos-root"));
        assert_eq!(summary.object_count, 1);
        assert!(summary.updated_unix.is_some());

        state.delete_object(&object.path)?;
        assert_eq!(state.get_object(&object.path)?, None);
        assert!(state.list_object_paths()?.is_empty());
        Ok(())
    }

    #[test]
    fn open_existing_reads_initialized_database() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        state.update_run_state("manifest", "root")?;

        let reopened = SyncState::open_existing(&state_db)?;
        let summary = reopened.summary()?;
        assert_eq!(summary.backend_name.as_deref(), Some("manifest"));
        assert_eq!(summary.root_id.as_deref(), Some("root"));
        Ok(())
    }

    #[test]
    fn upsert_object_overwrites_existing_row() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = SyncState::open(&temp_dir.path().join("state.sqlite"))?;
        let path = "2026/photo.jpg";
        state.upsert_object(&StoredObject {
            path: path.to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "rev-1".to_owned(),
            size: 1,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;
        state.upsert_object(&StoredObject {
            path: path.to_owned(),
            remote_id: "file-2".to_owned(),
            revision_id: "rev-2".to_owned(),
            size: 2,
            modified_at_ns: 2,
            sha1: Some("abc".to_owned()),
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;

        assert_eq!(
            state.get_object(path)?,
            Some(StoredObject {
                path: path.to_owned(),
                remote_id: "file-2".to_owned(),
                revision_id: "rev-2".to_owned(),
                size: 2,
                modified_at_ns: 2,
                sha1: Some("abc".to_owned()),
                original_modified_at_ns: None,
                capture_time_ns: None,
            })
        );
        Ok(())
    }

    #[test]
    fn missing_objects_and_deletes_are_harmless() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = SyncState::open(&temp_dir.path().join("state.sqlite"))?;
        assert_eq!(state.get_object("missing.jpg")?, None);
        state.delete_object("missing.jpg")?;
        assert!(state.list_object_paths()?.is_empty());
        assert_eq!(state.summary()?.object_count, 0);
        Ok(())
    }

    #[test]
    fn list_object_paths_returns_multiple_rows() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = SyncState::open(&temp_dir.path().join("state.sqlite"))?;
        state.upsert_object(&StoredObject {
            path: "b/photo.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "rev-1".to_owned(),
            size: 1,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;
        state.upsert_object(&StoredObject {
            path: "a/photo.jpg".to_owned(),
            remote_id: "file-2".to_owned(),
            revision_id: "rev-2".to_owned(),
            size: 2,
            modified_at_ns: 2,
            sha1: Some("abc".to_owned()),
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;

        let mut paths = state.list_object_paths()?;
        paths.sort();
        assert_eq!(
            paths,
            vec!["a/photo.jpg".to_owned(), "b/photo.jpg".to_owned()]
        );
        Ok(())
    }
}
