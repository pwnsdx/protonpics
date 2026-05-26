use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use filetime::{FileTime, set_file_mtime};
use serde_json::json;
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::backend::PhotoSource;
use crate::paths::{disambiguated_name, join_rel_path, local_path};
use crate::progress::{self, Reporter};
use crate::state::{StoredObject, SyncState};
use crate::types::{EntryKind, RemoteFile};

const BATCH_PROGRESS_EMIT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub to_dir: PathBuf,
    pub state_db: PathBuf,
    pub dry_run: bool,
    pub delete_missing: bool,
    pub download_concurrency: usize,
    pub progress_mode: progress::Mode,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportReport {
    pub listed_dirs: usize,
    pub listed_files: usize,
    pub downloaded: usize,
    pub deleted: usize,
    pub skipped: usize,
    pub would_download: usize,
    pub would_delete: usize,
    pub failed_downloads: Vec<DownloadFailure>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RepairOptions {
    pub state_db: PathBuf,
    pub to_dir: PathBuf,
    pub dry_run: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RepairReport {
    pub considered: usize,
    pub repaired: usize,
    pub already_correct: usize,
    pub missing_local: usize,
    pub no_metadata: usize,
    pub failed: Vec<RepairFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairFailure {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadFailure {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone)]
struct PendingDownload {
    rel_path: String,
    remote_id: String,
    file: RemoteFile,
}

#[derive(Debug, Clone)]
struct DownloadTask {
    job: PendingDownload,
}

#[derive(Debug)]
enum WorkerEvent {
    Progress { path: String, bytes: u64, size: u64 },
    Completed { job: PendingDownload, bytes: u64 },
    Failed { path: String, error: String },
}

pub fn execute(source: &dyn PhotoSource, options: &ExportOptions) -> Result<ExportReport> {
    let mut reporter = Reporter::stderr(options.progress_mode);
    fs::create_dir_all(&options.to_dir)
        .with_context(|| format!("create export directory {}", options.to_dir.display()))?;

    let state = SyncState::open(&options.state_db)?;
    state.update_run_state(source.backend_name(), source.root_id())?;

    let mut report = ExportReport::default();
    let mut remote_paths = HashSet::new();
    let mut pending_downloads = Vec::new();
    let mut queue = VecDeque::from([(source.root_id().to_owned(), String::new())]);

    while let Some((folder_id, parent_rel_path)) = queue.pop_front() {
        report.listed_dirs += 1;
        let entries = source
            .list_children(&folder_id)
            .with_context(|| format!("list children for folder {folder_id}"))?;
        let mut seen_names = HashMap::new();

        for entry in entries {
            let segment = disambiguated_name(&mut seen_names, &entry.name, &entry.id);
            let child_rel_path = join_rel_path(&parent_rel_path, &segment);

            match entry.kind {
                EntryKind::Folder => {
                    if !options.dry_run {
                        fs::create_dir_all(local_path(&options.to_dir, &child_rel_path))
                            .with_context(|| format!("create directory {child_rel_path}"))?;
                    }
                    queue.push_back((entry.id, child_rel_path));
                }
                EntryKind::File => {
                    report.listed_files += 1;
                    remote_paths.insert(child_rel_path.clone());

                    let file = entry
                        .file
                        .ok_or_else(|| anyhow!("file entry {} missing file metadata", entry.id))?;
                    let existing = state.get_object(&child_rel_path)?;
                    let destination = local_path(&options.to_dir, &child_rel_path);

                    if file_up_to_date(existing.as_ref(), &file, &destination)? {
                        report.skipped += 1;
                        reporter.event(
                            "download",
                            "skipped",
                            [
                                ("backend", json!(source.backend_name())),
                                ("path", json!(child_rel_path)),
                                ("remote_id", json!(entry.id)),
                                ("size", json!(file.size)),
                            ],
                        );
                        // Refresh the state row whenever any tracked field
                        // diverges from the remote view. This is what lets
                        // an upgrade backfill `original_modified_at_ns` and
                        // `capture_time_ns` for files that are otherwise
                        // already on disk.
                        let stored_view =
                            stored_object_from_remote(&child_rel_path, &entry.id, &file);
                        let needs_refresh = match existing.as_ref() {
                            None => true,
                            Some(existing) => {
                                existing.remote_id != stored_view.remote_id
                                    || existing.revision_id != stored_view.revision_id
                                    || existing.original_modified_at_ns
                                        != stored_view.original_modified_at_ns
                                    || existing.capture_time_ns != stored_view.capture_time_ns
                            }
                        };
                        if needs_refresh {
                            state.upsert_object(&stored_view)?;
                        }
                        continue;
                    }

                    if options.dry_run {
                        report.would_download += 1;
                        reporter.event(
                            "download",
                            "planned",
                            [
                                ("backend", json!(source.backend_name())),
                                ("path", json!(child_rel_path)),
                                ("remote_id", json!(entry.id)),
                                ("size", json!(file.size)),
                            ],
                        );
                    } else {
                        pending_downloads.push(PendingDownload {
                            rel_path: child_rel_path,
                            remote_id: entry.id,
                            file,
                        });
                    }
                }
            }
        }
    }

    if !options.dry_run {
        let total = pending_downloads.len();
        let total_bytes = pending_downloads
            .iter()
            .map(|job| u64::try_from(job.file.size.max(0)).unwrap_or(0))
            .sum::<u64>();
        if options.download_concurrency <= 1 || total <= 1 {
            for (index, job) in pending_downloads.iter().enumerate() {
                reporter.event(
                    "download",
                    "start",
                    [
                        ("backend", json!(source.backend_name())),
                        ("path", json!(job.rel_path)),
                        ("remote_id", json!(job.remote_id)),
                        ("size", json!(job.file.size)),
                        ("index", json!(index + 1)),
                        ("total", json!(total)),
                    ],
                );
                match download_one(
                    source,
                    &state,
                    &options.to_dir,
                    job,
                    &mut reporter,
                    index + 1,
                    total,
                ) {
                    Ok(bytes) => {
                        report.downloaded += 1;
                        reporter.event(
                            "download",
                            "complete",
                            [
                                ("backend", json!(source.backend_name())),
                                ("path", json!(job.rel_path)),
                                ("remote_id", json!(job.remote_id)),
                                ("bytes", json!(bytes)),
                                ("index", json!(index + 1)),
                                ("total", json!(total)),
                            ],
                        );
                    }
                    Err(error) => {
                        let message = format!("{error:#}");
                        reporter.event(
                            "download",
                            "failed",
                            [
                                ("backend", json!(source.backend_name())),
                                ("path", json!(job.rel_path)),
                                ("remote_id", json!(job.remote_id)),
                                ("error", json!(message.clone())),
                                ("index", json!(index + 1)),
                                ("total", json!(total)),
                            ],
                        );
                        report.failed_downloads.push(DownloadFailure {
                            path: job.rel_path.clone(),
                            error: message,
                        });
                    }
                }
            }
        } else {
            reporter.event(
                "download_batch",
                "start",
                [
                    ("backend", json!(source.backend_name())),
                    ("files", json!(total)),
                    ("total_bytes", json!(total_bytes)),
                    (
                        "concurrency",
                        json!(options.download_concurrency.min(total.max(1))),
                    ),
                ],
            );
            let (downloaded, failures) = execute_parallel_downloads(
                source,
                &state,
                &options.to_dir,
                &pending_downloads,
                &mut reporter,
                options.download_concurrency,
                total_bytes,
            )?;
            report.downloaded += downloaded;
            report.failed_downloads.extend(failures);
        }
    }

    if options.delete_missing {
        let stale_paths = stale_paths(&state, &remote_paths)?;
        if options.dry_run {
            report.would_delete = stale_paths.len();
            for rel_path in stale_paths {
                reporter.event(
                    "delete",
                    "planned",
                    [
                        ("backend", json!(source.backend_name())),
                        ("path", json!(rel_path)),
                    ],
                );
            }
        } else {
            for rel_path in stale_paths {
                let disk_path = local_path(&options.to_dir, &rel_path);
                if let Err(error) = fs::remove_file(&disk_path)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    return Err(error)
                        .with_context(|| format!("remove local file {}", disk_path.display()));
                }
                state.delete_object(&rel_path)?;
                report.deleted += 1;
                reporter.event(
                    "delete",
                    "complete",
                    [
                        ("backend", json!(source.backend_name())),
                        ("path", json!(rel_path)),
                    ],
                );
            }
            prune_empty_dirs(&options.to_dir)?;
        }
    }

    reporter.finish();
    Ok(report)
}

/// Re-applies the original modification and capture timestamps to files
/// already on disk, using the metadata recorded in the SQLite state DB.
/// This is the right entrypoint for users upgrading from a previous version
/// of the tool that did not yet decrypt Proton's XAttr blob: after a fresh
/// `export` run that backfills the new state columns, calling this function
/// fixes the on-disk timestamps without re-downloading anything.
pub fn repair_metadata(options: &RepairOptions) -> Result<RepairReport> {
    let state = SyncState::open_existing(&options.state_db)?;
    let stored = state.list_objects()?;
    let mut report = RepairReport {
        considered: stored.len(),
        ..RepairReport::default()
    };

    for object in stored {
        let local_path = local_path(&options.to_dir, &object.path);
        if !local_path.exists() {
            report.missing_local += 1;
            continue;
        }

        let mtime_ns = object
            .original_modified_at_ns
            .or(if object.modified_at_ns > 0 {
                Some(object.modified_at_ns)
            } else {
                None
            });
        let birthtime_ns = object
            .capture_time_ns
            .or(object.original_modified_at_ns)
            .or(if object.modified_at_ns > 0 {
                Some(object.modified_at_ns)
            } else {
                None
            });

        let Some(mtime_ns) = mtime_ns else {
            report.no_metadata += 1;
            continue;
        };

        if file_already_at_target_metadata(&local_path, mtime_ns) {
            report.already_correct += 1;
            continue;
        }

        if options.dry_run {
            report.repaired += 1;
            continue;
        }

        if let Err(error) = set_mtime_ns(&local_path, mtime_ns) {
            report.failed.push(RepairFailure {
                path: object.path.clone(),
                error: format!("{error:#}"),
            });
            continue;
        }
        if let Some(birthtime_ns) = birthtime_ns {
            // Birthtime updates are best-effort. A failure here does not
            // count as a repair failure since it never counted as "correct"
            // before either: it's strictly an improvement when supported.
            let _ = set_birthtime_ns(&local_path, birthtime_ns);
        }
        report.repaired += 1;
    }

    Ok(report)
}

fn file_already_at_target_metadata(path: &Path, target_mtime_ns: i64) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Ok(mtime) = metadata.modified() else {
        return false;
    };
    let Ok(local_ns) = system_time_to_ns(mtime) else {
        return false;
    };
    same_modified_second(local_ns, target_mtime_ns)
}

fn execute_parallel_downloads(
    source: &dyn PhotoSource,
    state: &SyncState,
    root_dir: &Path,
    jobs: &[PendingDownload],
    reporter: &mut Reporter,
    download_concurrency: usize,
    total_bytes: u64,
) -> Result<(usize, Vec<DownloadFailure>)> {
    let total = jobs.len();
    let worker_count = download_concurrency.max(1).min(total.max(1));
    let queue = Arc::new(Mutex::new(
        jobs.iter()
            .cloned()
            .map(|job| DownloadTask { job })
            .collect::<VecDeque<_>>(),
    ));
    let cancelled = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<WorkerEvent>();
    let root_dir = root_dir.to_path_buf();

    thread::scope(|scope| -> Result<(usize, Vec<DownloadFailure>)> {
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let cancelled = Arc::clone(&cancelled);
            let tx = tx.clone();
            let root_dir = root_dir.clone();
            scope.spawn(move || {
                loop {
                    if cancelled.load(Ordering::Acquire) {
                        break;
                    }

                    let task = {
                        queue
                            .lock()
                            .expect("download queue mutex poisoned")
                            .pop_front()
                    };
                    let Some(task) = task else {
                        break;
                    };
                    let expected_size = u64::try_from(task.job.file.size).ok();

                    let mut reported_bytes = 0u64;
                    match materialize_download_with_progress(
                        source,
                        &root_dir,
                        &task.job,
                        |bytes| {
                            if expected_size == Some(bytes)
                                || bytes.saturating_sub(reported_bytes) >= BATCH_PROGRESS_EMIT_BYTES
                            {
                                reported_bytes = bytes;
                                tx.send(WorkerEvent::Progress {
                                    path: task.job.rel_path.clone(),
                                    bytes,
                                    size: task.job.file.size as u64,
                                })
                                .map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "download progress receiver dropped",
                                    )
                                })?;
                            }
                            Ok(())
                        },
                    ) {
                        Ok(bytes) => {
                            if tx
                                .send(WorkerEvent::Completed {
                                    job: task.job,
                                    bytes,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(error) => {
                            // Per-file failure: report it and keep working on
                            // the rest of the queue. Other workers are not
                            // cancelled so the batch can finish what it can.
                            if tx
                                .send(WorkerEvent::Failed {
                                    path: task.job.rel_path,
                                    error: format!("{error:#}"),
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            });
        }
        drop(tx);

        let mut completed = 0usize;
        let mut completed_bytes = 0u64;
        let mut active_bytes = HashMap::<String, u64>::new();
        let mut failures: Vec<DownloadFailure> = Vec::new();
        while let Ok(event) = rx.recv() {
            match event {
                WorkerEvent::Progress { path, bytes, size } => {
                    active_bytes.insert(path.clone(), bytes);
                    let visible_bytes =
                        completed_bytes.saturating_add(active_bytes.values().copied().sum::<u64>());
                    reporter.event(
                        "download_batch",
                        "progress",
                        [
                            ("backend", json!(source.backend_name())),
                            ("path", json!(path)),
                            ("completed_files", json!(completed)),
                            ("total_files", json!(total)),
                            ("completed_bytes", json!(visible_bytes)),
                            ("total_bytes", json!(total_bytes)),
                            ("size", json!(size)),
                        ],
                    );
                }
                WorkerEvent::Completed { job, bytes } => {
                    active_bytes.remove(&job.rel_path);
                    completed += 1;
                    completed_bytes = completed_bytes.saturating_add(bytes);
                    let visible_bytes =
                        completed_bytes.saturating_add(active_bytes.values().copied().sum::<u64>());
                    state.upsert_object(&stored_object_from_remote(
                        &job.rel_path,
                        &job.remote_id,
                        &job.file,
                    ))?;
                    reporter.event(
                        "download_batch",
                        "progress",
                        [
                            ("backend", json!(source.backend_name())),
                            ("path", json!(job.rel_path)),
                            ("completed_files", json!(completed)),
                            ("total_files", json!(total)),
                            ("completed_bytes", json!(visible_bytes)),
                            ("total_bytes", json!(total_bytes)),
                        ],
                    );
                    reporter.event(
                        "download",
                        "complete",
                        [
                            ("backend", json!(source.backend_name())),
                            ("path", json!(job.rel_path)),
                            ("remote_id", json!(job.remote_id)),
                            ("bytes", json!(bytes)),
                            ("index", json!(completed)),
                            ("total", json!(total)),
                        ],
                    );
                }
                WorkerEvent::Failed { path, error } => {
                    active_bytes.remove(&path);
                    reporter.event(
                        "download",
                        "failed",
                        [
                            ("backend", json!(source.backend_name())),
                            ("path", json!(path.clone())),
                            ("error", json!(error.clone())),
                            ("total", json!(total)),
                        ],
                    );
                    failures.push(DownloadFailure { path, error });
                }
            }
        }

        // Keep `cancelled` in scope: it would be used for interruption signals
        // in a future change. For now it stays false through normal runs.
        let _ = &cancelled;

        reporter.event(
            "download_batch",
            "complete",
            [
                ("backend", json!(source.backend_name())),
                ("completed_files", json!(completed)),
                ("total_files", json!(total)),
                ("failed_files", json!(failures.len())),
                ("completed_bytes", json!(completed_bytes)),
                ("total_bytes", json!(total_bytes)),
            ],
        );

        Ok((completed, failures))
    })
}

fn stale_paths(state: &SyncState, remote_paths: &HashSet<String>) -> Result<Vec<String>> {
    let mut stale = Vec::new();
    for path in state.list_object_paths()? {
        if !remote_paths.contains(&path) {
            stale.push(path);
        }
    }
    Ok(stale)
}

fn stored_object_from_remote(path: &str, remote_id: &str, file: &RemoteFile) -> StoredObject {
    StoredObject {
        path: path.to_owned(),
        remote_id: remote_id.to_owned(),
        revision_id: file.revision_id.clone(),
        size: file.size,
        modified_at_ns: file.modified_at_ns,
        sha1: file.sha1.clone(),
        original_modified_at_ns: file.original_modified_at_ns,
        capture_time_ns: file.capture_time_ns,
    }
}

fn file_up_to_date(
    stored: Option<&StoredObject>,
    remote: &RemoteFile,
    destination: &Path,
) -> Result<bool> {
    let metadata = match fs::metadata(destination) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read metadata for {}", destination.display()));
        }
    };

    let local_size = i64::try_from(metadata.len()).context("local file size overflow")?;
    let local_mtime_ns = system_time_to_ns(
        metadata
            .modified()
            .with_context(|| format!("read mtime for {}", destination.display()))?,
    )?;

    Ok(stored.is_some_and(|stored| {
        (!remote.revision_id.is_empty()
            && stored.revision_id == remote.revision_id
            && local_size == remote.size)
            || (local_size == remote.size
                && same_modified_second(local_mtime_ns, remote.modified_at_ns))
            || (stored.size == remote.size
                && stored.modified_at_ns == remote.modified_at_ns
                && same_modified_second(local_mtime_ns, remote.modified_at_ns))
    }))
}

fn download_one(
    source: &dyn PhotoSource,
    state: &SyncState,
    root_dir: &Path,
    job: &PendingDownload,
    reporter: &mut Reporter,
    index: usize,
    total: usize,
) -> Result<u64> {
    let destination = local_path(root_dir, &job.rel_path);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }

    let mut reader = source
        .open_file(&job.remote_id)
        .with_context(|| format!("open remote file {}", job.remote_id))?;
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination missing parent: {}", destination.display()))?;
    let mut temp_file = NamedTempFile::new_in(parent)?;
    let bytes = copy_with_progress(
        &mut reader,
        temp_file.as_file_mut(),
        source.backend_name(),
        job,
        reporter,
        index,
        total,
    )
    .with_context(|| format!("write {}", destination.display()))?;
    reporter.event(
        "download",
        "finalizing",
        [
            ("backend", json!(source.backend_name())),
            ("path", json!(job.rel_path)),
            ("remote_id", json!(job.remote_id)),
            ("bytes", json!(bytes)),
            ("size", json!(job.file.size)),
            ("index", json!(index)),
            ("total", json!(total)),
        ],
    );
    apply_file_metadata(temp_file.path(), &job.file)?;

    if destination.exists() {
        fs::remove_file(&destination)
            .with_context(|| format!("replace existing file {}", destination.display()))?;
    }
    temp_file
        .persist(&destination)
        .map_err(|error| error.error)
        .with_context(|| format!("persist {}", destination.display()))?;

    state.upsert_object(&stored_object_from_remote(
        &job.rel_path,
        &job.remote_id,
        &job.file,
    ))?;
    Ok(bytes)
}

#[cfg(test)]
fn materialize_download(
    source: &dyn PhotoSource,
    root_dir: &Path,
    job: &PendingDownload,
) -> Result<u64> {
    let destination = local_path(root_dir, &job.rel_path);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }

    let mut reader = source
        .open_file(&job.remote_id)
        .with_context(|| format!("open remote file {}", job.remote_id))?;
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination missing parent: {}", destination.display()))?;
    let mut temp_file = NamedTempFile::new_in(parent)?;
    let bytes = copy_with_callback(&mut reader, temp_file.as_file_mut(), |_| Ok(()))
        .with_context(|| format!("write {}", destination.display()))?;
    apply_file_metadata(temp_file.path(), &job.file)?;

    if destination.exists() {
        fs::remove_file(&destination)
            .with_context(|| format!("replace existing file {}", destination.display()))?;
    }
    temp_file
        .persist(&destination)
        .map_err(|error| error.error)
        .with_context(|| format!("persist {}", destination.display()))?;
    Ok(bytes)
}

fn materialize_download_with_progress(
    source: &dyn PhotoSource,
    root_dir: &Path,
    job: &PendingDownload,
    mut on_progress: impl FnMut(u64) -> io::Result<()>,
) -> Result<u64> {
    let destination = local_path(root_dir, &job.rel_path);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }

    let mut reader = source
        .open_file(&job.remote_id)
        .with_context(|| format!("open remote file {}", job.remote_id))?;
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination missing parent: {}", destination.display()))?;
    let mut temp_file = NamedTempFile::new_in(parent)?;
    let bytes = copy_with_callback(&mut reader, temp_file.as_file_mut(), &mut on_progress)
        .with_context(|| format!("write {}", destination.display()))?;
    apply_file_metadata(temp_file.path(), &job.file)?;

    if destination.exists() {
        fs::remove_file(&destination)
            .with_context(|| format!("replace existing file {}", destination.display()))?;
    }
    temp_file
        .persist(&destination)
        .map_err(|error| error.error)
        .with_context(|| format!("persist {}", destination.display()))?;
    Ok(bytes)
}

fn copy_with_progress(
    reader: &mut dyn io::Read,
    writer: &mut dyn io::Write,
    backend_name: &str,
    job: &PendingDownload,
    reporter: &mut Reporter,
    index: usize,
    total: usize,
) -> io::Result<u64> {
    copy_with_callback(reader, writer, |total_bytes| {
        reporter.event(
            "download",
            "progress",
            [
                ("backend", json!(backend_name)),
                ("path", json!(job.rel_path)),
                ("remote_id", json!(job.remote_id)),
                ("bytes", json!(total_bytes)),
                ("size", json!(job.file.size)),
                ("index", json!(index)),
                ("total", json!(total)),
            ],
        );
        Ok(())
    })
}

fn copy_with_callback(
    reader: &mut dyn io::Read,
    writer: &mut dyn io::Write,
    mut on_progress: impl FnMut(u64) -> io::Result<()>,
) -> io::Result<u64> {
    let mut buffer = [0_u8; 256 * 1024];
    let mut total_bytes = 0_u64;

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read])?;
        total_bytes += u64::try_from(read).expect("chunk size fits into u64");
        on_progress(total_bytes)?;
    }

    Ok(total_bytes)
}

fn set_mtime_ns(path: &Path, modified_at_ns: i64) -> Result<()> {
    let seconds = modified_at_ns.div_euclid(1_000_000_000);
    let nanos = modified_at_ns.rem_euclid(1_000_000_000) as u32;
    set_file_mtime(path, FileTime::from_unix_time(seconds, nanos))
        .with_context(|| format!("set mtime on {}", path.display()))
}

/// Resolves the best mtime to apply for a remote file. Prefers the original
/// modification time decrypted from the Proton XAttr (the user's local mtime
/// at upload time), falling back to the upload time when XAttr is missing or
/// unparseable.
fn effective_mtime_ns(file: &RemoteFile) -> i64 {
    file.original_modified_at_ns.unwrap_or(file.modified_at_ns)
}

/// Resolves the best birthtime to apply on platforms that support setting it
/// (currently macOS). Prefers the camera capture time, then the original
/// modification time, then the upload time.
fn effective_birthtime_ns(file: &RemoteFile) -> i64 {
    file.capture_time_ns
        .or(file.original_modified_at_ns)
        .unwrap_or(file.modified_at_ns)
}

/// Applies mtime (and, on macOS, birthtime) to a freshly-written file.
/// Errors on the mtime side bubble up because that is the most important
/// metadata to preserve. Errors on the birthtime side are swallowed since
/// not every macOS filesystem supports the `setattrlist` syscall (network
/// volumes, some FUSE drivers).
fn apply_file_metadata(path: &Path, file: &RemoteFile) -> Result<()> {
    set_mtime_ns(path, effective_mtime_ns(file))?;
    let _ = set_birthtime_ns(path, effective_birthtime_ns(file));
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_birthtime_ns(path: &Path, birthtime_ns: i64) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: this calls into libc directly because the `filetime` crate
    // does not expose macOS birthtime. The struct layout below mirrors
    // `<sys/attr.h>` exactly. Both `attrlist` and `timespec` are
    // POD-compatible C structs.
    #[repr(C)]
    struct AttrList {
        bitmapcount: u16,
        reserved: u16,
        commonattr: u32,
        volattr: u32,
        dirattr: u32,
        fileattr: u32,
        forkattr: u32,
    }

    const ATTR_BIT_MAP_COUNT: u16 = 5;
    const ATTR_CMN_CRTIME: u32 = 0x0000_0200;
    const FSOPT_NOFOLLOW: u32 = 0x0000_0001;

    unsafe extern "C" {
        fn setattrlist(
            path: *const libc::c_char,
            attrlist: *const AttrList,
            attrbuf: *const libc::c_void,
            attrbufsize: libc::size_t,
            options: libc::c_ulong,
        ) -> libc::c_int;
    }

    let c_path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("encode path {} for setattrlist", path.display()))?;

    let attrs = AttrList {
        bitmapcount: ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: ATTR_CMN_CRTIME,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };

    let timespec = libc::timespec {
        tv_sec: birthtime_ns.div_euclid(1_000_000_000),
        tv_nsec: birthtime_ns.rem_euclid(1_000_000_000) as libc::c_long,
    };

    let result = unsafe {
        setattrlist(
            c_path.as_ptr(),
            &attrs,
            &timespec as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timespec>(),
            FSOPT_NOFOLLOW as libc::c_ulong,
        )
    };

    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(errno).with_context(|| format!("set birthtime on {}", path.display()))
    }
}

#[cfg(not(target_os = "macos"))]
fn set_birthtime_ns(_path: &Path, _birthtime_ns: i64) -> Result<()> {
    // No portable way to set the file creation time on Linux or Windows
    // without filesystem-specific syscalls or platform support that we
    // do not target. Treat as a no-op.
    Ok(())
}

fn system_time_to_ns(value: SystemTime) -> Result<i64> {
    let duration = value
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow!("system time before unix epoch: {error}"))?;
    let seconds = i128::from(duration.as_secs());
    let nanos = i128::from(duration.subsec_nanos());
    i64::try_from(seconds * 1_000_000_000 + nanos).context("nanosecond timestamp overflow")
}

fn same_modified_second(lhs_ns: i64, rhs_ns: i64) -> bool {
    lhs_ns.div_euclid(1_000_000_000) == rhs_ns.div_euclid(1_000_000_000)
}

fn prune_empty_dirs(root_dir: &Path) -> Result<()> {
    if !root_dir.exists() {
        return Ok(());
    }

    for entry in WalkDir::new(root_dir).min_depth(1).contents_first(true) {
        let entry = entry?;
        if !entry.file_type().is_dir() {
            continue;
        }

        let mut children = fs::read_dir(entry.path())
            .with_context(|| format!("list directory {}", entry.path().display()))?;
        if children.next().is_none() {
            fs::remove_dir(entry.path())
                .with_context(|| format!("remove empty directory {}", entry.path().display()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Cursor, Read};
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};
    #[cfg(unix)]
    use std::{fs::Permissions, os::unix::fs::PermissionsExt};

    use anyhow::{Result, anyhow};
    use tempfile::TempDir;

    #[cfg(target_os = "macos")]
    use super::set_birthtime_ns;
    use super::{
        ExportOptions, PendingDownload, RepairOptions, apply_file_metadata, download_one,
        effective_birthtime_ns, effective_mtime_ns, execute, execute_parallel_downloads,
        file_already_at_target_metadata, file_up_to_date, materialize_download, prune_empty_dirs,
        repair_metadata, same_modified_second, stale_paths, stored_object_from_remote,
        system_time_to_ns,
    };
    use crate::backend::PhotoSource;
    use crate::progress::{Mode, Reporter};
    use crate::state::{StoredObject, SyncState};
    use crate::types::{RemoteEntry, RemoteFile};

    #[derive(Default)]
    struct MemorySource {
        root_id: String,
        children: HashMap<String, Vec<RemoteEntry>>,
        files: HashMap<String, Vec<u8>>,
        open_error: Option<String>,
    }

    impl MemorySource {
        fn new(root_id: &str) -> Self {
            Self {
                root_id: root_id.to_owned(),
                ..Self::default()
            }
        }

        fn with_root_entries(mut self, entries: Vec<RemoteEntry>) -> Self {
            self.children.insert(self.root_id.clone(), entries);
            self
        }
    }

    impl PhotoSource for MemorySource {
        fn backend_name(&self) -> &'static str {
            "memory"
        }

        fn root_id(&self) -> &str {
            &self.root_id
        }

        fn list_children(&self, folder_id: &str) -> Result<Vec<RemoteEntry>> {
            self.children
                .get(folder_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown folder {folder_id}"))
        }

        fn open_file(&self, file_id: &str) -> Result<Box<dyn Read + Send>> {
            if let Some(message) = &self.open_error {
                return Err(anyhow!(message.clone()));
            }
            let bytes = self
                .files
                .get(file_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown file {file_id}"))?;
            Ok(Box::new(Cursor::new(bytes)))
        }
    }

    fn remote_file(revision_id: &str, size: i64, modified_at_ns: i64) -> RemoteFile {
        RemoteFile {
            revision_id: revision_id.to_owned(),
            size,
            modified_at_ns,
            sha1: Some("abc".to_owned()),
            original_modified_at_ns: None,
            capture_time_ns: None,
        }
    }

    #[test]
    fn stale_paths_returns_paths_missing_from_remote_index() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state = SyncState::open(&temp_dir.path().join("state.sqlite"))?;
        state.upsert_object(&StoredObject {
            path: "keep.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "rev-1".to_owned(),
            size: 1,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;
        state.upsert_object(&StoredObject {
            path: "drop.jpg".to_owned(),
            remote_id: "file-2".to_owned(),
            revision_id: "rev-2".to_owned(),
            size: 1,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;

        let stale = stale_paths(&state, &["keep.jpg".to_owned()].into_iter().collect())?;
        assert_eq!(stale, vec!["drop.jpg".to_owned()]);
        Ok(())
    }

    #[test]
    fn stored_object_from_remote_preserves_metadata() {
        let file = remote_file("rev-1", 42, 99);
        let stored = stored_object_from_remote("2026/photo.jpg", "file-1", &file);
        assert_eq!(
            stored,
            StoredObject {
                path: "2026/photo.jpg".to_owned(),
                remote_id: "file-1".to_owned(),
                revision_id: "rev-1".to_owned(),
                size: 42,
                modified_at_ns: 99,
                sha1: Some("abc".to_owned()),
                original_modified_at_ns: None,
                capture_time_ns: None,
            }
        );
    }

    #[test]
    fn file_up_to_date_checks_revision_size_and_modified_time() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("photo.jpg");
        fs::write(&path, b"jpeg")?;
        super::set_mtime_ns(&path, 1_700_000_000_123_000_000)?;

        let remote = remote_file("rev-1", 4, 1_700_000_000_999_000_000);
        let stored = StoredObject {
            path: "photo.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "rev-1".to_owned(),
            size: 4,
            modified_at_ns: 1_700_000_000_123_000_000,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        };
        assert!(file_up_to_date(Some(&stored), &remote, &path)?);

        let changed_remote = remote_file("rev-2", 4, 1_700_000_000_999_000_000);
        assert!(file_up_to_date(Some(&stored), &changed_remote, &path)?);

        let mismatch = remote_file("rev-3", 5, 1_700_000_000_999_000_000);
        assert!(!file_up_to_date(Some(&stored), &mismatch, &path)?);
        Ok(())
    }

    #[test]
    fn file_up_to_date_returns_false_for_missing_path_or_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let missing = temp_dir.path().join("missing.jpg");
        assert!(!file_up_to_date(None, &remote_file("rev", 4, 1), &missing)?);

        let dir = temp_dir.path().join("dir");
        fs::create_dir_all(&dir)?;
        assert!(!file_up_to_date(None, &remote_file("rev", 0, 1), &dir)?);
        Ok(())
    }

    #[test]
    fn file_up_to_date_can_fall_back_to_stored_metadata() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("photo.jpg");
        fs::write(&path, b"large!")?;
        super::set_mtime_ns(&path, 1_700_000_000_123_000_000)?;

        let remote = RemoteFile {
            revision_id: String::new(),
            size: 4,
            modified_at_ns: 1_700_000_000_123_999_999,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        };
        let stored = StoredObject {
            path: "photo.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "old-rev".to_owned(),
            size: 4,
            modified_at_ns: 1_700_000_000_123_999_999,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        };

        assert!(file_up_to_date(Some(&stored), &remote, &path)?);
        Ok(())
    }

    #[test]
    fn download_one_creates_missing_parent_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state = SyncState::open(&temp_dir.path().join("state.sqlite"))?;
        let mut source = MemorySource::new("root");
        source.files.insert("file-1".to_owned(), b"fresh".to_vec());
        let job = PendingDownload {
            rel_path: "2026/photo.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            file: remote_file("rev-1", 5, 1_700_000_000_123_000_000),
        };

        let mut reporter = Reporter::stderr(Mode::Quiet);
        let bytes = download_one(&source, &state, &output_dir, &job, &mut reporter, 1, 1)?;
        assert_eq!(bytes, 5);
        assert_eq!(fs::read(output_dir.join("2026/photo.jpg"))?, b"fresh");
        Ok(())
    }

    #[test]
    fn download_one_replaces_existing_file_and_updates_state() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state = SyncState::open(&temp_dir.path().join("state.sqlite"))?;
        let destination = output_dir.join("2026/photo.jpg");
        fs::create_dir_all(destination.parent().expect("parent"))?;
        fs::write(&destination, b"old")?;

        let mut source = MemorySource::new("root");
        source.files.insert("file-1".to_owned(), b"fresh".to_vec());
        let job = PendingDownload {
            rel_path: "2026/photo.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            file: remote_file("rev-1", 5, 1_700_000_000_123_000_000),
        };

        let mut reporter = Reporter::stderr(Mode::Quiet);
        let bytes = download_one(&source, &state, &output_dir, &job, &mut reporter, 1, 1)?;
        assert_eq!(bytes, 5);
        assert_eq!(fs::read(&destination)?, b"fresh");
        assert_eq!(
            state.get_object("2026/photo.jpg")?,
            Some(StoredObject {
                path: "2026/photo.jpg".to_owned(),
                remote_id: "file-1".to_owned(),
                revision_id: "rev-1".to_owned(),
                size: 5,
                modified_at_ns: 1_700_000_000_123_000_000,
                sha1: Some("abc".to_owned()),
                original_modified_at_ns: None,
                capture_time_ns: None,
            })
        );
        Ok(())
    }

    #[test]
    fn materialize_download_replaces_existing_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let destination = output_dir.join("2026/photo.jpg");
        fs::create_dir_all(destination.parent().expect("parent"))?;
        fs::write(&destination, b"old")?;

        let mut source = MemorySource::new("root");
        source.files.insert("file-1".to_owned(), b"fresh".to_vec());
        let job = PendingDownload {
            rel_path: "2026/photo.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            file: remote_file("rev-1", 5, 1_700_000_000_123_000_000),
        };

        let bytes = materialize_download(&source, &output_dir, &job)?;
        assert_eq!(bytes, 5);
        assert_eq!(fs::read(&destination)?, b"fresh");
        Ok(())
    }

    #[test]
    fn materialize_download_errors_when_destination_has_no_parent() {
        let mut source = MemorySource::new("root");
        source.files.insert("file-1".to_owned(), b"hello".to_vec());
        let job = PendingDownload {
            rel_path: String::new(),
            remote_id: "file-1".to_owned(),
            file: remote_file("rev-1", 5, 1_700_000_000_123_000_000),
        };

        let error = materialize_download(&source, Path::new(""), &job)
            .expect_err("missing parent should fail");
        assert!(error.to_string().contains("destination missing parent"));
    }

    #[test]
    fn execute_parallel_downloads_reports_worker_failures() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state = SyncState::open(&temp_dir.path().join("state.sqlite"))?;
        let mut source = MemorySource::new("root");
        source.files.insert("file-ok".to_owned(), b"ok".to_vec());
        let jobs = vec![
            PendingDownload {
                rel_path: "ok.jpg".to_owned(),
                remote_id: "file-ok".to_owned(),
                file: remote_file("rev-1", 2, 1_700_000_000_123_000_000),
            },
            PendingDownload {
                rel_path: "missing.jpg".to_owned(),
                remote_id: "file-missing".to_owned(),
                file: remote_file("rev-2", 7, 1_700_000_000_123_000_000),
            },
        ];

        let mut reporter = Reporter::stderr(Mode::Quiet);
        let (downloaded, failures) =
            execute_parallel_downloads(&source, &state, &output_dir, &jobs, &mut reporter, 2, 9)?;
        assert_eq!(downloaded, 1, "the healthy file must still complete");
        assert_eq!(failures.len(), 1, "the bad file must be reported");
        let failure = &failures[0];
        assert_eq!(failure.path, "missing.jpg");
        assert!(
            failure.error.contains("unknown file file-missing"),
            "unexpected error message: {}",
            failure.error
        );
        // The healthy file should have made it to the on-disk state too,
        // so a rerun would skip it.
        assert!(state.get_object("ok.jpg")?.is_some());
        Ok(())
    }

    #[test]
    fn execute_delete_missing_removes_files_and_prunes_empty_dirs() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        state.upsert_object(&StoredObject {
            path: "2026/stale.jpg".to_owned(),
            remote_id: "old".to_owned(),
            revision_id: "rev-old".to_owned(),
            size: 3,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;
        fs::create_dir_all(output_dir.join("2026"))?;
        fs::write(output_dir.join("2026/stale.jpg"), b"old")?;

        let source = MemorySource::new("root").with_root_entries(Vec::new());
        let report = execute(
            &source,
            &ExportOptions {
                to_dir: output_dir.clone(),
                state_db,
                dry_run: false,
                delete_missing: true,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect("delete missing should succeed");

        assert_eq!(report.deleted, 1);
        assert!(!output_dir.join("2026/stale.jpg").exists());
        assert!(!output_dir.join("2026").exists());
        Ok(())
    }

    #[test]
    fn execute_errors_when_export_directory_is_a_file() {
        let temp_dir = TempDir::new().expect("tempdir");
        let output_path = temp_dir.path().join("out");
        fs::write(&output_path, b"not a directory").expect("output file");

        let error = execute(
            &MemorySource::new("root").with_root_entries(Vec::new()),
            &ExportOptions {
                to_dir: output_path,
                state_db: temp_dir.path().join("state.sqlite"),
                dry_run: false,
                delete_missing: false,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect_err("create_dir_all should fail");
        assert!(error.to_string().contains("create export directory"));
    }

    #[cfg(unix)]
    #[test]
    fn file_up_to_date_reports_metadata_errors() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let blocked = temp_dir.path().join("blocked");
        fs::create_dir_all(&blocked)?;
        fs::set_permissions(&blocked, Permissions::from_mode(0o000))?;
        let destination = blocked.join("photo.jpg");

        let result = file_up_to_date(None, &remote_file("rev", 4, 1), &destination);
        fs::set_permissions(&blocked, Permissions::from_mode(0o755))?;

        let error = result.expect_err("permission error should bubble up");
        assert!(error.to_string().contains("read metadata for"));
        Ok(())
    }

    #[test]
    fn execute_dry_run_plans_downloads_and_deletes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        state.upsert_object(&StoredObject {
            path: "stale.jpg".to_owned(),
            remote_id: "old".to_owned(),
            revision_id: "rev-old".to_owned(),
            size: 3,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;

        let mut source = MemorySource::new("root");
        source = source.with_root_entries(vec![RemoteEntry::file(
            "file-1",
            "photo.jpg",
            remote_file("rev-1", 5, 1_700_000_000_123_000_000),
        )]);
        source.files.insert("file-1".to_owned(), b"fresh".to_vec());

        let report = execute(
            &source,
            &ExportOptions {
                to_dir: output_dir.clone(),
                state_db,
                dry_run: true,
                delete_missing: true,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect("dry run should succeed");

        assert_eq!(report.would_download, 1);
        assert_eq!(report.would_delete, 1);
        assert!(!output_dir.join("photo.jpg").exists());
        Ok(())
    }

    #[test]
    fn execute_creates_nested_directories_and_downloads_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let mut source = MemorySource::new("root");
        source.children.insert(
            "root".to_owned(),
            vec![RemoteEntry::folder("folder-1", "Trips")],
        );
        source.children.insert(
            "folder-1".to_owned(),
            vec![RemoteEntry::file(
                "file-1",
                "photo.jpg",
                remote_file("rev-1", 5, 1_700_000_000_123_000_000),
            )],
        );
        source.files.insert("file-1".to_owned(), b"fresh".to_vec());

        let report = execute(
            &source,
            &ExportOptions {
                to_dir: output_dir.clone(),
                state_db,
                dry_run: false,
                delete_missing: false,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect("nested export should succeed");

        assert_eq!(report.listed_dirs, 2);
        assert_eq!(report.downloaded, 1);
        assert!(output_dir.join("Trips").is_dir());
        assert_eq!(fs::read(output_dir.join("Trips/photo.jpg"))?, b"fresh");
        Ok(())
    }

    #[test]
    fn execute_downloads_multiple_files_in_parallel() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let mut source = MemorySource::new("root");
        source = source.with_root_entries(vec![
            RemoteEntry::file(
                "file-1",
                "one.jpg",
                remote_file("rev-1", 3, 1_700_000_000_123_000_000),
            ),
            RemoteEntry::file(
                "file-2",
                "two.jpg",
                remote_file("rev-2", 4, 1_700_000_000_456_000_000),
            ),
        ]);
        source.files.insert("file-1".to_owned(), b"one".to_vec());
        source.files.insert("file-2".to_owned(), b"two!".to_vec());

        let report = execute(
            &source,
            &ExportOptions {
                to_dir: output_dir.clone(),
                state_db: state_db.clone(),
                dry_run: false,
                delete_missing: false,
                download_concurrency: 2,
                progress_mode: Mode::Quiet,
            },
        )
        .expect("parallel export should succeed");

        assert_eq!(report.downloaded, 2);
        assert_eq!(fs::read(output_dir.join("one.jpg"))?, b"one");
        assert_eq!(fs::read(output_dir.join("two.jpg"))?, b"two!");
        assert_eq!(
            SyncState::open_existing(&state_db)?.summary()?.object_count,
            2
        );
        Ok(())
    }

    #[test]
    fn execute_handles_missing_local_file_on_delete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        state.upsert_object(&StoredObject {
            path: "stale.jpg".to_owned(),
            remote_id: "old".to_owned(),
            revision_id: "rev-old".to_owned(),
            size: 3,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;

        let source = MemorySource::new("root").with_root_entries(Vec::new());
        let report = execute(
            &source,
            &ExportOptions {
                to_dir: output_dir.clone(),
                state_db: state_db.clone(),
                dry_run: false,
                delete_missing: true,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect("delete missing without local file should succeed");

        assert_eq!(report.deleted, 1);
        assert_eq!(
            SyncState::open_existing(&state_db)?.list_object_paths()?,
            Vec::<String>::new()
        );
        Ok(())
    }

    #[test]
    fn execute_updates_state_for_skipped_file_with_new_remote_id() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        let destination = output_dir.join("photo.jpg");
        fs::create_dir_all(&output_dir)?;
        fs::write(&destination, b"jpeg")?;
        super::set_mtime_ns(&destination, 1_700_000_000_123_000_000)?;
        state.upsert_object(&StoredObject {
            path: "photo.jpg".to_owned(),
            remote_id: "old-file".to_owned(),
            revision_id: "rev-1".to_owned(),
            size: 4,
            modified_at_ns: 1_700_000_000_123_000_000,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;

        let source = MemorySource::new("root").with_root_entries(vec![RemoteEntry::file(
            "new-file",
            "photo.jpg",
            remote_file("rev-1", 4, 1_700_000_000_999_000_000),
        )]);

        let report = execute(
            &source,
            &ExportOptions {
                to_dir: output_dir,
                state_db,
                dry_run: false,
                delete_missing: false,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect("skip should succeed");

        assert_eq!(report.skipped, 1);
        assert_eq!(
            SyncState::open_existing(&temp_dir.path().join("state.sqlite"))?
                .get_object("photo.jpg")?,
            Some(StoredObject {
                path: "photo.jpg".to_owned(),
                remote_id: "new-file".to_owned(),
                revision_id: "rev-1".to_owned(),
                size: 4,
                modified_at_ns: 1_700_000_000_999_000_000,
                sha1: Some("abc".to_owned()),
                original_modified_at_ns: None,
                capture_time_ns: None,
            })
        );
        Ok(())
    }

    #[test]
    fn execute_delete_missing_errors_when_stale_path_is_a_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        state.upsert_object(&StoredObject {
            path: "stale".to_owned(),
            remote_id: "old".to_owned(),
            revision_id: "rev-old".to_owned(),
            size: 0,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;
        fs::create_dir_all(output_dir.join("stale"))?;

        let source = MemorySource::new("root").with_root_entries(Vec::new());
        let error = execute(
            &source,
            &ExportOptions {
                to_dir: output_dir,
                state_db,
                dry_run: false,
                delete_missing: true,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect_err("directory delete should fail");

        assert!(error.to_string().contains("remove local file"));
        Ok(())
    }

    #[test]
    fn execute_errors_when_file_entry_is_missing_metadata() {
        let temp_dir = TempDir::new().expect("tempdir");
        let source = MemorySource::new("root").with_root_entries(vec![RemoteEntry {
            id: "file-1".to_owned(),
            name: "photo.jpg".to_owned(),
            kind: crate::types::EntryKind::File,
            file: None,
        }]);

        let error = execute(
            &source,
            &ExportOptions {
                to_dir: temp_dir.path().join("out"),
                state_db: temp_dir.path().join("state.sqlite"),
                dry_run: false,
                delete_missing: false,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect_err("missing file metadata should fail");

        assert!(error.to_string().contains("missing file metadata"));
    }

    #[test]
    fn execute_collects_open_file_errors_into_report() {
        let temp_dir = TempDir::new().expect("tempdir");
        let source = MemorySource {
            root_id: "root".to_owned(),
            children: HashMap::from([(
                "root".to_owned(),
                vec![RemoteEntry::file(
                    "file-1",
                    "photo.jpg",
                    remote_file("rev-1", 5, 1_700_000_000_123_000_000),
                )],
            )]),
            files: HashMap::new(),
            open_error: Some("boom".to_owned()),
        };

        let report = execute(
            &source,
            &ExportOptions {
                to_dir: temp_dir.path().join("out"),
                state_db: temp_dir.path().join("state.sqlite"),
                dry_run: false,
                delete_missing: false,
                download_concurrency: 1,
                progress_mode: Mode::Quiet,
            },
        )
        .expect("execute should succeed even when one file fails");

        assert_eq!(report.downloaded, 0);
        assert_eq!(report.failed_downloads.len(), 1);
        let failure = &report.failed_downloads[0];
        assert_eq!(failure.path, "photo.jpg");
        assert!(
            failure.error.contains("open remote file"),
            "unexpected failure message: {}",
            failure.error
        );
    }

    #[test]
    fn download_one_errors_when_parent_directory_cannot_be_created() {
        let temp_dir = TempDir::new().expect("tempdir");
        let root_path = temp_dir.path().join("out");
        fs::write(&root_path, b"not a directory").expect("root file");
        let state = SyncState::open(&temp_dir.path().join("state.sqlite")).expect("state");
        let source = MemorySource::new("root");
        let job = PendingDownload {
            rel_path: "nested/photo.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            file: remote_file("rev-1", 5, 1_700_000_000_123_000_000),
        };

        let mut reporter = Reporter::stderr(Mode::Quiet);
        let error = download_one(&source, &state, &root_path, &job, &mut reporter, 1, 1)
            .expect_err("parent directory creation should fail");
        assert!(error.to_string().contains("create parent directory"));
    }

    #[test]
    fn download_one_errors_when_destination_has_no_parent() {
        let temp_dir = TempDir::new().expect("tempdir");
        let state = SyncState::open(&temp_dir.path().join("state.sqlite")).expect("state");
        let mut source = MemorySource::new("root");
        source.files.insert("file-1".to_owned(), b"hello".to_vec());
        let job = PendingDownload {
            rel_path: String::new(),
            remote_id: "file-1".to_owned(),
            file: remote_file("rev-1", 5, 1_700_000_000_123_000_000),
        };

        let mut reporter = Reporter::stderr(Mode::Quiet);
        let error = download_one(&source, &state, Path::new(""), &job, &mut reporter, 1, 1)
            .expect_err("missing parent should fail");
        assert!(error.to_string().contains("destination missing parent"));
    }

    #[test]
    fn prune_empty_dirs_removes_empty_descendants_only() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path().join("out");
        let empty = root.join("2026/empty");
        let non_empty = root.join("2025");
        fs::create_dir_all(&empty)?;
        fs::create_dir_all(&non_empty)?;
        fs::write(non_empty.join("photo.jpg"), b"jpeg")?;

        prune_empty_dirs(&root)?;

        assert!(!empty.exists());
        assert!(non_empty.exists());
        assert!(root.exists());
        Ok(())
    }

    #[test]
    fn system_time_to_ns_and_same_second_cover_edge_cases() -> Result<()> {
        let time = UNIX_EPOCH + Duration::new(12, 345);
        assert_eq!(system_time_to_ns(time)?, 12_000_000_345);
        assert!(same_modified_second(1_999_999_999, 1_000_000_000));
        assert!(!same_modified_second(2_000_000_000, 1_000_000_000));

        let error = system_time_to_ns(UNIX_EPOCH - Duration::from_secs(1))
            .expect_err("pre-epoch time should fail");
        assert!(error.to_string().contains("before unix epoch"));
        Ok(())
    }

    #[test]
    fn prune_empty_dirs_ignores_missing_root() -> Result<()> {
        let temp_dir = TempDir::new()?;
        prune_empty_dirs(&temp_dir.path().join("missing"))?;
        Ok(())
    }

    #[test]
    fn effective_mtime_prefers_original_then_falls_back() {
        let original = RemoteFile {
            revision_id: "rev".to_owned(),
            size: 0,
            modified_at_ns: 200,
            sha1: None,
            original_modified_at_ns: Some(100),
            capture_time_ns: None,
        };
        assert_eq!(effective_mtime_ns(&original), 100);

        let no_original = RemoteFile {
            original_modified_at_ns: None,
            ..original.clone()
        };
        assert_eq!(effective_mtime_ns(&no_original), 200);
    }

    #[test]
    fn effective_birthtime_prefers_capture_then_modification_then_upload() {
        let everything = RemoteFile {
            revision_id: "rev".to_owned(),
            size: 0,
            modified_at_ns: 30,
            sha1: None,
            original_modified_at_ns: Some(20),
            capture_time_ns: Some(10),
        };
        assert_eq!(effective_birthtime_ns(&everything), 10);

        let no_capture = RemoteFile {
            capture_time_ns: None,
            ..everything.clone()
        };
        assert_eq!(effective_birthtime_ns(&no_capture), 20);

        let only_upload = RemoteFile {
            capture_time_ns: None,
            original_modified_at_ns: None,
            ..everything
        };
        assert_eq!(effective_birthtime_ns(&only_upload), 30);
    }

    #[test]
    fn apply_file_metadata_sets_mtime_to_original_when_available() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("photo.jpg");
        fs::write(&path, b"jpeg")?;

        let file = RemoteFile {
            revision_id: "rev".to_owned(),
            size: 4,
            modified_at_ns: 1_900_000_000_000_000_000,
            sha1: None,
            // Original modification at 2020-01-02T03:04:05 UTC.
            original_modified_at_ns: Some(1_577_934_245_000_000_000),
            capture_time_ns: None,
        };

        apply_file_metadata(&path, &file)?;

        let actual = system_time_to_ns(fs::metadata(&path)?.modified()?)?;
        assert!(
            same_modified_second(actual, 1_577_934_245_000_000_000),
            "expected mtime around 2020-01-02T03:04:05 UTC, got {actual}"
        );
        Ok(())
    }

    /// On macOS we additionally try to set the birthtime via `setattrlist`.
    /// This test only runs on macOS and is best-effort: if the underlying
    /// filesystem rejects the call (rare on a TempDir backed by APFS in a
    /// CI sandbox), we accept that silently rather than failing.
    #[cfg(target_os = "macos")]
    #[test]
    fn set_birthtime_ns_round_trips_on_macos() -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("photo.jpg");
        fs::write(&path, b"jpeg")?;

        // 2020-01-02T03:04:05 UTC.
        let target_ns: i64 = 1_577_934_245_000_000_000;
        if set_birthtime_ns(&path, target_ns).is_err() {
            // Some sandboxes refuse setattrlist; treat as inconclusive.
            return Ok(());
        }

        // `Metadata::created()` reads st_birthtime on macOS via the libc
        // backed std implementation. Some filesystems still expose the
        // post-set value at second granularity, so compare with the same
        // tolerance as for mtime.
        let metadata = fs::metadata(&path)?;
        let observed_seconds = metadata
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            // Fallback: read directly from raw stat fields.
            .unwrap_or_else(|| metadata.ctime());
        let expected_seconds = target_ns / 1_000_000_000;
        assert!(
            (observed_seconds - expected_seconds).abs() <= 1,
            "expected birthtime around {expected_seconds}s, got {observed_seconds}s"
        );
        Ok(())
    }

    #[test]
    fn repair_metadata_applies_recorded_timestamps_to_existing_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        // Pretend we already have a downloaded file with a wrong mtime.
        let rel_path = "2024/photo.jpg";
        let local_path = super::local_path(&output_dir, rel_path);
        fs::create_dir_all(local_path.parent().expect("parent"))?;
        fs::write(&local_path, b"jpeg")?;
        super::set_mtime_ns(&local_path, 1_900_000_000_000_000_000)?;

        // Record the right metadata in the state DB the way an `export`
        // run would after decoding XAttr.
        let target_ns = 1_577_934_245_000_000_000_i64; // 2020-01-02T03:04:05 UTC.
        state.upsert_object(&StoredObject {
            path: rel_path.to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "rev-1".to_owned(),
            size: 4,
            modified_at_ns: 1_900_000_000_000_000_000,
            sha1: None,
            original_modified_at_ns: Some(target_ns),
            capture_time_ns: None,
        })?;
        // Drop the connection so repair_metadata can open the DB freshly.
        drop(state);

        let report = repair_metadata(&RepairOptions {
            state_db: state_db.clone(),
            to_dir: output_dir.clone(),
            dry_run: false,
        })?;
        assert_eq!(report.considered, 1);
        assert_eq!(report.repaired, 1);
        assert_eq!(report.already_correct, 0);
        assert_eq!(report.missing_local, 0);
        assert!(report.failed.is_empty());

        let observed = system_time_to_ns(fs::metadata(&local_path)?.modified()?)?;
        assert!(
            same_modified_second(observed, target_ns),
            "expected mtime ~2020-01-02 UTC, got {observed}"
        );
        Ok(())
    }

    #[test]
    fn repair_metadata_skips_already_correct_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        let target_ns = 1_577_934_245_000_000_000_i64;
        let rel_path = "ok.jpg";
        let local_path = super::local_path(&output_dir, rel_path);
        fs::create_dir_all(&output_dir)?;
        fs::write(&local_path, b"ok")?;
        super::set_mtime_ns(&local_path, target_ns)?;
        state.upsert_object(&StoredObject {
            path: rel_path.to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "rev-1".to_owned(),
            size: 2,
            modified_at_ns: 1_900_000_000_000_000_000,
            sha1: None,
            original_modified_at_ns: Some(target_ns),
            capture_time_ns: None,
        })?;
        drop(state);

        let report = repair_metadata(&RepairOptions {
            state_db,
            to_dir: output_dir,
            dry_run: false,
        })?;
        assert_eq!(report.considered, 1);
        assert_eq!(report.repaired, 0);
        assert_eq!(report.already_correct, 1);
        Ok(())
    }

    #[test]
    fn repair_metadata_counts_missing_local_and_no_metadata_rows() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().join("out");
        fs::create_dir_all(&output_dir)?;
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        // Row 1: file recorded but not on disk anymore.
        state.upsert_object(&StoredObject {
            path: "gone.jpg".to_owned(),
            remote_id: "file-1".to_owned(),
            revision_id: "rev".to_owned(),
            size: 1,
            modified_at_ns: 1,
            sha1: None,
            original_modified_at_ns: Some(1),
            capture_time_ns: None,
        })?;
        // Row 2: file on disk but no usable timestamp anywhere.
        let rel_path = "no_ts.jpg";
        let local_path = super::local_path(&output_dir, rel_path);
        fs::write(&local_path, b"x")?;
        state.upsert_object(&StoredObject {
            path: rel_path.to_owned(),
            remote_id: "file-2".to_owned(),
            revision_id: "rev".to_owned(),
            size: 1,
            modified_at_ns: 0,
            sha1: None,
            original_modified_at_ns: None,
            capture_time_ns: None,
        })?;
        drop(state);

        let report = repair_metadata(&RepairOptions {
            state_db,
            to_dir: output_dir,
            dry_run: false,
        })?;
        assert_eq!(report.considered, 2);
        assert_eq!(report.repaired, 0);
        assert_eq!(report.missing_local, 1);
        assert_eq!(report.no_metadata, 1);
        Ok(())
    }

    #[test]
    fn file_already_at_target_metadata_returns_false_for_missing_file() {
        let temp_dir = TempDir::new().expect("tempdir");
        let path = temp_dir.path().join("does-not-exist");
        assert!(!file_already_at_target_metadata(&path, 1_000_000_000));
    }
}
