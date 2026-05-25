use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Human,
    Json,
    Quiet,
}

impl Mode {
    pub fn auto(stderr_is_terminal: bool) -> Self {
        if stderr_is_terminal {
            Self::Human
        } else {
            Self::Quiet
        }
    }

    pub fn default_for_stderr() -> Self {
        Self::auto(io::stderr().is_terminal())
    }
}

pub struct Reporter {
    mode: Mode,
    human: Option<HumanState>,
    finished: bool,
}

impl Reporter {
    pub fn stderr(mode: Mode) -> Self {
        let human = match mode {
            Mode::Human => Some(HumanState::stderr()),
            Mode::Json | Mode::Quiet => None,
        };
        Self {
            mode,
            human,
            finished: false,
        }
    }

    pub fn event(
        &mut self,
        phase: &str,
        status: &str,
        extra: impl IntoIterator<Item = (&'static str, Value)>,
    ) {
        let payload = build_event(phase, status, extra);
        match self.mode {
            Mode::Human => {
                if let Some(human) = self.human.as_mut() {
                    human.handle(&payload);
                }
            }
            Mode::Json => {
                let _ = emit_to(io::stderr(), &payload);
            }
            Mode::Quiet => {}
        }
    }

    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(human) = self.human.as_mut() {
            human.finish();
        }
    }
}

impl Drop for Reporter {
    fn drop(&mut self) {
        self.finish();
    }
}

fn build_event(
    phase: &str,
    status: &str,
    extra: impl IntoIterator<Item = (&'static str, Value)>,
) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("type".to_owned(), json!("progress"));
    object.insert("phase".to_owned(), json!(phase));
    object.insert("status".to_owned(), json!(status));
    for (key, value) in extra {
        object.insert(key.to_owned(), value);
    }
    Value::Object(object)
}

fn emit_to(mut writer: impl Write, payload: &Value) -> io::Result<()> {
    writeln!(writer, "{payload}")
}

#[derive(Debug)]
struct HumanState {
    tree_spinner: Option<ProgressBar>,
    tree_share_name: Option<String>,
    file_bar: Option<ProgressBar>,
    batch_bar: Option<ProgressBar>,
    tree_files: Option<u64>,
    skipped_files: u64,
    planned_downloads: u64,
    started_downloads: u64,
    batch_total_files: u64,
    batch_completed_files: u64,
    batch_total_bytes: u64,
    batch_completed_bytes: u64,
}

impl HumanState {
    fn stderr() -> Self {
        Self {
            tree_spinner: None,
            tree_share_name: None,
            file_bar: None,
            batch_bar: None,
            tree_files: None,
            skipped_files: 0,
            planned_downloads: 0,
            started_downloads: 0,
            batch_total_files: 0,
            batch_completed_files: 0,
            batch_total_bytes: 0,
            batch_completed_bytes: 0,
        }
    }

    fn handle(&mut self, payload: &Value) {
        let Some(action) = action_from_event(payload) else {
            return;
        };

        match action {
            HumanAction::DownloadBatchStart {
                files,
                concurrency,
                total_bytes,
            } => {
                let files = files.unwrap_or(0);
                let concurrency = concurrency.unwrap_or(1);
                let total_bytes = total_bytes.unwrap_or(0);
                self.batch_total_files = files;
                self.batch_completed_files = 0;
                self.batch_total_bytes = total_bytes;
                self.batch_completed_bytes = 0;
                let length = if total_bytes > 0 { total_bytes } else { files };
                let bar = ProgressBar::with_draw_target(Some(length), ProgressDrawTarget::stderr());
                bar.set_style(file_style());
                bar.enable_steady_tick(Duration::from_millis(120));
                bar.set_message(batch_progress_message(
                    0,
                    files,
                    0,
                    total_bytes,
                    Some(concurrency),
                    None,
                ));
                self.batch_bar = Some(bar);
            }
            HumanAction::DownloadBatchProgress {
                path,
                completed_files,
                total_files,
                completed_bytes,
                total_bytes,
            } => {
                self.batch_completed_files = completed_files.unwrap_or(self.batch_completed_files);
                self.batch_total_files = total_files.unwrap_or(self.batch_total_files);
                self.batch_completed_bytes = completed_bytes.unwrap_or(self.batch_completed_bytes);
                self.batch_total_bytes = total_bytes.unwrap_or(self.batch_total_bytes);
                if let Some(bar) = self.batch_bar.as_ref() {
                    let length = if self.batch_total_bytes > 0 {
                        self.batch_total_bytes
                    } else {
                        self.batch_total_files
                    };
                    let position = if self.batch_total_bytes > 0 {
                        self.batch_completed_bytes
                    } else {
                        self.batch_completed_files
                    };
                    bar.set_length(length);
                    bar.set_position(position);
                    bar.set_message(batch_progress_message(
                        self.batch_completed_files,
                        self.batch_total_files,
                        self.batch_completed_bytes,
                        self.batch_total_bytes,
                        None,
                        path.as_deref(),
                    ));
                }
            }
            HumanAction::DownloadBatchComplete {
                completed_files,
                total_files,
                completed_bytes,
                total_bytes,
            } => {
                self.batch_completed_files = completed_files.unwrap_or(self.batch_completed_files);
                self.batch_total_files = total_files.unwrap_or(self.batch_total_files);
                self.batch_completed_bytes = completed_bytes.unwrap_or(self.batch_completed_bytes);
                self.batch_total_bytes = total_bytes.unwrap_or(self.batch_total_bytes);
                if let Some(bar) = self.batch_bar.take() {
                    let length = if self.batch_total_bytes > 0 {
                        self.batch_total_bytes
                    } else {
                        self.batch_total_files
                    };
                    let position = if self.batch_total_bytes > 0 {
                        self.batch_completed_bytes
                    } else {
                        self.batch_completed_files
                    };
                    bar.set_length(length);
                    bar.set_position(position);
                    bar.finish_and_clear();
                }
            }
            HumanAction::TreeLoadStart { share_name } => {
                self.tree_share_name = share_name.clone();
                let spinner = ProgressBar::new_spinner();
                spinner.set_draw_target(ProgressDrawTarget::stderr());
                spinner.set_style(spinner_style());
                spinner.enable_steady_tick(Duration::from_millis(120));
                spinner.set_message(match share_name {
                    Some(name) => format!("Loading remote tree for {name}"),
                    None => "Loading remote tree".to_owned(),
                });
                self.tree_spinner = Some(spinner);
            }
            HumanAction::TreeLoadProgress {
                folders,
                files,
                pages,
                items,
            } => {
                if let Some(spinner) = self.tree_spinner.as_ref() {
                    spinner.set_message(tree_progress_message(
                        self.tree_share_name.as_deref(),
                        folders,
                        files,
                        pages,
                        items,
                    ));
                }
            }
            HumanAction::TreeLoadComplete { folders, files } => {
                self.tree_files = files;
                let message = format!(
                    "Loaded remote tree: {} folders, {} files",
                    folders.unwrap_or(0),
                    files.unwrap_or(0)
                );
                if let Some(spinner) = self.tree_spinner.take() {
                    spinner.finish_with_message(message);
                } else {
                    self.println(message);
                }
            }
            HumanAction::DownloadStart {
                path,
                index,
                total,
                size,
            } => {
                self.started_downloads += 1;
                let total_bytes = size.unwrap_or(0);
                let bar = self.file_bar.get_or_insert_with(|| {
                    let bar = ProgressBar::with_draw_target(
                        Some(total_bytes),
                        ProgressDrawTarget::stderr(),
                    );
                    bar.set_style(file_style());
                    bar.enable_steady_tick(Duration::from_millis(120));
                    bar
                });
                bar.set_length(total_bytes);
                bar.set_position(0);
                bar.set_message(file_progress_message(
                    path.as_deref(),
                    index,
                    total,
                    0,
                    size,
                ));
            }
            HumanAction::DownloadProgress {
                path,
                index,
                total,
                bytes,
                size,
            } => {
                if let Some(bar) = self.file_bar.as_ref() {
                    if let Some(size) = size {
                        bar.set_length(size);
                    }
                    bar.set_position(bytes.unwrap_or(0));
                    bar.set_message(file_progress_message(
                        path.as_deref(),
                        index,
                        total,
                        bytes.unwrap_or(0),
                        size,
                    ));
                }
            }
            HumanAction::DownloadFinalizing {
                path,
                index,
                total,
                bytes,
                size,
            } => {
                if let Some(bar) = self.file_bar.as_ref() {
                    if let Some(size) = size {
                        bar.set_length(size);
                    }
                    bar.set_position(bytes.unwrap_or_else(|| bar.position()));
                    let path = path.as_deref().unwrap_or("file");
                    let count = match (index, total) {
                        (Some(index), Some(total)) => format!("File {index}/{total}"),
                        _ => "Downloading".to_owned(),
                    };
                    bar.set_message(format!("Finalizing {count} {path}"));
                }
            }
            HumanAction::DownloadComplete {
                path,
                index,
                total,
                bytes,
            } => {
                if self.batch_bar.is_some() {
                    return;
                }
                if let Some(bar) = self.file_bar.take() {
                    bar.set_position(bytes.unwrap_or_else(|| bar.length().unwrap_or(0)));
                    bar.finish_and_clear();
                }

                if let (Some(done), Some(total)) = (index, total)
                    && done >= total
                {
                    self.println(match total {
                        1 => "Downloaded 1 file".to_owned(),
                        count => format!("Downloaded {count} files"),
                    });
                } else if let Some(path) = path {
                    self.println(format!("Downloaded {path}"));
                }
            }
            HumanAction::DownloadPlanned { path } => {
                self.planned_downloads += 1;
                self.println(format!("Would download {path}"));
            }
            HumanAction::DeletePlanned { path } => {
                self.println(format!("Would delete {path}"));
            }
            HumanAction::DeleteComplete { path } => {
                self.println(format!("Deleted {path}"));
            }
            HumanAction::DownloadSkipped => {
                self.skipped_files += 1;
            }
        }
    }

    fn finish(&mut self) {
        if let Some(spinner) = self.tree_spinner.take() {
            spinner.finish_and_clear();
        }
        if let Some(bar) = self.file_bar.take() {
            bar.finish_and_clear();
        }
        if let Some(bar) = self.batch_bar.take() {
            bar.finish_and_clear();
        }
        if self.started_downloads == 0 && self.planned_downloads == 0 {
            match self.tree_files {
                Some(0) => self.println("No remote files found".to_owned()),
                Some(_) if self.skipped_files > 0 => self.println(format!(
                    "All files already up to date ({} skipped)",
                    self.skipped_files
                )),
                _ => {}
            }
        }
    }

    fn println(&self, message: String) {
        if let Some(bar) = self
            .batch_bar
            .as_ref()
            .or(self.file_bar.as_ref())
            .or(self.tree_spinner.as_ref())
        {
            bar.println(message);
        } else {
            eprintln!("{message}");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HumanAction {
    DownloadBatchStart {
        files: Option<u64>,
        concurrency: Option<u64>,
        total_bytes: Option<u64>,
    },
    DownloadBatchProgress {
        path: Option<String>,
        completed_files: Option<u64>,
        total_files: Option<u64>,
        completed_bytes: Option<u64>,
        total_bytes: Option<u64>,
    },
    DownloadBatchComplete {
        completed_files: Option<u64>,
        total_files: Option<u64>,
        completed_bytes: Option<u64>,
        total_bytes: Option<u64>,
    },
    TreeLoadStart {
        share_name: Option<String>,
    },
    TreeLoadProgress {
        folders: Option<u64>,
        files: Option<u64>,
        pages: Option<u64>,
        items: Option<u64>,
    },
    TreeLoadComplete {
        folders: Option<u64>,
        files: Option<u64>,
    },
    DownloadStart {
        path: Option<String>,
        index: Option<u64>,
        total: Option<u64>,
        size: Option<u64>,
    },
    DownloadProgress {
        path: Option<String>,
        index: Option<u64>,
        total: Option<u64>,
        bytes: Option<u64>,
        size: Option<u64>,
    },
    DownloadFinalizing {
        path: Option<String>,
        index: Option<u64>,
        total: Option<u64>,
        bytes: Option<u64>,
        size: Option<u64>,
    },
    DownloadComplete {
        path: Option<String>,
        index: Option<u64>,
        total: Option<u64>,
        bytes: Option<u64>,
    },
    DownloadPlanned {
        path: String,
    },
    DeletePlanned {
        path: String,
    },
    DeleteComplete {
        path: String,
    },
    DownloadSkipped,
}

fn action_from_event(payload: &Value) -> Option<HumanAction> {
    let phase = payload.get("phase")?.as_str()?;
    let status = payload.get("status")?.as_str()?;

    match (phase, status) {
        ("download_batch", "start") => Some(HumanAction::DownloadBatchStart {
            files: u64_field(payload, "files"),
            concurrency: u64_field(payload, "concurrency"),
            total_bytes: u64_field(payload, "total_bytes"),
        }),
        ("download_batch", "progress") => Some(HumanAction::DownloadBatchProgress {
            path: string_field(payload, "path"),
            completed_files: u64_field(payload, "completed_files"),
            total_files: u64_field(payload, "total_files"),
            completed_bytes: u64_field(payload, "completed_bytes"),
            total_bytes: u64_field(payload, "total_bytes"),
        }),
        ("download_batch", "complete") => Some(HumanAction::DownloadBatchComplete {
            completed_files: u64_field(payload, "completed_files"),
            total_files: u64_field(payload, "total_files"),
            completed_bytes: u64_field(payload, "completed_bytes"),
            total_bytes: u64_field(payload, "total_bytes"),
        }),
        ("tree_load", "start") => Some(HumanAction::TreeLoadStart {
            share_name: string_field(payload, "share_name"),
        }),
        ("tree_load", "progress") => Some(HumanAction::TreeLoadProgress {
            folders: u64_field(payload, "folders"),
            files: u64_field(payload, "files"),
            pages: u64_field(payload, "pages"),
            items: u64_field(payload, "items"),
        }),
        ("tree_load", "complete") => Some(HumanAction::TreeLoadComplete {
            folders: u64_field(payload, "folders"),
            files: u64_field(payload, "files"),
        }),
        ("download", "start") => Some(HumanAction::DownloadStart {
            path: string_field(payload, "path"),
            index: u64_field(payload, "index"),
            total: u64_field(payload, "total"),
            size: u64_field(payload, "size"),
        }),
        ("download", "progress") => Some(HumanAction::DownloadProgress {
            path: string_field(payload, "path"),
            index: u64_field(payload, "index"),
            total: u64_field(payload, "total"),
            bytes: u64_field(payload, "bytes"),
            size: u64_field(payload, "size"),
        }),
        ("download", "finalizing") => Some(HumanAction::DownloadFinalizing {
            path: string_field(payload, "path"),
            index: u64_field(payload, "index"),
            total: u64_field(payload, "total"),
            bytes: u64_field(payload, "bytes"),
            size: u64_field(payload, "size"),
        }),
        ("download", "complete") => Some(HumanAction::DownloadComplete {
            path: string_field(payload, "path"),
            index: u64_field(payload, "index"),
            total: u64_field(payload, "total"),
            bytes: u64_field(payload, "bytes"),
        }),
        ("download", "planned") => Some(HumanAction::DownloadPlanned {
            path: string_field(payload, "path")?,
        }),
        ("delete", "planned") => Some(HumanAction::DeletePlanned {
            path: string_field(payload, "path")?,
        }),
        ("delete", "complete") => Some(HumanAction::DeleteComplete {
            path: string_field(payload, "path")?,
        }),
        ("download", "skipped") => Some(HumanAction::DownloadSkipped),
        _ => None,
    }
}

fn string_field(payload: &Value, key: &str) -> Option<String> {
    payload.get(key)?.as_str().map(ToOwned::to_owned)
}

fn u64_field(payload: &Value, key: &str) -> Option<u64> {
    payload.get(key)?.as_u64()
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {msg}").expect("valid spinner style")
}

fn tree_progress_message(
    share_name: Option<&str>,
    folders: Option<u64>,
    files: Option<u64>,
    pages: Option<u64>,
    items: Option<u64>,
) -> String {
    let pages = pages.unwrap_or(0);
    let items = items.unwrap_or(0);
    let folders = folders.unwrap_or(0);
    let files = files.unwrap_or(0);
    match share_name {
        Some(name) => format!(
            "Loading remote tree for {name} ({pages} pages, {items} items seen, {folders} folders, {files} files)"
        ),
        None => format!(
            "Loading remote tree ({pages} pages, {items} items seen, {folders} folders, {files} files)"
        ),
    }
}

fn file_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.cyan} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {msg}",
    )
    .expect("valid file style")
    .progress_chars("=> ")
}

fn batch_progress_message(
    completed_files: u64,
    total_files: u64,
    completed_bytes: u64,
    total_bytes: u64,
    concurrency: Option<u64>,
    path: Option<&str>,
) -> String {
    let workers = concurrency
        .map(|value| format!(", {value} workers"))
        .unwrap_or_default();
    let amount = if total_bytes > 0 {
        format!(
            "{} / {}",
            human_bytes(completed_bytes),
            human_bytes(total_bytes)
        )
    } else {
        format!("{completed_files} / {total_files} files")
    };
    let tail = path
        .map(|value| format!(", last: {value}"))
        .unwrap_or_default();
    format!("Downloaded {completed_files}/{total_files} files ({amount}{workers}{tail})")
}

fn file_progress_message(
    path: Option<&str>,
    index: Option<u64>,
    total: Option<u64>,
    bytes: u64,
    size: Option<u64>,
) -> String {
    let path = path.unwrap_or("file");
    let count = match (index, total) {
        (Some(index), Some(total)) => format!("File {index}/{total}"),
        _ => "Downloading".to_owned(),
    };
    let amount = match size {
        Some(size) => format!("{} / {}", human_bytes(bytes), human_bytes(size)),
        None => human_bytes(bytes),
    };
    format!("{count} {path} ({amount})")
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use std::io::IsTerminal;

    use serde_json::json;

    use super::{
        HumanAction, HumanState, Mode, Reporter, action_from_event, batch_progress_message,
        build_event, emit_to, file_progress_message, human_bytes, tree_progress_message,
    };

    #[test]
    fn emit_to_writes_json_line() {
        let mut output = Vec::new();
        emit_to(&mut output, &json!({"ok": true})).expect("emit");
        assert_eq!(String::from_utf8(output).expect("utf8"), "{\"ok\":true}\n");
    }

    #[test]
    fn reporter_json_mode_emits_events_without_human_state() {
        let mut reporter = Reporter::stderr(Mode::Json);
        reporter.event("download", "start", [("path", json!("2026/photo.jpg"))]);
        reporter.finish();
    }

    #[test]
    fn build_event_includes_core_and_extra_fields() {
        let payload = build_event("download", "start", [("path", json!("2026/photo.jpg"))]);
        assert_eq!(
            payload,
            json!({
                "type": "progress",
                "phase": "download",
                "status": "start",
                "path": "2026/photo.jpg",
            })
        );
    }

    #[test]
    fn auto_mode_uses_human_for_terminals() {
        assert_eq!(Mode::auto(true), Mode::Human);
        assert_eq!(Mode::auto(false), Mode::Quiet);
    }

    #[test]
    fn default_mode_matches_current_stderr_terminal_state() {
        assert_eq!(
            Mode::default_for_stderr(),
            Mode::auto(std::io::stderr().is_terminal())
        );
    }

    #[test]
    fn action_from_event_extracts_tree_load_start() {
        let action = action_from_event(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "start",
            "share_name": "PhotosRoot",
        }));

        assert_eq!(
            action,
            Some(HumanAction::TreeLoadStart {
                share_name: Some("PhotosRoot".to_owned()),
            })
        );
    }

    #[test]
    fn action_from_event_extracts_tree_load_details() {
        let action = action_from_event(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "complete",
            "folders": 4,
            "files": 12,
        }));

        assert_eq!(
            action,
            Some(HumanAction::TreeLoadComplete {
                folders: Some(4),
                files: Some(12),
            })
        );
    }

    #[test]
    fn action_from_event_extracts_tree_load_progress() {
        let action = action_from_event(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "progress",
            "folders": 7,
            "files": 42,
        }));

        assert_eq!(
            action,
            Some(HumanAction::TreeLoadProgress {
                folders: Some(7),
                files: Some(42),
                pages: None,
                items: None,
            })
        );
    }

    #[test]
    fn action_from_event_extracts_download_completion_details() {
        let action = action_from_event(&json!({
            "type": "progress",
            "phase": "download",
            "status": "complete",
            "path": "2026/photo.jpg",
            "index": 2,
            "total": 5,
        }));

        assert_eq!(
            action,
            Some(HumanAction::DownloadComplete {
                path: Some("2026/photo.jpg".to_owned()),
                index: Some(2),
                total: Some(5),
                bytes: None,
            })
        );
    }

    #[test]
    fn action_from_event_extracts_download_batch_details() {
        let start = action_from_event(&json!({
            "type": "progress",
            "phase": "download_batch",
            "status": "start",
            "files": 10,
            "concurrency": 8,
            "total_bytes": 4096,
        }));
        assert_eq!(
            start,
            Some(HumanAction::DownloadBatchStart {
                files: Some(10),
                concurrency: Some(8),
                total_bytes: Some(4096),
            })
        );

        let progress = action_from_event(&json!({
            "type": "progress",
            "phase": "download_batch",
            "status": "progress",
            "path": "2026/photo.jpg",
            "completed_files": 2,
            "total_files": 10,
            "completed_bytes": 1024,
            "total_bytes": 4096,
        }));
        assert_eq!(
            progress,
            Some(HumanAction::DownloadBatchProgress {
                path: Some("2026/photo.jpg".to_owned()),
                completed_files: Some(2),
                total_files: Some(10),
                completed_bytes: Some(1024),
                total_bytes: Some(4096),
            })
        );
    }

    #[test]
    fn action_from_event_extracts_download_progress_details() {
        let action = action_from_event(&json!({
            "type": "progress",
            "phase": "download",
            "status": "progress",
            "path": "2026/photo.jpg",
            "index": 2,
            "total": 5,
            "bytes": 512,
            "size": 1024,
        }));

        assert_eq!(
            action,
            Some(HumanAction::DownloadProgress {
                path: Some("2026/photo.jpg".to_owned()),
                index: Some(2),
                total: Some(5),
                bytes: Some(512),
                size: Some(1024),
            })
        );
    }

    #[test]
    fn action_from_event_extracts_download_finalizing_details() {
        let action = action_from_event(&json!({
            "type": "progress",
            "phase": "download",
            "status": "finalizing",
            "path": "2026/photo.jpg",
            "index": 2,
            "total": 5,
            "bytes": 1024,
            "size": 2048,
        }));

        assert_eq!(
            action,
            Some(HumanAction::DownloadFinalizing {
                path: Some("2026/photo.jpg".to_owned()),
                index: Some(2),
                total: Some(5),
                bytes: Some(1024),
                size: Some(2048),
            })
        );
    }

    #[test]
    fn action_from_event_extracts_planned_delete_and_skip_variants() {
        assert_eq!(
            action_from_event(&json!({
                "type": "progress",
                "phase": "download",
                "status": "planned",
                "path": "2026/photo.jpg",
            })),
            Some(HumanAction::DownloadPlanned {
                path: "2026/photo.jpg".to_owned(),
            })
        );
        assert_eq!(
            action_from_event(&json!({
                "type": "progress",
                "phase": "delete",
                "status": "planned",
                "path": "stale.jpg",
            })),
            Some(HumanAction::DeletePlanned {
                path: "stale.jpg".to_owned(),
            })
        );
        assert_eq!(
            action_from_event(&json!({
                "type": "progress",
                "phase": "delete",
                "status": "complete",
                "path": "stale.jpg",
            })),
            Some(HumanAction::DeleteComplete {
                path: "stale.jpg".to_owned(),
            })
        );
        assert_eq!(
            action_from_event(&json!({
                "type": "progress",
                "phase": "download",
                "status": "skipped",
            })),
            Some(HumanAction::DownloadSkipped)
        );
    }

    #[test]
    fn action_from_event_ignores_unknown_payloads() {
        assert_eq!(
            action_from_event(&json!({
                "type": "progress",
                "phase": "download",
                "status": "mystery",
            })),
            None
        );
        assert_eq!(action_from_event(&json!({})), None);
    }

    #[test]
    fn human_state_ignores_unknown_payloads() {
        let mut state = HumanState::stderr();
        state.handle(&json!({}));
        state.finish();
    }

    #[test]
    fn human_bytes_formats_binary_units() {
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
    }

    #[test]
    fn file_progress_message_includes_counts_and_sizes() {
        assert_eq!(
            file_progress_message(Some("2026/photo.jpg"), Some(2), Some(5), 512, Some(1024)),
            "File 2/5 2026/photo.jpg (512 B / 1.0 KiB)"
        );
    }

    #[test]
    fn file_progress_message_falls_back_without_path_or_size() {
        assert_eq!(
            file_progress_message(None, None, None, 512, None),
            "Downloading file (512 B)"
        );
    }

    #[test]
    fn batch_progress_message_includes_counts_and_bytes() {
        assert_eq!(
            batch_progress_message(2, 10, 1024, 4096, Some(8), Some("2026/photo.jpg")),
            "Downloaded 2/10 files (1.0 KiB / 4.0 KiB, 8 workers, last: 2026/photo.jpg)"
        );
    }

    #[test]
    fn tree_progress_message_includes_counts() {
        assert_eq!(
            tree_progress_message(Some("PhotosRoot"), Some(7), Some(42), Some(3), Some(150)),
            "Loading remote tree for PhotosRoot (3 pages, 150 items seen, 7 folders, 42 files)"
        );
        assert_eq!(
            tree_progress_message(None, Some(1), Some(2), Some(1), Some(2)),
            "Loading remote tree (1 pages, 2 items seen, 1 folders, 2 files)"
        );
    }

    #[test]
    fn human_state_reports_up_to_date_when_everything_is_skipped() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "start",
            "share_name": "PhotosRoot",
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "complete",
            "folders": 2,
            "files": 3,
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "skipped",
            "path": "2026/photo.jpg",
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "skipped",
            "path": "2026/other.jpg",
        }));
        state.finish();
    }

    #[test]
    fn human_state_reports_when_remote_tree_is_empty() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "complete",
            "folders": 0,
            "files": 0,
        }));
        state.finish();
    }

    #[test]
    fn human_state_updates_spinner_for_tree_progress() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "start",
            "share_name": "PhotosRoot",
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "progress",
            "folders": 7,
            "files": 42,
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "complete",
            "folders": 7,
            "files": 42,
        }));
        state.finish();
    }

    #[test]
    fn human_state_handles_download_lifecycle() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "start",
            "path": "2026/photo.jpg",
            "index": 1,
            "total": 1,
            "size": 1024,
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "progress",
            "path": "2026/photo.jpg",
            "index": 1,
            "total": 1,
            "bytes": 512,
            "size": 1024,
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "complete",
            "path": "2026/photo.jpg",
            "index": 1,
            "total": 1,
            "bytes": 1024,
        }));
        state.finish();
    }

    #[test]
    fn human_state_handles_download_finalizing() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "start",
            "path": "2026/video.mp4",
            "index": 1,
            "total": 3,
            "size": 2048,
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "finalizing",
            "path": "2026/video.mp4",
            "index": 1,
            "total": 3,
            "bytes": 1536,
            "size": 2048,
        }));

        let bar = state.file_bar.as_ref().expect("progress bar");
        assert_eq!(bar.length(), Some(2048));
        assert_eq!(bar.position(), 1536);

        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "complete",
            "path": "2026/video.mp4",
            "index": 1,
            "total": 3,
            "bytes": 2048,
        }));
        state.finish();
    }

    #[test]
    fn human_state_handles_batch_download_progress() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "download_batch",
            "status": "start",
            "files": 3,
            "concurrency": 2,
            "total_bytes": 2048,
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "download_batch",
            "status": "progress",
            "path": "2026/photo.jpg",
            "completed_files": 1,
            "total_files": 3,
            "completed_bytes": 1024,
            "total_bytes": 2048,
        }));

        let bar = state.batch_bar.as_ref().expect("batch progress bar");
        assert_eq!(bar.length(), Some(2048));
        assert_eq!(bar.position(), 1024);

        state.handle(&json!({
            "type": "progress",
            "phase": "download_batch",
            "status": "complete",
            "completed_files": 3,
            "total_files": 3,
            "completed_bytes": 2048,
            "total_bytes": 2048,
        }));
        assert!(state.batch_bar.is_none());
        state.finish();
    }

    #[test]
    fn human_state_handles_batch_progress_without_byte_totals() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "download_batch",
            "status": "start",
            "files": 3,
            "concurrency": 2,
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "download_batch",
            "status": "progress",
            "completed_files": 1,
            "total_files": 3,
        }));

        let bar = state.batch_bar.as_ref().expect("batch progress bar");
        assert_eq!(bar.length(), Some(3));
        assert_eq!(bar.position(), 1);

        state.handle(&json!({
            "type": "progress",
            "phase": "download_batch",
            "status": "complete",
            "completed_files": 3,
            "total_files": 3,
        }));
        assert!(state.batch_bar.is_none());
        state.finish();
    }

    #[test]
    fn human_state_tree_spinner_and_println_cover_no_share_message() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "tree_load",
            "status": "start",
        }));
        state.println("still scanning".to_owned());
        state.finish();
    }

    #[test]
    fn human_state_handles_planned_and_delete_events() {
        let mut state = HumanState::stderr();
        state.handle(&json!({
            "type": "progress",
            "phase": "download",
            "status": "planned",
            "path": "2026/photo.jpg",
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "delete",
            "status": "planned",
            "path": "stale.jpg",
        }));
        state.handle(&json!({
            "type": "progress",
            "phase": "delete",
            "status": "complete",
            "path": "stale.jpg",
        }));
        state.finish();
    }

    #[test]
    fn reporter_finish_is_idempotent() {
        let mut reporter = Reporter::stderr(Mode::Human);
        reporter.event(
            "tree_load",
            "complete",
            [("folders", json!(1)), ("files", json!(0))],
        );
        reporter.finish();
        reporter.finish();
    }
}
