pub mod accounts;
pub mod backend;
pub mod cli;
pub mod export;
pub mod paths;
pub mod progress;
pub mod signals;
pub mod state;
pub mod types;

use std::io::IsTerminal;
use std::io::{self, Write};

use anyhow::Result;

use crate::backend::proton::{LoginOutput, ShareInfo};
use crate::cli::{Cli, Command, LoginCommand, ProgressMode, SharesCommand};
use crate::export::ExportOptions;
use crate::progress::Mode as ProgressOutputMode;

pub fn run(cli: Cli) -> Result<i32> {
    let mut stdout = io::stdout();
    run_with_writer(
        cli,
        &mut stdout,
        crate::backend::proton::login,
        crate::backend::proton::list_shares,
    )
}

pub fn install_signal_handler() -> Result<()> {
    signals::install()
}

fn run_with_writer<W, LF, SF>(cli: Cli, out: &mut W, login: LF, list_shares: SF) -> Result<i32>
where
    W: Write,
    LF: Fn(&LoginCommand) -> Result<LoginOutput>,
    SF: Fn(&SharesCommand) -> Result<Vec<ShareInfo>>,
{
    match cli.command {
        Command::Export(command) => {
            let progress_mode = resolve_progress_mode(command.progress);
            let opened = backend::open(&command.source, progress_mode)?;
            let state_db = command
                .state_db
                .or(opened.default_state_db)
                .ok_or_else(|| anyhow::anyhow!("`--state-db` is required for this source"))?;
            let options = ExportOptions {
                to_dir: command.to,
                state_db,
                dry_run: command.dry_run,
                delete_missing: command.delete_missing,
                download_concurrency: command.download_concurrency,
                progress_mode,
            };

            let report = export::execute(opened.source.as_ref(), &options)?;
            if options.dry_run {
                let line = format!(
                    "dry-run backend={} root={} dirs={} files={} would_download={} would_delete={} skipped={}",
                    opened.source.backend_name(),
                    opened.source.root_id(),
                    report.listed_dirs,
                    report.listed_files,
                    report.would_download,
                    report.would_delete,
                    report.skipped,
                );
                writeln!(out, "{line}")?;
                Ok(0)
            } else {
                let failed = report.failed_downloads.len();
                let line = format!(
                    "export backend={} root={} dirs={} files={} downloaded={} deleted={} skipped={} failed={}",
                    opened.source.backend_name(),
                    opened.source.root_id(),
                    report.listed_dirs,
                    report.listed_files,
                    report.downloaded,
                    report.deleted,
                    report.skipped,
                    failed,
                );
                writeln!(out, "{line}")?;
                if failed > 0 {
                    writeln!(
                        out,
                        "{} file(s) could not be downloaded. They will be retried on the next run.",
                        failed
                    )?;
                    let preview = report.failed_downloads.iter().take(20);
                    for failure in preview {
                        writeln!(out, "  failed: {} -- {}", failure.path, failure.error)?;
                    }
                    if failed > 20 {
                        writeln!(out, "  ... and {} more", failed - 20)?;
                    }
                    Ok(2)
                } else {
                    Ok(0)
                }
            }
        }
        Command::Login(command) => {
            let result = login(&command)?;
            writeln!(out, "credentials={}", result.credentials_path.display())?;
            print_shares(out, &result.shares)?;
            Ok(0)
        }
        Command::Shares(command) => {
            let shares = list_shares(&command)?;
            print_shares(out, &shares)?;
            Ok(0)
        }
        Command::State(command) => {
            let state = state::SyncState::open_existing(&command.state_db)?;
            let summary = state.summary()?;
            let backend = summary.backend_name.unwrap_or_else(|| "-".to_owned());
            let root_id = summary.root_id.unwrap_or_else(|| "-".to_owned());
            let updated_unix = summary
                .updated_unix
                .map_or_else(|| "-".to_owned(), |value| value.to_string());
            writeln!(out, "state_db={}", command.state_db.display())?;
            writeln!(out, "backend={backend}")?;
            writeln!(out, "root_id={root_id}")?;
            writeln!(out, "objects={}", summary.object_count)?;
            writeln!(out, "updated_unix={updated_unix}")?;
            Ok(0)
        }
    }
}

fn resolve_progress_mode(mode: ProgressMode) -> ProgressOutputMode {
    match mode {
        ProgressMode::Auto => ProgressOutputMode::auto(io::stderr().is_terminal()),
        ProgressMode::Human => ProgressOutputMode::Human,
        ProgressMode::Json => ProgressOutputMode::Json,
        ProgressMode::Off => ProgressOutputMode::Quiet,
    }
}

fn print_shares<W: Write>(out: &mut W, shares: &[backend::proton::ShareInfo]) -> Result<()> {
    const HEADER: &str = "Name\tShareID\tLinkID\tVolumeID\tType\tState\tFlags\tCreator";
    writeln!(out, "{HEADER}")?;
    if shares.is_empty() {
        writeln!(out, "(no shares found)")?;
        return Ok(());
    }
    for share in shares {
        let row = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            share.name,
            share.share_id,
            share.link_id,
            share.volume_id,
            share.share_type,
            share.state,
            share.flags,
            share.creator,
        );
        writeln!(out, "{row}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::IsTerminal;
    use std::path::PathBuf;

    use anyhow::{Result, anyhow};
    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::{print_shares, resolve_progress_mode, run_with_writer};
    use crate::backend::proton::{LinkMetadataMode, LoginOutput, ShareInfo};
    use crate::cli::{
        Cli, Command, ExportCommand, LoginCommand, ManifestSourceArgs, ProgressMode, SharesCommand,
        SourceCommand, StateCommand,
    };
    use crate::progress::Mode as ProgressOutputMode;
    use crate::state::SyncState;

    fn share(name: &str, id: &str) -> ShareInfo {
        ShareInfo {
            name: name.to_owned(),
            share_id: id.to_owned(),
            link_id: "link".to_owned(),
            volume_id: "volume".to_owned(),
            share_type: "device".to_owned(),
            state: "active".to_owned(),
            flags: "none".to_owned(),
            creator: "user@example.com".to_owned(),
            metadata_mode: LinkMetadataMode::Drive,
        }
    }

    fn write_manifest(temp_dir: &TempDir) -> Result<PathBuf> {
        let source = temp_dir.path().join("photo.jpg");
        fs::write(&source, b"jpeg")?;
        let manifest = temp_dir.path().join("manifest.json");
        let manifest_json = format!(
            r#"{{
  "root_id": "photos-root",
  "children": [
    {{
      "kind": "file",
      "id": "file-1",
      "name": "photo.jpg",
      "revision_id": "rev-1",
      "size": 4,
      "modified_at_ns": 1700000000000000000,
      "source_path": "{}"
    }}
  ]
}}"#,
            source.display(),
        );
        fs::write(&manifest, manifest_json)?;
        Ok(manifest)
    }

    fn unexpected_login(_: &LoginCommand) -> Result<LoginOutput> {
        Err(anyhow!("login should not be called"))
    }

    fn unexpected_shares(_: &SharesCommand) -> Result<Vec<ShareInfo>> {
        Err(anyhow!("shares should not be called"))
    }

    #[test]
    fn print_shares_writes_header_and_rows() -> Result<()> {
        let mut output = Vec::new();
        print_shares(&mut output, &[share("PhotosRoot", "share-1")])?;
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("Name\tShareID\tLinkID"));
        assert!(text.contains("PhotosRoot\tshare-1\tlink"));
        Ok(())
    }

    #[test]
    fn print_shares_reports_empty_results() -> Result<()> {
        let mut output = Vec::new();
        print_shares(&mut output, &[])?;
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("Name\tShareID\tLinkID"));
        assert!(text.contains("(no shares found)"));
        Ok(())
    }

    #[test]
    fn run_with_writer_formats_dry_run_export() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let manifest = write_manifest(&temp_dir)?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let cli = Cli {
            command: Command::Export(ExportCommand {
                to: output_dir,
                state_db: Some(state_db),
                dry_run: true,
                delete_missing: false,
                download_concurrency: 1,
                progress: ProgressMode::Off,
                source: SourceCommand::Manifest(ManifestSourceArgs { manifest }),
            }),
        };

        let mut output = Vec::new();
        run_with_writer(cli, &mut output, unexpected_login, unexpected_shares)?;

        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("dry-run backend=manifest root=photos-root"));
        assert!(text.contains("would_download=1"));
        Ok(())
    }

    #[test]
    fn run_with_writer_formats_non_dry_export() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let manifest = write_manifest(&temp_dir)?;
        let output_dir = temp_dir.path().join("out");
        let state_db = temp_dir.path().join("state.sqlite");
        let cli = Cli {
            command: Command::Export(ExportCommand {
                to: output_dir.clone(),
                state_db: Some(state_db.clone()),
                dry_run: false,
                delete_missing: false,
                download_concurrency: 1,
                progress: ProgressMode::Off,
                source: SourceCommand::Manifest(ManifestSourceArgs { manifest }),
            }),
        };

        let mut output = Vec::new();
        let exit_code = run_with_writer(cli, &mut output, unexpected_login, unexpected_shares)?;
        assert_eq!(exit_code, 0, "fully successful export should exit 0");

        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("export backend=manifest root=photos-root"));
        assert!(text.contains("downloaded=1"));
        assert!(text.contains("failed=0"));
        assert_eq!(fs::read(output_dir.join("photo.jpg"))?, b"jpeg");
        assert_eq!(
            SyncState::open_existing(&state_db)?.summary()?.object_count,
            1
        );
        Ok(())
    }

    #[test]
    fn run_with_writer_formats_login_output() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials = temp_dir.path().join("creds.json");
        let cli = Cli {
            command: Command::Login(LoginCommand {
                credentials: Some(credentials.clone()),
                email: Some("user@example.com".to_owned()),
                password: Some("secret".to_owned()),
                two_fa: None,
                mailbox_password: None,
                app_version: None,
                user_agent: None,
                no_input: true,
            }),
        };

        let mut output = Vec::new();
        run_with_writer(
            cli,
            &mut output,
            |_| {
                Ok(LoginOutput {
                    credentials_path: credentials.clone(),
                    shares: vec![share("PhotosRoot", "share-1")],
                })
            },
            unexpected_shares,
        )
        .expect("run login output");

        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains(&format!("credentials={}", credentials.display())));
        assert!(text.contains("PhotosRoot\tshare-1"));
        Ok(())
    }

    #[test]
    fn run_with_writer_formats_shares_output() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let cli = Cli {
            command: Command::Shares(SharesCommand {
                credentials: Some(temp_dir.path().join("creds.json")),
                account_password: None,
                app_version: None,
                user_agent: None,
                no_input: true,
            }),
        };

        let mut output = Vec::new();
        run_with_writer(cli, &mut output, unexpected_login, |_| {
            Ok(vec![
                share("PhotosRoot", "share-1"),
                share("Album", "share-2"),
            ])
        })?;

        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("PhotosRoot\tshare-1"));
        assert!(text.contains("Album\tshare-2"));
        Ok(())
    }

    #[test]
    fn run_with_writer_formats_state_output() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state_db = temp_dir.path().join("state.sqlite");
        let state = SyncState::open(&state_db)?;
        state.update_run_state("manifest", "photos-root")?;

        let cli = Cli {
            command: Command::State(StateCommand {
                state_db: state_db.clone(),
            }),
        };

        let mut output = Vec::new();
        run_with_writer(cli, &mut output, unexpected_login, unexpected_shares)?;

        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains(&format!("state_db={}", state_db.display())));
        assert!(text.contains("backend=manifest"));
        assert!(text.contains("root_id=photos-root"));
        assert!(text.contains("objects=0"));
        Ok(())
    }

    #[test]
    fn run_with_writer_formats_state_output_with_missing_values() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state_db = temp_dir.path().join("state.sqlite");
        let _state = SyncState::open(&state_db)?;
        let connection = Connection::open(&state_db)?;
        connection.execute("UPDATE sync_state SET backend_name = NULL, root_id = NULL, updated_unix = NULL WHERE id = 1", [])?;

        let cli = Cli {
            command: Command::State(StateCommand {
                state_db: state_db.clone(),
            }),
        };

        let mut output = Vec::new();
        run_with_writer(cli, &mut output, unexpected_login, unexpected_shares)?;

        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("backend=-"));
        assert!(text.contains("root_id=-"));
        assert!(text.contains("updated_unix=-"));
        Ok(())
    }

    #[test]
    fn helper_stubs_return_expected_errors() {
        let login_error = unexpected_login(&LoginCommand {
            credentials: Some(PathBuf::from("creds.json")),
            email: Some("user@example.com".to_owned()),
            password: Some("secret".to_owned()),
            two_fa: None,
            mailbox_password: None,
            app_version: None,
            user_agent: None,
            no_input: true,
        })
        .expect_err("login stub should fail");
        assert!(
            login_error
                .to_string()
                .contains("login should not be called")
        );

        let shares_error = unexpected_shares(&SharesCommand {
            credentials: Some(PathBuf::from("creds.json")),
            account_password: None,
            app_version: None,
            user_agent: None,
            no_input: true,
        })
        .expect_err("shares stub should fail");
        assert!(
            shares_error
                .to_string()
                .contains("shares should not be called")
        );
    }

    #[test]
    fn run_with_writer_propagates_share_errors() {
        let cli = Cli {
            command: Command::Shares(SharesCommand {
                credentials: Some(PathBuf::from("creds.json")),
                account_password: None,
                app_version: None,
                user_agent: None,
                no_input: true,
            }),
        };

        let error = run_with_writer(cli, &mut Vec::new(), unexpected_login, unexpected_shares)
            .expect_err("shares failure should propagate");
        assert!(error.to_string().contains("shares should not be called"));
    }

    #[test]
    fn run_with_writer_propagates_login_errors() {
        let cli = Cli {
            command: Command::Login(LoginCommand {
                credentials: Some(PathBuf::from("creds.json")),
                email: Some("user@example.com".to_owned()),
                password: Some("secret".to_owned()),
                two_fa: None,
                mailbox_password: None,
                app_version: None,
                user_agent: None,
                no_input: true,
            }),
        };

        let error = run_with_writer(cli, &mut Vec::new(), unexpected_login, unexpected_shares)
            .expect_err("login failure should propagate");
        assert!(error.to_string().contains("login should not be called"));
    }

    #[test]
    fn run_with_writer_requires_state_db_when_source_has_no_default() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let manifest = write_manifest(&temp_dir)?;
        let cli = Cli {
            command: Command::Export(ExportCommand {
                to: temp_dir.path().join("out"),
                state_db: None,
                dry_run: true,
                delete_missing: false,
                download_concurrency: 1,
                progress: ProgressMode::Off,
                source: SourceCommand::Manifest(ManifestSourceArgs { manifest }),
            }),
        };

        let error = run_with_writer(cli, &mut Vec::new(), unexpected_login, unexpected_shares)
            .expect_err("manifest export should require explicit state db");
        assert!(error.to_string().contains("`--state-db` is required"));
        Ok(())
    }

    #[test]
    fn run_with_writer_propagates_state_errors() {
        let cli = Cli {
            command: Command::State(StateCommand {
                state_db: PathBuf::from("missing.sqlite"),
            }),
        };

        let error = run_with_writer(cli, &mut Vec::new(), unexpected_login, unexpected_shares)
            .expect_err("missing state db should fail");
        assert!(error.to_string().contains("state DB not found"));
    }

    #[test]
    fn resolve_progress_mode_maps_all_variants() {
        assert_eq!(
            resolve_progress_mode(ProgressMode::Auto),
            ProgressOutputMode::auto(std::io::stderr().is_terminal())
        );
        assert_eq!(
            resolve_progress_mode(ProgressMode::Human),
            ProgressOutputMode::Human
        );
        assert_eq!(
            resolve_progress_mode(ProgressMode::Json),
            ProgressOutputMode::Json
        );
        assert_eq!(
            resolve_progress_mode(ProgressMode::Off),
            ProgressOutputMode::Quiet
        );
    }

    #[test]
    fn run_accepts_state_command_through_public_entrypoint() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let state_db = temp_dir.path().join("state.sqlite");
        SyncState::open(&state_db)?;

        super::run(Cli {
            command: Command::State(StateCommand { state_db }),
        })?;
        Ok(())
    }
}
