use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

const DEFAULT_SCAN_CONCURRENCY: usize = 4;
const DEFAULT_DOWNLOAD_CONCURRENCY: usize = 4;

#[derive(Debug, Parser)]
#[command(
    name = "protonpics",
    version,
    about = "Experimental one-way exporter for Proton Photos"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Export(ExportCommand),
    Login(LoginCommand),
    Shares(SharesCommand),
    State(StateCommand),
}

#[derive(Debug, Args)]
pub struct ExportCommand {
    #[arg(long, value_name = "DIR")]
    pub to: PathBuf,

    #[arg(long, value_name = "FILE")]
    pub state_db: Option<PathBuf>,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub delete_missing: bool,

    #[arg(
        long,
        default_value_t = DEFAULT_DOWNLOAD_CONCURRENCY,
        value_parser = clap::value_parser!(usize),
        help = "Maximum number of concurrent file downloads"
    )]
    pub download_concurrency: usize,

    #[arg(
        long,
        value_enum,
        value_name = "MODE",
        num_args = 0..=1,
        default_value = "auto",
        default_missing_value = "human",
        help = "Progress output mode: auto, human, json, off"
    )]
    pub progress: ProgressMode,

    #[command(subcommand)]
    pub source: SourceCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum ProgressMode {
    #[default]
    Auto,
    Human,
    Json,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum TreeCacheMode {
    Off,
    #[default]
    Refresh,
    ReuseIfPresent,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SourceCommand {
    Manifest(ManifestSourceArgs),
    Proton(ProtonSourceArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ManifestSourceArgs {
    #[arg(long, value_name = "FILE")]
    pub manifest: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct ProtonSourceArgs {
    #[arg(long, env = "PROTON_CREDENTIALS_FILE", value_name = "FILE")]
    pub credentials: Option<PathBuf>,

    #[arg(long, env = "PROTON_ACCOUNT_PASSWORD")]
    pub account_password: Option<String>,

    #[arg(long, default_value = "PhotosRoot")]
    pub share_name: String,

    #[arg(long)]
    pub share_id: Option<String>,

    #[arg(long, env = "PROTON_APP_VERSION")]
    pub app_version: Option<String>,

    #[arg(long, env = "PROTON_USER_AGENT")]
    pub user_agent: Option<String>,

    #[arg(
        long,
        env = "PROTON_SCAN_CONCURRENCY",
        default_value_t = DEFAULT_SCAN_CONCURRENCY,
        value_parser = clap::value_parser!(usize),
        help = "Maximum number of concurrent folder/album scans during tree loading"
    )]
    pub scan_concurrency: usize,

    #[arg(
        long,
        value_enum,
        default_value = "refresh",
        help = "Tree cache mode: off, refresh (default), reuse-if-present"
    )]
    pub tree_cache: TreeCacheMode,

    #[arg(long)]
    pub no_input: bool,
}

#[derive(Debug, Clone, Args)]
pub struct LoginCommand {
    #[arg(long, env = "PROTON_CREDENTIALS_FILE", value_name = "FILE")]
    pub credentials: Option<PathBuf>,

    #[arg(long, env = "PROTON_EMAIL")]
    pub email: Option<String>,

    #[arg(long, env = "PROTON_PASSWORD")]
    pub password: Option<String>,

    #[arg(long = "2fa", env = "PROTON_MFA")]
    pub two_fa: Option<String>,

    #[arg(long)]
    pub mailbox_password: Option<String>,

    #[arg(long, env = "PROTON_APP_VERSION")]
    pub app_version: Option<String>,

    #[arg(long, env = "PROTON_USER_AGENT")]
    pub user_agent: Option<String>,

    #[arg(long)]
    pub no_input: bool,
}

#[derive(Debug, Clone, Args)]
pub struct SharesCommand {
    #[arg(long, env = "PROTON_CREDENTIALS_FILE", value_name = "FILE")]
    pub credentials: Option<PathBuf>,

    #[arg(long, env = "PROTON_ACCOUNT_PASSWORD")]
    pub account_password: Option<String>,

    #[arg(long, env = "PROTON_APP_VERSION")]
    pub app_version: Option<String>,

    #[arg(long, env = "PROTON_USER_AGENT")]
    pub user_agent: Option<String>,

    #[arg(long)]
    pub no_input: bool,
}

#[derive(Debug, Args)]
pub struct StateCommand {
    #[arg(long, value_name = "FILE")]
    pub state_db: PathBuf,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, ProgressMode, TreeCacheMode};

    #[test]
    fn export_progress_defaults_to_auto() {
        let cli = Cli::parse_from(["protonpics", "export", "--to", "./out", "proton"]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if command.progress == ProgressMode::Auto && command.download_concurrency == 4
        ));
    }

    #[test]
    fn export_parses_download_concurrency() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--download-concurrency",
            "8",
            "--to",
            "./out",
            "proton",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command) if command.download_concurrency == 8
        ));
    }

    #[test]
    fn export_progress_without_value_means_human() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--progress",
            "--to",
            "./out",
            "proton",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command) if command.progress == ProgressMode::Human
        ));
    }

    #[test]
    fn export_progress_accepts_json_mode() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--progress",
            "json",
            "--to",
            "./out",
            "proton",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command) if command.progress == ProgressMode::Json
        ));
    }

    #[test]
    fn export_progress_accepts_explicit_human_mode() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--progress",
            "human",
            "--to",
            "./out",
            "proton",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command) if command.progress == ProgressMode::Human
        ));
    }

    #[test]
    fn export_progress_accepts_off_mode() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--progress",
            "off",
            "--to",
            "./out",
            "proton",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command) if command.progress == ProgressMode::Off
        ));
    }

    #[test]
    fn login_command_parses_email_and_password_flags() {
        let cli = Cli::parse_from([
            "protonpics",
            "login",
            "--email",
            "user@example.com",
            "--password",
            "secret",
        ]);
        assert!(matches!(
            cli.command,
            Command::Login(ref command)
                if command.email.as_deref() == Some("user@example.com")
                    && command.password.as_deref() == Some("secret")
        ));
    }

    #[test]
    fn shares_command_parses_credentials_and_no_input_flag() {
        let cli = Cli::parse_from([
            "protonpics",
            "shares",
            "--credentials",
            "./session.json",
            "--no-input",
        ]);
        assert!(matches!(
            cli.command,
            Command::Shares(ref command)
                if command.credentials.as_deref() == Some(std::path::Path::new("./session.json"))
                    && command.no_input
        ));
    }

    #[test]
    fn state_command_parses_state_db_path() {
        let cli = Cli::parse_from(["protonpics", "state", "--state-db", "./state.sqlite"]);
        assert!(matches!(
            cli.command,
            Command::State(ref command)
                if command.state_db == std::path::Path::new("./state.sqlite")
        ));
    }

    #[test]
    fn manifest_source_parses_nested_export_subcommand() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--to",
            "./out",
            "manifest",
            "--manifest",
            "./manifest.json",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if matches!(
                    command.source,
                    super::SourceCommand::Manifest(ref args)
                        if args.manifest == std::path::Path::new("./manifest.json")
                )
        ));
    }

    #[test]
    fn proton_source_defaults_share_name_to_photos_root() {
        let cli = Cli::parse_from(["protonpics", "export", "--to", "./out", "proton"]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if matches!(
                    command.source,
                    super::SourceCommand::Proton(ref args) if args.share_name == "PhotosRoot"
                )
        ));
    }

    #[test]
    fn proton_source_defaults_scan_concurrency_to_four() {
        let cli = Cli::parse_from(["protonpics", "export", "--to", "./out", "proton"]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if matches!(
                    command.source,
                    super::SourceCommand::Proton(ref args)
                        if args.scan_concurrency == 4
                            && args.tree_cache == TreeCacheMode::Refresh
                )
        ));
    }

    #[test]
    fn proton_source_parses_credentials_and_password_flags() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--to",
            "./out",
            "proton",
            "--credentials",
            "./session.json",
            "--account-password",
            "secret",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if matches!(
                    command.source,
                    super::SourceCommand::Proton(ref args)
                        if args.credentials.as_deref() == Some(std::path::Path::new("./session.json"))
                            && args.account_password.as_deref() == Some("secret")
                )
        ));
    }

    #[test]
    fn proton_source_parses_share_id_and_no_input() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--to",
            "./out",
            "proton",
            "--share-id",
            "share-1",
            "--no-input",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if matches!(
                    command.source,
                    super::SourceCommand::Proton(ref args)
                        if args.share_id.as_deref() == Some("share-1") && args.no_input
                )
        ));
    }

    #[test]
    fn proton_source_parses_app_metadata_flags() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--to",
            "./out",
            "proton",
            "--app-version",
            "web-account@5.0.0.0",
            "--user-agent",
            "test-agent",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if matches!(
                    command.source,
                    super::SourceCommand::Proton(ref args)
                        if args.app_version.as_deref() == Some("web-account@5.0.0.0")
                            && args.user_agent.as_deref() == Some("test-agent")
                )
        ));
    }

    #[test]
    fn proton_source_parses_scan_concurrency_flag() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--to",
            "./out",
            "proton",
            "--scan-concurrency",
            "8",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if matches!(
                    command.source,
                    super::SourceCommand::Proton(ref args) if args.scan_concurrency == 8
                )
        ));
    }

    #[test]
    fn proton_source_parses_tree_cache_flag() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--to",
            "./out",
            "proton",
            "--tree-cache",
            "reuse-if-present",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if matches!(
                    command.source,
                    super::SourceCommand::Proton(ref args)
                        if args.tree_cache == TreeCacheMode::ReuseIfPresent
                )
        ));
    }

    #[test]
    fn export_command_parses_state_db_and_delete_flags() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--to",
            "./out",
            "--state-db",
            "./state.sqlite",
            "--dry-run",
            "--delete-missing",
            "proton",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if command.state_db.as_deref() == Some(std::path::Path::new("./state.sqlite"))
                    && command.dry_run
                    && command.delete_missing
        ));
    }

    #[test]
    fn login_command_parses_two_factor_and_mailbox_password() {
        let cli = Cli::parse_from([
            "protonpics",
            "login",
            "--email",
            "user@example.com",
            "--password",
            "secret",
            "--2fa",
            "123456",
            "--mailbox-password",
            "mail-secret",
        ]);
        assert!(matches!(
            cli.command,
            Command::Login(ref command)
                if command.two_fa.as_deref() == Some("123456")
                    && command.mailbox_password.as_deref() == Some("mail-secret")
        ));
    }

    #[test]
    fn login_command_parses_app_metadata_flags() {
        let cli = Cli::parse_from([
            "protonpics",
            "login",
            "--email",
            "user@example.com",
            "--password",
            "secret",
            "--app-version",
            "web-account@5.0.0.0",
            "--user-agent",
            "test-agent",
        ]);
        assert!(matches!(
            cli.command,
            Command::Login(ref command)
                if command.app_version.as_deref() == Some("web-account@5.0.0.0")
                    && command.user_agent.as_deref() == Some("test-agent")
        ));
    }

    #[test]
    fn shares_command_parses_account_password_flag() {
        let cli = Cli::parse_from(["protonpics", "shares", "--account-password", "secret"]);
        assert!(matches!(
            cli.command,
            Command::Shares(ref command)
                if command.account_password.as_deref() == Some("secret")
        ));
    }

    #[test]
    fn shares_command_parses_app_metadata_flags() {
        let cli = Cli::parse_from([
            "protonpics",
            "shares",
            "--app-version",
            "web-account@5.0.0.0",
            "--user-agent",
            "test-agent",
        ]);
        assert!(matches!(
            cli.command,
            Command::Shares(ref command)
                if command.app_version.as_deref() == Some("web-account@5.0.0.0")
                    && command.user_agent.as_deref() == Some("test-agent")
        ));
    }

    #[test]
    fn manifest_source_parses_with_dry_run_flag() {
        let cli = Cli::parse_from([
            "protonpics",
            "export",
            "--to",
            "./out",
            "--dry-run",
            "manifest",
            "--manifest",
            "./manifest.json",
        ]);
        assert!(matches!(
            cli.command,
            Command::Export(ref command)
                if command.dry_run
                    && matches!(
                        command.source,
                        super::SourceCommand::Manifest(ref args)
                            if args.manifest == std::path::Path::new("./manifest.json")
                    )
        ));
    }
}
