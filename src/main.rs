use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    protonpics::install_signal_handler()?;
    protonpics::run(protonpics::cli::Cli::parse())
}
