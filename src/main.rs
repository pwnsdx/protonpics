use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    protonpics::install_signal_handler()?;
    let exit_code = protonpics::run(protonpics::cli::Cli::parse())?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}
