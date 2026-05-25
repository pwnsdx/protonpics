use std::process::Command;

use anyhow::Result;
use protonpics::state::SyncState;
use tempfile::TempDir;

#[test]
fn state_command_runs_through_binary_entrypoint() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let state_db = temp_dir.path().join("state.sqlite");
    let state = SyncState::open(&state_db)?;
    state.update_run_state("manifest", "photos-root")?;

    let output = Command::new(env!("CARGO_BIN_EXE_protonpics"))
        .args(["state", "--state-db"])
        .arg(&state_db)
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(&format!("state_db={}", state_db.display())));
    assert!(stdout.contains("backend=manifest"));
    assert!(stdout.contains("root_id=photos-root"));
    Ok(())
}
