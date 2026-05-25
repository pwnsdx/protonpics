use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, anyhow};

static HANDLER_INSTALLED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
static INTERRUPT_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
fn immediate_exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

#[cfg(not(unix))]
fn immediate_exit(code: i32) -> ! {
    std::process::exit(code)
}

fn handle_interrupt<R>(exit: impl FnOnce(i32) -> R) -> R {
    INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
    exit(130)
}

pub fn install() -> Result<()> {
    HANDLER_INSTALLED
        .get_or_init(|| {
            ctrlc::set_handler(|| handle_interrupt(immediate_exit))
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map(|_| ())
        .map_err(|error| anyhow!(error.clone()))
        .context("install SIGINT handler")
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::Ordering;

    use super::{HANDLER_INSTALLED, INTERRUPT_COUNT, handle_interrupt, install};

    #[test]
    fn handle_interrupt_uses_exit_code_130_and_increments_count() {
        INTERRUPT_COUNT.store(0, Ordering::SeqCst);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            handle_interrupt(|code| panic!("exit:{code}"));
        }))
        .expect_err("interrupt handler should exit");
        let message = panic
            .downcast_ref::<String>()
            .expect("panic string from fake exit");
        assert_eq!(message, "exit:130");
        assert_eq!(INTERRUPT_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn install_is_idempotent() {
        let _ = HANDLER_INSTALLED.get();
        install().expect("install signal handler");
        install().expect("reinstall signal handler");
    }
}
