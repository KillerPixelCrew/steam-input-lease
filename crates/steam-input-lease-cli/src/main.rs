//! Console launcher and diagnostic front end for `steam-input-lease`.
//!
//! Arguments after `--` are preserved as individual Windows arguments and run
//! through [`steam_input_lease::Client::run_wrapped`]. When no lease can be taken
//! the command still runs, without one. Options before `--` select a diagnostic
//! operation or the opt-in injection path.

use std::ffi::OsString;
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use steam_input_lease::{Client, ClientOptions, run_unleased};

/// How long a launch waits for a resident gate when it may not inject.
///
/// A deployed gate keeps its pipe for as long as Steam runs, so a missing pipe is
/// an answer rather than a race. The library default of ten seconds covers a
/// freshly injected payload starting its server, and here would only delay the
/// game on every launch without a gate.
const RESIDENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Launch record written beside the executable.
const LOG_FILE_NAME: &str = "steam-input-lease.log";

fn usage() -> String {
    format!(
        r#"Steam Input Lease {version}

Stops Steam Input from holding your controllers while a program runs, and gives
them back when the program and everything it started have exited.

Run a program through it:
  steam-input-lease.exe [options] -- program.exe [arguments...]

Steam launch options (with steam-input-lease.exe beside steam.exe):
  "C:\Program Files (x86)\Steam\steam-input-lease.exe" -- %command%

Diagnostics:
  steam-input-lease.exe --status   query the gate Steam has loaded
  steam-input-lease.exe --rescan   ask Steam to look for controllers again

Options:
  --inject             load steam_input_gate.dll into the target when no gate answers
  --payload PATH       the DLL --inject loads (default: beside this executable)
  --target-name NAME   target process instead of steam.exe
  --help, -h           show this text"#,
        version = env!("CARGO_PKG_VERSION")
    )
}

/// What one invocation asks for.
#[derive(Debug, PartialEq)]
enum Mode {
    Help,
    Status,
    Rescan,
    Run(Vec<OsString>),
}

/// Parsed command line.
#[derive(Debug)]
struct Invocation {
    options: ClientOptions,
    mode: Mode,
}

fn parse(mut arguments: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut options = ClientOptions::default();
    let mut payload = None;
    let mut help = false;
    let mut status = false;
    let mut rescan = false;
    let mut command = None;

    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--") => {
                command = Some(arguments.by_ref().collect::<Vec<_>>());
                break;
            }
            Some("--status") => status = true,
            Some("--rescan") => rescan = true,
            Some("--inject") => options.allow_injection = true,
            Some("--target-name") => {
                options.target_name = arguments
                    .next()
                    .ok_or("--target-name requires a value")?
                    .into_string()
                    .map_err(|_| "--target-name must be valid Unicode")?;
            }
            Some("--payload") => {
                payload = Some(PathBuf::from(
                    arguments.next().ok_or("--payload requires a value")?,
                ));
            }
            Some("--help" | "-h") => help = true,
            _ => return Err(format!("unknown option: {}", argument.to_string_lossy())),
        }
    }

    if let Some(path) = payload {
        if !options.allow_injection {
            return Err("--payload is only used together with --inject".into());
        }
        options.payload_path = path;
    }
    if !options.allow_injection {
        options.connect_timeout = RESIDENT_CONNECT_TIMEOUT;
    }

    // Diagnostics take precedence over a command given on the same line.
    let mode = if help {
        Mode::Help
    } else if status {
        Mode::Status
    } else if rescan {
        Mode::Rescan
    } else {
        match command {
            Some(command) if !command.is_empty() => Mode::Run(command),
            _ => return Err("a program to run is required after --".into()),
        }
    };
    Ok(Invocation { options, mode })
}

/// The last launch, recorded beside the executable.
///
/// Steam closes the console window together with the game, so without this a
/// launch that fell back to running unleased leaves nothing to look at. Each
/// launch replaces the file, and a log that cannot be written is skipped.
struct LaunchLog(Option<File>);

impl LaunchLog {
    fn open() -> Self {
        let file = std::env::current_exe()
            .ok()
            .and_then(|executable| executable.parent().map(|directory| directory.join(LOG_FILE_NAME)))
            .and_then(|path| File::create(path).ok());
        Self(file)
    }

    fn info(&mut self, message: impl Display) {
        println!("{message}");
        self.write(message);
    }

    fn warn(&mut self, message: impl Display) {
        eprintln!("{message}");
        self.write(message);
    }

    fn write(&mut self, message: impl Display) {
        if let Some(file) = self.0.as_mut() {
            let _ = writeln!(file, "{message}");
        }
    }
}

fn run_command(options: ClientOptions, command: &[OsString]) -> u32 {
    let mut log = LaunchLog::open();
    log.write(format_args!(
        "Steam Input Lease {} launching {:?}",
        env!("CARGO_PKG_VERSION"),
        command
    ));
    log.info("Acquiring Steam Input block lease...");
    match Client::new(options).run_wrapped(command) {
        Ok(run) => {
            match &run.release {
                Ok(outcome) => {
                    log.info(format_args!(
                        "Process tree exited with code {}; Steam Input unblocked.",
                        run.exit_code
                    ));
                    if let Some(error) = outcome.recovery.error() {
                        log.warn(format_args!(
                            "Steam was not asked to look for controllers again: {error}"
                        ));
                    }
                }
                // Blocking is lifted regardless (the pipe dies with this process),
                // but Steam was not asked to rediscover controllers.
                Err(error) => log.warn(format_args!(
                    "Process tree exited with code {}; Steam Input unblocked, but the release \
                     handshake failed and controller recovery did not run: {error}",
                    run.exit_code
                )),
            }
            run.exit_code
        }
        Err(error) => {
            // Fail open. run_wrapped reports an error only when the program never
            // started, so starting it here cannot run it twice, and a game that
            // will not start is worse than one Steam Input can still see.
            log.warn(format_args!(
                "Steam Input block unavailable ({error}); starting without it."
            ));
            match run_unleased(command) {
                Ok(exit_code) => {
                    log.info(format_args!("Process tree exited with code {exit_code}."));
                    exit_code
                }
                Err(error) => {
                    log.warn(format_args!("Could not start the program: {error}"));
                    1
                }
            }
        }
    }
}

fn run(invocation: Invocation) -> Result<u32, String> {
    let client = Client::new(invocation.options);
    match invocation.mode {
        Mode::Help => {
            println!("{}", usage());
            Ok(0)
        }
        Mode::Status => {
            let status = client.status().map_err(|error| error.to_string())?;
            println!(
                "Gate active; leases={}, tracked HID handles={}, handles revoked by last transition={}.",
                status.lease_count, status.hid_handle_count, status.last_revoked_handle_count
            );
            Ok(0)
        }
        Mode::Rescan => {
            let result = client.rescan().map_err(|error| error.to_string())?;
            println!(
                "Requested Steam controller discovery (scan counter {} -> {}).",
                result.scan_count_before, result.scan_count_after
            );
            Ok(0)
        }
        Mode::Run(command) => Ok(run_command(client.options().clone(), &command)),
    }
}

fn main() {
    let code = match parse(std::env::args_os().skip(1)) {
        Ok(invocation) => run(invocation).unwrap_or_else(|error| {
            eprintln!("{error}");
            1
        }),
        Err(error) => {
            eprintln!("{error}\n\n{}", usage());
            1
        }
    };
    // The full 32-bit code, so a crash status such as 0xC0000005 reaches the
    // caller intact instead of being clamped to one byte.
    std::process::exit(code as i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(arguments: &[&str]) -> Result<Invocation, String> {
        parse(arguments.iter().map(OsString::from))
    }

    #[test]
    fn a_launch_connects_only_to_a_resident_gate_by_default() {
        let invocation = parse_args(&["--", "game.exe", "--fullscreen"]).expect("valid launch");
        assert!(!invocation.options.allow_injection);
        assert_eq!(invocation.options.connect_timeout, RESIDENT_CONNECT_TIMEOUT);
        assert_eq!(
            invocation.mode,
            Mode::Run(vec!["game.exe".into(), "--fullscreen".into()])
        );
    }

    #[test]
    fn everything_after_the_separator_belongs_to_the_program() {
        let invocation =
            parse_args(&["--", "game.exe", "--status", "--", "-h"]).expect("valid launch");
        assert_eq!(
            invocation.mode,
            Mode::Run(vec![
                "game.exe".into(),
                "--status".into(),
                "--".into(),
                "-h".into()
            ])
        );
    }

    #[test]
    fn injection_is_opt_in_and_keeps_the_longer_startup_wait() {
        let invocation = parse_args(&["--inject", "--payload", r"D:\gate.dll", "--", "game.exe"])
            .expect("valid injecting launch");
        assert!(invocation.options.allow_injection);
        assert_eq!(invocation.options.payload_path, PathBuf::from(r"D:\gate.dll"));
        assert_eq!(
            invocation.options.connect_timeout,
            ClientOptions::default().connect_timeout
        );
    }

    #[test]
    fn a_payload_without_inject_is_rejected() {
        let error = parse_args(&["--payload", r"D:\gate.dll", "--", "game.exe"])
            .expect_err("--payload alone must be refused");
        assert!(error.contains("--inject"), "unexpected error: {error}");
    }

    #[test]
    fn diagnostics_take_precedence_over_a_command() {
        let invocation = parse_args(&["--status", "--", "game.exe"]).expect("valid status");
        assert_eq!(invocation.mode, Mode::Status);
    }

    #[test]
    fn a_launch_without_a_program_is_rejected() {
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&["--"]).is_err());
        assert!(parse_args(&["--bogus"]).is_err());
    }
}
