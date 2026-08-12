//! Command-line wrapper and diagnostic frontend for `steam-input-lease`.
//!
//! Arguments after `--` are preserved as individual Windows arguments and run
//! through [`steam_input_lease::Client::run_wrapped`]. Options before `--`
//! configure the target, payload, or a non-mutating diagnostic operation.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use steam_input_lease::{Client, ClientOptions};

fn usage() {
    // Development/diagnostic front-end only: this binary is deliberately not
    // shipped, and the installer deletes it on update. The user-facing wrapper
    // is WSGM.Launch.exe, so never advertise this path as a launch option.
    eprintln!(
        "Steam Input Lease (development diagnostic tool; not the user-facing wrapper)\n\n\
         Steam launch options are configured with WSGM.Launch.exe instead:\n  \
         \"C:\\path\\WSGM.Launch.exe\" [--deelevate] [--input-lease] -- %command%\n\n\
         Status:\n  steam-input-lease.exe --status\n\n\
         Controller recovery:\n  steam-input-lease.exe --rescan\n\n\
         Wrapped run (diagnostics):\n  steam-input-lease.exe -- program.exe arguments\n\n\
         Options:\n  --target-name process.exe\n  --payload path\\steam_input_gate.dll"
    );
}

fn run() -> Result<u32, String> {
    let mut options = ClientOptions::default();
    let mut command = Vec::<OsString>::new();
    let mut after_separator = false;
    let mut status_only = false;
    let mut rescan_only = false;
    let mut arguments = std::env::args_os().skip(1);

    while let Some(argument) = arguments.next() {
        if after_separator {
            command.push(argument);
            continue;
        }
        match argument.to_string_lossy().as_ref() {
            "--" => after_separator = true,
            "--status" => status_only = true,
            "--rescan" => rescan_only = true,
            "--target-name" => {
                options.target_name = arguments
                    .next()
                    .ok_or("--target-name requires a value")?
                    .to_string_lossy()
                    .into_owned();
            }
            "--payload" => {
                options.payload_path =
                    PathBuf::from(arguments.next().ok_or("--payload requires a value")?);
            }
            "--help" | "-h" => {
                usage();
                return Ok(0);
            }
            unknown => return Err(format!("unknown option: {unknown}")),
        }
    }

    let client = Client::new(options);
    if status_only {
        let status = client.status().map_err(|error| error.to_string())?;
        println!(
            "Payload active; leases={}, tracked HID handles={}, handles revoked by last transition={}.",
            status.lease_count, status.hid_handle_count, status.last_revoked_handle_count
        );
        return Ok(0);
    }
    if rescan_only {
        let result = client.rescan().map_err(|error| error.to_string())?;
        println!(
            "Requested Steam controller discovery (scan counter {} -> {}).",
            result.scan_count_before, result.scan_count_after
        );
        return Ok(0);
    }
    if command.is_empty() {
        usage();
        return Err("wrapped command is required after --".into());
    }

    println!("Acquiring Steam Input block lease...");
    let run = client
        .run_wrapped(command)
        .map_err(|error| error.to_string())?;
    match &run.release {
        Ok(_) => println!("Game process tree exited; Steam Input unblocked."),
        // Blocking is lifted regardless (the pipe dies with this process), but
        // Steam was not asked to rediscover controllers.
        Err(error) => println!(
            "Game process tree exited; Steam Input unblocked, but the release \
             handshake failed and controller recovery did not run: {error}"
        ),
    }
    Ok(run.exit_code)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code.min(u8::MAX as u32) as u8),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
