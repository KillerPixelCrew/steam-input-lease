//! Isolated process used to validate injection and detour state transitions.
//!
//! In server mode it accepts a one-byte localhost request and attempts to open
//! a deliberately nonexistent HID-style path inside this process. The test
//! script observes the resulting Win32 error before, during, and after a lease.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, ExitCode};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_SUCH_DEVICE, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

fn probe_fake_hid_path() -> u32 {
    let path: Vec<u16> = r"\\?\hid#steam_input_lease_missing"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    let error = unsafe { GetLastError() };
    if handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
    }
    error
}

fn serve(port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;
    println!("test target ready, pid={}, port={port}", std::process::id());
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut request = [0u8; 1];
                stream.read_exact(&mut request)?;
                stream.write_all(&probe_fake_hid_path().to_le_bytes())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn probe_client(port: u16, expect_blocked: bool) -> ExitCode {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                eprintln!("could not connect to test target: {error}");
                return ExitCode::from(25);
            }
        }
    };
    if stream.write_all(&[1]).is_err() {
        return ExitCode::from(25);
    }
    let mut response = [0u8; 4];
    if stream.read_exact(&mut response).is_err() {
        return ExitCode::from(25);
    }
    let error = u32::from_le_bytes(response);
    println!("fake HID open returned Windows error {error}");
    let blocked = error == ERROR_NO_SUCH_DEVICE;
    if blocked == expect_blocked {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(24)
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.as_slice() == ["--child"] {
        println!("test target child completed");
        return ExitCode::from(23);
    }
    if arguments.first().map(String::as_str) == Some("--child-tree") {
        let Some(marker) = arguments.get(1) else {
            return ExitCode::from(2);
        };
        let executable = match std::env::current_exe() {
            Ok(executable) => executable,
            Err(error) => {
                eprintln!("could not resolve test target path: {error}");
                return ExitCode::from(27);
            }
        };
        match Command::new(executable)
            .arg("--delayed-marker")
            .arg(marker)
            .spawn()
        {
            Ok(_) => {
                println!("test target root spawned a delayed descendant");
                return ExitCode::from(23);
            }
            Err(error) => {
                eprintln!("could not spawn test descendant: {error}");
                return ExitCode::from(27);
            }
        }
    }
    if arguments.first().map(String::as_str) == Some("--delayed-marker") {
        let Some(marker) = arguments.get(1) else {
            return ExitCode::from(2);
        };
        thread::sleep(Duration::from_millis(750));
        return match std::fs::write(marker, b"descendant completed\n") {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("could not write descendant marker: {error}");
                ExitCode::from(28)
            }
        };
    }
    if arguments.first().map(String::as_str) == Some("--serve") {
        let Some(port) = arguments.get(1).and_then(|value| value.parse().ok()) else {
            return ExitCode::from(2);
        };
        return match serve(port) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("test server failed: {error}");
                ExitCode::from(26)
            }
        };
    }
    if arguments.first().map(String::as_str) == Some("--probe-client") {
        let Some(port) = arguments.get(1).and_then(|value| value.parse().ok()) else {
            return ExitCode::from(2);
        };
        return probe_client(
            port,
            arguments.get(2).map(String::as_str) == Some("--expect-blocked"),
        );
    }
    if arguments.first().map(String::as_str) == Some("--wait") {
        let milliseconds = arguments
            .get(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(100);
        thread::sleep(Duration::from_millis(milliseconds));
        return ExitCode::SUCCESS;
    }
    thread::sleep(Duration::from_secs(60));
    ExitCode::SUCCESS
}
