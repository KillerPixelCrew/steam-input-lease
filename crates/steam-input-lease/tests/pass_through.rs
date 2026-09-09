//! Attended by scripts/test-lifecycle.ps1 against its isolated fake-HID target only.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use steam_input_lease::{Client, ClientOptions};

#[test]
#[ignore = "requires the isolated lifecycle harness target"]
fn overlapping_pass_through_preserves_and_restores_block_owners() {
    let target = PathBuf::from(std::env::var_os("SIL_TEST_TARGET").expect("harness target"));
    assert_eq!(target.file_name().unwrap(), "steam-input-test-target.exe");
    let port = std::env::var("SIL_TEST_PORT").expect("harness port");
    let client = Client::new(ClientOptions {
        target_name: "steam-input-test-target.exe".into(),
        allow_injection: false,
        ..ClientOptions::default()
    });
    let probe = |blocked: bool| {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let result = Command::new(&target).args([
                "--probe-client", &port,
                if blocked { "--expect-blocked" } else { "--expect-open" },
            ]).output().expect("probe process");
            if result.status.success() { break; }
            assert!(Instant::now() < deadline, "fake-HID state did not converge: {}",
                String::from_utf8_lossy(&result.stderr));
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let first = client.acquire().unwrap();
    let second = client.acquire().unwrap();
    probe(true);
    let handoff = client.acquire_pass_through().unwrap();
    assert_eq!(handoff.status().lease_count, 2);
    probe(false);
    let overlapping = client.acquire_pass_through().unwrap();
    first.release().unwrap();
    let new_game = client.acquire().unwrap();
    probe(false);
    handoff.release().unwrap();
    probe(false);
    // EOF follows the same cleanup path as a crashed claim owner.
    drop(overlapping);
    probe(true);
    let final_handoff = client.acquire_pass_through().unwrap();
    second.release().unwrap();
    new_game.release().unwrap();
    final_handoff.release().unwrap();
    probe(false);
}
