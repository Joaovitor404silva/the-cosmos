//! Builds `examples/chat.c` with MSVC against `cosmos.dll` and runs it:
//! 4 instances on loopback, join by code, chat, one record put + query.
#![cfg(windows)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod msvc;
use msvc::{vcvars64, vswhere_dir};

#[test]
fn chat_example_builds_and_runs_with_4_instances() {
    // No canonicalize: cl does not take verbatim (\?\) paths.
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf();
    // cargo builds the cdylib + import lib next to this test exe (deps/).
    let bin = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let implib = bin.join("cosmos.dll.lib");
    assert!(bin.join("cosmos.dll").exists() && implib.exists(), "cosmos.dll / import lib missing in {}", bin.display());

    let out = bin.parent().unwrap().join("chat-c");
    std::fs::create_dir_all(&out).unwrap();
    let bat = out.join("build.bat");
    let script = format!(
        // vcvars64 itself runs vswhere, which is not on PATH.
        "@echo off\r\nset \"PATH=%PATH%;{}\"\r\ncall \"{}\" >nul || exit /b 1\r\ncl /nologo /W4 /WX /I \"{}\" \"{}\" /Fo\"{}\\\\\" /Fe\"{}\" /link \"{}\"\r\n",
        vswhere_dir().display(),
        vcvars64().display(),
        repo.join("include").display(),
        repo.join(r"examples\chat.c").display(),
        out.display(),
        out.join("chat.exe").display(),
        implib.display(),
    );
    std::fs::write(&bat, script).unwrap();
    let b = Command::new("cmd").arg("/C").arg(&bat).current_dir(&out).output().unwrap();
    assert!(
        b.status.success(),
        "cl failed:\n{}{}",
        String::from_utf8_lossy(&b.stdout),
        String::from_utf8_lossy(&b.stderr)
    );

    let path = format!("{};{}", bin.display(), std::env::var("PATH").unwrap_or_default());
    let mut child = Command::new(out.join("chat.exe"))
        .env("PATH", path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(180) {
            child.kill().unwrap();
            panic!("chat.exe timed out");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let text = std::io::read_to_string(child.stdout.take().unwrap()).unwrap();
    println!("{text}");
    assert!(status.success(), "chat.exe exit {status}");
    for i in 0..4 {
        assert!(text.contains(&format!("peer {i}: 3 peers joined")), "peer {i} did not see 3 peers");
        assert!(text.contains(&format!("peer {i}: got 3 messages")), "peer {i} missed messages");
    }
    assert!(text.contains("code "), "no join code printed");
    assert!(text.contains("record: note/lobby = 'meet at the north gate'"), "record not found");
    assert!(text.contains("dropped events: 0"), "events were dropped");
    assert!(text.trim_end().ends_with("CHAT OK"));
}
