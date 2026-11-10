//! Builds `examples/cosmos-depths` (C + raylib) with MSVC against `cosmos.dll`
//! and runs `cosmos-depths --selftest`: host + 3 joiners (one late) and a
//! fresh instance on loopback, no window.
//! raylib comes from `examples/cosmos-depths/fetch-raylib.ps1` (downloaded once).
#![cfg(windows)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod msvc;
use msvc::{vcvars64, vswhere_dir};

#[test]
fn cosmos_depths_builds_and_passes_selftest() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf();
    let demo = repo.join(r"examples\cosmos-depths");
    let bin = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let implib = bin.join("cosmos.dll.lib");
    assert!(bin.join("cosmos.dll").exists() && implib.exists(), "cosmos.dll / import lib missing in {}", bin.display());

    let fetch = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(demo.join("fetch-raylib.ps1"))
        .status()
        .unwrap();
    assert!(fetch.success(), "fetch-raylib.ps1 failed");
    let rl = demo.join(r"vendor\raylib");

    let out = bin.parent().unwrap().join("cosmos-depths-c");
    std::fs::create_dir_all(&out).unwrap();
    let exe = out.join("cosmos-depths.exe");
    let script = format!(
        "@echo off\r\nset \"PATH=%PATH%;{}\"\r\ncall \"{}\" >nul || exit /b 1\r\n\
         cl /nologo /W4 /WX /MD /D_CRT_SECURE_NO_WARNINGS /I \"{}\" /I \"{}\" \"{}\" /Fo\"{}\\\\\" /Fe\"{}\" \
         /link \"{}\" \"{}\" opengl32.lib gdi32.lib winmm.lib user32.lib shell32.lib\r\n",
        vswhere_dir().display(),
        vcvars64().display(),
        repo.join("include").display(),
        rl.join("include").display(),
        demo.join(r"src\*.c").display(),
        out.display(),
        exe.display(),
        implib.display(),
        rl.join(r"lib\raylib.lib").display(),
    );
    let bat = out.join("build.bat");
    std::fs::write(&bat, script).unwrap();
    let b = Command::new("cmd").arg("/C").arg(&bat).current_dir(&out).output().unwrap();
    assert!(
        b.status.success(),
        "cl failed:\n{}{}",
        String::from_utf8_lossy(&b.stdout),
        String::from_utf8_lossy(&b.stderr)
    );

    let path = format!("{};{}", bin.display(), std::env::var("PATH").unwrap_or_default());
    let mut child = Command::new(&exe)
        .arg("--selftest")
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
        if start.elapsed() > Duration::from_secs(240) {
            child.kill().unwrap();
            panic!("cosmos-depths --selftest timed out");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let text = std::io::read_to_string(child.stdout.take().unwrap()).unwrap();
    println!("{text}");
    assert!(status.success(), "selftest exit {status}");
    for line in [
        "ok: same map from seed",
        "ok: player 1 move predicted at once, confirmed by host, seen by all",
        "ok: monster",
        "killed by player 2, gone for all 3",
        "ok: late 4th player got the seed, the dead monster and every position",
        "ok: note put by player 1, live on player 2 via subscription",
        "ok: note queried back by a fresh instance",
        "ok: death mark of player 3 queried back by a fresh instance",
    ] {
        assert!(text.contains(line), "missing '{line}'");
    }
    assert!(text.trim_end().ends_with("SELFTEST OK"));
}
