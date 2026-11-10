//! Finds MSVC for the C example tests: vswhere, then vcvars64 (cl is not on PATH).

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn vswhere_dir() -> PathBuf {
    let pf = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
    Path::new(&pf).join(r"Microsoft Visual Studio\Installer")
}

pub fn vcvars64() -> PathBuf {
    let vswhere = vswhere_dir().join("vswhere.exe");
    let out = Command::new(&vswhere)
        .args(["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"])
        .args(["-property", "installationPath"])
        .output()
        .unwrap_or_else(|e| panic!("vswhere at {}: {e}", vswhere.display()));
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(!root.is_empty(), "no Visual Studio with the x64 C++ tools found");
    let p = Path::new(&root).join(r"VC\Auxiliary\Build\vcvars64.bat");
    assert!(p.exists(), "missing {}", p.display());
    p
}
