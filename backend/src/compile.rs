use serde::Serialize;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CompilerError {
    stdout: String,
    stderr: String,
}

pub fn compile(source: &[u8]) -> Result<Vec<u8>, CompilerError> {
    // TODO this is absolutely not unique
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let s = Instant::now();
    let temp_path = format!("/tmp/bpf_compile_{}.o", now);

    let mut clang = Command::new("clang")
        .args([
            "-g",
            "-O2",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-I.",
            "-I/usr/include/bpf",
            "-I/usr/include",
            "-x",
            "c",
            "-c",
            "-",
            "-o",
            &temp_path,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    clang.stdin.as_mut().unwrap().write_all(source).unwrap();
    let output = clang.wait_with_output().unwrap();

    if !output.status.success() {
        let _ = fs::remove_file(&temp_path);
        return Err(CompilerError {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    println!("Compile itself took {:?}", s.elapsed());
    let strip_output = Command::new("llvm-strip")
        .args(["-g", &temp_path])
        .output()
        .unwrap();

    if !strip_output.status.success() {
        eprintln!(
            "llvm-strip failed: {}",
            String::from_utf8_lossy(&strip_output.stderr)
        );
        let _ = fs::remove_file(&temp_path);
        return Err(CompilerError {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let compiled = fs::read(&temp_path).unwrap_or_default();
    let _ = fs::remove_file(&temp_path);

    Ok(compiled)
}
