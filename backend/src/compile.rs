use serde::Serialize;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProcessError {
    stdout: String,
    stderr: String,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum InputProcessingError {
    CompilerError(ProcessError),
    StripError(ProcessError),
}

pub fn compile(source: &[u8]) -> Result<Vec<u8>, InputProcessingError> {
    let s = Instant::now();

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
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    clang.stdin.as_mut().unwrap().write_all(source).unwrap();
    let output = clang.wait_with_output().unwrap();

    if !output.status.success() {
        return Err(InputProcessingError::CompilerError(ProcessError {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }));
    }

    println!("Compile itself took {:?}", s.elapsed());

    let compiled_bytes = output.stdout;

    let mut strip = Command::new("llvm-strip")
        .args(["-g", "-", "-o", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    strip
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&compiled_bytes)
        .unwrap();
    let strip_output = strip.wait_with_output().unwrap();

    if !strip_output.status.success() {
        eprintln!(
            "llvm-strip failed: {}",
            String::from_utf8_lossy(&strip_output.stderr)
        );
        return Err(InputProcessingError::StripError(ProcessError {
            stdout: String::from_utf8_lossy(&strip_output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&strip_output.stderr).to_string(),
        }));
    }

    Ok(strip_output.stdout)
}
