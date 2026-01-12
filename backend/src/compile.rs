use crate::config::Config;
use std::io::Write;
use std::process::{Command, Stdio};

pub fn pre_compile(config: &Config) -> Result<Vec<u8>, String> {
    let h_path = config.includes_path.join("task.h");
    let pch_path = config.includes_path.join("task.h.pch");
    let args = [
        "-g",
        "-fpch-debuginfo",
        "-O2",
        "-target",
        "bpf",
        "-fno-builtin", // avoid builtin memcpy
        "-x",
        "c-header",
        &h_path.display().to_string(),
        "-o",
        &pch_path.display().to_string(),
    ];
    let clang = Command::new(&config.clang_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Can't launch clang");

    let output = clang.wait_with_output().unwrap();

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(output.stdout)
}
pub fn compile(source: &[u8], config: &Config) -> Result<Vec<u8>, String> {
    let includes_flag = format!("-I{}", config.includes_path.display());
    let pch_path = config.includes_path.join("task.h.pch");

    let args = [
        "-g",
        "-gmodules",
        "-O2",
        "-target",
        "bpf",
        "-D__TARGET_ARCH_x86",
        "-include-pch",
        &pch_path.display().to_string(),
        // pch+gmodules means
        // symbols are not part of this
        //"-I/usr/include/bpf",
        &includes_flag,
        "-fno-builtin", // avoid builtin memcpy
        "-x",
        "c",
        "-c",
        "-",
        "-o",
        "-",
    ];
    let mut clang = Command::new(&config.clang_path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Can't launch clang");

    clang.stdin.as_mut().unwrap().write_all(source).unwrap();
    let output = clang.wait_with_output().unwrap();

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(output.stdout)
}
