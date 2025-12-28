use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

pub fn compile(source: &[u8]) -> Result<Vec<u8>, String> {
    let s = Instant::now();

    let mut clang = Command::new("/home/david/git/ebpf-playground/clang/bin/clang")
        .args([
            "-g",
            "-gmodules",
            "-O2",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-include-pch",
            "task.h.pch", // pch+gmodules means
            // symbols are not part of this
            "-I/usr/include/bpf",
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
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    println!(
        "Compiling {} bytes to {} bytes took {:?}",
        source.len(),
        output.stdout.len(),
        s.elapsed()
    );
    Ok(output.stdout)
}
