use backend::compile;
use backend::config::Config;
use firecracker_spawn::{Disk, Vm};
use shared::GuestMessage;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Requires a kernel with the verifier provenance patch (see verifier-diagnostics.md
// at the repo root). Override the kernel with EBPF_PARTY_TEST_VMLINUX; regenerate
// goldens with UPDATE_GOLDEN=1.

fn run_in_vm(vmlinux: &Path, rootfs: &Path, program: Vec<u8>, id: usize) -> String {
    let vsock_path = format!("/tmp/diag_golden_{}_{}.v.sock", std::process::id(), id);
    let vsock_listener = format!("{}_1234", vsock_path);
    let _ = fs::remove_file(&vsock_path);
    let _ = fs::remove_file(&vsock_listener);

    let v = Vm {
        vcpu_count: 1,
        mem_size_mib: 64,
        kernel: fs::File::open(vmlinux).expect("cannot open vmlinux"),
        kernel_cmdline: "quiet ro panic=-1 reboot=t init=/main".to_string(),
        rootfs: Some(Disk {
            path: rootfs.to_path_buf(),
            read_only: true,
        }),
        initrd: None,
        extra_disks: vec![],
        net_config: None,
        use_hugepages: false,
        vsock: Some(vsock_path.clone()),
    };

    let listener = UnixListener::bind(&vsock_listener).unwrap();
    let handle = std::thread::spawn(move || {
        let mut stream = listener.incoming().next().unwrap().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let config = bincode::config::standard();
        let host_msg = shared::HostMessage::ExecuteProgram {
            exercise_id: shared::ExerciseId::PlatformOverview,
            timeout: Duration::from_millis(500),
            program,
            user_key: 0,
        };
        bincode::encode_into_std_write(&host_msg, &mut stream, config).unwrap();

        while let Ok(msg) =
            bincode::decode_from_std_read::<GuestMessage, _, _>(&mut stream, config)
        {
            match msg {
                GuestMessage::VerifierFail(log) => return log,
                GuestMessage::LoadFail(log) => {
                    panic!("program failed to load before verification:\n{}", log)
                }
                GuestMessage::DebugMapNotFound | GuestMessage::FoundProgram { .. } => {
                    panic!("program verified successfully, expected a verifier failure")
                }
                GuestMessage::Finished => panic!("guest finished without a verifier failure"),
                _ => continue,
            }
        }
        panic!("vsock stream ended without a verifier failure");
    });

    let vm = v.make(Box::new(std::io::sink()), Some(Duration::from_secs(10)));
    let log = handle.join().unwrap();
    drop(vm);
    let _ = fs::remove_file(&vsock_path);
    let _ = fs::remove_file(&vsock_listener);
    log
}

/// The error line and the DIAG1 trailer that follows it. None for failures
/// with no kernel provenance (ctx-access, some global-fn cases).
fn extract_diag_section(log: &str) -> Option<String> {
    let lines: Vec<&str> = log.lines().collect();
    let start = lines.iter().position(|l| l.starts_with("DIAG1 "))?;
    let end = lines.iter().rposition(|l| l.starts_with("DIAG1"))?;
    let mut section: Vec<&str> = Vec::new();
    if start > 0 {
        section.push(lines[start - 1]);
    }
    section.extend(&lines[start..=end]);
    Some(section.join("\n"))
}

/// Kernel pointers (map addresses in ld_imm64 dumps) differ per boot, and
/// clang prefixes <stdin> locations with the compile directory.
fn normalize(s: &str) -> String {
    let cwd = std::env::current_dir().unwrap();
    let s = &s.replace(&format!("{}/", cwd.display()), "");
    let mut out = String::with_capacity(s.len());
    let mut rest = s.as_str();
    while let Some(pos) = rest.find("0x") {
        let (head, tail) = rest.split_at(pos);
        out.push_str(head);
        let hex_len = tail[2..]
            .bytes()
            .take_while(|b| b.is_ascii_hexdigit())
            .count();
        if hex_len >= 8 {
            out.push_str("0xADDR");
        } else {
            out.push_str(&tail[..2 + hex_len]);
        }
        rest = &tail[2 + hex_len..];
    }
    out.push_str(rest);
    out
}

#[test]
fn diag_golden() {
    let config = Config {
        listen_address: String::new(),
        max_concurrent_vms: 1,
        clang_path: "./clang".into(),
        includes_path: "./includes/".into(),
        rootfs_path: "../rootfs.ext4".into(),
        vmlinux_path: "../vmlinux".into(),
    };
    let vmlinux: PathBuf = std::env::var("EBPF_PARTY_TEST_VMLINUX")
        .map(PathBuf::from)
        .unwrap_or_else(|_| config.vmlinux_path.clone());
    let update = std::env::var("UPDATE_GOLDEN").is_ok();

    let mut fixtures: Vec<PathBuf> = fs::read_dir("tests/data/diag")
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            p.to_str().unwrap().ends_with(".bpf.c").then_some(p)
        })
        .collect();
    fixtures.sort();
    assert!(!fixtures.is_empty(), "no fixtures in tests/data/diag");

    let mut failures = Vec::new();
    let mut check_golden = |golden_path: String, got: &str| {
        if update {
            fs::write(&golden_path, got).unwrap();
            return;
        }
        let want = fs::read_to_string(&golden_path)
            .unwrap_or_else(|_| panic!("missing golden {golden_path}, run with UPDATE_GOLDEN=1"));
        if got != want.trim_end() {
            failures.push(format!(
                "== {} ==\n-- expected --\n{}\n-- got --\n{}",
                golden_path, want, got
            ));
        }
    };

    for (i, fixture) in fixtures.iter().enumerate() {
        let source = fs::read(fixture).unwrap();
        let obj = compile::compile(&source, &config)
            .unwrap_or_else(|e| panic!("clang failed on {}:\n{}", fixture.display(), e));
        let log = run_in_vm(&vmlinux, &config.rootfs_path, obj.clone(), i);
        let path = fixture.to_str().unwrap();
        if let Some(section) = extract_diag_section(&log) {
            check_golden(path.replace(".bpf.c", ".golden"), &normalize(&section));
        }

        let dwarf_info = backend::dwarf::parse_dwarf_debug_info(&obj).ok();
        let diagnosis = backend::diag::diagnose(
            &log,
            std::str::from_utf8(&source).unwrap(),
            &obj,
            dwarf_info.as_ref(),
        )
        .unwrap_or_else(|| panic!("no diagnosis for {}", fixture.display()));
        check_golden(path.replace(".bpf.c", ".rendered"), &diagnosis.rendered);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
