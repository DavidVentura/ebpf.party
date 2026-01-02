use libbpf_rs::{MapCore, MapType, ObjectBuilder, PrintLevel, RingBuffer, RingBufferBuilder};
use libbpf_sys::{LIBBPF_STRICT_ALL, libbpf_set_strict_mode};
use shared::GuestMessage;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};
use vsock::{VMADDR_CID_HOST, VsockStream};

static VERIFIER_LOG: Mutex<String> = Mutex::new(String::new());
static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

fn capturing_printer(lvl: PrintLevel, s: String) {
    if lvl == PrintLevel::Debug {
        return;
    }
    if let Ok(mut log) = VERIFIER_LOG.lock() {
        log.push_str(&s);
    }
}

fn main() {
    let panics = std::panic::catch_unwind(|| {
        real_main();
    });
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
    if let Err(e) = panics {
        println!("panicked, bye! {e:?}");
    }
}
fn real_main() {
    if std::process::id() <= 100 {
        if let Err(e) = setup_host_env() {
            eprintln!("{}", e);
            return;
        }
    }

    let mut s_send = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, 1234).unwrap();
    let mut s_rcv = s_send.try_clone().unwrap();
    let msg = shared::GuestMessage::Booted;
    let config = bincode::config::standard();
    bincode::encode_into_std_write(&msg, &mut s_send, config).unwrap();

    let (tx, rx) = std::sync::mpsc::channel::<GuestMessage>();

    let jh = std::thread::spawn(move || {
        while let Ok(v) = rx.recv() {
            let _ = bincode::encode_into_std_write(&v, &mut s_send, config)
                .expect("can't send over vsock");

            if v.is_terminal() {
                SHOULD_STOP.store(true, Ordering::Relaxed);
            }
        }
    });

    // TODO: parametrize
    let panic_tx = tx.clone();
    let jh2 = std::thread::spawn(move || {
        let panics = std::panic::catch_unwind(|| {
            //exercise1();
            exercise_argv();
        });
        if let Err(_) = panics {
            let _ = panic_tx.send(GuestMessage::Crashed);
        }
    });

    match bincode::decode_from_std_read::<shared::HostMessage, _, _>(&mut s_rcv, config) {
        Ok(shared::HostMessage::ExecuteProgram { timeout, program }) => {
            run_ebpf_program(&program, timeout, tx);
        }
        Err(e) => {
            eprintln!("Failed to deserialize HostMessage: {}", e);
            //std::process::exit(1);
        }
    }
    jh.join().unwrap();
    jh2.join().unwrap();
}

fn exercise_argv() {
    let secret_command = &[
        "/bin/secret_command",
        "--user",
        "admin",
        "--password",
        "very safe",
    ];
    let ls = &["/bin/ls", "/home/"];
    let bash = &["/bin/sudo", "/bin/bash"];
    let mut cmds: [&[&str]; _] = [secret_command, ls, bash];
    for cmd in cmds {
        let prog = cmd[0];
        fs::copy("/true", prog).unwrap();
    }
    while !SHOULD_STOP.load(Ordering::Relaxed) {
        let (prog, args) = cmds[0].split_first().unwrap();
        let mut cmd = Command::new(prog).args(args).spawn().expect("missing bin");
        cmds.rotate_left(1);
        cmd.wait().unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn exercise1() {
    let mut cmds = ["/true", "/ls", "/git", "/bash", "/secret_command"];
    while !SHOULD_STOP.load(Ordering::Relaxed) {
        let mut cmd = Command::new(cmds[0]).spawn().expect("missing bin");
        cmds.rotate_left(1);
        cmd.wait().unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn mount(source: &str, target: &str, fstype: &str, flags: u64) -> Result<(), String> {
    let source = CString::new(source).unwrap();
    let target_c = CString::new(target).unwrap();
    let fstype = CString::new(fstype).unwrap();

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };

    if ret != 0 {
        return Err(format!(
            "Failed to mount {} at {}: {}",
            source.to_str().unwrap(),
            target,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn setup_host_env() -> Result<(), String> {
    mount("sysfs", "/sys", "sysfs", 0)?;
    fs::create_dir_all("/sys/kernel/tracing/").unwrap();
    mount("tracefs", "/sys/kernel/tracing", "tracefs", 0)?;
    mount("ramfs", "/bin", "ramfs", 0)?;
    Ok(())
}

fn run_ebpf_program(program: &[u8], timeout: Duration, tx: Sender<GuestMessage>) {
    unsafe {
        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    }

    if let Ok(mut log) = VERIFIER_LOG.lock() {
        log.clear();
    }

    libbpf_rs::set_print(Some((PrintLevel::Info, capturing_printer)));

    let open_obj = match ObjectBuilder::default().open_memory(program) {
        Ok(o) => o,
        Err(_) => {
            let captured_log = VERIFIER_LOG.lock().unwrap().clone();
            tx.send(GuestMessage::LoadFail(captured_log)).unwrap();
            return;
        }
    };

    let mut obj = match open_obj.load() {
        Ok(o) => o,
        Err(_) => {
            let captured_log = VERIFIER_LOG.lock().unwrap().clone();
            tx.send(GuestMessage::VerifierFail(captured_log)).unwrap();
            return;
        }
    };

    let mut links: Vec<_> = Vec::new();

    for p in obj.progs_mut() {
        tx.send(GuestMessage::FoundProgram {
            name: p.name().to_string_lossy().to_string(),
            section: p.section().to_string_lossy().to_string(),
        })
        .unwrap();
        let link = p.attach().unwrap(); // TODO
        links.push(link);
    }
    if links.len() == 0 {
        tx.send(GuestMessage::NoProgramsFound).unwrap();
        return;
    }

    let mut pb: Option<RingBuffer> = None;

    for m in obj.maps_mut() {
        if m.map_type() == MapType::RingBuf && m.name().to_string_lossy() == "_ep_debug_events" {
            let txer = tx.clone();
            let r_closure = move |data: &[u8]| {
                txer.send(GuestMessage::Event(data.into())).unwrap();
                0
            };

            let mut rpb = RingBufferBuilder::new();
            rpb.add(&m, r_closure).unwrap();
            pb = Some(rpb.build().unwrap());
            break;
        }
    }

    let pb = if let Some(pb) = pb {
        pb
    } else {
        tx.send(GuestMessage::DebugMapNotFound).unwrap();
        return;
    };

    let start = Instant::now();
    while start.elapsed() < timeout {
        let time_left = timeout.saturating_sub(start.elapsed());
        if let Err(e) = pb.poll(time_left) {
            // Error polling perf buffer: Interrupted system call (os error 4)
            if e.kind() == libbpf_rs::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("Error polling perf buffer: {}", e);
            break;
        }
    }
    tx.send(GuestMessage::Finished).unwrap();
}
