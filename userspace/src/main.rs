use libbpf_rs::{MapCore, MapType, ObjectBuilder, PrintLevel, RingBuffer, RingBufferBuilder};
use libbpf_sys::{LIBBPF_STRICT_ALL, libbpf_set_strict_mode};
use shared::{ExecutionMessage, GuestMessage};
use std::ffi::CString;
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
        setup_host_env();
    }

    let mut s_send = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, 1234).unwrap();
    let mut s_rcv = s_send.try_clone().unwrap();
    let msg = shared::GuestMessage::Booted;
    let config = bincode::config::standard();
    bincode::encode_into_std_write(&msg, &mut s_send, config).unwrap();

    let (tx, rx) = std::sync::mpsc::channel::<ExecutionMessage>();

    let jh = std::thread::spawn(move || {
        while let Ok(v) = rx.recv() {
            let is_terminal = matches!(
                v,
                ExecutionMessage::LoadFail(_)
                    | ExecutionMessage::VerifierFail(_)
                    | ExecutionMessage::DebugMapNotFound
                    | ExecutionMessage::NoProgramsFound
                    | ExecutionMessage::Finished()
            );

            let _ = bincode::encode_into_std_write(
                GuestMessage::ExecutionResult(v),
                &mut s_send,
                config,
            )
            .expect("can't send over vsock");

            if is_terminal {
                SHOULD_STOP.store(true, Ordering::Relaxed);
            }
        }
    });

    // TODO: parametrize
    let jh2 = std::thread::spawn(|| {
        exercise1();
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

fn exercise1() {
    let mut cmds = ["/true", "/ls", "/git", "/bash", "/secret_command"];
    while !SHOULD_STOP.load(Ordering::Relaxed) {
        let mut cmd = Command::new(cmds[0]).spawn().expect("missing bin");
        cmds.rotate_left(1);
        cmd.wait().unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn setup_host_env() {
    let target = CString::new("/sys").unwrap();

    unsafe {
        libc::mkdir(target.as_ptr(), 0o755);
    }

    let source = CString::new("sysfs").unwrap();
    let fstype = CString::new("sysfs").unwrap();

    unsafe {
        let ret = libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        );
        if ret != 0 {
            panic!("Failed to mount /sys: {}", std::io::Error::last_os_error());
        }
    }

    let sys_kernel = CString::new("/sys/kernel").unwrap();
    let sys_kernel_tracing = CString::new("/sys/kernel/tracing").unwrap();

    unsafe {
        libc::mkdir(sys_kernel.as_ptr(), 0o755);
        libc::mkdir(sys_kernel_tracing.as_ptr(), 0o755);
    }

    let tracefs_source = CString::new("tracefs").unwrap();
    let tracefs_type = CString::new("tracefs").unwrap();

    unsafe {
        let ret = libc::mount(
            tracefs_source.as_ptr(),
            sys_kernel_tracing.as_ptr(),
            tracefs_type.as_ptr(),
            0,
            std::ptr::null(),
        );
        if ret != 0 {
            panic!(
                "Failed to mount tracefs: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

fn run_ebpf_program(program: &[u8], timeout: Duration, tx: Sender<ExecutionMessage>) {
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
            tx.send(ExecutionMessage::LoadFail(captured_log)).unwrap();
            return;
        }
    };

    let mut obj = match open_obj.load() {
        Ok(o) => o,
        Err(_) => {
            let captured_log = VERIFIER_LOG.lock().unwrap().clone();
            tx.send(ExecutionMessage::VerifierFail(captured_log))
                .unwrap();
            return;
        }
    };

    let mut links: Vec<_> = Vec::new();

    for p in obj.progs_mut() {
        tx.send(ExecutionMessage::FoundProgram {
            name: p.name().to_string_lossy().to_string(),
            section: p.section().to_string_lossy().to_string(),
        })
        .unwrap();
        let link = p.attach().unwrap(); // TODO
        links.push(link);
    }
    if links.len() == 0 {
        tx.send(ExecutionMessage::NoProgramsFound).unwrap();
        return;
    }

    let mut pb: Option<RingBuffer> = None;

    for m in obj.maps_mut() {
        if m.map_type() == MapType::RingBuf && m.name().to_string_lossy() == "_ep_debug_events" {
            let txer = tx.clone();
            let r_closure = move |data: &[u8]| {
                txer.send(ExecutionMessage::Event(data.into())).unwrap();
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
        tx.send(ExecutionMessage::DebugMapNotFound).unwrap();
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
    tx.send(ExecutionMessage::Finished()).unwrap();
}
