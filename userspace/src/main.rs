use libbpf_rs::{MapCore, MapType, ObjectBuilder, PerfBuffer, PerfBufferBuilder, PrintLevel};
use libbpf_sys::{LIBBPF_STRICT_ALL, libbpf_set_strict_mode};
use shared::{ExecutionMessage, GuestMessage};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant, SystemTime};
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

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum DebugType {
    U32 = 1,
    U64 = 2,
    Str = 3,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct DebugEventU32 {
    label: [u8; 15],
    value: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct DebugEventU64 {
    label: [u8; 15],
    value: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct DebugEventStr {
    label: [u8; 15],
    value: [u8; 16],
}

#[repr(C, packed)]
union DebugEventData {
    u32: DebugEventU32,
    u64: DebugEventU64,
    str: DebugEventStr,
}

#[repr(C, packed)]
struct DebugEvent {
    event_type: u8,
    data: DebugEventData,
}

fn handle_lost_events(cpu: i32, lost_cnt: u64) {
    eprintln!("Lost {} events on CPU #{}!", lost_cnt, cpu);
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
                    | ExecutionMessage::NoPerfMapsFound
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

    let jh2 = std::thread::spawn(|| {
        while !SHOULD_STOP.load(Ordering::Relaxed) {
            let mut cmd = Command::new("/true").spawn().expect("where true");
            cmd.wait().unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    //println!("Waiting for ExecuteProgram message from host");
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

fn handle_event(cpu: i32, data: &[u8]) {
    if data.len() >= std::mem::size_of::<DebugEvent>()
        && data.len() <= std::mem::size_of::<DebugEvent>() + 8
    {
        let event = unsafe { &*(data.as_ptr() as *const DebugEvent) };

        if event.event_type >= DebugType::U32 as u8 && event.event_type <= DebugType::Str as u8 {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            print!(
                "[{:6}.{:06}] [CPU {}] ",
                now.as_secs(),
                now.subsec_micros(),
                cpu
            );

            unsafe {
                match event.event_type {
                    1 => {
                        let label = CStr::from_bytes_until_nul(&event.data.u32.label)
                            .unwrap_or(CStr::from_bytes_with_nul(b"\0").unwrap())
                            .to_string_lossy();
                        let value = std::ptr::addr_of!(event.data.u32.value).read_unaligned();
                        println!("{:<20} = {}", label, value);
                    }
                    2 => {
                        let label = CStr::from_bytes_until_nul(&event.data.u64.label)
                            .unwrap_or(CStr::from_bytes_with_nul(b"\0").unwrap())
                            .to_string_lossy();
                        let value = std::ptr::addr_of!(event.data.u64.value).read_unaligned();
                        println!("{:<20} = {}", label, value);
                    }
                    3 => {
                        let label = CStr::from_bytes_until_nul(&event.data.str.label)
                            .unwrap_or(CStr::from_bytes_with_nul(b"\0").unwrap())
                            .to_string_lossy();
                        let value = CStr::from_bytes_until_nul(&event.data.str.value)
                            .unwrap_or(CStr::from_bytes_with_nul(b"\0").unwrap())
                            .to_string_lossy();
                        println!("{:<20} = \"{}\"", label, value);
                    }
                    _ => {}
                }
            }
            return;
        }
    }

    print!("[CPU {}] Raw event ({} bytes):\n  ", cpu, data.len());
    for (i, byte) in data.iter().take(256).enumerate() {
        print!("{:02x} ", byte);
        if (i + 1) % 16 == 0 && i + 1 < data.len().min(256) {
            print!("\n  ");
        }
    }
    println!();
}

fn list_traces() {
    eprintln!("\n=== Listing /sys/kernel/tracing ===");
    if let Ok(entries) = std::fs::read_dir("/sys/kernel/tracing") {
        for entry in entries.flatten() {
            eprintln!("  {}", entry.file_name().to_string_lossy());
        }
    }

    eprintln!("\n=== Listing /sys/kernel/tracing/events ===");
    if let Ok(entries) = std::fs::read_dir("/sys/kernel/tracing/events") {
        for entry in entries.flatten() {
            eprintln!("  {}", entry.file_name().to_string_lossy());
        }
    }

    eprintln!("\n=== Listing /sys/kernel/tracing/events/syscalls ===");
    if let Ok(entries) = std::fs::read_dir("/sys/kernel/tracing/events/syscalls") {
        for entry in entries.flatten() {
            eprintln!("  {}", entry.file_name().to_string_lossy());
        }
    } else {
        eprintln!("  (directory does not exist or cannot be read)");
    }

    eprintln!("\n=== Listing /sys/kernel/tracing/events/syscalls/sys_enter_execve ===");
    if let Ok(entries) = std::fs::read_dir("/sys/kernel/tracing/events/syscalls/sys_enter_execve") {
        for entry in entries.flatten() {
            eprintln!("  {}", entry.file_name().to_string_lossy());
        }
    } else {
        eprintln!("  (directory does not exist or cannot be read)");
    }
    eprintln!();
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

    if false {
        list_traces();
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

    let mut pb: Option<PerfBuffer> = None;

    for m in obj.maps_mut() {
        if m.map_type() == MapType::PerfEventArray {
            tx.send(ExecutionMessage::FoundMap {
                name: m.name().to_string_lossy().to_string(),
            })
            .unwrap();

            let txer = tx.clone();
            let closure = move |cpu: i32, data: &[u8]| {
                //let ev = handle_event(cpu, data);
                txer.send(ExecutionMessage::Event(data.into())).unwrap();
            };
            pb = Some(
                // TODO pass tx clone to closure?
                PerfBufferBuilder::new(&m)
                    .sample_cb(closure)
                    .lost_cb(handle_lost_events)
                    .pages(8)
                    .build()
                    .unwrap(),
            );
            break;
        }
    }

    match pb {
        None => {
            tx.send(ExecutionMessage::NoPerfMapsFound).unwrap();
        }
        Some(pb) => {
            let start = Instant::now();
            while start.elapsed() < timeout {
                let time_left = timeout.saturating_sub(start.elapsed());
                if let Err(e) = pb.poll(time_left) {
                    eprintln!("Error polling perf buffer: {}", e);
                    break;
                }
            }
        }
    }
    tx.send(ExecutionMessage::Finished()).unwrap();
}
