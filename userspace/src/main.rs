use libbpf_rs::{MapCore, MapType, ObjectBuilder, PerfBuffer, PerfBufferBuilder, PrintLevel};
use libbpf_sys::{LIBBPF_STRICT_ALL, libbpf_set_strict_mode};
use std::ffi::CStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

fn printer(lvl: PrintLevel, s: String) {
    if lvl == PrintLevel::Debug {
        return;
    }
    eprint!("{}", s);
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

fn handle_lost_events(cpu: i32, lost_cnt: u64) {
    eprintln!("Lost {} events on CPU #{}!", lost_cnt, cpu);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <bpf_object.o>", args[0]);
        eprintln!("\nThis loader automatically:");
        eprintln!("  - Loads any BPF object file");
        eprintln!("  - Auto-attaches based on SEC() annotations");
        eprintln!("  - Handles perf buffers/ring buffers");
        eprintln!("  - Prints raw events as hex dumps");
        std::process::exit(1);
    }

    unsafe {
        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    }
    libbpf_rs::set_print(Some((PrintLevel::Info, printer)));

    let exiting = Arc::new(AtomicBool::new(false));
    let exiting_clone = exiting.clone();
    ctrlc::set_handler(move || {
        exiting_clone.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    println!("Loading BPF object: {}", args[1]);

    let open_obj = ObjectBuilder::default().open_file(&args[1]).unwrap();
    let mut obj = open_obj.load().unwrap();

    println!("✓ BPF object loaded successfully\n");

    println!("Attaching BPF programs:");
    let mut links: Vec<_> = Vec::new();

    for p in obj.progs_mut() {
        print!(
            "  - {} (section: {}) ... ",
            p.name().to_string_lossy(),
            p.section().to_string_lossy()
        );
        let link = p.attach().unwrap();
        println!("attached");
        links.push(link);
    }

    println!();

    let mut pb: Option<PerfBuffer> = None;

    for m in obj.maps_mut() {
        if m.map_type() == MapType::PerfEventArray {
            println!("Found perf event array: {}", m.name().to_string_lossy());

            pb = Some(
                PerfBufferBuilder::new(&m)
                    .sample_cb(handle_event)
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
            println!("No perf event array found. Programs are attached but not consuming events.");
            println!("Press Ctrl-C to exit...");

            while !exiting.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        Some(pb) => {
            println!("Listening for events (Ctrl-C to exit)...\n");
            while !exiting.load(Ordering::SeqCst) {
                if let Err(e) = pb.poll(Duration::from_millis(100)) {
                    eprintln!("Error polling perf buffer: {}", e);
                    break;
                }
            }
        }
    }
}
