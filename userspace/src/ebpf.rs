use libbpf_rs::{MapCore, MapType, ObjectBuilder, PrintLevel, RingBuffer, RingBufferBuilder};
use libbpf_sys::{LIBBPF_STRICT_ALL, libbpf_set_strict_mode};
use shared::GuestMessage;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

static VERIFIER_LOG: Mutex<String> = Mutex::new(String::new());
fn capturing_printer(lvl: PrintLevel, s: String) {
    if lvl == PrintLevel::Debug {
        return;
    }
    if let Ok(mut log) = VERIFIER_LOG.lock() {
        log.push_str(&s);
    }
}

pub fn run_program(program: &[u8], timeout: Duration, tx: Sender<GuestMessage>) {
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
    crate::EBPF_READY.store(true, Ordering::Relaxed);
    while start.elapsed() < timeout && !crate::SHOULD_STOP.load(Ordering::Relaxed) {
        let time_left = timeout.saturating_sub(start.elapsed());
        let min_dur = Duration::from_millis(10);
        if let Err(e) = pb.poll(std::cmp::min(time_left, min_dur)) {
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
