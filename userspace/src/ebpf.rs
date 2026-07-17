use libbpf_rs::{
    AsRawLibbpf, Link, MapCore, MapType, ObjectBuilder, PrintLevel, RingBuffer, RingBufferBuilder,
};
use libbpf_sys::{LIBBPF_STRICT_ALL, libbpf_set_strict_mode};
use shared::{AttachFailKind, GuestMessage};
use std::sync::Mutex;
use std::sync::atomic::Ordering;
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

/// A pathological program (e.g. an unbounded loop) can drive the verifier to
/// emit tens of megabytes of log. Left to itself libbpf grows its own buffer to
/// fit all of it; instead we hand each program a fixed buffer, so the kernel
/// keeps only the tail — which carries the verdict and our DIAG1 provenance
/// lines — bounding guest memory and everything we ship to the host.
const VERIFIER_LOG_CAP: usize = 32 * 1024;

/// The kernel log from the program that failed to load. Only the failing
/// program has a non-empty buffer: earlier programs loaded at log_level 0, and
/// libbpf aborts at the first failure. The buffer holds the raw, NUL-terminated
/// verifier log (no libbpf `BEGIN/END` wrapper, since we own the buffer).
fn failed_prog_log(log_bufs: &[Vec<u8>]) -> String {
    for buf in log_bufs {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        if end == 0 {
            continue;
        }
        let log = String::from_utf8_lossy(&buf[..end]);
        // A filled buffer means the verifier's rotating log dropped the head to
        // keep the tail; flag it so the partial first line is not mistaken for
        // the start of the program.
        if end >= VERIFIER_LOG_CAP - 1 {
            return format!(
                "[log truncated, showing last {} KiB]\n{}",
                VERIFIER_LOG_CAP / 1024,
                log
            );
        }
        return log.into_owned();
    }
    VERIFIER_LOG.lock().unwrap().clone()
}

pub struct ProgramDetails {
    pub name: String,
    pub section: String,
}
pub struct EbpfLoader<'a> {
    pb: RingBuffer<'a>,
    _links: Vec<Link>,
    pub program_details: Vec<ProgramDetails>,
}

impl<'a> EbpfLoader<'a> {
    pub fn load_program<F>(program: &[u8], ev_closure: F) -> Result<EbpfLoader<'a>, GuestMessage>
    where
        F: Fn(&[u8]) -> i32 + 'a,
    {
        unsafe {
            libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
        }

        if let Ok(mut log) = VERIFIER_LOG.lock() {
            log.clear();
        }

        libbpf_rs::set_print(Some((PrintLevel::Info, capturing_printer)));

        let mut open_obj = match ObjectBuilder::default().open_memory(program) {
            Ok(o) => o,
            Err(_) => {
                let captured_log = VERIFIER_LOG.lock().unwrap().clone();
                return Err(GuestMessage::LoadFail(captured_log));
            }
        };

        let mut log_bufs: Vec<Vec<u8>> = Vec::new();
        for prog in open_obj.progs_mut() {
            let mut buf = vec![0u8; VERIFIER_LOG_CAP];
            unsafe {
                libbpf_sys::bpf_program__set_log_buf(
                    prog.as_libbpf_object().as_ptr(),
                    buf.as_mut_ptr().cast(),
                    VERIFIER_LOG_CAP as _,
                );
            }
            log_bufs.push(buf);
        }

        let mut obj = match open_obj.load() {
            Ok(o) => o,
            Err(_) => return Err(GuestMessage::VerifierFail(failed_prog_log(&log_bufs))),
        };

        let mut links: Vec<_> = Vec::new();
        let mut program_details: Vec<_> = Vec::new();

        for p in obj.progs_mut() {
            let section = p.section().to_string_lossy().to_string();
            program_details.push(ProgramDetails {
                name: p.name().to_string_lossy().to_string(),
                section: section.clone(),
            });

            let link = match p.attach() {
                Ok(l) => l,
                Err(e) => {
                    let kind = match e.kind() {
                        libbpf_rs::ErrorKind::NotFound => AttachFailKind::NoSuchHook,
                        libbpf_rs::ErrorKind::PermissionDenied => AttachFailKind::Denied,
                        _ => AttachFailKind::Other,
                    };
                    return Err(GuestMessage::CantAttachProgram { section, kind });
                }
            };
            links.push(link);
        }
        if links.len() == 0 {
            return Err(GuestMessage::NoProgramsFound);
        }

        let mut pb: Option<RingBuffer> = None;

        for m in obj.maps_mut() {
            if m.map_type() == MapType::RingBuf && m.name().to_string_lossy() == "_ep_debug_events"
            {
                let mut rpb = RingBufferBuilder::new();
                rpb.add(&m, ev_closure).unwrap();
                pb = Some(rpb.build().unwrap());
                break;
            }
        }

        if let Some(pb) = pb {
            Ok(EbpfLoader {
                pb,
                _links: links,
                program_details,
            })
        } else {
            Err(GuestMessage::DebugMapNotFound)
        }
    }
    pub fn run(&self, timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout && !crate::SHOULD_STOP.load(Ordering::Relaxed) {
            let time_left = timeout.saturating_sub(start.elapsed());
            let min_dur = Duration::from_millis(10);
            if let Err(e) = self.pb.poll(std::cmp::min(time_left, min_dur)) {
                // Error polling perf buffer: Interrupted system call (os error 4)
                if e.kind() == libbpf_rs::ErrorKind::Interrupted {
                    continue;
                }
                eprintln!("Error polling perf buffer: {}", e);
                break;
            }
        }
    }
}
