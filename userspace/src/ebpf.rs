use libbpf_rs::{Link, MapCore, MapType, ObjectBuilder, PrintLevel, RingBuffer, RingBufferBuilder};
use libbpf_sys::{LIBBPF_STRICT_ALL, libbpf_set_strict_mode};
use shared::GuestMessage;
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

pub fn extract_prog_load_log(log: &str) -> Option<String> {
    let begin = log.find("BEGIN PROG LOAD LOG")?;
    let end = log.find("END PROG LOAD LOG")?;
    let start = log[begin..].find('\n')? + begin + 1;
    Some(log[start..end].trim_end().to_string())
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

        let open_obj = match ObjectBuilder::default().open_memory(program) {
            Ok(o) => o,
            Err(_) => {
                let captured_log = VERIFIER_LOG.lock().unwrap().clone();
                return Err(GuestMessage::LoadFail(captured_log));
            }
        };

        let mut obj = match open_obj.load() {
            Ok(o) => o,
            Err(_) => {
                let captured_log = VERIFIER_LOG.lock().unwrap().clone();
                let prog_load_log = extract_prog_load_log(&captured_log);
                return Err(GuestMessage::VerifierFail(
                    prog_load_log.unwrap_or(captured_log),
                ));
            }
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
                Err(_e) => {
                    return Err(GuestMessage::CantAttachProgram(section));
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
