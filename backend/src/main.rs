use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use shared::GuestMessage;
use strum::IntoEnumIterator;

use crate::guest_message::UserAnswer;
use crate::metrics::{ExerciseResult, MetricEvent, Metrics, SubmissionResult};
use crate::types::PlatformMessage;

mod compile;
mod config;
mod dwarf;
mod guest_message;
mod metrics;
mod types;
mod vm_pool;

fn check_hugepages(required_vms: usize, vm_mem_mb: usize) -> Result<(), String> {
    const HUGEPAGE_SIZE_MB: usize = 2;
    let required_hugepages = (required_vms * vm_mem_mb + HUGEPAGE_SIZE_MB - 1) / HUGEPAGE_SIZE_MB;

    let nr_hugepages = fs::read_to_string("/proc/sys/vm/nr_hugepages")
        .map_err(|e| format!("Failed to read /proc/sys/vm/nr_hugepages: {}", e))?
        .trim()
        .parse::<usize>()
        .map_err(|e| format!("Failed to parse nr_hugepages: {}", e))?;

    if nr_hugepages < required_hugepages {
        return Err(format!(
            "Insufficient hugepages: need {} ({}MB each VM * {} VMs / {}MB hugepage), have {} configured",
            required_hugepages, vm_mem_mb, required_vms, HUGEPAGE_SIZE_MB, nr_hugepages
        ));
    }

    println!(
        "Hugepages OK: {} configured, {} required for {} VMs",
        nr_hugepages, required_hugepages, required_vms
    );
    Ok(())
}

fn main() {
    let config = Arc::new(config::Config::load("config.toml").expect("Failed to load config.toml"));

    check_hugepages(config.max_concurrent_vms, 64).expect("Hugepages check failed");

    let metrics = Arc::new(Mutex::new(Metrics::new()));
    let (metrics_tx, rx) = channel();
    let m = metrics.clone();
    thread::spawn(move || {
        metrics::process_metrics_events(rx, m);
    });

    {
        let mut m = metrics.lock().unwrap();
        for exercise_id in shared::ExerciseId::iter() {
            m.init(MetricEvent::CompileDuration {
                exercise_id,
                duration_secs: 0.0,
            });
            m.init(MetricEvent::VmBootDuration {
                exercise_id,
                duration_secs: 0.0,
            });
            m.init(MetricEvent::ExecutionDuration {
                exercise_id,
                duration_secs: 0.0,
            });
            m.init(MetricEvent::TotalRequestDuration {
                exercise_id,
                duration_secs: 0.0,
            });
            for result in ExerciseResult::iter() {
                let sr = SubmissionResult {
                    exercise: exercise_id,
                    result,
                };
                m.init(MetricEvent::ExerciseResult(sr));
            }
        }
    }

    let vm_pool = Arc::new(vm_pool::VmPool::new(
        config.max_concurrent_vms,
        config.clone(),
    ));
    let listener = TcpListener::bind(&config.listen_address).unwrap();
    println!("Server running on {}", config.listen_address);

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let pool = vm_pool.clone();
        let cfg = config.clone();
        let metrics_tx = metrics_tx.clone();
        let metrics = metrics.clone();

        thread::spawn(move || {
            let start = Instant::now();
            // Parse HTTP request headers
            let mut buf = [0u8; 4096];
            let n = {
                let mut stream_r = stream.try_clone().unwrap();
                stream_r.read(&mut buf).unwrap()
            };
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            let status = req.parse(&buf[..n]).unwrap();
            let path = req.path.unwrap_or("/");
            println!("path is '{path}'");
            if path == "/metrics" {
                let metrics_output = metrics.lock().unwrap().to_string();
                stream.write_all(b"HTTP/1.1 200 OK\r\n").unwrap();
                stream
                    .write_all(b"Content-Type: text/plain; version=0.0.4\r\n")
                    .unwrap();
                stream
                    .write_all(format!("Content-Length: {}\r\n", metrics_output.len()).as_bytes())
                    .unwrap();
                stream.write_all(b"\r\n").unwrap();
                stream.write_all(metrics_output.as_bytes()).unwrap();
            } else if path.starts_with("/run_code/") {
                let exercise_id_str = &path[10..];
                run_code_handler(
                    stream,
                    &buf[..n],
                    status.unwrap(),
                    &req.headers,
                    pool,
                    cfg,
                    exercise_id_str,
                    metrics_tx,
                );
            }

            eprintln!("Request completed in {:?}", start.elapsed());
        });
    }
}
fn run_code_handler(
    mut stream: TcpStream,
    initial_buf: &[u8],
    body_offset: usize,
    headers: &[httparse::Header],
    vm_pool: Arc<vm_pool::VmPool>,
    config: Arc<config::Config>,
    exercise_id_str: &str,
    metrics_tx: Sender<MetricEvent>,
) {
    let start = Instant::now();

    let origin = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Origin"))
        .and_then(|h| std::str::from_utf8(h.value).ok());

    let cors_origin = origin
        .filter(|o| o.starts_with("http://localhost:") || o.starts_with("http://127.0.0.1:"))
        .unwrap_or("http://localhost:3000");

    let exercise_id = match shared::ExerciseId::from_str(exercise_id_str) {
        Some(id) => id,
        None => {
            let _ = metrics_tx.send(MetricEvent::BadExerciseRequest);
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\n").unwrap();
            stream
                .write_all(format!("Access-Control-Allow-Origin: {}\r\n", cors_origin).as_bytes())
                .unwrap();
            stream.write_all(b"\r\n").unwrap();
            stream
                .write_all(format!("Invalid exercise ID: {}", exercise_id_str).as_bytes())
                .unwrap();
            return;
        }
    };

    let user_key: u64 = rand::random();

    let has_expect_continue = headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("Expect") && h.value == b"100-continue");

    if has_expect_continue {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        stream.flush().unwrap();
    }

    let content_length = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let mut program = Vec::new();
    let already_read = initial_buf.len() - body_offset;
    program.extend_from_slice(&initial_buf[body_offset..]);

    const MAX_PROGRAM_SIZE: usize = 16 * 1024;
    let mut remaining = content_length.saturating_sub(already_read);
    let mut buf = [0u8; 16 * 4096];
    while remaining > 0 && program.len() <= MAX_PROGRAM_SIZE {
        let to_read = remaining.min(buf.len());
        let bytes_read = stream.read(&mut buf[..to_read]).unwrap();
        if bytes_read == 0 {
            break;
        }
        program.extend_from_slice(&buf[..bytes_read]);
        remaining -= bytes_read;
    }
    if program.len() > MAX_PROGRAM_SIZE {
        stream
            .write_all(b"HTTP/1.1 413 Content Too Large\r\n")
            .unwrap();
        stream
            .write_all(format!("Access-Control-Allow-Origin: {}\r\n", cors_origin).as_bytes())
            .unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream
            .write_all(
                format!(
                    "Program size {} exceeds maximum of {} bytes",
                    program.len(),
                    MAX_PROGRAM_SIZE
                )
                .as_bytes(),
            )
            .unwrap();
        return;
    }

    // TODO, maybe do a tinycc pass, as quick check??
    // clang = ~20ms to fail, tinycc should be .. 2?
    // clang = ~30ms to succeed
    let (tx, rx) = channel();

    stream.write_all(b"HTTP/1.1 200 OK\r\n").unwrap();
    stream
        .write_all(b"Content-Type: text/event-stream\r\n")
        .unwrap();
    stream.write_all(b"Cache-Control: no-cache\r\n").unwrap();
    stream
        .write_all(format!("Access-Control-Allow-Origin: {}\r\n", cors_origin).as_bytes())
        .unwrap();
    stream.write_all(b"\r\n").unwrap();
    stream.flush().unwrap();

    let user_key_clone = user_key;
    let mtx = metrics_tx.clone();
    let jh =
        thread::spawn(move || handle_guest_events(stream, rx, mtx, exercise_id, user_key_clone));

    let s = Instant::now();
    tx.send(PlatformMessage::Compiling).unwrap();
    let c = compile::compile(&program, &config);
    let compile_duration = s.elapsed();
    let compiled = match c {
        Ok(bytes) => {
            let _ = metrics_tx.send(MetricEvent::CompileDuration {
                exercise_id,
                duration_secs: compile_duration.as_secs_f64(),
            });
            Some(bytes)
        }
        Err(e) => {
            // TODO track content to improve TCC
            let _ = tx.send(PlatformMessage::CompileError(e));
            None
        }
    };

    if let Some(compiled) = compiled {
        match vm_pool.acquire(Duration::from_millis(2_000)) {
            Ok(permit) => {
                if let Ok(stack) = dwarf::parse_dwarf_debug_info(compiled.as_slice()) {
                    let _ = tx.send(PlatformMessage::Stack(stack));
                }
                let _ = tx.send(PlatformMessage::Booting).unwrap();
                permit.run(tx, compiled, exercise_id, user_key, metrics_tx.clone());
            }
            Err(_) => {
                let _ = tx.send(PlatformMessage::NoCapacityLeft(
                    "My poor server can't handle this many requests. Please try again in a little bit.".to_string(),
                ));
                drop(tx);
            }
        }
    } else {
        drop(tx);
    }
    jh.join().unwrap();
    let total_duration = start.elapsed();
    let _ = metrics_tx.send(MetricEvent::TotalRequestDuration {
        exercise_id,
        duration_secs: total_duration.as_secs_f64(),
    });
}

fn send_msg(stream: &mut TcpStream, msg: &PlatformMessage) -> Result<(), std::io::Error> {
    let json = serde_json::to_string(msg).unwrap();

    stream.write_all(format!("data: {}\n\n", json).as_bytes())?;
    let _ = stream.flush();
    Ok(())
}

impl TryFrom<&PlatformMessage> for ExerciseResult {
    type Error = ();
    fn try_from(value: &PlatformMessage) -> Result<Self, Self::Error> {
        match value {
            PlatformMessage::CorrectAnswer => Ok(ExerciseResult::Success),
            PlatformMessage::WrongAnswer => Ok(ExerciseResult::Fail),
            PlatformMessage::MultipleAnswers => Ok(ExerciseResult::MultipleAnswer),
            PlatformMessage::NoAnswer => Ok(ExerciseResult::NoAnswer),

            PlatformMessage::CompileError(..) => Ok(ExerciseResult::CompileError),
            PlatformMessage::NoCapacityLeft(..) => Ok(ExerciseResult::NoCapacityLeft),

            PlatformMessage::Booting => Err(()),
            PlatformMessage::Compiling => Err(()),
            PlatformMessage::Stack(..) => Err(()),

            PlatformMessage::GuestMessage(gm) => match gm {
                // not interested to track
                GuestMessage::Booted => Err(()),
                GuestMessage::Event(..) => Err(()),
                GuestMessage::Finished => Err(()),
                GuestMessage::FoundMap { .. } => Err(()),
                GuestMessage::FoundProgram { .. } => Err(()),
                GuestMessage::NoProgramsFound => Err(()),

                // interesting
                GuestMessage::DebugMapNotFound => Ok(ExerciseResult::DebugMapNotFound),
                GuestMessage::LoadFail(..) => Ok(ExerciseResult::VerifierFail),
                GuestMessage::VerifierFail(..) => Ok(ExerciseResult::VerifierFail),
                GuestMessage::Crashed => Ok(ExerciseResult::Crashed),
            },
        }
    }
}
fn handle_guest_events(
    mut stream: TcpStream,
    rx: Receiver<PlatformMessage>,
    metrics_tx: Sender<MetricEvent>,
    exercise_id: shared::ExerciseId,
    user_key: u64,
) {
    let mut answer = None::<UserAnswer>;
    let mut answer_count = 0u8;
    for msg in rx {
        if let Some(this_answer) = guest_message::extract_answer(&msg) {
            answer_count = answer_count.saturating_add(1);
            if answer.is_none() {
                answer = Some(this_answer);
            }
            continue;
        }

        if let Ok(r) = ExerciseResult::try_from(&msg) {
            let sr = SubmissionResult {
                exercise: exercise_id,
                result: r,
            };
            let r = MetricEvent::ExerciseResult(sr);
            let _ = metrics_tx.send(r);
        }

        // forward all messages
        // disconnected is not a big deal
        if let Err(_) = send_msg(&mut stream, &msg) {
            break;
        }
    }
    let answer_msg = match answer_count {
        0 => PlatformMessage::NoAnswer,
        1 => {
            let expected_answer = shared::get_answer(exercise_id, user_key);
            println!("E {expected_answer:?}");
            let is_correct = match answer.as_ref().unwrap() {
                UserAnswer::String(submitted) => {
                    let trimmed = submitted
                        .iter()
                        .rposition(|&b| b != 0)
                        .map(|pos| &submitted[..=pos])
                        .unwrap_or(&[]);

                    trimmed == &expected_answer[..]
                }
                UserAnswer::Number(submitted) => &expected_answer[..] == submitted,
            };

            if is_correct {
                PlatformMessage::CorrectAnswer
            } else {
                PlatformMessage::WrongAnswer
            }
        }
        _ => PlatformMessage::MultipleAnswers,
    };
    let _ = send_msg(&mut stream, &answer_msg);
    // also submit answer
    if let Ok(r) = ExerciseResult::try_from(&answer_msg) {
        let sr = SubmissionResult {
            exercise: exercise_id,
            result: r,
        };
        let r = MetricEvent::ExerciseResult(sr);
        let _ = metrics_tx.send(r);
    }
}
