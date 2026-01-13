use std::convert::Infallible;
use std::fs;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use http::header;
use touche::{Body, HttpBody, Method, Request, Response, Server, StatusCode};

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

fn init_metrics(m: &mut Metrics) {
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
fn main() {
    let metrics = Arc::new(Mutex::new(Metrics::new()));
    let config = Arc::new(config::Config::load("config.toml").expect("Failed to load config.toml"));

    check_hugepages(config.max_concurrent_vms, 64).expect("Hugepages check failed");
    init_metrics(&mut metrics.lock().unwrap());

    let (metrics_tx, rx) = channel();
    let m = metrics.clone();
    thread::spawn(move || {
        metrics::process_metrics_events(rx, m);
    });

    let vm_pool = Arc::new(vm_pool::VmPool::new(
        config.max_concurrent_vms,
        config.clone(),
    ));

    println!("Server running on {}", config.listen_address);
    compile::pre_compile(&config).unwrap();

    let _ = Server::bind(&config.listen_address).make_service(move |conn: &touche::Connection| {
        conn.set_nodelay(true).ok();

        let pool = vm_pool.clone();
        let cfg = config.clone();
        let metrics_tx = metrics_tx.clone();
        let metrics = metrics.clone();

        Ok::<_, Infallible>(move |req: Request<Body>| {
            let pool = pool.clone();
            let cfg = cfg.clone();
            let metrics_tx = metrics_tx.clone();
            let metrics = metrics.clone();
            let start = Instant::now();

            let path = req.uri().path().to_string();
            let method = req.method().clone();
            println!("path is '{path}'");

            let response = match (method, path.as_str()) {
                (Method::GET, "/metrics") => handle_metrics(req, metrics),
                (Method::POST, path) if path.starts_with("/run_code/") => {
                    let exercise_id_str = &path[10..];
                    handle_run_code(req, pool, cfg, exercise_id_str, metrics_tx)
                }
                (_, path) if path.starts_with("/run_code/") => Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .header(header::ALLOW, "POST")
                    .body(Body::from("Method Not Allowed - use POST")),
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from("Not Found")),
            };

            eprintln!("Request completed in {:?}", start.elapsed());
            response
        })
    });
}

fn handle_metrics(
    _req: Request<Body>,
    metrics: Arc<Mutex<Metrics>>,
) -> Result<Response<Body>, http::Error> {
    let metrics_output = metrics.lock().unwrap().to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Body::from(metrics_output))
}

fn handle_run_code(
    req: Request<Body>,
    vm_pool: Arc<vm_pool::VmPool>,
    config: Arc<config::Config>,
    exercise_id_str: &str,
    metrics_tx: Sender<MetricEvent>,
) -> Result<Response<Body>, http::Error> {
    let start = Instant::now();

    let cors_origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .filter(|o| o.starts_with("http://localhost:") || o.starts_with("http://127.0.0.1:"))
        .unwrap_or("http://localhost:3000")
        .to_string();

    let exercise_id = match shared::ExerciseId::from_str(exercise_id_str) {
        Some(id) => id,
        _ => {
            let _ = metrics_tx.send(MetricEvent::BadExerciseRequest);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, cors_origin.as_str())
                .body(Body::from(format!(
                    "Invalid exercise ID: {}",
                    exercise_id_str
                )));
        }
    };

    let user_key: u64 = rand::random();

    const MAX_PROGRAM_SIZE: usize = 16 * 1024;

    let program = match req.into_body().into_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to read request body: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, cors_origin.as_str())
                .body(Body::from("Failed to read request body"));
        }
    };

    if program.len() > MAX_PROGRAM_SIZE {
        return Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, cors_origin.as_str())
            .body(Body::from(format!(
                "Program size {} exceeds maximum of {} bytes",
                program.len(),
                MAX_PROGRAM_SIZE
            )));
    }

    let (tx, rx) = channel();
    let (body_tx, body) = Body::channel();

    let user_key_clone = user_key;
    let mtx = metrics_tx.clone();
    thread::spawn(move || {
        handle_guest_events(body_tx, rx, mtx, exercise_id, user_key_clone);
    });

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

    let total_duration = start.elapsed();
    let _ = metrics_tx.send(MetricEvent::TotalRequestDuration {
        exercise_id,
        duration_secs: total_duration.as_secs_f64(),
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, cors_origin.as_str())
        .body(body)
}

fn send_msg(
    body_tx: &touche::body::BodyChannel,
    msg: &PlatformMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(msg)?;
    let sse_chunk = format!("data: {}\n\n", json);
    body_tx.send(sse_chunk)?;
    Ok(())
}

fn handle_guest_events(
    body_tx: touche::body::BodyChannel,
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
        if send_msg(&body_tx, &msg).is_err() {
            break;
        }
    }

    let answer_msg = match answer_count {
        0 => PlatformMessage::NoAnswer,
        1 => {
            let expected_answer = shared::get_answer(exercise_id, user_key);
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
    let _ = send_msg(&body_tx, &answer_msg);
    drop(body_tx);

    // also track metrics for answer
    if let Ok(r) = ExerciseResult::try_from(&answer_msg) {
        let sr = SubmissionResult {
            exercise: exercise_id,
            result: r,
        };
        let r = MetricEvent::ExerciseResult(sr);
        let _ = metrics_tx.send(r);
    }
}
