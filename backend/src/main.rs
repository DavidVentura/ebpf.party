use shared::GuestMessage;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, Instant};

mod compile;
mod config;
mod vm_pool;

fn main() {
    let config = Arc::new(
        config::Config::load("config.toml")
            .expect("Failed to load config.toml")
    );

    let vm_pool = Arc::new(vm_pool::VmPool::new(4, config.clone()));
    let listener = TcpListener::bind(&config.listen_address).unwrap();
    println!("Server running on {}", config.listen_address);

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let pool = vm_pool.clone();
        let cfg = config.clone();

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
            if path.starts_with("/run_code/") {
                run_code_handler(stream, &buf[..n], status.unwrap(), &req.headers, pool, cfg);
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
) {
    let start = Instant::now();

    let origin = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Origin"))
        .and_then(|h| std::str::from_utf8(h.value).ok());

    let cors_origin = origin
        .filter(|o| o.starts_with("http://localhost:") || o.starts_with("http://127.0.0.1:"))
        .unwrap_or("http://localhost:3000");

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
    // clang = ~50ms to fail, tinycc should be .. 2?
    // clang = 90~100ms to succeed
    // -- about 15ms to strip
    // with static, ~50ms to succeed, no strip needed (ish)
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

    let jh = thread::spawn(move || {
        for msg in rx {
            let json = serde_json::to_string(&msg).unwrap();
            stream
                .write_all(format!("data: {}\n\n", json).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        }
        stream.flush().unwrap();
    });

    let s = Instant::now();
    tx.send(GuestMessage::Compiling).unwrap();
    let c = compile::compile(&program, &config);
    println!("Compile of {} bytes took {:?}", program.len(), s.elapsed());
    let compiled = match c {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            let _ = tx.send(GuestMessage::CompileError(e));
            None
        }
    };

    if let Some(compiled) = compiled {
        match vm_pool.acquire(Duration::from_millis(2_000)) {
            Ok(permit) => {
                permit.run(tx, compiled);
                // running `vm` requires running through a KVM `Drop`
                // which takes like 30ms -- the request insta-flushed the msgs
                // so it only delays closing the connection, and skews
                // the VM measurement time
            }
            Err(_) => {
                let _ = tx.send(GuestMessage::NoCapacityLeft(
                    "My poor server can't handle this many requests. Please try again in a little bit.".to_string(),
                ));
                drop(tx);
            }
        }
    } else {
        drop(tx);
    }
    jh.join().unwrap();
    eprintln!("Run-code completed in {:?}", start.elapsed());
}
