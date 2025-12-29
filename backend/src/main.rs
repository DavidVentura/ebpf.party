use shared::GuestMessage;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use std::time::Instant;

mod compile;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:8081").unwrap();
    println!("Server running on http://0.0.0.0:8081");

    for stream in listener.incoming() {
        let stream = stream.unwrap();

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
                run_code_handler(stream, &buf[..n], status.unwrap(), &req.headers);
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
) {
    let start = Instant::now();

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
        println!("reading {to_read}");
        let bytes_read = stream.read(&mut buf[..to_read]).unwrap();
        println!("read {bytes_read}");
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
    let c = compile::compile(&program);
    println!("Compile of {} bytes took {:?}", program.len(), s.elapsed());
    let compiled = match c {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            let _ = tx.send(GuestMessage::CompileError(e));
            None
        }
    };

    if let Some(compiled) = compiled {
        vm(tx, compiled);
        // running `vm` requires running through a KVM `Drop`
        // which takes like 30ms -- the request insta-flushed the msgs
        // so it only delays closing the connection, and skews
        // the VM measurement time
    } else {
        drop(tx);
    }
    jh.join().unwrap();
    eprintln!("Run-code completed in {:?}", start.elapsed());
}

fn vm(out_tx: std::sync::mpsc::Sender<GuestMessage>, program: Vec<u8>) {
    let start = Instant::now();
    use firecracker_spawn::{Disk, Vm};

    let kernel = fs::File::open("../vmlinux").unwrap();
    // TODO unique vsock
    let vsock_path = "/tmp/test.v.sock";
    let port = 1234;
    let vsock_listener = format!("{}_{}", vsock_path, port);
    let _ = fs::remove_file(vsock_path);
    let _ = fs::remove_file(&vsock_listener);

    let v = Vm {
        vcpu_count: 1,
        mem_size_mib: 64,
        kernel,
        //kernel_cmdline: "ro panic=-1 reboot=t init=/strace -- -F /main execve.bpf.o".to_string(),
        kernel_cmdline: "quiet ro panic=-1 reboot=t init=/main".to_string(),
        rootfs: Some(Disk {
            path: PathBuf::from("../rootfs.ext4"),
            read_only: true,
        }),
        initrd: None,
        extra_disks: vec![],
        net_config: None,
        use_hugepages: true,                 // TODO
        vsock: Some(vsock_path.to_string()), // TODO
    };

    out_tx.send(GuestMessage::Booting).unwrap();
    let handle = thread::spawn(move || {
        let listener = UnixListener::bind(vsock_listener).unwrap();
        for stream in listener.incoming() {
            eprintln!("Host Connected, at {:?}", start.elapsed());
            match stream {
                Ok(mut stream) => {
                    let host_msg = shared::HostMessage::ExecuteProgram {
                        timeout: Duration::from_millis(500),
                        program,
                    };
                    let config = bincode::config::standard();
                    bincode::encode_into_std_write(&host_msg, &mut stream, config).unwrap();

                    while let Ok(msg) = bincode::decode_from_std_read::<shared::GuestMessage, _, _>(
                        &mut stream,
                        config,
                    ) {
                        let _ = out_tx.send(msg.clone());

                        match msg {
                            shared::GuestMessage::ExecutionResult(exec_msg) => {
                                if matches!(exec_msg, shared::ExecutionMessage::Finished()) {
                                    break;
                                }
                            }
                            _ => (),
                        }
                    }
                    println!("host disconnected");
                    break;
                }
                Err(_) => panic!("uh"),
            }
        }
    });
    v.make(Box::new(io::stdout())).unwrap();
    io::stdout().flush().unwrap();
    io::stderr().flush().unwrap();
    handle.join().unwrap();
}
