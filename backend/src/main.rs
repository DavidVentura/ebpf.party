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

    let content_length = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let mut program = Vec::new();
    let already_read = initial_buf.len() - body_offset;
    program.extend_from_slice(&initial_buf[body_offset..]);

    let mut remaining = content_length.saturating_sub(already_read);
    let mut buf = [0u8; 4096];
    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let bytes_read = stream.read(&mut buf[..to_read]).unwrap();
        if bytes_read == 0 {
            break;
        }
        program.extend_from_slice(&buf[..bytes_read]);
        remaining -= bytes_read;
    }
    // TODO, maybe do a tinycc pass, as quick check??
    // clang = ~50ms to fail, tinycc should be .. 2?
    // clang = 90~100ms to succeed
    // -- about 15ms to strip
    let s = Instant::now();
    let c = compile::compile(&program);
    println!("Compile of {} bytes took {:?}", program.len(), s.elapsed());
    let compiled = match c {
        Ok(bytes) => bytes,
        Err(e) => {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\n").unwrap();
            stream.write_all(b"\r\n").unwrap();
            stream
                .write_all(serde_json::to_string(&e).unwrap().as_bytes())
                .unwrap();
            return;
        }
    };

    stream.write_all(b"HTTP/1.1 200 OK\r\n").unwrap();
    stream
        .write_all(b"Content-Type: text/event-stream\r\n")
        .unwrap();
    stream.write_all(b"Cache-Control: no-cache\r\n").unwrap();
    stream.write_all(b"\r\n").unwrap();
    stream.flush().unwrap();

    let (tx, rx) = channel();
    let jh = thread::spawn(move || {
        vm(tx, &compiled);
    });

    for msg in rx {
        let json = serde_json::to_string(&msg).unwrap();
        stream
            .write_all(format!("data: {}\n\n", json).as_bytes())
            .unwrap();
        stream.flush().unwrap();
    }
    stream.flush().unwrap();
    eprintln!("Run-code completed in {:?}", start.elapsed());
    // this `jh.join` requires running through `Drop`
    // which takes like 30ms
    jh.join().unwrap();
}

fn vm(out_tx: std::sync::mpsc::Sender<GuestMessage>, program: &[u8]) {
    let start = Instant::now();
    use firecracker_spawn::{Disk, Vm};

    let kernel = fs::File::open("../vmlinux").unwrap();
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
        kernel_cmdline: "ro panic=-1 reboot=t init=/main -- execve.bpf.o".to_string(),
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

    let program = program.to_vec();
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
