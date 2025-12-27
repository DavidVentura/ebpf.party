use shared::GuestMessage;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use std::time::Instant;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:8081").unwrap();
    println!("Server running on http://0.0.0.0:8081");

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

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
            req.parse(&buf[..n]).unwrap();

            stream.write_all(b"HTTP/1.1 200 OK\r\n").unwrap();
            stream.write_all(b"Content-Type: text/plain\r\n").unwrap();
            stream.write_all(b"Transfer-Encoding: chunked\r\n").unwrap();
            stream.write_all(b"\r\n").unwrap();
            stream.flush().unwrap();

            let (tx, rx) = channel();
            let jh = thread::spawn(move || {
                vm(tx);
            });

            for msg in rx {
                let json = serde_json::to_string(&msg).unwrap();
                let data = format!("{}\n", json);
                let chunk = format!("{:x}\r\n{}\r\n", data.len(), data);
                stream.write_all(chunk.as_bytes()).unwrap();
                stream.flush().unwrap();
            }

            stream.write_all(b"0\r\n\r\n").unwrap();
            stream.flush().unwrap();

            eprintln!("Request completed in {:?}", start.elapsed());
            // this `jh.join` requires running through `Drop`
            // which takes like 30ms
            jh.join().unwrap();
            eprintln!("Resources freed in {:?}", start.elapsed());
        });
    }
}

fn vm(out_tx: std::sync::mpsc::Sender<GuestMessage>) {
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

    let handle = thread::spawn(move || {
        let listener = UnixListener::bind(vsock_listener).unwrap();
        for stream in listener.incoming() {
            eprintln!("Host Connected, at {:?}", start.elapsed());
            match stream {
                Ok(mut stream) => {
                    let program = fs::read("execve.bpf.o").unwrap();
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
