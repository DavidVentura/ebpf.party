use shared::GuestMessage;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tiny_http::{Response, Server};

fn main() {
    let server = Server::http("0.0.0.0:8081").unwrap();
    println!("Server running on http://0.0.0.0:8081");

    let (tx, rx) = channel();
    let jh = thread::spawn(move || {
        vm(tx);
    });
    for msg in rx {
        println!("rx got msg {msg:?}");
    }
    jh.join().unwrap();

    for request in server.incoming_requests() {
        let start = Instant::now();
        let (tx, rx) = channel();

        let jh = thread::spawn(move || {
            vm(tx);
        });

        let reader = ChannelReader::new(rx);

        println!("building response");
        let response = Response::new(
            tiny_http::StatusCode(200),
            vec![tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap()],
            reader,
            None,
            None,
        );

        println!("responding response");
        if let Err(e) = request.respond(response) {
            eprintln!("Failed to send response: {}", e);
        }
        println!("waiting thread");

        jh.join().unwrap();
        eprintln!("Request completed in {:?}", start.elapsed());
    }
}

struct ChannelReader {
    rx: Receiver<GuestMessage>,
    buffer: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: Receiver<GuestMessage>) -> Self {
        Self {
            rx,
            buffer: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.buffer.len() {
                let remaining = &self.buffer[self.pos..];
                let to_copy = remaining.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
                self.pos += to_copy;
                println!("ret ok");
                return Ok(to_copy);
            }

            match self.rx.recv() {
                Ok(msg) => {
                    println!("got msg");
                    self.buffer = format!("{:?}\n", msg).into_bytes();
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
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
        //kernel_cmdline: "ro panic=-1 reboot=t init=/strace -- /main execve.bpf.o".to_string(),
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
