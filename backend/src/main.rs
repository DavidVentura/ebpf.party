use rouille::Response;
use serde::Serialize;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::Instant;
use threadpool::ThreadPool;

#[derive(Serialize)]
struct Data<'a> {
    req: Option<&'a str>,
}

fn main() {
    let workers = 32;
    let _ = ThreadPool::new(workers);

    vm();
    rouille::start_server("0.0.0.0:8081", move |request| {
        let start = Instant::now();
        vm();
        println!("VM Done {:?}", start.elapsed());
        let data = Data {
            req: request.header("X-User-Id"),
        };
        Response::json(&data)
    });
}

fn vm() {
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
            println!("Host Connected, at {:?}", start.elapsed());
            match stream {
                Ok(mut stream) => {
                    let config = bincode::config::standard();
                    match bincode::decode_from_std_read::<shared::GuestMessage, _, _>(&mut stream, config) {
                        Ok(msg) => {
                            println!("Host received message: {:?}", msg);

                            match msg {
                                shared::GuestMessage::Booted => {
                                    let program = fs::read("execve.bpf.o").unwrap();
                                    let host_msg = shared::HostMessage::ExecuteProgram {
                                        timeout_ms: 5000,
                                        program,
                                    };
                                    bincode::encode_into_std_write(&host_msg, &mut stream, config).unwrap();
                                    println!("Sent ExecuteProgram to guest");
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to deserialize GuestMessage: {}", e);
                        }
                    }
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
