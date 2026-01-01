use crate::config::Config;
use crate::types::PlatformMessage;
use firecracker_spawn::{Disk, Vm};
use shared::GuestMessage;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TimeoutError;

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Timeout waiting for VM permit")
    }
}

impl std::error::Error for TimeoutError {}

pub struct VmPool {
    semaphore: Arc<Semaphore>,
    config: Arc<Config>,
}

impl VmPool {
    pub fn new(max_concurrent: usize, config: Arc<Config>) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            config,
        }
    }

    pub fn acquire(&self, timeout: Duration) -> Result<VmPermit, TimeoutError> {
        self.semaphore.acquire(timeout)?;
        Ok(VmPermit {
            semaphore: self.semaphore.clone(),
            config: self.config.clone(),
            vsock_path: None,
            vsock_listener: None,
        })
    }
}

pub struct VmPermit {
    semaphore: Arc<Semaphore>,
    config: Arc<Config>,
    vsock_path: Option<String>,
    vsock_listener: Option<String>,
}

impl VmPermit {
    pub fn run(mut self, out_tx: std::sync::mpsc::Sender<PlatformMessage>, program: Vec<u8>) {
        let start = Instant::now();

        static VM_COUNTER: AtomicU64 = AtomicU64::new(0);
        let vm_id = VM_COUNTER.fetch_add(1, Ordering::SeqCst);
        let vsock_path = format!("/tmp/vm_{}.v.sock", vm_id);
        let port = 1234;
        let vsock_listener = format!("{}_{}", vsock_path, port);

        self.vsock_path = Some(vsock_path.clone());
        self.vsock_listener = Some(vsock_listener.clone());

        let kernel = fs::File::open(&self.config.vmlinux_path).unwrap();
        let _ = fs::remove_file(&vsock_path);
        let _ = fs::remove_file(&vsock_listener);

        let v = Vm {
            vcpu_count: 1,
            mem_size_mib: 64,
            kernel,
            kernel_cmdline: "quiet ro panic=-1 reboot=t init=/main".to_string(),
            rootfs: Some(Disk {
                path: self.config.rootfs_path.clone(),
                read_only: true,
            }),
            initrd: None,
            extra_disks: vec![],
            net_config: None,
            use_hugepages: true,
            vsock: Some(vsock_path.to_string()),
        };

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

                        while let Ok(msg) =
                            bincode::decode_from_std_read::<GuestMessage, _, _>(&mut stream, config)
                        {
                            let _ = out_tx.send(PlatformMessage::GuestMessage(msg.clone()));

                            match msg {
                                GuestMessage::Finished() => {
                                    break;
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
}

impl Drop for VmPermit {
    fn drop(&mut self) {
        if let Some(ref path) = self.vsock_path {
            let _ = fs::remove_file(path);
        }
        if let Some(ref path) = self.vsock_listener {
            let _ = fs::remove_file(path);
        }
        self.semaphore.release();
    }
}

struct Semaphore {
    count: Mutex<usize>,
    condvar: Condvar,
    max: usize,
}

impl Semaphore {
    fn new(max: usize) -> Self {
        Self {
            count: Mutex::new(0),
            condvar: Condvar::new(),
            max,
        }
    }

    fn acquire(&self, timeout: Duration) -> Result<(), TimeoutError> {
        let mut count = self.count.lock().unwrap();
        let deadline = Instant::now() + timeout;

        while *count >= self.max {
            let now = Instant::now();
            if now >= deadline {
                return Err(TimeoutError);
            }
            let remaining = deadline - now;
            let result = self.condvar.wait_timeout(count, remaining).unwrap();
            count = result.0;
            if result.1.timed_out() {
                return Err(TimeoutError);
            }
        }
        *count += 1;
        Ok(())
    }

    fn release(&self) {
        let mut count = self.count.lock().unwrap();
        *count -= 1;
        self.condvar.notify_one();
    }
}
