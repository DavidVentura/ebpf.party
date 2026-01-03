use shared::GuestMessage;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use vsock::{VMADDR_CID_HOST, VsockStream};

pub static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

mod ebpf;
mod exercises;
mod setup;

fn main() {
    let panics = std::panic::catch_unwind(|| {
        real_main();
    });
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
    if let Err(e) = panics {
        println!("panicked, bye! {e:?}");
    }
}
fn real_main() {
    if std::process::id() <= 100 {
        if let Err(e) = setup::setup_host_env() {
            eprintln!("{}", e);
            return;
        }
    }

    let mut s_send = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, 1234).unwrap();
    let mut s_rcv = s_send.try_clone().unwrap();
    let msg = shared::GuestMessage::Booted;
    let config = bincode::config::standard();
    bincode::encode_into_std_write(&msg, &mut s_send, config).unwrap();

    let (tx, rx) = std::sync::mpsc::channel::<GuestMessage>();

    let jh = std::thread::spawn(move || {
        while let Ok(v) = rx.recv() {
            let _ = bincode::encode_into_std_write(&v, &mut s_send, config)
                .expect("can't send over vsock");

            if v.is_terminal() {
                SHOULD_STOP.store(true, Ordering::Relaxed);
            }
        }
    });

    match bincode::decode_from_std_read::<shared::HostMessage, _, _>(&mut s_rcv, config) {
        Ok(shared::HostMessage::ExecuteProgram { timeout, program }) => {
            // TODO: parametrize
            let panic_tx = tx.clone();
            let jh2 = std::thread::spawn(move || {
                let panics = std::panic::catch_unwind(|| {
                    //exercise1();
                    exercises::exercise_argv();
                });
                if let Err(_) = panics {
                    let _ = panic_tx.send(GuestMessage::Crashed);
                }
            });
            ebpf::run_program(&program, timeout, tx);
            jh2.join().unwrap();
        }
        Err(e) => {
            eprintln!("Failed to deserialize HostMessage: {}", e);
            //std::process::exit(1);
        }
    }
    jh.join().unwrap();
}
