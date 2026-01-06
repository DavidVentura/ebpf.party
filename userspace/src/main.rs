use shared::{GuestMessage, HostMessage};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use vsock::{VMADDR_CID_HOST, VsockStream};

use crate::ebpf::EbpfLoader;

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
            bincode::encode_into_std_write(&v, &mut s_send, config).expect("can't send over vsock");

            if v.is_terminal() {
                SHOULD_STOP.store(true, Ordering::Relaxed);
            }
        }
    });

    match bincode::decode_from_std_read::<shared::HostMessage, _, _>(&mut s_rcv, config) {
        Ok(hm) => run_exercise(hm, tx),
        Err(e) => {
            eprintln!("Failed to deserialize HostMessage: {}", e);
        }
    }
    jh.join().unwrap();
}

fn run_exercise(hm: HostMessage, tx: Sender<GuestMessage>) {
    let shared::HostMessage::ExecuteProgram {
        exercise_id,
        timeout,
        program,
        user_key,
    } = hm;
    let exercise = exercises::get_exercise(exercise_id);
    let answer = shared::get_answer(exercise_id, user_key);

    let txer = tx.clone();
    let r_closure = move |data: &[u8]| {
        txer.send(GuestMessage::Event(data.into())).unwrap();
        0
    };

    let e = match EbpfLoader::load_program(&program, r_closure) {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(e).unwrap();
            return;
        }
    };

    exercise.setup(&answer);
    for pd in &e.program_details {
        let _ = tx.send(GuestMessage::FoundProgram {
            name: pd.name.clone(),
            section: pd.section.clone(),
        });
    }

    let panic_tx = tx.clone();
    let jh2 = std::thread::spawn(move || {
        e.run(timeout);
        let _ = tx.send(GuestMessage::Finished);
    });

    let panics = std::panic::catch_unwind(|| {
        exercise.run(&answer);
    });
    if let Err(_) = panics {
        let _ = panic_tx.send(GuestMessage::Crashed);
    }
    SHOULD_STOP.store(true, Ordering::Relaxed);
    jh2.join().unwrap();
}
