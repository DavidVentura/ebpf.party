use shared::{ExerciseId, GuestMessage};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
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
        Ok(shared::HostMessage::ExecuteProgram {
            exercise_id,
            timeout,
            program,
            user_key,
        }) => {
            let panic_tx = tx.clone();
            let jh2 = std::thread::spawn(move || {
                // TODO: wait for ebpf::run_program to have started
                std::thread::sleep(Duration::from_millis(20));
                let panics = std::panic::catch_unwind(|| {
                    run_exercise(exercise_id, user_key);
                });
                if let Err(_) = panics {
                    let _ = panic_tx.send(GuestMessage::Crashed);
                }

                SHOULD_STOP.store(true, Ordering::Relaxed);
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

fn run_exercise(exercise_id: ExerciseId, user_key: u64) {
    match exercise_id {
        shared::ExerciseId::ReadArgvPassword => exercises::exercise_argv(user_key),
        shared::ExerciseId::PlatformOverview => exercises::exercise_platform_overview(user_key),
        shared::ExerciseId::ConceptIntro => exercises::exercise_concept_intro(user_key),
        shared::ExerciseId::ReadingEventData => exercises::exercise_reading_event_data(user_key),
        shared::ExerciseId::ReadingSyscalls => exercises::exercise_reading_syscalls(user_key),
        shared::ExerciseId::ReadEnvPassword => exercises::exercise_env(user_key),
        shared::ExerciseId::ReadFilePassword => exercises::exercise_file(user_key),
        shared::ExerciseId::ReadDns => exercises::exercise_dns(user_key),
        shared::ExerciseId::ReadHttpPassword => exercises::exercise_http(user_key),
    }
}
