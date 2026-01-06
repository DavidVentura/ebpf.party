use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::panic::RefUnwindSafe;
use std::process::Command;
use std::time::Duration;

pub trait Exercise: Send + RefUnwindSafe {
    fn setup(&self, answer: &[u8]);
    fn run(&self, answer: &[u8]);
}
pub struct ReadArgvPassword;

impl Exercise for ReadArgvPassword {
    fn setup(&self, _answer: &[u8]) {
        for prog in ["/bin/ls", "/bin/sudo", "/bin/secret_command"] {
            fs::copy("/true", prog).unwrap();
        }
    }

    fn run(&self, answer: &[u8]) {
        let password_str = std::str::from_utf8(answer).unwrap();

        let ls = &["/bin/ls", "/home/"];
        let bash = &["/bin/sudo", "/bin/bash"];
        let secret: Vec<&str> = vec![
            "/bin/secret_command",
            "--user",
            "admin",
            "--password",
            password_str,
        ];

        for cmd in [ls.as_slice(), bash.as_slice(), secret.as_slice()] {
            let (prog, args) = cmd.split_first().unwrap();
            let mut cmd = Command::new(prog).args(args).spawn().expect("missing bin");
            cmd.wait().unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

pub struct PlatformOverview;

impl Exercise for PlatformOverview {
    fn setup(&self, _answer: &[u8]) {}

    fn run(&self, _answer: &[u8]) {
        let mut cmd = Command::new("/true").spawn().expect("missing bin");
        cmd.wait().unwrap();
    }
}

pub struct ConceptIntro;

impl Exercise for ConceptIntro {
    fn setup(&self, answer: &[u8]) {
        let cmd_name_str = std::str::from_utf8(answer).unwrap();
        let command_name = format!("/bin/{cmd_name_str}");

        for prog in ["/bin/ls", "/bin/sudo", command_name.as_str()] {
            fs::copy("/true", prog).unwrap();
        }
    }

    fn run(&self, answer: &[u8]) {
        let cmd_name_str = std::str::from_utf8(answer).unwrap();
        let command_name = format!("/bin/{cmd_name_str}");

        let ls = &["/bin/ls", "/home/"];
        let bash = &["/bin/sudo", "/bin/bash"];
        let secret: Vec<&str> = vec![command_name.as_str()];

        for cmd in [ls.as_slice(), bash.as_slice(), secret.as_slice()] {
            let (prog, args) = cmd.split_first().unwrap();
            let mut cmd = Command::new(prog).args(args).spawn().expect("missing bin");
            cmd.wait().unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

pub struct ReadingEventData;

impl Exercise for ReadingEventData {
    fn setup(&self, answer: &[u8]) {
        let cmd_name_str = std::str::from_utf8(answer).unwrap();

        for prog in ["/bin/ls", "/bin/sudo", cmd_name_str] {
            fs::copy("/true", prog).unwrap();
        }
    }

    fn run(&self, answer: &[u8]) {
        let cmd_name_str = std::str::from_utf8(answer).unwrap();

        let ls = &["/bin/ls", "/home/"];
        let bash = &["/bin/sudo", "/bin/bash"];
        let secret: Vec<&str> = vec![cmd_name_str];

        for cmd in [ls.as_slice(), bash.as_slice(), secret.as_slice()] {
            let (prog, args) = cmd.split_first().unwrap();
            let mut cmd = Command::new(prog).args(args).spawn().expect("missing bin");
            cmd.wait().unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

pub struct ReadingSyscalls;

impl Exercise for ReadingSyscalls {
    fn setup(&self, answer: &[u8]) {
        let cmd_name_str = std::str::from_utf8(answer).unwrap();

        for prog in ["/bin/ls", "/bin/sudo", cmd_name_str] {
            fs::copy("/true", prog).unwrap();
        }
    }

    fn run(&self, answer: &[u8]) {
        let cmd_name_str = std::str::from_utf8(answer).unwrap();

        let ls = &["/bin/ls", "/home/"];
        let bash = &["/bin/sudo", "/bin/bash"];
        let secret: Vec<&str> = vec![cmd_name_str];

        for cmd in [ls.as_slice(), bash.as_slice(), secret.as_slice()] {
            let (prog, args) = cmd.split_first().unwrap();
            let mut cmd = Command::new(prog).args(args).spawn().expect("missing bin");
            cmd.wait().unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

pub struct IntroMapsPrograms;

impl Exercise for IntroMapsPrograms {
    fn setup(&self, _answer: &[u8]) {}

    fn run(&self, answer: &[u8]) {
        let answer_num: u16 = u16::from_le_bytes(answer[0..2].try_into().unwrap());
        let mut cmd = Command::new("/true").spawn().expect("missing /true bin");
        let _ = cmd.wait();

        let mut cmd = Command::new("/exit_with_code")
            .args(&[answer_num.to_string()])
            .spawn()
            .expect("missing exit bin");
        let _ = cmd.wait();
    }
}

pub struct ReadBufferContents;

impl Exercise for ReadBufferContents {
    fn setup(&self, answer: &[u8]) {
        std::fs::write("/tmp/file.txt", answer).unwrap();
    }

    fn run(&self, _answer: &[u8]) {
        std::fs::read("/tmp/file.txt").unwrap();
    }
}
pub struct ReadFilePassword;

impl Exercise for ReadFilePassword {
    fn setup(&self, answer: &[u8]) {
        std::fs::write("/tmp/bait_file.txt", "this file was bait :)").unwrap();
        std::fs::write("/tmp/password", answer).unwrap();
    }

    fn run(&self, _answer: &[u8]) {
        std::fs::read_to_string("/tmp/bait_file.txt").unwrap();
        std::fs::read_to_string("/tmp/password").unwrap();
    }
}
pub struct TrackSocketAndConnect;

impl Exercise for TrackSocketAndConnect {
    fn setup(&self, answer: &[u8]) {
        let port_: u64 = u64::from_le_bytes(answer.try_into().unwrap());
        assert!(port_ < u16::MAX as u64);
        let port: u16 = port_ as u16;
        std::thread::spawn(move || {
            let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
            while !crate::SHOULD_STOP.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(listener);
        });
    }

    fn run(&self, answer: &[u8]) {
        let port_: u64 = u64::from_le_bytes(answer.try_into().unwrap());
        assert!(port_ < u16::MAX as u64);
        let port: u16 = port_ as u16;
        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port));
        TcpStream::connect_timeout(&sa, Duration::from_millis(100)).unwrap();
    }
}

pub struct ReadDns;

impl Exercise for ReadDns {
    fn setup(&self, _answer: &[u8]) {}

    fn run(&self, _answer: &[u8]) {
        todo!("Implement DNS exercise")
    }
}

pub struct ReadHttpPassword;

impl Exercise for ReadHttpPassword {
    fn setup(&self, _answer: &[u8]) {}

    fn run(&self, _answer: &[u8]) {
        todo!("Implement HTTP exercise")
    }
}

pub fn get_exercise(exercise_id: shared::ExerciseId) -> Box<dyn Exercise> {
    match exercise_id {
        shared::ExerciseId::PlatformOverview => Box::new(PlatformOverview),
        shared::ExerciseId::ConceptIntro => Box::new(ConceptIntro),
        shared::ExerciseId::ReadingEventData => Box::new(ReadingEventData),
        shared::ExerciseId::ReadingSyscalls => Box::new(ReadingSyscalls),
        shared::ExerciseId::ReadArgvPassword => Box::new(ReadArgvPassword),
        shared::ExerciseId::IntroMapsPrograms => Box::new(IntroMapsPrograms),
        shared::ExerciseId::ReadBufferContents => Box::new(ReadBufferContents),
        shared::ExerciseId::ReadFilePassword => Box::new(ReadFilePassword),
        shared::ExerciseId::TrackSocketAndConnect => Box::new(TrackSocketAndConnect),
        shared::ExerciseId::ReadDns => Box::new(ReadDns),
        shared::ExerciseId::ReadHttpPassword => Box::new(ReadHttpPassword),
    }
}
