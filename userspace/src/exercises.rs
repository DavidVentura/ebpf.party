use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::panic::RefUnwindSafe;
use std::process::Command;
use std::sync::mpsc;
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
        let addr = format!("127.0.0.1:{port}");
        println!("Listening on {addr}");

        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let listener = TcpListener::bind(addr).unwrap();
            tx.send(()).unwrap();
            while !crate::SHOULD_STOP.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(listener);
        });

        // wait til the listener is up before confirming setup
        rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }

    fn run(&self, answer: &[u8]) {
        let port_: u64 = u64::from_le_bytes(answer.try_into().unwrap());
        assert!(port_ < u16::MAX as u64);
        let port: u16 = port_ as u16;
        for i in 1..10 {
            let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port + i));
            // this is supposed to fail
            let _ = TcpStream::connect(&sa);
        }

        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port));
        // Using connect_timeout here sets the socket in non-blocking mode
        // which means `connect` returns EINPROGRESS
        // and tracking that is more complex than expected for a first socket intro
        TcpStream::connect(&sa).unwrap();
    }
}

pub struct ReadDns;

impl Exercise for ReadDns {
    fn setup(&self, _answer: &[u8]) {
        println!("setup dns");
    }

    fn run(&self, _answer: &[u8]) {
        println!("start running dns");

        let sl = UdpSocket::bind("127.0.0.1:53").unwrap();
        sl.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let j = std::thread::spawn(move || {
            let mut buf = vec![0; 128];
            sl.recv(&mut buf).unwrap();
        });
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect("127.0.0.1:53").unwrap();

        let mut buf = vec![0u8; 1024];

        // Create a message. This is a query for the A record of example.com.
        let mut questions = [dns_protocol::Question::new(
            "ebpf.party",
            dns_protocol::ResourceType::A,
            0,
        )];
        let mut answers = [dns_protocol::ResourceRecord::default()];
        let message = dns_protocol::Message::new(
            0x42,
            dns_protocol::Flags::default(),
            &mut questions,
            &mut answers,
            &mut [],
            &mut [],
        );

        // Serialize the message into the buffer
        assert!(message.space_needed() <= buf.len());
        let len = message.write(&mut buf).unwrap();

        s.send(&buf[..len]).unwrap();
        println!("done running dns, len {len}");
        j.join().unwrap();
    }
}

pub struct ReadHttpPassword;

impl Exercise for ReadHttpPassword {
    fn setup(&self, _answer: &[u8]) {
        let addr = format!("127.0.0.1:80");

        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let listener = TcpListener::bind(addr).unwrap();
            tx.send(()).unwrap();
            while !crate::SHOULD_STOP.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(listener);
        });

        // wait til the listener is up before confirming setup
        rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        println!("http setup complete");
    }

    fn run(&self, answer: &[u8]) {
        let token = String::from_utf8(answer.to_vec()).unwrap();
        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80));
        let mut s = TcpStream::connect(&sa).unwrap();
        println!("http run connected");
        let buf = format!(
            r#"POST /api/users HTTP/1.1
Host: ebpf.party
Authorization: Bearer {token}

some type of body"#
        )
        .replace("\n", "\r\n");
        s.write_all(buf.as_bytes()).unwrap();
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
