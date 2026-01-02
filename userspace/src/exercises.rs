use std::fs;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub fn exercise_argv() {
    let secret_command = &[
        "/bin/secret_command",
        "--user",
        "admin",
        "--password",
        "very safe",
    ];
    let ls = &["/bin/ls", "/home/"];
    let bash = &["/bin/sudo", "/bin/bash"];
    let cmds: [&[&str]; _] = [ls, bash, secret_command];
    for cmd in cmds {
        let prog = cmd[0];
        fs::copy("/true", prog).unwrap();
    }

    for cmd in cmds {
        if crate::SHOULD_STOP.load(Ordering::Relaxed) {
            break;
        }
        let (prog, args) = cmd.split_first().unwrap();
        let mut cmd = Command::new(prog).args(args).spawn().expect("missing bin");
        cmd.wait().unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
    crate::SHOULD_STOP.store(true, Ordering::Relaxed);
}

pub fn exercise1() {
    let mut cmds = ["/true", "/ls", "/git", "/bash", "/secret_command"];
    while !crate::SHOULD_STOP.load(Ordering::Relaxed) {
        let mut cmd = Command::new(cmds[0]).spawn().expect("missing bin");
        cmds.rotate_left(1);
        cmd.wait().unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
}
