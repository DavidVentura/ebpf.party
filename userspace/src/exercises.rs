use std::fs;
use std::process::Command;
use std::time::Duration;

pub fn cmds_with_secret_command(command_name: &str) {
    let ls = &["/bin/ls", "/home/"];
    let bash = &["/bin/sudo", "/bin/bash"];
    let secret: &[&str] = &[command_name];

    for prog in ["/bin/ls", "/bin/sudo", &command_name] {
        fs::copy("/true", prog).unwrap();
    }

    for cmd in [ls, bash, secret] {
        let (prog, args) = cmd.split_first().unwrap();
        let mut cmd = Command::new(prog).args(args).spawn().expect("missing bin");
        cmd.wait().unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn cmds_with_secret_flag(password_str: &str) {
    let ls = &["/bin/ls", "/home/"];
    let bash = &["/bin/sudo", "/bin/bash"];
    let secret: &[&str] = &[
        "/bin/secret_command",
        "--user",
        "admin",
        "--password",
        password_str,
    ];

    for prog in ["/bin/ls", "/bin/sudo", "/bin/secret_command"] {
        fs::copy("/true", prog).unwrap();
    }

    for cmd in [ls, bash, secret] {
        let (prog, args) = cmd.split_first().unwrap();
        let mut cmd = Command::new(prog).args(args).spawn().expect("missing bin");
        cmd.wait().unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub fn exercise_argv(user_key: u64) {
    let password = shared::get_answer(shared::ExerciseId::ReadArgvPassword, user_key);
    let password_str = std::str::from_utf8(&password).unwrap();
    cmds_with_secret_flag(password_str);
}

pub fn exercise_platform_overview(_user_key: u64) {
    let mut cmd = Command::new("/true").spawn().expect("missing bin");
    cmd.wait().unwrap();
}

pub fn exercise_concept_intro(user_key: u64) {
    let cmd_name = shared::get_answer(shared::ExerciseId::ConceptIntro, user_key);
    let cmd_name_str = std::str::from_utf8(&cmd_name).unwrap();
    cmds_with_secret_command(format!("/bin/{cmd_name_str}").as_str());
}

pub fn exercise_reading_event_data(user_key: u64) {
    let cmd_name = shared::get_answer(shared::ExerciseId::ReadingEventData, user_key);
    let cmd_name_str = std::str::from_utf8(&cmd_name).unwrap();
    cmds_with_secret_command(cmd_name_str);
}

pub fn exercise_reading_syscalls(user_key: u64) {
    let cmd_name = shared::get_answer(shared::ExerciseId::ReadingSyscalls, user_key);
    let cmd_name_str = std::str::from_utf8(&cmd_name).unwrap();
    cmds_with_secret_command(cmd_name_str);
}

pub fn exercise_env(user_key: u64) {
    let _answer = shared::get_answer(shared::ExerciseId::ReadEnvPassword, user_key);
    todo!("Implement environment variable reading exercise")
}

pub fn exercise_file(user_key: u64) {
    let _answer = shared::get_answer(shared::ExerciseId::ReadFilePassword, user_key);
    todo!("Implement file reading exercise")
}

pub fn exercise_dns(user_key: u64) {
    let _answer = shared::get_answer(shared::ExerciseId::ReadDns, user_key);
    todo!("Implement DNS exercise")
}

pub fn exercise_http(user_key: u64) {
    let _answer = shared::get_answer(shared::ExerciseId::ReadHttpPassword, user_key);
    todo!("Implement HTTP exercise")
}
