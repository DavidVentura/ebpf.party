use std::time::Duration;

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum GuestMessage {
    Booted,
    LoadFail(String),
    VerifierFail(String),
    DebugMapNotFound,
    NoProgramsFound,
    FoundProgram { name: String, section: String },
    FoundMap { name: String },
    Event(Vec<u8>),
    Crashed,
    Finished,
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExerciseId {
    PlatformOverview,
    ConceptIntro,
    ReadingEventData,
    ReadingSyscalls,
    ReadArgvPassword,
    ReadEnvPassword,
    ReadFilePassword,
    ReadDns,
    ReadHttpPassword,
}

impl ExerciseId {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "platform-overview" => Some(Self::PlatformOverview),
            "concept-intro" => Some(Self::ConceptIntro),
            "reading-event-data" => Some(Self::ReadingEventData),
            "reading-syscalls" => Some(Self::ReadingSyscalls),
            "read-argv-password" => Some(Self::ReadArgvPassword),
            "read-env-password" => Some(Self::ReadEnvPassword),
            "read-file-password" => Some(Self::ReadFilePassword),
            "read-dns" => Some(Self::ReadDns),
            "read-http-password" => Some(Self::ReadHttpPassword),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PlatformOverview => "platform-overview",
            Self::ConceptIntro => "concept-intro",
            Self::ReadingEventData => "reading-event-data",
            Self::ReadingSyscalls => "reading-syscalls",
            Self::ReadArgvPassword => "read-argv-password",
            Self::ReadEnvPassword => "read-env-password",
            Self::ReadFilePassword => "read-file-password",
            Self::ReadDns => "read-dns",
            Self::ReadHttpPassword => "read-http-password",
        }
    }
}

pub fn get_answer(exercise_id: ExerciseId, user_key: u64) -> Vec<u8> {
    use ExerciseId::*;

    match exercise_id {
        ReadArgvPassword => user_key.to_string().into_bytes(),

        PlatformOverview => "the answer".to_string().into_bytes(),
        // keep it under 16 chars to fit in COMM
        ConceptIntro => format!("secret_{}", user_key % 1_000_000).into_bytes(),
        // this one fits entirely in ctx->filename
        ReadingEventData => format!("/bin/secret_{:0>6}", user_key % 1_000_000).into_bytes(),

        ReadingSyscalls => format!("/bin/secret_{:0>6}", user_key % 1_000_000).into_bytes(),
        ReadEnvPassword => todo!("Implement answer generation for ex-2-2"),
        ReadFilePassword => todo!("Implement answer generation for ex-2-3"),
        ReadDns => todo!("Implement answer generation for ex-3-1"),
        ReadHttpPassword => todo!("Implement answer generation for ex-3-2"),
    }
}

impl GuestMessage {
    pub fn is_terminal(&self) -> bool {
        return matches!(
            self,
            GuestMessage::LoadFail(_)
                | GuestMessage::VerifierFail(_)
                | GuestMessage::DebugMapNotFound
                | GuestMessage::NoProgramsFound
                | GuestMessage::Finished
                | GuestMessage::Crashed
        );
    }
}
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum HostMessage {
    ExecuteProgram {
        exercise_id: ExerciseId,
        timeout: Duration,
        program: Vec<u8>,
        user_key: u64,
    },
}
