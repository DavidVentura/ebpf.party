use std::fmt;
use std::time::Duration;

use aetos::core::Label;
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

#[derive(
    Encode, Decode, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter,
)]
pub enum ExerciseId {
    // Chapter 0
    PlatformOverview,
    ConceptIntro,
    // Chapter 1
    ReadingEventData,
    ReadingSyscalls,
    ReadArgvPassword,
    // Chapter 2
    IntroMapsPrograms,
    ReadBufferContents,
    ReadFilePassword,
    TrackSocketAndConnect,
    // Chapter 3
    ReadDns,
    ReadHttpPassword,
}

impl ExerciseId {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            // Chapter 0
            "platform-overview" => Some(Self::PlatformOverview),
            "concept-intro" => Some(Self::ConceptIntro),

            // Chapter 1
            "reading-event-data" => Some(Self::ReadingEventData),
            "reading-syscalls" => Some(Self::ReadingSyscalls),
            "read-argv-password" => Some(Self::ReadArgvPassword),

            // Chapter 2
            "intro-maps-and-programs" => Some(Self::IntroMapsPrograms),
            "read-buffer-contents" => Some(Self::ReadBufferContents),
            "read-file-password" => Some(Self::ReadFilePassword),
            "socket-and-connect" => Some(Self::TrackSocketAndConnect),

            // Chapter 3
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

            Self::IntroMapsPrograms => "intro-maps-and-programs",
            Self::ReadBufferContents => "read-buffer-contents",
            Self::ReadFilePassword => "read-file-password",
            Self::TrackSocketAndConnect => "socket-and-connect",

            Self::ReadDns => "read-dns",
            Self::ReadHttpPassword => "read-http-password",
        }
    }
}

impl fmt::Display for ExerciseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Label for ExerciseId {
    fn fmt_labels(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exercise_id=\"{}\"", self.as_str())
    }
}

pub fn get_answer(exercise_id: ExerciseId, user_key: u64) -> Vec<u8> {
    use ExerciseId::*;

    match exercise_id {
        PlatformOverview => "the answer".to_string().into_bytes(),
        // keep it under 16 chars to fit in COMM
        ConceptIntro => format!("secret_{:0>6}", user_key % 1_000_000).into_bytes(),
        // this one fits entirely in ctx->filename
        ReadingEventData => format!("/bin/secret_{:0>6}", user_key % 1_000_000).into_bytes(),
        ReadingSyscalls => format!("/bin/secret_{:0>6}", user_key % 1_000_000).into_bytes(),
        ReadArgvPassword => user_key.to_string().into_bytes(),

        // numbers always require u64, simplifies the macro
        IntroMapsPrograms => (user_key % u8::MAX as u64).to_le_bytes().to_vec(),
        ReadBufferContents => "for sure there's a lot of content in this file"
            .to_string()
            .into_bytes(),
        TrackSocketAndConnect => (user_key % u16::MAX as u64).to_le_bytes().to_vec(),
        ReadFilePassword => format!("banana-{:0>6}", user_key % 1_000_000).into_bytes(),

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
