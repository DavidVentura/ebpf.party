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

impl GuestMessage {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            GuestMessage::LoadFail(_)
                | GuestMessage::VerifierFail(_)
                | GuestMessage::DebugMapNotFound
                | GuestMessage::NoProgramsFound
                | GuestMessage::Finished
                | GuestMessage::Crashed
        )
    }
}
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum HostMessage {
    ExecuteProgram { timeout: Duration, program: Vec<u8> },
}
