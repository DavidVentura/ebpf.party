use std::time::Duration;

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum ExecutionMessage {
    LoadFail(String),
    VerifierFail(String),
    DebugMapNotFound,
    NoProgramsFound,
    FoundProgram { name: String, section: String },
    FoundMap { name: String },
    Event(Vec<u8>),
    Finished(),
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum GuestMessage {
    // TODO move out of GM
    CompileError(String),
    Compiling,
    NoCapacityLeft(String),
    Booting,
    Booted,
    ExecutionResult(ExecutionMessage),
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum HostMessage {
    ExecuteProgram { timeout: Duration, program: Vec<u8> },
}
