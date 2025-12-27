use std::time::Duration;

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

/*
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct BpfEvent {
    pub data: Vec<u8>,
}
*/

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum ExecutionMessage {
    LoadFail(Vec<u8>),
    VerifierFail(Vec<u8>),
    NoPerfMapsFound,
    FoundProgram { name: String, section: String },
    FoundMap { name: String },
    Event(Vec<u8>),
    Finished(),
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum GuestMessage {
    Booted,
    ExecutionResult(ExecutionMessage),
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum HostMessage {
    ExecuteProgram { timeout: Duration, program: Vec<u8> },
}
