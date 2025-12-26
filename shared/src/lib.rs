use std::time::Duration;

use bincode::{Decode, Encode};

#[derive(Encode, Decode, Debug, Clone)]
pub struct BpfEvent {
    pub data: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum ExecutionMessage {
    LoadFail(Vec<u8>),
    VerifierFail(Vec<u8>),
    NoPerfMapsFound,
    FoundProgram { name: String, section: String },
    FoundMap { name: String },
    Event(BpfEvent),
    Finished(),
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum GuestMessage {
    Booted,
    ExecutionResult(ExecutionMessage),
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum HostMessage {
    ExecuteProgram { timeout: Duration, program: Vec<u8> },
}
