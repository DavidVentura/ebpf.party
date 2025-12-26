use bincode::{Decode, Encode};

#[derive(Encode, Decode, Debug, Clone)]
pub struct BpfEvent {
    pub data: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum GuestMessage {
    Booted,
    LoadFail(Vec<u8>),
    VerifierFail(Vec<u8>),
    Finished(Vec<BpfEvent>),
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum HostMessage {
    ExecuteProgram { timeout_ms: u16, program: Vec<u8> },
}
