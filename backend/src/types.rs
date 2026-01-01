use crate::dwarf::DwarfDebugInfo;
use serde::{Deserialize, Serialize};
use shared::GuestMessage;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum PlatformMessage {
    CompileError(String),
    Compiling,
    NoCapacityLeft(String),
    Stack(DwarfDebugInfo),
    Booting,
    GuestMessage(GuestMessage),
}
