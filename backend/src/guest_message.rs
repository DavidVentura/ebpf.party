use serde::{Deserialize, Serialize};
use shared::GuestMessage;

use crate::types::PlatformMessage;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "camelCase")]
pub enum UserAnswer {
    String(Vec<u8>),
    Number([u8; 8]),
}
pub enum UserMessage {
    Debug,
    Answer(UserAnswer),
}
pub enum MessageKind {
    Number,
    String,
    Struct,
}
/*
#define NUM_ID      0x02
#define STR_ID      0x03
#define STRUCT_ID   0x04
#define ANSWER_FLAG 0x80
*/

pub fn extract_answer(msg: &PlatformMessage) -> Option<UserAnswer> {
    if let PlatformMessage::GuestMessage(g) = msg {
        if let GuestMessage::Event(e) = g {
            if let Some(um) = parse(e.as_slice())
                && let UserMessage::Answer(a) = um
            {
                return Some(a);
            }
        }
    }
    None
}
fn parse(data: &[u8]) -> Option<UserMessage> {
    if data.len() == 0 {
        return None;
    }
    let is_answer = data[0] & 0x80 == 0x80;
    let kind = match data[0] & 0x7f {
        0x02 => MessageKind::Number,
        0x03 => MessageKind::String,
        0x04 => MessageKind::Struct,
        _ => return None,
    };
    if !is_answer {
        return Some(UserMessage::Debug);
    }
    match kind {
        MessageKind::Struct => None,
        MessageKind::Number => {
            // type, counter, data
            if data.len() != 11 {
                return None;
            }
            let num_data: [u8; 8] = data[3..11].try_into().unwrap();
            Some(UserMessage::Answer(UserAnswer::Number(num_data)))
        }
        MessageKind::String => {
            // type, counter, data
            if data.len() < 2 {
                return None;
            }
            Some(UserMessage::Answer(UserAnswer::String(data[2..].to_vec())))
        }
    }
}
