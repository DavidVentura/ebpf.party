use crate::{dwarf::DwarfDebugInfo, metrics::ExerciseResult};
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

    MultipleAnswers,
    NoAnswer,
    CorrectAnswer,
    WrongAnswer,
}

impl TryFrom<&PlatformMessage> for ExerciseResult {
    type Error = ();
    fn try_from(value: &PlatformMessage) -> Result<Self, Self::Error> {
        match value {
            PlatformMessage::CorrectAnswer => Ok(ExerciseResult::Success),
            PlatformMessage::WrongAnswer => Ok(ExerciseResult::Fail),
            PlatformMessage::MultipleAnswers => Ok(ExerciseResult::MultipleAnswer),
            PlatformMessage::NoAnswer => Ok(ExerciseResult::NoAnswer),

            PlatformMessage::CompileError(..) => Ok(ExerciseResult::CompileError),
            PlatformMessage::NoCapacityLeft(..) => Ok(ExerciseResult::NoCapacityLeft),

            PlatformMessage::Booting => Err(()),
            PlatformMessage::Compiling => Err(()),
            PlatformMessage::Stack(..) => Err(()),

            PlatformMessage::GuestMessage(gm) => match gm {
                // not interested to track
                GuestMessage::Booted => Err(()),
                GuestMessage::Event(..) => Err(()),
                GuestMessage::Finished => Err(()),
                GuestMessage::FoundMap { .. } => Err(()),
                GuestMessage::FoundProgram { .. } => Err(()),
                GuestMessage::NoProgramsFound => Err(()),

                // interesting
                GuestMessage::DebugMapNotFound => Ok(ExerciseResult::DebugMapNotFound),
                GuestMessage::LoadFail(..) => Ok(ExerciseResult::VerifierFail),
                GuestMessage::CantAttachProgram(s) => {
                    Ok(ExerciseResult::CantAttachProgram(s.clone()))
                }
                GuestMessage::VerifierFail(..) => Ok(ExerciseResult::VerifierFail),
                GuestMessage::Crashed => Ok(ExerciseResult::Crashed),
            },
        }
    }
}
