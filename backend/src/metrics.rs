use aetos::{Label, define_histogram, exponential_buckets, linear_buckets, metrics};
use shared::ExerciseId;
use std::collections::HashMap;
use std::fmt;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

define_histogram!(CompileDuration<ExerciseId> = linear_buckets::<8>(0.01, 0.01));
define_histogram!(VmBootDuration<ExerciseId> = linear_buckets::<8>(0.04, 0.01));
define_histogram!(ExecutionDuration<ExerciseId> = exponential_buckets::<8>(0.01, 1.5));
define_histogram!(TotalRequestDuration<ExerciseId> = exponential_buckets::<8>(0.02, 1.5));

#[derive(Debug, Clone)]
pub enum MetricEvent {
    BadExerciseRequest,
    CompileDuration {
        exercise_id: ExerciseId,
        duration_secs: f64,
    },
    VmBootDuration {
        exercise_id: ExerciseId,
        duration_secs: f64,
    },
    ExecutionDuration {
        exercise_id: ExerciseId,
        duration_secs: f64,
    },
    TotalRequestDuration {
        exercise_id: ExerciseId,
        duration_secs: f64,
    },
    ExerciseResult(SubmissionResult),
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, strum::EnumIter)]
pub enum ExerciseResult {
    // platform
    Success,
    Fail,
    NoAnswer,
    MultipleAnswer,
    VerifierFail,
    DebugMapNotFound,
    CompileError,
    NoCapacityLeft,
    // guest
    Crashed,
}

impl fmt::Display for ExerciseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExerciseResult::Success => write!(f, "success"),
            ExerciseResult::Fail => write!(f, "fail"),
            ExerciseResult::NoAnswer => write!(f, "no_answer"),
            ExerciseResult::MultipleAnswer => write!(f, "multiple_answer"),
            ExerciseResult::VerifierFail => write!(f, "verifier_fail"),
            ExerciseResult::Crashed => write!(f, "crashed"),
            ExerciseResult::DebugMapNotFound => write!(f, "debug_map_not_found"),
            ExerciseResult::CompileError => write!(f, "clang_compile_error"),
            ExerciseResult::NoCapacityLeft => write!(f, "no_capacity_left"),
        }
    }
}

#[derive(Label, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SubmissionResult {
    pub exercise: ExerciseId,
    pub result: ExerciseResult,
}

#[metrics]
pub(crate) struct Metrics {
    #[counter(help = "Requests with invalid exercise ID")]
    bad_exercise_requests_total: u64,

    #[counter(help = "Exercise submissions")]
    exercise_submissions_total: HashMap<SubmissionResult, u64>,

    #[histogram(help = "Compilation duration in seconds")]
    compile_duration_seconds: CompileDuration,

    #[histogram(help = "VM boot duration in seconds")]
    vm_boot_duration_seconds: VmBootDuration,

    #[histogram(help = "Program execution duration in seconds")]
    execution_duration_seconds: ExecutionDuration,

    #[histogram(help = "Total request duration in seconds")]
    total_request_duration_seconds: TotalRequestDuration,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            bad_exercise_requests_total: 0,
            exercise_submissions_total: HashMap::new(),
            compile_duration_seconds: CompileDuration::default(),
            vm_boot_duration_seconds: VmBootDuration::default(),
            execution_duration_seconds: ExecutionDuration::default(),
            total_request_duration_seconds: TotalRequestDuration::default(),
        }
    }

    pub fn init(&mut self, event: MetricEvent) {
        match event {
            MetricEvent::CompileDuration { exercise_id, .. } => {
                self.compile_duration_seconds.zero_initialize(exercise_id);
            }
            MetricEvent::VmBootDuration { exercise_id, .. } => {
                self.vm_boot_duration_seconds.zero_initialize(exercise_id);
            }
            MetricEvent::ExecutionDuration { exercise_id, .. } => {
                self.execution_duration_seconds.zero_initialize(exercise_id);
            }
            MetricEvent::TotalRequestDuration { exercise_id, .. } => {
                self.total_request_duration_seconds
                    .zero_initialize(exercise_id);
            }
            MetricEvent::ExerciseResult(e) => {
                self.exercise_submissions_total.entry(e).or_default();
            }
            _ => (),
        }
    }
    fn handle_event(&mut self, event: MetricEvent) {
        match event {
            MetricEvent::BadExerciseRequest => {
                self.bad_exercise_requests_total += 1;
            }
            MetricEvent::CompileDuration {
                exercise_id,
                duration_secs,
            } => {
                self.compile_duration_seconds
                    .observe(exercise_id, duration_secs);
            }
            MetricEvent::VmBootDuration {
                exercise_id,
                duration_secs,
            } => {
                self.vm_boot_duration_seconds
                    .observe(exercise_id, duration_secs);
            }
            MetricEvent::ExecutionDuration {
                exercise_id,
                duration_secs,
            } => {
                self.execution_duration_seconds
                    .observe(exercise_id, duration_secs);
            }
            MetricEvent::TotalRequestDuration {
                exercise_id,
                duration_secs,
            } => {
                self.total_request_duration_seconds
                    .observe(exercise_id, duration_secs);
            }
            MetricEvent::ExerciseResult(e) => {
                let v = self.exercise_submissions_total.entry(e).or_default();
                *v += 1;
            }
        }
    }
}

pub fn process_metrics_events(rx: Receiver<MetricEvent>, metrics: Arc<Mutex<Metrics>>) {
    for event in rx {
        let mut m = metrics.lock().unwrap();
        m.handle_event(event);
    }
}
