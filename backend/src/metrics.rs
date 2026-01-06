use aetos::{define_histogram, exponential_buckets, linear_buckets, metrics};
use shared::ExerciseId;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

struct AtomicCounter(AtomicU64);

impl AtomicCounter {
    fn new(val: u64) -> Self {
        Self(AtomicU64::new(val))
    }

    fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl fmt::Display for AtomicCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.load(Ordering::Relaxed))
    }
}

define_histogram!(CompileDuration<ExerciseId> = linear_buckets::<8>(0.01, 0.01));
define_histogram!(VmBootDuration<ExerciseId> = linear_buckets::<8>(0.04, 0.01));
define_histogram!(ExecutionDuration<ExerciseId> = exponential_buckets::<8>(0.01, 1.5));
define_histogram!(TotalRequestDuration<ExerciseId> = exponential_buckets::<7>(0.02, 2.0));

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
}

#[metrics(prefix = "ebpf_party")]
pub(crate) struct Metrics {
    #[counter(help = "Requests with invalid exercise ID")]
    bad_exercise_requests_total: AtomicCounter,

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
            bad_exercise_requests_total: AtomicCounter::new(0),
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
            _ => (),
        }
    }
    fn handle_event(&mut self, event: MetricEvent) {
        match event {
            MetricEvent::BadExerciseRequest => {
                self.bad_exercise_requests_total.increment();
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
        }
    }
}

pub fn process_metrics_events(rx: Receiver<MetricEvent>, metrics: Arc<Mutex<Metrics>>) {
    for event in rx {
        let mut m = metrics.lock().unwrap();
        m.handle_event(event);
    }
}
