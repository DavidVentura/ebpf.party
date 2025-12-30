
enum {
	BPF_F_INDEX_MASK = 4294967295ULL,
	BPF_F_CURRENT_CPU = 4294967295ULL,
	BPF_F_CTXLEN_MASK = 4503595332403200ULL,
};
enum numa_vmaskip_reason {
	NUMAB_SKIP_UNSUITABLE = 0,
	NUMAB_SKIP_SHARED_RO = 1,
	NUMAB_SKIP_INACCESSIBLE = 2,
	NUMAB_SKIP_SCAN_DELAY = 3,
	NUMAB_SKIP_PID_INACTIVE = 4,
	NUMAB_SKIP_IGNORE_PID = 5,
	NUMAB_SKIP_SEQ_COMPLETED = 6,
};
struct trace_event_raw_sched_kthread_stop {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	char __data[0];
};
struct trace_event_raw_sched_kthread_stop_ret {
	struct trace_entry ent;
	int ret;
	char __data[0];
};
struct trace_event_raw_sched_kthread_work_execute_end {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};
struct trace_event_raw_sched_kthread_work_execute_start {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};
struct trace_event_raw_sched_kthread_work_queue_work {
	struct trace_entry ent;
	void *work;
	void *function;
	void *worker;
	char __data[0];
};
struct trace_event_raw_sched_migrate_task {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int orig_cpu;
	int dest_cpu;
	char __data[0];
};
struct trace_event_raw_sched_move_numa {
	struct trace_entry ent;
	pid_t pid;
	pid_t tgid;
	pid_t ngid;
	int src_cpu;
	int src_nid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};
struct trace_event_raw_sched_numa_pair_template {
	struct trace_entry ent;
	pid_t src_pid;
	pid_t src_tgid;
	pid_t src_ngid;
	int src_cpu;
	int src_nid;
	pid_t dst_pid;
	pid_t dst_tgid;
	pid_t dst_ngid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};
struct trace_event_raw_sched_pi_setprio {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int oldprio;
	int newprio;
	char __data[0];
};
struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	char parent_comm[16];
	pid_t parent_pid;
	char child_comm[16];
	pid_t child_pid;
	char __data[0];
};
struct trace_event_raw_sched_process_hang {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	char __data[0];
};
struct trace_event_raw_sched_process_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};
struct trace_event_raw_sched_process_wait {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};
struct trace_event_raw_sched_skip_vma_numa {
	struct trace_entry ent;
	long unsigned int numa_scan_offset;
	long unsigned int vm_start;
	long unsigned int vm_end;
	enum numa_vmaskip_reason reason;
	char __data[0];
};
struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};
struct trace_event_raw_sched_wake_idle_without_ipi {
	struct trace_entry ent;
	int cpu;
	char __data[0];
};
struct trace_event_raw_sched_wakeup_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int target_cpu;
	char __data[0];
};
struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
};
struct trace_event_raw_sched_stat_runtime {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 runtime;
	char __data[0];
};
struct trace_event_raw_sched_stat_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 delay;
	char __data[0];
};