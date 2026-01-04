
struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};
struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};