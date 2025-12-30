/* Forward declarations */
#ifndef task_h
#define task_h
struct _ddebug;
struct aa_dfa;
struct aa_label;
struct aa_loaddata;
struct aa_net_compat;
struct aa_ns;
struct aa_policydb;
struct aa_profile;
struct aa_proxy;
struct ack_sample;
struct acpi_device_id;
struct address_space;
struct address_space_operations;
struct affinity_context;
struct anon_vma;
struct anon_vma_name;
struct arch_uprobe;
struct array_buffer;
struct assoc_array_ptr;
struct async_poll;
struct atomic64_t;
struct attribute;
struct attribute_group;
struct audit_names;
struct autogroup;
struct backing_dev_info;
struct badblocks;
struct balance_callback;
struct bdev_handle;
struct bdi_writeback;
struct bin_attribute;
struct binfmt_misc;
struct bio;
struct bio_alloc_cache;
struct bio_crypt_ctx;
struct bio_list;
struct bio_set;
struct bio_vec;
struct blk_crypto_key;
struct blk_crypto_keyslot;
struct blk_crypto_profile;
struct blk_flush_queue;
struct blk_holder_ops;
struct blk_independent_access_ranges;
struct blk_integrity_iter;
struct blk_integrity_profile;
struct blk_mq_alloc_data;
struct blk_mq_ctx;
struct blk_mq_ctxs;
struct blk_mq_debugfs_attr;
struct blk_mq_hw_ctx;
struct blk_mq_ops;
struct blk_mq_queue_data;
struct blk_mq_tag_set;
struct blk_mq_tags;
struct blk_plug;
struct blk_queue_stats;
struct blk_trace;
struct blk_zone;
struct blkcg;
struct blkcg_gq;
struct blkcg_policy_data;
struct blkg_iostat_set;
struct blkg_policy_data;
struct block_device;
struct block_device_operations;
struct blocking_notifier_head;
union bpf_attr;
struct bpf_cgroup_storage_map;
struct bpf_ctx_arg_aux;
struct bpf_func_info;
struct bpf_func_info_aux;
struct bpf_func_proto;
struct bpf_func_state;
struct bpf_insn;
struct bpf_insn_access_aux;
struct bpf_insn_aux_data;
struct bpf_iter_aux_info;
struct bpf_iter_seq_info;
struct bpf_jit_poke_descriptor;
struct bpf_jmp_history_entry;
struct bpf_kfunc_btf_tab;
struct bpf_kfunc_desc_tab;
struct bpf_line_info;
struct bpf_local_storage;
struct bpf_local_storage_data;
struct bpf_local_storage_map;
struct bpf_local_storage_map_bucket;
struct bpf_map;
struct bpf_map_ops;
struct bpf_mem_cache;
struct bpf_mem_caches;
struct bpf_offload_dev;
struct bpf_prog;
struct bpf_prog_array;
struct bpf_prog_aux;
struct bpf_prog_offload;
struct bpf_prog_offload_ops;
struct bpf_prog_ops;
struct bpf_prog_stats;
struct bpf_raw_event_map;
struct bpf_reference_state;
struct bpf_reg_state;
struct bpf_run_ctx;
struct bpf_stack_state;
struct bpf_tramp_image;
struct bpf_trampoline;
struct bpf_verifier_env;
struct bpf_verifier_log;
struct bpf_verifier_ops;
struct bpf_verifier_stack_elem;
struct bpf_verifier_state;
struct bpf_verifier_state_list;
struct btf;
struct btf_id_dtor_kfunc_tab;
struct btf_id_set8;
struct btf_kfunc_set_tab;
struct btf_mod_pair;
struct btf_record;
struct btf_struct_meta;
struct btf_struct_metas;
struct btf_type;
struct bucket_table;
struct buffer_data_page;
struct buffer_page;
struct bug_entry;
struct bus_dma_region;
struct bus_type;
struct callback_head;
struct can_dev_rcv_lists;
struct can_pkg_stats;
struct can_rcv_lists_stats;
struct capture_control;
struct cdrom_device_info;
struct cdrom_device_ops;
struct cdrom_mcn;
struct cdrom_multisession;
struct cfs_rq;
struct cftype;
struct cgroup;
struct cgroup_namespace;
struct cgroup_root;
struct cgroup_rstat_cpu;
struct cgroup_subsys;
struct cgroup_subsys_state;
struct cgroup_taskset;
struct class;
struct compact_control;
struct compat_robust_list_head;
struct completion;
struct cond_snapshot;
struct core_state;
struct core_thread;
struct core_vma_metadata;
struct coredump_params;
struct cpu_stop_done;
struct cpudl_item;
struct cpuidle_device;
struct cpuidle_device_kobj;
struct cpuidle_driver;
struct cpuidle_driver_kobj;
struct cpuidle_state;
struct cpuidle_state_kobj;
struct cpuidle_state_usage;
struct cpumask;
struct cred;
struct crypto_alg;
struct crypto_instance;
struct crypto_shash;
struct crypto_skcipher;
struct crypto_template;
struct crypto_tfm;
struct crypto_type;
struct css_set;
struct ctl_dir;
struct ctl_node;
struct ctl_table;
struct ctl_table_header;
struct ctl_table_poll;
struct ctl_table_root;
struct ctl_table_set;
struct ctx_rq_wait;
struct dax_device;
struct dax_holder_operations;
struct dax_operations;
struct ddebug_class_map;
struct delayed_call;
struct dentry;
struct dentry_operations;
struct desc_struct;
struct dev_iommu;
struct dev_pagemap;
struct dev_pagemap_ops;
struct dev_pin_info;
struct dev_pm_domain;
struct dev_pm_ops;
struct dev_pm_qos;
struct dev_pm_qos_request;
struct device;
struct device_attribute;
struct device_dma_parameters;
struct device_driver;
struct device_node;
struct device_physical_location;
struct device_private;
struct device_type;
struct dir_context;
struct disk_events;
struct disk_stats;
struct dma_map_ops;
struct dquot;
struct dquot_operations;
struct driver_private;
struct dst_entry;
struct dst_metrics;
struct dst_ops;
struct elevator_queue;
struct elevator_type;
struct elf64_shdr;
struct elf64_sym;
struct elv_fs_entry;
struct em_perf_domain;
struct em_perf_state;
struct error_injection_entry;
struct event_filter;
struct event_subsystem;
struct eventfd_ctx;
struct eventfs_attr;
struct eventfs_entry;
struct eventfs_inode;
struct exception_table_entry;
struct export_operations;
struct fasync_struct;
struct fc_log;
struct fdtable;
struct fib6_info;
struct fib6_node;
struct fib6_table;
struct fib_info;
struct fib_lookup_arg;
struct fib_nh_exception;
struct fib_notifier_ops;
struct fib_rule;
struct fib_rule_hdr;
struct fib_rules_ops;
struct fib_table;
struct fid;
struct fiemap_extent;
struct fiemap_extent_info;
struct file;
struct file_lock;
struct file_lock_context;
struct file_lock_operations;
struct file_operations;
struct file_ra_state;
struct file_system_type;
struct fileattr;
struct filename;
struct files_struct;
struct filter_pred;
struct flowi;
struct fnhe_hash_bucket;
struct folio;
struct fpstate;
struct fqdir;
struct freq_constraints;
struct fs_context;
struct fs_context_operations;
struct fs_parameter;
struct fs_parameter_spec;
struct fs_parse_result;
struct fs_pin;
struct fs_struct;
struct fscrypt_direct_key;
struct fscrypt_inode_info;
struct fscrypt_keyring;
struct fscrypt_master_key;
struct fscrypt_mode;
struct fscrypt_operations;
union fscrypt_policy;
struct fsnotify_mark_connector;
struct fsverity_hash_alg;
struct fsverity_info;
struct fsverity_operations;
struct ftrace_event_field;
struct ftrace_hash;
struct ftrace_ops;
struct ftrace_ops_hash;
struct ftrace_regs;
struct ftrace_ret_stack;
struct futex_pi_state;
struct fwnode_endpoint;
struct fwnode_handle;
struct fwnode_operations;
struct fwnode_reference_args;
struct gendisk;
struct group_info;
struct hd_geometry;
struct hlist_bl_node;
struct hlist_head;
struct hlist_node;
struct hlist_nulls_node;
struct hrtimer;
struct hrtimer_clock_base;
struct hrtimer_cpu_base;
struct iattr;
struct icmp_mib;
struct icmpmsg_mib;
struct icmpv6_mib;
struct icmpv6_mib_device;
struct icmpv6msg_mib;
struct icmpv6msg_mib_device;
struct ifacaddr6;
struct ifmcaddr6;
struct in6_addr;
struct inet6_dev;
struct inet_bind_hashbucket;
struct inet_ehash_bucket;
struct inet_frag_queue;
struct inet_frags;
struct inet_hashinfo;
struct inet_listen_hashbucket;
struct inet_peer_base;
struct inode;
struct inode_operations;
struct io_bitmap;
struct io_comp_batch;
struct io_context;
struct io_cq;
struct io_fixed_file;
struct io_hash_bucket;
struct io_kiocb;
struct io_mapped_ubuf;
struct io_poll;
struct io_ring_ctx;
struct io_rsrc_data;
struct io_rsrc_node;
struct io_sq_data;
struct io_tlb_area;
struct io_tlb_mem;
struct io_tlb_slot;
struct io_tw_state;
struct io_uring_cmd;
struct io_uring_sqe;
struct io_uring_task;
struct io_wq;
struct io_wq_hash;
struct io_wq_work;
struct io_wq_work_node;
struct ioam6_pernet_data;
struct iomap;
struct iomap_folio_ops;
struct iomap_iter;
struct iommu_device;
struct iommu_dirty_bitmap;
struct iommu_dirty_ops;
struct iommu_dma_cookie;
struct iommu_domain;
struct iommu_domain_ops;
struct iommu_fault;
struct iommu_fault_event;
struct iommu_fault_param;
struct iommu_fwspec;
struct iommu_group;
struct iommu_iotlb_gather;
struct iommu_ops;
struct iommu_page_response;
struct iommu_user_data;
struct iommu_user_data_array;
struct iopf_device_param;
struct iopf_queue;
struct iov_iter;
struct iova_bitmap;
struct iova_cpu_rcache;
struct iova_domain;
struct iova_magazine;
struct iova_rcache;
struct ip6_sf_list;
struct ip_conntrack_stat;
struct ip_ra_chain;
struct ipc_namespace;
struct ipstats_mib;
struct ipv4_devconf;
struct ipv6_devconf;
struct irq_affinity_desc;
struct irq_affinity_notify;
struct irq_chip;
struct irq_chip_generic;
struct irq_common_data;
struct irq_data;
struct irq_desc;
struct irq_domain;
struct irq_domain_chip_generic;
struct irq_domain_ops;
struct irq_fwspec;
struct irq_work;
struct irqaction;
struct jump_entry;
struct kernel_param;
struct kernel_param_ops;
struct kernel_pkey_params;
struct kernel_pkey_query;
struct kernel_siginfo;
struct kernel_symbol;
struct kernfs_iattrs;
struct kernfs_node;
struct kernfs_open_file;
struct kernfs_open_node;
struct kernfs_ops;
struct kernfs_root;
struct kernfs_syscall_ops;
struct key;
struct key_match_data;
union key_payload;
struct key_preparsed_payload;
struct key_restriction;
struct key_tag;
struct key_type;
struct key_user;
struct kiocb;
struct kioctx;
struct kioctx_cpu;
struct klist_node;
struct klp_modinfo;
struct kmem_cache;
struct kmem_cache_cpu;
struct kmem_cache_node;
struct kobj_ns_type_operations;
struct kobj_type;
struct kobj_uevent_env;
struct kobject;
struct kqid;
struct kref;
struct kset;
struct kset_uevent_ops;
struct kstat;
struct kstatfs;
struct ktermios;
struct kthread_work;
struct kthread_worker;
struct latency_bucket;
struct ldt_struct;
struct linux_binprm;
struct linux_mib;
struct linux_tls_mib;
struct linux_xfrm_mib;
struct list_head;
struct list_lru_node;
struct llist_head;
struct llist_node;
struct lock_class_key;
struct lock_manager_operations;
union lower_chunk;
struct lru_gen_mm_walk;
struct lruvec;
struct lruvec_stats_percpu;
struct lwtunnel_state;
struct math_emu_info;
struct mem_cgroup;
struct mem_cgroup_per_node;
struct mem_cgroup_threshold_ary;
struct memcg_vmstats;
struct memcg_vmstats_percpu;
struct memory_tier;
struct mempolicy;
struct mm_struct;
struct mnt_idmap;
struct mnt_namespace;
struct mnt_pcp;
struct mod_kallsyms;
struct module;
struct module_attribute;
struct module_kobject;
struct module_notes_attrs;
struct module_param_attrs;
struct module_sect_attrs;
struct mount;
struct mountpoint;
struct mpls_route;
struct mptcp_mib;
struct msghdr;
struct msi_desc;
struct msi_device_data;
struct msi_domain_info;
struct msi_domain_ops;
struct msi_msg;
struct msi_parent_ops;
struct mtd_info;
struct nameidata;
struct napi_struct;
struct neigh_hash_table;
struct neigh_ops;
struct neigh_parms;
struct neigh_statistics;
struct neigh_table;
struct neighbour;
struct net;
struct net_generic;
struct netlbl_lsm_cache;
struct netlbl_lsm_catmap;
struct netlink_ext_ack;
struct netns_ipvs;
struct nexthop;
struct nf_conn;
struct nf_conntrack_expect;
struct nf_conntrack_helper;
struct nf_ct_event;
struct nf_ct_event_notifier;
struct nf_ct_ext;
struct nf_exp_event;
struct nf_flow_table_stat;
struct nf_hook_entries;
struct nf_hook_state;
struct nf_logger;
struct nf_loginfo;
struct nfs4_lock_state;
struct nh_group;
struct nh_grp_entry;
struct nh_res_table;
struct nla_policy;
struct nlattr;
struct nlm_lockowner;
struct notification;
struct notifier_block;
struct ns_common;
struct nsproxy;
struct nsset;
struct numa_group;
struct obj_cgroup;
struct of_device_id;
struct of_phandle_args;
struct offset_ctx;
struct p_log;
struct packet_command;
struct page;
struct page_counter;
struct page_pool_recycle_stats;
struct partition_meta_info;
struct path;
struct per_cpu_nodestat;
struct per_cpu_pages;
struct per_cpu_zonestat;
struct percpu_cluster;
struct percpu_counter;
struct percpu_ref;
struct percpu_ref_data;
struct perf_addr_filter_range;
struct perf_branch_stack;
struct perf_buffer;
struct perf_callchain_entry;
struct perf_cgroup;
struct perf_cgroup_info;
struct perf_cpu_pmu_context;
struct perf_domain;
struct perf_event;
struct perf_event_context;
struct perf_event_mmap_page;
struct perf_event_pmu_context;
struct perf_output_handle;
struct perf_raw_record;
struct perf_sample_data;
struct pglist_data;
struct pid;
struct pid_namespace;
struct pinctrl;
struct pinctrl_state;
struct pipe_buf_operations;
struct pipe_buffer;
struct pipe_inode_info;
struct platform_msi_priv_data;
struct pm_domain_data;
struct pm_subsys_data;
struct pmd_t;
struct pmu;
struct pneigh_entry;
struct poll_table_struct;
struct pool_workqueue;
struct posix_acl;
struct pr_held_reservation;
struct pr_keys;
struct pr_ops;
struct proc_dir_entry;
struct proc_ns_operations;
struct prog_entry;
struct property;
struct prot_inuse;
struct proto;
struct proto_ops;
struct psi_group;
struct psi_group_cpu;
struct pt_regs;
struct pte_t;
struct pud_t;
struct qc_dqblk;
struct qc_info;
struct qc_state;
struct qstr;
struct quota_format_ops;
struct quota_format_type;
struct quotactl_ops;
struct rate_sample;
struct rb_node;
struct rchan;
struct rchan_buf;
struct rchan_callbacks;
struct rcu_node;
struct readahead_control;
struct reclaim_state;
struct regex;
struct request;
struct request_queue;
struct request_sock;
struct request_sock_ops;
struct restart_block;
struct return_instance;
struct rhash_head;
struct rhash_lock_head;
struct rhashtable;
struct rhashtable_compare_arg;
struct rhlist_head;
struct ring_buffer_event;
struct ring_buffer_iter;
struct ring_buffer_per_cpu;
struct robust_list;
struct robust_list_head;
struct root_domain;
struct rq;
struct rq_flags;
struct rq_qos;
struct rq_qos_ops;
struct rseq;
struct rt6_exception_bucket;
struct rt6_info;
struct rt6_statistics;
struct rt_mutex_base;
struct rt_mutex_waiter;
struct rtable;
struct rtattr;
struct saved;
struct saved_syn;
struct sbitmap_word;
struct sbq_wait_state;
struct scatterlist;
struct sched_class;
struct sched_dl_entity;
struct sched_domain;
struct sched_domain_shared;
struct sched_entity;
struct sched_group;
struct sched_group_capacity;
struct sched_rt_entity;
struct scsi_sense_hdr;
struct sctp_mib;
struct seccomp_filter;
struct seg6_pernet_data;
struct sem_undo_list;
struct seq_file;
struct seq_operations;
struct serial_icounter_struct;
struct serial_struct;
struct sg_table;
struct shrink_control;
struct shrinker;
struct shrinker_info;
struct shrinker_info_unit;
struct sighand_struct;
struct signal_struct;
struct sk_buff;
struct sk_filter;
struct sk_msg;
struct sk_psock;
struct skb_ext;
struct slab;
struct smack_known;
struct smc_stats;
struct smc_stats_rsn;
struct sock;
struct sock_filter;
struct sock_fprog_kern;
struct sock_reuseport;
struct sockaddr;
struct socket;
struct spinlock;
struct srcu_data;
struct srcu_node;
struct srcu_struct;
struct srcu_usage;
struct static_call_key;
struct static_call_mod;
struct static_call_site;
struct static_key_mod;
struct strparser;
struct super_block;
struct super_operations;
struct swap_cluster_info;
struct swap_info_struct;
struct swap_iocb;
struct sysfs_ops;
struct table_header;
struct task_delay_info;
struct task_group;
struct task_struct;
struct taskstats;
union tcp_cc_info;
struct tcp_congestion_ops;
struct tcp_fastopen_context;
struct tcp_mib;
struct throtl_data;
struct throtl_service_queue;
struct time_namespace;
struct timer_list;
struct timer_rand_state;
struct timewait_sock_ops;
struct trace_array;
struct trace_array_cpu;
struct trace_buffer;
struct trace_entry;
struct trace_eval_map;
struct trace_event;
struct trace_event_call;
struct trace_event_class;
struct trace_event_fields;
struct trace_event_file;
struct trace_event_functions;
struct trace_func_repeats;
struct trace_iterator;
struct trace_option_dentry;
struct trace_options;
struct trace_pid_list;
struct trace_subsystem_dir;
struct tracepoint;
struct tracepoint_func;
struct tracer;
struct tracer_flags;
struct tracer_opt;
struct tty_audit_buf;
struct tty_buffer;
struct tty_ldisc;
struct tty_ldisc_ops;
struct tty_operations;
struct tty_port;
struct tty_port_client_operations;
struct tty_port_operations;
struct tty_struct;
struct ubuf_info;
struct ucounts;
struct udp_hslot;
struct udp_mib;
struct udp_table;
struct uevent_sock;
struct uncached_list;
struct unicode_map;
union upper_chunk;
struct uprobe;
struct uprobe_consumer;
struct uprobe_task;
struct uprobe_xol_ops;
struct user_event_mm;
struct user_namespace;
struct user_struct;
struct userfaultfd_ctx;
struct utf8data;
struct utf8data_table;
struct uts_namespace;
struct vdso_image;
struct vfsmount;
struct vm_area_struct;
struct vm_fault;
struct vm_operations_struct;
struct vm_special_mapping;
struct vm_struct;
struct vma_lock;
struct vma_numab_state;
struct wait_queue_entry;
struct wait_queue_head;
struct wake_irq;
struct wake_q_node;
struct wakeup_source;
struct watch;
struct watch_filter;
struct watch_list;
struct watch_queue;
struct winsize;
struct work_struct;
struct worker;
struct worker_pool;
struct workqueue_attrs;
struct workqueue_struct;
struct wq_device;
struct wq_flusher;
struct writeback_control;
struct ww_acquire_ctx;
struct xattr_handler;
struct xol_area;
struct zone;

typedef int __kernel_clockid_t;
typedef struct {
	int val[2];
} __kernel_fsid_t;
typedef unsigned int __kernel_gid32_t;
typedef long long int __kernel_loff_t;
typedef long int __kernel_long_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_pid_t;
typedef int __kernel_rwf_t;
typedef short unsigned int __kernel_sa_family_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef long long int __kernel_time64_t;
typedef int __kernel_timer_t;
struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};
typedef unsigned int __kernel_uid32_t;
typedef long unsigned int __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_size_t;
struct __kfifo {
	unsigned int in;
	unsigned int out;
	unsigned int mask;
	unsigned int esize;
	void *data;
};
typedef unsigned int __poll_t;
typedef void __restorefn_t(void);
typedef short int __s16;
typedef int __s32;
typedef long long int __s64;
typedef signed char __s8;
typedef void __signalfn_t(int);
typedef __signalfn_t *__sighandler_t;
typedef __restorefn_t *__sigrestore_t;
typedef __int128 unsigned __u128;
typedef short unsigned int __u16;
typedef __u16 Elf64_Half;
typedef __u16 __be16;
typedef unsigned int __u32;
typedef __u32 Elf64_Word;
typedef __u32 __be32;
typedef __u32 __portpair;
typedef long long unsigned int __u64;
typedef __u64 Elf64_Addr;
typedef __u64 Elf64_Off;
typedef __u64 Elf64_Xword;
typedef __u64 __addrpair;
typedef __u64 __be64;
typedef unsigned char __u8;
typedef __u32 __wsum;
struct _ddebug_info {
	struct _ddebug *descs;
	struct ddebug_class_map *classes;
	unsigned int num_descs;
	unsigned int num_classes;
};
struct aa_attachment {
	const char *xmatch_str;
	struct aa_policydb *xmatch;
	unsigned int xmatch_len;
	int xattr_count;
	char **xattrs;
};
struct aa_ns_acct {
	int max_size;
	int max_count;
	int size;
	int count;
};
struct aa_str_table {
	int size;
	char **table;
};
struct action_cache {
	long unsigned int allow_native[8];
	long unsigned int allow_compat[8];
};
struct affinity_context {
	const struct cpumask *new_mask;
	struct cpumask *user_mask;
	unsigned int flags;
};
struct arch_uprobe_task {
	long unsigned int saved_scratch_register;
	unsigned int saved_trap_nr;
	unsigned int saved_tf;
};
struct assoc_array {
	struct assoc_array_ptr *root;
	long unsigned int nr_leaves_on_tree;
};
struct assoc_array_ptr;
typedef struct {
	int counter;
} atomic_t;
enum audit_mode {
	AUDIT_NORMAL = 0,
	AUDIT_QUIET_DENIED = 1,
	AUDIT_QUIET = 2,
	AUDIT_NOQUIET = 3,
	AUDIT_ALL = 4,
};
struct balance_callback {
	struct balance_callback *next;
	void (*func)(struct rq *);
};
struct bio_alloc_cache {
	struct bio *free_list;
	struct bio *free_list_irq;
	unsigned int nr;
	unsigned int nr_irq;
};
typedef void bio_end_io_t(struct bio *);
struct bio_list {
	struct bio *head;
	struct bio *tail;
};
struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};
enum blk_bounce {
	BLK_BOUNCE_NONE = 0,
	BLK_BOUNCE_HIGH = 1,
};
struct blk_crypto_ll_ops {
	int (*keyslot_program)(struct blk_crypto_profile *, const struct blk_crypto_key *, unsigned int);
	int (*keyslot_evict)(struct blk_crypto_profile *, const struct blk_crypto_key *, unsigned int);
};
enum blk_crypto_mode_num {
	BLK_ENCRYPTION_MODE_INVALID = 0,
	BLK_ENCRYPTION_MODE_AES_256_XTS = 1,
	BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV = 2,
	BLK_ENCRYPTION_MODE_ADIANTUM = 3,
	BLK_ENCRYPTION_MODE_SM4_XTS = 4,
	BLK_ENCRYPTION_MODE_MAX = 5,
};
struct blk_crypto_config {
	enum blk_crypto_mode_num crypto_mode;
	unsigned int data_unit_size;
	unsigned int dun_bytes;
};
enum blk_eh_timer_return {
	BLK_EH_DONE = 0,
	BLK_EH_RESET_TIMER = 1,
};
typedef unsigned int blk_insert_t;
struct blk_integrity {
	const struct blk_integrity_profile *profile;
	unsigned char flags;
	unsigned char tuple_size;
	unsigned char interval_exp;
	unsigned char tag_size;
};
typedef unsigned int blk_mode_t;
struct bdev_handle {
	struct block_device *bdev;
	void *holder;
	blk_mode_t mode;
};
struct blk_mq_queue_map {
	unsigned int *mq_map;
	unsigned int nr_queues;
	unsigned int queue_offset;
};
typedef __u32 blk_mq_req_flags_t;
typedef __u32 blk_opf_t;
typedef unsigned int blk_qc_t;
enum blk_unique_id {
	BLK_UID_T10 = 1,
	BLK_UID_EUI64 = 2,
	BLK_UID_NAA = 3,
};
struct blk_zone {
	__u64 start;
	__u64 len;
	__u64 wp;
	__u8 type;
	__u8 cond;
	__u8 non_seq;
	__u8 reset;
	__u8 resv[4];
	__u64 capacity;
	__u8 reserved[24];
};
struct blkcg_policy_data {
	struct blkcg *blkcg;
	int plid;
};
typedef _Bool bool;
struct avg_latency_bucket {
	long unsigned int latency;
	bool valid;
};
struct blk_holder_ops {
	void (*mark_dead)(struct block_device *, bool);
	void (*sync)(struct block_device *);
	int (*freeze)(struct block_device *);
	int (*thaw)(struct block_device *);
};
struct blk_mq_queue_data {
	struct request *rq;
	bool last;
};
struct blkg_policy_data {
	struct blkcg_gq *blkg;
	int plid;
	bool online;
};
enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2,
};
enum bpf_arg_type {
	ARG_DONTCARE = 0,
	ARG_CONST_MAP_PTR = 1,
	ARG_PTR_TO_MAP_KEY = 2,
	ARG_PTR_TO_MAP_VALUE = 3,
	ARG_PTR_TO_MEM = 4,
	ARG_CONST_SIZE = 5,
	ARG_CONST_SIZE_OR_ZERO = 6,
	ARG_PTR_TO_CTX = 7,
	ARG_ANYTHING = 8,
	ARG_PTR_TO_SPIN_LOCK = 9,
	ARG_PTR_TO_SOCK_COMMON = 10,
	ARG_PTR_TO_SOCKET = 11,
	ARG_PTR_TO_BTF_ID = 12,
	ARG_PTR_TO_RINGBUF_MEM = 13,
	ARG_CONST_ALLOC_SIZE_OR_ZERO = 14,
	ARG_PTR_TO_BTF_ID_SOCK_COMMON = 15,
	ARG_PTR_TO_PERCPU_BTF_ID = 16,
	ARG_PTR_TO_FUNC = 17,
	ARG_PTR_TO_STACK = 18,
	ARG_PTR_TO_CONST_STR = 19,
	ARG_PTR_TO_TIMER = 20,
	ARG_PTR_TO_KPTR = 21,
	ARG_PTR_TO_DYNPTR = 22,
	__BPF_ARG_TYPE_MAX = 23,
	ARG_PTR_TO_MAP_VALUE_OR_NULL = 259,
	ARG_PTR_TO_MEM_OR_NULL = 260,
	ARG_PTR_TO_CTX_OR_NULL = 263,
	ARG_PTR_TO_SOCKET_OR_NULL = 267,
	ARG_PTR_TO_STACK_OR_NULL = 274,
	ARG_PTR_TO_BTF_ID_OR_NULL = 268,
	ARG_PTR_TO_UNINIT_MEM = 67141636,
	ARG_PTR_TO_FIXED_SIZE_MEM = 262148,
	__BPF_ARG_TYPE_LIMIT = 134217727,
};
enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_INET_EGRESS = 1,
	BPF_CGROUP_INET_SOCK_CREATE = 2,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_CGROUP_DEVICE = 6,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_BIND = 8,
	BPF_CGROUP_INET6_BIND = 9,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_CGROUP_INET6_CONNECT = 11,
	BPF_CGROUP_INET4_POST_BIND = 12,
	BPF_CGROUP_INET6_POST_BIND = 13,
	BPF_CGROUP_UDP4_SENDMSG = 14,
	BPF_CGROUP_UDP6_SENDMSG = 15,
	BPF_LIRC_MODE2 = 16,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG = 20,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT = 22,
	BPF_TRACE_RAW_TP = 23,
	BPF_TRACE_FENTRY = 24,
	BPF_TRACE_FEXIT = 25,
	BPF_MODIFY_RETURN = 26,
	BPF_LSM_MAC = 27,
	BPF_TRACE_ITER = 28,
	BPF_CGROUP_INET4_GETPEERNAME = 29,
	BPF_CGROUP_INET6_GETPEERNAME = 30,
	BPF_CGROUP_INET4_GETSOCKNAME = 31,
	BPF_CGROUP_INET6_GETSOCKNAME = 32,
	BPF_XDP_DEVMAP = 33,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	BPF_XDP_CPUMAP = 35,
	BPF_SK_LOOKUP = 36,
	BPF_XDP = 37,
	BPF_SK_SKB_VERDICT = 38,
	BPF_SK_REUSEPORT_SELECT = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	BPF_PERF_EVENT = 41,
	BPF_TRACE_KPROBE_MULTI = 42,
	BPF_LSM_CGROUP = 43,
	BPF_STRUCT_OPS = 44,
	BPF_NETFILTER = 45,
	BPF_TCX_INGRESS = 46,
	BPF_TCX_EGRESS = 47,
	BPF_TRACE_UPROBE_MULTI = 48,
	BPF_CGROUP_UNIX_CONNECT = 49,
	BPF_CGROUP_UNIX_SENDMSG = 50,
	BPF_CGROUP_UNIX_RECVMSG = 51,
	BPF_CGROUP_UNIX_GETPEERNAME = 52,
	BPF_CGROUP_UNIX_GETSOCKNAME = 53,
	BPF_NETKIT_PRIMARY = 54,
	BPF_NETKIT_PEER = 55,
	__MAX_BPF_ATTACH_TYPE = 56,
};
union bpf_attr {
	struct {
		__u32 map_type;
		__u32 key_size;
		__u32 value_size;
		__u32 max_entries;
		__u32 map_flags;
		__u32 inner_map_fd;
		__u32 numa_node;
		char map_name[16];
		__u32 map_ifindex;
		__u32 btf_fd;
		__u32 btf_key_type_id;
		__u32 btf_value_type_id;
		__u32 btf_vmlinux_value_type_id;
		__u64 map_extra;
	};
	struct {
		__u32 map_fd;
		__u64 key;
		union {
			__u64 value;
			__u64 next_key;
		};
		__u64 flags;
	};
	struct {
		__u64 in_batch;
		__u64 out_batch;
		__u64 keys;
		__u64 values;
		__u32 count;
		__u32 map_fd;
		__u64 elem_flags;
		__u64 flags;
	} batch;
	struct {
		__u32 prog_type;
		__u32 insn_cnt;
		__u64 insns;
		__u64 license;
		__u32 log_level;
		__u32 log_size;
		__u64 log_buf;
		__u32 kern_version;
		__u32 prog_flags;
		char prog_name[16];
		__u32 prog_ifindex;
		__u32 expected_attach_type;
		__u32 prog_btf_fd;
		__u32 func_info_rec_size;
		__u64 func_info;
		__u32 func_info_cnt;
		__u32 line_info_rec_size;
		__u64 line_info;
		__u32 line_info_cnt;
		__u32 attach_btf_id;
		union {
			__u32 attach_prog_fd;
			__u32 attach_btf_obj_fd;
		};
		__u32 core_relo_cnt;
		__u64 fd_array;
		__u64 core_relos;
		__u32 core_relo_rec_size;
		__u32 log_true_size;
	};
	struct {
		__u64 pathname;
		__u32 bpf_fd;
		__u32 file_flags;
		__s32 path_fd;
	};
	struct {
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
		__u32 replace_bpf_fd;
		union {
			__u32 relative_fd;
			__u32 relative_id;
		};
		__u64 expected_revision;
	};
	struct {
		__u32 prog_fd;
		__u32 retval;
		__u32 data_size_in;
		__u32 data_size_out;
		__u64 data_in;
		__u64 data_out;
		__u32 repeat;
		__u32 duration;
		__u32 ctx_size_in;
		__u32 ctx_size_out;
		__u64 ctx_in;
		__u64 ctx_out;
		__u32 flags;
		__u32 cpu;
		__u32 batch_size;
	} test;
	struct {
		union {
			__u32 start_id;
			__u32 prog_id;
			__u32 map_id;
			__u32 btf_id;
			__u32 link_id;
		};
		__u32 next_id;
		__u32 open_flags;
	};
	struct {
		__u32 bpf_fd;
		__u32 info_len;
		__u64 info;
	} info;
	struct {
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 query_flags;
		__u32 attach_flags;
		__u64 prog_ids;
		union {
			__u32 prog_cnt;
			__u32 count;
		};
		__u64 prog_attach_flags;
		__u64 link_ids;
		__u64 link_attach_flags;
		__u64 revision;
	} query;
	struct {
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;
	struct {
		__u64 btf;
		__u64 btf_log_buf;
		__u32 btf_size;
		__u32 btf_log_size;
		__u32 btf_log_level;
		__u32 btf_log_true_size;
	};
	struct {
		__u32 pid;
		__u32 fd;
		__u32 flags;
		__u32 buf_len;
		__u64 buf;
		__u32 prog_id;
		__u32 fd_type;
		__u64 probe_offset;
		__u64 probe_addr;
	} task_fd_query;
	struct {
		union {
			__u32 prog_fd;
			__u32 map_fd;
		};
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 flags;
		union {
			__u32 target_btf_id;
			struct {
				__u64 iter_info;
				__u32 iter_info_len;
			};
			struct {
				__u64 bpf_cookie;
			} perf_event;
			struct {
				__u32 flags;
				__u32 cnt;
				__u64 syms;
				__u64 addrs;
				__u64 cookies;
			} kprobe_multi;
			struct {
				__u32 target_btf_id;
				__u64 cookie;
			} tracing;
			struct {
				__u32 pf;
				__u32 hooknum;
				__s32 priority;
				__u32 flags;
			} netfilter;
			struct {
				union {
					__u32 relative_fd;
					__u32 relative_id;
				};
				__u64 expected_revision;
			} tcx;
			struct {
				__u64 path;
				__u64 offsets;
				__u64 ref_ctr_offsets;
				__u64 cookies;
				__u32 cnt;
				__u32 flags;
				__u32 pid;
			} uprobe_multi;
			struct {
				union {
					__u32 relative_fd;
					__u32 relative_id;
				};
				__u64 expected_revision;
			} netkit;
		};
	} link_create;
	struct {
		__u32 link_fd;
		union {
			__u32 new_prog_fd;
			__u32 new_map_fd;
		};
		__u32 flags;
		union {
			__u32 old_prog_fd;
			__u32 old_map_fd;
		};
	} link_update;
	struct {
		__u32 link_fd;
	} link_detach;
	struct {
		__u32 type;
	} enable_stats;
	struct {
		__u32 link_fd;
		__u32 flags;
	} iter_create;
	struct {
		__u32 prog_fd;
		__u32 map_fd;
		__u32 flags;
	} prog_bind_map;
};
enum bpf_cgroup_iter_order {
	BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
	BPF_CGROUP_ITER_SELF_ONLY = 1,
	BPF_CGROUP_ITER_DESCENDANTS_PRE = 2,
	BPF_CGROUP_ITER_DESCENDANTS_POST = 3,
	BPF_CGROUP_ITER_ANCESTORS_UP = 4,
};
struct bpf_cgroup_storage_key {
	__u64 cgroup_inode_id;
	__u32 attach_type;
};
enum bpf_dynptr_type {
	BPF_DYNPTR_TYPE_INVALID = 0,
	BPF_DYNPTR_TYPE_LOCAL = 1,
	BPF_DYNPTR_TYPE_RINGBUF = 2,
	BPF_DYNPTR_TYPE_SKB = 3,
	BPF_DYNPTR_TYPE_XDP = 4,
};
enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_probe_read = 4,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_skb_store_bytes = 9,
	BPF_FUNC_l3_csum_replace = 10,
	BPF_FUNC_l4_csum_replace = 11,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_clone_redirect = 13,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_get_cgroup_classid = 17,
	BPF_FUNC_skb_vlan_push = 18,
	BPF_FUNC_skb_vlan_pop = 19,
	BPF_FUNC_skb_get_tunnel_key = 20,
	BPF_FUNC_skb_set_tunnel_key = 21,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_redirect = 23,
	BPF_FUNC_get_route_realm = 24,
	BPF_FUNC_perf_event_output = 25,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_stackid = 27,
	BPF_FUNC_csum_diff = 28,
	BPF_FUNC_skb_get_tunnel_opt = 29,
	BPF_FUNC_skb_set_tunnel_opt = 30,
	BPF_FUNC_skb_change_proto = 31,
	BPF_FUNC_skb_change_type = 32,
	BPF_FUNC_skb_under_cgroup = 33,
	BPF_FUNC_get_hash_recalc = 34,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_probe_write_user = 36,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_skb_change_tail = 38,
	BPF_FUNC_skb_pull_data = 39,
	BPF_FUNC_csum_update = 40,
	BPF_FUNC_set_hash_invalid = 41,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_skb_change_head = 43,
	BPF_FUNC_xdp_adjust_head = 44,
	BPF_FUNC_probe_read_str = 45,
	BPF_FUNC_get_socket_cookie = 46,
	BPF_FUNC_get_socket_uid = 47,
	BPF_FUNC_set_hash = 48,
	BPF_FUNC_setsockopt = 49,
	BPF_FUNC_skb_adjust_room = 50,
	BPF_FUNC_redirect_map = 51,
	BPF_FUNC_sk_redirect_map = 52,
	BPF_FUNC_sock_map_update = 53,
	BPF_FUNC_xdp_adjust_meta = 54,
	BPF_FUNC_perf_event_read_value = 55,
	BPF_FUNC_perf_prog_read_value = 56,
	BPF_FUNC_getsockopt = 57,
	BPF_FUNC_override_return = 58,
	BPF_FUNC_sock_ops_cb_flags_set = 59,
	BPF_FUNC_msg_redirect_map = 60,
	BPF_FUNC_msg_apply_bytes = 61,
	BPF_FUNC_msg_cork_bytes = 62,
	BPF_FUNC_msg_pull_data = 63,
	BPF_FUNC_bind = 64,
	BPF_FUNC_xdp_adjust_tail = 65,
	BPF_FUNC_skb_get_xfrm_state = 66,
	BPF_FUNC_get_stack = 67,
	BPF_FUNC_skb_load_bytes_relative = 68,
	BPF_FUNC_fib_lookup = 69,
	BPF_FUNC_sock_hash_update = 70,
	BPF_FUNC_msg_redirect_hash = 71,
	BPF_FUNC_sk_redirect_hash = 72,
	BPF_FUNC_lwt_push_encap = 73,
	BPF_FUNC_lwt_seg6_store_bytes = 74,
	BPF_FUNC_lwt_seg6_adjust_srh = 75,
	BPF_FUNC_lwt_seg6_action = 76,
	BPF_FUNC_rc_repeat = 77,
	BPF_FUNC_rc_keydown = 78,
	BPF_FUNC_skb_cgroup_id = 79,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_get_local_storage = 81,
	BPF_FUNC_sk_select_reuseport = 82,
	BPF_FUNC_skb_ancestor_cgroup_id = 83,
	BPF_FUNC_sk_lookup_tcp = 84,
	BPF_FUNC_sk_lookup_udp = 85,
	BPF_FUNC_sk_release = 86,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_msg_push_data = 90,
	BPF_FUNC_msg_pop_data = 91,
	BPF_FUNC_rc_pointer_rel = 92,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_sk_fullsock = 95,
	BPF_FUNC_tcp_sock = 96,
	BPF_FUNC_skb_ecn_set_ce = 97,
	BPF_FUNC_get_listener_sock = 98,
	BPF_FUNC_skc_lookup_tcp = 99,
	BPF_FUNC_tcp_check_syncookie = 100,
	BPF_FUNC_sysctl_get_name = 101,
	BPF_FUNC_sysctl_get_current_value = 102,
	BPF_FUNC_sysctl_get_new_value = 103,
	BPF_FUNC_sysctl_set_new_value = 104,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_sk_storage_get = 107,
	BPF_FUNC_sk_storage_delete = 108,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_tcp_gen_syncookie = 110,
	BPF_FUNC_skb_output = 111,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_tcp_send_ack = 116,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_read_branch_records = 119,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_xdp_output = 121,
	BPF_FUNC_get_netns_cookie = 122,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_sk_assign = 124,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_seq_printf = 126,
	BPF_FUNC_seq_write = 127,
	BPF_FUNC_sk_cgroup_id = 128,
	BPF_FUNC_sk_ancestor_cgroup_id = 129,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_csum_level = 135,
	BPF_FUNC_skc_to_tcp6_sock = 136,
	BPF_FUNC_skc_to_tcp_sock = 137,
	BPF_FUNC_skc_to_tcp_timewait_sock = 138,
	BPF_FUNC_skc_to_tcp_request_sock = 139,
	BPF_FUNC_skc_to_udp6_sock = 140,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_load_hdr_opt = 142,
	BPF_FUNC_store_hdr_opt = 143,
	BPF_FUNC_reserve_hdr_opt = 144,
	BPF_FUNC_inode_storage_get = 145,
	BPF_FUNC_inode_storage_delete = 146,
	BPF_FUNC_d_path = 147,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_seq_printf_btf = 150,
	BPF_FUNC_skb_cgroup_classid = 151,
	BPF_FUNC_redirect_neigh = 152,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_redirect_peer = 155,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_bprm_opts_set = 159,
	BPF_FUNC_ktime_get_coarse_ns = 160,
	BPF_FUNC_ima_inode_hash = 161,
	BPF_FUNC_sock_from_file = 162,
	BPF_FUNC_check_mtu = 163,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_sys_bpf = 166,
	BPF_FUNC_btf_find_by_name_kind = 167,
	BPF_FUNC_sys_close = 168,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_get_func_ip = 173,
	BPF_FUNC_get_attach_cookie = 174,
	BPF_FUNC_task_pt_regs = 175,
	BPF_FUNC_get_branch_snapshot = 176,
	BPF_FUNC_trace_vprintk = 177,
	BPF_FUNC_skc_to_unix_sock = 178,
	BPF_FUNC_kallsyms_lookup_name = 179,
	BPF_FUNC_find_vma = 180,
	BPF_FUNC_loop = 181,
	BPF_FUNC_strncmp = 182,
	BPF_FUNC_get_func_arg = 183,
	BPF_FUNC_get_func_ret = 184,
	BPF_FUNC_get_func_arg_cnt = 185,
	BPF_FUNC_get_retval = 186,
	BPF_FUNC_set_retval = 187,
	BPF_FUNC_xdp_get_buff_len = 188,
	BPF_FUNC_xdp_load_bytes = 189,
	BPF_FUNC_xdp_store_bytes = 190,
	BPF_FUNC_copy_from_user_task = 191,
	BPF_FUNC_skb_set_tstamp = 192,
	BPF_FUNC_ima_file_hash = 193,
	BPF_FUNC_kptr_xchg = 194,
	BPF_FUNC_map_lookup_percpu_elem = 195,
	BPF_FUNC_skc_to_mptcp_sock = 196,
	BPF_FUNC_dynptr_from_mem = 197,
	BPF_FUNC_ringbuf_reserve_dynptr = 198,
	BPF_FUNC_ringbuf_submit_dynptr = 199,
	BPF_FUNC_ringbuf_discard_dynptr = 200,
	BPF_FUNC_dynptr_read = 201,
	BPF_FUNC_dynptr_write = 202,
	BPF_FUNC_dynptr_data = 203,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205,
	BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206,
	BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207,
	BPF_FUNC_ktime_get_tai_ns = 208,
	BPF_FUNC_user_ringbuf_drain = 209,
	BPF_FUNC_cgrp_storage_get = 210,
	BPF_FUNC_cgrp_storage_delete = 211,
	__BPF_FUNC_MAX_ID = 212,
};
struct bpf_func_info {
	__u32 insn_off;
	__u32 type_id;
};
struct bpf_insn {
	__u8 code;
	__u8 dst_reg: 4;
	__u8 src_reg: 4;
	__s16 off;
	__s32 imm;
};
typedef void (*bpf_iter_fini_seq_priv_t)(void *);
typedef int (*bpf_iter_init_seq_priv_t)(void *, struct bpf_iter_aux_info *);
enum bpf_iter_state {
	BPF_ITER_STATE_INVALID = 0,
	BPF_ITER_STATE_ACTIVE = 1,
	BPF_ITER_STATE_DRAINED = 2,
};
enum bpf_iter_task_type {
	BPF_TASK_ITER_ALL = 0,
	BPF_TASK_ITER_TID = 1,
	BPF_TASK_ITER_TGID = 2,
};
struct bpf_line_info {
	__u32 insn_off;
	__u32 file_name_off;
	__u32 line_off;
	__u32 line_col;
};
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
};
struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *, const union bpf_attr *, union bpf_attr *);
};
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
	BPF_PROG_TYPE_SOCKET_FILTER = 1,
	BPF_PROG_TYPE_KPROBE = 2,
	BPF_PROG_TYPE_SCHED_CLS = 3,
	BPF_PROG_TYPE_SCHED_ACT = 4,
	BPF_PROG_TYPE_TRACEPOINT = 5,
	BPF_PROG_TYPE_XDP = 6,
	BPF_PROG_TYPE_PERF_EVENT = 7,
	BPF_PROG_TYPE_CGROUP_SKB = 8,
	BPF_PROG_TYPE_CGROUP_SOCK = 9,
	BPF_PROG_TYPE_LWT_IN = 10,
	BPF_PROG_TYPE_LWT_OUT = 11,
	BPF_PROG_TYPE_LWT_XMIT = 12,
	BPF_PROG_TYPE_SOCK_OPS = 13,
	BPF_PROG_TYPE_SK_SKB = 14,
	BPF_PROG_TYPE_CGROUP_DEVICE = 15,
	BPF_PROG_TYPE_SK_MSG = 16,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
	BPF_PROG_TYPE_LIRC_MODE2 = 20,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
	BPF_PROG_TYPE_STRUCT_OPS = 27,
	BPF_PROG_TYPE_EXT = 28,
	BPF_PROG_TYPE_LSM = 29,
	BPF_PROG_TYPE_SK_LOOKUP = 30,
	BPF_PROG_TYPE_SYSCALL = 31,
	BPF_PROG_TYPE_NETFILTER = 32,
};
struct bpf_reference_state {
	int id;
	int insn_idx;
	int callback_ref;
};
enum bpf_reg_liveness {
	REG_LIVE_NONE = 0,
	REG_LIVE_READ32 = 1,
	REG_LIVE_READ64 = 2,
	REG_LIVE_READ = 3,
	REG_LIVE_WRITTEN = 4,
	REG_LIVE_DONE = 8,
};
enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE = 1,
	PTR_TO_CTX = 2,
	CONST_PTR_TO_MAP = 3,
	PTR_TO_MAP_VALUE = 4,
	PTR_TO_MAP_KEY = 5,
	PTR_TO_STACK = 6,
	PTR_TO_PACKET_META = 7,
	PTR_TO_PACKET = 8,
	PTR_TO_PACKET_END = 9,
	PTR_TO_FLOW_KEYS = 10,
	PTR_TO_SOCKET = 11,
	PTR_TO_SOCK_COMMON = 12,
	PTR_TO_TCP_SOCK = 13,
	PTR_TO_TP_BUFFER = 14,
	PTR_TO_XDP_SOCK = 15,
	PTR_TO_BTF_ID = 16,
	PTR_TO_MEM = 17,
	PTR_TO_BUF = 18,
	PTR_TO_FUNC = 19,
	CONST_PTR_TO_DYNPTR = 20,
	__BPF_REG_TYPE_MAX = 21,
	PTR_TO_MAP_VALUE_OR_NULL = 260,
	PTR_TO_SOCKET_OR_NULL = 267,
	PTR_TO_SOCK_COMMON_OR_NULL = 268,
	PTR_TO_TCP_SOCK_OR_NULL = 269,
	PTR_TO_BTF_ID_OR_NULL = 272,
	__BPF_REG_TYPE_LIMIT = 134217727,
};
enum bpf_return_type {
	RET_INTEGER = 0,
	RET_VOID = 1,
	RET_PTR_TO_MAP_VALUE = 2,
	RET_PTR_TO_SOCKET = 3,
	RET_PTR_TO_TCP_SOCK = 4,
	RET_PTR_TO_SOCK_COMMON = 5,
	RET_PTR_TO_MEM = 6,
	RET_PTR_TO_MEM_OR_BTF_ID = 7,
	RET_PTR_TO_BTF_ID = 8,
	__BPF_RET_TYPE_MAX = 9,
	RET_PTR_TO_MAP_VALUE_OR_NULL = 258,
	RET_PTR_TO_SOCKET_OR_NULL = 259,
	RET_PTR_TO_TCP_SOCK_OR_NULL = 260,
	RET_PTR_TO_SOCK_COMMON_OR_NULL = 261,
	RET_PTR_TO_RINGBUF_MEM_OR_NULL = 1286,
	RET_PTR_TO_DYNPTR_MEM_OR_NULL = 262,
	RET_PTR_TO_BTF_ID_OR_NULL = 264,
	RET_PTR_TO_BTF_ID_TRUSTED = 1048584,
	__BPF_RET_TYPE_LIMIT = 134217727,
};
struct bpf_run_ctx {};
typedef void (*btf_dtor_kfunc_t)(void *);
enum btf_field_type {
	BPF_SPIN_LOCK = 1,
	BPF_TIMER = 2,
	BPF_KPTR_UNREF = 4,
	BPF_KPTR_REF = 8,
	BPF_KPTR_PERCPU = 16,
	BPF_KPTR = 28,
	BPF_LIST_HEAD = 32,
	BPF_LIST_NODE = 64,
	BPF_RB_ROOT = 128,
	BPF_RB_NODE = 256,
	BPF_GRAPH_NODE = 320,
	BPF_GRAPH_ROOT = 160,
	BPF_REFCOUNT = 512,
};
struct btf_header {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};
struct btf_mod_pair {
	struct btf *btf;
	struct module *module;
};
struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};
struct bug_entry {
	int bug_addr_disp;
	int file_disp;
	short unsigned int line;
	short unsigned int flags;
};
struct cacheline_padding {
	char x[0];
};
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};
struct bpf_storage_buffer {
	struct callback_head rcu;
	char data[0];
};
struct can_dev_rcv_lists;
struct can_pkg_stats;
struct can_rcv_lists_stats;
struct capture_control {
	struct compact_control *cc;
	struct page *page;
};
typedef unsigned char cc_t;
struct cdrom_mcn {
	__u8 medium_catalog_number[14];
};
struct cdrom_msf0 {
	__u8 minute;
	__u8 second;
	__u8 frame;
};
union cdrom_addr {
	struct cdrom_msf0 msf;
	int lba;
};
struct cdrom_multisession {
	union cdrom_addr addr;
	__u8 xa_flag;
	__u8 addr_format;
};
struct cgroup_freezer_state {
	bool freeze;
	int e_freeze;
	int nr_frozen_descendants;
	int nr_frozen_tasks;
};
enum class_map_type {
	DD_CLASS_TYPE_DISJOINT_BITS = 0,
	DD_CLASS_TYPE_LEVEL_NUM = 1,
	DD_CLASS_TYPE_DISJOINT_NAMES = 2,
	DD_CLASS_TYPE_LEVEL_NAMES = 3,
};
typedef __kernel_clockid_t clockid_t;
typedef bool (*cond_update_fn_t)(struct trace_array *, void *);
struct cond_snapshot {
	void *cond_data;
	cond_update_fn_t update;
};
struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};
struct core_vma_metadata {
	long unsigned int start;
	long unsigned int end;
	long unsigned int flags;
	long unsigned int dump_size;
	long unsigned int pgoff;
	struct file *file;
};
typedef int (*cpu_stop_fn_t)(void *);
struct cpuidle_driver_kobj;
struct cpumask {
	long unsigned int bits[128];
};
struct arch_tlbflush_unmap_batch {
	struct cpumask cpumask;
};
typedef struct cpumask cpumask_t;
typedef struct cpumask *cpumask_var_t;
struct cpupri_vec {
	atomic_t count;
	cpumask_var_t mask;
};
struct cpupri {
	struct cpupri_vec pri_to_cpu[101];
	int *cpu_to_pri;
};
struct da_monitor {
	bool monitoring;
	unsigned int curr_state;
};
enum dax_access_mode {
	DAX_ACCESS = 0,
	DAX_RECOVERY_WRITE = 1,
};
struct delayed_call {
	void (*fn)(void *);
	void *arg;
};
struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char * (*d_dname)(struct dentry *, char *, int);
	struct vfsmount * (*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry * (*d_real)(struct dentry *, const struct inode *);
	long: 64;
	long: 64;
	long: 64;
};
struct dev_archdata {};
enum dev_dma_attr {
	DEV_DMA_NOT_SUPPORTED = 0,
	DEV_DMA_NON_COHERENT = 1,
	DEV_DMA_COHERENT = 2,
};
struct dev_msi_info {
	struct irq_domain *domain;
	struct msi_device_data *data;
};
struct dev_pin_info {
	struct pinctrl *p;
	struct pinctrl_state *default_state;
	struct pinctrl_state *init_state;
	struct pinctrl_state *sleep_state;
	struct pinctrl_state *idle_state;
};
struct dev_pm_ops {
	int (*prepare)(struct device *);
	void (*complete)(struct device *);
	int (*suspend)(struct device *);
	int (*resume)(struct device *);
	int (*freeze)(struct device *);
	int (*thaw)(struct device *);
	int (*poweroff)(struct device *);
	int (*restore)(struct device *);
	int (*suspend_late)(struct device *);
	int (*resume_early)(struct device *);
	int (*freeze_late)(struct device *);
	int (*thaw_early)(struct device *);
	int (*poweroff_late)(struct device *);
	int (*restore_early)(struct device *);
	int (*suspend_noirq)(struct device *);
	int (*resume_noirq)(struct device *);
	int (*freeze_noirq)(struct device *);
	int (*thaw_noirq)(struct device *);
	int (*poweroff_noirq)(struct device *);
	int (*restore_noirq)(struct device *);
	int (*runtime_suspend)(struct device *);
	int (*runtime_resume)(struct device *);
	int (*runtime_idle)(struct device *);
};
struct dev_pm_domain {
	struct dev_pm_ops ops;
	int (*start)(struct device *);
	void (*detach)(struct device *, bool);
	int (*activate)(struct device *);
	void (*sync)(struct device *);
	void (*dismiss)(struct device *);
	int (*set_performance_state)(struct device *, unsigned int);
};
enum dev_pm_qos_req_type {
	DEV_PM_QOS_RESUME_LATENCY = 1,
	DEV_PM_QOS_LATENCY_TOLERANCE = 2,
	DEV_PM_QOS_MIN_FREQUENCY = 3,
	DEV_PM_QOS_MAX_FREQUENCY = 4,
	DEV_PM_QOS_FLAGS = 5,
};
struct device_dma_parameters {
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	long unsigned int segment_boundary_mask;
};
enum device_physical_location_horizontal_position {
	DEVICE_HORI_POS_LEFT = 0,
	DEVICE_HORI_POS_CENTER = 1,
	DEVICE_HORI_POS_RIGHT = 2,
};
enum device_physical_location_panel {
	DEVICE_PANEL_TOP = 0,
	DEVICE_PANEL_BOTTOM = 1,
	DEVICE_PANEL_LEFT = 2,
	DEVICE_PANEL_RIGHT = 3,
	DEVICE_PANEL_FRONT = 4,
	DEVICE_PANEL_BACK = 5,
	DEVICE_PANEL_UNKNOWN = 6,
};
enum device_physical_location_vertical_position {
	DEVICE_VERT_POS_UPPER = 0,
	DEVICE_VERT_POS_CENTER = 1,
	DEVICE_VERT_POS_LOWER = 2,
};
struct device_physical_location {
	enum device_physical_location_panel panel;
	enum device_physical_location_vertical_position vertical_position;
	enum device_physical_location_horizontal_position horizontal_position;
	bool dock;
	bool lid;
};
enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN = 1,
	DEVICE_FIXED = 2,
	DEVICE_REMOVABLE = 3,
};
enum dl_dev_state {
	DL_DEV_NO_DRIVER = 0,
	DL_DEV_PROBING = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING = 3,
};
typedef bool (*dl_server_has_tasks_f)(struct sched_dl_entity *);
typedef struct task_struct * (*dl_server_pick_f)(struct sched_dl_entity *);
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};
struct elf64_hdr {
	unsigned char e_ident[16];
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;
	Elf64_Off e_phoff;
	Elf64_Off e_shoff;
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_phnum;
	Elf64_Half e_shentsize;
	Elf64_Half e_shnum;
	Elf64_Half e_shstrndx;
};
typedef struct elf64_hdr Elf64_Ehdr;
struct elf64_shdr {
	Elf64_Word sh_name;
	Elf64_Word sh_type;
	Elf64_Xword sh_flags;
	Elf64_Addr sh_addr;
	Elf64_Off sh_offset;
	Elf64_Xword sh_size;
	Elf64_Word sh_link;
	Elf64_Word sh_info;
	Elf64_Xword sh_addralign;
	Elf64_Xword sh_entsize;
};
typedef struct elf64_shdr Elf64_Shdr;
struct elf64_sym {
	Elf64_Word st_name;
	unsigned char st_info;
	unsigned char st_other;
	Elf64_Half st_shndx;
	Elf64_Addr st_value;
	Elf64_Xword st_size;
};
typedef struct elf64_sym Elf64_Sym;
enum elv_merge {
	ELEVATOR_NO_MERGE = 0,
	ELEVATOR_FRONT_MERGE = 1,
	ELEVATOR_BACK_MERGE = 2,
	ELEVATOR_DISCARD_MERGE = 3,
};
struct em_perf_domain {
	struct em_perf_state *table;
	int nr_perf_states;
	long unsigned int flags;
	long unsigned int cpus[0];
};
struct em_perf_state {
	long unsigned int frequency;
	long unsigned int power;
	long unsigned int cost;
	long unsigned int flags;
};
struct error_injection_entry {
	long unsigned int addr;
	int etype;
};
struct event_filter {
	struct prog_entry *prog;
	char *filter_string;
};
typedef void (*eventfs_release)(const char *, void *);
struct exception_table_entry {
	int insn;
	int fixup;
	int data;
};
enum fault_flag {
	FAULT_FLAG_WRITE = 1,
	FAULT_FLAG_MKWRITE = 2,
	FAULT_FLAG_ALLOW_RETRY = 4,
	FAULT_FLAG_RETRY_NOWAIT = 8,
	FAULT_FLAG_KILLABLE = 16,
	FAULT_FLAG_TRIED = 32,
	FAULT_FLAG_USER = 64,
	FAULT_FLAG_REMOTE = 128,
	FAULT_FLAG_INSTRUCTION = 256,
	FAULT_FLAG_INTERRUPTIBLE = 512,
	FAULT_FLAG_UNSHARE = 1024,
	FAULT_FLAG_ORIG_PTE_VALID = 2048,
	FAULT_FLAG_VMA_LOCK = 4096,
};
struct fdtable {
	unsigned int max_fds;
	struct file **fd;
	long unsigned int *close_on_exec;
	long unsigned int *open_fds;
	long unsigned int *full_fds_bits;
	struct callback_head rcu;
};
struct fib6_node {
	struct fib6_node *parent;
	struct fib6_node *left;
	struct fib6_node *right;
	struct fib6_node *subtree;
	struct fib6_info *leaf;
	__u16 fn_bit;
	__u16 fn_flags;
	int fn_sernum;
	struct fib6_info *rr_ptr;
	struct callback_head rcu;
};
struct fib_rule_hdr {
	__u8 family;
	__u8 dst_len;
	__u8 src_len;
	__u8 tos;
	__u8 table;
	__u8 res1;
	__u8 res2;
	__u8 action;
	__u32 flags;
};
struct fib_rule_port_range {
	__u16 start;
	__u16 end;
};
struct fiemap_extent {
	__u64 fe_logical;
	__u64 fe_physical;
	__u64 fe_length;
	__u64 fe_reserved64[2];
	__u32 fe_flags;
	__u32 fe_reserved[3];
};
struct fiemap_extent_info {
	unsigned int fi_flags;
	unsigned int fi_extents_mapped;
	unsigned int fi_extents_max;
	struct fiemap_extent *fi_extents_start;
};
struct file_lock_operations {
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};
struct filename {
	const char *name;
	const char *uptr;
	atomic_t refcnt;
	struct audit_names *aname;
	const char iname[0];
};
enum filter_pred_fn {
	FILTER_PRED_FN_NOP = 0,
	FILTER_PRED_FN_64 = 1,
	FILTER_PRED_FN_64_CPUMASK = 2,
	FILTER_PRED_FN_S64 = 3,
	FILTER_PRED_FN_U64 = 4,
	FILTER_PRED_FN_32 = 5,
	FILTER_PRED_FN_32_CPUMASK = 6,
	FILTER_PRED_FN_S32 = 7,
	FILTER_PRED_FN_U32 = 8,
	FILTER_PRED_FN_16 = 9,
	FILTER_PRED_FN_16_CPUMASK = 10,
	FILTER_PRED_FN_S16 = 11,
	FILTER_PRED_FN_U16 = 12,
	FILTER_PRED_FN_8 = 13,
	FILTER_PRED_FN_8_CPUMASK = 14,
	FILTER_PRED_FN_S8 = 15,
	FILTER_PRED_FN_U8 = 16,
	FILTER_PRED_FN_COMM = 17,
	FILTER_PRED_FN_STRING = 18,
	FILTER_PRED_FN_STRLOC = 19,
	FILTER_PRED_FN_STRRELLOC = 20,
	FILTER_PRED_FN_PCHAR_USER = 21,
	FILTER_PRED_FN_PCHAR = 22,
	FILTER_PRED_FN_CPU = 23,
	FILTER_PRED_FN_CPU_CPUMASK = 24,
	FILTER_PRED_FN_CPUMASK = 25,
	FILTER_PRED_FN_CPUMASK_CPU = 26,
	FILTER_PRED_FN_FUNCTION = 27,
	FILTER_PRED_FN_ = 28,
	FILTER_PRED_TEST_VISITED = 29,
};
typedef void *fl_owner_t;
struct flowi_tunnel {
	__be64 tun_id;
};
union flowi_uli {
	struct {
		__be16 dport;
		__be16 sport;
	} ports;
	struct {
		__u8 type;
		__u8 code;
	} icmpt;
	__be32 gre_key;
	struct {
		__u8 type;
	} mht;
};
typedef unsigned int fmode_t;
struct fnhe_hash_bucket {
	struct fib_nh_exception *chain;
};
typedef struct io_wq_work *free_work_fn(struct io_wq_work *);
enum freeze_holder {
	FREEZE_HOLDER_KERNEL = 1,
	FREEZE_HOLDER_USERSPACE = 2,
	FREEZE_MAY_NEST = 4,
};
enum freq_qos_req_type {
	FREQ_QOS_MIN = 1,
	FREQ_QOS_MAX = 2,
};
struct fs_context_operations {
	void (*free)(struct fs_context *);
	int (*dup)(struct fs_context *, struct fs_context *);
	int (*parse_param)(struct fs_context *, struct fs_parameter *);
	int (*parse_monolithic)(struct fs_context *, void *);
	int (*get_tree)(struct fs_context *);
	int (*reconfigure)(struct fs_context *);
};
enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS = 0,
	FS_CONTEXT_CREATING = 1,
	FS_CONTEXT_AWAITING_MOUNT = 2,
	FS_CONTEXT_AWAITING_RECONF = 3,
	FS_CONTEXT_RECONF_PARAMS = 4,
	FS_CONTEXT_RECONFIGURING = 5,
	FS_CONTEXT_FAILED = 6,
};
enum fs_context_purpose {
	FS_CONTEXT_FOR_MOUNT = 0,
	FS_CONTEXT_FOR_SUBMOUNT = 1,
	FS_CONTEXT_FOR_RECONFIGURE = 2,
};
typedef int fs_param_type(struct p_log *, const struct fs_parameter_spec *, struct fs_parameter *, struct fs_parse_result *);
enum fs_value_type {
	fs_value_is_undefined = 0,
	fs_value_is_flag = 1,
	fs_value_is_string = 2,
	fs_value_is_blob = 3,
	fs_value_is_filename = 4,
	fs_value_is_file = 5,
};
struct fscrypt_hkdf {
	struct crypto_shash *hmac_tfm;
};
struct fscrypt_key_specifier {
	__u32 type;
	__u32 __reserved;
	union {
		__u8 __reserved[32];
		__u8 descriptor[8];
		__u8 identifier[16];
	} u;
};
struct fscrypt_mode {
	const char *friendly_name;
	const char *cipher_str;
	int keysize;
	int security_strength;
	int ivsize;
	int logged_cryptoapi_impl;
	int logged_blk_crypto_native;
	int logged_blk_crypto_fallback;
	enum blk_crypto_mode_num blk_crypto_mode;
};
struct fscrypt_policy_v1 {
	__u8 version;
	__u8 contents_encryption_mode;
	__u8 filenames_encryption_mode;
	__u8 flags;
	__u8 master_key_descriptor[8];
};
struct fscrypt_policy_v2 {
	__u8 version;
	__u8 contents_encryption_mode;
	__u8 filenames_encryption_mode;
	__u8 flags;
	__u8 log2_data_unit_size;
	__u8 __reserved[3];
	__u8 master_key_identifier[16];
};
struct fscrypt_prepared_key {
	struct crypto_skcipher *tfm;
	struct blk_crypto_key *blk_key;
};
typedef struct fsnotify_mark_connector *fsnotify_connp_t;
typedef void (*ftrace_func_t)(long unsigned int, long unsigned int, struct ftrace_ops *, struct ftrace_regs *);
struct ftrace_hash {
	long unsigned int size_bits;
	struct hlist_head *buckets;
	long unsigned int count;
	long unsigned int flags;
	struct callback_head rcu;
};
enum ftrace_ops_cmd {
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_SELF = 0,
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_PEER = 1,
	FTRACE_OPS_CMD_DISABLE_SHARE_IPMODIFY_PEER = 2,
};
typedef int (*ftrace_ops_func_t)(struct ftrace_ops *, enum ftrace_ops_cmd);
struct ftrace_ret_stack {
	long unsigned int ret;
	long unsigned int func;
	long long unsigned int calltime;
	long long unsigned int subtime;
	long unsigned int *retp;
};
struct fwnode_endpoint {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle *local_fwnode;
};
typedef unsigned int gfp_t;
typedef __kernel_gid32_t gid_t;
enum hash_algo {
	HASH_ALGO_MD4 = 0,
	HASH_ALGO_MD5 = 1,
	HASH_ALGO_SHA1 = 2,
	HASH_ALGO_RIPE_MD_160 = 3,
	HASH_ALGO_SHA256 = 4,
	HASH_ALGO_SHA384 = 5,
	HASH_ALGO_SHA512 = 6,
	HASH_ALGO_SHA224 = 7,
	HASH_ALGO_RIPE_MD_128 = 8,
	HASH_ALGO_RIPE_MD_256 = 9,
	HASH_ALGO_RIPE_MD_320 = 10,
	HASH_ALGO_WP_256 = 11,
	HASH_ALGO_WP_384 = 12,
	HASH_ALGO_WP_512 = 13,
	HASH_ALGO_TGR_128 = 14,
	HASH_ALGO_TGR_160 = 15,
	HASH_ALGO_TGR_192 = 16,
	HASH_ALGO_SM3_256 = 17,
	HASH_ALGO_STREEBOG_256 = 18,
	HASH_ALGO_STREEBOG_512 = 19,
	HASH_ALGO_SHA3_256 = 20,
	HASH_ALGO_SHA3_384 = 21,
	HASH_ALGO_SHA3_512 = 22,
	HASH_ALGO__LAST = 23,
};
struct fsverity_hash_alg {
	struct crypto_shash *tfm;
	const char *name;
	unsigned int digest_size;
	unsigned int block_size;
	enum hash_algo algo_id;
};
struct hd_geometry {
	unsigned char heads;
	unsigned char sectors;
	short unsigned int cylinders;
	long unsigned int start;
};
struct hlist_bl_head {
	struct hlist_bl_node *first;
};
struct hlist_bl_node {
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};
struct hlist_head {
	struct hlist_node *first;
};
struct ctl_table_header {
	union {
		struct {
			struct ctl_table *ctl_table;
			int ctl_table_size;
			int used;
			int count;
			int nreg;
		};
		struct callback_head rcu;
	};
	struct completion *unregistering;
	struct ctl_table *ctl_table_arg;
	struct ctl_table_root *root;
	struct ctl_table_set *set;
	struct ctl_dir *parent;
	struct ctl_node *node;
	struct hlist_head inodes;
};
struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};
struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};
struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};
enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};
struct icmp_mib {
	long unsigned int mibs[30];
};
struct icmpv6_mib {
	long unsigned int mibs[7];
};
struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};
struct in_addr {
	__be32 s_addr;
};
struct inet_ehash_bucket {
	struct hlist_nulls_head chain;
};
typedef void integrity_complete_fn(struct request *, unsigned int);
typedef void integrity_prepare_fn(struct request *);
struct io_cmd_data {
	struct file *file;
	__u8 data[56];
};
struct io_comp_batch {
	struct request *req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};
struct io_cqe {
	__u64 user_data;
	__s32 res;
	union {
		__u32 flags;
		int fd;
	};
};
struct io_ev_fd {
	struct eventfd_ctx *cq_ev_fd;
	unsigned int eventfd_async: 1;
	struct callback_head rcu;
	atomic_t refs;
	atomic_t ops;
};
struct io_file_table {
	struct io_fixed_file *files;
	long unsigned int *bitmap;
	unsigned int alloc_hint;
};
struct io_fixed_file {
	long unsigned int file_ptr;
};
struct io_hash_table {
	struct io_hash_bucket *hbs;
	unsigned int hash_bits;
};
typedef void (*io_req_tw_func_t)(struct io_kiocb *, struct io_tw_state *);
struct io_submit_link {
	struct io_kiocb *head;
	struct io_kiocb *last;
};
struct io_tw_state {
	bool locked;
};
struct io_uring_buf {
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 resv;
};
struct io_uring_buf_ring {
	union {
		struct {
			__u64 resv1;
			__u32 resv2;
			__u16 resv3;
			__u16 tail;
		};
		struct {
			struct {} __empty_bufs;
			struct io_uring_buf bufs[0];
		};
	};
};
struct io_uring_cqe {
	__u64 user_data;
	__s32 res;
	__u32 flags;
	__u64 big_cqe[0];
};
struct io_uring_sqe {
	__u8 opcode;
	__u8 flags;
	__u16 ioprio;
	__s32 fd;
	union {
		__u64 off;
		__u64 addr2;
		struct {
			__u32 cmd_op;
			__u32 __pad1;
		};
	};
	union {
		__u64 addr;
		__u64 splice_off_in;
		struct {
			__u32 level;
			__u32 optname;
		};
	};
	__u32 len;
	union {
		__kernel_rwf_t rw_flags;
		__u32 fsync_flags;
		__u16 poll_events;
		__u32 poll32_events;
		__u32 sync_range_flags;
		__u32 msg_flags;
		__u32 timeout_flags;
		__u32 accept_flags;
		__u32 cancel_flags;
		__u32 open_flags;
		__u32 statx_flags;
		__u32 fadvise_advice;
		__u32 splice_flags;
		__u32 rename_flags;
		__u32 unlink_flags;
		__u32 hardlink_flags;
		__u32 xattr_flags;
		__u32 msg_ring_flags;
		__u32 uring_cmd_flags;
		__u32 waitid_flags;
		__u32 futex_flags;
		__u32 install_fd_flags;
	};
	__u64 user_data;
	union {
		__u16 buf_index;
		__u16 buf_group;
	};
	__u16 personality;
	union {
		__s32 splice_fd_in;
		__u32 file_index;
		__u32 optlen;
		struct {
			__u16 addr_len;
			__u16 __pad3[1];
		};
	};
	union {
		struct {
			__u64 addr3;
			__u64 __pad2[1];
		};
		__u64 optval;
		__u8 cmd[0];
	};
};
typedef void io_wq_work_fn(struct io_wq_work *);
struct io_wq_work_list {
	struct io_wq_work_node *first;
	struct io_wq_work_node *last;
};
struct io_wq_work_node {
	struct io_wq_work_node *next;
};
struct io_cache_entry {
	struct io_wq_work_node node;
};
struct io_wq_work {
	struct io_wq_work_node list;
	unsigned int flags;
	int cancel_seq;
};
typedef unsigned int ioasid_t;
enum iommu_cap {
	IOMMU_CAP_CACHE_COHERENCY = 0,
	IOMMU_CAP_NOEXEC = 1,
	IOMMU_CAP_PRE_BOOT_PROTECTION = 2,
	IOMMU_CAP_ENFORCE_CACHE_COHERENCY = 3,
	IOMMU_CAP_DEFERRED_FLUSH = 4,
	IOMMU_CAP_DIRTY_TRACKING = 5,
};
typedef int (*iommu_dev_fault_handler_t)(struct iommu_fault *, void *);
enum iommu_dev_features {
	IOMMU_DEV_FEAT_SVA = 0,
	IOMMU_DEV_FEAT_IOPF = 1,
};
struct iommu_dirty_bitmap {
	struct iova_bitmap *bitmap;
	struct iommu_iotlb_gather *gather;
};
enum iommu_dma_cookie_type {
	IOMMU_DMA_IOVA_COOKIE = 0,
	IOMMU_DMA_MSI_COOKIE = 1,
};
enum iommu_dma_queue_type {
	IOMMU_DMA_OPTS_PER_CPU_QUEUE = 0,
	IOMMU_DMA_OPTS_SINGLE_QUEUE = 1,
};
typedef int (*iommu_fault_handler_t)(struct iommu_domain *, struct device *, long unsigned int, int, void *);
struct iommu_fault_page_request {
	__u32 flags;
	__u32 pasid;
	__u32 grpid;
	__u32 perm;
	__u64 addr;
	__u64 private_data[2];
};
struct iommu_fault_unrecoverable {
	__u32 reason;
	__u32 flags;
	__u32 pasid;
	__u32 perm;
	__u64 addr;
	__u64 fetch_addr;
};
struct iommu_fault {
	__u32 type;
	__u32 padding;
	union {
		struct iommu_fault_unrecoverable event;
		struct iommu_fault_page_request prm;
		__u8 padding2[56];
	};
};
struct iommu_page_response {
	__u32 argsz;
	__u32 version;
	__u32 flags;
	__u32 pasid;
	__u32 grpid;
	__u32 code;
};
enum iommu_page_response_code {
	IOMMU_PAGE_RESP_SUCCESS = 0,
	IOMMU_PAGE_RESP_INVALID = 1,
	IOMMU_PAGE_RESP_FAILURE = 2,
};
struct iova_bitmap_map {
	long unsigned int iova;
	long unsigned int pgshift;
	long unsigned int pgoff;
	long unsigned int npages;
	struct page **pages;
};
struct iova_magazine {
	union {
		long unsigned int size;
		struct iova_magazine *next;
	};
	long unsigned int pfns[127];
};
struct iovec {
	void *iov_base;
	__kernel_size_t iov_len;
};
struct ip6_sf_list {
	struct ip6_sf_list *sf_next;
	struct in6_addr sf_addr;
	long unsigned int sf_count[2];
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
	struct callback_head rcu;
};
enum ip_conntrack_dir {
	IP_CT_DIR_ORIGINAL = 0,
	IP_CT_DIR_REPLY = 1,
	IP_CT_DIR_MAX = 2,
};
struct ip_conntrack_stat {
	unsigned int found;
	unsigned int invalid;
	unsigned int insert;
	unsigned int insert_failed;
	unsigned int clash_resolve;
	unsigned int drop;
	unsigned int early_drop;
	unsigned int error;
	unsigned int expect_new;
	unsigned int expect_create;
	unsigned int expect_delete;
	unsigned int search_restart;
	unsigned int chaintoolong;
};
struct ip_ra_chain {
	struct ip_ra_chain *next;
	struct sock *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};
struct ipv4_devconf {
	void *sysctl;
	int data[33];
	long unsigned int state[1];
};
struct ipv6_devstat {
	struct proc_dir_entry *proc_dir_entry;
	struct ipstats_mib *ipv6;
	struct icmpv6_mib_device *icmpv6dev;
	struct icmpv6msg_mib_device *icmpv6msgdev;
};
struct ipv6_stable_secret {
	bool initialized;
	struct in6_addr secret;
};
struct ipv6_devconf {
	__s32 forwarding;
	__s32 hop_limit;
	__s32 mtu6;
	__s32 accept_ra;
	__s32 accept_redirects;
	__s32 autoconf;
	__s32 dad_transmits;
	__s32 rtr_solicits;
	__s32 rtr_solicit_interval;
	__s32 rtr_solicit_max_interval;
	__s32 rtr_solicit_delay;
	__s32 force_mld_version;
	__s32 mldv1_unsolicited_report_interval;
	__s32 mldv2_unsolicited_report_interval;
	__s32 use_tempaddr;
	__s32 temp_valid_lft;
	__s32 temp_prefered_lft;
	__s32 regen_max_retry;
	__s32 max_desync_factor;
	__s32 max_addresses;
	__s32 accept_ra_defrtr;
	__u32 ra_defrtr_metric;
	__s32 accept_ra_min_hop_limit;
	__s32 accept_ra_min_lft;
	__s32 accept_ra_pinfo;
	__s32 ignore_routes_with_linkdown;
	__s32 accept_ra_rtr_pref;
	__s32 rtr_probe_interval;
	__s32 accept_ra_rt_info_min_plen;
	__s32 accept_ra_rt_info_max_plen;
	__s32 proxy_ndp;
	__s32 accept_source_route;
	__s32 accept_ra_from_local;
	atomic_t mc_forwarding;
	__s32 disable_ipv6;
	__s32 drop_unicast_in_l2_multicast;
	__s32 accept_dad;
	__s32 force_tllao;
	__s32 ndisc_notify;
	__s32 suppress_frag_ndisc;
	__s32 accept_ra_mtu;
	__s32 drop_unsolicited_na;
	__s32 accept_untracked_na;
	struct ipv6_stable_secret stable_secret;
	__s32 use_oif_addrs_only;
	__s32 keep_addr_on_down;
	__s32 seg6_enabled;
	__s32 seg6_require_hmac;
	__u32 enhanced_dad;
	__u32 addr_gen_mode;
	__s32 disable_policy;
	__s32 ndisc_tclass;
	__s32 rpl_seg_enabled;
	__u32 ioam6_id;
	__u32 ioam6_id_wide;
	__u8 ioam6_enabled;
	__u8 ndisc_evict_nocarrier;
	__u8 ra_honor_pio_life;
	struct ctl_table_header *sysctl_header;
};
struct irq_affinity_desc {
	struct cpumask mask;
	unsigned int is_managed: 1;
};
enum irq_alloc_type {
	X86_IRQ_ALLOC_TYPE_IOAPIC = 1,
	X86_IRQ_ALLOC_TYPE_HPET = 2,
	X86_IRQ_ALLOC_TYPE_PCI_MSI = 3,
	X86_IRQ_ALLOC_TYPE_PCI_MSIX = 4,
	X86_IRQ_ALLOC_TYPE_DMAR = 5,
	X86_IRQ_ALLOC_TYPE_AMDVI = 6,
	X86_IRQ_ALLOC_TYPE_UV = 7,
};
struct irq_chip_regs {
	long unsigned int enable;
	long unsigned int disable;
	long unsigned int mask;
	long unsigned int ack;
	long unsigned int eoi;
	long unsigned int type;
	long unsigned int polarity;
};
struct irq_common_data {
	unsigned int state_use_accessors;
	unsigned int node;
	void *handler_data;
	struct msi_desc *msi_desc;
	cpumask_var_t affinity;
	cpumask_var_t effective_affinity;
};
enum irq_domain_bus_token {
	DOMAIN_BUS_ANY = 0,
	DOMAIN_BUS_WIRED = 1,
	DOMAIN_BUS_GENERIC_MSI = 2,
	DOMAIN_BUS_PCI_MSI = 3,
	DOMAIN_BUS_PLATFORM_MSI = 4,
	DOMAIN_BUS_NEXUS = 5,
	DOMAIN_BUS_IPI = 6,
	DOMAIN_BUS_FSL_MC_MSI = 7,
	DOMAIN_BUS_TI_SCI_INTA_MSI = 8,
	DOMAIN_BUS_WAKEUP = 9,
	DOMAIN_BUS_VMD_MSI = 10,
	DOMAIN_BUS_PCI_DEVICE_MSI = 11,
	DOMAIN_BUS_PCI_DEVICE_MSIX = 12,
	DOMAIN_BUS_DMAR = 13,
	DOMAIN_BUS_AMDVI = 14,
	DOMAIN_BUS_PCI_DEVICE_IMS = 15,
};
typedef void (*irq_flow_handler_t)(struct irq_desc *);
enum irq_gc_flags {
	IRQ_GC_INIT_MASK_CACHE = 1,
	IRQ_GC_INIT_NESTED_LOCK = 2,
	IRQ_GC_MASK_CACHE_PER_TYPE = 4,
	IRQ_GC_NO_MASK = 8,
	IRQ_GC_BE_IO = 16,
};
struct irq_domain_chip_generic {
	unsigned int irqs_per_chip;
	unsigned int num_chips;
	unsigned int irq_flags_to_clear;
	unsigned int irq_flags_to_set;
	enum irq_gc_flags gc_flags;
	struct irq_chip_generic *gc[0];
};
typedef long unsigned int irq_hw_number_t;
typedef void (*irq_write_msi_msg_t)(struct msi_desc *, struct msi_msg *);
enum irqchip_irq_state {
	IRQCHIP_STATE_PENDING = 0,
	IRQCHIP_STATE_ACTIVE = 1,
	IRQCHIP_STATE_MASKED = 2,
	IRQCHIP_STATE_LINE_LEVEL = 3,
};
struct irq_chip {
	const char *name;
	unsigned int (*irq_startup)(struct irq_data *);
	void (*irq_shutdown)(struct irq_data *);
	void (*irq_enable)(struct irq_data *);
	void (*irq_disable)(struct irq_data *);
	void (*irq_ack)(struct irq_data *);
	void (*irq_mask)(struct irq_data *);
	void (*irq_mask_ack)(struct irq_data *);
	void (*irq_unmask)(struct irq_data *);
	void (*irq_eoi)(struct irq_data *);
	int (*irq_set_affinity)(struct irq_data *, const struct cpumask *, bool);
	int (*irq_retrigger)(struct irq_data *);
	int (*irq_set_type)(struct irq_data *, unsigned int);
	int (*irq_set_wake)(struct irq_data *, unsigned int);
	void (*irq_bus_lock)(struct irq_data *);
	void (*irq_bus_sync_unlock)(struct irq_data *);
	void (*irq_suspend)(struct irq_data *);
	void (*irq_resume)(struct irq_data *);
	void (*irq_pm_shutdown)(struct irq_data *);
	void (*irq_calc_mask)(struct irq_data *);
	void (*irq_print_chip)(struct irq_data *, struct seq_file *);
	int (*irq_request_resources)(struct irq_data *);
	void (*irq_release_resources)(struct irq_data *);
	void (*irq_compose_msi_msg)(struct irq_data *, struct msi_msg *);
	void (*irq_write_msi_msg)(struct irq_data *, struct msi_msg *);
	int (*irq_get_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool *);
	int (*irq_set_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool);
	int (*irq_set_vcpu_affinity)(struct irq_data *, void *);
	void (*ipi_send_single)(struct irq_data *, unsigned int);
	void (*ipi_send_mask)(struct irq_data *, const struct cpumask *);
	int (*irq_nmi_setup)(struct irq_data *);
	void (*irq_nmi_teardown)(struct irq_data *);
	long unsigned int flags;
};
enum irqreturn {
	IRQ_NONE = 0,
	IRQ_HANDLED = 1,
	IRQ_WAKE_THREAD = 2,
};
typedef enum irqreturn irqreturn_t;
typedef irqreturn_t (*irq_handler_t)(int, void *);
struct irqaction {
	irq_handler_t handler;
	void *dev_id;
	void *percpu_dev_id;
	struct irqaction *next;
	irq_handler_t thread_fn;
	struct task_struct *thread;
	struct irqaction *secondary;
	unsigned int irq;
	unsigned int flags;
	long unsigned int thread_flags;
	long unsigned int thread_mask;
	const char *name;
	struct proc_dir_entry *dir;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
};
enum kernel_pkey_operation {
	kernel_pkey_encrypt = 0,
	kernel_pkey_decrypt = 1,
	kernel_pkey_sign = 2,
	kernel_pkey_verify = 3,
};
struct kernel_pkey_params {
	struct key *key;
	const char *encoding;
	const char *hash_algo;
	char *info;
	__u32 in_len;
	union {
		__u32 out_len;
		__u32 in2_len;
	};
	enum kernel_pkey_operation op: 8;
};
struct kernel_pkey_query {
	__u32 supported_ops;
	__u32 key_size;
	__u16 max_data_size;
	__u16 max_sig_size;
	__u16 max_enc_size;
	__u16 max_dec_size;
};
struct kernel_symbol {
	int value_offset;
	int name_offset;
	int namespace_offset;
};
typedef long unsigned int kernel_ulong_t;
struct acpi_device_id {
	__u8 id[16];
	kernel_ulong_t driver_data;
	__u32 cls;
	__u32 cls_msk;
};
struct kernfs_elem_symlink {
	struct kernfs_node *target_kn;
};
struct key_match_data {
	bool (*cmp)(const struct key *, const struct key_match_data *);
	const void *raw_data;
	void *preparsed;
	unsigned int lookup_type;
};
union key_payload {
	void *rcu_data0;
	void *data[4];
};
typedef int (*key_restrict_link_func_t)(struct key *, const struct key_type *, const union key_payload *, struct key *);
struct key_restriction {
	key_restrict_link_func_t check;
	struct key *key;
	struct key_type *keytype;
};
typedef struct {
	gid_t val;
} kgid_t;
struct kioctx_cpu {
	unsigned int reqs_available;
};
struct kioctx_table {
	struct callback_head rcu;
	unsigned int nr;
	struct kioctx *table[0];
};
struct klp_modinfo {
	Elf64_Ehdr hdr;
	Elf64_Shdr *sechdrs;
	char *secstrings;
	unsigned int symndx;
};
struct kmap_ctrl {};
struct kmem_cache_order_objects {
	unsigned int x;
};
enum kobj_ns_type {
	KOBJ_NS_TYPE_NONE = 0,
	KOBJ_NS_TYPE_NET = 1,
	KOBJ_NS_TYPES = 2,
};
struct kobj_ns_type_operations {
	enum kobj_ns_type type;
	bool (*current_may_mount)(void);
	void * (*grab_current_ns)(void);
	const void * (*netlink_ns)(struct sock *);
	const void * (*initial_ns)(void);
	void (*drop_ns)(void *);
};
struct kobj_uevent_env {
	char *argv[3];
	char *envp[64];
	int envp_idx;
	char buf[2048];
	int buflen;
};
struct kparam_array {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};
struct kparam_string {
	unsigned int maxlen;
	char *string;
};
struct kset_uevent_ops {
	int (* const filter)(const struct kobject *);
	const char * (* const name)(const struct kobject *);
	int (* const uevent)(const struct kobject *, struct kobj_uevent_env *);
};
typedef void (*kthread_work_func_t)(struct kthread_work *);
struct latency_bucket {
	long unsigned int total_latency;
	int samples;
};
struct latency_record {
	long unsigned int backtrace[12];
	unsigned int count;
	long unsigned int time;
	long unsigned int max;
};
struct ldt_struct {
	struct desc_struct *entries;
	unsigned int nr_entries;
	int slot;
};
struct linux_mib {
	long unsigned int mibs[132];
};
struct linux_tls_mib {
	long unsigned int mibs[13];
};
struct linux_xfrm_mib {
	long unsigned int mibs[29];
};
struct list_head {
	struct list_head *next;
	struct list_head *prev;
};
struct aa_policy {
	const char *name;
	char *hname;
	struct list_head list;
	struct list_head profiles;
};
struct blk_crypto_keyslot {
	atomic_t slot_refs;
	struct list_head idle_slot_node;
	struct hlist_node hash_node;
	const struct blk_crypto_key *key;
	struct blk_crypto_profile *profile;
};
struct blk_plug {
	struct request *mq_list;
	struct request *cached_rq;
	short unsigned int nr_ios;
	short unsigned int rq_count;
	bool multiple_queues;
	bool has_elevator;
	struct list_head cb_list;
};
struct bpf_offload_dev {
	const struct bpf_prog_offload_ops *ops;
	struct list_head netdevs;
	void *priv;
};
struct cdrom_device_info {
	const struct cdrom_device_ops *ops;
	struct list_head list;
	struct gendisk *disk;
	void *handle;
	int mask;
	int speed;
	int capacity;
	unsigned int options: 30;
	unsigned int mc_flags: 2;
	unsigned int vfs_events;
	unsigned int ioctl_events;
	int use_count;
	char name[20];
	__u8 sanyo_slot: 2;
	__u8 keeplocked: 1;
	__u8 reserved: 5;
	int cdda_method;
	__u8 last_sense;
	__u8 media_written;
	short unsigned int mmc3_profile;
	int (*exit)(struct cdrom_device_info *);
	int mrw_mode_page;
	bool opened_for_data;
	__s64 last_media_change_ms;
};
struct cgroup_taskset {
	struct list_head src_csets;
	struct list_head dst_csets;
	int nr_tasks;
	int ssid;
	struct list_head *csets;
	struct css_set *cur_cset;
	struct task_struct *cur_task;
};
struct cpu_stop_work {
	struct list_head list;
	cpu_stop_fn_t fn;
	long unsigned int caller;
	void *arg;
	struct cpu_stop_done *done;
};
struct crypto_template {
	struct list_head list;
	struct hlist_head instances;
	struct module *module;
	int (*create)(struct crypto_template *, struct rtattr **);
	char name[128];
};
struct ddebug_class_map {
	struct list_head link;
	struct module *mod;
	const char *mod_name;
	const char **class_names;
	const int length;
	const int base;
	enum class_map_type map_type;
};
struct dev_links_info {
	struct list_head suppliers;
	struct list_head consumers;
	struct list_head defer_sync;
	enum dl_dev_state status;
};
struct event_subsystem {
	struct list_head list;
	const char *name;
	struct event_filter *filter;
	int ref_count;
};
struct fib_notifier_ops {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net *);
	int (*fib_dump)(struct net *, struct notifier_block *, struct netlink_ext_ack *);
	struct module *owner;
	struct callback_head rcu;
};
struct free_area {
	struct list_head free_list[5];
	long unsigned int nr_free;
};
struct ftrace_event_field {
	struct list_head link;
	const char *name;
	const char *type;
	int filter_type;
	int offset;
	int size;
	unsigned int is_signed: 1;
	unsigned int needs_test: 1;
	int len;
};
struct gro_list {
	struct list_head list;
	int count;
};
struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};
struct io_buffer_list {
	union {
		struct list_head buf_list;
		struct {
			struct page **buf_pages;
			struct io_uring_buf_ring *buf_ring;
		};
		struct callback_head rcu;
	};
	__u16 bgid;
	__u16 buf_nr_pages;
	__u16 nr_entries;
	__u16 head;
	__u16 mask;
	atomic_t refs;
	__u8 is_mapped;
	__u8 is_mmap;
};
struct io_cq {
	struct request_queue *q;
	struct io_context *ioc;
	union {
		struct list_head q_node;
		struct kmem_cache *__rcu_icq_cache;
	};
	union {
		struct hlist_node ioc_node;
		struct callback_head __rcu_head;
	};
	unsigned int flags;
};
struct io_submit_state {
	struct io_wq_work_node free_list;
	struct io_wq_work_list compl_reqs;
	struct io_submit_link link;
	bool plug_started;
	bool need_plug;
	short unsigned int submit_nr;
	unsigned int cqes_count;
	struct blk_plug plug;
};
struct iommu_fault_event {
	struct iommu_fault fault;
	struct list_head list;
};
struct iopf_device_param {
	struct device *dev;
	struct iopf_queue *queue;
	struct list_head queue_list;
	struct list_head partial;
};
struct kthread_work {
	struct list_head node;
	kthread_work_func_t func;
	struct kthread_worker *worker;
	int canceling;
};
struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *);
	int (*load_shlib)(struct file *);
	int (*core_dump)(struct coredump_params *);
	long unsigned int min_coredump;
};
struct list_lru_one {
	struct list_head list;
	long int nr_items;
};
struct llist_head {
	struct llist_node *first;
};
struct llist_node {
	struct llist_node *next;
};
struct io_task_work {
	struct llist_node node;
	io_req_tw_func_t func;
};
typedef struct {} local_lock_t;
struct lock_class_key {};
struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry * (*mount)(struct file_system_type *, int, const char *, void *);
	void (*kill_sb)(struct super_block *);
	struct module *owner;
	struct file_system_type *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};
struct lock_manager_operations {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock *);
	int (*lm_grant)(struct file_lock *, int);
	bool (*lm_break)(struct file_lock *);
	int (*lm_change)(struct file_lock *, int, struct list_head *);
	void (*lm_setup)(struct file_lock *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock *);
	bool (*lm_lock_expirable)(struct file_lock *);
	void (*lm_expire_lock)(void);
};
struct lockdep_map {};
typedef struct {} lockdep_map_p;
typedef __kernel_loff_t loff_t;
struct file_ra_state {
	long unsigned int start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};
struct iomap_folio_ops {
	struct folio * (*get_folio)(struct iomap_iter *, loff_t, unsigned int);
	void (*put_folio)(struct inode *, loff_t, unsigned int, struct folio *);
	bool (*iomap_valid)(struct inode *, const struct iomap *);
};
struct kernfs_elem_attr {
	const struct kernfs_ops *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node *notify_next;
};
union lower_chunk {
	union lower_chunk *next;
	long unsigned int data[256];
};
struct lru_gen_mm_state {
	long unsigned int seq;
	struct list_head *head;
	struct list_head *tail;
	long unsigned int *filters[2];
	long unsigned int stats[4];
};
struct lru_gen_mm_walk {
	struct lruvec *lruvec;
	long unsigned int max_seq;
	long unsigned int next_addr;
	int nr_pages[40];
	int mm_stats[4];
	int batched;
	bool can_swap;
	bool force_scan;
};
struct lruvec_stats {
	long int state[46];
	long int state_local[46];
	long int state_pending[46];
};
struct lruvec_stats_percpu {
	long int state[46];
	long int state_prev[46];
};
struct lsmblob_apparmor {
	struct aa_label *label;
};
struct lsmblob_smack {
	struct smack_known *skp;
};
struct lwtunnel_state {
	__u16 type;
	__u16 flags;
	__u16 headroom;
	atomic_t refcnt;
	int (*orig_output)(struct net *, struct sock *, struct sk_buff *);
	int (*orig_input)(struct sk_buff *);
	struct callback_head rcu;
	__u8 data[0];
};
struct math_emu_info {
	long int ___orig_eip;
	struct pt_regs *regs;
};
struct mem_cgroup_reclaim_iter {
	struct mem_cgroup *position;
	unsigned int generation;
};
struct mem_cgroup_threshold {
	struct eventfd_ctx *eventfd;
	long unsigned int threshold;
};
struct mem_cgroup_threshold_ary {
	int current_threshold;
	unsigned int size;
	struct mem_cgroup_threshold entries[0];
};
struct mem_cgroup_thresholds {
	struct mem_cgroup_threshold_ary *primary;
	struct mem_cgroup_threshold_ary *spare;
};
struct memcg_vmstats_percpu {
	unsigned int stats_updates;
	struct memcg_vmstats_percpu *parent;
	struct memcg_vmstats *vmstats;
	long int state[53];
	long unsigned int events[22];
	long int state_prev[53];
	long unsigned int events_prev[22];
	long unsigned int nr_page_events;
	long unsigned int targets[2];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct memory_failure_stats {
	long unsigned int total;
	long unsigned int ignored;
	long unsigned int failed;
	long unsigned int delayed;
	long unsigned int recovered;
};
enum memory_type {
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_COHERENT = 2,
	MEMORY_DEVICE_FS_DAX = 3,
	MEMORY_DEVICE_GENERIC = 4,
	MEMORY_DEVICE_PCI_P2PDMA = 5,
};
typedef void *mempool_alloc_t(gfp_t, void *);
typedef void mempool_free_t(void *, void *);
enum migrate_mode {
	MIGRATE_ASYNC = 0,
	MIGRATE_SYNC_LIGHT = 1,
	MIGRATE_SYNC = 2,
	MIGRATE_SYNC_NO_COPY = 3,
};
struct compact_control {
	struct list_head freepages;
	struct list_head migratepages;
	unsigned int nr_freepages;
	unsigned int nr_migratepages;
	long unsigned int free_pfn;
	long unsigned int migrate_pfn;
	long unsigned int fast_start_pfn;
	struct zone *zone;
	long unsigned int total_migrate_scanned;
	long unsigned int total_free_scanned;
	short unsigned int fast_search_fail;
	short int search_order;
	const gfp_t gfp_mask;
	int order;
	int migratetype;
	const unsigned int alloc_flags;
	const int highest_zoneidx;
	enum migrate_mode mode;
	bool ignore_skip_hint;
	bool no_set_skip_hint;
	bool ignore_block_suitable;
	bool direct_compaction;
	bool proactive_compaction;
	bool whole_zone;
	bool contended;
	bool finish_pageblock;
	bool alloc_contig;
};
struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};
struct mod_arch_specific {};
struct mod_kallsyms {
	Elf64_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};
enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
};
struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};
struct mpls_route;
struct mptcp_mib {
	long unsigned int mibs[64];
};
enum mq_rq_state {
	MQ_RQ_IDLE = 0,
	MQ_RQ_IN_FLIGHT = 1,
	MQ_RQ_COMPLETE = 2,
};
struct mtd_info;
struct neigh_hash_table {
	struct neighbour **hash_buckets;
	unsigned int hash_shift;
	__u32 hash_rnd[4];
	struct callback_head rcu;
};
struct neigh_ops {
	int family;
	void (*solicit)(struct neighbour *, struct sk_buff *);
	void (*error_report)(struct neighbour *, struct sk_buff *);
	int (*output)(struct neighbour *, struct sk_buff *);
	int (*connected_output)(struct neighbour *, struct sk_buff *);
};
struct neigh_statistics {
	long unsigned int allocs;
	long unsigned int destroys;
	long unsigned int hash_grows;
	long unsigned int res_failed;
	long unsigned int lookups;
	long unsigned int hits;
	long unsigned int rcv_probes_mcast;
	long unsigned int rcv_probes_ucast;
	long unsigned int periodic_gc_runs;
	long unsigned int forced_gc_runs;
	long unsigned int unres_discards;
	long unsigned int table_fulls;
};
struct net_generic {
	union {
		struct {
			unsigned int len;
			struct callback_head rcu;
		} s;
		struct {
			struct {} __empty_ptr;
			void *ptr[0];
		};
	};
};
typedef struct {} netdevice_tracker;
struct netns_bpf {
	struct bpf_prog_array *run_array[2];
	struct bpf_prog *progs[2];
	struct list_head links[2];
};
struct netns_ft {
	struct nf_flow_table_stat *stat;
};
struct netns_ipvs;
struct netns_mib {
	struct ipstats_mib *ip_statistics;
	struct ipstats_mib *ipv6_statistics;
	struct tcp_mib *tcp_statistics;
	struct linux_mib *net_statistics;
	struct udp_mib *udp_statistics;
	struct udp_mib *udp_stats_in6;
	struct linux_xfrm_mib *xfrm_statistics;
	struct linux_tls_mib *tls_statistics;
	struct mptcp_mib *mptcp_statistics;
	struct udp_mib *udplite_statistics;
	struct udp_mib *udplite_stats_in6;
	struct icmp_mib *icmp_statistics;
	struct icmpmsg_mib *icmpmsg_statistics;
	struct icmpv6_mib *icmpv6_statistics;
	struct icmpv6msg_mib *icmpv6msg_statistics;
	struct proc_dir_entry *proc_net_devsnmp6;
};
struct netns_nf {
	struct proc_dir_entry *proc_netfilter;
	const struct nf_logger *nf_loggers[11];
	struct ctl_table_header *nf_log_dir_header;
	struct ctl_table_header *nf_lwtnl_dir_header;
	struct nf_hook_entries *hooks_ipv4[5];
	struct nf_hook_entries *hooks_ipv6[5];
	struct nf_hook_entries *hooks_arp[3];
	struct nf_hook_entries *hooks_bridge[5];
	unsigned int defrag_ipv4_users;
	unsigned int defrag_ipv6_users;
};
struct netns_sysctl_lowpan {
	struct ctl_table_header *frags_hdr;
};
struct netns_ieee802154_lowpan {
	struct netns_sysctl_lowpan sysctl;
	struct fqdir *fqdir;
};
typedef struct {} netns_tracker;
struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};
struct nf_conntrack_helper;
union nf_conntrack_man_proto {
	__be16 all;
	struct {
		__be16 port;
	} tcp;
	struct {
		__be16 port;
	} udp;
	struct {
		__be16 id;
	} icmp;
	struct {
		__be16 port;
	} dccp;
	struct {
		__be16 port;
	} sctp;
	struct {
		__be16 key;
	} gre;
};
struct nf_ct_event_notifier {
	int (*ct_event)(unsigned int, const struct nf_ct_event *);
	int (*exp_event)(unsigned int, const struct nf_exp_event *);
};
struct nf_ct_gre {
	unsigned int stream_timeout;
	unsigned int timeout;
};
struct nf_ct_udp {
	long unsigned int stream_ts;
};
struct nf_flow_table_stat {
	unsigned int count_wq_add;
	unsigned int count_wq_del;
	unsigned int count_wq_stats;
};
struct nf_generic_net {
	unsigned int timeout;
};
struct nf_gre_net {
	struct list_head keymap_list;
	unsigned int timeouts[2];
};
typedef unsigned int nf_hookfn(void *, struct sk_buff *, const struct nf_hook_state *);
struct nf_hook_entry {
	nf_hookfn *hook;
	void *priv;
};
struct nf_icmp_net {
	unsigned int timeout;
};
union nf_inet_addr {
	__u32 all[4];
	__be32 ip;
	__be32 ip6[4];
	struct in_addr in;
	struct in6_addr in6;
};
struct nf_conntrack_tuple_mask {
	struct {
		union nf_inet_addr u3;
		union nf_conntrack_man_proto u;
	} src;
};
enum nf_log_type {
	NF_LOG_TYPE_LOG = 0,
	NF_LOG_TYPE_ULOG = 1,
	NF_LOG_TYPE_MAX = 2,
};
struct nf_sctp_net {
	unsigned int timeouts[10];
};
struct nf_udp_net {
	unsigned int timeouts[2];
	unsigned int offload_timeout;
};
struct nfs4_lock_info {
	struct nfs4_lock_state *owner;
};
struct nfs4_stateid_struct {
	union {
		char data[16];
		struct {
			__be32 seqid;
			char other[12];
		};
	};
	enum {
		NFS4_INVALID_STATEID_TYPE = 0,
		NFS4_SPECIAL_STATEID_TYPE = 1,
		NFS4_OPEN_STATEID_TYPE = 2,
		NFS4_LOCK_STATEID_TYPE = 3,
		NFS4_DELEGATION_STATEID_TYPE = 4,
		NFS4_LAYOUT_STATEID_TYPE = 5,
		NFS4_PNFS_DS_STATEID_TYPE = 6,
		NFS4_REVOKED_STATEID_TYPE = 7,
	} type;
};
typedef struct nfs4_stateid_struct nfs4_stateid;
struct nlattr {
	__u16 nla_len;
	__u16 nla_type;
};
struct nlm_lockowner;
typedef struct {
	long unsigned int bits[16];
} nodemask_t;
struct mempolicy {
	atomic_t refcnt;
	short unsigned int mode;
	short unsigned int flags;
	nodemask_t nodes;
	int home_node;
	union {
		nodemask_t cpuset_mems_allowed;
		nodemask_t user_nodemask;
	} w;
};
typedef int (*notifier_fn_t)(struct notifier_block *, long unsigned int, void *);
struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block *next;
	int priority;
};
struct nsset {
	unsigned int flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
};
struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
	const void *data;
};
struct optimistic_spin_queue {
	atomic_t tail;
};
struct p_log {
	const char *prefix;
	struct fc_log *log;
};
struct packet_command {
	unsigned char cmd[12];
	unsigned char *buffer;
	unsigned int buflen;
	int stat;
	struct scsi_sense_hdr *sshdr;
	unsigned char data_direction;
	int quiet;
	int timeout;
	void *reserved[1];
};
struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
};
struct page_pool_params_fast {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device *dev;
	struct napi_struct *napi;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
};
struct page_pool_params_slow {
	void *netdev;
	void (*init_callback)(struct page *, void *);
	void *init_arg;
};
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};
struct percpu_ref {
	long unsigned int percpu_count_ptr;
	struct percpu_ref_data *data;
};
struct obj_cgroup {
	struct percpu_ref refcnt;
	struct mem_cgroup *memcg;
	atomic_t nr_charged_bytes;
	union {
		struct list_head list;
		struct callback_head rcu;
	};
};
typedef void percpu_ref_func_t(struct percpu_ref *);
struct perf_addr_filter_range {
	long unsigned int start;
	long unsigned int size;
};
struct perf_branch_entry {
	__u64 from;
	__u64 to;
	__u64 mispred: 1;
	__u64 predicted: 1;
	__u64 in_tx: 1;
	__u64 abort: 1;
	__u64 cycles: 16;
	__u64 type: 4;
	__u64 spec: 2;
	__u64 new_type: 4;
	__u64 priv: 3;
	__u64 reserved: 31;
};
struct perf_branch_stack {
	__u64 nr;
	__u64 hw_idx;
	struct perf_branch_entry entries[0];
};
struct perf_callchain_entry {
	__u64 nr;
	__u64 ip[0];
};
typedef long unsigned int (*perf_copy_f)(void *, const void *, long unsigned int, long unsigned int);
struct perf_domain {
	struct em_perf_domain *em_pd;
	struct perf_domain *next;
	struct callback_head rcu;
};
struct perf_event_attr {
	__u32 type;
	__u32 size;
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 disabled: 1;
	__u64 inherit: 1;
	__u64 pinned: 1;
	__u64 exclusive: 1;
	__u64 exclude_user: 1;
	__u64 exclude_kernel: 1;
	__u64 exclude_hv: 1;
	__u64 exclude_idle: 1;
	__u64 mmap: 1;
	__u64 comm: 1;
	__u64 freq: 1;
	__u64 inherit_stat: 1;
	__u64 enable_on_exec: 1;
	__u64 task: 1;
	__u64 watermark: 1;
	__u64 precise_ip: 2;
	__u64 mmap_data: 1;
	__u64 sample_id_all: 1;
	__u64 exclude_host: 1;
	__u64 exclude_guest: 1;
	__u64 exclude_callchain_kernel: 1;
	__u64 exclude_callchain_user: 1;
	__u64 mmap2: 1;
	__u64 comm_exec: 1;
	__u64 use_clockid: 1;
	__u64 context_switch: 1;
	__u64 write_backward: 1;
	__u64 namespaces: 1;
	__u64 ksymbol: 1;
	__u64 bpf_event: 1;
	__u64 aux_output: 1;
	__u64 cgroup: 1;
	__u64 text_poke: 1;
	__u64 build_id: 1;
	__u64 inherit_thread: 1;
	__u64 remove_on_exec: 1;
	__u64 sigtrap: 1;
	__u64 __reserved_1: 26;
	union {
		__u32 wakeup_events;
		__u32 wakeup_watermark;
	};
	__u32 bp_type;
	union {
		__u64 bp_addr;
		__u64 kprobe_func;
		__u64 uprobe_path;
		__u64 config1;
	};
	union {
		__u64 bp_len;
		__u64 kprobe_addr;
		__u64 probe_offset;
		__u64 config2;
	};
	__u64 branch_sample_type;
	__u64 sample_regs_user;
	__u32 sample_stack_user;
	__s32 clockid;
	__u64 sample_regs_intr;
	__u32 aux_watermark;
	__u16 sample_max_stack;
	__u16 __reserved_2;
	__u32 aux_sample_size;
	__u32 __reserved_3;
	__u64 sig_data;
	__u64 config3;
};
struct perf_event_mmap_page {
	__u32 version;
	__u32 compat_version;
	__u32 lock;
	__u32 index;
	__s64 offset;
	__u64 time_enabled;
	__u64 time_running;
	union {
		__u64 capabilities;
		struct {
			__u64 cap_bit0: 1;
			__u64 cap_bit0_is_deprecated: 1;
			__u64 cap_user_rdpmc: 1;
			__u64 cap_user_time: 1;
			__u64 cap_user_time_zero: 1;
			__u64 cap_user_time_short: 1;
			__u64 cap_____res: 58;
		};
	};
	__u16 pmc_width;
	__u16 time_shift;
	__u32 time_mult;
	__u64 time_offset;
	__u64 time_zero;
	__u32 size;
	__u32 __reserved_1;
	__u64 time_cycles;
	__u64 time_mask;
	__u8 __reserved[928];
	__u64 data_head;
	__u64 data_tail;
	__u64 data_offset;
	__u64 data_size;
	__u64 aux_head;
	__u64 aux_tail;
	__u64 aux_offset;
	__u64 aux_size;
};
struct perf_event_pmu_context {
	struct pmu *pmu;
	struct perf_event_context *ctx;
	struct list_head pmu_ctx_entry;
	struct list_head pinned_active;
	struct list_head flexible_active;
	unsigned int embedded: 1;
	unsigned int nr_events;
	unsigned int nr_cgroups;
	atomic_t refcount;
	struct callback_head callback_head;
	void *task_ctx_data;
	int rotate_necessary;
};
enum perf_event_state {
	PERF_EVENT_STATE_DEAD = -4,
	PERF_EVENT_STATE_EXIT = -3,
	PERF_EVENT_STATE_ERROR = -2,
	PERF_EVENT_STATE_OFF = -1,
	PERF_EVENT_STATE_INACTIVE = 0,
	PERF_EVENT_STATE_ACTIVE = 1,
};
union perf_mem_data_src {
	__u64 val;
	struct {
		__u64 mem_op: 5;
		__u64 mem_lvl: 14;
		__u64 mem_snoop: 5;
		__u64 mem_lock: 2;
		__u64 mem_dtlb: 7;
		__u64 mem_lvl_num: 4;
		__u64 mem_remote: 1;
		__u64 mem_snoopx: 2;
		__u64 mem_blk: 3;
		__u64 mem_hops: 3;
		__u64 mem_rsvd: 18;
	};
};
typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);
struct perf_regs {
	__u64 abi;
	struct pt_regs *regs;
};
union perf_sample_weight {
	__u64 full;
	struct {
		__u32 var1_dw;
		__u16 var2_w;
		__u16 var3_w;
	};
};
typedef long unsigned int pgdval_t;
typedef struct {
	pgdval_t pgd;
} pgd_t;
typedef long unsigned int pgprotval_t;
struct pgprot {
	pgprotval_t pgprot;
};
typedef struct pgprot pgprot_t;
typedef struct page *pgtable_t;
typedef __kernel_pid_t pid_t;
enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};
struct pin_cookie {};
struct pinctrl_state {
	struct list_head node;
	const char *name;
	struct list_head settings;
};
struct pipe_buf_operations {
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};
struct pipe_buffer {
	struct page *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	long unsigned int private;
};
struct plist_head {
	struct list_head node_list;
};
struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};
struct freq_qos_request {
	enum freq_qos_req_type type;
	struct plist_node pnode;
	struct freq_constraints *qos;
};
struct pm_domain_data {
	struct list_head list_node;
	struct device *dev;
};
struct pm_message {
	int event;
};
typedef struct pm_message pm_message_t;
struct bus_type {
	const char *name;
	const char *dev_name;
	const struct attribute_group **bus_groups;
	const struct attribute_group **dev_groups;
	const struct attribute_group **drv_groups;
	int (*match)(struct device *, struct device_driver *);
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	void (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*online)(struct device *);
	int (*offline)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	int (*num_vf)(struct device *);
	int (*dma_configure)(struct device *);
	void (*dma_cleanup)(struct device *);
	const struct dev_pm_ops *pm;
	bool need_parent_lock;
};
enum pm_qos_type {
	PM_QOS_UNITIALIZED = 0,
	PM_QOS_MAX = 1,
	PM_QOS_MIN = 2,
};
typedef long unsigned int pmdval_t;
typedef struct {
	pmdval_t pmd;
} pmd_t;
struct pollfd {
	int fd;
	short int events;
	short int revents;
};
typedef struct {
	struct net *net;
} possible_net_t;
enum pr_type {
	PR_WRITE_EXCLUSIVE = 1,
	PR_EXCLUSIVE_ACCESS = 2,
	PR_WRITE_EXCLUSIVE_REG_ONLY = 3,
	PR_EXCLUSIVE_ACCESS_REG_ONLY = 4,
	PR_WRITE_EXCLUSIVE_ALL_REGS = 5,
	PR_EXCLUSIVE_ACCESS_ALL_REGS = 6,
};
enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE = 0,
	TRACE_TYPE_HANDLED = 1,
	TRACE_TYPE_UNHANDLED = 2,
	TRACE_TYPE_NO_CONSUME = 3,
};
enum probe_type {
	PROBE_DEFAULT_STRATEGY = 0,
	PROBE_PREFER_ASYNCHRONOUS = 1,
	PROBE_FORCE_SYNCHRONOUS = 2,
};
struct device_driver {
	const char *name;
	const struct bus_type *bus;
	struct module *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	int (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	const struct dev_pm_ops *pm;
	void (*coredump)(struct device *);
	struct driver_private *p;
};
struct proc_ns_operations {
	const char *name;
	const char *real_ns_name;
	int type;
	struct ns_common * (*get)(struct task_struct *);
	void (*put)(struct ns_common *);
	int (*install)(struct nsset *, struct ns_common *);
	struct user_namespace * (*owner)(struct ns_common *);
	struct ns_common * (*get_parent)(struct ns_common *);
};
struct prog_entry {
	int target;
	int when_to_branch;
	struct filter_pred *pred;
};
typedef __kernel_uid32_t projid_t;
typedef struct {
	projid_t val;
} kprojid_t;
struct property {
	char *name;
	int length;
	void *value;
	struct property *next;
};
struct prot_inuse {
	int all;
	int val[64];
};
typedef long unsigned int pteval_t;
typedef struct {
	pteval_t pte;
} pte_t;
typedef long unsigned int pudval_t;
typedef struct {
	pudval_t pud;
} pud_t;
struct qc_info {
	int i_fieldmask;
	unsigned int i_flags;
	unsigned int i_spc_timelimit;
	unsigned int i_ino_timelimit;
	unsigned int i_rt_spc_timelimit;
	unsigned int i_spc_warnlimit;
	unsigned int i_ino_warnlimit;
	unsigned int i_rt_spc_warnlimit;
};
typedef long long int qsize_t;
struct dquot_operations {
	int (*write_dquot)(struct dquot *);
	struct dquot * (*alloc_dquot)(struct super_block *, int);
	void (*destroy_dquot)(struct dquot *);
	int (*acquire_dquot)(struct dquot *);
	int (*release_dquot)(struct dquot *);
	int (*mark_dirty)(struct dquot *);
	int (*write_info)(struct super_block *, int);
	qsize_t * (*get_reserved_space)(struct inode *);
	int (*get_projid)(struct inode *, kprojid_t *);
	int (*get_inode_usage)(struct inode *, qsize_t *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};
struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};
struct queue_limits {
	enum blk_bounce bounce;
	long unsigned int seg_boundary_mask;
	long unsigned int virt_boundary_mask;
	unsigned int max_hw_sectors;
	unsigned int max_dev_sectors;
	unsigned int chunk_sectors;
	unsigned int max_sectors;
	unsigned int max_user_sectors;
	unsigned int max_segment_size;
	unsigned int physical_block_size;
	unsigned int logical_block_size;
	unsigned int alignment_offset;
	unsigned int io_min;
	unsigned int io_opt;
	unsigned int max_discard_sectors;
	unsigned int max_hw_discard_sectors;
	unsigned int max_secure_erase_sectors;
	unsigned int max_write_zeroes_sectors;
	unsigned int max_zone_append_sectors;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int zone_write_granularity;
	short unsigned int max_segments;
	short unsigned int max_integrity_segments;
	short unsigned int max_discard_segments;
	unsigned char misaligned;
	unsigned char discard_misaligned;
	unsigned char raid_partial_stripes_expensive;
	bool zoned;
	unsigned int dma_alignment;
};
struct quota_format_ops {
	int (*check_quota_file)(struct super_block *, int);
	int (*read_file_info)(struct super_block *, int);
	int (*write_file_info)(struct super_block *, int);
	int (*free_file_info)(struct super_block *, int);
	int (*read_dqblk)(struct dquot *);
	int (*commit_dqblk)(struct dquot *);
	int (*release_dqblk)(struct dquot *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};
struct quota_format_type {
	int qf_fmt_id;
	const struct quota_format_ops *qf_ops;
	struct module *qf_owner;
	struct quota_format_type *qf_next;
};
enum quota_type {
	USRQUOTA = 0,
	GRPQUOTA = 1,
	PRJQUOTA = 2,
};
struct raw_notifier_head {
	struct notifier_block *head;
};
struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};
struct bpf_cgroup_storage {
	union {
		struct bpf_storage_buffer *buf;
		void *percpu_buf;
	};
	struct bpf_cgroup_storage_map *map;
	struct bpf_cgroup_storage_key key;
	struct list_head list_map;
	struct list_head list_cg;
	struct rb_node node;
	struct callback_head rcu;
};
struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};
struct iova {
	struct rb_node node;
	long unsigned int pfn_hi;
	long unsigned int pfn_lo;
};
struct latch_tree_node {
	struct rb_node node[2];
};
struct bpf_ksym {
	long unsigned int start;
	long unsigned int end;
	char name[512];
	struct list_head lnode;
	struct latch_tree_node tnode;
	bool prog;
};
struct mod_tree_node {
	struct module *mod;
	struct latch_tree_node node;
};
struct module_memory {
	void *base;
	unsigned int size;
	struct mod_tree_node mtn;
};
struct rb_root {
	struct rb_node *rb_node;
};
struct ctl_dir {
	struct ctl_table_header header;
	struct rb_root root;
};
struct ctl_table_set {
	int (*is_seen)(struct ctl_table_set *);
	struct ctl_dir dir;
};
struct kernfs_elem_dir {
	long unsigned int subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	long unsigned int rev;
};
struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};
typedef struct {
	atomic_t refcnt;
} rcuref_t;
struct dst_entry {
	void *dev;
	struct dst_ops *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	void *xfrm;
	int (*input)(struct sk_buff *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	rcuref_t __rcuref;
	int __use;
	long unsigned int lastuse;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
	struct list_head rt_uncached;
	struct uncached_list *rt_uncached_list;
	struct lwtunnel_state *lwtstate;
};
struct rcuwait {
	struct task_struct *task;
};
struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	long unsigned int _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
	bool _workingset;
	long unsigned int _pflags;
};
struct reclaim_state {
	long unsigned int reclaimed;
	struct lru_gen_mm_walk *mm_walk;
};
struct ref_tracker_dir {};
struct refcount_struct {
	atomic_t refs;
};
typedef struct refcount_struct refcount_t;
struct css_set {
	struct cgroup_subsys_state *subsys[14];
	refcount_t refcount;
	struct css_set *dom_cset;
	struct cgroup *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[14];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup *mg_src_cgrp;
	struct cgroup *mg_dst_cgrp;
	struct css_set *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};
struct group_info {
	refcount_t usage;
	int ngroups;
	kgid_t gid[0];
};
struct ifacaddr6 {
	struct in6_addr aca_addr;
	struct fib6_info *aca_rt;
	struct ifacaddr6 *aca_next;
	struct hlist_node aca_addr_lst;
	int aca_users;
	refcount_t aca_refcnt;
	long unsigned int aca_cstamp;
	long unsigned int aca_tstamp;
	struct callback_head rcu;
};
struct inet_timewait_death_row {
	refcount_t tw_refcount;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct inet_hashinfo *hashinfo;
	int sysctl_max_tw_buckets;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct key_tag {
	struct callback_head rcu;
	refcount_t usage;
	bool removed;
};
struct kref {
	refcount_t refcount;
};
struct aa_proxy {
	struct kref count;
	struct aa_label *label;
};
struct anon_vma_name {
	struct kref kref;
	char name[0];
};
struct klist_node {
	void *n_klist;
	struct list_head n_node;
	struct kref n_ref;
};
struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};
struct blk_mq_ctxs {
	struct kobject kobj;
	struct blk_mq_ctx *queue_ctx;
};
struct mem_cgroup_id {
	int id;
	refcount_t ref;
};
struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};
struct netlbl_lsm_cache {
	refcount_t refcount;
	void (*free)(const void *);
	void *data;
};
struct nf_conntrack {
	refcount_t use;
};
struct nsproxy {
	refcount_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};
struct pinctrl {
	struct list_head node;
	struct device *dev;
	struct list_head states;
	struct pinctrl_state *state;
	struct list_head dt_maps;
	struct kref users;
};
typedef int (*regex_match_func)(char *, struct regex *, int);
struct regex {
	char pattern[256];
	int len;
	int field_len;
	regex_match_func match;
};
typedef int (*report_zones_cb)(struct blk_zone *, unsigned int, void *);
typedef __u32 req_flags_t;
struct blk_mq_alloc_data {
	struct request_queue *q;
	blk_mq_req_flags_t flags;
	unsigned int shallow_depth;
	blk_opf_t cmd_flags;
	req_flags_t rq_flags;
	unsigned int nr_tags;
	struct request **cached_rq;
	struct blk_mq_ctx *ctx;
	struct blk_mq_hw_ctx *hctx;
};
typedef int (*request_key_actor_t)(struct key *, void *);
struct request_sock_ops {
	int family;
	unsigned int obj_size;
	struct kmem_cache *slab;
	char *slab_name;
	int (*rtx_syn_ack)(const struct sock *, struct request_sock *);
	void (*send_ack)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*send_reset)(const struct sock *, struct sk_buff *);
	void (*destructor)(struct request_sock *);
	void (*syn_ack_timeout)(const struct request_sock *);
};
struct return_instance {
	struct uprobe *uprobe;
	long unsigned int func;
	long unsigned int stack;
	long unsigned int orig_ret_vaddr;
	bool chained;
	struct return_instance *next;
};
struct rhash_head {
	struct rhash_head *next;
};
struct rhash_lock_head {};
struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};
struct rhlist_head {
	struct rhash_head rhead;
	struct rhlist_head *next;
};
typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *, const void *);
struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};
struct linux_binprm {
	struct vm_area_struct *vma;
	long unsigned int vma_pages;
	struct mm_struct *mm;
	long unsigned int p;
	long unsigned int argmin;
	unsigned int have_execfd: 1;
	unsigned int execfd_creds: 1;
	unsigned int secureexec: 1;
	unsigned int point_of_no_return: 1;
	unsigned int comm_from_dentry: 1;
	struct file *executable;
	struct file *interpreter;
	struct file *file;
	struct cred *cred;
	int unsafe;
	unsigned int per_clear;
	int argc;
	int envc;
	const char *filename;
	const char *interp;
	const char *fdpath;
	unsigned int interp_flags;
	int execfd;
	long unsigned int loader;
	long unsigned int exec;
	struct rlimit rlim_stack;
	char buf[256];
};
struct robust_list {
	struct robust_list *next;
};
struct robust_list_head {
	struct robust_list list;
	long int futex_offset;
	struct robust_list *list_op_pending;
};
enum rpm_request {
	RPM_REQ_NONE = 0,
	RPM_REQ_IDLE = 1,
	RPM_REQ_SUSPEND = 2,
	RPM_REQ_AUTOSUSPEND = 3,
	RPM_REQ_RESUME = 4,
};
enum rpm_status {
	RPM_INVALID = -1,
	RPM_ACTIVE = 0,
	RPM_RESUMING = 1,
	RPM_SUSPENDED = 2,
	RPM_SUSPENDING = 3,
};
enum rq_end_io_ret {
	RQ_END_IO_NONE = 0,
	RQ_END_IO_FREE = 1,
};
struct rq_flags {
	long unsigned int flags;
	struct pin_cookie cookie;
	unsigned int clock_update_flags;
};
enum rq_qos_id {
	RQ_QOS_WBT = 0,
	RQ_QOS_LATENCY = 1,
	RQ_QOS_COST = 2,
};
struct rq_qos {
	const struct rq_qos_ops *ops;
	struct gendisk *disk;
	enum rq_qos_id id;
	struct rq_qos *next;
	struct dentry *debugfs_dir;
};
struct rq_qos_ops {
	void (*throttle)(struct rq_qos *, struct bio *);
	void (*track)(struct rq_qos *, struct request *, struct bio *);
	void (*merge)(struct rq_qos *, struct request *, struct bio *);
	void (*issue)(struct rq_qos *, struct request *);
	void (*requeue)(struct rq_qos *, struct request *);
	void (*done)(struct rq_qos *, struct request *);
	void (*done_bio)(struct rq_qos *, struct bio *);
	void (*cleanup)(struct rq_qos *, struct bio *);
	void (*queue_depth_changed)(struct rq_qos *);
	void (*exit)(struct rq_qos *);
	const struct blk_mq_debugfs_attr *debugfs_attrs;
};
struct rseq {
	__u32 cpu_id_start;
	__u32 cpu_id;
	__u64 rseq_cs;
	__u32 flags;
	__u32 node_id;
	__u32 mm_cid;
	char end[0];
};
struct rt6_exception_bucket {
	struct hlist_head chain;
	int depth;
};
struct rt6_statistics {
	__u32 fib_nodes;
	__u32 fib_route_nodes;
	__u32 fib_rt_entries;
	__u32 fib_rt_cache;
	__u32 fib_discarded_routes;
	atomic_t fib_rt_alloc;
};
struct rt6key {
	struct in6_addr addr;
	int plen;
};
struct rt_prio_array {
	long unsigned int bitmap[2];
	struct list_head queue[100];
};
struct rtattr {
	short unsigned int rta_len;
	short unsigned int rta_type;
};
union rv_task_monitor {
	struct da_monitor da_mon;
};
typedef __s16 s16;
typedef __s32 s32;
struct bpf_retval_range {
	s32 minval;
	s32 maxval;
};
typedef s32 compat_long_t;
typedef s32 int32_t;
struct jump_entry {
	s32 code;
	s32 target;
	long int key;
};
typedef int32_t key_serial_t;
typedef s32 old_time32_t;
struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};
struct pm_qos_constraints {
	struct plist_head list;
	s32 target_value;
	s32 default_value;
	s32 no_constraint_value;
	enum pm_qos_type type;
	struct blocking_notifier_head *notifiers;
};
struct pm_qos_flags {
	struct list_head list;
	s32 effective_flags;
};
struct pm_qos_flags_request {
	struct list_head node;
	s32 flags;
};
struct dev_pm_qos_request {
	enum dev_pm_qos_req_type type;
	union {
		struct plist_node pnode;
		struct pm_qos_flags_request flr;
		struct freq_qos_request freq;
	} data;
	struct device *dev;
};
typedef __s64 s64;
typedef struct {
	s64 counter;
} atomic64_t;
typedef atomic64_t atomic_long_t;
struct cpuidle_state {
	char name[16];
	char desc[32];
	s64 exit_latency_ns;
	s64 target_residency_ns;
	unsigned int flags;
	unsigned int exit_latency;
	int power_usage;
	unsigned int target_residency;
	int (*enter)(struct cpuidle_device *, struct cpuidle_driver *, int);
	int (*enter_dead)(struct cpuidle_device *, int);
	int (*enter_s2idle)(struct cpuidle_device *, struct cpuidle_driver *, int);
};
struct cpuidle_driver {
	const char *name;
	struct module *owner;
	unsigned int bctimer: 1;
	struct cpuidle_state states[10];
	int state_count;
	int safe_state_index;
	struct cpumask *cpumask;
	const char *governor;
};
struct icmpmsg_mib {
	atomic_long_t mibs[512];
};
struct icmpv6_mib_device {
	atomic_long_t mibs[7];
};
struct icmpv6msg_mib {
	atomic_long_t mibs[512];
};
struct icmpv6msg_mib_device {
	atomic_long_t mibs[512];
};
typedef s64 ktime_t;
typedef struct {
	atomic_long_t a;
} local_t;
struct buffer_page {
	struct list_head list;
	local_t write;
	unsigned int read;
	local_t entries;
	long unsigned int real_end;
	unsigned int order;
	struct buffer_data_page *page;
};
typedef struct {
	local_t a;
} local64_t;
struct memcg_vmstats {
	long int state[53];
	long unsigned int events[22];
	long int state_local[53];
	long unsigned int events_local[22];
	long int state_pending[53];
	long unsigned int events_pending[22];
	atomic64_t stats_updates;
};
struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};
struct ns_common {
	atomic_long_t stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};
struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};
struct page {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space *mapping;
			union {
				long unsigned int index;
				long unsigned int share;
			};
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			atomic_long_t pp_ref_count;
		};
		struct {
			long unsigned int compound_head;
		};
		struct {
			struct dev_pagemap *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};
struct page_counter {
	atomic_long_t usage;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	long unsigned int emin;
	atomic_long_t min_usage;
	atomic_long_t children_min_usage;
	long unsigned int elow;
	atomic_long_t low_usage;
	atomic_long_t children_low_usage;
	long unsigned int watermark;
	long unsigned int failcnt;
	struct cacheline_padding _pad2_;
	long unsigned int min;
	long unsigned int low;
	long unsigned int high;
	long unsigned int max;
	struct page_counter *parent;
	long: 64;
	long: 64;
	long: 64;
};
struct percpu_ref_data {
	atomic_long_t count;
	percpu_ref_func_t *release;
	percpu_ref_func_t *confirm_switch;
	bool force_atomic: 1;
	bool allow_reinit: 1;
	struct callback_head rcu;
	struct percpu_ref *ref;
};
struct rb_time_struct {
	local64_t time;
};
typedef struct rb_time_struct rb_time_t;
typedef __s8 s8;
struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[46];
};
struct per_cpu_zonestat {
	s8 vm_stat_diff[12];
	s8 stat_threshold;
	long unsigned int vm_numa_event[6];
};
typedef __kernel_sa_family_t sa_family_t;
struct saved {
	struct path link;
	struct delayed_call done;
	const char *name;
	unsigned int seq;
};
struct sbitmap {
	unsigned int depth;
	unsigned int shift;
	unsigned int map_nr;
	bool round_robin;
	struct sbitmap_word *map;
	unsigned int *alloc_hint;
};
struct sbitmap_queue {
	struct sbitmap sb;
	unsigned int wake_batch;
	atomic_t wake_index;
	struct sbq_wait_state *ws;
	atomic_t ws_active;
	unsigned int min_shallow_depth;
	atomic_t completion_cnt;
	atomic_t wakeup_cnt;
};
struct sched_class {
	int uclamp_enabled;
	void (*enqueue_task)(struct rq *, struct task_struct *, int);
	void (*dequeue_task)(struct rq *, struct task_struct *, int);
	void (*yield_task)(struct rq *);
	bool (*yield_to_task)(struct rq *, struct task_struct *);
	void (*wakeup_preempt)(struct rq *, struct task_struct *, int);
	struct task_struct * (*pick_next_task)(struct rq *);
	void (*put_prev_task)(struct rq *, struct task_struct *);
	void (*set_next_task)(struct rq *, struct task_struct *, bool);
	int (*balance)(struct rq *, struct task_struct *, struct rq_flags *);
	int (*select_task_rq)(struct task_struct *, int, int);
	struct task_struct * (*pick_task)(struct rq *);
	void (*migrate_task_rq)(struct task_struct *, int);
	void (*task_woken)(struct rq *, struct task_struct *);
	void (*set_cpus_allowed)(struct task_struct *, struct affinity_context *);
	void (*rq_online)(struct rq *);
	void (*rq_offline)(struct rq *);
	struct rq * (*find_lock_rq)(struct task_struct *, struct rq *);
	void (*task_tick)(struct rq *, struct task_struct *, int);
	void (*task_fork)(struct task_struct *);
	void (*task_dead)(struct task_struct *);
	void (*switched_from)(struct rq *, struct task_struct *);
	void (*switched_to)(struct rq *, struct task_struct *);
	void (*prio_changed)(struct rq *, struct task_struct *, int);
	unsigned int (*get_rr_interval)(struct rq *, struct task_struct *);
	void (*update_curr)(struct rq *);
	void (*task_change_group)(struct task_struct *);
	int (*task_is_throttled)(struct task_struct *, int);
};
struct sched_domain_shared {
	atomic_t ref;
	atomic_t nr_busy_cpus;
	int has_idle_cores;
	int nr_idle_scan;
};
struct sched_group {
	struct sched_group *next;
	atomic_t ref;
	unsigned int group_weight;
	unsigned int cores;
	struct sched_group_capacity *sgc;
	int asym_prefer_cpu;
	int flags;
	long unsigned int cpumask[0];
};
struct sched_group_capacity {
	atomic_t ref;
	long unsigned int capacity;
	long unsigned int min_capacity;
	long unsigned int max_capacity;
	long unsigned int next_update;
	int imbalance;
	int id;
	long unsigned int cpumask[0];
};
struct sched_info {
	long unsigned int pcount;
	long long unsigned int run_delay;
	long long unsigned int last_arrival;
	long long unsigned int last_queued;
};
struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
};
enum sctp_conntrack {
	SCTP_CONNTRACK_NONE = 0,
	SCTP_CONNTRACK_CLOSED = 1,
	SCTP_CONNTRACK_COOKIE_WAIT = 2,
	SCTP_CONNTRACK_COOKIE_ECHOED = 3,
	SCTP_CONNTRACK_ESTABLISHED = 4,
	SCTP_CONNTRACK_SHUTDOWN_SENT = 5,
	SCTP_CONNTRACK_SHUTDOWN_RECD = 6,
	SCTP_CONNTRACK_SHUTDOWN_ACK_SENT = 7,
	SCTP_CONNTRACK_HEARTBEAT_SENT = 8,
	SCTP_CONNTRACK_HEARTBEAT_ACKED = 9,
	SCTP_CONNTRACK_MAX = 10,
};
struct sctp_mib;
struct seccomp {
	int mode;
	atomic_t filter_count;
	struct seccomp_filter *filter;
};
struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};
struct seqcount {
	unsigned int sequence;
};
typedef struct seqcount seqcount_t;
struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};
typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;
struct seqcount_spinlock {
	seqcount_t seqcount;
};
typedef struct seqcount_spinlock seqcount_spinlock_t;
struct serial_icounter_struct {
	int cts;
	int dsr;
	int rng;
	int dcd;
	int rx;
	int tx;
	int frame;
	int overrun;
	int parity;
	int brk;
	int buf_overrun;
	int reserved[9];
};
struct serial_struct {
	int type;
	int line;
	unsigned int port;
	int irq;
	int flags;
	int xmit_fifo_size;
	int custom_divisor;
	int baud_base;
	short unsigned int close_delay;
	char io_type;
	char reserved_char[1];
	int hub6;
	short unsigned int closing_wait;
	short unsigned int closing_wait2;
	unsigned char *iomem_base;
	short unsigned int iomem_reg_shift;
	unsigned int port_high;
	long unsigned int iomap_base;
};
struct sg_table {
	struct scatterlist *sgl;
	unsigned int nents;
	unsigned int orig_nents;
};
struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup *memcg;
};
struct shrinker_info {
	struct callback_head rcu;
	int map_nr_max;
	struct shrinker_info_unit *unit[0];
};
struct shrinker_info_unit {
	atomic_long_t nr_deferred[64];
	long unsigned int map[1];
};
typedef struct {
	long unsigned int sig[1];
} sigset_t;
struct sigaction {
	__sighandler_t sa_handler;
	long unsigned int sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};
struct k_sigaction {
	struct sigaction sa;
};
struct sigpending {
	struct list_head list;
	sigset_t signal;
};
union sigval {
	int sival_int;
	void *sival_ptr;
};
typedef union sigval sigval_t;
union __sifields {
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
	} _kill;
	struct {
		__kernel_timer_t _tid;
		int _overrun;
		sigval_t _sigval;
		int _sys_private;
	} _timer;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		sigval_t _sigval;
	} _rt;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		int _status;
		__kernel_clock_t _utime;
		__kernel_clock_t _stime;
	} _sigchld;
	struct {
		void *_addr;
		union {
			int _trapno;
			short int _addr_lsb;
			struct {
				char _dummy_bnd[8];
				void *_lower;
				void *_upper;
			} _addr_bnd;
			struct {
				char _dummy_pkey[8];
				__u32 _pkey;
			} _addr_pkey;
			struct {
				long unsigned int _data;
				__u32 _type;
				__u32 _flags;
			} _perf;
		};
	} _sigfault;
	struct {
		long int _band;
		int _fd;
	} _sigpoll;
	struct {
		void *_call_addr;
		int _syscall;
		unsigned int _arch;
	} _sigsys;
};
struct kernel_siginfo {
	struct {
		int si_signo;
		int si_errno;
		int si_code;
		union __sifields _sifields;
	};
};
typedef struct kernel_siginfo kernel_siginfo_t;
typedef __kernel_size_t size_t;
struct coredump_params {
	const kernel_siginfo_t *siginfo;
	struct file *file;
	long unsigned int limit;
	long unsigned int mm_flags;
	int cpu;
	loff_t written;
	loff_t pos;
	loff_t to_skip;
	int vma_count;
	size_t vma_data_size;
	struct core_vma_metadata *vma_meta;
};
struct fib_rules_ops {
	int family;
	struct list_head list;
	int rule_size;
	int addr_size;
	int unresolved_rules;
	int nr_goto_rules;
	unsigned int fib_rules_seq;
	int (*action)(struct fib_rule *, struct flowi *, int, struct fib_lookup_arg *);
	bool (*suppress)(struct fib_rule *, int, struct fib_lookup_arg *);
	int (*match)(struct fib_rule *, struct flowi *, int);
	int (*configure)(struct fib_rule *, struct sk_buff *, struct fib_rule_hdr *, struct nlattr **, struct netlink_ext_ack *);
	int (*delete)(struct fib_rule *);
	int (*compare)(struct fib_rule *, struct fib_rule_hdr *, struct nlattr **);
	int (*fill)(struct fib_rule *, struct sk_buff *, struct fib_rule_hdr *);
	size_t (*nlmsg_payload)(struct fib_rule *);
	void (*flush_cache)(struct fib_rules_ops *);
	int nlgroup;
	struct list_head rules_list;
	struct module *owner;
	struct net *fro_net;
	struct callback_head rcu;
};
struct fs_parameter {
	const char *key;
	enum fs_value_type type: 8;
	union {
		char *string;
		void *blob;
		struct filename *name;
		struct file *file;
	};
	size_t size;
	int dirfd;
};
struct fscrypt_operations {
	unsigned int needs_bounce_pages: 1;
	unsigned int has_32bit_inodes: 1;
	unsigned int supports_subblock_data_units: 1;
	const char *legacy_key_prefix;
	int (*get_context)(struct inode *, void *, size_t);
	int (*set_context)(struct inode *, const void *, size_t, void *);
	const union fscrypt_policy * (*get_dummy_policy)(struct super_block *);
	bool (*empty_dir)(struct inode *);
	bool (*has_stable_inodes)(struct super_block *);
	struct block_device ** (*get_devices)(struct super_block *, unsigned int *);
};
struct fwnode_operations {
	struct fwnode_handle * (*get)(struct fwnode_handle *);
	void (*put)(struct fwnode_handle *);
	bool (*device_is_available)(const struct fwnode_handle *);
	const void * (*device_get_match_data)(const struct fwnode_handle *, const struct device *);
	bool (*device_dma_supported)(const struct fwnode_handle *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle *);
	bool (*property_present)(const struct fwnode_handle *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle *);
	const char * (*get_name_prefix)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_parent)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_next_child_node)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*get_named_child_node)(const struct fwnode_handle *, const char *);
	int (*get_reference_args)(const struct fwnode_handle *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args *);
	struct fwnode_handle * (*graph_get_next_endpoint)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_remote_endpoint)(const struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_port_parent)(struct fwnode_handle *);
	int (*graph_parse_endpoint)(const struct fwnode_handle *, struct fwnode_endpoint *);
	void * (*iomap)(struct fwnode_handle *, int);
	int (*irq_get)(const struct fwnode_handle *, unsigned int);
	int (*add_links)(struct fwnode_handle *);
};
struct io_alloc_cache {
	struct io_wq_work_node list;
	unsigned int nr_cached;
	unsigned int max_cached;
	size_t elem_size;
};
struct iommu_dirty_ops {
	int (*set_dirty_tracking)(struct iommu_domain *, bool);
	int (*read_and_clear_dirty)(struct iommu_domain *, long unsigned int, size_t, long unsigned int, struct iommu_dirty_bitmap *);
};
struct iommu_dma_options {
	enum iommu_dma_queue_type qt;
	size_t fq_size;
	unsigned int fq_timeout;
};
struct iommu_iotlb_gather {
	long unsigned int start;
	long unsigned int end;
	size_t pgsize;
	struct list_head freelist;
	bool queued;
};
struct iommu_user_data {
	unsigned int type;
	void *uptr;
	size_t len;
};
struct key_type {
	const char *name;
	size_t def_datalen;
	unsigned int flags;
	int (*vet_description)(const char *);
	int (*preparse)(struct key_preparsed_payload *);
	void (*free_preparse)(struct key_preparsed_payload *);
	int (*instantiate)(struct key *, struct key_preparsed_payload *);
	int (*update)(struct key *, struct key_preparsed_payload *);
	int (*match_preparse)(struct key_match_data *);
	void (*match_free)(struct key_match_data *);
	void (*revoke)(struct key *);
	void (*destroy)(struct key *);
	void (*describe)(const struct key *, struct seq_file *);
	long int (*read)(const struct key *, char *, size_t);
	request_key_actor_t request_key;
	struct key_restriction * (*lookup_restriction)(const char *);
	int (*asym_query)(const struct kernel_pkey_params *, struct kernel_pkey_query *);
	int (*asym_eds_op)(struct kernel_pkey_params *, const void *, void *);
	int (*asym_verify_signature)(struct kernel_pkey_params *, const void *, const void *);
	struct list_head link;
	struct lock_class_key lock_class;
};
struct kvec {
	void *iov_base;
	size_t iov_len;
};
struct netns_mpls {
	int ip_ttl_propagate;
	int default_ttl;
	size_t platform_labels;
	struct mpls_route **platform_label;
	struct ctl_table_header *ctl;
};
typedef int proc_handler(struct ctl_table *, int, void *, size_t *, loff_t *);
typedef int (*proc_write_t)(struct file *, char *, size_t);
typedef struct {
	size_t written;
	size_t count;
	union {
		char *buf;
		void *data;
	} arg;
	int error;
} read_descriptor_t;
struct seq_buf {
	char *buffer;
	size_t size;
	size_t len;
};
typedef unsigned int sk_buff_data_t;
struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};
struct sk_filter {
	refcount_t refcnt;
	struct callback_head rcu;
	struct bpf_prog *prog;
};
struct sk_psock_progs {
	struct bpf_prog *msg_parser;
	struct bpf_prog *stream_parser;
	struct bpf_prog *stream_verdict;
	struct bpf_prog *skb_verdict;
};
typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *, unsigned int, size_t);
typedef int (*skb_read_actor_t)(struct sock *, struct sk_buff *);
typedef unsigned int slab_flags_t;
struct smc_hashinfo;
struct smc_stats;
struct smc_stats_rsn;
typedef void (*smp_call_func_t)(void *);
struct sock_filter {
	__u16 code;
	__u8 jt;
	__u8 jf;
	__u32 k;
};
struct sockaddr {
	sa_family_t sa_family;
	union {
		char sa_data_min[14];
		struct {
			struct {} __empty_sa_data;
			char sa_data[0];
		};
	};
};
typedef enum {
	SS_FREE = 0,
	SS_UNCONNECTED = 1,
	SS_CONNECTING = 2,
	SS_CONNECTED = 3,
	SS_DISCONNECTING = 4,
} socket_state;
typedef struct {
	union {
		void *kernel;
		void *user;
	};
	bool is_kernel: 1;
} sockptr_t;
typedef sockptr_t bpfptr_t;
typedef unsigned int speed_t;
struct srcu_struct {
	unsigned int srcu_idx;
	struct srcu_data *sda;
	struct lockdep_map dep_map;
	struct srcu_usage *srcu_sup;
};
typedef __kernel_ssize_t ssize_t;
struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long int (*unlocked_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap)(struct file *, struct vm_area_struct *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct file *);
	int (*setlease)(struct file *, int, struct file_lock **, void **);
	long int (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};
struct kernfs_ops {
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	ssize_t (*read)(struct kernfs_open_file *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	int (*mmap)(struct kernfs_open_file *, struct vm_area_struct *);
	loff_t (*llseek)(struct kernfs_open_file *, loff_t, int);
};
struct proc_ops {
	unsigned int proc_flags;
	int (*proc_open)(struct inode *, struct file *);
	ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*proc_read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*proc_write)(struct file *, const char *, size_t, loff_t *);
	loff_t (*proc_lseek)(struct file *, loff_t, int);
	int (*proc_release)(struct inode *, struct file *);
	__poll_t (*proc_poll)(struct file *, struct poll_table_struct *);
	long int (*proc_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*proc_compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*proc_mmap)(struct file *, struct vm_area_struct *);
	long unsigned int (*proc_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
};
struct proto_ops {
	int family;
	struct module *owner;
	int (*release)(struct socket *);
	int (*bind)(struct socket *, struct sockaddr *, int);
	int (*connect)(struct socket *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket *, struct socket *);
	int (*accept)(struct socket *, struct socket *, int, bool);
	int (*getname)(struct socket *, struct sockaddr *, int);
	__poll_t (*poll)(struct file *, struct socket *, struct poll_table_struct *);
	int (*ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket *, void *, bool, bool);
	int (*listen)(struct socket *, int);
	int (*shutdown)(struct socket *, int);
	int (*setsockopt)(struct socket *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file *, struct socket *);
	int (*sendmsg)(struct socket *, struct msghdr *, size_t);
	int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);
	int (*mmap)(struct file *, struct socket *, struct vm_area_struct *);
	ssize_t (*splice_read)(struct socket *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct socket *);
	int (*set_peek_off)(struct sock *, int);
	int (*peek_len)(struct socket *);
	int (*read_sock)(struct sock *, read_descriptor_t *, sk_read_actor_t);
	int (*read_skb)(struct sock *, skb_read_actor_t);
	int (*sendmsg_locked)(struct sock *, struct msghdr *, size_t);
	int (*set_rcvlowat)(struct sock *, int);
};
struct static_call_key {
	void *func;
	union {
		long unsigned int type;
		struct static_call_mod *mods;
		struct static_call_site *sites;
	};
};
struct static_call_mod {
	struct static_call_mod *next;
	struct module *mod;
	struct static_call_site *sites;
};
struct static_call_site {
	s32 addr;
	s32 key;
};
struct static_key {
	atomic_t enabled;
	union {
		long unsigned int type;
		struct jump_entry *entries;
		struct static_key_mod *next;
	};
};
struct static_key_false {
	struct static_key key;
};
struct static_key_mod {
	struct static_key_mod *next;
	struct jump_entry *entries;
	struct module *mod;
};
struct static_key_true {
	struct static_key key;
};
struct _ddebug {
	const char *modname;
	const char *function;
	const char *filename;
	const char *format;
	unsigned int lineno: 18;
	unsigned int class_id: 6;
	unsigned int flags: 8;
	union {
		struct static_key_true dd_key_true;
		struct static_key_false dd_key_false;
	} key;
};
struct strp_callbacks {
	int (*parse_msg)(struct strparser *, struct sk_buff *);
	void (*rcv_msg)(struct strparser *, struct sk_buff *);
	int (*read_sock)(struct strparser *, read_descriptor_t *, sk_read_actor_t);
	int (*read_sock_done)(struct strparser *, int);
	void (*abort_parser)(struct strparser *, int);
	void (*lock)(struct strparser *);
	void (*unlock)(struct strparser *);
};
struct strp_stats {
	long long unsigned int msgs;
	long long unsigned int bytes;
	unsigned int mem_fail;
	unsigned int need_more_hdr;
	unsigned int msg_too_big;
	unsigned int msg_timeouts;
	unsigned int bad_hdr_len;
};
struct super_operations {
	struct inode * (*alloc_inode)(struct super_block *);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);
	void (*dirty_inode)(struct inode *, int);
	int (*write_inode)(struct inode *, struct writeback_control *);
	int (*drop_inode)(struct inode *);
	void (*evict_inode)(struct inode *);
	void (*put_super)(struct super_block *);
	int (*sync_fs)(struct super_block *, int);
	int (*freeze_super)(struct super_block *, enum freeze_holder);
	int (*freeze_fs)(struct super_block *);
	int (*thaw_super)(struct super_block *, enum freeze_holder);
	int (*unfreeze_fs)(struct super_block *);
	int (*statfs)(struct dentry *, struct kstatfs *);
	int (*remount_fs)(struct super_block *, int *, char *);
	void (*umount_begin)(struct super_block *);
	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	int (*show_stats)(struct seq_file *, struct dentry *);
	ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
	struct dquot ** (*get_dquots)(struct inode *);
	long int (*nr_cached_objects)(struct super_block *, struct shrink_control *);
	long int (*free_cached_objects)(struct super_block *, struct shrink_control *);
	void (*shutdown)(struct super_block *);
};
typedef struct {
	long unsigned int val;
} swp_entry_t;
struct folio {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			union {
				void *private;
				swp_entry_t swap;
			};
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page page;
	};
	union {
		struct {
			long unsigned int _flags_1;
			long unsigned int _head_1;
			long unsigned int _folio_avail;
			atomic_t _entire_mapcount;
			atomic_t _nr_pages_mapped;
			atomic_t _pincount;
			unsigned int _folio_nr_pages;
		};
		struct page __page_1;
	};
	union {
		struct {
			long unsigned int _flags_2;
			long unsigned int _head_2;
			void *_hugetlb_subpool;
			void *_hugetlb_cgroup;
			void *_hugetlb_cgroup_rsvd;
			void *_hugetlb_hwpoison;
		};
		struct {
			long unsigned int _flags_2a;
			long unsigned int _head_2a;
			struct list_head _deferred_list;
		};
		struct page __page_2;
	};
};
struct syscall_user_dispatch {
	char *selector;
	long unsigned int offset;
	long unsigned int len;
	bool on_dispatch;
};
struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};
struct sysv_sem {
	struct sem_undo_list *undo_list;
};
struct sysv_shm {
	struct list_head shm_clist;
};
struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};
enum task_work_notify_mode {
	TWA_NONE = 0,
	TWA_RESUME = 1,
	TWA_SIGNAL = 2,
	TWA_SIGNAL_NO_IPI = 3,
	TWA_NMI_CURRENT = 4,
	TWA_FLAGS = 65280,
	TWAF_NO_ALLOC = 256,
};
struct taskstats {
	__u16 version;
	__u32 ac_exitcode;
	__u8 ac_flag;
	__u8 ac_nice;
	__u64 cpu_count;
	__u64 cpu_delay_total;
	__u64 blkio_count;
	__u64 blkio_delay_total;
	__u64 swapin_count;
	__u64 swapin_delay_total;
	__u64 cpu_run_real_total;
	__u64 cpu_run_virtual_total;
	char ac_comm[32];
	__u8 ac_sched;
	__u8 ac_pad[3];
	long: 0;
	__u32 ac_uid;
	__u32 ac_gid;
	__u32 ac_pid;
	__u32 ac_ppid;
	__u32 ac_btime;
	__u64 ac_etime;
	__u64 ac_utime;
	__u64 ac_stime;
	__u64 ac_minflt;
	__u64 ac_majflt;
	__u64 coremem;
	__u64 virtmem;
	__u64 hiwater_rss;
	__u64 hiwater_vm;
	__u64 read_char;
	__u64 write_char;
	__u64 read_syscalls;
	__u64 write_syscalls;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 cancelled_write_bytes;
	__u64 nvcsw;
	__u64 nivcsw;
	__u64 ac_utimescaled;
	__u64 ac_stimescaled;
	__u64 cpu_scaled_run_real_total;
	__u64 freepages_count;
	__u64 freepages_delay_total;
	__u64 thrashing_count;
	__u64 thrashing_delay_total;
	__u64 ac_btime64;
	__u64 compact_count;
	__u64 compact_delay_total;
	__u32 ac_tgid;
	__u64 ac_tgetime;
	__u64 ac_exe_dev;
	__u64 ac_exe_inode;
	__u64 wpcopy_count;
	__u64 wpcopy_delay_total;
	__u64 irq_count;
	__u64 irq_delay_total;
};
typedef unsigned int tcflag_t;
struct ktermios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[19];
	speed_t c_ispeed;
	speed_t c_ospeed;
};
struct tcp_bbr_info {
	__u32 bbr_bw_lo;
	__u32 bbr_bw_hi;
	__u32 bbr_min_rtt;
	__u32 bbr_pacing_gain;
	__u32 bbr_cwnd_gain;
};
enum tcp_ca_event {
	CA_EVENT_TX_START = 0,
	CA_EVENT_CWND_RESTART = 1,
	CA_EVENT_COMPLETE_CWR = 2,
	CA_EVENT_LOSS = 3,
	CA_EVENT_ECN_NO_CE = 4,
	CA_EVENT_ECN_IS_CE = 5,
};
struct tcp_dctcp_info {
	__u16 dctcp_enabled;
	__u16 dctcp_ce_state;
	__u32 dctcp_alpha;
	__u32 dctcp_ab_ecn;
	__u32 dctcp_ab_tot;
};
struct tcp_mib {
	long unsigned int mibs[16];
};
struct tcpvegas_info {
	__u32 tcpv_enabled;
	__u32 tcpv_rttcnt;
	__u32 tcpv_rtt;
	__u32 tcpv_minrtt;
};
union tcp_cc_info {
	struct tcpvegas_info vegas;
	struct tcp_dctcp_info dctcp;
	struct tcp_bbr_info bbr;
};
struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
};
typedef __s64 time64_t;
struct key_preparsed_payload {
	const char *orig_description;
	char *description;
	union key_payload payload;
	const void *data;
	size_t datalen;
	size_t quotalen;
	time64_t expiry;
};
struct mem_dqblk {
	qsize_t dqb_bhardlimit;
	qsize_t dqb_bsoftlimit;
	qsize_t dqb_curspace;
	qsize_t dqb_rsvspace;
	qsize_t dqb_ihardlimit;
	qsize_t dqb_isoftlimit;
	qsize_t dqb_curinodes;
	time64_t dqb_btime;
	time64_t dqb_itime;
};
struct timer_rand_state {
	long unsigned int last_time;
	long int last_delta;
	long int last_delta2;
};
struct timerqueue_head {
	struct rb_root_cached rb_root;
};
struct hrtimer_clock_base {
	struct hrtimer_cpu_base *cpu_base;
	unsigned int index;
	clockid_t clockid;
	seqcount_raw_spinlock_t seq;
	struct hrtimer *running;
	struct timerqueue_head active;
	ktime_t (*get_time)(void);
	ktime_t offset;
};
struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};
struct timespec64 {
	time64_t tv_sec;
	long int tv_nsec;
};
struct timens_offsets {
	struct timespec64 monotonic;
	struct timespec64 boottime;
};
struct time_namespace {
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
	struct timens_offsets offsets;
	struct page *vvar_page;
	bool frozen_offsets;
};
enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};
struct timewait_sock_ops {
	struct kmem_cache *twsk_slab;
	char *twsk_slab_name;
	unsigned int twsk_obj_size;
	int (*twsk_unique)(struct sock *, struct sock *, void *);
	void (*twsk_destructor)(struct sock *);
};
struct tlbflush_unmap_batch {
	struct arch_tlbflush_unmap_batch arch;
	bool flush_required;
	bool writable;
};
struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};
struct trace_eval_map {
	const char *system;
	const char *eval_string;
	long unsigned int eval_value;
};
struct trace_event {
	struct hlist_node node;
	int type;
	struct trace_event_functions *funcs;
};
struct trace_event_call {
	struct list_head list;
	struct trace_event_class *class;
	union {
		const char *name;
		struct tracepoint *tp;
	};
	struct trace_event event;
	char *print_fmt;
	struct event_filter *filter;
	union {
		void *module;
		atomic_t refcnt;
	};
	void *data;
	int flags;
	int perf_refcount;
	struct hlist_head *perf_events;
	struct bpf_prog_array *prog_array;
	int (*perf_perm)(struct trace_event_call *, struct perf_event *);
};
struct trace_event_fields {
	const char *type;
	union {
		struct {
			const char *name;
			const int size;
			const int align;
			const unsigned int is_signed: 1;
			unsigned int needs_test: 1;
			const int filter_type;
			const int len;
		};
		int (*define_fields)(struct trace_event_call *);
	};
};
struct trace_event_file {
	struct list_head list;
	struct trace_event_call *event_call;
	struct event_filter *filter;
	struct eventfs_inode *ei;
	struct trace_array *tr;
	struct trace_subsystem_dir *system;
	struct list_head triggers;
	long unsigned int flags;
	atomic_t ref;
	atomic_t sm_ref;
	atomic_t tm_ref;
};
struct trace_option_dentry {
	struct tracer_opt *opt;
	struct tracer_flags *flags;
	struct trace_array *tr;
	struct dentry *entry;
};
struct trace_options {
	struct tracer *tracer;
	struct trace_option_dentry *topts;
};
typedef enum print_line_t (*trace_print_func)(struct trace_iterator *, int, struct trace_event *);
struct trace_event_functions {
	trace_print_func trace;
	trace_print_func raw;
	trace_print_func hex;
	trace_print_func binary;
};
enum trace_reg {
	TRACE_REG_REGISTER = 0,
	TRACE_REG_UNREGISTER = 1,
	TRACE_REG_PERF_REGISTER = 2,
	TRACE_REG_PERF_UNREGISTER = 3,
	TRACE_REG_PERF_OPEN = 4,
	TRACE_REG_PERF_CLOSE = 5,
	TRACE_REG_PERF_ADD = 6,
	TRACE_REG_PERF_DEL = 7,
};
struct trace_event_class {
	const char *system;
	void *probe;
	void *perf_probe;
	int (*reg)(struct trace_event_call *, enum trace_reg, void *);
	struct trace_event_fields *fields_array;
	struct list_head * (*get_fields)(struct trace_event_call *);
	struct list_head fields;
	int (*raw_init)(struct trace_event_call *);
};
struct trace_seq {
	char buffer[8156];
	struct seq_buf seq;
	size_t readpos;
	int full;
};
struct trace_subsystem_dir {
	struct list_head list;
	struct event_subsystem *subsystem;
	struct trace_array *tr;
	struct eventfs_inode *ei;
	int ref_count;
	int nr_events;
};
struct tracepoint {
	const char *name;
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	void *probestub;
	int (*regfunc)(void);
	void (*unregfunc)(void);
	struct tracepoint_func *funcs;
};
struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};
typedef const int tracepoint_ptr_t;
struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
};
struct tty_port_operations {
	bool (*carrier_raised)(struct tty_port *);
	void (*dtr_rts)(struct tty_port *, bool);
	void (*shutdown)(struct tty_port *);
	int (*activate)(struct tty_port *, struct tty_struct *);
	void (*destruct)(struct tty_port *);
};
typedef __u128 u128;
typedef u128 freelist_full_t;
typedef union {
	struct {
		void *freelist;
		long unsigned int counter;
	};
	freelist_full_t full;
} freelist_aba_t;
struct kmem_cache_cpu {
	union {
		struct {
			void **freelist;
			long unsigned int tid;
		};
		freelist_aba_t freelist_tid;
	};
	struct slab *slab;
	struct slab *partial;
	local_lock_t lock;
};
struct slab {
	long unsigned int __page_flags;
	struct kmem_cache *slab_cache;
	union {
		struct {
			union {
				struct list_head slab_list;
				struct {
					struct slab *next;
					int slabs;
				};
			};
			union {
				struct {
					void *freelist;
					union {
						long unsigned int counters;
						struct {
							unsigned int inuse: 16;
							unsigned int objects: 15;
							unsigned int frozen: 1;
						};
					};
				};
				freelist_aba_t freelist_counter;
			};
		};
		struct callback_head callback_head;
	};
	unsigned int __unused;
	atomic_t __page_refcount;
	long unsigned int memcg_data;
};
typedef __u16 u16;
struct __call_single_node {
	struct llist_node llist;
	union {
		unsigned int u_flags;
		atomic_t a_flags;
	};
	u16 src;
	u16 dst;
};
struct __call_single_data {
	struct __call_single_node node;
	smp_call_func_t func;
	void *info;
};
struct aa_net_compat {
	u16 allow[46];
	u16 audit[46];
	u16 quiet[46];
};
struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
	bool called: 1;
	bool verified: 1;
};
struct bpf_kfunc_btf {
	struct btf *btf;
	struct module *module;
	u16 offset;
};
typedef struct __call_single_data call_single_data_t;
struct desc_struct {
	u16 limit0;
	u16 base0;
	u16 base1: 8;
	u16 type: 4;
	u16 s: 1;
	u16 dpl: 2;
	u16 p: 1;
	u16 limit1: 4;
	u16 avl: 1;
	u16 l: 1;
	u16 d: 1;
	u16 g: 1;
	u16 base2: 8;
};
struct irq_work {
	struct __call_single_node node;
	void (*func)(struct irq_work *);
	struct rcuwait irqwait;
};
struct bpf_mem_cache {
	struct llist_head free_llist;
	local_t active;
	struct llist_head free_llist_extra;
	struct irq_work refill_work;
	struct obj_cgroup *objcg;
	int unit_size;
	int free_cnt;
	int low_watermark;
	int high_watermark;
	int batch;
	int percpu_size;
	bool draining;
	struct bpf_mem_cache *tgt;
	struct llist_head free_by_rcu;
	struct llist_node *free_by_rcu_tail;
	struct llist_head waiting_for_gp;
	struct llist_node *waiting_for_gp_tail;
	struct callback_head rcu;
	atomic_t call_rcu_in_progress;
	struct llist_head free_llist_extra_rcu;
	struct llist_head free_by_rcu_ttrace;
	struct llist_head waiting_for_gp_ttrace;
	struct callback_head rcu_ttrace;
	atomic_t call_rcu_ttrace_in_progress;
};
struct bpf_mem_caches {
	struct bpf_mem_cache cache[11];
};
struct keyring_index_key {
	long unsigned int hash;
	union {
		struct {
			u16 desc_len;
			char desc[6];
		};
		long unsigned int x;
	};
	struct key_type *type;
	struct key_tag *domain_tag;
	const char *description;
};
struct kiocb {
	struct file *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	union {
		struct wait_page_queue *ki_waitq;
		ssize_t (*dio_complete)(void *);
	};
};
struct nf_hook_entries {
	u16 num_hook_entries;
	struct nf_hook_entry hooks[0];
};
struct sock_fprog_kern {
	u16 len;
	struct sock_filter *filter;
};
struct sock_reuseport {
	struct callback_head rcu;
	u16 max_socks;
	u16 num_socks;
	u16 num_closed_socks;
	u16 incoming_cpu;
	unsigned int synq_overflow_ts;
	unsigned int reuseport_id;
	unsigned int bind_inany: 1;
	unsigned int has_conns: 1;
	struct bpf_prog *prog;
	struct sock *socks[0];
};
struct swap_iocb {
	struct kiocb iocb;
	struct bio_vec bvec[32];
	int pages;
	int len;
};
typedef __u32 u32;
typedef u32 __kernel_dev_t;
struct aa_dfa {
	struct kref count;
	u16 flags;
	u32 max_oob;
	struct table_header *tables[8];
};
struct aa_perms {
	u32 allow;
	u32 deny;
	u32 subtree;
	u32 cond;
	u32 kill;
	u32 complain;
	u32 prompt;
	u32 audit;
	u32 quiet;
	u32 hide;
	u32 xindex;
	u32 tag;
	u32 label;
};
struct aa_policydb {
	struct kref count;
	struct aa_dfa *dfa;
	struct {
		struct aa_perms *perms;
		u32 size;
	};
	struct aa_str_table trans;
	unsigned int start[33];
};
struct ack_sample {
	u32 pkts_acked;
	s32 rtt_us;
	u32 in_flight;
};
struct bpf_active_lock {
	void *ptr;
	u32 id;
};
struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	u32 btf_id;
};
struct bpf_id_pair {
	u32 old;
	u32 cur;
};
struct bpf_idmap {
	u32 tmp_id_gen;
	struct bpf_id_pair map[600];
};
struct bpf_idset {
	u32 count;
	u32 ids[600];
};
struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	bool is_ldsx;
	union {
		int ctx_field_size;
		struct {
			struct btf *btf;
			u32 btf_id;
		};
	};
	struct bpf_verifier_log *log;
	bool is_retval;
};
struct bpf_iter_aux_info {
	struct bpf_map *map;
	struct {
		struct cgroup *start;
		enum bpf_cgroup_iter_order order;
	} cgroup;
	struct {
		enum bpf_iter_task_type type;
		u32 pid;
	} task;
};
struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};
struct bpf_jmp_history_entry {
	u32 idx;
	u32 prev_idx: 22;
	u32 flags: 10;
};
struct bpf_kfunc_btf_tab {
	struct bpf_kfunc_btf descs[256];
	u32 nr_descs;
};
struct bpf_loop_inline_state {
	unsigned int initialized: 1;
	unsigned int fit_for_inline: 1;
	u32 callback_subprogno;
};
struct bpf_prog_offload {
	struct bpf_prog *prog;
	void *netdev;
	struct bpf_offload_dev *offdev;
	void *dev_priv;
	struct list_head offloads;
	bool dev_state;
	bool opt_failed;
	void *jited_image;
	u32 jited_len;
};
struct bpf_prog_offload_ops {
	int (*insn_hook)(struct bpf_verifier_env *, int, int);
	int (*finalize)(struct bpf_verifier_env *);
	int (*replace_insn)(struct bpf_verifier_env *, u32, struct bpf_insn *);
	int (*remove_insns)(struct bpf_verifier_env *, u32, u32);
	int (*prepare)(struct bpf_prog *);
	int (*translate)(struct bpf_prog *);
	void (*destroy)(struct bpf_prog *);
};
struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};
struct bpf_subprog_arg_info {
	enum bpf_arg_type arg_type;
	union {
		u32 mem_size;
	};
};
struct bpf_verifier_ops {
	const struct bpf_func_proto * (*get_func_proto)(enum bpf_func_id, const struct bpf_prog *);
	bool (*is_valid_access)(int, int, enum bpf_access_type, const struct bpf_prog *, struct bpf_insn_access_aux *);
	int (*gen_prologue)(struct bpf_insn *, bool, const struct bpf_prog *);
	int (*gen_ld_abs)(const struct bpf_insn *, struct bpf_insn *);
	u32 (*convert_ctx_access)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);
	int (*btf_struct_access)(struct bpf_verifier_log *, const struct bpf_reg_state *, int, int);
};
struct bpf_verifier_state {
	struct bpf_func_state *frame[8];
	struct bpf_verifier_state *parent;
	u32 branches;
	u32 insn_idx;
	u32 curframe;
	struct bpf_active_lock active_lock;
	bool speculative;
	bool active_rcu_lock;
	bool used_as_loop_entry;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_verifier_state *loop_entry;
	struct bpf_jmp_history_entry *jmp_history;
	u32 jmp_history_cnt;
	u32 dfs_depth;
	u32 callback_unroll_depth;
};
struct bpf_verifier_stack_elem {
	struct bpf_verifier_state st;
	int insn_idx;
	int prev_insn_idx;
	struct bpf_verifier_stack_elem *next;
	u32 log_pos;
};
struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
	int miss_cnt;
	int hit_cnt;
};
struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct callback_head rcu;
	struct btf_kfunc_set_tab *kfunc_set_tab;
	struct btf_id_dtor_kfunc_tab *dtor_kfunc_tab;
	struct btf_struct_metas *struct_meta_tab;
	struct btf *base_btf;
	u32 start_id;
	u32 start_str_off;
	char name[56];
	bool kernel_btf;
};
struct btf_field_graph_root {
	struct btf *btf;
	u32 value_btf_id;
	u32 node_offset;
	struct btf_record *value_rec;
};
struct btf_field_kptr {
	struct btf *btf;
	struct module *module;
	btf_dtor_kfunc_t dtor;
	u32 btf_id;
};
struct btf_field {
	u32 offset;
	u32 size;
	enum btf_field_type type;
	union {
		struct btf_field_kptr kptr;
		struct btf_field_graph_root graph_root;
	};
};
struct btf_id_dtor_kfunc {
	u32 btf_id;
	u32 kfunc_btf_id;
};
struct btf_id_dtor_kfunc_tab {
	u32 cnt;
	struct btf_id_dtor_kfunc dtors[0];
};
struct btf_id_set8 {
	u32 cnt;
	u32 flags;
	struct {
		u32 id;
		u32 flags;
	} pairs[0];
};
typedef int (*btf_kfunc_filter_t)(const struct bpf_prog *, u32);
struct btf_kfunc_hook_filter {
	btf_kfunc_filter_t filters[16];
	u32 nr_filters;
};
struct btf_kfunc_set_tab {
	struct btf_id_set8 *sets[13];
	struct btf_kfunc_hook_filter hook_filters[13];
};
struct btf_record {
	u32 cnt;
	u32 field_mask;
	int spin_lock_off;
	int timer_off;
	int refcount_off;
	struct btf_field fields[0];
};
struct btf_struct_meta {
	u32 btf_id;
	struct btf_record *record;
};
struct btf_struct_metas {
	u32 cnt;
	struct btf_struct_meta types[0];
};
struct bucket_table {
	unsigned int size;
	unsigned int nest;
	u32 hash_rnd;
	struct list_head walkers;
	struct callback_head rcu;
	struct bucket_table *future_tbl;
	struct lockdep_map dep_map;
	long: 64;
	struct rhash_lock_head *buckets[0];
};
typedef u32 compat_uptr_t;
struct compat_robust_list {
	compat_uptr_t next;
};
struct compat_robust_list_head {
	struct compat_robust_list list;
	compat_long_t futex_offset;
	compat_uptr_t list_op_pending;
};
struct crypto_spawn {
	struct list_head list;
	struct crypto_alg *alg;
	union {
		struct crypto_instance *inst;
		struct crypto_spawn *next;
	};
	const struct crypto_type *frontend;
	u32 mask;
	bool dead;
	bool registered;
};
struct crypto_tfm {
	refcount_t refcnt;
	u32 crt_flags;
	int node;
	void (*exit)(struct crypto_tfm *);
	struct crypto_alg *__crt_alg;
	void *__crt_ctx[0];
};
struct crypto_shash {
	unsigned int descsize;
	struct crypto_tfm base;
};
struct crypto_skcipher {
	unsigned int reqsize;
	struct crypto_tfm base;
};
struct crypto_type {
	unsigned int (*ctxsize)(struct crypto_alg *, u32, u32);
	unsigned int (*extsize)(struct crypto_alg *);
	int (*init_tfm)(struct crypto_tfm *);
	void (*show)(struct seq_file *, struct crypto_alg *);
	int (*report)(struct sk_buff *, struct crypto_alg *);
	void (*free)(struct crypto_instance *);
	int (*report_stat)(struct sk_buff *, struct crypto_alg *);
	unsigned int type;
	unsigned int maskclear;
	unsigned int maskset;
	unsigned int tfmsize;
};
typedef __kernel_dev_t dev_t;
struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};
struct dst_metrics {
	u32 metrics[17];
	refcount_t refcnt;
};
typedef u32 errseq_t;
struct fib_lookup_arg {
	void *lookup_ptr;
	const void *lookup_data;
	void *result;
	struct fib_rule *rule;
	u32 table;
	int flags;
};
struct fib_nh_exception {
	struct fib_nh_exception *fnhe_next;
	int fnhe_genid;
	__be32 fnhe_daddr;
	u32 fnhe_pmtu;
	bool fnhe_mtu_locked;
	__be32 fnhe_gw;
	long unsigned int fnhe_expires;
	struct rtable *fnhe_rth_input;
	struct rtable *fnhe_rth_output;
	long unsigned int fnhe_stamp;
	struct callback_head rcu;
};
struct fib_table {
	struct hlist_node tb_hlist;
	u32 tb_id;
	int tb_num_default;
	struct callback_head rcu;
	long unsigned int *tb_data;
	long unsigned int __data[0];
};
struct fileattr {
	u32 flags;
	u32 fsx_xflags;
	u32 fsx_extsize;
	u32 fsx_nextents;
	u32 fsx_projid;
	u32 fsx_cowextsize;
	bool flags_valid: 1;
	bool fsx_valid: 1;
};
struct frag_v4_compare_key {
	__be32 saddr;
	__be32 daddr;
	u32 user;
	u32 vif;
	__be16 id;
	u16 protocol;
};
struct frag_v6_compare_key {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u32 user;
	__be32 id;
	u32 iif;
};
struct fregs_state {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u32 status;
};
struct io_uring {
	u32 head;
	u32 tail;
};
struct io_rings {
	struct io_uring sq;
	struct io_uring cq;
	u32 sq_ring_mask;
	u32 cq_ring_mask;
	u32 sq_ring_entries;
	u32 cq_ring_entries;
	u32 sq_dropped;
	atomic_t sq_flags;
	u32 cq_flags;
	u32 cq_overflow;
	long: 64;
	long: 64;
	struct io_uring_cqe cqes[0];
};
struct ioapic_alloc_info {
	int pin;
	int node;
	u32 is_level: 1;
	u32 active_low: 1;
	u32 valid: 1;
};
struct iommu_device {
	struct list_head list;
	const struct iommu_ops *ops;
	struct fwnode_handle *fwnode;
	struct device *dev;
	struct iommu_group *singleton_group;
	u32 max_pasids;
};
struct iommu_fwspec {
	const struct iommu_ops *ops;
	struct fwnode_handle *iommu_fwnode;
	u32 flags;
	unsigned int num_ids;
	u32 ids[0];
};
struct iommu_mm_data {
	u32 pasid;
	struct list_head sva_domains;
	struct list_head sva_handles;
};
struct iommu_ops {
	bool (*capable)(struct device *, enum iommu_cap);
	void * (*hw_info)(struct device *, u32 *, u32 *);
	struct iommu_domain * (*domain_alloc)(unsigned int);
	struct iommu_domain * (*domain_alloc_user)(struct device *, u32, struct iommu_domain *, const struct iommu_user_data *);
	struct iommu_domain * (*domain_alloc_paging)(struct device *);
	struct iommu_device * (*probe_device)(struct device *);
	void (*release_device)(struct device *);
	void (*probe_finalize)(struct device *);
	struct iommu_group * (*device_group)(struct device *);
	void (*get_resv_regions)(struct device *, struct list_head *);
	int (*of_xlate)(struct device *, struct of_phandle_args *);
	bool (*is_attach_deferred)(struct device *);
	int (*dev_enable_feat)(struct device *, enum iommu_dev_features);
	int (*dev_disable_feat)(struct device *, enum iommu_dev_features);
	int (*page_response)(struct device *, struct iommu_fault_event *, struct iommu_page_response *);
	int (*def_domain_type)(struct device *);
	void (*remove_dev_pasid)(struct device *, ioasid_t);
	const struct iommu_domain_ops *default_domain_ops;
	long unsigned int pgsize_bitmap;
	struct module *owner;
	struct iommu_domain *identity_domain;
	struct iommu_domain *blocked_domain;
	struct iommu_domain *release_domain;
	struct iommu_domain *default_domain;
};
struct iommu_user_data_array {
	unsigned int type;
	void *uptr;
	size_t entry_len;
	u32 entry_num;
};
struct irq_chip_type {
	struct irq_chip chip;
	struct irq_chip_regs regs;
	irq_flow_handler_t handler;
	u32 type;
	u32 mask_cache_priv;
	u32 *mask_cache;
};
struct irq_data {
	u32 mask;
	unsigned int irq;
	long unsigned int hwirq;
	struct irq_common_data *common;
	struct irq_chip *chip;
	struct irq_domain *domain;
	struct irq_data *parent_data;
	void *chip_data;
};
struct irq_domain_ops {
	int (*match)(struct irq_domain *, struct device_node *, enum irq_domain_bus_token);
	int (*select)(struct irq_domain *, struct irq_fwspec *, enum irq_domain_bus_token);
	int (*map)(struct irq_domain *, unsigned int, irq_hw_number_t);
	void (*unmap)(struct irq_domain *, unsigned int);
	int (*xlate)(struct irq_domain *, struct device_node *, const u32 *, unsigned int, long unsigned int *, unsigned int *);
	int (*alloc)(struct irq_domain *, unsigned int, unsigned int, void *);
	void (*free)(struct irq_domain *, unsigned int, unsigned int);
	int (*activate)(struct irq_domain *, struct irq_data *, bool);
	void (*deactivate)(struct irq_domain *, struct irq_data *);
	int (*translate)(struct irq_domain *, struct irq_fwspec *, long unsigned int *, unsigned int *);
};
struct irq_fwspec {
	struct fwnode_handle *fwnode;
	int param_count;
	u32 param[16];
};
struct load_weight {
	long unsigned int weight;
	u32 inv_weight;
};
struct local_ports {
	u32 range;
	bool warned;
};
struct lsmblob_bpf {
	u32 secid;
};
struct lsmblob_selinux {
	u32 secid;
};
struct lsmblob {
	struct lsmblob_selinux selinux;
	struct lsmblob_smack smack;
	struct lsmblob_apparmor apparmor;
	struct lsmblob_bpf bpf;
};
struct msi_domain_info {
	u32 flags;
	enum irq_domain_bus_token bus_token;
	unsigned int hwsize;
	struct msi_domain_ops *ops;
	struct irq_chip *chip;
	void *chip_data;
	irq_flow_handler_t handler;
	void *handler_data;
	const char *handler_name;
	void *data;
};
struct msi_parent_ops {
	u32 supported_flags;
	const char *prefix;
	bool (*init_dev_msi_info)(struct device *, struct irq_domain *, struct irq_domain *, struct msi_domain_info *);
};
struct neigh_parms {
	possible_net_t net;
	void *dev;
	netdevice_tracker dev_tracker;
	struct list_head list;
	int (*neigh_setup)(struct neighbour *);
	struct neigh_table *tbl;
	void *sysctl_table;
	int dead;
	refcount_t refcnt;
	struct callback_head callback_head;
	int reachable_time;
	u32 qlen;
	int data[14];
	long unsigned int data_state[1];
};
struct netlbl_lsm_secattr {
	u32 flags;
	u32 type;
	char *domain;
	struct netlbl_lsm_cache *cache;
	struct {
		struct {
			struct netlbl_lsm_catmap *cat;
			u32 lvl;
		} mls;
		u32 secid;
	} attr;
};
struct nf_ct_event {
	struct nf_conn *ct;
	u32 portid;
	int report;
};
struct nf_exp_event {
	struct nf_conntrack_expect *exp;
	u32 portid;
	int report;
};
struct nfs_lock_info {
	u32 state;
	struct nlm_lockowner *owner;
	struct list_head list;
};
typedef u32 nlink_t;
struct perf_raw_frag {
	union {
		struct perf_raw_frag *next;
		long unsigned int pad;
	};
	perf_copy_f copy;
	void *data;
	u32 size;
};
struct perf_raw_record {
	struct perf_raw_frag frag;
	u32 size;
};
typedef u32 phandle;
struct pp_alloc_cache {
	u32 count;
	struct page *cache[128];
};
struct proto {
	void (*close)(struct sock *, long int);
	int (*pre_connect)(struct sock *, struct sockaddr *, int);
	int (*connect)(struct sock *, struct sockaddr *, int);
	int (*disconnect)(struct sock *, int);
	struct sock * (*accept)(struct sock *, int, int *, bool);
	int (*ioctl)(struct sock *, int, int *);
	int (*init)(struct sock *);
	void (*destroy)(struct sock *);
	void (*shutdown)(struct sock *, int);
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*keepalive)(struct sock *, int);
	int (*compat_ioctl)(struct sock *, unsigned int, long unsigned int);
	int (*sendmsg)(struct sock *, struct msghdr *, size_t);
	int (*recvmsg)(struct sock *, struct msghdr *, size_t, int, int *);
	void (*splice_eof)(struct socket *);
	int (*bind)(struct sock *, struct sockaddr *, int);
	int (*bind_add)(struct sock *, struct sockaddr *, int);
	int (*backlog_rcv)(struct sock *, struct sk_buff *);
	bool (*bpf_bypass_getsockopt)(int, int);
	void (*release_cb)(struct sock *);
	int (*hash)(struct sock *);
	void (*unhash)(struct sock *);
	void (*rehash)(struct sock *);
	int (*get_port)(struct sock *, short unsigned int);
	void (*put_port)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	unsigned int inuse_idx;
	int (*forward_alloc_get)(const struct sock *);
	bool (*stream_memory_free)(const struct sock *, int);
	bool (*sock_is_readable)(struct sock *);
	void (*enter_memory_pressure)(struct sock *);
	void (*leave_memory_pressure)(struct sock *);
	atomic_long_t *memory_allocated;
	int *per_cpu_fw_alloc;
	struct percpu_counter *sockets_allocated;
	long unsigned int *memory_pressure;
	long int *sysctl_mem;
	int *sysctl_wmem;
	int *sysctl_rmem;
	u32 sysctl_wmem_offset;
	u32 sysctl_rmem_offset;
	int max_header;
	bool no_autobind;
	struct kmem_cache *slab;
	unsigned int obj_size;
	unsigned int ipv6_pinfo_offset;
	slab_flags_t slab_flags;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int *orphan_count;
	struct request_sock_ops *rsk_prot;
	struct timewait_sock_ops *twsk_prot;
	union {
		struct inet_hashinfo *hashinfo;
		struct udp_table *udp_table;
		struct raw_hashinfo *raw_hash;
		struct smc_hashinfo *smc_hash;
	} h;
	struct module *owner;
	char name[32];
	struct list_head node;
	int (*diag_destroy)(struct sock *, int);
};
struct rchan {
	u32 version;
	size_t subbuf_size;
	size_t n_subbufs;
	size_t alloc_size;
	const struct rchan_callbacks *cb;
	struct kref kref;
	void *private_data;
	size_t last_toobig;
	struct rchan_buf **buf;
	int is_global;
	struct list_head list;
	struct dentry *parent;
	int has_base_filename;
	char base_filename[255];
};
typedef u32 (*rht_hashfn_t)(const void *, u32, u32);
typedef u32 (*rht_obj_hashfn_t)(const void *, u32, u32);
struct rhashtable_params {
	u16 nelem_hint;
	u16 key_len;
	u16 key_offset;
	u16 head_offset;
	unsigned int max_size;
	u16 min_size;
	bool automatic_shrinking;
	rht_hashfn_t hashfn;
	rht_obj_hashfn_t obj_hashfn;
	rht_obj_cmpfn_t obj_cmpfn;
};
struct ring_buffer_event {
	u32 type_len: 5;
	u32 time_delta: 27;
	u32 array[0];
};
struct rt6_info {
	struct dst_entry dst;
	struct fib6_info *from;
	int sernum;
	struct rt6key rt6i_dst;
	struct rt6key rt6i_src;
	struct in6_addr rt6i_gateway;
	struct inet6_dev *rt6i_idev;
	u32 rt6i_flags;
	short unsigned int rt6i_nfheader_len;
};
struct sk_psock_work_state {
	u32 len;
	u32 off;
};
struct sock_cgroup_data {
	struct cgroup *cgroup;
	u32 classid;
	u16 prioidx;
};
struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse: 4;
	unsigned char skc_reuseport: 1;
	unsigned char skc_ipv6only: 1;
	unsigned char skc_net_refcnt: 1;
	int skc_bound_dev_if;
	union {
		struct hlist_node skc_bind_node;
		struct hlist_node skc_portaddr_node;
	};
	struct proto *skc_prot;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
	atomic64_t skc_cookie;
	union {
		long unsigned int skc_flags;
		struct sock *skc_listener;
		struct inet_timewait_death_row *skc_tw_dr;
	};
	int skc_dontcopy_begin[0];
	union {
		struct hlist_node skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	short unsigned int skc_tx_queue_mapping;
	short unsigned int skc_rx_queue_mapping;
	union {
		int skc_incoming_cpu;
		u32 skc_rcv_wnd;
		u32 skc_tw_rcv_nxt;
	};
	refcount_t skc_refcnt;
	int skc_dontcopy_end[0];
	union {
		u32 skc_rxhash;
		u32 skc_window_clamp;
		u32 skc_tw_snd_nxt;
	};
};
struct table_header {
	u16 td_id;
	u16 td_flags;
	u32 td_hilen;
	u32 td_lolen;
	char td_data[0];
};
struct thread_info {
	long unsigned int flags;
	long unsigned int syscall_work;
	u32 status;
	u32 cpu;
};
struct timer_list {
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
};
struct cgroup_file {
	struct kernfs_node *kn;
	long unsigned int notified_at;
	struct timer_list notify_timer;
};
struct throtl_service_queue {
	struct throtl_service_queue *parent_sq;
	struct list_head queued[2];
	unsigned int nr_queued[2];
	struct rb_root_cached pending_tree;
	unsigned int nr_pending;
	long unsigned int first_pending_disptime;
	struct timer_list pending_timer;
};
struct tracer {
	const char *name;
	int (*init)(struct trace_array *);
	void (*reset)(struct trace_array *);
	void (*start)(struct trace_array *);
	void (*stop)(struct trace_array *);
	int (*update_thresh)(struct trace_array *);
	void (*open)(struct trace_iterator *);
	void (*pipe_open)(struct trace_iterator *);
	void (*close)(struct trace_iterator *);
	void (*pipe_close)(struct trace_iterator *);
	ssize_t (*read)(struct trace_iterator *, struct file *, char *, size_t, loff_t *);
	ssize_t (*splice_read)(struct trace_iterator *, struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*print_header)(struct seq_file *);
	enum print_line_t (*print_line)(struct trace_iterator *);
	int (*set_flag)(struct trace_array *, u32, u32, int);
	int (*flag_changed)(struct trace_array *, u32, int);
	struct tracer *next;
	struct tracer_flags *flags;
	int enabled;
	bool print_max;
	bool allow_instances;
	bool use_max_tr;
	bool noboot;
};
struct tracer_flags {
	u32 val;
	struct tracer_opt *opts;
	struct tracer *trace;
};
struct tracer_opt {
	const char *name;
	u32 bit;
};
typedef __u64 u64;
struct aa_label {
	struct kref count;
	struct rb_node node;
	struct callback_head rcu;
	struct aa_proxy *proxy;
	char *hname;
	long int flags;
	u32 secid;
	int size;
	u64 mediates;
	struct aa_profile *vec[0];
};
struct array_buffer {
	struct trace_array *tr;
	struct trace_buffer *buffer;
	struct trace_array_cpu *data;
	u64 time_start;
	int cpu;
};
struct backtrack_state {
	struct bpf_verifier_env *env;
	u32 frame;
	u32 reg_masks[8];
	u64 stack_masks[8];
};
struct bio_crypt_ctx {
	const struct blk_crypto_key *bc_key;
	u64 bc_dun[4];
};
struct bio_issue {
	u64 value;
};
struct blk_trace {
	int trace_state;
	struct rchan *rchan;
	long unsigned int *sequence;
	unsigned char *msg_data;
	u16 act_mask;
	u64 start_lba;
	u64 end_lba;
	u32 pid;
	u32 dev;
	struct dentry *dir;
	struct list_head running_list;
	atomic_t dropped;
};
typedef u64 blkcnt_t;
struct blkg_iostat {
	u64 bytes[3];
	u64 ios[3];
};
typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);
struct bpf_func_proto {
	u64 (*func)(u64, u64, u64, u64, u64);
	bool gpl_only;
	bool pkt_access;
	bool might_sleep;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
		struct {
			size_t arg1_size;
			size_t arg2_size;
			size_t arg3_size;
			size_t arg4_size;
			size_t arg5_size;
		};
		size_t arg_size[5];
	};
	int *ret_btf_id;
	bool (*allowed)(const struct bpf_prog *);
};
struct bpf_map_ops {
	int (*map_alloc_check)(union bpf_attr *);
	struct bpf_map * (*map_alloc)(union bpf_attr *);
	void (*map_release)(struct bpf_map *, struct file *);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *, void *, void *);
	void (*map_release_uref)(struct bpf_map *);
	void * (*map_lookup_elem_sys_only)(struct bpf_map *, void *);
	int (*map_lookup_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_lookup_and_delete_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_lookup_and_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_update_batch)(struct bpf_map *, struct file *, const union bpf_attr *, union bpf_attr *);
	int (*map_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	void * (*map_lookup_elem)(struct bpf_map *, void *);
	long int (*map_update_elem)(struct bpf_map *, void *, void *, u64);
	long int (*map_delete_elem)(struct bpf_map *, void *);
	long int (*map_push_elem)(struct bpf_map *, void *, u64);
	long int (*map_pop_elem)(struct bpf_map *, void *);
	long int (*map_peek_elem)(struct bpf_map *, void *);
	void * (*map_lookup_percpu_elem)(struct bpf_map *, void *, u32);
	void * (*map_fd_get_ptr)(struct bpf_map *, struct file *, int);
	void (*map_fd_put_ptr)(struct bpf_map *, void *, bool);
	int (*map_gen_lookup)(struct bpf_map *, struct bpf_insn *);
	u32 (*map_fd_sys_lookup_elem)(void *);
	void (*map_seq_show_elem)(struct bpf_map *, void *, struct seq_file *);
	int (*map_check_btf)(const struct bpf_map *, const struct btf *, const struct btf_type *, const struct btf_type *);
	int (*map_poke_track)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_untrack)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_run)(struct bpf_map *, u32, struct bpf_prog *, struct bpf_prog *);
	int (*map_direct_value_addr)(const struct bpf_map *, u64 *, u32);
	int (*map_direct_value_meta)(const struct bpf_map *, u64, u32 *);
	int (*map_mmap)(struct bpf_map *, struct vm_area_struct *);
	__poll_t (*map_poll)(struct bpf_map *, struct file *, struct poll_table_struct *);
	int (*map_local_storage_charge)(struct bpf_local_storage_map *, void *, u32);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *, void *, u32);
	struct bpf_local_storage ** (*map_owner_storage_ptr)(void *);
	long int (*map_redirect)(struct bpf_map *, u64, u64);
	bool (*map_meta_equal)(const struct bpf_map *, const struct bpf_map *);
	int (*map_set_for_each_callback_args)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *);
	long int (*map_for_each_callback)(struct bpf_map *, bpf_callback_t, void *, u64);
	u64 (*map_mem_usage)(const struct bpf_map *);
	int *map_btf_id;
	const struct bpf_iter_seq_info *iter_seq_info;
};
struct bpf_prog_array_item {
	struct bpf_prog *prog;
	union {
		struct bpf_cgroup_storage *cgroup_storage[2];
		u64 bpf_cookie;
	};
};
struct bpf_prog_array {
	struct callback_head rcu;
	struct bpf_prog_array_item items[0];
};
struct bpf_verifier_log {
	u64 start_pos;
	u64 end_pos;
	char *ubuf;
	u32 level;
	u32 len_total;
	u32 len_max;
	char kbuf[1024];
};
struct buffer_data_page {
	u64 time_stamp;
	local_t commit;
	unsigned char data[0];
};
struct cftype {
	char name[64];
	long unsigned int private;
	size_t max_write_len;
	unsigned int flags;
	unsigned int file_offset;
	struct cgroup_subsys *ss;
	struct list_head node;
	struct kernfs_ops *kf_ops;
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	u64 (*read_u64)(struct cgroup_subsys_state *, struct cftype *);
	s64 (*read_s64)(struct cgroup_subsys_state *, struct cftype *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	int (*write_u64)(struct cgroup_subsys_state *, struct cftype *, u64);
	int (*write_s64)(struct cgroup_subsys_state *, struct cftype *, s64);
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
};
struct cpu_itimer {
	u64 expires;
	u64 incr;
};
struct cpudl_item {
	u64 dl;
	int cpu;
	int idx;
};
struct cpuidle_state_usage {
	long long unsigned int disable;
	long long unsigned int usage;
	u64 time_ns;
	long long unsigned int above;
	long long unsigned int below;
	long long unsigned int rejected;
	long long unsigned int s2idle_usage;
	long long unsigned int s2idle_time;
};
struct cpuidle_device {
	unsigned int registered: 1;
	unsigned int enabled: 1;
	unsigned int poll_time_limit: 1;
	unsigned int cpu;
	ktime_t next_hrtimer;
	int last_state_idx;
	u64 last_residency_ns;
	u64 poll_limit_ns;
	u64 forced_idle_latency_limit_ns;
	struct cpuidle_state_usage states_usage[10];
	struct cpuidle_state_kobj *kobjs[10];
	struct cpuidle_driver_kobj *kobj_driver;
	struct cpuidle_device_kobj *kobj_dev;
	struct list_head device_list;
};
struct dax_holder_operations {
	int (*notify_failure)(struct dax_device *, u64, u64, int);
};
struct disk_stats {
	u64 nsecs[4];
	long unsigned int sectors[4];
	long unsigned int ios[4];
	long unsigned int merges[4];
	long unsigned int io_ticks;
	local_t in_flight[2];
};
struct dl_rq {
	struct rb_root_cached root;
	unsigned int dl_nr_running;
	struct {
		u64 curr;
		u64 next;
	} earliest_dl;
	int overloaded;
	struct rb_root_cached pushable_dl_tasks_root;
	u64 running_bw;
	u64 this_bw;
	u64 extra_bw;
	u64 max_bw;
	u64 bw_ratio;
};
typedef u64 dma_addr_t;
struct elevator_mq_ops {
	int (*init_sched)(struct request_queue *, struct elevator_type *);
	void (*exit_sched)(struct elevator_queue *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*depth_updated)(struct blk_mq_hw_ctx *);
	bool (*allow_merge)(struct request_queue *, struct request *, struct bio *);
	bool (*bio_merge)(struct request_queue *, struct bio *, unsigned int);
	int (*request_merge)(struct request_queue *, struct request **, struct bio *);
	void (*request_merged)(struct request_queue *, struct request *, enum elv_merge);
	void (*requests_merged)(struct request_queue *, struct request *, struct request *);
	void (*limit_depth)(blk_opf_t, struct blk_mq_alloc_data *);
	void (*prepare_request)(struct request *);
	void (*finish_request)(struct request *);
	void (*insert_requests)(struct blk_mq_hw_ctx *, struct list_head *, blk_insert_t);
	struct request * (*dispatch_request)(struct blk_mq_hw_ctx *);
	bool (*has_work)(struct blk_mq_hw_ctx *);
	void (*completed_request)(struct request *, u64);
	void (*requeue_request)(struct request *);
	struct request * (*former_request)(struct request_queue *, struct request *);
	struct request * (*next_request)(struct request_queue *, struct request *);
	void (*init_icq)(struct io_cq *);
	void (*exit_icq)(struct io_cq *);
};
struct elevator_type {
	struct kmem_cache *icq_cache;
	struct elevator_mq_ops ops;
	size_t icq_size;
	size_t icq_align;
	struct elv_fs_entry *elevator_attrs;
	const char *elevator_name;
	const char *elevator_alias;
	const unsigned int elevator_features;
	struct module *elevator_owner;
	const struct blk_mq_debugfs_attr *queue_debugfs_attrs;
	const struct blk_mq_debugfs_attr *hctx_debugfs_attrs;
	char icq_cache_name[22];
	struct list_head list;
};
struct fid {
	union {
		struct {
			u32 ino;
			u32 gen;
			u32 parent_ino;
			u32 parent_gen;
		} i32;
		struct {
			u64 ino;
			u32 gen;
		} __attribute__((packed)) i64;
		struct {
			u32 block;
			u16 partref;
			u16 parent_partref;
			u32 generation;
			u32 parent_block;
			u32 parent_generation;
		} udf;
		struct {
			struct {} __empty_raw;
			__u32 raw[0];
		};
	};
};
typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);
struct dir_context {
	filldir_t actor;
	loff_t pos;
};
struct filter_pred {
	struct regex *regex;
	struct cpumask *mask;
	short unsigned int *ops;
	struct ftrace_event_field *field;
	u64 val;
	u64 val2;
	enum filter_pred_fn fn_num;
	int offset;
	int not;
	int op;
};
struct fpu_state_perm {
	u64 __state_perm;
	unsigned int __state_size;
	unsigned int __user_state_size;
};
struct fred_cs {
	u64 cs: 16;
	u64 sl: 2;
	u64 wfe: 1;
};
struct fred_ss {
	u64 ss: 16;
	u64 sti: 1;
	u64 swevent: 1;
	u64 nmi: 1;
	int: 13;
	u64 vector: 8;
	short: 8;
	u64 type: 4;
	char: 4;
	u64 enclave: 1;
	u64 lm: 1;
	u64 nested: 1;
	char: 1;
	u64 insnlen: 4;
};
struct fsverity_operations {
	int (*begin_enable_verity)(struct file *);
	int (*end_enable_verity)(struct file *, const void *, size_t, u64);
	int (*get_verity_descriptor)(struct inode *, void *, size_t);
	struct page * (*read_merkle_tree_page)(struct inode *, long unsigned int, long unsigned int);
	int (*write_merkle_tree_block)(struct inode *, const void *, u64, unsigned int);
};
union futex_key {
	struct {
		u64 i_seq;
		long unsigned int pgoff;
		unsigned int offset;
	} shared;
	struct {
		union {
			struct mm_struct *mm;
			u64 __tmp;
		};
		long unsigned int address;
		unsigned int offset;
	} private;
	struct {
		u64 ptr;
		long unsigned int word;
		unsigned int offset;
	} both;
};
struct fwnode_reference_args {
	struct fwnode_handle *fwnode;
	unsigned int nargs;
	u64 args[16];
};
struct fxregs_state {
	u16 cwd;
	u16 swd;
	u16 twd;
	u16 fop;
	union {
		struct {
			u64 rip;
			u64 rdp;
		};
		struct {
			u32 fip;
			u32 fcs;
			u32 foo;
			u32 fos;
		};
	};
	u32 mxcsr;
	u32 mxcsr_mask;
	u32 st_space[32];
	u32 xmm_space[64];
	u32 padding[12];
	union {
		u32 padding1[12];
		u32 sw_reserved[12];
	};
};
struct hw_perf_event_extra {
	u64 config;
	unsigned int reg;
	int alloc;
	int idx;
};
struct io_bitmap {
	u64 sequence;
	refcount_t refcnt;
	unsigned int max;
	long unsigned int bitmap[1024];
};
struct io_mapped_ubuf {
	u64 ubuf;
	u64 ubuf_end;
	unsigned int nr_bvecs;
	long unsigned int acct_pages;
	struct bio_vec bvec[0];
};
struct io_rsrc_data {
	struct io_ring_ctx *ctx;
	u64 **tags;
	unsigned int nr;
	u16 rsrc_type;
	bool quiesce;
};
struct io_rsrc_put {
	u64 tag;
	union {
		void *rsrc;
		struct file *file;
		struct io_mapped_ubuf *buf;
	};
};
struct io_rsrc_node {
	union {
		struct io_cache_entry cache;
		struct io_ring_ctx *ctx;
	};
	int refs;
	bool empty;
	u16 type;
	struct list_head node;
	struct io_rsrc_put item;
};
struct iomap {
	u64 addr;
	loff_t offset;
	u64 length;
	u16 type;
	u16 flags;
	struct block_device *bdev;
	struct dax_device *dax_dev;
	void *inline_data;
	void *private;
	const struct iomap_folio_ops *folio_ops;
	u64 validity_cookie;
};
struct iomap_iter {
	struct inode *inode;
	loff_t pos;
	u64 len;
	s64 processed;
	unsigned int flags;
	struct iomap iomap;
	struct iomap srcmap;
	void *private;
};
struct iommu_domain_geometry {
	dma_addr_t aperture_start;
	dma_addr_t aperture_end;
	bool force_aperture;
};
struct iommu_domain {
	unsigned int type;
	const struct iommu_domain_ops *ops;
	const struct iommu_dirty_ops *dirty_ops;
	const struct iommu_ops *owner;
	long unsigned int pgsize_bitmap;
	struct iommu_domain_geometry geometry;
	struct iommu_dma_cookie *iova_cookie;
	enum iommu_page_response_code (*iopf_handler)(struct iommu_fault *, void *);
	void *fault_data;
	union {
		struct {
			iommu_fault_handler_t handler;
			void *handler_token;
		};
		struct {
			struct mm_struct *mm;
			int users;
			struct list_head next;
		};
	};
};
struct iova_fq_entry {
	long unsigned int iova_pfn;
	long unsigned int pages;
	struct list_head freelist;
	u64 counter;
};
typedef struct {
	u64 val;
} kernel_cap_t;
struct kstatfs {
	long int f_type;
	long int f_bsize;
	u64 f_blocks;
	u64 f_bfree;
	u64 f_bavail;
	u64 f_files;
	u64 f_ffree;
	__kernel_fsid_t f_fsid;
	long int f_namelen;
	long int f_frsize;
	long int f_flags;
	long int f_spare[4];
};
struct mm_cid {
	u64 time;
	int cid;
};
union msi_domain_cookie {
	u64 value;
	void *ptr;
	void *iobase;
};
union msi_instance_cookie {
	u64 value;
	void *ptr;
};
struct msi_desc_data {
	union msi_domain_cookie dcookie;
	union msi_instance_cookie icookie;
};
typedef u64 netdev_features_t;
struct netlbl_lsm_catmap {
	u32 startbit;
	u64 bitmap[4];
	struct netlbl_lsm_catmap *next;
};
struct netlink_range_validation {
	u64 min;
	u64 max;
};
struct notification {
	atomic_t requests;
	u32 flags;
	u64 next_id;
	struct list_head notifications;
};
struct pacct_struct {
	int ac_flag;
	long int ac_exitcode;
	long unsigned int ac_mem;
	u64 ac_utime;
	u64 ac_stime;
	long unsigned int ac_minflt;
	long unsigned int ac_majflt;
};
struct page_pool_alloc_stats {
	u64 fast;
	u64 slow;
	u64 slow_high_order;
	u64 empty;
	u64 refill;
	u64 waive;
};
struct page_pool_recycle_stats {
	u64 cached;
	u64 cache_full;
	u64 ring;
	u64 ring_full;
	u64 released_refcnt;
};
struct perf_cgroup_info {
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	int active;
};
struct perf_event_groups {
	struct rb_root tree;
	u64 index;
};
struct perf_output_handle {
	struct perf_event *event;
	struct perf_buffer *rb;
	long unsigned int wakeup;
	long unsigned int size;
	u64 aux_flags;
	union {
		void *addr;
		long unsigned int head;
	};
	int page;
};
struct perf_sample_data {
	u64 sample_flags;
	u64 period;
	u64 dyn_size;
	u64 type;
	struct {
		u32 pid;
		u32 tid;
	} tid_entry;
	u64 time;
	u64 id;
	struct {
		u32 cpu;
		u32 reserved;
	} cpu_entry;
	u64 ip;
	struct perf_callchain_entry *callchain;
	struct perf_raw_record *raw;
	struct perf_branch_stack *br_stack;
	u64 *br_stack_cntr;
	union perf_sample_weight weight;
	union perf_mem_data_src data_src;
	u64 txn;
	struct perf_regs regs_user;
	struct perf_regs regs_intr;
	u64 stack_user_size;
	u64 stream_id;
	u64 cgroup;
	u64 addr;
	u64 phys_addr;
	u64 data_page_size;
	u64 code_page_size;
	u64 aux_size;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
typedef struct {
	u64 val;
} pfn_t;
typedef u64 phys_addr_t;
struct bus_dma_region {
	phys_addr_t cpu_start;
	dma_addr_t dma_start;
	u64 size;
};
struct dma_map_ops {
	unsigned int flags;
	void * (*alloc)(struct device *, size_t, dma_addr_t *, gfp_t, long unsigned int);
	void (*free)(struct device *, size_t, void *, dma_addr_t, long unsigned int);
	struct page * (*alloc_pages)(struct device *, size_t, dma_addr_t *, enum dma_data_direction, gfp_t);
	void (*free_pages)(struct device *, size_t, struct page *, dma_addr_t, enum dma_data_direction);
	struct sg_table * (*alloc_noncontiguous)(struct device *, size_t, enum dma_data_direction, gfp_t, long unsigned int);
	void (*free_noncontiguous)(struct device *, size_t, struct sg_table *, enum dma_data_direction);
	int (*mmap)(struct device *, struct vm_area_struct *, void *, dma_addr_t, size_t, long unsigned int);
	int (*get_sgtable)(struct device *, struct sg_table *, void *, dma_addr_t, size_t, long unsigned int);
	dma_addr_t (*map_page)(struct device *, struct page *, long unsigned int, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_page)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	int (*map_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	void (*unmap_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	dma_addr_t (*map_resource)(struct device *, phys_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_resource)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*sync_single_for_cpu)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_single_for_device)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_sg_for_cpu)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*sync_sg_for_device)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*cache_sync)(struct device *, void *, size_t, enum dma_data_direction);
	int (*dma_supported)(struct device *, u64);
	u64 (*get_required_mask)(struct device *);
	size_t (*max_mapping_size)(struct device *);
	size_t (*opt_mapping_size)(void);
	long unsigned int (*get_merge_boundary)(struct device *);
};
struct io_tlb_pool {
	phys_addr_t start;
	phys_addr_t end;
	void *vaddr;
	long unsigned int nslabs;
	bool late_alloc;
	unsigned int nareas;
	unsigned int area_nslabs;
	struct io_tlb_area *areas;
	struct io_tlb_slot *slots;
	struct list_head node;
	struct callback_head rcu;
	bool transient;
};
struct io_tlb_slot {
	phys_addr_t orig_addr;
	size_t alloc_size;
	short unsigned int list;
	short unsigned int pad_slots;
};
struct iommu_domain_ops {
	int (*attach_dev)(struct iommu_domain *, struct device *);
	int (*set_dev_pasid)(struct iommu_domain *, struct device *, ioasid_t);
	int (*map_pages)(struct iommu_domain *, long unsigned int, phys_addr_t, size_t, size_t, int, gfp_t, size_t *);
	size_t (*unmap_pages)(struct iommu_domain *, long unsigned int, size_t, size_t, struct iommu_iotlb_gather *);
	void (*flush_iotlb_all)(struct iommu_domain *);
	int (*iotlb_sync_map)(struct iommu_domain *, long unsigned int, size_t);
	void (*iotlb_sync)(struct iommu_domain *, struct iommu_iotlb_gather *);
	int (*cache_invalidate_user)(struct iommu_domain *, struct iommu_user_data_array *);
	phys_addr_t (*iova_to_phys)(struct iommu_domain *, dma_addr_t);
	bool (*enforce_cache_coherency)(struct iommu_domain *);
	int (*enable_nesting)(struct iommu_domain *);
	int (*set_pgtable_quirks)(struct iommu_domain *, long unsigned int);
	void (*free)(struct iommu_domain *);
};
struct pmu {
	struct list_head entry;
	struct module *module;
	struct device *dev;
	struct device *parent;
	const struct attribute_group **attr_groups;
	const struct attribute_group **attr_update;
	const char *name;
	int type;
	int capabilities;
	int *pmu_disable_count;
	struct perf_cpu_pmu_context *cpu_pmu_context;
	atomic_t exclusive_cnt;
	int task_ctx_nr;
	int hrtimer_interval_ms;
	unsigned int nr_addr_filters;
	void (*pmu_enable)(struct pmu *);
	void (*pmu_disable)(struct pmu *);
	int (*event_init)(struct perf_event *);
	void (*event_mapped)(struct perf_event *, struct mm_struct *);
	void (*event_unmapped)(struct perf_event *, struct mm_struct *);
	int (*add)(struct perf_event *, int);
	void (*del)(struct perf_event *, int);
	void (*start)(struct perf_event *, int);
	void (*stop)(struct perf_event *, int);
	void (*read)(struct perf_event *);
	void (*start_txn)(struct pmu *, unsigned int);
	int (*commit_txn)(struct pmu *);
	void (*cancel_txn)(struct pmu *);
	int (*event_idx)(struct perf_event *);
	void (*sched_task)(struct perf_event_pmu_context *, bool);
	struct kmem_cache *task_ctx_cache;
	void (*swap_task_ctx)(struct perf_event_pmu_context *, struct perf_event_pmu_context *);
	void * (*setup_aux)(struct perf_event *, void **, int, bool);
	void (*free_aux)(void *);
	long int (*snapshot_aux)(struct perf_event *, struct perf_output_handle *, long unsigned int);
	int (*addr_filters_validate)(struct list_head *);
	void (*addr_filters_sync)(struct perf_event *);
	int (*aux_output_match)(struct perf_event *);
	bool (*filter)(struct pmu *, int);
	int (*check_period)(struct perf_event *, u64);
};
struct pool_workqueue {
	struct worker_pool *pool;
	struct workqueue_struct *wq;
	int work_color;
	int flush_color;
	int refcnt;
	int nr_in_flight[16];
	int nr_active;
	int max_active;
	struct list_head inactive_works;
	struct list_head pwqs_node;
	struct list_head mayday_node;
	u64 stats[8];
	struct kthread_work release_work;
	struct callback_head rcu;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct posix_cputimer_base {
	u64 nextevt;
	struct timerqueue_head tqhead;
};
struct posix_cputimers {
	struct posix_cputimer_base bases[3];
	unsigned int timers_active;
	unsigned int expiry_active;
};
struct pr_held_reservation {
	u64 key;
	u32 generation;
	enum pr_type type;
};
struct pr_keys {
	u32 generation;
	u32 num_keys;
	u64 keys[0];
};
struct pr_ops {
	int (*pr_register)(struct block_device *, u64, u64, u32);
	int (*pr_reserve)(struct block_device *, u64, enum pr_type, u32);
	int (*pr_release)(struct block_device *, u64, enum pr_type);
	int (*pr_preempt)(struct block_device *, u64, u64, enum pr_type, bool);
	int (*pr_clear)(struct block_device *, u64);
	int (*pr_read_keys)(struct block_device *, struct pr_keys *);
	int (*pr_read_reservation)(struct block_device *, struct pr_held_reservation *);
};
struct psi_group_cpu {
	seqcount_t seq;
	unsigned int tasks[4];
	u32 state_mask;
	u32 times[7];
	u64 state_start;
	u32 times_prev[14];
	long: 64;
};
struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	union {
		u16 cs;
		u64 csx;
		struct fred_cs fred_cs;
	};
	long unsigned int flags;
	long unsigned int sp;
	union {
		u16 ss;
		u64 ssx;
		struct fred_ss fred_ss;
	};
};
struct ftrace_regs {
	struct pt_regs regs;
};
struct qc_dqblk {
	int d_fieldmask;
	u64 d_spc_hardlimit;
	u64 d_spc_softlimit;
	u64 d_ino_hardlimit;
	u64 d_ino_softlimit;
	u64 d_space;
	u64 d_ino_count;
	s64 d_ino_timer;
	s64 d_spc_timer;
	int d_ino_warns;
	int d_spc_warns;
	u64 d_rt_spc_hardlimit;
	u64 d_rt_spc_softlimit;
	u64 d_rt_space;
	s64 d_rt_spc_timer;
	int d_rt_spc_warns;
};
struct qc_type_state {
	unsigned int flags;
	unsigned int spc_timelimit;
	unsigned int ino_timelimit;
	unsigned int rt_spc_timelimit;
	unsigned int spc_warnlimit;
	unsigned int ino_warnlimit;
	unsigned int rt_spc_warnlimit;
	long long unsigned int ino;
	blkcnt_t blocks;
	blkcnt_t nextents;
};
struct qc_state {
	unsigned int s_incoredqs;
	struct qc_type_state s_state[3];
};
struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};
struct range {
	u64 start;
	u64 end;
};
struct rate_sample {
	u64 prior_mstamp;
	u32 prior_delivered;
	u32 prior_delivered_ce;
	s32 delivered;
	s32 delivered_ce;
	long int interval_us;
	u32 snd_interval_us;
	u32 rcv_interval_us;
	long int rtt_us;
	int losses;
	u32 acked_sacked;
	u32 prior_in_flight;
	u32 last_end_seq;
	bool is_app_limited;
	bool is_retrans;
	bool is_ack_delayed;
};
struct restart_block {
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union {
		struct {
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};
struct ring_buffer_iter {
	struct ring_buffer_per_cpu *cpu_buffer;
	long unsigned int head;
	long unsigned int next_event;
	struct buffer_page *head_page;
	struct buffer_page *cache_reader_page;
	long unsigned int cache_read;
	long unsigned int cache_pages_removed;
	u64 read_stamp;
	u64 page_stamp;
	struct ring_buffer_event *event;
	size_t event_size;
	int missed_events;
};
struct rt_waiter_node {
	struct rb_node entry;
	int prio;
	u64 deadline;
};
struct rt_mutex_waiter {
	struct rt_waiter_node tree;
	struct rt_waiter_node pi_tree;
	struct task_struct *task;
	struct rt_mutex_base *lock;
	unsigned int wake_state;
	struct ww_acquire_ctx *ww_ctx;
};
struct scatterlist {
	long unsigned int page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
	unsigned int dma_length;
	unsigned int dma_flags;
};
struct sched_avg {
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_sum;
	u32 util_sum;
	u32 period_contrib;
	long unsigned int load_avg;
	long unsigned int runnable_avg;
	long unsigned int util_avg;
	unsigned int util_est;
};
struct sched_domain {
	struct sched_domain *parent;
	struct sched_domain *child;
	struct sched_group *groups;
	long unsigned int min_interval;
	long unsigned int max_interval;
	unsigned int busy_factor;
	unsigned int imbalance_pct;
	unsigned int cache_nice_tries;
	unsigned int imb_numa_nr;
	int nohz_idle;
	int flags;
	int level;
	long unsigned int last_balance;
	unsigned int balance_interval;
	unsigned int nr_balance_failed;
	u64 max_newidle_lb_cost;
	long unsigned int last_decay_max_lb_cost;
	unsigned int lb_count[3];
	unsigned int lb_failed[3];
	unsigned int lb_balanced[3];
	unsigned int lb_imbalance[3];
	unsigned int lb_gained[3];
	unsigned int lb_hot_gained[3];
	unsigned int lb_nobusyg[3];
	unsigned int lb_nobusyq[3];
	unsigned int alb_count;
	unsigned int alb_failed;
	unsigned int alb_pushed;
	unsigned int sbe_count;
	unsigned int sbe_balanced;
	unsigned int sbe_pushed;
	unsigned int sbf_count;
	unsigned int sbf_balanced;
	unsigned int sbf_pushed;
	unsigned int ttwu_wake_remote;
	unsigned int ttwu_move_affine;
	unsigned int ttwu_move_balance;
	char *name;
	union {
		void *private;
		struct callback_head rcu;
	};
	struct sched_domain_shared *shared;
	unsigned int span_weight;
	long unsigned int span[0];
};
struct sched_entity {
	struct load_weight load;
	struct rb_node run_node;
	u64 deadline;
	u64 min_vruntime;
	struct list_head group_node;
	unsigned int on_rq;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 prev_sum_exec_runtime;
	u64 vruntime;
	s64 vlag;
	u64 slice;
	u64 nr_migrations;
	int depth;
	struct sched_entity *parent;
	struct cfs_rq *cfs_rq;
	struct cfs_rq *my_q;
	long unsigned int runnable_weight;
	long: 64;
	long: 64;
	struct sched_avg avg;
};
struct sched_statistics {
	u64 wait_start;
	u64 wait_max;
	u64 wait_count;
	u64 wait_sum;
	u64 iowait_count;
	u64 iowait_sum;
	u64 sleep_start;
	u64 sleep_max;
	s64 sum_sleep_runtime;
	u64 block_start;
	u64 block_max;
	s64 sum_block_runtime;
	s64 exec_max;
	u64 slice_max;
	u64 nr_migrations_cold;
	u64 nr_failed_migrations_affine;
	u64 nr_failed_migrations_running;
	u64 nr_failed_migrations_hot;
	u64 nr_forced_migrations;
	u64 nr_wakeups;
	u64 nr_wakeups_sync;
	u64 nr_wakeups_migrate;
	u64 nr_wakeups_local;
	u64 nr_wakeups_remote;
	u64 nr_wakeups_affine;
	u64 nr_wakeups_affine_attempts;
	u64 nr_wakeups_passive;
	u64 nr_wakeups_idle;
	u64 core_forceidle_sum;
	long: 64;
	long: 64;
	long: 64;
};
typedef u64 sector_t;
struct address_space_operations {
	int (*writepage)(struct page *, struct writeback_control *);
	int (*read_folio)(struct file *, struct folio *);
	int (*writepages)(struct address_space *, struct writeback_control *);
	bool (*dirty_folio)(struct address_space *, struct folio *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file *, struct address_space *, loff_t, unsigned int, struct page **, void **);
	int (*write_end)(struct file *, struct address_space *, loff_t, unsigned int, unsigned int, struct page *, void *);
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidate_folio)(struct folio *, size_t, size_t);
	bool (*release_folio)(struct folio *, gfp_t);
	void (*free_folio)(struct folio *);
	ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *);
	int (*migrate_folio)(struct address_space *, struct folio *, struct folio *, enum migrate_mode);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio *, bool *, bool *);
	int (*error_remove_folio)(struct address_space *, struct folio *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
	int (*swap_rw)(struct kiocb *, struct iov_iter *);
};
struct blk_independent_access_range {
	struct kobject kobj;
	sector_t sector;
	sector_t nr_sectors;
};
struct blk_independent_access_ranges {
	struct kobject kobj;
	bool sysfs_registered;
	unsigned int nr_ia_ranges;
	struct blk_independent_access_range ia_range[0];
};
struct blk_integrity_iter {
	void *prot_buf;
	void *data_buf;
	sector_t seed;
	unsigned int data_size;
	short unsigned int interval;
	unsigned char tuple_size;
	const char *disk_name;
};
struct bvec_iter {
	sector_t bi_sector;
	unsigned int bi_size;
	unsigned int bi_idx;
	unsigned int bi_bvec_done;
};
struct dax_operations {
	long int (*direct_access)(struct dax_device *, long unsigned int, long int, enum dax_access_mode, void **, pfn_t *);
	bool (*dax_supported)(struct dax_device *, struct block_device *, int, sector_t, sector_t);
	int (*zero_page_range)(struct dax_device *, long unsigned int, size_t);
	size_t (*recovery_write)(struct dax_device *, long unsigned int, void *, size_t, struct iov_iter *);
};
typedef struct {
	u64 key[2];
} siphash_key_t;
struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				void *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	struct sock *sk;
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 mono_delivery_time: 1;
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 nf_trace: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u16 tc_index;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 mono_delivery_time: 1;
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 nf_trace: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u16 tc_index;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};
struct sk_msg_sg {
	u32 start;
	u32 curr;
	u32 end;
	u32 size;
	u32 copybreak;
	long unsigned int copy[1];
	struct scatterlist data[19];
};
struct sk_msg {
	struct sk_msg_sg sg;
	void *data;
	void *data_end;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 flags;
	struct sk_buff *skb;
	struct sock *sk_redir;
	struct sock *sk;
	struct list_head list;
};
struct task_cputime {
	u64 stime;
	u64 utime;
	long long unsigned int sum_exec_runtime;
};
struct cgroup_base_stat {
	struct task_cputime cputime;
	u64 forceidle_sum;
};
struct task_io_accounting {
	u64 rchar;
	u64 wchar;
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
	u64 cancelled_write_bytes;
};
struct tcp_fastopen_context {
	siphash_key_t key[2];
	int num;
	struct callback_head rcu;
};
struct thread_shstk {
	u64 base;
	u64 size;
};
struct tnum {
	u64 value;
	u64 mask;
};
struct bpf_reg_state {
	enum bpf_reg_type type;
	s32 off;
	union {
		int range;
		struct {
			struct bpf_map *map_ptr;
			u32 map_uid;
		};
		struct {
			struct btf *btf;
			u32 btf_id;
		};
		struct {
			u32 mem_size;
			u32 dynptr_id;
		};
		struct {
			enum bpf_dynptr_type type;
			bool first_slot;
		} dynptr;
		struct {
			struct btf *btf;
			u32 btf_id;
			enum bpf_iter_state state: 2;
			int depth: 30;
		} iter;
		struct {
			long unsigned int raw1;
			long unsigned int raw2;
		} raw;
		u32 subprogno;
	};
	struct tnum var_off;
	s64 smin_value;
	s64 smax_value;
	u64 umin_value;
	u64 umax_value;
	s32 s32_min_value;
	s32 s32_max_value;
	u32 u32_min_value;
	u32 u32_max_value;
	u32 id;
	u32 ref_obj_id;
	struct bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
};
struct bpf_func_state {
	struct bpf_reg_state regs[11];
	int callsite;
	u32 frameno;
	u32 subprogno;
	u32 async_entry_cnt;
	struct bpf_retval_range callback_ret_range;
	bool in_callback_fn;
	bool in_async_callback_fn;
	bool in_exception_callback_fn;
	u32 callback_depth;
	int acquired_refs;
	struct bpf_reference_state *refs;
	struct bpf_stack_state *stack;
	int allocated_stack;
};
struct trace_func_repeats {
	long unsigned int ip;
	long unsigned int parent_ip;
	long unsigned int count;
	u64 ts_last_call;
};
struct u64_stats_sync {};
struct blkg_iostat_set {
	struct u64_stats_sync sync;
	struct blkcg_gq *blkg;
	struct llist_node lnode;
	int lqueued;
	struct blkg_iostat cur;
	struct blkg_iostat last;
};
struct cgroup_rstat_cpu {
	struct u64_stats_sync bsync;
	struct cgroup_base_stat bstat;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat subtree_bstat;
	struct cgroup_base_stat last_subtree_bstat;
	struct cgroup *updated_children;
	struct cgroup *updated_next;
};
struct ipstats_mib {
	u64 mibs[38];
	struct u64_stats_sync syncp;
};
typedef struct {
	local64_t v;
} u64_stats_t;
struct bpf_prog_stats {
	u64_stats_t cnt;
	u64_stats_t nsecs;
	u64_stats_t misses;
	struct u64_stats_sync syncp;
	long: 64;
};
typedef __u8 u8;
struct arch_hw_breakpoint {
	long unsigned int address;
	long unsigned int mask;
	u8 len;
	u8 type;
};
struct arch_uprobe {
	union {
		u8 insn[16];
		u8 ixol[16];
	};
	const struct uprobe_xol_ops *ops;
	union {
		struct {
			s32 offs;
			u8 ilen;
			u8 opc1;
		} branch;
		struct {
			u8 fixups;
			u8 ilen;
		} defparam;
		struct {
			u8 reg_offset;
			u8 ilen;
		} push;
	};
};
struct blk_crypto_key {
	struct blk_crypto_config crypto_cfg;
	unsigned int data_unit_size_bits;
	unsigned int size;
	u8 raw[64];
};
typedef u8 blk_status_t;
struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec bi_inline_vecs[0];
};
struct blk_mq_ops {
	blk_status_t (*queue_rq)(struct blk_mq_hw_ctx *, const struct blk_mq_queue_data *);
	void (*commit_rqs)(struct blk_mq_hw_ctx *);
	void (*queue_rqs)(struct request **);
	int (*get_budget)(struct request_queue *);
	void (*put_budget)(struct request_queue *, int);
	void (*set_rq_budget_token)(struct request *, int);
	int (*get_rq_budget_token)(struct request *);
	enum blk_eh_timer_return (*timeout)(struct request *);
	int (*poll)(struct blk_mq_hw_ctx *, struct io_comp_batch *);
	void (*complete)(struct request *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, void *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	int (*init_request)(struct blk_mq_tag_set *, struct request *, unsigned int, unsigned int);
	void (*exit_request)(struct blk_mq_tag_set *, struct request *, unsigned int);
	void (*cleanup_rq)(struct request *);
	bool (*busy)(struct request_queue *);
	void (*map_queues)(struct blk_mq_tag_set *);
	void (*show_rq)(struct seq_file *, struct request *);
};
struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;
		long unsigned int map_ptr_state;
		s32 call_imm;
		u32 alu_limit;
		struct {
			u32 map_index;
			u32 map_off;
		};
		struct {
			enum bpf_reg_type reg_type;
			union {
				struct {
					struct btf *btf;
					u32 btf_id;
				};
				u32 mem_size;
			};
		} btf_var;
		struct bpf_loop_inline_state loop_inline_state;
	};
	union {
		u64 obj_new_size;
		u64 insert_off;
	};
	struct btf_struct_meta *kptr_struct_meta;
	u64 map_key_state;
	int ctx_field_size;
	u32 seen;
	bool sanitize_stack_spill;
	bool zext_dst;
	bool storage_get_func_atomic;
	bool is_iter_next;
	bool call_with_percpu_alloc_ptr;
	u8 alu_state;
	unsigned int orig_idx;
	bool jmp_point;
	bool prune_point;
	bool force_checkpoint;
	bool calls_callback;
};
struct bpf_jit_poke_descriptor {
	void *tailcall_target;
	void *tailcall_bypass;
	void *bypass_addr;
	void *aux;
	union {
		struct {
			struct bpf_map *map;
			u32 key;
		} tail_call;
	};
	bool tailcall_target_stable;
	u8 adj_off;
	u16 reason;
	u32 insn_idx;
};
struct bpf_local_storage_data {
	struct bpf_local_storage_map *smap;
	u8 data[0];
};
struct bpf_prog {
	u16 pages;
	u16 jited: 1;
	u16 jit_requested: 1;
	u16 gpl_compatible: 1;
	u16 cb_access: 1;
	u16 dst_needed: 1;
	u16 blinding_requested: 1;
	u16 blinded: 1;
	u16 is_func: 1;
	u16 kprobe_override: 1;
	u16 has_callchain_buf: 1;
	u16 enforce_expected_attach_type: 1;
	u16 call_get_stack: 1;
	u16 call_get_func_ip: 1;
	u16 tstamp_type_access: 1;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	u32 len;
	u32 jited_len;
	u8 tag[8];
	struct bpf_prog_stats *stats;
	int *active;
	unsigned int (*bpf_func)(const void *, const struct bpf_insn *);
	struct bpf_prog_aux *aux;
	struct sock_fprog_kern *orig_prog;
	union {
		struct {
			struct {} __empty_insns;
			struct sock_filter insns[0];
		};
		struct {
			struct {} __empty_insnsi;
			struct bpf_insn insnsi[0];
		};
	};
};
struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[8];
};
struct bpf_subprog_info {
	u32 start;
	u32 linfo_idx;
	u16 stack_depth;
	bool has_tail_call: 1;
	bool tail_call_reachable: 1;
	bool has_ld_abs: 1;
	bool is_cb: 1;
	bool is_async_cb: 1;
	bool is_exception_cb: 1;
	bool args_cached: 1;
	u8 arg_cnt;
	struct bpf_subprog_arg_info args[5];
};
struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;
	const struct bpf_verifier_ops *ops;
	struct bpf_verifier_stack_elem *head;
	int stack_size;
	bool strict_alignment;
	bool test_state_freq;
	bool test_reg_invariants;
	struct bpf_verifier_state *cur_state;
	struct bpf_verifier_state_list **explored_states;
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[64];
	struct btf_mod_pair used_btfs[64];
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 id_gen;
	u32 hidden_subprog_cnt;
	int exception_callback_subprog;
	bool explore_alu_limits;
	bool allow_ptr_leaks;
	bool allow_uninit_stack;
	bool bpf_capable;
	bool bypass_spec_v1;
	bool bypass_spec_v4;
	bool seen_direct_write;
	bool seen_exception;
	struct bpf_insn_aux_data *insn_aux_data;
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[258];
	union {
		struct bpf_idmap idmap_scratch;
		struct bpf_idset idset_scratch;
	};
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	struct backtrack_state bt;
	struct bpf_jmp_history_entry *cur_hist_ent;
	u32 pass_cnt;
	u32 subprog_cnt;
	u32 prev_insn_processed;
	u32 insn_processed;
	u32 prev_jmps_processed;
	u32 jmps_processed;
	u64 verification_time;
	u32 max_states_per_insn;
	u32 total_states;
	u32 peak_states;
	u32 longest_mark_read_walk;
	bpfptr_t fd_array;
	u32 scratched_regs;
	u64 scratched_stack_slots;
	u64 prev_log_pos;
	u64 prev_insn_print_pos;
	struct bpf_reg_state fake_reg[2];
	char tmp_str_buf[320];
};
struct btf_func_model {
	u8 ret_size;
	u8 ret_flags;
	u8 nr_args;
	u8 arg_size[12];
	u8 arg_flags[12];
};
struct bpf_kfunc_desc {
	struct btf_func_model func_model;
	u32 func_id;
	s32 imm;
	u16 offset;
	long unsigned int addr;
};
struct bpf_kfunc_desc_tab {
	struct bpf_kfunc_desc descs[256];
	u32 nr_descs;
};
struct cdrom_device_ops {
	int (*open)(struct cdrom_device_info *, int);
	void (*release)(struct cdrom_device_info *);
	int (*drive_status)(struct cdrom_device_info *, int);
	unsigned int (*check_events)(struct cdrom_device_info *, unsigned int, int);
	int (*tray_move)(struct cdrom_device_info *, int);
	int (*lock_door)(struct cdrom_device_info *, int);
	int (*select_speed)(struct cdrom_device_info *, long unsigned int);
	int (*get_last_session)(struct cdrom_device_info *, struct cdrom_multisession *);
	int (*get_mcn)(struct cdrom_device_info *, struct cdrom_mcn *);
	int (*reset)(struct cdrom_device_info *);
	int (*audio_ioctl)(struct cdrom_device_info *, unsigned int, void *);
	int (*generic_packet)(struct cdrom_device_info *, struct packet_command *);
	int (*read_cdda_bpc)(struct cdrom_device_info *, void *, u32, u32, u8 *);
	const int capability;
};
struct cipher_alg {
	unsigned int cia_min_keysize;
	unsigned int cia_max_keysize;
	int (*cia_setkey)(struct crypto_tfm *, const u8 *, unsigned int);
	void (*cia_encrypt)(struct crypto_tfm *, u8 *, const u8 *);
	void (*cia_decrypt)(struct crypto_tfm *, u8 *, const u8 *);
};
struct compress_alg {
	int (*coa_compress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
	int (*coa_decompress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
};
struct crypto_alg {
	struct list_head cra_list;
	struct list_head cra_users;
	u32 cra_flags;
	unsigned int cra_blocksize;
	unsigned int cra_ctxsize;
	unsigned int cra_alignmask;
	int cra_priority;
	refcount_t cra_refcnt;
	char cra_name[128];
	char cra_driver_name[128];
	const struct crypto_type *cra_type;
	union {
		struct cipher_alg cipher;
		struct compress_alg compress;
	} cra_u;
	int (*cra_init)(struct crypto_tfm *);
	void (*cra_exit)(struct crypto_tfm *);
	void (*cra_destroy)(struct crypto_alg *);
	struct module *cra_module;
};
struct export_operations {
	int (*encode_fh)(struct inode *, __u32 *, int *, struct inode *);
	struct dentry * (*fh_to_dentry)(struct super_block *, struct fid *, int, int);
	struct dentry * (*fh_to_parent)(struct super_block *, struct fid *, int, int);
	int (*get_name)(struct dentry *, char *, struct dentry *);
	struct dentry * (*get_parent)(struct dentry *);
	int (*commit_metadata)(struct inode *);
	int (*get_uuid)(struct super_block *, u8 *, u32 *, u64 *);
	int (*map_blocks)(struct inode *, loff_t, u64, struct iomap *, bool, u32 *);
	int (*commit_blocks)(struct inode *, struct iomap *, int, struct iattr *);
	long unsigned int flags;
};
struct fc_log {
	refcount_t usage;
	u8 head;
	u8 tail;
	u8 need_free;
	struct module *owner;
	char *buffer[8];
};
struct fib_nh_common {
	void *nhc_dev;
	netdevice_tracker nhc_dev_tracker;
	int nhc_oif;
	unsigned char nhc_scope;
	u8 nhc_family;
	u8 nhc_gw_family;
	unsigned char nhc_flags;
	struct lwtunnel_state *nhc_lwtstate;
	union {
		__be32 ipv4;
		struct in6_addr ipv6;
	} nhc_gw;
	int nhc_weight;
	atomic_t nhc_upper_bound;
	struct rtable **nhc_pcpu_rth_output;
	struct rtable *nhc_rth_input;
	struct fnhe_hash_bucket *nhc_exceptions;
};
struct fib6_nh {
	struct fib_nh_common nh_common;
	long unsigned int last_probe;
	struct rt6_info **rt6i_pcpu;
	struct rt6_exception_bucket *rt6i_exception_bucket;
};
struct fib6_info {
	struct fib6_table *fib6_table;
	struct fib6_info *fib6_next;
	struct fib6_node *fib6_node;
	union {
		struct list_head fib6_siblings;
		struct list_head nh_list;
	};
	unsigned int fib6_nsiblings;
	refcount_t fib6_ref;
	long unsigned int expires;
	struct dst_metrics *fib6_metrics;
	struct rt6key fib6_dst;
	u32 fib6_flags;
	struct rt6key fib6_src;
	struct rt6key fib6_prefsrc;
	u32 fib6_metric;
	u8 fib6_protocol;
	u8 fib6_type;
	u8 offload;
	u8 trap;
	u8 offload_failed;
	u8 should_flush: 1;
	u8 dst_nocount: 1;
	u8 dst_nopolicy: 1;
	u8 fib6_destroying: 1;
	u8 unused: 4;
	struct callback_head rcu;
	struct nexthop *nh;
	struct fib6_nh fib6_nh[0];
};
struct fib_nh {
	struct fib_nh_common nh_common;
	struct hlist_node nh_hash;
	struct fib_info *nh_parent;
	__u32 nh_tclassid;
	__be32 nh_saddr;
	int nh_saddr_genid;
};
struct fib_info {
	struct hlist_node fib_hash;
	struct hlist_node fib_lhash;
	struct list_head nh_list;
	struct net *fib_net;
	refcount_t fib_treeref;
	refcount_t fib_clntref;
	unsigned int fib_flags;
	unsigned char fib_dead;
	unsigned char fib_protocol;
	unsigned char fib_scope;
	unsigned char fib_type;
	__be32 fib_prefsrc;
	u32 fib_tb_id;
	u32 fib_priority;
	struct dst_metrics *fib_metrics;
	int fib_nhs;
	bool fib_nh_is_v6;
	bool nh_updated;
	bool pfsrc_removed;
	struct nexthop *nh;
	struct callback_head rcu;
	struct fib_nh fib_nh[0];
};
struct fs_parameter_spec {
	const char *name;
	fs_param_type *type;
	u8 opt;
	short unsigned int flags;
	const void *data;
};
struct fscrypt_direct_key {
	struct super_block *dk_sb;
	struct hlist_node dk_node;
	refcount_t dk_refcount;
	const struct fscrypt_mode *dk_mode;
	struct fscrypt_prepared_key dk_key;
	u8 dk_descriptor[8];
	u8 dk_raw[64];
};
struct fscrypt_master_key_secret {
	struct fscrypt_hkdf hkdf;
	u32 size;
	u8 raw[64];
};
union fscrypt_policy {
	u8 version;
	struct fscrypt_policy_v1 v1;
	struct fscrypt_policy_v2 v2;
};
struct fscrypt_inode_info {
	struct fscrypt_prepared_key ci_enc_key;
	bool ci_owns_key;
	bool ci_inlinecrypt;
	u8 ci_data_unit_bits;
	u8 ci_data_units_per_block_bits;
	struct fscrypt_mode *ci_mode;
	struct inode *ci_inode;
	struct fscrypt_master_key *ci_master_key;
	struct list_head ci_master_key_link;
	struct fscrypt_direct_key *ci_direct_key;
	siphash_key_t ci_dirhash_key;
	bool ci_dirhash_key_initialized;
	union fscrypt_policy ci_policy;
	u8 ci_nonce[16];
	u32 ci_hashed_ino;
};
struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};
struct device_node {
	const char *name;
	phandle phandle;
	const char *full_name;
	struct fwnode_handle fwnode;
	struct property *properties;
	struct property *deadprops;
	struct device_node *parent;
	struct device_node *child;
	struct device_node *sibling;
	long unsigned int _flags;
	void *data;
};
struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
};
struct hw_perf_event {
	union {
		struct {
			u64 config;
			u64 last_tag;
			long unsigned int config_base;
			long unsigned int event_base;
			int event_base_rdpmc;
			int idx;
			int last_cpu;
			int flags;
			struct hw_perf_event_extra extra_reg;
			struct hw_perf_event_extra branch_reg;
		};
		struct {
			struct hrtimer hrtimer;
		};
		struct {
			struct list_head tp_list;
		};
		struct {
			u64 pwr_acc;
			u64 ptsc;
		};
		struct {
			struct arch_hw_breakpoint info;
			struct rhlist_head bp_list;
		};
		struct {
			u8 iommu_bank;
			u8 iommu_cntr;
			u16 padding;
			u64 conf;
			u64 conf1;
		};
	};
	struct task_struct *target;
	void *addr_filters;
	long unsigned int addr_filters_gen;
	int state;
	local64_t prev_count;
	u64 sample_period;
	union {
		struct {
			u64 last_period;
			local64_t period_left;
		};
		struct {
			u64 saved_metric;
			u64 saved_slots;
		};
	};
	u64 interrupts_seq;
	u64 interrupts;
	u64 freq_time_stamp;
	u64 freq_count_stamp;
};
typedef blk_status_t integrity_processing_fn(struct blk_integrity_iter *);
struct blk_integrity_profile {
	integrity_processing_fn *generate_fn;
	integrity_processing_fn *verify_fn;
	integrity_prepare_fn *prepare_fn;
	integrity_complete_fn *complete_fn;
	const char *name;
};
struct io_kiocb {
	union {
		struct file *file;
		struct io_cmd_data cmd;
	};
	u8 opcode;
	u8 iopoll_completed;
	u16 buf_index;
	unsigned int flags;
	struct io_cqe cqe;
	struct io_ring_ctx *ctx;
	struct task_struct *task;
	struct io_rsrc_node *rsrc_node;
	union {
		struct io_mapped_ubuf *imu;
		struct io_buffer *kbuf;
		struct io_buffer_list *buf_list;
	};
	union {
		struct io_wq_work_node comp_list;
		__poll_t apoll_events;
	};
	atomic_t refs;
	atomic_t poll_refs;
	struct io_task_work io_task_work;
	unsigned int nr_tw;
	struct hlist_node hash_node;
	struct async_poll *apoll;
	void *async_data;
	struct io_kiocb *link;
	const struct cred *creds;
	struct io_wq_work work;
	struct {
		u64 extra1;
		u64 extra2;
	} big_cqe;
};
struct io_restriction {
	long unsigned int register_op[1];
	long unsigned int sqe_op[1];
	u8 sqe_flags_allowed;
	u8 sqe_flags_required;
	bool registered;
};
struct io_uring_cmd {
	struct file *file;
	const struct io_uring_sqe *sqe;
	void (*task_work_cb)(struct io_uring_cmd *, unsigned int);
	u32 cmd_op;
	u32 flags;
	u8 pdu[32];
};
struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				struct xarray *xarray;
				void *ubuf;
			};
			size_t count;
		};
	};
	union {
		long unsigned int nr_segs;
		loff_t xarray_start;
	};
};
struct iova_bitmap {
	struct iova_bitmap_map mapped;
	u8 *bitmap;
	long unsigned int mapped_base_index;
	long unsigned int mapped_total_index;
	long unsigned int iova;
	size_t length;
	long unsigned int set_ahead_length;
};
struct ip_ct_sctp {
	enum sctp_conntrack state;
	__be32 vtag[2];
	u8 init[2];
	u8 last_dir;
	u8 flags;
};
struct kernel_param {
	const char *name;
	struct module *mod;
	const struct kernel_param_ops *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array *arr;
	};
};
struct lru_gen_folio {
	long unsigned int max_seq;
	long unsigned int min_seq[2];
	long unsigned int timestamps[4];
	struct list_head folios[40];
	long int nr_pages[40];
	long unsigned int avg_refaulted[8];
	long unsigned int avg_total[8];
	long unsigned int protected[6];
	atomic_long_t evicted[8];
	atomic_long_t refaulted[8];
	bool enabled;
	u8 gen;
	u8 seg;
	struct hlist_nulls_node list;
};
struct merkle_tree_params {
	const struct fsverity_hash_alg *hash_alg;
	const u8 *hashstate;
	unsigned int digest_size;
	unsigned int block_size;
	unsigned int hashes_per_block;
	unsigned int blocks_per_page;
	u8 log_digestsize;
	u8 log_blocksize;
	u8 log_arity;
	u8 log_blocks_per_page;
	unsigned int num_levels;
	u64 tree_size;
	long unsigned int tree_pages;
	long unsigned int level_start[8];
};
struct msghdr {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb *msg_iocb;
	struct ubuf_info *msg_ubuf;
	int (*sg_from_iter)(struct sock *, struct sk_buff *, struct iov_iter *, size_t);
};
struct napi_struct {
	struct list_head poll_list;
	long unsigned int state;
	int weight;
	u32 defer_hard_irqs_count;
	long unsigned int gro_bitmask;
	int (*poll)(struct napi_struct *, int);
	int poll_owner;
	int list_owner;
	void *dev;
	struct gro_list gro_hash[8];
	struct sk_buff *skb;
	struct list_head rx_list;
	int rx_count;
	unsigned int napi_id;
	struct hrtimer timer;
	struct task_struct *thread;
	struct list_head dev_list;
	struct hlist_node napi_hash_node;
	int irq;
};
struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	const struct nla_policy *policy;
	const struct nlattr *miss_nest;
	u16 miss_type;
	u8 cookie[20];
	u8 cookie_len;
	char _msg_buf[80];
};
struct netns_core {
	struct ctl_table_header *sysctl_hdr;
	int sysctl_somaxconn;
	int sysctl_optmem_max;
	u8 sysctl_txrehash;
	struct prot_inuse *prot_inuse;
	struct cpumask *rps_default_mask;
};
struct netns_nftables {
	u8 gencursor;
};
struct netns_sysctl_ipv6 {
	struct ctl_table_header *hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *icmp_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *xfrm6_hdr;
	int flush_delay;
	int ip6_rt_max_size;
	int ip6_rt_gc_min_interval;
	int ip6_rt_gc_timeout;
	int ip6_rt_gc_interval;
	int ip6_rt_gc_elasticity;
	int ip6_rt_mtu_expires;
	int ip6_rt_min_advmss;
	u32 multipath_hash_fields;
	u8 multipath_hash_policy;
	u8 bindv6only;
	u8 flowlabel_consistency;
	u8 auto_flowlabels;
	int icmpv6_time;
	u8 icmpv6_echo_ignore_all;
	u8 icmpv6_echo_ignore_multicast;
	u8 icmpv6_echo_ignore_anycast;
	long unsigned int icmpv6_ratemask[4];
	long unsigned int *icmpv6_ratemask_ptr;
	u8 anycast_src_echo_reply;
	u8 ip_nonlocal_bind;
	u8 fwmark_reflect;
	u8 flowlabel_state_ranges;
	int idgen_retries;
	int idgen_delay;
	int flowlabel_reflect;
	int max_dst_opts_cnt;
	int max_hbh_opts_cnt;
	int max_dst_opts_len;
	int max_hbh_opts_len;
	int seg6_flowlabel;
	u32 ioam6_id;
	u64 ioam6_id_wide;
	u8 skip_notify_on_dev_down;
	u8 fib_notify_on_flag_change;
	u8 icmpv6_error_anycast_as_unicast;
};
struct nexthop {
	struct rb_node rb_node;
	struct list_head fi_list;
	struct list_head f6i_list;
	struct list_head fdb_list;
	struct list_head grp_list;
	struct net *net;
	u32 id;
	u8 protocol;
	u8 nh_flags;
	bool is_group;
	refcount_t refcnt;
	struct callback_head rcu;
	union {
		struct nh_info *nh_info;
		struct nh_group *nh_grp;
	};
};
struct nf_conntrack_zone {
	u16 id;
	u8 flags;
	u8 dir;
};
struct nf_ct_ext {
	u8 offset[10];
	u8 len;
	unsigned int gen_id;
	char data[0];
};
struct nf_dccp_net {
	u8 dccp_loose;
	unsigned int dccp_timeout[10];
};
struct nf_hook_state {
	u8 hook;
	u8 pf;
	void *in;
	void *out;
	struct sock *sk;
	struct net *net;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};
struct nf_tcp_net {
	unsigned int timeouts[14];
	u8 tcp_loose;
	u8 tcp_be_liberal;
	u8 tcp_max_retrans;
	u8 tcp_ignore_invalid_rst;
	unsigned int offload_timeout;
};
struct nf_ip_net {
	struct nf_generic_net generic;
	struct nf_tcp_net tcp;
	struct nf_udp_net udp;
	struct nf_icmp_net icmp;
	struct nf_icmp_net icmpv6;
	struct nf_dccp_net dccp;
	struct nf_sctp_net sctp;
	struct nf_gre_net gre;
};
struct netns_ct {
	bool ecache_dwork_pending;
	u8 sysctl_log_invalid;
	u8 sysctl_events;
	u8 sysctl_acct;
	u8 sysctl_tstamp;
	u8 sysctl_checksum;
	struct ip_conntrack_stat *stat;
	struct nf_ct_event_notifier *nf_conntrack_event_cb;
	struct nf_ip_net nf_ct_proto;
	atomic_t labels_used;
};
struct nh_grp_entry {
	struct nexthop *nh;
	u8 weight;
	union {
		struct {
			atomic_t upper_bound;
		} hthr;
		struct {
			struct list_head uw_nh_entry;
			u16 count_buckets;
			u16 wants_buckets;
		} res;
	};
	struct list_head nh_list;
	struct nexthop *nh_parent;
};
struct nh_group {
	struct nh_group *spare;
	u16 num_nh;
	bool is_multipath;
	bool hash_threshold;
	bool resilient;
	bool fdb_nh;
	bool has_v4;
	struct nh_res_table *res_table;
	struct nh_grp_entry nh_entries[0];
};
struct nh_info {
	struct hlist_node dev_hash;
	struct nexthop *nh_parent;
	u8 family;
	bool reject_nh;
	bool fdb_nh;
	union {
		struct fib_nh_common fib_nhc;
		struct fib_nh fib_nh;
		struct fib6_nh fib6_nh;
	};
};
struct nh_res_bucket {
	struct nh_grp_entry *nh_entry;
	atomic_long_t used_time;
	long unsigned int migrated_time;
	bool occupied;
	u8 nh_flags;
};
struct nla_policy {
	u8 type;
	u8 validation_type;
	u16 len;
	union {
		u16 strict_start_type;
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		const struct netlink_range_validation *range;
		const struct netlink_range_validation_signed *range_signed;
		struct {
			s16 min;
			s16 max;
		};
		int (*validate)(const struct nlattr *, struct netlink_ext_ack *);
	};
};
struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};
struct pci_msi_desc {
	union {
		u32 msi_mask;
		u32 msix_ctrl;
	};
	struct {
		u8 is_msix: 1;
		u8 multiple: 3;
		u8 multi_cap: 3;
		u8 can_mask: 1;
		u8 is_64: 1;
		u8 is_virtual: 1;
		unsigned int default_irq;
	} msi_attrib;
	union {
		u8 mask_pos;
		void *mask_base;
	};
};
struct pneigh_entry {
	struct pneigh_entry *next;
	possible_net_t net;
	void *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
	u8 protocol;
	u32 key[0];
};
struct qspinlock {
	union {
		atomic_t val;
		struct {
			u8 locked;
			u8 pending;
		};
		struct {
			u16 locked_pending;
			u16 tail;
		};
	};
};
typedef struct qspinlock arch_spinlock_t;
struct qrwlock {
	union {
		atomic_t cnts;
		struct {
			u8 wlocked;
			u8 __lstate[3];
		};
	};
	arch_spinlock_t wait_lock;
};
typedef struct qrwlock arch_rwlock_t;
struct raw_spinlock {
	arch_spinlock_t raw_lock;
};
typedef struct raw_spinlock raw_spinlock_t;
struct bpf_local_storage {
	struct bpf_local_storage_data *cache[16];
	struct bpf_local_storage_map *smap;
	struct hlist_head list;
	void *owner;
	struct callback_head rcu;
	raw_spinlock_t lock;
};
struct bpf_local_storage_map_bucket {
	struct hlist_head list;
	raw_spinlock_t lock;
};
struct cfs_bandwidth {
	raw_spinlock_t lock;
	ktime_t period;
	u64 quota;
	u64 runtime;
	u64 burst;
	u64 runtime_snap;
	s64 hierarchical_quota;
	u8 idle;
	u8 period_active;
	u8 slack_started;
	struct hrtimer period_timer;
	struct hrtimer slack_timer;
	struct list_head throttled_cfs_rq;
	int nr_periods;
	int nr_throttled;
	int nr_burst;
	u64 throttled_time;
	u64 burst_time;
};
struct cfs_rq {
	struct load_weight load;
	unsigned int nr_running;
	unsigned int h_nr_running;
	unsigned int idle_nr_running;
	unsigned int idle_h_nr_running;
	s64 avg_vruntime;
	u64 avg_load;
	u64 exec_clock;
	u64 min_vruntime;
	unsigned int forceidle_seq;
	u64 min_vruntime_fi;
	struct rb_root_cached tasks_timeline;
	struct sched_entity *curr;
	struct sched_entity *next;
	unsigned int nr_spread_over;
	long: 64;
	struct sched_avg avg;
	struct {
		raw_spinlock_t lock;
		int nr;
		long unsigned int load_avg;
		long unsigned int util_avg;
		long unsigned int runnable_avg;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	} removed;
	u64 last_update_tg_load_avg;
	long unsigned int tg_load_avg_contrib;
	long int propagate;
	long int prop_runnable_sum;
	long unsigned int h_load;
	u64 last_h_load_update;
	struct sched_entity *h_load_next;
	struct rq *rq;
	int on_list;
	struct list_head leaf_cfs_rq_list;
	struct task_group *tg;
	int idle;
	int runtime_enabled;
	s64 runtime_remaining;
	u64 throttled_pelt_idle;
	u64 throttled_clock;
	u64 throttled_clock_pelt;
	u64 throttled_clock_pelt_time;
	u64 throttled_clock_self;
	u64 throttled_clock_self_time;
	int throttled;
	int throttle_count;
	struct list_head throttled_list;
	struct list_head throttled_csd_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct cpudl {
	raw_spinlock_t lock;
	int size;
	cpumask_var_t free_cpus;
	struct cpudl_item *elements;
};
struct dl_bw {
	raw_spinlock_t lock;
	u64 bw;
	u64 total_bw;
};
struct hrtimer_cpu_base {
	raw_spinlock_t lock;
	unsigned int cpu;
	unsigned int active_bases;
	unsigned int clock_was_set_seq;
	unsigned int hres_active: 1;
	unsigned int in_hrtirq: 1;
	unsigned int hang_detected: 1;
	unsigned int softirq_activated: 1;
	unsigned int online: 1;
	unsigned int nr_events;
	short unsigned int nr_retries;
	short unsigned int nr_hangs;
	unsigned int max_hang_time;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	struct hrtimer_clock_base clock_base[8];
	call_single_data_t csd;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct io_wq_acct {
	unsigned int nr_workers;
	unsigned int max_workers;
	int index;
	atomic_t nr_running;
	raw_spinlock_t lock;
	struct io_wq_work_list work_list;
	long unsigned int flags;
};
struct irq_chip_generic {
	raw_spinlock_t lock;
	void *reg_base;
	u32 (*reg_readl)(void *);
	void (*reg_writel)(u32, void *);
	void (*suspend)(struct irq_chip_generic *);
	void (*resume)(struct irq_chip_generic *);
	unsigned int irq_base;
	unsigned int irq_cnt;
	u32 mask_cache;
	u32 type_cache;
	u32 polarity_cache;
	u32 wake_enabled;
	u32 wake_active;
	unsigned int num_ct;
	void *private;
	long unsigned int installed;
	long unsigned int unused;
	struct irq_domain *domain;
	struct list_head list;
	struct irq_chip_type chip_types[0];
};
struct kthread_worker {
	unsigned int flags;
	raw_spinlock_t lock;
	struct list_head work_list;
	struct list_head delayed_work_list;
	struct task_struct *task;
	struct kthread_work *current_work;
};
struct ld_semaphore {
	atomic_long_t count;
	raw_spinlock_t wait_lock;
	unsigned int wait_readers;
	struct list_head read_wait;
	struct list_head write_wait;
};
struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
};
struct blk_mq_tag_set {
	const struct blk_mq_ops *ops;
	struct blk_mq_queue_map map[3];
	unsigned int nr_maps;
	unsigned int nr_hw_queues;
	unsigned int queue_depth;
	unsigned int reserved_tags;
	unsigned int cmd_size;
	int numa_node;
	unsigned int timeout;
	unsigned int flags;
	void *driver_data;
	struct blk_mq_tags **tags;
	struct blk_mq_tags *shared_tags;
	struct mutex tag_list_lock;
	struct list_head tag_list;
	struct srcu_struct *srcu;
};
struct bpf_trampoline {
	struct hlist_node hlist;
	struct ftrace_ops *fops;
	struct mutex mutex;
	refcount_t refcnt;
	u32 flags;
	u64 key;
	struct {
		struct btf_func_model model;
		void *addr;
		bool ftrace_managed;
	} func;
	struct bpf_prog *extension_prog;
	struct hlist_head progs_hlist[3];
	int progs_cnt[3];
	struct bpf_tramp_image *cur_image;
	struct module *mod;
};
struct dev_iommu {
	struct mutex lock;
	struct iommu_fault_param *fault_param;
	struct iopf_device_param *iopf_param;
	struct iommu_fwspec *fwspec;
	struct iommu_device *iommu_dev;
	void *priv;
	u32 max_pasids;
	u32 attach_deferred: 1;
	u32 pci_32bit_workaround: 1;
	u32 require_direct: 1;
	u32 shadow_on_flush: 1;
};
struct elevator_queue {
	struct elevator_type *type;
	void *elevator_data;
	struct kobject kobj;
	struct mutex sysfs_lock;
	long unsigned int flags;
	struct hlist_head hash[64];
};
struct fs_context {
	const struct fs_context_operations *ops;
	struct mutex uapi_mutex;
	struct file_system_type *fs_type;
	void *fs_private;
	void *sget_key;
	struct dentry *root;
	struct user_namespace *user_ns;
	struct net *net_ns;
	const struct cred *cred;
	struct p_log log;
	const char *source;
	void *security;
	void *s_fs_info;
	unsigned int sb_flags;
	unsigned int sb_flags_mask;
	unsigned int s_iflags;
	enum fs_context_purpose purpose: 8;
	enum fs_context_phase phase: 8;
	bool need_free: 1;
	bool global: 1;
	bool oldapi: 1;
	bool exclusive: 1;
};
struct ftrace_ops_hash {
	struct ftrace_hash *notrace_hash;
	struct ftrace_hash *filter_hash;
	struct mutex regex_lock;
};
struct ftrace_ops {
	ftrace_func_t func;
	struct ftrace_ops *next;
	long unsigned int flags;
	void *private;
	ftrace_func_t saved_func;
	struct ftrace_ops_hash local_hash;
	struct ftrace_ops_hash *func_hash;
	struct ftrace_ops_hash old_hash;
	long unsigned int trampoline;
	long unsigned int trampoline_size;
	struct list_head list;
	ftrace_ops_func_t ops_func;
	long unsigned int direct_call;
};
struct iommu_fault_param {
	iommu_dev_fault_handler_t handler;
	void *data;
	struct list_head faults;
	struct mutex lock;
};
struct iopf_queue {
	struct workqueue_struct *wq;
	struct list_head devices;
	struct mutex lock;
};
struct kernfs_open_file {
	struct kernfs_node *kn;
	struct file *file;
	struct seq_file *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct *vm_ops;
};
struct module {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)(void);
	struct module_memory mem[7];
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)(void);
	atomic_t refcnt;
	struct error_injection_entry *ei_funcs;
	unsigned int num_ei_funcs;
	struct _ddebug_info dyndbg_info;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct netns_packet {
	struct mutex sklist_lock;
	struct hlist_head sklist;
};
struct netns_smc {
	struct smc_stats *smc_stats;
	struct mutex mutex_fback_rsn;
	struct smc_stats_rsn *fback_rsn;
	bool limit_smc_hs;
	struct ctl_table_header *smc_hdr;
	unsigned int sysctl_autocorking_size;
	unsigned int sysctl_smcr_buf_type;
	int sysctl_smcr_testlink_time;
	int sysctl_wmem;
	int sysctl_rmem;
	int sysctl_max_links_per_lgr;
	int sysctl_max_conns_per_lgr;
};
struct netns_xdp {
	struct mutex lock;
	struct hlist_head list;
};
struct percpu_counter {
	raw_spinlock_t lock;
	s64 count;
	struct list_head list;
	s32 *counters;
};
struct dst_ops {
	short unsigned int family;
	unsigned int gc_thresh;
	void (*gc)(struct dst_ops *);
	struct dst_entry * (*check)(struct dst_entry *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry *);
	unsigned int (*mtu)(const struct dst_entry *);
	u32 * (*cow_metrics)(struct dst_entry *, long unsigned int);
	void (*destroy)(struct dst_entry *);
	void (*ifdown)(struct dst_entry *, void *);
	void (*negative_advice)(struct sock *, struct dst_entry *);
	void (*link_failure)(struct sk_buff *);
	void (*update_pmtu)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool);
	void (*redirect)(struct dst_entry *, struct sock *, struct sk_buff *);
	int (*local_out)(struct net *, struct sock *, struct sk_buff *);
	struct neighbour * (*neigh_lookup)(const struct dst_entry *, struct sk_buff *, const void *);
	void (*confirm_neigh)(const struct dst_entry *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
	long: 64;
	long: 64;
	long: 64;
};
struct fprop_global {
	struct percpu_counter events;
	unsigned int period;
	seqcount_t sequence;
};
struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
};
struct perf_addr_filters_head {
	struct list_head list;
	raw_spinlock_t lock;
	unsigned int nr_file_filters;
};
struct perf_cpu_pmu_context {
	struct perf_event_pmu_context epc;
	struct perf_event_pmu_context *task_epc;
	struct list_head sched_cb_entry;
	int sched_cb_usage;
	int active_oncpu;
	int exclusive;
	raw_spinlock_t hrtimer_lock;
	struct hrtimer hrtimer;
	ktime_t hrtimer_interval;
	unsigned int hrtimer_active;
};
struct perf_event_context {
	raw_spinlock_t lock;
	struct mutex mutex;
	struct list_head pmu_ctx_list;
	struct perf_event_groups pinned_groups;
	struct perf_event_groups flexible_groups;
	struct list_head event_list;
	int nr_events;
	int nr_user;
	int is_active;
	int nr_task_data;
	int nr_stat;
	int nr_freq;
	int rotate_disable;
	refcount_t refcount;
	struct task_struct *task;
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	struct perf_event_context *parent_ctx;
	u64 parent_gen;
	u64 generation;
	int pin_count;
	int nr_cgroups;
	struct callback_head callback_head;
	local_t nr_pending;
};
struct posix_cputimers_work {
	struct callback_head work;
	struct mutex mutex;
	unsigned int scheduled;
};
struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};
struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	long unsigned int begin;
	long unsigned int flags;
};
struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	atomic_long_t len;
	long int seglen[4];
	u8 flags;
};
union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};
struct reciprocal_value {
	u32 m;
	u8 sh1;
	u8 sh2;
};
struct kmem_cache {
	struct kmem_cache_cpu *cpu_slab;
	slab_flags_t flags;
	long unsigned int min_partial;
	unsigned int size;
	unsigned int object_size;
	struct reciprocal_value reciprocal_size;
	unsigned int offset;
	unsigned int cpu_partial;
	unsigned int cpu_partial_slabs;
	struct kmem_cache_order_objects oo;
	struct kmem_cache_order_objects min;
	gfp_t allocflags;
	int refcount;
	void (*ctor)(void *);
	unsigned int inuse;
	unsigned int align;
	unsigned int red_left_pad;
	const char *name;
	struct list_head list;
	struct kobject kobj;
	long unsigned int random;
	unsigned int remote_node_defrag_ratio;
	unsigned int *random_seq;
	unsigned int useroffset;
	unsigned int usersize;
	struct kmem_cache_node *node[1024];
};
struct request_sock {
	struct sock_common __req_common;
	struct request_sock *dl_next;
	u16 mss;
	u8 num_retrans;
	u8 syncookie: 1;
	u8 num_timeout: 7;
	u32 ts_recent;
	struct timer_list rsk_timer;
	const struct request_sock_ops *rsk_ops;
	struct sock *sk;
	struct saved_syn *saved_syn;
	u32 secid;
	u32 peer_secid;
	u32 timeout;
};
struct root_domain {
	atomic_t refcount;
	atomic_t rto_count;
	struct callback_head rcu;
	cpumask_var_t span;
	cpumask_var_t online;
	int overload;
	int overutilized;
	cpumask_var_t dlo_mask;
	atomic_t dlo_count;
	struct dl_bw dl_bw;
	struct cpudl cpudl;
	u64 visit_gen;
	struct irq_work rto_push_work;
	raw_spinlock_t rto_lock;
	int rto_loop;
	int rto_cpu;
	atomic_t rto_loop_next;
	atomic_t rto_loop_start;
	cpumask_var_t rto_mask;
	struct cpupri cpupri;
	long unsigned int max_cpu_capacity;
	struct perf_domain *pd;
};
typedef enum rq_end_io_ret rq_end_io_fn(struct request *, blk_status_t);
struct request {
	struct request_queue *q;
	struct blk_mq_ctx *mq_ctx;
	struct blk_mq_hw_ctx *mq_hctx;
	blk_opf_t cmd_flags;
	req_flags_t rq_flags;
	int tag;
	int internal_tag;
	unsigned int timeout;
	unsigned int __data_len;
	sector_t __sector;
	struct bio *bio;
	struct bio *biotail;
	union {
		struct list_head queuelist;
		struct request *rq_next;
	};
	struct block_device *part;
	u64 alloc_time_ns;
	u64 start_time_ns;
	u64 io_start_time_ns;
	short unsigned int wbt_flags;
	short unsigned int stats_sectors;
	short unsigned int nr_phys_segments;
	short unsigned int nr_integrity_segments;
	struct bio_crypt_ctx *crypt_ctx;
	struct blk_crypto_keyslot *crypt_keyslot;
	short unsigned int ioprio;
	enum mq_rq_state state;
	atomic_t ref;
	long unsigned int deadline;
	union {
		struct hlist_node hash;
		struct llist_node ipi_list;
	};
	union {
		struct rb_node rb_node;
		struct bio_vec special_vec;
	};
	struct {
		struct io_cq *icq;
		void *priv[2];
	} elv;
	struct {
		unsigned int seq;
		rq_end_io_fn *saved_end_io;
	} flush;
	u64 fifo_time;
	rq_end_io_fn *end_io;
	void *end_io_data;
};
struct rt_mutex_base {
	raw_spinlock_t wait_lock;
	struct rb_root_cached waiters;
	struct task_struct *owner;
};
struct futex_pi_state {
	struct list_head list;
	struct rt_mutex_base pi_mutex;
	struct task_struct *owner;
	refcount_t refcount;
	union futex_key key;
};
struct rt_mutex {
	struct rt_mutex_base rtmutex;
};
struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
	struct {
		int curr;
		int next;
	} highest_prio;
	int overloaded;
	struct plist_head pushable_tasks;
	int rt_queued;
	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	raw_spinlock_t rt_runtime_lock;
};
struct rtable {
	struct dst_entry dst;
	int rt_genid;
	unsigned int rt_flags;
	__u16 rt_type;
	__u8 rt_is_input;
	__u8 rt_uses_gateway;
	int rt_iif;
	u8 rt_gw_family;
	union {
		__be32 rt_gw4;
		struct in6_addr rt_gw6;
	};
	u32 rt_mtu_locked: 1;
	u32 rt_pmtu: 31;
};
struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	struct optimistic_spin_queue osq;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};
struct anon_vma {
	struct anon_vma *root;
	struct rw_semaphore rwsem;
	atomic_t refcount;
	long unsigned int num_children;
	long unsigned int num_active_vmas;
	struct anon_vma *parent;
	struct rb_root_cached rb_root;
};
struct autogroup {
	struct kref kref;
	struct task_group *tg;
	struct rw_semaphore lock;
	long unsigned int id;
	int nice;
};
struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block *head;
};
struct freq_constraints {
	struct pm_qos_constraints min_freq;
	struct blocking_notifier_head min_freq_notifiers;
	struct pm_qos_constraints max_freq;
	struct blocking_notifier_head max_freq_notifiers;
};
struct dev_pm_qos {
	struct pm_qos_constraints resume_latency;
	struct pm_qos_constraints latency_tolerance;
	struct freq_constraints freq;
	struct pm_qos_flags flags;
	struct dev_pm_qos_request *resume_latency_req;
	struct dev_pm_qos_request *latency_tolerance_req;
	struct dev_pm_qos_request *flags_req;
};
typedef struct {
	u64 ctx_id;
	atomic64_t tlb_gen;
	long unsigned int next_trim_cpumask;
	struct rw_semaphore ldt_usr_sem;
	struct ldt_struct *ldt;
	long unsigned int flags;
	struct mutex lock;
	void *vdso;
	const struct vdso_image *vdso_image;
	atomic_t perf_rdpmc_allowed;
	u16 pkey_allocation_map;
	s16 execute_only_pkey;
} mm_context_t;
struct netns_nexthop {
	struct rb_root rb_root;
	struct hlist_head *devhash;
	unsigned int seq;
	u32 last_id_allocated;
	struct blocking_notifier_head notifier_chain;
};
struct quota_info {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode *files[3];
	struct mem_dqinfo info[3];
	const struct quota_format_ops *ops[3];
};
typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;
struct aa_labelset {
	rwlock_t lock;
	struct rb_root root;
};
struct binfmt_misc {
	struct list_head entries;
	rwlock_t entries_lock;
	bool enabled;
};
struct fasync_struct {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	struct file *fa_file;
	struct callback_head fa_rcu;
};
struct saved_syn {
	u32 mac_hdrlen;
	u32 network_hdrlen;
	u32 tcp_hdrlen;
	u8 data[0];
};
struct sbitmap_word {
	long unsigned int word;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int cleared;
	raw_spinlock_t swap_lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct sched_dl_entity {
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled: 1;
	unsigned int dl_yielded: 1;
	unsigned int dl_non_contending: 1;
	unsigned int dl_overrun: 1;
	unsigned int dl_server: 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
	struct rq *rq;
	dl_server_has_tasks_f server_has_tasks;
	dl_server_pick_f server_pick;
	struct sched_dl_entity *pi_se;
};
struct scsi_sense_hdr {
	u8 response_code;
	u8 sense_key;
	u8 asc;
	u8 ascq;
	u8 byte4;
	u8 byte5;
	u8 byte6;
	u8 additional_length;
};
struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};
struct simple_xattrs {
	struct rb_root rb_root;
	rwlock_t lock;
};
struct skb_ext {
	refcount_t refcnt;
	u8 offset[4];
	u8 chunks;
	long: 0;
	char data[0];
};
struct smack_known {
	struct list_head list;
	struct hlist_node smk_hashed;
	char *smk_known;
	u32 smk_secid;
	struct netlbl_lsm_secattr smk_netlabel;
	struct list_head smk_rules;
	struct mutex smk_rules_lock;
};
struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};
typedef struct spinlock spinlock_t;
struct aa_audit_cache {
	spinlock_t lock;
	int size;
	struct list_head head;
};
struct aa_profile {
	struct aa_policy base;
	struct aa_profile *parent;
	struct aa_ns *ns;
	const char *rename;
	enum audit_mode audit;
	long int mode;
	u32 path_flags;
	int signal;
	const char *disconnected;
	struct aa_attachment attach;
	struct list_head rules;
	struct aa_net_compat *net_compat;
	struct aa_audit_cache learning_cache;
	struct aa_loaddata *rawdata;
	unsigned char *hash;
	char *dirname;
	struct dentry *dents[10];
	struct rhashtable *data;
	struct aa_label label;
};
struct blk_flush_queue {
	spinlock_t mq_flush_lock;
	unsigned int flush_pending_idx: 1;
	unsigned int flush_running_idx: 1;
	blk_status_t rq_status;
	long unsigned int flush_pending_since;
	struct list_head flush_queue[2];
	long unsigned int flush_data_in_flight;
	struct request *flush_rq;
};
struct blk_mq_ctx {
	struct {
		spinlock_t lock;
		struct list_head rq_lists[3];
		long: 64;
	};
	unsigned int cpu;
	short unsigned int index_hw[3];
	struct blk_mq_hw_ctx *hctxs[3];
	struct request_queue *queue;
	struct blk_mq_ctxs *ctxs;
	struct kobject kobj;
	long: 64;
};
struct blk_mq_tags {
	unsigned int nr_tags;
	unsigned int nr_reserved_tags;
	unsigned int active_queues;
	struct sbitmap_queue bitmap_tags;
	struct sbitmap_queue breserved_tags;
	struct request **rqs;
	struct request **static_rqs;
	struct list_head page_list;
	spinlock_t lock;
};
struct blk_queue_stats {
	struct list_head callbacks;
	spinlock_t lock;
	int accounting;
};
struct deferred_split {
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	long unsigned int split_queue_len;
};
struct file_lock_context {
	spinlock_t flc_lock;
	struct list_head flc_flock;
	struct list_head flc_posix;
	struct list_head flc_lease;
};
struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_spinlock_t seq;
	int umask;
	int in_exec;
	struct path root;
	struct path pwd;
};
struct fscrypt_keyring {
	spinlock_t lock;
	struct hlist_head key_hashtable[128];
};
struct fscrypt_master_key {
	struct hlist_node mk_node;
	struct rw_semaphore mk_sem;
	refcount_t mk_active_refs;
	refcount_t mk_struct_refs;
	struct callback_head mk_rcu_head;
	struct fscrypt_master_key_secret mk_secret;
	struct fscrypt_key_specifier mk_spec;
	struct key *mk_users;
	struct list_head mk_decrypted_inodes;
	spinlock_t mk_decrypted_inodes_lock;
	struct fscrypt_prepared_key mk_direct_keys[11];
	struct fscrypt_prepared_key mk_iv_ino_lblk_64_keys[11];
	struct fscrypt_prepared_key mk_iv_ino_lblk_32_keys[11];
	siphash_key_t mk_ino_hash_key;
	bool mk_ino_hash_key_initialized;
	bool mk_present;
};
struct fsnotify_mark_connector {
	spinlock_t lock;
	short unsigned int type;
	short unsigned int flags;
	union {
		fsnotify_connp_t *obj;
		struct fsnotify_mark_connector *destroy_next;
	};
	struct hlist_head list;
};
struct fsverity_info {
	struct merkle_tree_params tree_params;
	u8 root_hash[64];
	u8 file_digest[64];
	const struct inode *inode;
	long unsigned int *hash_block_verified;
	spinlock_t hash_page_init_lock;
};
struct inet_bind_hashbucket {
	spinlock_t lock;
	struct hlist_head chain;
};
struct inet_frag_queue {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff *fragments_tail;
	struct sk_buff *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 mono_delivery_time;
	__u8 flags;
	u16 max_size;
	struct fqdir *fqdir;
	struct callback_head rcu;
};
struct inet_hashinfo {
	struct inet_ehash_bucket *ehash;
	spinlock_t *ehash_locks;
	unsigned int ehash_mask;
	unsigned int ehash_locks_mask;
	struct kmem_cache *bind_bucket_cachep;
	struct inet_bind_hashbucket *bhash;
	struct kmem_cache *bind2_bucket_cachep;
	struct inet_bind_hashbucket *bhash2;
	unsigned int bhash_size;
	unsigned int lhash2_mask;
	struct inet_listen_hashbucket *lhash2;
	bool pernet;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct inet_listen_hashbucket {
	spinlock_t lock;
	struct hlist_nulls_head nulls_head;
};
struct io_hash_bucket {
	spinlock_t lock;
	struct hlist_head list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct io_tlb_area {
	long unsigned int used;
	unsigned int index;
	spinlock_t lock;
};
struct iova_cpu_rcache {
	spinlock_t lock;
	struct iova_magazine *loaded;
	struct iova_magazine *prev;
};
struct iova_domain {
	spinlock_t iova_rbtree_lock;
	struct rb_root rbroot;
	struct rb_node *cached_node;
	struct rb_node *cached32_node;
	long unsigned int granule;
	long unsigned int start_pfn;
	long unsigned int dma_32bit_pfn;
	long unsigned int max32_alloc_size;
	struct iova anchor;
	struct iova_rcache *rcaches;
	struct hlist_node cpuhp_dead;
};
struct iommu_dma_cookie {
	enum iommu_dma_cookie_type type;
	union {
		struct {
			struct iova_domain iovad;
			union {
				struct iova_fq *single_fq;
				struct iova_fq *percpu_fq;
			};
			atomic64_t fq_flush_start_cnt;
			atomic64_t fq_flush_finish_cnt;
			struct timer_list fq_timer;
			atomic_t fq_timer_on;
		};
		dma_addr_t msi_iova;
	};
	struct list_head msi_page_list;
	struct iommu_domain *fq_domain;
	struct iommu_dma_options options;
	struct mutex mutex;
};
struct iova_fq {
	spinlock_t lock;
	unsigned int head;
	unsigned int tail;
	unsigned int mod_mask;
	struct iova_fq_entry entries[0];
};
struct klist {
	spinlock_t k_lock;
	struct list_head k_list;
	void (*get)(struct klist_node *);
	void (*put)(struct klist_node *);
};
struct device_private {
	struct klist klist_children;
	struct klist_node knode_parent;
	struct klist_node knode_driver;
	struct klist_node knode_bus;
	struct klist_node knode_class;
	struct list_head deferred_probe;
	struct device_driver *async_driver;
	char *deferred_probe_reason;
	struct device *device;
	u8 dead: 1;
};
struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;
};
struct kmem_cache_node {
	spinlock_t list_lock;
	long unsigned int nr_partial;
	struct list_head partial;
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
};
struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};
struct list_lru_node {
	spinlock_t lock;
	struct list_lru_one lru;
	long int nr_items;
	long: 64;
	long: 64;
	long: 64;
};
struct lockref {
	union {
		__u64 lock_count;
		struct {
			spinlock_t lock;
			int count;
		};
	};
};
struct lru_gen_memcg {
	long unsigned int seq;
	long unsigned int nr_memcgs[3];
	struct hlist_nulls_head fifo[24];
	spinlock_t lock;
};
struct lru_gen_mm_list {
	struct list_head fifo;
	spinlock_t lock;
};
struct maple_tree {
	union {
		spinlock_t ma_lock;
		lockdep_map_p ma_external_lock;
	};
	unsigned int ma_flags;
	void *ma_root;
};
struct netns_can {
	struct proc_dir_entry *proc_dir;
	struct proc_dir_entry *pde_stats;
	struct proc_dir_entry *pde_reset_stats;
	struct proc_dir_entry *pde_rcvlist_all;
	struct proc_dir_entry *pde_rcvlist_fil;
	struct proc_dir_entry *pde_rcvlist_inv;
	struct proc_dir_entry *pde_rcvlist_sff;
	struct proc_dir_entry *pde_rcvlist_eff;
	struct proc_dir_entry *pde_rcvlist_err;
	struct proc_dir_entry *bcmproc_dir;
	struct can_dev_rcv_lists *rx_alldev_list;
	spinlock_t rcvlists_lock;
	struct timer_list stattimer;
	struct can_pkg_stats *pkg_stats;
	struct can_rcv_lists_stats *rcv_lists_stats;
	struct hlist_head cgw_list;
};
struct netns_mctp {
	struct list_head routes;
	struct mutex bind_lock;
	struct hlist_head binds;
	spinlock_t keys_lock;
	struct hlist_head keys;
	unsigned int default_net;
	struct mutex neigh_lock;
	struct list_head neighbours;
};
struct netns_sctp {
	struct sctp_mib *sctp_statistics;
	struct proc_dir_entry *proc_net_sctp;
	struct ctl_table_header *sysctl_header;
	struct sock *ctl_sock;
	struct sock *udp4_sock;
	struct sock *udp6_sock;
	int udp_port;
	int encap_port;
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;
	spinlock_t addr_wq_lock;
	spinlock_t local_addr_lock;
	unsigned int rto_initial;
	unsigned int rto_min;
	unsigned int rto_max;
	int rto_alpha;
	int rto_beta;
	int max_burst;
	int cookie_preserve_enable;
	char *sctp_hmac_alg;
	unsigned int valid_cookie_life;
	unsigned int sack_timeout;
	unsigned int hb_interval;
	unsigned int probe_interval;
	int max_retrans_association;
	int max_retrans_path;
	int max_retrans_init;
	int pf_retrans;
	int ps_retrans;
	int pf_enable;
	int pf_expose;
	int sndbuf_policy;
	int rcvbuf_policy;
	int default_auto_asconf;
	int addip_enable;
	int addip_noauth;
	int prsctp_enable;
	int reconf_enable;
	int auth_enable;
	int intl_enable;
	int ecn_enable;
	int scope_policy;
	int rwnd_upd_shift;
	long unsigned int max_autoclose;
	int l3mdev_accept;
};
struct numa_group {
	refcount_t refcount;
	spinlock_t lock;
	int nr_tasks;
	pid_t gid;
	int active_nodes;
	struct callback_head rcu;
	long unsigned int total_faults;
	long unsigned int max_faults_cpu;
	long unsigned int faults[0];
};
struct offset_ctx {
	struct maple_tree mt;
	long unsigned int next_offset;
};
struct per_cpu_pages {
	spinlock_t lock;
	int count;
	int high;
	int high_min;
	int high_max;
	int batch;
	u8 flags;
	u8 alloc_factor;
	u8 expire;
	short int free_count;
	struct list_head lists[14];
};
struct perf_buffer {
	refcount_t refcount;
	struct callback_head callback_head;
	int nr_pages;
	int overwrite;
	int paused;
	atomic_t poll;
	local_t head;
	unsigned int nest;
	local_t events;
	local_t wakeup;
	local_t lost;
	long int watermark;
	long int aux_watermark;
	spinlock_t event_lock;
	struct list_head event_list;
	atomic_t mmap_count;
	long unsigned int mmap_locked;
	struct user_struct *mmap_user;
	struct mutex aux_mutex;
	long int aux_head;
	unsigned int aux_nest;
	long int aux_wakeup;
	long unsigned int aux_pgoff;
	int aux_nr_pages;
	int aux_overwrite;
	atomic_t aux_mmap_count;
	long unsigned int aux_mmap_locked;
	void (*free_aux)(void *);
	refcount_t aux_refcount;
	int aux_in_sampling;
	void **aux_pages;
	void *aux_priv;
	struct perf_event_mmap_page *user_page;
	void *data_pages[0];
};
struct pm_subsys_data {
	spinlock_t lock;
	unsigned int refcount;
	unsigned int clock_op_might_sleep;
	struct mutex clock_mutex;
	struct list_head clock_list;
	struct pm_domain_data *domain_data;
};
struct ptr_ring {
	int producer;
	spinlock_t producer_lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	int consumer_head;
	int consumer_tail;
	spinlock_t consumer_lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	int size;
	int batch;
	void **queue;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct raw_hashinfo {
	spinlock_t lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct hlist_head ht[256];
};
struct sem_undo_list {
	refcount_t refcnt;
	spinlock_t lock;
	struct list_head list_proc;
};
typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;
struct badblocks {
	struct device *dev;
	int count;
	int unacked_exist;
	int shift;
	u64 *page;
	int changed;
	seqlock_t lock;
	sector_t sector;
	sector_t size;
};
struct hh_cache {
	unsigned int hh_len;
	seqlock_t hh_lock;
	long unsigned int hh_data[16];
};
struct inet_peer_base {
	struct rb_root rb_root;
	seqlock_t lock;
	int total;
};
struct fib6_table {
	struct hlist_node tb6_hlist;
	u32 tb6_id;
	spinlock_t tb6_lock;
	struct fib6_node tb6_root;
	struct inet_peer_base tb6_peers;
	unsigned int flags;
	unsigned int fib_seq;
};
struct ping_group_range {
	seqlock_t lock;
	kgid_t range[2];
};
struct netns_ipv4 {
	__u8 __cacheline_group_begin__netns_ipv4_read_tx[0];
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	int sysctl_tcp_min_snd_mss;
	unsigned int sysctl_tcp_notsent_lowat;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_min_rtt_wlen;
	int sysctl_tcp_wmem[3];
	u8 sysctl_ip_fwd_use_pmtu;
	__u8 __cacheline_group_end__netns_ipv4_read_tx[0];
	__u8 __cacheline_group_begin__netns_ipv4_read_txrx[0];
	u8 sysctl_tcp_moderate_rcvbuf;
	__u8 __cacheline_group_end__netns_ipv4_read_txrx[0];
	__u8 __cacheline_group_begin__netns_ipv4_read_rx[0];
	u8 sysctl_ip_early_demux;
	u8 sysctl_tcp_early_demux;
	int sysctl_tcp_reordering;
	int sysctl_tcp_rmem[3];
	__u8 __cacheline_group_end__netns_ipv4_read_rx[0];
	long: 64;
	struct inet_timewait_death_row tcp_death_row;
	struct udp_table *udp_table;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain *ra_chain;
	struct mutex ra_mutex;
	struct fib_rules_ops *rules_ops;
	struct fib_table *fib_main;
	struct fib_table *fib_default;
	unsigned int fib_rules_require_fldissect;
	bool fib_has_custom_rules;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	u8 sysctl_tcp_shrink_window;
	atomic_t fib_num_tclassid_users;
	struct hlist_head *fib_table_hash;
	struct sock *fibnl;
	struct sock *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_raw_l3mdev_accept;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_l3mdev_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	u8 sysctl_tcp_backlog_ack_defer;
	u8 sysctl_tcp_pingpong_thresh;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_challenge_ack_limit;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	unsigned int sysctl_tcp_child_ehash_entries;
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
	u8 sysctl_tcp_plb_enabled;
	u8 sysctl_tcp_plb_idle_rehash_rounds;
	u8 sysctl_tcp_plb_rehash_rounds;
	u8 sysctl_tcp_plb_suspend_rto_sec;
	int sysctl_tcp_plb_cong_thresh;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_tcp_syn_linear_timeouts;
	u8 sysctl_udp_l3mdev_accept;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	unsigned int sysctl_udp_child_hash_entries;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct list_head mr_tables;
	struct fib_rules_ops *mr_rules_ops;
	u32 sysctl_fib_multipath_hash_fields;
	u8 sysctl_fib_multipath_use_neigh;
	u8 sysctl_fib_multipath_hash_policy;
	struct fib_notifier_ops *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
	spinlock_t lock;
};
struct neighbour {
	struct neighbour *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	long: 0;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	void *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};
struct srcu_node {
	spinlock_t lock;
	long unsigned int srcu_have_cbs[4];
	long unsigned int srcu_data_have_cbs[4];
	long unsigned int srcu_gp_seq_needed_exp;
	struct srcu_node *srcu_parent;
	int grplo;
	int grphi;
};
struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};
struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};
struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};
struct cpu_stop_done {
	atomic_t nr_todo;
	int ret;
	struct completion completion;
};
struct cpuidle_device_kobj {
	struct cpuidle_device *dev;
	struct completion kobj_unregister;
	struct kobject kobj;
};
struct cpuidle_state_kobj {
	struct cpuidle_state *state;
	struct cpuidle_state_usage *state_usage;
	struct completion kobj_unregister;
	struct kobject kobj;
	struct cpuidle_device *device;
};
struct ctx_rq_wait {
	struct completion comp;
	atomic_t count;
};
struct inet_frags {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue *, const void *);
	void (*destructor)(struct inet_frag_queue *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};
struct shrinker {
	long unsigned int (*count_objects)(struct shrinker *, struct shrink_control *);
	long unsigned int (*scan_objects)(struct shrinker *, struct shrink_control *);
	long int batch;
	int seeks;
	unsigned int flags;
	refcount_t refcount;
	struct completion done;
	struct callback_head rcu;
	void *private_data;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};
struct swap_cluster_info {
	spinlock_t lock;
	unsigned int data: 24;
	unsigned int flags: 8;
};
struct percpu_cluster {
	struct swap_cluster_info index;
	unsigned int next;
};
struct swap_cluster_list {
	struct swap_cluster_info head;
	struct swap_cluster_info tail;
};
struct swregs_state {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u8 ftop;
	u8 changed;
	u8 lookahead;
	u8 no_update;
	u8 rm;
	u8 alimit;
	struct math_emu_info *info;
	u32 entry_eip;
};
struct task_delay_info {
	raw_spinlock_t lock;
	u64 blkio_start;
	u64 blkio_delay;
	u64 swapin_start;
	u64 swapin_delay;
	u32 blkio_count;
	u32 swapin_count;
	u64 freepages_start;
	u64 freepages_delay;
	u64 thrashing_start;
	u64 thrashing_delay;
	u64 compact_start;
	u64 compact_delay;
	u64 wpcopy_start;
	u64 wpcopy_delay;
	u64 irq_delay;
	u32 freepages_count;
	u32 thrashing_count;
	u32 compact_count;
	u32 wpcopy_count;
	u32 irq_count;
};
struct tcp_congestion_ops {
	u32 (*ssthresh)(struct sock *);
	void (*cong_avoid)(struct sock *, u32, u32);
	void (*set_state)(struct sock *, u8);
	void (*cwnd_event)(struct sock *, enum tcp_ca_event);
	void (*in_ack_event)(struct sock *, u32);
	void (*pkts_acked)(struct sock *, const struct ack_sample *);
	u32 (*min_tso_segs)(struct sock *);
	void (*cong_control)(struct sock *, const struct rate_sample *);
	u32 (*undo_cwnd)(struct sock *);
	u32 (*sndbuf_expand)(struct sock *);
	size_t (*get_info)(struct sock *, u32, int *, union tcp_cc_info *);
	char name[16];
	struct module *owner;
	struct list_head list;
	u32 key;
	u32 flags;
	void (*init)(struct sock *);
	void (*release)(struct sock *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct trace_iterator {
	struct trace_array *tr;
	struct tracer *trace;
	struct array_buffer *array_buffer;
	void *private;
	int cpu_file;
	struct mutex mutex;
	struct ring_buffer_iter **buffer_iter;
	long unsigned int iter_flags;
	void *temp;
	unsigned int temp_size;
	char *fmt;
	unsigned int fmt_size;
	atomic_t wait_index;
	struct trace_seq tmp_seq;
	cpumask_var_t started;
	bool closed;
	bool snapshot;
	struct trace_seq seq;
	struct trace_entry *ent;
	long unsigned int lost_events;
	int leftover;
	int ent_size;
	int cpu;
	u64 ts;
	loff_t pos;
	long int idx;
};
struct trace_pid_list {
	raw_spinlock_t lock;
	struct irq_work refill_irqwork;
	union upper_chunk *upper[256];
	union upper_chunk *upper_list;
	union lower_chunk *lower_list;
	int free_upper_chunks;
	int free_lower_chunks;
};
struct tty_audit_buf {
	struct mutex mutex;
	dev_t dev;
	bool icanon;
	size_t valid;
	u8 *data;
};
struct tty_buffer {
	union {
		struct tty_buffer *next;
		struct llist_node free;
	};
	unsigned int used;
	unsigned int size;
	unsigned int commit;
	unsigned int lookahead;
	unsigned int read;
	bool flags;
	long: 0;
	u8 data[0];
};
struct tty_ldisc_ops {
	char *name;
	int num;
	int (*open)(struct tty_struct *);
	void (*close)(struct tty_struct *);
	void (*flush_buffer)(struct tty_struct *);
	ssize_t (*read)(struct tty_struct *, struct file *, u8 *, size_t, void **, long unsigned int);
	ssize_t (*write)(struct tty_struct *, struct file *, const u8 *, size_t);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, const struct ktermios *);
	__poll_t (*poll)(struct tty_struct *, struct file *, struct poll_table_struct *);
	void (*hangup)(struct tty_struct *);
	void (*receive_buf)(struct tty_struct *, const u8 *, const u8 *, size_t);
	void (*write_wakeup)(struct tty_struct *);
	void (*dcd_change)(struct tty_struct *, bool);
	size_t (*receive_buf2)(struct tty_struct *, const u8 *, const u8 *, size_t);
	void (*lookahead_buf)(struct tty_struct *, const u8 *, const u8 *, size_t);
	struct module *owner;
};
struct tty_operations {
	struct tty_struct * (*lookup)(void *, struct file *, int);
	int (*install)(void *, struct tty_struct *);
	void (*remove)(void *, struct tty_struct *);
	int (*open)(struct tty_struct *, struct file *);
	void (*close)(struct tty_struct *, struct file *);
	void (*shutdown)(struct tty_struct *);
	void (*cleanup)(struct tty_struct *);
	ssize_t (*write)(struct tty_struct *, const u8 *, size_t);
	int (*put_char)(struct tty_struct *, u8);
	void (*flush_chars)(struct tty_struct *);
	unsigned int (*write_room)(struct tty_struct *);
	unsigned int (*chars_in_buffer)(struct tty_struct *);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, const struct ktermios *);
	void (*throttle)(struct tty_struct *);
	void (*unthrottle)(struct tty_struct *);
	void (*stop)(struct tty_struct *);
	void (*start)(struct tty_struct *);
	void (*hangup)(struct tty_struct *);
	int (*break_ctl)(struct tty_struct *, int);
	void (*flush_buffer)(struct tty_struct *);
	int (*ldisc_ok)(struct tty_struct *, int);
	void (*set_ldisc)(struct tty_struct *);
	void (*wait_until_sent)(struct tty_struct *, int);
	void (*send_xchar)(struct tty_struct *, u8);
	int (*tiocmget)(struct tty_struct *);
	int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);
	int (*resize)(struct tty_struct *, struct winsize *);
	int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *);
	int (*get_serial)(struct tty_struct *, struct serial_struct *);
	int (*set_serial)(struct tty_struct *, struct serial_struct *);
	void (*show_fdinfo)(struct tty_struct *, struct seq_file *);
	int (*poll_init)(void *, int, char *);
	int (*poll_get_char)(void *, int);
	void (*poll_put_char)(void *, int, char);
	int (*proc_show)(struct seq_file *, void *);
};
struct tty_port_client_operations {
	size_t (*receive_buf)(struct tty_port *, const u8 *, const u8 *, size_t);
	void (*lookahead_buf)(struct tty_port *, const u8 *, const u8 *, size_t);
	void (*write_wakeup)(struct tty_port *);
};
typedef u16 u_int16_t;
struct nf_conntrack_man {
	union nf_inet_addr u3;
	union nf_conntrack_man_proto u;
	u_int16_t l3num;
};
typedef u32 u_int32_t;
typedef u64 u_int64_t;
typedef u8 u_int8_t;
struct ip_ct_tcp_state {
	u_int32_t td_end;
	u_int32_t td_maxend;
	u_int32_t td_maxwin;
	u_int32_t td_maxack;
	u_int8_t td_scale;
	u_int8_t flags;
};
struct ip_ct_tcp {
	struct ip_ct_tcp_state seen[2];
	u_int8_t state;
	u_int8_t last_dir;
	u_int8_t retrans;
	u_int8_t last_index;
	u_int32_t last_seq;
	u_int32_t last_ack;
	u_int32_t last_end;
	u_int16_t last_win;
	u_int8_t last_wscale;
	u_int8_t last_flags;
};
struct nf_conntrack_tuple {
	struct nf_conntrack_man src;
	struct {
		union nf_inet_addr u3;
		union {
			__be16 all;
			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				u_int8_t type;
				u_int8_t code;
			} icmp;
			struct {
				__be16 port;
			} dccp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;
		u_int8_t protonum;
		struct {} __nfct_hash_offsetend;
		u_int8_t dir;
	} dst;
};
struct nf_conntrack_expect {
	struct hlist_node lnode;
	struct hlist_node hnode;
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_mask mask;
	refcount_t use;
	unsigned int flags;
	unsigned int class;
	void (*expectfn)(struct nf_conn *, struct nf_conntrack_expect *);
	struct nf_conntrack_helper *helper;
	struct nf_conn *master;
	struct timer_list timeout;
	union nf_inet_addr saved_addr;
	union nf_conntrack_man_proto saved_proto;
	enum ip_conntrack_dir dir;
	struct callback_head rcu;
};
struct nf_conntrack_tuple_hash {
	struct hlist_nulls_node hnnode;
	struct nf_conntrack_tuple tuple;
};
struct nf_ct_dccp {
	u_int8_t role[2];
	u_int8_t state;
	u_int8_t last_pkt;
	u_int8_t last_dir;
	u_int64_t handshake_seq;
};
union nf_conntrack_proto {
	struct nf_ct_dccp dccp;
	struct ip_ct_sctp sctp;
	struct ip_ct_tcp tcp;
	struct nf_ct_udp udp;
	struct nf_ct_gre gre;
	unsigned int tmpl_padto;
};
struct nf_conn {
	struct nf_conntrack ct_general;
	spinlock_t lock;
	u32 timeout;
	struct nf_conntrack_zone zone;
	struct nf_conntrack_tuple_hash tuplehash[2];
	long unsigned int status;
	possible_net_t ct_net;
	struct hlist_node nat_bysource;
	struct {} __nfct_init_offset;
	struct nf_conn *master;
	u_int32_t mark;
	u_int32_t secmark;
	struct nf_ct_ext *ext;
	union nf_conntrack_proto proto;
};
typedef void nf_logfn(struct net *, u_int8_t, unsigned int, const struct sk_buff *, const void *, const void *, const struct nf_loginfo *, const char *);
struct nf_logger {
	char *name;
	enum nf_log_type type;
	nf_logfn *logfn;
	struct module *me;
};
struct nf_loginfo {
	u_int8_t type;
	union {
		struct {
			u_int32_t copy_len;
			u_int16_t group;
			u_int16_t qthreshold;
			u_int16_t flags;
		} ulog;
		struct {
			u_int8_t level;
			u_int8_t logflags;
		} log;
	} u;
};
struct ubuf_info {
	void (*callback)(struct sk_buff *, struct ubuf_info *, bool);
	refcount_t refcnt;
	u8 flags;
};
struct uclamp_bucket {
	long unsigned int value: 11;
	long unsigned int tasks: 53;
};
struct uclamp_rq {
	unsigned int value;
	struct uclamp_bucket bucket[5];
};
struct rq {
	raw_spinlock_t __lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;
	long: 64;
	long: 64;
	long: 64;
	call_single_data_t nohz_csd;
	unsigned int nohz_tick_stopped;
	atomic_t nohz_flags;
	unsigned int ttwu_pending;
	u64 nr_switches;
	long: 64;
	struct uclamp_rq uclamp[2];
	unsigned int uclamp_flags;
	long: 64;
	long: 64;
	long: 64;
	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;
	struct list_head leaf_cfs_rq_list;
	struct list_head *tmp_alone_branch;
	unsigned int nr_uninterruptible;
	struct task_struct *curr;
	struct task_struct *idle;
	struct task_struct *stop;
	long unsigned int next_balance;
	struct mm_struct *prev_mm;
	unsigned int clock_update_flags;
	u64 clock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u64 clock_task;
	u64 clock_pelt;
	long unsigned int lost_idle_time;
	u64 clock_pelt_idle;
	u64 clock_idle;
	atomic_t nr_iowait;
	u64 last_seen_need_resched_ns;
	int ticks_without_resched;
	int membarrier_state;
	struct root_domain *rd;
	struct sched_domain *sd;
	long unsigned int cpu_capacity;
	struct balance_callback *balance_callback;
	unsigned char nohz_idle_balance;
	unsigned char idle_balance;
	long unsigned int misfit_task_load;
	int active_balance;
	int push_cpu;
	struct cpu_stop_work active_balance_work;
	int cpu;
	int online;
	struct list_head cfs_tasks;
	struct sched_avg avg_rt;
	struct sched_avg avg_dl;
	u64 idle_stamp;
	u64 avg_idle;
	u64 max_idle_balance_cost;
	struct rcuwait hotplug_wait;
	u64 prev_steal_time;
	long unsigned int calc_load_update;
	long int calc_load_active;
	long: 64;
	call_single_data_t hrtick_csd;
	struct hrtimer hrtick_timer;
	ktime_t hrtick_time;
	struct sched_info rq_sched_info;
	long long unsigned int rq_cpu_time;
	unsigned int yld_count;
	unsigned int sched_count;
	unsigned int sched_goidle;
	unsigned int ttwu_count;
	unsigned int ttwu_local;
	struct cpuidle_state *idle_state;
	unsigned int nr_pinned;
	unsigned int push_busy;
	struct cpu_stop_work push_work;
	struct rq *core;
	struct task_struct *core_pick;
	unsigned int core_enabled;
	unsigned int core_sched_seq;
	struct rb_root core_tree;
	unsigned int core_task_seq;
	unsigned int core_pick_seq;
	long unsigned int core_cookie;
	unsigned int core_forceidle_count;
	unsigned int core_forceidle_seq;
	unsigned int core_forceidle_occupation;
	u64 core_forceidle_start;
	cpumask_var_t scratch_mask;
	long: 64;
	call_single_data_t cfsb_csd;
	struct list_head cfsb_csd_list;
	long: 64;
	long: 64;
};
struct uclamp_se {
	unsigned int value: 11;
	unsigned int bucket_id: 3;
	unsigned int active: 1;
	unsigned int user_defined: 1;
};
struct udp_hslot {
	struct hlist_head head;
	int count;
	spinlock_t lock;
};
struct udp_mib {
	long unsigned int mibs[10];
};
struct udp_table {
	struct udp_hslot *hash;
	struct udp_hslot *hash2;
	unsigned int mask;
	unsigned int log;
};
struct uevent_sock {
	struct list_head list;
	struct sock *sk;
};
struct uid_gid_extent {
	u32 first;
	u32 lower_first;
	u32 count;
};
struct uid_gid_map {
	u32 nr_extents;
	union {
		struct uid_gid_extent extent[5];
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};
struct mnt_idmap {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	refcount_t count;
};
typedef __kernel_uid32_t uid_t;
typedef struct {
	uid_t val;
} kuid_t;
struct audit_cap_data {
	kernel_cap_t permitted;
	kernel_cap_t inheritable;
	union {
		unsigned int fE;
		kernel_cap_t effective;
	};
	kernel_cap_t ambient;
	kuid_t rootid;
};
struct cred {
	atomic_long_t usage;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned int securebits;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	kernel_cap_t cap_bset;
	kernel_cap_t cap_ambient;
	unsigned char jit_keyring;
	struct key *session_keyring;
	struct key *process_keyring;
	struct key *thread_keyring;
	struct key *request_key_auth;
	void *security;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union {
		int non_rcu;
		struct callback_head rcu;
	};
};
struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, struct ctl_table *);
};
struct eventfs_attr {
	int mode;
	kuid_t uid;
	kgid_t gid;
};
struct eventfs_inode {
	union {
		struct list_head list;
		struct callback_head rcu;
	};
	struct list_head children;
	const struct eventfs_entry *entries;
	const char *name;
	struct eventfs_attr *entry_attrs;
	void *data;
	struct eventfs_attr attr;
	struct kref kref;
	unsigned int is_freed: 1;
	unsigned int is_events: 1;
	unsigned int nr_entries: 30;
	unsigned int ino;
};
struct fib_kuid_range {
	kuid_t start;
	kuid_t end;
};
struct fib_rule {
	struct list_head list;
	int iifindex;
	int oifindex;
	u32 mark;
	u32 mark_mask;
	u32 flags;
	u32 table;
	u8 action;
	u8 l3mdev;
	u8 proto;
	u8 ip_proto;
	u32 target;
	__be64 tun_id;
	struct fib_rule *ctarget;
	struct net *fr_net;
	refcount_t refcnt;
	u32 pref;
	int suppress_ifgroup;
	int suppress_prefixlen;
	char iifname[16];
	char oifname[16];
	struct fib_kuid_range uid_range;
	struct fib_rule_port_range sport_range;
	struct fib_rule_port_range dport_range;
	struct callback_head rcu;
};
struct flowi_common {
	int flowic_oif;
	int flowic_iif;
	int flowic_l3mdev;
	__u32 flowic_mark;
	__u8 flowic_tos;
	__u8 flowic_scope;
	__u8 flowic_proto;
	__u8 flowic_flags;
	__u32 flowic_secid;
	kuid_t flowic_uid;
	__u32 flowic_multipath_hash;
	struct flowi_tunnel flowic_tun_key;
};
struct flowi4 {
	struct flowi_common __fl_common;
	__be32 saddr;
	__be32 daddr;
	union flowi_uli uli;
};
struct flowi6 {
	struct flowi_common __fl_common;
	struct in6_addr daddr;
	struct in6_addr saddr;
	__be32 flowlabel;
	union flowi_uli uli;
	__u32 mp_hash;
};
struct flowi {
	union {
		struct flowi_common __fl_common;
		struct flowi4 ip4;
		struct flowi6 ip6;
	} u;
};
struct fown_struct {
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};
struct file {
	union {
		struct callback_head f_task_work;
		struct llist_node f_llist;
		unsigned int f_iocb_flags;
	};
	spinlock_t f_lock;
	fmode_t f_mode;
	atomic_long_t f_count;
	struct mutex f_pos_lock;
	loff_t f_pos;
	unsigned int f_flags;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	struct path f_path;
	struct inode *f_inode;
	const struct file_operations *f_op;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};
struct fs_parse_result {
	bool negated;
	union {
		bool boolean;
		int int_32;
		unsigned int uint_32;
		u64 uint_64;
		kuid_t uid;
		kgid_t gid;
	};
};
struct kernfs_iattrs {
	kuid_t ia_uid;
	kgid_t ia_gid;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct simple_xattrs xattrs;
	atomic_t nr_user_xattrs;
	atomic_t user_xattr_size;
};
struct key_user {
	struct rb_node node;
	struct mutex cons_lock;
	spinlock_t lock;
	refcount_t usage;
	atomic_t nkeys;
	atomic_t nikeys;
	kuid_t uid;
	int qnkeys;
	int qnbytes;
};
struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(const struct kobject *);
	const void * (*namespace)(const struct kobject *);
	void (*get_ownership)(const struct kobject *, kuid_t *, kgid_t *);
};
struct kqid {
	union {
		kuid_t uid;
		kgid_t gid;
		kprojid_t projid;
	};
	enum quota_type type;
};
struct dquot {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};
struct posix_acl_entry {
	short int e_tag;
	short unsigned int e_perm;
	union {
		kuid_t e_uid;
		kgid_t e_gid;
	};
};
struct posix_acl {
	refcount_t a_refcount;
	struct callback_head a_rcu;
	unsigned int a_count;
	struct posix_acl_entry a_entries[0];
};
struct quotactl_ops {
	int (*quota_on)(struct super_block *, int, int, const struct path *);
	int (*quota_off)(struct super_block *, int);
	int (*quota_enable)(struct super_block *, unsigned int);
	int (*quota_disable)(struct super_block *, unsigned int);
	int (*quota_sync)(struct super_block *, int);
	int (*set_info)(struct super_block *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block *, struct qc_state *);
	int (*rm_xquota)(struct super_block *, unsigned int);
};
struct trace_array_cpu {
	atomic_t disabled;
	void *buffer_page;
	long unsigned int entries;
	long unsigned int saved_latency;
	long unsigned int critical_start;
	long unsigned int critical_end;
	long unsigned int critical_sequence;
	long unsigned int nice;
	long unsigned int policy;
	long unsigned int rt_priority;
	long unsigned int skipped_entries;
	u64 preempt_timestamp;
	pid_t pid;
	kuid_t uid;
	char comm[16];
	int ftrace_ignore_pid;
	bool ignore_pid;
};
struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[12];
	atomic_long_t rlimit[4];
};
typedef u32 uint32_t;
typedef uint32_t key_perm_t;
struct key {
	refcount_t usage;
	key_serial_t serial;
	union {
		struct list_head graveyard_link;
		struct rb_node serial_node;
	};
	struct watch_list *watchers;
	struct rw_semaphore sem;
	struct key_user *user;
	void *security;
	union {
		time64_t expiry;
		time64_t revoked_at;
	};
	time64_t last_used_at;
	kuid_t uid;
	kgid_t gid;
	key_perm_t perm;
	short unsigned int quotalen;
	short unsigned int datalen;
	short int state;
	long unsigned int flags;
	union {
		struct keyring_index_key index_key;
		struct {
			long unsigned int hash;
			long unsigned int len_desc;
			struct key_type *type;
			struct key_tag *domain_tag;
			char *description;
		};
	};
	union {
		union key_payload payload;
		struct {
			struct list_head name_link;
			struct assoc_array keys;
		};
	};
	struct key_restriction *restrict_link;
};
struct of_phandle_args {
	struct device_node *np;
	int args_count;
	uint32_t args[16];
};
typedef short unsigned int umode_t;
struct attribute {
	const char *name;
	umode_t mode;
};
struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
	struct attribute **attrs;
	struct bin_attribute **bin_attrs;
};
struct audit_names {
	struct list_head list;
	struct filename *name;
	int name_len;
	bool hidden;
	long unsigned int ino;
	dev_t dev;
	umode_t mode;
	kuid_t uid;
	kgid_t gid;
	dev_t rdev;
	struct lsmblob oblob;
	struct audit_cap_data fcap;
	unsigned int fcap_ver;
	unsigned char type;
	bool should_free;
};
struct bin_attribute {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space * (*f_mapping)(void);
	ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*write)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	loff_t (*llseek)(struct file *, struct kobject *, struct bin_attribute *, loff_t, int);
	int (*mmap)(struct file *, struct kobject *, struct bin_attribute *, struct vm_area_struct *);
};
struct blk_mq_debugfs_attr {
	const char *name;
	umode_t mode;
	int (*show)(void *, struct seq_file *);
	ssize_t (*write)(void *, const char *, size_t, loff_t *);
	const struct seq_operations *seq_ops;
};
struct block_device_operations {
	void (*submit_bio)(struct bio *);
	int (*poll_bio)(struct bio *, struct io_comp_batch *, unsigned int);
	int (*open)(struct gendisk *, blk_mode_t);
	void (*release)(struct gendisk *);
	int (*ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	unsigned int (*check_events)(struct gendisk *, unsigned int);
	void (*unlock_native_capacity)(struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *, bool);
	void (*free_disk)(struct gendisk *);
	void (*swap_slot_free_notify)(struct block_device *, long unsigned int);
	int (*report_zones)(struct gendisk *, sector_t, unsigned int, report_zones_cb, void *);
	char * (*devnode)(struct gendisk *, umode_t *);
	int (*get_unique_id)(struct gendisk *, u8 *, enum blk_unique_id);
	struct module *owner;
	const struct pr_ops *pr_ops;
	int (*alternative_gpt_sector)(struct gendisk *, sector_t *);
};
struct class {
	const char *name;
	const struct attribute_group **class_groups;
	const struct attribute_group **dev_groups;
	int (*dev_uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *);
	void (*class_release)(const struct class *);
	void (*dev_release)(struct device *);
	int (*shutdown_pre)(struct device *);
	const struct kobj_ns_type_operations *ns_type;
	const void * (*namespace)(const struct device *);
	void (*get_ownership)(const struct device *, kuid_t *, kgid_t *);
	const struct dev_pm_ops *pm;
};
struct ctl_table {
	const char *procname;
	void *data;
	int maxlen;
	umode_t mode;
	enum {
		SYSCTL_TABLE_TYPE_DEFAULT = 0,
		SYSCTL_TABLE_TYPE_PERMANENTLY_EMPTY = 1,
	} type;
	proc_handler *proc_handler;
	struct ctl_table_poll *poll;
	void *extra1;
	void *extra2;
};
struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *, struct device_attribute *, char *);
	ssize_t (*store)(struct device *, struct device_attribute *, const char *, size_t);
};
struct device_type {
	const char *name;
	const struct attribute_group **groups;
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device *);
	const struct dev_pm_ops *pm;
};
struct elv_fs_entry {
	struct attribute attr;
	ssize_t (*show)(struct elevator_queue *, char *);
	ssize_t (*store)(struct elevator_queue *, const char *, size_t);
};
typedef int (*eventfs_callback)(const char *, umode_t *, void **, const struct file_operations **);
struct eventfs_entry {
	const char *name;
	eventfs_callback callback;
	eventfs_release release;
};
struct inode_operations {
	struct dentry * (*lookup)(struct inode *, struct dentry *, unsigned int);
	const char * (*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct mnt_idmap *, struct inode *, int);
	struct posix_acl * (*get_inode_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char *, int);
	int (*create)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, bool);
	int (*link)(struct dentry *, struct inode *, struct dentry *);
	int (*unlink)(struct inode *, struct dentry *);
	int (*symlink)(struct mnt_idmap *, struct inode *, struct dentry *, const char *);
	int (*mkdir)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
	int (*rmdir)(struct inode *, struct dentry *);
	int (*mknod)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, dev_t);
	int (*rename)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
	int (*setattr)(struct mnt_idmap *, struct dentry *, struct iattr *);
	int (*getattr)(struct mnt_idmap *, const struct path *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode *, int);
	int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned int, umode_t);
	int (*tmpfile)(struct mnt_idmap *, struct inode *, struct file *, umode_t);
	struct posix_acl * (*get_acl)(struct mnt_idmap *, struct dentry *, int);
	int (*set_acl)(struct mnt_idmap *, struct dentry *, struct posix_acl *, int);
	int (*fileattr_set)(struct mnt_idmap *, struct dentry *, struct fileattr *);
	int (*fileattr_get)(struct dentry *, struct fileattr *);
	struct offset_ctx * (*get_offset_ctx)(struct inode *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct kernfs_node {
	atomic_t count;
	atomic_t active;
	struct kernfs_node *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink symlink;
		struct kernfs_elem_attr attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
	struct callback_head rcu;
};
struct kernfs_syscall_ops {
	int (*show_options)(struct seq_file *, struct kernfs_root *);
	int (*mkdir)(struct kernfs_node *, const char *, umode_t);
	int (*rmdir)(struct kernfs_node *);
	int (*rename)(struct kernfs_node *, struct kernfs_node *, const char *);
	int (*show_path)(struct seq_file *, struct kernfs_node *, struct kernfs_root *);
};
struct kstat {
	u32 result_mask;
	umode_t mode;
	unsigned int nlink;
	uint32_t blksize;
	u64 attributes;
	u64 attributes_mask;
	u64 ino;
	dev_t dev;
	dev_t rdev;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct timespec64 btime;
	u64 blocks;
	u64 mnt_id;
	u32 dio_mem_align;
	u32 dio_offset_align;
	u64 change_cookie;
};
struct module_attribute {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
	ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
};
struct module_notes_attrs {
	struct kobject *dir;
	unsigned int notes;
	struct bin_attribute attrs[0];
};
struct module_sect_attr {
	struct bin_attribute battr;
	long unsigned int address;
};
struct module_sect_attrs {
	struct attribute_group grp;
	unsigned int nsections;
	struct module_sect_attr attrs[0];
};
struct param_attribute {
	struct module_attribute mattr;
	const struct kernel_param *param;
};
struct module_param_attrs {
	unsigned int num;
	struct attribute_group grp;
	struct param_attribute attrs[0];
};
struct proc_dir_entry {
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	union {
		const struct proc_ops *proc_ops;
		const struct file_operations *proc_dir_ops;
	};
	const struct dentry_operations *proc_dops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	proc_write_t write;
	void *data;
	unsigned int state_size;
	unsigned int low_ino;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	char *name;
	umode_t mode;
	u8 flags;
	u8 namelen;
	char inline_name[0];
};
struct rchan_callbacks {
	int (*subbuf_start)(struct rchan_buf *, void *, void *, size_t);
	struct dentry * (*create_buf_file)(const char *, struct dentry *, umode_t, struct rchan_buf *, int *);
	int (*remove_buf_file)(struct dentry *);
};
struct uncached_list {
	spinlock_t lock;
	struct list_head head;
	struct list_head quarantine;
};
struct unicode_map {
	unsigned int version;
	const struct utf8data *ntab[2];
	const struct utf8data_table *tables;
};
struct unix_table {
	spinlock_t *locks;
	struct hlist_head *buckets;
};
struct netns_unix {
	struct unix_table table;
	int sysctl_max_dgram_qlen;
	struct ctl_table_header *ctl;
};
struct upid {
	int nr;
	struct pid_namespace *ns;
};
union upper_chunk {
	union upper_chunk *next;
	union lower_chunk *data[256];
};
struct uprobe {
	struct rb_node rb_node;
	refcount_t ref;
	struct rw_semaphore register_rwsem;
	struct rw_semaphore consumer_rwsem;
	struct list_head pending_list;
	struct uprobe_consumer *consumers;
	struct inode *inode;
	loff_t offset;
	loff_t ref_ctr_offset;
	long unsigned int flags;
	struct arch_uprobe arch;
};
enum uprobe_filter_ctx {
	UPROBE_FILTER_REGISTER = 0,
	UPROBE_FILTER_UNREGISTER = 1,
	UPROBE_FILTER_MMAP = 2,
};
struct uprobe_consumer {
	int (*handler)(struct uprobe_consumer *, struct pt_regs *);
	int (*ret_handler)(struct uprobe_consumer *, long unsigned int, struct pt_regs *);
	bool (*filter)(struct uprobe_consumer *, enum uprobe_filter_ctx, struct mm_struct *);
	struct uprobe_consumer *next;
};
enum uprobe_task_state {
	UTASK_RUNNING = 0,
	UTASK_SSTEP = 1,
	UTASK_SSTEP_ACK = 2,
	UTASK_SSTEP_TRAPPED = 3,
};
struct uprobe_task {
	enum uprobe_task_state state;
	union {
		struct {
			struct arch_uprobe_task autask;
			long unsigned int vaddr;
		};
		struct {
			struct callback_head dup_xol_work;
			long unsigned int dup_xol_addr;
		};
	};
	struct uprobe *active_uprobe;
	long unsigned int xol_vaddr;
	struct arch_uprobe *auprobe;
	struct return_instance *return_instances;
	unsigned int depth;
};
struct uprobe_xol_ops {
	bool (*emulate)(struct arch_uprobe *, struct pt_regs *);
	int (*pre_xol)(struct arch_uprobe *, struct pt_regs *);
	int (*post_xol)(struct arch_uprobe *, struct pt_regs *);
	void (*abort)(struct arch_uprobe *, struct pt_regs *);
};
struct uprobes_state {
	struct xol_area *xol_area;
};
struct user_struct {
	refcount_t __count;
	struct percpu_counter epoll_watches;
	long unsigned int unix_inflight;
	atomic_long_t pipe_bufs;
	struct hlist_node uidhash_node;
	kuid_t uid;
	atomic_long_t locked_vm;
	atomic_t nr_watches;
	struct ratelimit_state ratelimit;
};
struct utf8data {
	unsigned int maxage;
	unsigned int offset;
};
struct utf8data_table {
	const unsigned int *utf8agetab;
	int utf8agetab_size;
	const struct utf8data *utf8nfdicfdata;
	int utf8nfdicfdata_size;
	const struct utf8data *utf8nfdidata;
	int utf8nfdidata_size;
	const unsigned char *utf8data;
};
struct uts_namespace {
	struct new_utsname name;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
};
typedef struct {
	__u8 b[16];
} uuid_t;
struct uv_alloc_info {
	int limit;
	int blade;
	long unsigned int offset;
	char *name;
};
struct irq_alloc_info {
	enum irq_alloc_type type;
	u32 flags;
	u32 devid;
	irq_hw_number_t hwirq;
	const struct cpumask *mask;
	struct msi_desc *desc;
	void *data;
	union {
		struct ioapic_alloc_info ioapic;
		struct uv_alloc_info uv;
	};
};
typedef struct irq_alloc_info msi_alloc_info_t;
struct msi_domain_ops {
	irq_hw_number_t (*get_hwirq)(struct msi_domain_info *, msi_alloc_info_t *);
	int (*msi_init)(struct irq_domain *, struct msi_domain_info *, unsigned int, irq_hw_number_t, msi_alloc_info_t *);
	void (*msi_free)(struct irq_domain *, struct msi_domain_info *, unsigned int);
	int (*msi_prepare)(struct irq_domain *, struct device *, int, msi_alloc_info_t *);
	void (*prepare_desc)(struct irq_domain *, msi_alloc_info_t *, struct msi_desc *);
	void (*set_desc)(msi_alloc_info_t *, struct msi_desc *);
	int (*domain_alloc_irqs)(struct irq_domain *, struct device *, int);
	void (*domain_free_irqs)(struct irq_domain *, struct device *);
	void (*msi_post_free)(struct irq_domain *, struct device *);
};
struct platform_msi_priv_data {
	struct device *dev;
	void *host_data;
	msi_alloc_info_t arg;
	irq_write_msi_msg_t write_msg;
	int devid;
};
struct vdso_image {
	void *data;
	long unsigned int size;
	long unsigned int alt;
	long unsigned int alt_len;
	long unsigned int extable_base;
	long unsigned int extable_len;
	const void *extable;
	long int sym_vvar_start;
	long int sym_vvar_page;
	long int sym_pvclock_page;
	long int sym_hvclock_page;
	long int sym_timens_page;
	long int sym_VDSO32_NOTE_MASK;
	long int sym___kernel_sigreturn;
	long int sym___kernel_rt_sigreturn;
	long int sym___kernel_vsyscall;
	long int sym_int80_landing_pad;
	long int sym_vdso32_sigreturn_landing_pad;
	long int sym_vdso32_rt_sigreturn_landing_pad;
};
typedef struct {
	gid_t val;
} vfsgid_t;
struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
	struct mnt_idmap *mnt_idmap;
};
struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rb_node mnt_node;
		struct callback_head mnt_rcu;
		struct llist_node mnt_llist;
	};
	struct mnt_pcp *mnt_pcp;
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	struct list_head mnt_instance;
	const char *mnt_devname;
	struct list_head mnt_list;
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct mount *mnt_master;
	struct mnt_namespace *mnt_ns;
	struct mountpoint *mnt_mp;
	union {
		struct hlist_node mnt_mp_list;
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting;
	struct fsnotify_mark_connector *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
	int mnt_id;
	u64 mnt_id_unique;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
};
typedef struct {
	uid_t val;
} vfsuid_t;
struct iattr {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file *ia_file;
};
struct nameidata {
	struct path path;
	struct qstr last;
	struct path root;
	struct inode *inode;
	unsigned int flags;
	unsigned int state;
	unsigned int seq;
	unsigned int next_seq;
	unsigned int m_seq;
	unsigned int r_seq;
	int last_type;
	unsigned int depth;
	int total_link_count;
	struct saved *stack;
	struct saved internal[2];
	struct filename *name;
	struct nameidata *saved;
	unsigned int root_seq;
	int dfd;
	vfsuid_t dir_vfsuid;
	umode_t dir_mode;
};
struct vm_fault {
	const struct {
		struct vm_area_struct *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page *cow_page;
	struct page *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t prealloc_pte;
};
typedef unsigned int vm_fault_t;
struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
	int (*memory_failure)(struct dev_pagemap *, long unsigned int, long unsigned int, int);
};
typedef long unsigned int vm_flags_t;
struct vm_operations_struct {
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, long unsigned int);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, unsigned int);
	vm_fault_t (*map_pages)(struct vm_fault *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct *);
	int (*set_policy)(struct vm_area_struct *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct *, long unsigned int, long unsigned int *);
	struct page * (*find_special_page)(struct vm_area_struct *, long unsigned int);
};
struct vm_special_mapping {
	const char *name;
	struct page **pages;
	vm_fault_t (*fault)(const struct vm_special_mapping *, struct vm_area_struct *, struct vm_fault *);
	int (*mremap)(const struct vm_special_mapping *, struct vm_area_struct *);
};
struct vm_struct {
	struct vm_struct *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};
struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};
struct vm_area_struct {
	union {
		struct {
			long unsigned int vm_start;
			long unsigned int vm_end;
		};
		struct callback_head vm_rcu;
	};
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	union {
		const vm_flags_t vm_flags;
		vm_flags_t __vm_flags;
	};
	int vm_lock_seq;
	struct vma_lock *vm_lock;
	bool detached;
	struct {
		struct rb_node rb;
		long unsigned int rb_subtree_last;
	} shared;
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	long unsigned int vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	struct anon_vma_name *anon_name;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vma_numab_state *numab_state;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};
struct vma_lock {
	struct rw_semaphore lock;
};
struct vma_numab_state {
	long unsigned int next_scan;
	long unsigned int pids_active_reset;
	long unsigned int pids_active[2];
	int start_scan_seq;
	int prev_scan_seq;
};
struct vmem_altmap {
	long unsigned int base_pfn;
	const long unsigned int end_pfn;
	const long unsigned int reserve;
	long unsigned int free;
	long unsigned int align;
	long unsigned int alloc;
	bool inaccessible;
};
struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct {
			struct {} __empty_ranges;
			struct range ranges[0];
		};
	};
};
enum vtime_state {
	VTIME_INACTIVE = 0,
	VTIME_IDLE = 1,
	VTIME_SYS = 2,
	VTIME_USER = 3,
	VTIME_GUEST = 4,
};
struct vtime {
	seqcount_t seqcount;
	long long unsigned int starttime;
	enum vtime_state state;
	unsigned int cpu;
	u64 utime;
	u64 stime;
	u64 gtime;
};
typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned int, int, void *);
struct wait_queue_entry {
	unsigned int flags;
	void *private;
	wait_queue_func_t func;
	struct list_head entry;
};
struct io_poll {
	struct file *file;
	struct wait_queue_head *head;
	__poll_t events;
	int retries;
	struct wait_queue_entry wait;
};
struct async_poll {
	union {
		struct io_poll poll;
		struct io_cache_entry cache;
	};
	struct io_poll *double_poll;
};
struct io_wq {
	long unsigned int state;
	free_work_fn *free_work;
	io_wq_work_fn *do_work;
	struct io_wq_hash *hash;
	atomic_t worker_refs;
	struct completion worker_done;
	struct hlist_node cpuhp_node;
	struct task_struct *task;
	struct io_wq_acct acct[2];
	raw_spinlock_t lock;
	struct hlist_nulls_head free_list;
	struct list_head all_list;
	struct wait_queue_entry wait;
	struct io_wq_work *hash_tail[64];
	cpumask_var_t cpu_mask;
};
typedef struct wait_queue_entry wait_queue_entry_t;
struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};
struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};
struct io_sq_data {
	refcount_t refs;
	atomic_t park_pending;
	struct mutex lock;
	struct list_head ctx_list;
	struct task_struct *thread;
	struct wait_queue_head wait;
	unsigned int sq_thread_idle;
	int sq_cpu;
	pid_t task_pid;
	pid_t task_tgid;
	long unsigned int state;
	struct completion exited;
};
struct io_wq_hash {
	refcount_t refs;
	long unsigned int map;
	struct wait_queue_head wait;
};
typedef struct wait_queue_head wait_queue_head_t;
struct aa_ns {
	struct aa_policy base;
	struct aa_ns *parent;
	struct mutex lock;
	struct aa_ns_acct acct;
	struct aa_profile *unconfined;
	struct list_head sub_ns;
	atomic_t uniq_null;
	long int uniq_id;
	int level;
	long int revision;
	wait_queue_head_t wait;
	spinlock_t listener_lock;
	struct list_head listeners;
	struct aa_labelset labels;
	struct list_head rawdata_list;
	struct dentry *dents[13];
};
struct blk_crypto_profile {
	struct blk_crypto_ll_ops ll_ops;
	unsigned int max_dun_bytes_supported;
	unsigned int modes_supported[5];
	struct device *dev;
	unsigned int num_slots;
	struct rw_semaphore lock;
	struct lock_class_key lockdep_key;
	wait_queue_head_t idle_slots_wait_queue;
	struct list_head idle_slots;
	spinlock_t idle_slots_lock;
	struct hlist_head *slot_hashtable;
	unsigned int log_slot_ht_size;
	struct blk_crypto_keyslot *slots;
};
struct ctl_table_poll {
	atomic_t event;
	wait_queue_head_t wait;
};
struct dentry {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[40];
	struct lockref d_lockref;
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct hlist_node d_sib;
	struct hlist_head d_children;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};
struct eventfd_ctx {
	struct kref kref;
	wait_queue_head_t wqh;
	__u64 count;
	unsigned int flags;
	int id;
};
struct file_lock {
	struct file_lock *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations *fl_ops;
	const struct lock_manager_operations *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
		struct {
			struct inode *inode;
		} ceph;
	} fl_u;
};
struct files_struct {
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;
	struct fdtable *fdt;
	struct fdtable fdtab;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t file_lock;
	unsigned int next_fd;
	long unsigned int close_on_exec_init[1];
	long unsigned int open_fds_init[1];
	long unsigned int full_fds_bits_init[1];
	struct file *fd_array[64];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct fs_pin {
	wait_queue_head_t wait;
	int done;
	struct hlist_node s_list;
	struct hlist_node m_list;
	void (*kill)(struct fs_pin *);
};
struct irq_desc {
	struct irq_common_data irq_common_data;
	struct irq_data irq_data;
	unsigned int *kstat_irqs;
	irq_flow_handler_t handle_irq;
	struct irqaction *action;
	unsigned int status_use_accessors;
	unsigned int core_internal_state__do_not_mess_with_it;
	unsigned int depth;
	unsigned int wake_depth;
	unsigned int tot_count;
	unsigned int irq_count;
	long unsigned int last_unhandled;
	unsigned int irqs_unhandled;
	atomic_t threads_handled;
	int threads_handled_last;
	raw_spinlock_t lock;
	struct cpumask *percpu_enabled;
	const struct cpumask *percpu_affinity;
	const struct cpumask *affinity_hint;
	struct irq_affinity_notify *affinity_notify;
	cpumask_var_t pending_mask;
	long unsigned int threads_oneshot;
	atomic_t threads_active;
	wait_queue_head_t wait_for_threads;
	unsigned int nr_actions;
	unsigned int no_suspend_depth;
	unsigned int cond_suspend_depth;
	unsigned int force_resume_depth;
	struct proc_dir_entry *dir;
	struct callback_head rcu;
	struct kobject kobj;
	struct mutex request_mutex;
	int parent_irq;
	struct module *owner;
	const char *name;
	struct hlist_node resend_node;
	long: 64;
	long: 64;
	long: 64;
};
struct kernfs_open_node {
	struct callback_head callback_head;
	atomic_t event;
	wait_queue_head_t poll;
	struct list_head files;
	unsigned int nr_mmapped;
	unsigned int nr_to_release;
};
struct mempool_s {
	spinlock_t lock;
	int min_nr;
	int curr_nr;
	void **elements;
	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
};
typedef struct mempool_s mempool_t;
struct mmu_notifier_subscriptions {
	struct hlist_head list;
	bool has_itree;
	spinlock_t lock;
	long unsigned int invalidate_seq;
	long unsigned int active_invalidate_ranges;
	struct rb_root_cached itree;
	wait_queue_head_t wq;
	struct hlist_head deferred_list;
};
struct mnt_namespace {
	struct ns_common ns;
	struct mount *root;
	struct rb_root mounts;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	u64 seq;
	wait_queue_head_t poll;
	u64 event;
	unsigned int nr_mounts;
	unsigned int pending_mounts;
};
struct perf_event {
	struct list_head event_entry;
	struct list_head sibling_list;
	struct list_head active_list;
	struct rb_node group_node;
	u64 group_index;
	struct list_head migrate_entry;
	struct hlist_node hlist_entry;
	struct list_head active_entry;
	int nr_siblings;
	int event_caps;
	int group_caps;
	unsigned int group_generation;
	struct perf_event *group_leader;
	struct pmu *pmu;
	void *pmu_private;
	enum perf_event_state state;
	unsigned int attach_state;
	local64_t count;
	atomic64_t child_count;
	u64 total_time_enabled;
	u64 total_time_running;
	u64 tstamp;
	struct perf_event_attr attr;
	u16 header_size;
	u16 id_header_size;
	u16 read_size;
	struct hw_perf_event hw;
	struct perf_event_context *ctx;
	struct perf_event_pmu_context *pmu_ctx;
	atomic_long_t refcount;
	atomic64_t child_total_time_enabled;
	atomic64_t child_total_time_running;
	struct mutex child_mutex;
	struct list_head child_list;
	struct perf_event *parent;
	int oncpu;
	int cpu;
	struct list_head owner_entry;
	struct task_struct *owner;
	struct mutex mmap_mutex;
	atomic_t mmap_count;
	struct perf_buffer *rb;
	struct list_head rb_entry;
	long unsigned int rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	unsigned int pending_wakeup;
	unsigned int pending_kill;
	unsigned int pending_disable;
	unsigned int pending_sigtrap;
	long unsigned int pending_addr;
	struct irq_work pending_irq;
	struct callback_head pending_task;
	unsigned int pending_work;
	struct rcuwait pending_work_wait;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
	struct perf_event *aux_event;
	void (*destroy)(struct perf_event *);
	struct callback_head callback_head;
	struct pid_namespace *ns;
	u64 id;
	atomic64_t lost_samples;
	u64 (*clock)(void);
	perf_overflow_handler_t overflow_handler;
	void *overflow_handler_context;
	perf_overflow_handler_t orig_overflow_handler;
	struct bpf_prog *prog;
	u64 bpf_cookie;
	struct trace_event_call *tp_event;
	struct event_filter *filter;
	struct ftrace_ops ftrace_ops;
	struct perf_cgroup *cgrp;
	void *security;
	struct list_head sb_list;
	__u32 orig_type;
};
struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid numbers[0];
};
struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	bool note_loss;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};
typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);
struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
};
struct rb_irq_work {
	struct irq_work work;
	wait_queue_head_t waiters;
	wait_queue_head_t full_waiters;
	atomic_t seq;
	bool waiters_pending;
	bool full_waiters_pending;
	bool wakeup_full;
};
struct rchan_buf {
	void *start;
	void *data;
	size_t offset;
	size_t subbufs_produced;
	size_t subbufs_consumed;
	struct rchan *chan;
	wait_queue_head_t read_wait;
	struct irq_work wakeup_work;
	struct dentry *dentry;
	struct kref kref;
	struct page **page_array;
	unsigned int page_count;
	unsigned int finalized;
	size_t *padding;
	size_t prev_padding;
	size_t bytes_consumed;
	size_t early_bytes;
	unsigned int cpu;
	long: 64;
	long: 64;
};
struct rcu_sync {
	int gp_state;
	int gp_count;
	wait_queue_head_t gp_wait;
	struct callback_head cb_head;
};
struct percpu_rw_semaphore {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait writer;
	wait_queue_head_t waiters;
	atomic_t block;
};
struct sb_writers {
	short unsigned int frozen;
	int freeze_kcount;
	int freeze_ucount;
	struct percpu_rw_semaphore rw_sem[3];
};
struct sbq_wait_state {
	wait_queue_head_t wait;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct seccomp_filter {
	refcount_t refs;
	refcount_t users;
	bool log;
	bool wait_killable_recv;
	struct action_cache cache;
	struct seccomp_filter *prev;
	struct bpf_prog *prog;
	struct notification *notif;
	struct mutex notify_lock;
	wait_queue_head_t wqh;
};
struct sighand_struct {
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[64];
};
struct signal_struct {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	unsigned int next_posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	atomic_t tick_dep_mask;
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};
typedef struct {
	spinlock_t slock;
	int owned;
	wait_queue_head_t wq;
} socket_lock_t;
struct sock {
	struct sock_common __sk_common;
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head sk_error_queue;
	struct sk_buff_head sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	int sk_disconnects;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	void *sk_policy[2];
	struct dst_entry *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u32 sk_tsflags;
	u8 sk_shutdown;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	bool sk_use_task_frag;
	struct socket *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup *sk_memcg;
	void (*sk_state_change)(struct sock *);
	void (*sk_data_ready)(struct sock *);
	void (*sk_write_space)(struct sock *);
	void (*sk_error_report)(struct sock *);
	int (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	struct sk_buff * (*sk_validate_xmit_skb)(struct sock *, void *, struct sk_buff *);
	void (*sk_destruct)(struct sock *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
};
struct socket_wq {
	wait_queue_head_t wait;
	struct fasync_struct *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};
struct socket {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq wq;
};
struct trace_buffer {
	unsigned int flags;
	int cpus;
	atomic_t record_disabled;
	atomic_t resizing;
	cpumask_var_t cpumask;
	struct lock_class_key *reader_lock_key;
	struct mutex mutex;
	struct ring_buffer_per_cpu **buffers;
	struct hlist_node node;
	u64 (*clock)(void);
	struct rb_irq_work irq_work;
	bool time_stamp_abs;
	unsigned int subbuf_size;
	unsigned int subbuf_order;
	unsigned int max_data_size;
};
struct userfaultfd_ctx {
	wait_queue_head_t fault_pending_wqh;
	wait_queue_head_t fault_wqh;
	wait_queue_head_t fd_wqh;
	wait_queue_head_t event_wqh;
	seqcount_spinlock_t refile_seq;
	refcount_t refcount;
	unsigned int flags;
	unsigned int features;
	bool released;
	atomic_t mmap_changing;
	struct mm_struct *mm;
};
struct wake_irq {
	struct device *dev;
	unsigned int status;
	int irq;
	const char *name;
};
struct wake_q_node {
	struct wake_q_node *next;
};
struct wakeup_source {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};
struct watch {
	union {
		struct callback_head rcu;
		u32 info_id;
	};
	struct watch_queue *queue;
	struct hlist_node queue_node;
	struct watch_list *watch_list;
	struct hlist_node list_node;
	const struct cred *cred;
	void *private;
	u64 id;
	struct kref usage;
};
struct watch_list {
	struct callback_head rcu;
	struct hlist_head watchers;
	void (*release_watch)(struct watch *);
	spinlock_t lock;
};
enum watch_notification_type {
	WATCH_TYPE_META = 0,
	WATCH_TYPE_KEY_NOTIFY = 1,
	WATCH_TYPE__NR = 2,
};
struct watch_queue {
	struct callback_head rcu;
	struct watch_filter *filter;
	struct pipe_inode_info *pipe;
	struct hlist_head watches;
	struct page **notes;
	long unsigned int *notes_bitmap;
	struct kref usage;
	spinlock_t lock;
	unsigned int nr_notes;
	unsigned int nr_pages;
};
struct watch_type_filter {
	enum watch_notification_type type;
	__u32 subtype_filter[1];
	__u32 info_filter;
	__u32 info_mask;
};
struct watch_filter {
	union {
		struct callback_head rcu;
		long unsigned int type_filter[1];
	};
	u32 nr_filters;
	struct watch_type_filter filters[0];
};
struct wb_completion {
	atomic_t cnt;
	wait_queue_head_t *waitq;
};
struct memcg_cgwb_frn {
	u64 bdi_id;
	int memcg_id;
	u64 at;
	struct wb_completion done;
};
struct wb_domain {
	spinlock_t lock;
	struct fprop_global completions;
	struct timer_list period_timer;
	long unsigned int period_time;
	long unsigned int dirty_limit_tstamp;
	long unsigned int dirty_limit;
};
enum wb_reason {
	WB_REASON_BACKGROUND = 0,
	WB_REASON_VMSCAN = 1,
	WB_REASON_SYNC = 2,
	WB_REASON_PERIODIC = 3,
	WB_REASON_LAPTOP_TIMER = 4,
	WB_REASON_FS_FREE_SPACE = 5,
	WB_REASON_FORKER_THREAD = 6,
	WB_REASON_FOREIGN_FLUSH = 7,
	WB_REASON_MAX = 8,
};
struct winsize {
	short unsigned int ws_row;
	short unsigned int ws_col;
	short unsigned int ws_xpixel;
	short unsigned int ws_ypixel;
};
typedef void (*work_func_t)(struct work_struct *);
struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};
struct aa_loaddata {
	struct kref count;
	struct list_head list;
	struct work_struct work;
	struct dentry *dents[6];
	struct aa_ns *ns;
	char *name;
	size_t size;
	size_t compressed_size;
	long int revision;
	int abi;
	unsigned char *hash;
	char *data;
};
struct bio_integrity_payload {
	struct bio *bip_bio;
	struct bvec_iter bip_iter;
	short unsigned int bip_vcnt;
	short unsigned int bip_max_vcnt;
	short unsigned int bip_flags;
	int: 0;
	struct bvec_iter bio_iter;
	struct work_struct bip_work;
	struct bio_vec *bip_vec;
	struct bio_vec bip_inline_vecs[0];
};
struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;
	struct bio_alloc_cache *cache;
	mempool_t bio_pool;
	mempool_t bvec_pool;
	mempool_t bio_integrity_pool;
	mempool_t bvec_integrity_pool;
	unsigned int back_pad;
	spinlock_t rescue_lock;
	struct bio_list rescue_list;
	struct work_struct rescue_work;
	struct workqueue_struct *rescue_workqueue;
	struct hlist_node cpuhp_dead;
};
struct blkcg_gq {
	struct request_queue *q;
	struct list_head q_node;
	struct hlist_node blkcg_node;
	struct blkcg *blkcg;
	struct blkcg_gq *parent;
	struct percpu_ref refcnt;
	bool online;
	struct blkg_iostat_set *iostat_cpu;
	struct blkg_iostat_set iostat;
	struct blkg_policy_data *pd[6];
	spinlock_t async_bio_lock;
	struct bio_list async_bios;
	union {
		struct work_struct async_bio_work;
		struct work_struct free_work;
	};
	atomic_t use_delay;
	atomic64_t delay_nsec;
	atomic64_t delay_start;
	u64 last_delay;
	int last_use;
	struct callback_head callback_head;
};
struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
	void *security;
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u64 map_extra;
	u32 map_flags;
	u32 id;
	struct btf_record *record;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
	struct obj_cgroup *objcg;
	char name[16];
	long: 64;
	long: 64;
	atomic64_t refcnt;
	atomic64_t usercnt;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
	struct mutex freeze_mutex;
	atomic64_t writecnt;
	struct {
		const struct btf_type *attach_func_proto;
		spinlock_t lock;
		enum bpf_prog_type type;
		bool jited;
		bool xdp_has_frags;
	} owner;
	bool bypass_spec_v1;
	bool frozen;
	bool free_after_mult_rcu_gp;
	bool free_after_rcu_gp;
	atomic64_t sleepable_refcnt;
	s64 *elem_count;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct bpf_cgroup_storage_map {
	struct bpf_map map;
	spinlock_t lock;
	struct rb_root root;
	struct list_head list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct bpf_mem_alloc {
	struct bpf_mem_caches *caches;
	struct bpf_mem_cache *cache;
	struct obj_cgroup *objcg;
	bool percpu;
	struct work_struct work;
};
struct bpf_local_storage_map {
	struct bpf_map map;
	struct bpf_local_storage_map_bucket *buckets;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
	struct bpf_mem_alloc selem_ma;
	struct bpf_mem_alloc storage_ma;
	bool bpf_ma;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct bpf_prog_aux {
	atomic64_t refcnt;
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 max_ctx_offset;
	u32 max_pkt_offset;
	u32 max_tp_access;
	u32 stack_depth;
	u32 id;
	u32 func_cnt;
	u32 real_func_cnt;
	u32 func_idx;
	u32 attach_btf_id;
	u32 ctx_arg_info_size;
	u32 max_rdonly_access;
	u32 max_rdwr_access;
	struct btf *attach_btf;
	const struct bpf_ctx_arg_aux *ctx_arg_info;
	struct mutex dst_mutex;
	struct bpf_prog *dst_prog;
	struct bpf_trampoline *dst_trampoline;
	enum bpf_prog_type saved_dst_prog_type;
	enum bpf_attach_type saved_dst_attach_type;
	bool verifier_zext;
	bool dev_bound;
	bool offload_requested;
	bool attach_btf_trace;
	bool attach_tracing_prog;
	bool func_proto_unreliable;
	bool sleepable;
	bool tail_call_reachable;
	bool xdp_has_frags;
	bool exception_cb;
	bool exception_boundary;
	bool is_extended;
	u64 prog_array_member_cnt;
	struct mutex ext_mutex;
	const struct btf_type *attach_func_proto;
	const char *attach_func_name;
	struct bpf_prog **func;
	void *jit_data;
	struct bpf_jit_poke_descriptor *poke_tab;
	struct bpf_kfunc_desc_tab *kfunc_tab;
	struct bpf_kfunc_btf_tab *kfunc_btf_tab;
	u32 size_poke_tab;
	struct bpf_ksym ksym;
	const struct bpf_prog_ops *ops;
	struct bpf_map **used_maps;
	struct mutex used_maps_mutex;
	struct btf_mod_pair *used_btfs;
	struct bpf_prog *prog;
	struct user_struct *user;
	u64 load_time;
	u32 verified_insns;
	int cgroup_atype;
	struct bpf_map *cgroup_storage[2];
	char name[16];
	u64 (*bpf_exception_cb)(u64, u64, u64, u64, u64);
	void *security;
	struct bpf_prog_offload *offload;
	struct btf *btf;
	struct bpf_func_info *func_info;
	struct bpf_func_info_aux *func_info_aux;
	struct bpf_line_info *linfo;
	void **jited_linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
	u32 linfo_idx;
	struct module *mod;
	u32 num_exentries;
	struct exception_table_entry *extable;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
};
struct bpf_tramp_image {
	void *image;
	int size;
	struct bpf_ksym ksym;
	struct percpu_ref pcref;
	void *ip_after_call;
	void *ip_epilogue;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};
struct cgroup_bpf {
	struct bpf_prog_array *effective[38];
	struct hlist_head progs[38];
	u8 flags[38];
	struct list_head storages;
	struct bpf_prog_array *inactive;
	struct percpu_ref refcnt;
	struct work_struct release_work;
};
struct crypto_instance {
	struct crypto_alg alg;
	struct crypto_template *tmpl;
	union {
		struct hlist_node list;
		struct crypto_spawn *spawns;
	};
	struct work_struct free_work;
	void *__ctx[0];
};
struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};
struct bdi_writeback {
	struct backing_dev_info *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};
struct blk_mq_hw_ctx {
	struct {
		spinlock_t lock;
		struct list_head dispatch;
		long unsigned int state;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	};
	struct delayed_work run_work;
	cpumask_var_t cpumask;
	int next_cpu;
	int next_cpu_batch;
	long unsigned int flags;
	void *sched_data;
	struct request_queue *queue;
	struct blk_flush_queue *fq;
	void *driver_data;
	struct sbitmap ctx_map;
	struct blk_mq_ctx *dispatch_from;
	unsigned int dispatch_busy;
	short unsigned int type;
	short unsigned int nr_ctx;
	struct blk_mq_ctx **ctxs;
	spinlock_t dispatch_wait_lock;
	wait_queue_entry_t dispatch_wait;
	atomic_t wait_index;
	struct blk_mq_tags *tags;
	struct blk_mq_tags *sched_tags;
	unsigned int numa_node;
	unsigned int queue_num;
	atomic_t nr_active;
	struct hlist_node cpuhp_online;
	struct hlist_node cpuhp_dead;
	struct kobject kobj;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct list_head hctx_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct dev_pm_info {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	bool async_in_progress: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device *, s32);
	struct dev_pm_qos *qos;
};
struct device {
	struct kobject kobj;
	struct device *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type *type;
	const struct bus_type *bus;
	struct device_driver *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info power;
	struct dev_pm_domain *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct list_head dma_io_tlb_pools;
	spinlock_t dma_io_tlb_lock;
	bool dma_uses_io_tlb;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	const struct class *class;
	const struct attribute_group **groups;
	void (*release)(struct device *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};
struct block_device {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	u8 bd_partno;
	bool bd_write_holder;
	bool bd_has_submit_bio;
	dev_t bd_dev;
	struct inode *bd_inode;
	atomic_t bd_openers;
	spinlock_t bd_size_lock;
	void *bd_claiming;
	void *bd_holder;
	const struct blk_holder_ops *bd_holder_ops;
	struct mutex bd_holder_lock;
	int bd_holders;
	struct kobject *bd_holder_dir;
	atomic_t bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct partition_meta_info *bd_meta_info;
	bool bd_ro_warned;
	int bd_writers;
	struct device bd_device;
};
struct disk_events {
	struct list_head node;
	struct gendisk *disk;
	spinlock_t lock;
	struct mutex block_mutex;
	int block;
	unsigned int pending;
	unsigned int clearing;
	long int poll_msecs;
	struct delayed_work dwork;
};
struct ifmcaddr6 {
	struct in6_addr mca_addr;
	struct inet6_dev *idev;
	struct ifmcaddr6 *next;
	struct ip6_sf_list *mca_sources;
	struct ip6_sf_list *mca_tomb;
	unsigned int mca_sfmode;
	unsigned char mca_crcount;
	long unsigned int mca_sfcount[2];
	struct delayed_work mca_work;
	unsigned int mca_flags;
	int mca_users;
	refcount_t mca_refcnt;
	long unsigned int mca_cstamp;
	long unsigned int mca_tstamp;
	struct callback_head rcu;
};
struct inet6_dev {
	void *dev;
	netdevice_tracker dev_tracker;
	struct list_head addr_list;
	struct ifmcaddr6 *mc_list;
	struct ifmcaddr6 *mc_tomb;
	unsigned char mc_qrv;
	unsigned char mc_gq_running;
	unsigned char mc_ifc_count;
	unsigned char mc_dad_count;
	long unsigned int mc_v1_seen;
	long unsigned int mc_qi;
	long unsigned int mc_qri;
	long unsigned int mc_maxdelay;
	struct delayed_work mc_gq_work;
	struct delayed_work mc_ifc_work;
	struct delayed_work mc_dad_work;
	struct delayed_work mc_query_work;
	struct delayed_work mc_report_work;
	struct sk_buff_head mc_query_queue;
	struct sk_buff_head mc_report_queue;
	spinlock_t mc_query_lock;
	spinlock_t mc_report_lock;
	struct mutex mc_lock;
	struct ifacaddr6 *ac_list;
	rwlock_t lock;
	refcount_t refcnt;
	__u32 if_flags;
	int dead;
	u32 desync_factor;
	struct list_head tempaddr_list;
	struct in6_addr token;
	struct neigh_parms *nd_parms;
	struct ipv6_devconf cnf;
	struct ipv6_devstat stats;
	struct timer_list rs_timer;
	__s32 rs_interval;
	__u8 rs_probes;
	long unsigned int tstamp;
	struct callback_head rcu;
	unsigned int ra_mtu;
};
struct io_tlb_mem {
	struct io_tlb_pool defpool;
	long unsigned int nslabs;
	struct dentry *debugfs;
	bool force_bounce;
	bool for_alloc;
	bool can_grow;
	u64 phys_limit;
	spinlock_t lock;
	struct list_head pools;
	struct work_struct dyn_alloc;
	atomic_long_t total_used;
	atomic_long_t used_hiwater;
};
struct iova_rcache {
	spinlock_t lock;
	unsigned int depot_size;
	struct iova_magazine *depot;
	struct iova_cpu_rcache *cpu_rcaches;
	struct iova_domain *iovad;
	struct delayed_work work;
};
struct irq_affinity_notify {
	unsigned int irq;
	struct kref kref;
	struct work_struct work;
	void (*notify)(struct irq_affinity_notify *, const cpumask_t *);
	void (*release)(struct kref *);
};
struct memory_tier {
	struct list_head list;
	struct list_head memory_types;
	int adistance_start;
	struct device dev;
	nodemask_t lower_tier_mask;
};
struct mm_struct {
	struct {
		struct {
			atomic_t mm_count;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
		};
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		struct mm_cid *pcpu_cid;
		long unsigned int mm_cid_next_scan;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		int mm_lock_seq;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[52];
		struct percpu_counter rss_stat[4];
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct *owner;
		struct user_namespace *user_ns;
		struct file *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		struct iommu_mm_data *iommu_mm;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		atomic_long_t ksm_zero_pages;
		struct {
			struct list_head list;
			long unsigned int bitmap;
			struct mem_cgroup *memcg;
		} lru_gen;
		long: 64;
		long: 64;
	};
	long unsigned int cpu_bitmap[0];
};
struct neigh_table {
	int family;
	unsigned int entry_size;
	unsigned int key_len;
	__be16 protocol;
	__u32 (*hash)(const void *, const void *, __u32 *);
	bool (*key_eq)(const struct neighbour *, const void *);
	int (*constructor)(struct neighbour *);
	int (*pconstructor)(struct pneigh_entry *);
	void (*pdestructor)(struct pneigh_entry *);
	void (*proxy_redo)(struct sk_buff *);
	int (*is_multicast)(const void *);
	bool (*allow_add)(const void *, struct netlink_ext_ack *);
	char *id;
	struct neigh_parms parms;
	struct list_head parms_list;
	int gc_interval;
	int gc_thresh1;
	int gc_thresh2;
	int gc_thresh3;
	long unsigned int last_flush;
	struct delayed_work gc_work;
	struct delayed_work managed_work;
	struct timer_list proxy_timer;
	struct sk_buff_head proxy_queue;
	atomic_t entries;
	atomic_t gc_entries;
	struct list_head gc_list;
	struct list_head managed_list;
	rwlock_t lock;
	long unsigned int last_rand;
	struct neigh_statistics *stats;
	struct neigh_hash_table *nht;
	struct pneigh_entry **phash_buckets;
};
struct netns_ipv6 {
	struct dst_ops ip6_dst_ops;
	struct netns_sysctl_ipv6 sysctl;
	struct ipv6_devconf *devconf_all;
	struct ipv6_devconf *devconf_dflt;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	struct fib6_info *fib6_null_entry;
	struct rt6_info *ip6_null_entry;
	struct rt6_statistics *rt6_stats;
	struct timer_list ip6_fib_timer;
	struct hlist_head *fib_table_hash;
	struct fib6_table *fib6_main_tbl;
	struct list_head fib6_walkers;
	rwlock_t fib6_walker_lock;
	spinlock_t fib6_gc_lock;
	atomic_t ip6_rt_gc_expire;
	long unsigned int ip6_rt_last_gc;
	unsigned char flowlabel_has_excl;
	bool fib6_has_custom_rules;
	unsigned int fib6_rules_require_fldissect;
	unsigned int fib6_routes_require_src;
	struct rt6_info *ip6_prohibit_entry;
	struct rt6_info *ip6_blk_hole_entry;
	struct fib6_table *fib6_local_tbl;
	struct fib_rules_ops *fib6_rules_ops;
	struct sock *ndisc_sk;
	struct sock *tcp_sk;
	struct sock *igmp_sk;
	struct sock *mc_autojoin_sk;
	struct hlist_head *inet6_addr_lst;
	spinlock_t addrconf_hash_lock;
	struct delayed_work addr_chk_work;
	struct list_head mr6_tables;
	struct fib_rules_ops *mr6_rules_ops;
	atomic_t dev_addr_genid;
	atomic_t fib6_sernum;
	struct seg6_pernet_data *seg6_data;
	struct fib_notifier_ops *notifier_ops;
	struct fib_notifier_ops *ip6mr_notifier_ops;
	unsigned int ipmr_seq;
	struct {
		struct hlist_head head;
		spinlock_t lock;
		u32 seq;
	} ip6addrlbl_table;
	struct ioam6_pernet_data *ioam6_data;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct nh_res_table {
	struct net *net;
	u32 nhg_id;
	struct delayed_work upkeep_dw;
	struct list_head uw_nh_entries;
	long unsigned int unbalanced_since;
	u32 idle_timer;
	u32 unbalanced_timer;
	u16 num_nh_buckets;
	struct nh_res_bucket nh_buckets[0];
};
struct page_pool {
	struct page_pool_params_fast p;
	bool has_init_callback;
	long int frag_users;
	struct page *frag_page;
	unsigned int frag_offset;
	u32 pages_state_hold_cnt;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	struct page_pool_alloc_stats alloc_stats;
	u32 xdp_mem_id;
	long: 64;
	struct pp_alloc_cache alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	struct page_pool_recycle_stats *recycle_stats;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	struct page_pool_params_slow slow;
	struct {
		struct hlist_node list;
		u64 detach_time;
		u32 napi_id;
		u32 id;
	} user;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct psi_group {
	struct psi_group *parent;
	bool enabled;
	struct mutex avgs_lock;
	struct psi_group_cpu *pcpu;
	u64 avg_total[6];
	u64 avg_last_update;
	u64 avg_next_update;
	struct delayed_work avgs_work;
	struct list_head avg_triggers;
	u32 avg_nr_triggers[6];
	u64 total[12];
	long unsigned int avg[18];
	struct task_struct *rtpoll_task;
	struct timer_list rtpoll_timer;
	wait_queue_head_t rtpoll_wait;
	atomic_t rtpoll_wakeup;
	atomic_t rtpoll_scheduled;
	struct mutex rtpoll_trigger_lock;
	struct list_head rtpoll_triggers;
	u32 rtpoll_nr_triggers[6];
	u32 rtpoll_states;
	u64 rtpoll_min_period;
	u64 rtpoll_total[6];
	u64 rtpoll_next_update;
	u64 rtpoll_until;
};
struct rcu_exp_work {
	long unsigned int rew_s;
	struct work_struct rew_work;
};
struct rcu_node {
	raw_spinlock_t lock;
	long unsigned int gp_seq;
	long unsigned int gp_seq_needed;
	long unsigned int completedqs;
	long unsigned int qsmask;
	long unsigned int rcu_gp_init_mask;
	long unsigned int qsmaskinit;
	long unsigned int qsmaskinitnext;
	long unsigned int expmask;
	long unsigned int expmaskinit;
	long unsigned int expmaskinitnext;
	long unsigned int cbovldmask;
	long unsigned int ffmask;
	long unsigned int grpmask;
	int grplo;
	int grphi;
	u8 grpnum;
	u8 level;
	bool wait_blkd_tasks;
	struct rcu_node *parent;
	struct list_head blkd_tasks;
	struct list_head *gp_tasks;
	struct list_head *exp_tasks;
	struct list_head *boost_tasks;
	struct rt_mutex boost_mtx;
	long unsigned int boost_time;
	struct mutex boost_kthread_mutex;
	struct task_struct *boost_kthread_task;
	unsigned int boost_kthread_status;
	long unsigned int n_boosts;
	struct swait_queue_head nocb_gp_wq[2];
	raw_spinlock_t fqslock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t exp_lock;
	long unsigned int exp_seq_rq;
	wait_queue_head_t exp_wq[4];
	struct rcu_exp_work rew;
	bool exp_need_flush;
	raw_spinlock_t exp_poll_lock;
	long unsigned int exp_seq_poll_rq;
	struct work_struct exp_poll_wq;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};
struct cgroup_subsys_state {
	struct cgroup *cgroup;
	struct cgroup_subsys *ss;
	struct percpu_ref refcnt;
	struct list_head sibling;
	struct list_head children;
	struct list_head rstat_css_node;
	int id;
	unsigned int flags;
	u64 serial_nr;
	atomic_t online_cnt;
	struct work_struct destroy_work;
	struct rcu_work destroy_rwork;
	struct cgroup_subsys_state *parent;
};
struct cgroup {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	unsigned int kill_seq;
	struct kernfs_node *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[3];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[14];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[14];
	struct cgroup *dom_cgrp;
	struct cgroup *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	long: 64;
	long: 64;
	struct cacheline_padding _pad_;
	struct cgroup *rstat_flush_next;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct bpf_local_storage *bpf_cgrp_storage;
	struct cgroup *ancestors[0];
};
struct cgroup_root {
	struct kernfs_root *kf_root;
	unsigned int subsys_mask;
	int hierarchy_id;
	struct list_head root_list;
	struct callback_head rcu;
	long: 64;
	long: 64;
	struct cgroup cgrp;
	struct cgroup *cgrp_ancestor_storage;
	atomic_t nr_cgrps;
	unsigned int flags;
	char release_agent_path[4096];
	char name[64];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct kioctx {
	struct percpu_ref users;
	atomic_t dead;
	struct percpu_ref reqs;
	long unsigned int user_id;
	struct kioctx_cpu *cpu;
	unsigned int req_batch;
	unsigned int max_reqs;
	unsigned int nr_events;
	long unsigned int mmap_base;
	long unsigned int mmap_size;
	struct page **ring_pages;
	long int nr_pages;
	struct rcu_work free_rwork;
	struct ctx_rq_wait *rq_wait;
	long: 64;
	long: 64;
	long: 64;
	struct {
		atomic_t reqs_available;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	};
	struct {
		spinlock_t ctx_lock;
		struct list_head active_reqs;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	};
	struct {
		struct mutex ring_lock;
		wait_queue_head_t wait;
		long: 64;
	};
	struct {
		unsigned int tail;
		unsigned int completed_events;
		spinlock_t completion_lock;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	};
	struct page *internal_pages[8];
	struct file *aio_ring_file;
	unsigned int id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct perf_cgroup {
	struct cgroup_subsys_state css;
	struct perf_cgroup_info *info;
};
struct rhashtable {
	struct bucket_table *tbl;
	unsigned int key_len;
	unsigned int max_elems;
	struct rhashtable_params p;
	bool rhlist;
	struct work_struct run_work;
	struct mutex mutex;
	spinlock_t lock;
	atomic_t nelems;
};
struct fqdir {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net *net;
	bool dead;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
	long: 64;
};
struct ioam6_pernet_data {
	struct mutex lock;
	struct rhashtable namespaces;
	struct rhashtable schemas;
};
struct ring_buffer_per_cpu {
	int cpu;
	atomic_t record_disabled;
	atomic_t resize_disabled;
	struct trace_buffer *buffer;
	raw_spinlock_t reader_lock;
	arch_spinlock_t lock;
	struct lock_class_key lock_key;
	struct buffer_data_page *free_page;
	long unsigned int nr_pages;
	unsigned int current_context;
	struct list_head *pages;
	long unsigned int cnt;
	struct buffer_page *head_page;
	struct buffer_page *tail_page;
	struct buffer_page *commit_page;
	struct buffer_page *reader_page;
	long unsigned int lost_events;
	long unsigned int last_overrun;
	long unsigned int nest;
	local_t entries_bytes;
	local_t entries;
	local_t overrun;
	local_t commit_overrun;
	local_t dropped_events;
	local_t committing;
	local_t commits;
	local_t pages_touched;
	local_t pages_lost;
	local_t pages_read;
	long int last_pages_touch;
	size_t shortest_full;
	long unsigned int read;
	long unsigned int read_bytes;
	rb_time_t write_stamp;
	rb_time_t before_stamp;
	u64 event_stamp[5];
	u64 read_stamp;
	long unsigned int pages_removed;
	long int nr_pages_to_update;
	struct list_head new_pages;
	struct work_struct update_pages_work;
	struct completion update_done;
	struct rb_irq_work irq_work;
};
struct rpc_timer {
	struct list_head list;
	long unsigned int expires;
	struct delayed_work dwork;
};
struct rpc_wait_queue {
	spinlock_t lock;
	struct list_head tasks[4];
	unsigned char maxpriority;
	unsigned char priority;
	unsigned char nr;
	unsigned int qlen;
	struct rpc_timer timer_list;
	const char *name;
};
struct nfs_seqid_counter {
	ktime_t create_time;
	int owner_id;
	int flags;
	u32 counter;
	spinlock_t lock;
	struct list_head list;
	struct rpc_wait_queue wait;
};
struct nfs4_lock_state {
	struct list_head ls_locks;
	void *ls_state;
	long unsigned int ls_flags;
	struct nfs_seqid_counter ls_seqid;
	nfs4_stateid ls_stateid;
	refcount_t ls_count;
	fl_owner_t ls_owner;
};
struct seg6_pernet_data {
	struct mutex lock;
	struct in6_addr *tun_src;
	struct rhashtable hmac_infos;
};
struct srcu_data {
	atomic_long_t srcu_lock_count[2];
	atomic_long_t srcu_unlock_count[2];
	int srcu_nmi_safety;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t lock;
	struct rcu_segcblist srcu_cblist;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	bool srcu_cblist_invoking;
	struct timer_list delay_work;
	struct work_struct work;
	struct callback_head srcu_barrier_head;
	struct srcu_node *mynode;
	long unsigned int grpmask;
	int cpu;
	struct srcu_struct *ssp;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct srcu_usage {
	struct srcu_node *node;
	struct srcu_node *level[4];
	int srcu_size_state;
	struct mutex srcu_cb_mutex;
	spinlock_t lock;
	struct mutex srcu_gp_mutex;
	long unsigned int srcu_gp_seq;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	long unsigned int srcu_gp_start;
	long unsigned int srcu_last_gp_end;
	long unsigned int srcu_size_jiffies;
	long unsigned int srcu_n_lock_retries;
	long unsigned int srcu_n_exp_nodelay;
	bool sda_is_static;
	long unsigned int srcu_barrier_seq;
	struct mutex srcu_barrier_mutex;
	struct completion srcu_barrier_completion;
	atomic_t srcu_barrier_cpu_cnt;
	long unsigned int reschedule_jiffies;
	long unsigned int reschedule_count;
	struct delayed_work work;
	struct srcu_struct *srcu_ssp;
};
struct strparser {
	struct sock *sk;
	u32 stopped: 1;
	u32 paused: 1;
	u32 aborted: 1;
	u32 interrupted: 1;
	u32 unrecov_intr: 1;
	struct sk_buff **skb_nextp;
	struct sk_buff *skb_head;
	unsigned int need_bytes;
	struct delayed_work msg_timer_work;
	struct work_struct work;
	struct strp_stats stats;
	struct strp_callbacks cb;
};
struct sk_psock {
	struct sock *sk;
	struct sock *sk_redir;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 eval;
	bool redir_ingress;
	struct sk_msg *cork;
	struct sk_psock_progs progs;
	struct strparser strp;
	u32 copied_seq;
	u32 ingress_bytes;
	struct sk_buff_head ingress_skb;
	struct list_head ingress_msg;
	spinlock_t ingress_lock;
	long unsigned int state;
	struct list_head link;
	spinlock_t link_lock;
	refcount_t refcnt;
	void (*saved_unhash)(struct sock *);
	void (*saved_destroy)(struct sock *);
	void (*saved_close)(struct sock *, long int);
	void (*saved_write_space)(struct sock *);
	void (*saved_data_ready)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	struct proto *sk_proto;
	struct mutex work_mutex;
	struct sk_psock_work_state work_state;
	struct delayed_work work;
	struct sock *sk_pair;
	struct rcu_work rwork;
};
struct swap_info_struct {
	struct percpu_ref users;
	long unsigned int flags;
	short int prio;
	struct plist_node list;
	signed char type;
	unsigned int max;
	unsigned char *swap_map;
	struct swap_cluster_info *cluster_info;
	struct swap_cluster_list free_clusters;
	unsigned int lowest_bit;
	unsigned int highest_bit;
	unsigned int pages;
	unsigned int inuse_pages;
	unsigned int cluster_next;
	unsigned int cluster_nr;
	unsigned int *cluster_next_cpu;
	struct percpu_cluster *percpu_cluster;
	struct rb_root swap_extent_root;
	struct bdev_handle *bdev_handle;
	struct block_device *bdev;
	struct file *swap_file;
	unsigned int old_block_size;
	struct completion comp;
	spinlock_t lock;
	spinlock_t cont_lock;
	struct work_struct discard_work;
	struct swap_cluster_list discard_clusters;
	struct plist_node avail_lists[0];
};
struct task_group {
	struct cgroup_subsys_state css;
	struct sched_entity **se;
	struct cfs_rq **cfs_rq;
	long unsigned int shares;
	int idle;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t load_avg;
	struct callback_head rcu;
	struct list_head list;
	struct task_group *parent;
	struct list_head siblings;
	struct list_head children;
	struct autogroup *autogroup;
	struct cfs_bandwidth cfs_bandwidth;
	unsigned int uclamp_pct[2];
	struct uclamp_se uclamp_req[2];
	struct uclamp_se uclamp[2];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct throtl_data {
	struct throtl_service_queue service_queue;
	struct request_queue *queue;
	unsigned int nr_queued[2];
	unsigned int throtl_slice;
	struct work_struct dispatch_work;
	unsigned int limit_index;
	bool limit_valid[2];
	long unsigned int low_upgrade_time;
	long unsigned int low_downgrade_time;
	unsigned int scale;
	struct latency_bucket tmp_buckets[18];
	struct avg_latency_bucket avg_buckets[18];
	struct latency_bucket *latency_buckets[2];
	long unsigned int last_calculate_time;
	long unsigned int filtered_latency;
	bool track_bio_latency;
};
struct trace_array {
	struct list_head list;
	char *name;
	struct array_buffer array_buffer;
	struct array_buffer max_buffer;
	bool allocated_snapshot;
	long unsigned int max_latency;
	struct dentry *d_max_latency;
	struct work_struct fsnotify_work;
	struct irq_work fsnotify_irqwork;
	struct trace_pid_list *filtered_pids;
	struct trace_pid_list *filtered_no_pids;
	arch_spinlock_t max_lock;
	int buffer_disabled;
	int sys_refcount_enter;
	int sys_refcount_exit;
	struct trace_event_file *enter_syscall_files[462];
	struct trace_event_file *exit_syscall_files[462];
	int stop_count;
	int clock_id;
	int nr_topts;
	bool clear_trace;
	int buffer_percent;
	unsigned int n_err_log_entries;
	struct tracer *current_trace;
	unsigned int trace_flags;
	unsigned char trace_flags_index[32];
	unsigned int flags;
	raw_spinlock_t start_lock;
	const char *system_names;
	struct list_head err_log;
	struct dentry *dir;
	struct dentry *options;
	struct dentry *percpu_dir;
	struct eventfs_inode *event_dir;
	struct trace_options *topts;
	struct list_head systems;
	struct list_head events;
	struct trace_event_file *trace_marker_file;
	cpumask_var_t tracing_cpumask;
	cpumask_var_t pipe_cpumask;
	int ref;
	int trace_ref;
	struct ftrace_ops *ops;
	struct trace_pid_list *function_pids;
	struct trace_pid_list *function_no_pids;
	struct list_head func_probes;
	struct list_head mod_trace;
	struct list_head mod_notrace;
	int function_enabled;
	int no_filter_buffering_ref;
	struct list_head hist_vars;
	struct cond_snapshot *cond_snapshot;
	struct trace_func_repeats *last_func_repeats;
	bool ring_buffer_expanded;
};
struct tty_bufhead {
	struct tty_buffer *head;
	struct work_struct work;
	struct mutex lock;
	atomic_t priority;
	struct tty_buffer sentinel;
	struct llist_head free;
	atomic_t mem_used;
	int mem_limit;
	struct tty_buffer *tail;
};
struct tty_port {
	struct tty_bufhead buf;
	struct tty_struct *tty;
	struct tty_struct *itty;
	const struct tty_port_operations *ops;
	const struct tty_port_client_operations *client_ops;
	spinlock_t lock;
	int blocked_open;
	int count;
	wait_queue_head_t open_wait;
	wait_queue_head_t delta_msr_wait;
	long unsigned int flags;
	long unsigned int iflags;
	unsigned char console: 1;
	struct mutex mutex;
	struct mutex buf_mutex;
	u8 *xmit_buf;
	struct {
		union {
			struct __kfifo kfifo;
			u8 *type;
			const u8 *const_type;
			char (*rectype)[0];
			u8 *ptr;
			const u8 *ptr_const;
		};
		u8 buf[0];
	} xmit_fifo;
	unsigned int close_delay;
	unsigned int closing_wait;
	int drain_delay;
	struct kref kref;
	void *client_data;
};
struct tty_struct {
	struct kref kref;
	int index;
	struct device *dev;
	void *driver;
	struct tty_port *port;
	const struct tty_operations *ops;
	struct tty_ldisc *ldisc;
	struct ld_semaphore ldisc_sem;
	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	struct ktermios termios;
	struct ktermios termios_locked;
	char name[64];
	long unsigned int flags;
	int count;
	unsigned int receive_room;
	struct winsize winsize;
	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		long unsigned int unused[0];
	} flow;
	struct {
		struct pid *pgrp;
		struct pid *session;
		spinlock_t lock;
		unsigned char pktstatus;
		bool packet;
		long unsigned int unused[0];
	} ctrl;
	bool hw_stopped;
	bool closing;
	int flow_change;
	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;
	int write_cnt;
	u8 *write_buf;
	struct list_head tty_files;
	struct work_struct SAK_work;
};
struct user_event_mm {
	struct list_head mms_link;
	struct list_head enablers;
	struct mm_struct *mm;
	struct user_event_mm *next;
	refcount_t refcnt;
	refcount_t tasks;
	struct rcu_work put_rwork;
};
struct user_namespace {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	struct uid_gid_map projid_map;
	struct user_namespace *parent;
	int level;
	kuid_t owner;
	kgid_t group;
	struct ns_common ns;
	long unsigned int flags;
	bool parent_could_setfcap;
	struct list_head keyring_name_list;
	struct key *user_keyring_register;
	struct rw_semaphore keyring_sem;
	struct key *persistent_keyring_register;
	struct work_struct work;
	struct ctl_table_set set;
	struct ctl_table_header *sysctls;
	struct ucounts *ucounts;
	long int ucount_max[12];
	long int rlimit_max[4];
	struct binfmt_misc *binfmt_misc;
};
struct vmpressure {
	long unsigned int scanned;
	long unsigned int reclaimed;
	long unsigned int tree_scanned;
	long unsigned int tree_reclaimed;
	spinlock_t sr_lock;
	struct list_head events;
	struct mutex events_lock;
	struct work_struct work;
};
struct mem_cgroup {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	bool zswap_writeback;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct obj_cgroup *orig_objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct lru_gen_mm_list mm_list;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct worker {
	union {
		struct list_head entry;
		struct hlist_node hentry;
	};
	struct work_struct *current_work;
	work_func_t current_func;
	struct pool_workqueue *current_pwq;
	u64 current_at;
	unsigned int current_color;
	int sleeping;
	work_func_t last_func;
	struct list_head scheduled;
	struct task_struct *task;
	struct worker_pool *pool;
	struct list_head node;
	long unsigned int last_active;
	unsigned int flags;
	int id;
	char desc[32];
	struct workqueue_struct *rescue_wq;
};
struct workqueue_struct {
	struct list_head pwqs;
	struct list_head list;
	struct mutex mutex;
	int work_color;
	int flush_color;
	atomic_t nr_pwqs_to_flush;
	struct wq_flusher *first_flusher;
	struct list_head flusher_queue;
	struct list_head flusher_overflow;
	struct list_head maydays;
	struct worker *rescuer;
	int nr_drainers;
	int saved_max_active;
	struct workqueue_attrs *unbound_attrs;
	struct pool_workqueue *dfl_pwq;
	struct wq_device *wq_dev;
	char name[24];
	struct callback_head rcu;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	unsigned int flags;
	struct pool_workqueue **cpu_pwq;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
enum wq_affn_scope {
	WQ_AFFN_DFL = 0,
	WQ_AFFN_CPU = 1,
	WQ_AFFN_SMT = 2,
	WQ_AFFN_CACHE = 3,
	WQ_AFFN_NUMA = 4,
	WQ_AFFN_SYSTEM = 5,
	WQ_AFFN_NR_TYPES = 6,
};
struct workqueue_attrs {
	int nice;
	cpumask_var_t cpumask;
	cpumask_var_t __pod_cpumask;
	bool affn_strict;
	enum wq_affn_scope affn_scope;
	bool ordered;
};
struct wq_device {
	struct workqueue_struct *wq;
	struct device dev;
};
struct wq_flusher {
	struct list_head list;
	int flush_color;
	struct completion done;
};
enum writeback_sync_modes {
	WB_SYNC_NONE = 0,
	WB_SYNC_ALL = 1,
};
struct writeback_control {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_netfs_wb: 1;
	unsigned int no_cgroup_owner: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback *wb;
	struct inode *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};
struct ww_acquire_ctx {
	struct task_struct *task;
	long unsigned int stamp;
	unsigned int acquired;
	short unsigned int wounded;
	short unsigned int is_wait_die;
};
struct x86_msi_addr_hi {
	u32 reserved: 8;
	u32 destid_8_31: 24;
};
typedef struct x86_msi_addr_hi arch_msi_msg_addr_hi_t;
struct x86_msi_addr_lo {
	union {
		struct {
			u32 reserved_0: 2;
			u32 dest_mode_logical: 1;
			u32 redirect_hint: 1;
			u32 reserved_1: 1;
			u32 virt_destid_8_14: 7;
			u32 destid_0_7: 8;
			u32 base_address: 12;
		};
		struct {
			u32 dmar_reserved_0: 2;
			u32 dmar_index_15: 1;
			u32 dmar_subhandle_valid: 1;
			u32 dmar_format: 1;
			u32 dmar_index_0_14: 15;
			u32 dmar_base_address: 12;
		};
	};
};
typedef struct x86_msi_addr_lo arch_msi_msg_addr_lo_t;
struct x86_msi_data {
	union {
		struct {
			u32 vector: 8;
			u32 delivery_mode: 3;
			u32 dest_mode_logical: 1;
			u32 reserved: 2;
			u32 active_low: 1;
			u32 is_level: 1;
		};
		u32 dmar_subhandle;
	};
};
typedef struct x86_msi_data arch_msi_msg_data_t;
struct msi_msg {
	union {
		u32 address_lo;
		arch_msi_msg_addr_lo_t arch_addr_lo;
	};
	union {
		u32 address_hi;
		arch_msi_msg_addr_hi_t arch_addr_hi;
	};
	union {
		u32 data;
		arch_msi_msg_data_t arch_data;
	};
};
struct msi_desc {
	unsigned int irq;
	unsigned int nvec_used;
	struct device *dev;
	struct msi_msg msg;
	struct irq_affinity_desc *affinity;
	const void *iommu_cookie;
	struct device_attribute *sysfs_attrs;
	void (*write_msi_msg)(struct msi_desc *, void *);
	void *write_msi_msg_data;
	u16 msi_index;
	union {
		struct pci_msi_desc pci;
		struct msi_desc_data data;
	};
};
struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};
struct address_space {
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations *a_ops;
	long unsigned int flags;
	struct rw_semaphore i_mmap_rwsem;
	errseq_t wb_err;
	spinlock_t i_private_lock;
	struct list_head i_private_list;
	void *i_private_data;
};
struct backing_dev_info {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	long unsigned int last_bdp_sleep;
	struct bdi_writeback wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device *dev;
	char dev_name[64];
	struct device *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry *debug_dir;
};
struct blkcg {
	struct cgroup_subsys_state css;
	spinlock_t lock;
	refcount_t online_pin;
	struct xarray blkg_tree;
	struct blkcg_gq *blkg_hint;
	struct hlist_head blkg_list;
	struct blkcg_policy_data *cpd[6];
	struct list_head all_blkcgs_node;
	struct llist_head *lhead;
	char fc_app_id[129];
	struct list_head cgwb_list;
};
struct gendisk {
	int major;
	int first_minor;
	int minors;
	char disk_name[32];
	short unsigned int events;
	short unsigned int event_flags;
	struct xarray part_tbl;
	struct block_device *part0;
	const struct block_device_operations *fops;
	struct request_queue *queue;
	void *private_data;
	struct bio_set bio_split;
	int flags;
	long unsigned int state;
	struct mutex open_mutex;
	unsigned int open_partitions;
	struct backing_dev_info *bdi;
	struct kobject queue_kobj;
	struct kobject *slave_dir;
	struct list_head slave_bdevs;
	struct timer_rand_state *random;
	atomic_t sync_io;
	struct disk_events *ev;
	unsigned int nr_zones;
	unsigned int max_open_zones;
	unsigned int max_active_zones;
	long unsigned int *conv_zones_bitmap;
	long unsigned int *seq_zones_wlock;
	struct cdrom_device_info *cdi;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
	blk_mode_t open_mode;
	struct blk_independent_access_ranges *ia_ranges;
};
struct ida {
	struct xarray xa;
};
struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};
struct cgroup_subsys {
	struct cgroup_subsys_state * (*css_alloc)(struct cgroup_subsys_state *);
	int (*css_online)(struct cgroup_subsys_state *);
	void (*css_offline)(struct cgroup_subsys_state *);
	void (*css_released)(struct cgroup_subsys_state *);
	void (*css_free)(struct cgroup_subsys_state *);
	void (*css_reset)(struct cgroup_subsys_state *);
	void (*css_rstat_flush)(struct cgroup_subsys_state *, int);
	int (*css_extra_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*css_local_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*can_attach)(struct cgroup_taskset *);
	void (*cancel_attach)(struct cgroup_taskset *);
	void (*attach)(struct cgroup_taskset *);
	void (*post_attach)(void);
	int (*can_fork)(struct task_struct *, struct css_set *);
	void (*cancel_fork)(struct task_struct *, struct css_set *);
	void (*fork)(struct task_struct *);
	void (*exit)(struct task_struct *);
	void (*release)(struct task_struct *);
	void (*bind)(struct cgroup_subsys_state *);
	bool early_init: 1;
	bool implicit_on_dfl: 1;
	bool threaded: 1;
	int id;
	const char *name;
	const char *legacy_name;
	struct cgroup_root *root;
	struct idr css_idr;
	struct list_head cfts;
	struct cftype *dfl_cftypes;
	struct cftype *legacy_cftypes;
	unsigned int depends_on;
};
struct inode {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	struct list_head i_lru;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 __i_atime;
	struct timespec64 __i_mtime;
	struct timespec64 __i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_inode_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};
struct dax_device {
	struct inode inode;
	struct cdev cdev;
	void *private;
	long unsigned int flags;
	const struct dax_operations *ops;
	void *holder_data;
	const struct dax_holder_operations *holder_ops;
};
struct io_context {
	atomic_long_t refcount;
	atomic_t active_ref;
	short unsigned int ioprio;
	spinlock_t lock;
	struct xarray icq_tree;
	struct io_cq *icq_hint;
	struct hlist_head icq_list;
	struct work_struct release_work;
};
struct io_ring_ctx {
	struct {
		unsigned int flags;
		unsigned int drain_next: 1;
		unsigned int restricted: 1;
		unsigned int off_timeout_used: 1;
		unsigned int drain_active: 1;
		unsigned int has_evfd: 1;
		unsigned int task_complete: 1;
		unsigned int lockless_cq: 1;
		unsigned int syscall_iopoll: 1;
		unsigned int poll_activated: 1;
		unsigned int drain_disabled: 1;
		unsigned int compat: 1;
		struct task_struct *submitter_task;
		struct io_rings *rings;
		struct percpu_ref refs;
		enum task_work_notify_mode notify_method;
		long: 64;
		long: 64;
	};
	struct {
		struct mutex uring_lock;
		u32 *sq_array;
		struct io_uring_sqe *sq_sqes;
		unsigned int cached_sq_head;
		unsigned int sq_entries;
		struct io_rsrc_node *rsrc_node;
		atomic_t cancel_seq;
		struct io_file_table file_table;
		unsigned int nr_user_files;
		unsigned int nr_user_bufs;
		struct io_mapped_ubuf **user_bufs;
		struct io_submit_state submit_state;
		struct xarray io_bl_xa;
		struct io_hash_table cancel_table_locked;
		struct io_alloc_cache apoll_cache;
		struct io_alloc_cache netmsg_cache;
		struct io_wq_work_list iopoll_list;
		bool poll_multi_queue;
		struct hlist_head cancelable_uring_cmd;
		long: 64;
	};
	struct {
		struct io_uring_cqe *cqe_cached;
		struct io_uring_cqe *cqe_sentinel;
		unsigned int cached_cq_tail;
		unsigned int cq_entries;
		struct io_ev_fd *io_ev_fd;
		unsigned int cq_extra;
		long: 64;
		long: 64;
		long: 64;
	};
	struct {
		struct llist_head work_llist;
		long unsigned int check_cq;
		atomic_t cq_wait_nr;
		atomic_t cq_timeouts;
		struct wait_queue_head cq_wait;
		long: 64;
		long: 64;
	};
	struct {
		spinlock_t timeout_lock;
		struct list_head timeout_list;
		struct list_head ltimeout_list;
		unsigned int cq_last_tm_flush;
		long: 64;
		long: 64;
	};
	struct io_uring_cqe completion_cqes[16];
	spinlock_t completion_lock;
	struct io_wq_work_list locked_free_list;
	unsigned int locked_free_nr;
	struct list_head io_buffers_comp;
	struct list_head cq_overflow_list;
	struct io_hash_table cancel_table;
	struct hlist_head waitid_list;
	struct hlist_head futex_list;
	struct io_alloc_cache futex_cache;
	const struct cred *sq_creds;
	struct io_sq_data *sq_data;
	struct wait_queue_head sqo_sq_wait;
	struct list_head sqd_list;
	unsigned int file_alloc_start;
	unsigned int file_alloc_end;
	struct xarray personalities;
	u32 pers_next;
	struct list_head io_buffers_cache;
	struct wait_queue_head poll_wq;
	struct io_restriction restrictions;
	struct io_mapped_ubuf *dummy_ubuf;
	struct io_rsrc_data *file_data;
	struct io_rsrc_data *buf_data;
	struct list_head rsrc_ref_list;
	struct io_alloc_cache rsrc_node_cache;
	struct wait_queue_head rsrc_quiesce_wq;
	unsigned int rsrc_quiesce;
	struct io_wq_hash *hash_map;
	struct user_struct *user;
	struct mm_struct *mm_account;
	struct llist_head fallback_llist;
	struct delayed_work fallback_work;
	struct work_struct exit_work;
	struct list_head tctx_list;
	struct completion ref_comp;
	u32 iowq_limits[2];
	bool iowq_limits_set;
	struct callback_head poll_wq_task_work;
	struct list_head defer_list;
	unsigned int sq_thread_idle;
	unsigned int evfd_last_cq_tail;
	short unsigned int n_ring_pages;
	short unsigned int n_sqe_pages;
	struct page **ring_pages;
	struct page **sqe_pages;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
struct io_uring_task {
	int cached_refs;
	const struct io_ring_ctx *last;
	struct io_wq *io_wq;
	struct file *registered_rings[16];
	struct xarray xa;
	struct wait_queue_head wait;
	atomic_t in_cancel;
	atomic_t inflight_tracked;
	struct percpu_counter inflight;
	long: 64;
	long: 64;
	struct {
		struct llist_head task_list;
		struct callback_head task_work;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	};
};
struct iommu_group {
	struct kobject kobj;
	struct kobject *devices_kobj;
	struct list_head devices;
	struct xarray pasid_array;
	struct mutex mutex;
	void *iommu_data;
	void (*iommu_data_release)(void *);
	char *name;
	int id;
	struct iommu_domain *default_domain;
	struct iommu_domain *blocking_domain;
	struct iommu_domain *domain;
	struct list_head entry;
	unsigned int owner_cnt;
	void *owner;
};
struct ipc_ids {
	int in_use;
	short unsigned int seq;
	struct rw_semaphore rwsem;
	struct idr ipcs_idr;
	int max_idx;
	int last_idx;
	int next_id;
	struct rhashtable key_ht;
};
struct ipc_namespace {
	struct ipc_ids ids[3];
	int sem_ctls[4];
	int used_sems;
	unsigned int msg_ctlmax;
	unsigned int msg_ctlmnb;
	unsigned int msg_ctlmni;
	struct percpu_counter percpu_msg_bytes;
	struct percpu_counter percpu_msg_hdrs;
	size_t shm_ctlmax;
	size_t shm_ctlall;
	long unsigned int shm_tot;
	int shm_ctlmni;
	int shm_rmid_forced;
	struct notifier_block ipcns_nb;
	struct vfsmount *mq_mnt;
	unsigned int mq_queues_count;
	unsigned int mq_queues_max;
	unsigned int mq_msg_max;
	unsigned int mq_msgsize_max;
	unsigned int mq_msg_default;
	unsigned int mq_msgsize_default;
	struct ctl_table_set mq_set;
	struct ctl_table_header *mq_sysctls;
	struct ctl_table_set ipc_set;
	struct ctl_table_header *ipc_sysctls;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct llist_node mnt_llist;
	struct ns_common ns;
};
struct irq_domain {
	struct list_head link;
	const char *name;
	const struct irq_domain_ops *ops;
	void *host_data;
	unsigned int flags;
	unsigned int mapcount;
	struct mutex mutex;
	struct irq_domain *root;
	struct fwnode_handle *fwnode;
	enum irq_domain_bus_token bus_token;
	struct irq_domain_chip_generic *gc;
	struct device *dev;
	struct device *pm_dev;
	struct irq_domain *parent;
	const struct msi_parent_ops *msi_parent_ops;
	irq_hw_number_t hwirq_max;
	unsigned int revmap_size;
	struct xarray revmap_tree;
	struct irq_data *revmap[0];
};
struct kernfs_root {
	struct kernfs_node *kn;
	unsigned int flags;
	struct idr ino_idr;
	u32 last_id_lowbits;
	u32 id_highbits;
	struct kernfs_syscall_ops *syscall_ops;
	struct list_head supers;
	wait_queue_head_t deactivate_waitq;
	struct rw_semaphore kernfs_rwsem;
	struct rw_semaphore kernfs_iattr_rwsem;
	struct rw_semaphore kernfs_supers_rwsem;
	struct callback_head rcu;
};
struct list_lru {
	struct list_lru_node *node;
	struct list_head list;
	int shrinker_id;
	bool memcg_aware;
	struct xarray xa;
};
struct msi_dev_domain {
	struct xarray store;
	struct irq_domain *domain;
};
struct msi_device_data {
	long unsigned int properties;
	struct platform_msi_priv_data *platform_data;
	struct mutex mutex;
	struct msi_dev_domain __domains[2];
	long unsigned int __iter_idx;
};
struct pid_namespace {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
	struct fs_pin *bacct;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
	int memfd_noexec_scope;
};
struct request_queue {
	void *queuedata;
	struct elevator_queue *elevator;
	const struct blk_mq_ops *mq_ops;
	struct blk_mq_ctx *queue_ctx;
	long unsigned int queue_flags;
	unsigned int rq_timeout;
	unsigned int queue_depth;
	refcount_t refs;
	unsigned int nr_hw_queues;
	struct xarray hctx_table;
	struct percpu_ref q_usage_counter;
	struct lock_class_key io_lock_cls_key;
	struct lockdep_map io_lockdep_map;
	struct lock_class_key q_lock_cls_key;
	struct lockdep_map q_lockdep_map;
	struct request *last_merge;
	spinlock_t queue_lock;
	int quiesce_depth;
	struct gendisk *disk;
	struct kobject *mq_kobj;
	struct queue_limits limits;
	struct blk_integrity integrity;
	struct device *dev;
	enum rpm_status rpm_status;
	atomic_t pm_only;
	struct blk_queue_stats *stats;
	struct rq_qos *rq_qos;
	struct mutex rq_qos_mutex;
	int id;
	unsigned int dma_pad_mask;
	long unsigned int nr_requests;
	struct blk_crypto_profile *crypto_profile;
	struct kobject *crypto_kobject;
	struct timer_list timeout;
	struct work_struct timeout_work;
	atomic_t nr_active_requests_shared_tags;
	unsigned int required_elevator_features;
	struct blk_mq_tags *sched_shared_tags;
	struct list_head icq_list;
	long unsigned int blkcg_pols[1];
	struct blkcg_gq *root_blkg;
	struct list_head blkg_list;
	struct mutex blkcg_mutex;
	int node;
	spinlock_t requeue_lock;
	struct list_head requeue_list;
	struct delayed_work requeue_work;
	struct blk_trace *blk_trace;
	struct blk_flush_queue *fq;
	struct list_head flush_list;
	struct mutex sysfs_lock;
	struct mutex sysfs_dir_lock;
	struct list_head unused_hctx_list;
	spinlock_t unused_hctx_lock;
	int mq_freeze_depth;
	struct throtl_data *td;
	struct callback_head callback_head;
	wait_queue_head_t mq_freeze_wq;
	struct mutex mq_freeze_lock;
	struct blk_mq_tag_set *tag_set;
	struct list_head tag_set_list;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct dentry *rqos_debugfs_dir;
	struct mutex debugfs_mutex;
	bool mq_sysfs_init_done;
};
struct super_block {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct dquot_operations *dq_op;
	const struct quotactl_ops *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler * const *s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device *s_bdev;
	struct bdev_handle *s_bdev_handle;
	struct backing_dev_info *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info s_dquot;
	struct sb_writers s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations *s_d_op;
	struct shrinker *s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};
struct worker_pool {
	raw_spinlock_t lock;
	int cpu;
	int node;
	int id;
	unsigned int flags;
	long unsigned int watchdog_ts;
	bool cpu_stall;
	int nr_running;
	struct list_head worklist;
	int nr_workers;
	int nr_idle;
	struct list_head idle_list;
	struct timer_list idle_timer;
	struct work_struct idle_cull_work;
	struct timer_list mayday_timer;
	struct hlist_head busy_hash[64];
	struct worker *manager;
	struct list_head workers;
	struct list_head dying_workers;
	struct completion *detach_completion;
	struct ida worker_ida;
	struct workqueue_attrs *attrs;
	struct hlist_node hash_node;
	int refcnt;
	struct callback_head rcu;
};
struct xattr_handler {
	const char *name;
	const char *prefix;
	int flags;
	bool (*list)(struct dentry *);
	int (*get)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t);
	int (*set)(const struct xattr_handler *, struct mnt_idmap *, struct dentry *, struct inode *, const char *, const void *, size_t, int);
};
struct xfrm_policy_hash {
	struct hlist_head *table;
	unsigned int hmask;
	u8 dbits4;
	u8 sbits4;
	u8 dbits6;
	u8 sbits6;
};
struct xfrm_policy_hthresh {
	struct work_struct work;
	seqlock_t lock;
	u8 lbits4;
	u8 rbits4;
	u8 lbits6;
	u8 rbits6;
};
struct netns_xfrm {
	struct list_head state_all;
	struct hlist_head *state_bydst;
	struct hlist_head *state_bysrc;
	struct hlist_head *state_byspi;
	struct hlist_head *state_byseq;
	struct hlist_head *state_cache_input;
	unsigned int state_hmask;
	unsigned int state_num;
	struct work_struct state_hash_work;
	struct list_head policy_all;
	struct hlist_head *policy_byidx;
	unsigned int policy_idx_hmask;
	unsigned int idx_generator;
	struct hlist_head policy_inexact[3];
	struct xfrm_policy_hash policy_bydst[3];
	unsigned int policy_count[6];
	struct work_struct policy_hash_work;
	struct xfrm_policy_hthresh policy_hthresh;
	struct list_head inexact_bins;
	struct sock *nlsk;
	struct sock *nlsk_stash;
	u32 sysctl_aevent_etime;
	u32 sysctl_aevent_rseqth;
	int sysctl_larval_drop;
	u32 sysctl_acq_expires;
	u8 policy_default[3];
	struct ctl_table_header *sysctl_hdr;
	long: 64;
	long: 64;
	struct dst_ops xfrm4_dst_ops;
	struct dst_ops xfrm6_dst_ops;
	spinlock_t xfrm_state_lock;
	seqcount_spinlock_t xfrm_state_hash_generation;
	seqcount_spinlock_t xfrm_policy_hash_generation;
	spinlock_t xfrm_policy_lock;
	struct mutex xfrm_cfg_mutex;
	long: 64;
	long: 64;
};
struct net {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	u32 ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node defer_free_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct ref_tracker_dir notrefcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock *rtnl;
	struct sock *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct xarray dev_by_index;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	void *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	struct netns_ipv4 ipv4;
	struct netns_ipv6 ipv6;
	struct netns_ieee802154_lowpan ieee802154_lowpan;
	struct netns_sctp sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock *crypto_nlsk;
	struct sock *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
};
struct xol_area {
	wait_queue_head_t wq;
	atomic_t slot_count;
	long unsigned int *bitmap;
	struct vm_special_mapping xol_mapping;
	struct page *pages[2];
	long unsigned int vaddr;
};
struct xstate_header {
	u64 xfeatures;
	u64 xcomp_bv;
	u64 reserved[6];
};
struct xregs_state {
	struct fxregs_state i387;
	struct xstate_header header;
	u8 extended_state_area[0];
};
union fpregs_state {
	struct fregs_state fsave;
	struct fxregs_state fxsave;
	struct swregs_state soft;
	struct xregs_state xsave;
	u8 __padding[4096];
};
struct fpstate {
	unsigned int size;
	unsigned int user_size;
	u64 xfeatures;
	u64 user_xfeatures;
	u64 xfd;
	unsigned int is_valloc: 1;
	unsigned int is_guest: 1;
	unsigned int is_confidential: 1;
	unsigned int in_use: 1;
	long: 64;
	long: 64;
	long: 64;
	union fpregs_state regs;
};
struct fpu {
	unsigned int last_cpu;
	long unsigned int avx512_timestamp;
	struct fpstate *fpstate;
	struct fpstate *__task_fpstate;
	struct fpu_state_perm perm;
	struct fpu_state_perm guest_perm;
	struct fpstate __fpstate;
};
struct thread_struct {
	struct desc_struct tls_array[3];
	long unsigned int sp;
	short unsigned int es;
	short unsigned int ds;
	short unsigned int fsindex;
	short unsigned int gsindex;
	long unsigned int fsbase;
	long unsigned int gsbase;
	struct perf_event *ptrace_bps[4];
	long unsigned int virtual_dr6;
	long unsigned int ptrace_dr7;
	long unsigned int cr2;
	long unsigned int trap_nr;
	long unsigned int error_code;
	struct io_bitmap *io_bitmap;
	long unsigned int iopl_emul;
	unsigned int iopl_warn: 1;
	u32 pkru;
	long unsigned int features;
	long unsigned int features_locked;
	struct thread_shstk shstk;
	long: 64;
	struct fpu fpu;
};
struct task_struct {
	struct thread_info thread_info;
	unsigned int __state;
	unsigned int saved_state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	struct sched_dl_entity *dl_server;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	struct uclamp_se uclamp_req[2];
	struct uclamp_se uclamp[2];
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int rcu_tasks_exit_cpu;
	struct list_head rcu_tasks_exit_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct address_space *faults_disabled_mapping;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_task_hot: 1;
	long: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int sched_rt_mutex: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	long unsigned int last_switch_count;
	long unsigned int last_switch_time;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	void *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	unsigned int in_ubsan;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp;
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_len;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	int mm_cid;
	int last_mm_cid;
	int migrate_from_cpu;
	int mm_cid_active;
	struct callback_head cid_work;
	struct tlbflush_unmap_batch tlb_ubc;
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup *active_memcg;
	struct obj_cgroup *objcg;
	struct gendisk *throttle_disk;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	struct callback_head rcu;
	refcount_t rcu_users;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	union rv_task_monitor rv[1];
	struct user_event_mm *user_event_mm;
	struct thread_struct thread;
};
struct zone {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high_min;
	int pageset_high_max;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	struct list_head unaccepted_pages;
	long unsigned int flags;
	spinlock_t lock;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	long: 0;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[12];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};
enum zone_type {
	ZONE_DMA = 0,
	ZONE_DMA32 = 1,
	ZONE_NORMAL = 2,
	ZONE_MOVABLE = 3,
	ZONE_DEVICE = 4,
	__MAX_NR_ZONES = 5,
};
struct zoneref {
	struct zone *zone;
	int zone_idx;
};
struct zonelist {
	struct zoneref _zonerefs[5121];
};
struct zswap_lruvec_state {
	atomic_long_t nr_zswap_protected;
};
struct lruvec {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_folio lrugen;
	struct lru_gen_mm_state mm_state;
	struct pglist_data *pgdat;
	struct zswap_lruvec_state zswap_lruvec_state;
};
struct mem_cgroup_per_node {
	struct lruvec lruvec;
	struct lruvec_stats_percpu *lruvec_stats_percpu;
	struct lruvec_stats lruvec_stats;
	long unsigned int lru_zone_size[25];
	struct mem_cgroup_reclaim_iter iter;
	struct shrinker_info *shrinker_info;
	struct rb_node tree_node;
	long unsigned int usage_in_excess;
	bool on_tree;
	struct mem_cgroup *memcg;
};
struct pglist_data {
	struct zone node_zones[5];
	struct zonelist node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk mm_walk;
	struct lru_gen_memcg memcg_lru;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[46];
	struct memory_tier *memtier;
	struct memory_failure_stats mf_stats;
	long: 64;
	long: 64;
	long: 64;
};
#endif
