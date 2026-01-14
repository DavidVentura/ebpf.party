import type { FuncDoc as FuncDocType } from "../types/function-docs";
import FuncDoc from "./FuncDoc";
import styles from "./QuickReference.module.css";

interface QuickReferenceProps {
  stringMatching?: boolean;
  stringSearch?: boolean;
  mapUsage?: boolean;
  userSpaceReading?: boolean;
  kernelSpaceReading?: boolean;
  kprobeArgs?: boolean;
  pid?: boolean;
  comm?: boolean;
}

const stringMatchingFuncs: FuncDocType[] = [
  {
    function_name: "bpf_strncmp",
    description: "Compare two strings for equality",
    args: [
      {
        type: "char*",
        name: "buf",
        description: "dynamic buffer to compare",
      },
      {
        type: "u32",
        name: "buf_sz",
        description: "length of dynamic buffer",
      },
      {
        type: "const char*",
        name: "buf2",
        description: "literal string to compare against",
      },
    ],
    returns: {
      type: "int",
      description: "0 if strings match, non-zero if they differ",
    },
    docsUrl: "https://docs.ebpf.io/linux/helper-function/bpf_strncmp/",
  },
];

const stringSearchFuncs: FuncDocType[] = [
  {
    function_name: "bpf_strstr",
    description: "Find substring in string",
    args: [
      {
        type: "const char*",
        name: "haystack",
        description: "string to search in",
      },
      {
        type: "const char*",
        name: "needle",
        description: "substring to find",
      },
    ],
    returns: {
      type: "long",
      description: "index of needle in haystack, or negative on error",
    },
    docsUrl: "https://docs.ebpf.io/linux/kfuncs/bpf_strstr/",
  },
  {
    function_name: "bpf_strchr",
    description: "Find character in string",
    args: [
      {
        type: "const char*",
        name: "str",
        description: "string to search in",
      },
      {
        type: "char",
        name: "c",
        description: "character to find",
      },
    ],
    returns: {
      type: "long",
      description: "index of character in string, or negative on error",
    },
    docsUrl: "https://docs.ebpf.io/linux/kfuncs/bpf_strchr/",
  },
];

const mapUsageFuncs: FuncDocType[] = [
  {
    function_name: "bpf_map_update_elem",
    description: "Insert or update map entry",
    args: [
      {
        type: "void*",
        name: "map",
        description: "pointer to map",
      },
      {
        type: "const void*",
        name: "key",
        description: "pointer to key",
      },
      {
        type: "const void*",
        name: "value",
        description: "pointer to value",
      },
      {
        type: "u64",
        name: "flags",
        description:
          "BPF_ANY (create or update), BPF_NOEXIST (create only), or BPF_EXIST (update only)",
      },
    ],
    returns: {
      type: "int",
      description: {
        success: "0",
        error: "negative error code",
      },
    },
    docsUrl: "https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/",
  },
  {
    function_name: "bpf_map_lookup_elem",
    description: "Get value from map by key",
    args: [
      {
        type: "void*",
        name: "map",
        description: "pointer to map",
      },
      {
        type: "const void*",
        name: "key",
        description: "pointer to key",
      },
    ],
    returns: {
      type: "void*",
      description: "pointer to value if found, NULL otherwise",
    },
    docsUrl: "https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/",
  },
  {
    function_name: "bpf_map_delete_elem",
    description: "Remove entry from map",
    args: [
      {
        type: "void*",
        name: "map",
        description: "pointer to map",
      },
      {
        type: "const void*",
        name: "key",
        description: "pointer to key to delete",
      },
    ],
    returns: {
      type: "int",
      description: {
        success: "0",
        error: "negative error code if key not found",
      },
    },
    docsUrl: "https://docs.ebpf.io/linux/helper-function/bpf_map_delete_elem/",
  },
];

const kprobeArgsFuncs: FuncDocType[] = [
  {
    function_name: "PT_REGS_PARM{1-8}",
    description: "Extract the Nth parameter from kprobe context",
    args: [
      {
        type: "struct pt_regs*",
        name: "ctx",
        description: "kprobe context containing CPU registers",
      },
    ],
    returns: {
      type: "unsigned long",
      description: "value of Nth function parameter",
    },
    docsUrl: "https://docs.ebpf.io/ebpf-library/libbpf/ebpf/PT_REGS_PARM/",
  },
];

const kernelSpaceReadingFuncs: FuncDocType[] = [
  {
    function_name: "bpf_probe_read_kernel",
    description: "Read bytes from kernel space into kernel buffer",
    args: [
      {
        type: "void*",
        name: "dst",
        description: "kernel buffer to read into",
      },
      {
        type: "u32",
        name: "size",
        description: "bytes to read",
      },
      {
        type: "const void*",
        name: "src",
        description: "kernel space pointer",
      },
    ],
    returns: {
      type: "int",
      description: {
        success: "0",
        error: "negative error code",
      },
    },
    docsUrl:
      "https://docs.ebpf.io/linux/helper-function/bpf_probe_read_kernel/",
  },
  {
    function_name: "bpf_probe_read_kernel_str",
    description: "Read string from kernel space into kernel buffer",
    args: [
      {
        type: "void*",
        name: "dst",
        description: "kernel buffer to read into",
      },
      {
        type: "u32",
        name: "size",
        description: "maximum bytes to read",
      },
      {
        type: "const void*",
        name: "src",
        description: "kernel space pointer to string",
      },
    ],
    returns: {
      type: "int",
      description: {
        success: "number of bytes read (including null terminator)",
        error: "negative error code",
      },
    },
    docsUrl:
      "https://docs.ebpf.io/linux/helper-function/bpf_probe_read_kernel_str/",
  },
];

const userSpaceReadingFuncs: FuncDocType[] = [
  {
    function_name: "bpf_probe_read_user_str",
    description: "Read string from user space into kernel buffer",
    args: [
      {
        type: "void*",
        name: "dst",
        description: "kernel buffer to read into",
      },
      {
        type: "u32",
        name: "size",
        description: "maximum bytes to read",
      },
      {
        type: "const void*",
        name: "src",
        description: "user space pointer to string",
      },
    ],
    returns: {
      type: "int",
      description: {
        success: "number of bytes read (including null terminator)",
        error: "negative error code",
      },
    },
    docsUrl:
      "https://docs.ebpf.io/linux/helper-function/bpf_probe_read_user_str/",
  },
  {
    function_name: "bpf_probe_read_user",
    description: "Read bytes from user space into kernel buffer",
    args: [
      {
        type: "void*",
        name: "dst",
        description: "kernel buffer to read into",
      },
      {
        type: "u32",
        name: "size",
        description: "bytes to read",
      },
      {
        type: "const void*",
        name: "src",
        description: "user space pointer",
      },
    ],
    returns: {
      type: "int",
      description: {
        success: "0",
        error: "negative error code",
      },
    },
    docsUrl: "https://docs.ebpf.io/linux/helper-function/bpf_probe_read_user/",
  },
];

const getPID: FuncDocType[] = [
  {
    function_name: "bpf_get_current_pid_tgid",
    description: "Get current process and thread ID",
    args: [],
    returns: {
      type: "u64",
      description: "Upper 32 bits are PID, lower 32 bits are TID.",
    },
    docsUrl:
      "https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/",
  },
];
const getCOMM: FuncDocType[] = [
  {
    function_name: "bpf_get_current_comm",
    description: "Get current process name",
    args: [
      {
        type: "char*",
        name: "buf",
        description: "buffer to write process name into",
      },
      {
        type: "u32",
        name: "size",
        description: "size of buffer",
      },
    ],
    returns: {
      type: "int",
      description: {
        success: "0",
        error: "negative error code",
      },
    },
    docsUrl: "https://docs.ebpf.io/linux/helper-function/bpf_get_current_comm/",
  },
];

export default function QuickReference({
  stringMatching = false,
  stringSearch = false,
  mapUsage = false,
  userSpaceReading = false,
  kernelSpaceReading = false,
  kprobeArgs = false,
  pid = false,
  comm = false,
}: QuickReferenceProps) {
  const funcs = [
    pid ? getPID : [],
    comm ? getCOMM : [],
    stringMatching ? stringMatchingFuncs : [],
    stringSearch ? stringSearchFuncs : [],
    mapUsage ? mapUsageFuncs : [],
    kprobeArgs ? kprobeArgsFuncs : [],
    userSpaceReading ? userSpaceReadingFuncs : [],
    kernelSpaceReading ? kernelSpaceReadingFuncs : [],
  ].flat();
  return (
    <div className={styles.reference}>
      <b className={styles.title}>Quick reference</b>
      {funcs.map((func, index) => (
        <FuncDoc key={index} doc={func} />
      ))}
    </div>
  );
}
