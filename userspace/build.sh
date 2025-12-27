set -e
LIBBPF_SYS_EXTRA_CFLAGS="-idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include" cargo build --target x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/debug/userspace
set -x
cp target/x86_64-unknown-linux-musl/debug/userspace ../rootfs/main
cd .. && mkfs.ext4 -F -d rootfs rootfs.ext4 

