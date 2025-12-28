set -e
LIBBPF_SYS_EXTRA_CFLAGS="-idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include" cargo build --release --target x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/release/userspace
set -x
cp target/x86_64-unknown-linux-musl/release/userspace ../rootfs/main
cd .. && mkfs.ext4 -F -d rootfs rootfs.ext4 

