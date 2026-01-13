.PHONY: all website_bindings

CFLAGS = -static -fno-ident -fno-asynchronous-unwind-tables -fno-unwind-tables -s -Os -nostdlib -I/home/david/git/linux-6.18.2/tools/include/nolibc -include nolibc.h

all: website_bindings backend/includes/task.h.pch rootfs.ext4 backend/includes/kfuncs.h
	:
website_bindings: website/src/wasm/syntax_check.mjs website/public/tcc/syntax_check.data website/public/tcc/syntax_check.wasm
	:

backend/includes/kfuncs.h:
	# generating this automatically requires a new pahole & bpftool
	# for now, grep works
	grep ^__bpf_kfunc ~/git/linux-6.18.2/kernel/bpf/helpers.c | grep bpf_str | sed -e 's/^__bpf_kfunc/extern/' -e 's/$$/ __ksym __weak;/' > $@

backend/includes/task.h.pch: backend/includes/task.h
	cd ./backend/includes && ../clang -g -fpch-debuginfo -O2 -target bpf -x c-header task.h -o task.h.pch

tcc/em_include:
	ln -s ../backend/includes/ tcc/em_include

tcc/config.h:
	cd tcc && ./configure

# tcc/em_include removed dep to speed up builds, need to debug
tcc/syntax_check.wasm: tcc/config.h tcc/*.c tcc/*.h tcc/em_include/*.h tcc/em_include/bpf/*.h
	cd tcc && bash embuild.sh

website/src/wasm/syntax_check.mjs: tcc/syntax_check.wasm
	cp tcc/syntax_check.mjs $@
website/public/tcc/syntax_check.data: tcc/syntax_check.wasm
	cp tcc/syntax_check.data $@
website/public/tcc/syntax_check.wasm: tcc/syntax_check.wasm
	cp tcc/syntax_check.wasm $@

rootfs:
	mkdir -p rootfs
rootfs/%: bins/%.c rootfs
	gcc $(CFLAGS) $< -o $@


rootfs/main: userspace/src/*.rs userspace/src/setup/*.rs
	cd userspace && LIBBPF_SYS_EXTRA_CFLAGS="-idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include" cargo build --release --target x86_64-unknown-linux-musl
	strip userspace/target/x86_64-unknown-linux-musl/release/userspace
	cp userspace/target/x86_64-unknown-linux-musl/release/userspace $@

rootfs/tmp:
	mkdir -p $@
rootfs/bin:
	mkdir -p $@
rootfs/sys:
	mkdir -p $@

rootfs.ext4: rootfs/exit_with_code rootfs/true rootfs/main rootfs/bin rootfs/sys
	truncate -s 16M $@
	mkfs.ext4 -q -F -d rootfs $@
