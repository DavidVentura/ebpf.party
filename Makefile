.PHONY: all website_bindings

all: website_bindings backend/includes/task.h.pch
	:
website_bindings: website/src/wasm/syntax_check.mjs website/public/tcc/syntax_check.data website/public/tcc/syntax_check.wasm
	:

backend/includes/task.h.pch: backend/includes/task.h
	cd ./backend/includes && ../clang -g -fpch-debuginfo -O2 -target bpf -x c-header task.h -o task.h.pch

tcc/em_include:
	ln -s ../backend/includes/ tcc/em_include
tcc/config.h:
	cd tcc && ./configure

tcc/syntax_check.wasm: tcc/config.h tcc/em_include tcc/*.c tcc/*.h tcc/em_include/*
	cd tcc && bash embuild.sh

website/src/wasm/syntax_check.mjs: tcc/syntax_check.wasm
	cp tcc/syntax_check.mjs $@
website/public/tcc/syntax_check.data: tcc/syntax_check.wasm
	cp tcc/syntax_check.data $@
website/public/tcc/syntax_check.wasm: tcc/syntax_check.wasm
	cp tcc/syntax_check.wasm $@
