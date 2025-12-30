CFLAGS="-idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu" \
CC=musl-gcc \
	cargo build --release --target x86_64-unknown-linux-musl 
