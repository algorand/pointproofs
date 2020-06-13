all:
	# this build a debug library; we will need to change to
	#		`cargo build --release`
	# for deployment
	cargo build --release
	# we use cbindgen crate to automatically generate the header for C
	cbindgen --config cbindgen.toml --crate pointproofs --output c_test/pointproofs_c.h


test_pointproofs:
	cargo build --release
	cbindgen --config cbindgen.toml --crate pointproofs --output c_test/pointproofs_c.h
	gcc c_test/*.c -L./target/release -lpointproofs -lpthread -ldl -lm -o c_test/c_example
	c_test/c_example


test: test_pointproofs


clean:
	cargo clean
	rm -f c_test/c_example
