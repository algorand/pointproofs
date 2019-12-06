all:
	# this build a debug library; we will need to change to
	#		`cargo build --release`
	# for deployment
	cargo build
	# we use cbindgen crate to automatically generate the header for C
	cbindgen --config cbindgen.toml --crate veccom --output c_test/veccom_c.h


test_veccom:
	cargo build
	cbindgen --config cbindgen.toml --crate veccom --output c_test/veccom_c.h
	gcc c_test/*.c -L./target/debug -lveccom -lpthread -ldl -o c_test/c_example
	c_test/c_example


test: test_veccom



clean:
	cargo clean
	rm c_test/c_example
