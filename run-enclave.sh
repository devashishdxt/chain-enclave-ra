TARGET_NAME=sample-ra-enclave
TARGET_DIR=$TARGET_NAME/target/x86_64-fortanix-unknown-sgx/debug
TARGET=$TARGET_DIR/$TARGET_NAME.sgxs

# Run enclave with the default runner
ftxsgx-runner $TARGET