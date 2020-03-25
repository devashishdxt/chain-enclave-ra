TARGET_NAME=sample-ra-enclave
TARGET_DIR=$TARGET_NAME/target/x86_64-fortanix-unknown-sgx/debug
TARGET=$TARGET_DIR/$TARGET_NAME
TARGET_SGX=$TARGET_DIR/$TARGET_NAME.sgxs
TARGET_SIG=$TARGET_DIR/$TARGET_NAME.sig
KEY=$TARGET_NAME/data/vendor-keys/private_key.pem

# Build and sign enclave
(cd sample-ra-enclave && RUSTFLAGS="-C target-feature=+aes,+pclmul" cargo build --target x86_64-fortanix-unknown-sgx) && \
ftxsgx-elf2sgxs $TARGET --heap-size 0x2000000 --stack-size 0x20000 --threads 8 \
    --debug --output $TARGET_SGX && \
sgxs-sign --key $KEY $TARGET_SGX $TARGET_SIG -d --xfrm 7/0 --isvprodid 0 --isvsvn 0

# Build SP
(cd sample-ra-sp && cargo build)

# Build Client
(cd sample-ra-client && cargo build)
