fmt:
	@cargo fmt

fmt-check:
	@cargo fmt --check

lint: fmt-check
	@cargo clippy --all-targets -- -D warnings

test:
	@cargo test

check: lint test
