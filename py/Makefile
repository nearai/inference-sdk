.PHONY: check fmt fmt-check lint test check-e2e

check: fmt-check lint test check-e2e

fmt:
	@uv run ruff format

fmt-check:
	@uv run ruff format --check

lint:
	@uv run ruff check

test:
	@uv run pytest -q

check-e2e:
	@uv run pytest e2e --collect-only -q
