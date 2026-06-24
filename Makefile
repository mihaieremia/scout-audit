# Scout-audit (XOXNO fork) — Soroban-only.
# Detectors and test-cases build under nightly-2026-05-28; contracts target wasm32v1-none.

.PHONY: ci fmt lint test test-soroban

ci: fmt lint test

test: test-soroban

fmt:
	@echo "Formatting Rust code..."
	@python3 scripts/run-fmt.py

lint:
	@echo "Linting cargo-scout-audit..."
	@python3 scripts/run-clippy.py

# Run the integration harness over every Soroban test-case.
# RUSTC_WRAPPER is cleared because sccache caches rustc output and would otherwise
# skip the dylint lint pass on cache hits, silently yielding stale (zero) findings.
test-soroban:
	@echo "Running soroban tests..."
	@python3 scripts/find-test-cases.py -b=soroban --format=list \
		| xargs -I {} env -u RUSTC_WRAPPER python3 scripts/run-tests.py --detector={}
