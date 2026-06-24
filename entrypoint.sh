#!/bin/bash
# GitHub Action entrypoint: run scout-audit against the target Soroban project using
# the detectors and driver bundled in this image, so nothing is fetched over the
# network at analysis time (--local-detectors + --scout-source point at the image).
set -euo pipefail

cd "${INPUT_TARGET:?INPUT_TARGET must be set}"

# INPUT_SCOUT_ARGS is intentionally unquoted so multiple flags word-split into args.
# shellcheck disable=SC2086
cargo scout-audit \
	--local-detectors /scout-audit/nightly \
	--scout-source /scout-audit \
	${INPUT_SCOUT_ARGS:-}
