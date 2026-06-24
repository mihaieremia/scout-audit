from glob import glob
from collections import Counter
import os
import argparse
import time
import tempfile
import json
import utils

from utils import (
    parse_json_from_string,
    print_errors,
    print_results,
    run_subprocess,
    is_rust_project,
)


def run_tests(detector):
    errors = []
    [blockchain, detector] = detector.split("/")
    directory = os.path.join("test-cases", blockchain, detector)
    print(f"\n{utils.GREEN}Performing tests in {directory}:{utils.ENDC}")
    if not os.path.exists(directory):
        print(f"{utils.RED}The specified directory does not exist.{utils.ENDC}")
        return errors

    for root, _, _ in os.walk(directory):
        if is_rust_project(root):
            if run_unit_tests(root):
                errors.append(root)
            if run_integration_tests(detector, root):
                errors.append(root)
    return errors


def convert_code(s):
    return s.replace("_", "-")


def load_manifest(root):
    """Load an optional expected.json manifest from a test-case crate root.

    Schema: {"findings": [{"detector": "<id>", "count": <int>, "lines": [<int>...]?}]}
    Each entry asserts the EXACT number of findings for that detector; detectors
    not listed are ignored (so always-on detectors like soroban_version don't make
    the assertion brittle). A clean false-positive-regression case pins the target
    detector with count 0, e.g. {"findings": [{"detector": "<det>", "count": 0}]}.
    Returns the parsed dict, or None if absent.
    """
    path = os.path.join(root, "expected.json")
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def finding_lines(finding):
    """Line numbers of a finding's primary span(s) (falls back to all spans)."""
    spans = finding.get("message", {}).get("spans", [])
    primary = [s for s in spans if s.get("is_primary")] or spans
    return {s["line_start"] for s in primary if "line_start" in s}


def check_expected_findings(manifest, findings):
    """Compare actual findings against a manifest. Returns (ok, explanation).

    For each listed detector, asserts its EXACT finding count (and, when given,
    that the expected lines are a subset of the actual lines). Detectors not
    listed in the manifest are ignored."""
    expected = manifest.get("findings", [])

    actual_counts = Counter(
        convert_code(f["message"]["code"]["code"]) for f in findings
    )
    actual_lines = {}
    for f in findings:
        code = convert_code(f["message"]["code"]["code"])
        actual_lines.setdefault(code, set()).update(finding_lines(f))

    for entry in expected:
        code = convert_code(entry["detector"])
        want_count = entry["count"]
        got_count = actual_counts.get(code, 0)
        if got_count != want_count:
            return False, f"{code}: expected count {want_count}, got {got_count}"
        if "lines" in entry:
            want_lines = set(entry["lines"])
            got_lines = actual_lines.get(code, set())
            if not want_lines.issubset(got_lines):
                return (
                    False,
                    f"{code}: expected lines {sorted(want_lines)} not all present in {sorted(got_lines)}",
                )

    return True, ""


def run_unit_tests(root):
    start_time = time.time()
    params = ["cargo", "test", "--all-features"]
    returncode, stdout, stderr = run_subprocess(params, root)
    print_results(
        returncode,
        stderr,
        "unit-test",
        root,
        time.time() - start_time,
    )
    return returncode != 0


def run_integration_tests(detector, root):
    start_time = time.time()

    # Get latest nightly from the directory nightly/
    latest_nightly = os.path.join(os.getcwd(), "nightly")
    # Build the driver from this local checkout (otherwise scout clones it from the
    # published SCOUT_BRANCH, which lags local changes).
    repo_root = os.getcwd()

    returncode, stdout, stderr = run_subprocess(
        [
            "cargo",
            "+nightly-2026-05-28",
            "scout-audit",
            "--scout-source",
            repo_root,
            "--filter",
            detector,
            "--metadata",
            "--local-detectors",
            latest_nightly,
        ],
        root,
    )

    if stdout is None:
        print(f"{utils.RED}STDOUT: {stdout}\n\n{utils.ENDC}")
        print(f"{utils.RED}STDERR: {stderr}\n\n{utils.ENDC}")
        print(
            f"{utils.RED}Failed to run integration tests in {root} - Metadata returned empty.{utils.ENDC}"
        )
        return True

    detector_metadata = parse_json_from_string(stdout)

    if not isinstance(detector_metadata, dict):
        print("Failed to extract JSON:", detector_metadata)
        return True

    _, tempPath = tempfile.mkstemp(None, f"scout_{os.getpid()}_")

    returncode = None
    stderr = None

    returncode, _, stderr = run_subprocess(
        [
            "cargo",
            "+nightly-2026-05-28",
            "scout-audit",
            "--scout-source",
            repo_root,
            "--local-detectors",
            latest_nightly,
            "--output-format",
            "raw-json",
            "--output-path",
            tempPath,
        ],
        root,
    )

    if returncode != 0:
        print(f"{utils.RED}Scout failed to run.\n{stderr}{utils.ENDC}")
        return True

    with open(tempPath) as file:
        findings = [json.loads(line.rstrip()) for line in file if line.rstrip()]

    manifest = load_manifest(root)
    if manifest is not None:
        # Manifest-based assertion: exact {detector: count} across all detectors.
        ok, explanation = check_expected_findings(manifest, findings)
        if not ok:
            print(
                f"{utils.RED}Test case {root} didn't match expected.json: {explanation}.\n{stderr}{utils.ENDC}"
            )
            return True
    else:
        # Legacy binary check: this detector must fire iff the path is "vulnerable".
        detectors_triggered = {
            convert_code(f["message"]["code"]["code"]) for f in findings
        }
        should_fail = "vulnerable" in root
        did_fail = detector in detectors_triggered
        if should_fail != did_fail:
            explanation = (
                "it failed when it shouldn't have"
                if did_fail
                else "it didn't fail when it should have"
            )
            print(
                f"{utils.RED}Test case {root} didn't pass because {explanation}.\n{stderr}{utils.ENDC}"
            )
            return True

    print_results(
        returncode,
        stderr,
        "integration-test",
        root,
        time.time() - start_time,
    )
    return False


if __name__ == "__main__":
    print(run_subprocess(["cargo", "scout-audit", "--version"], ".")[1])
    parser = argparse.ArgumentParser(description="Run tests for a specific detector.")
    parser.add_argument(
        "--detector",
        type=str,
        required=True,
        help='The detector to run tests for, e.g., "unsafe-unwrap"',
    )
    args = parser.parse_args()

    errors = run_tests(args.detector)
    print_errors(errors)
    if errors:
        exit(1)
