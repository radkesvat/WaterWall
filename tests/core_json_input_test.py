#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


CORE_INPUT_ENV = "WW_CORE_JSON_INPUT"
UNSET = object()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_waterwall(binary, working_directory, arguments=(), environment_input=UNSET, stdin_text=""):
    environment = os.environ.copy()
    environment.pop(CORE_INPUT_ENV, None)
    if environment_input is not UNSET:
        environment[CORE_INPUT_ENV] = environment_input

    return subprocess.run(
        [str(binary), *arguments],
        cwd=working_directory,
        env=environment,
        input=stdin_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )


def expect_selected(result, marker, case_name, excluded_markers=()):
    require(result.returncode != 0, f"{case_name}: invalid marker input unexpectedly succeeded\n{result.stdout}")
    require(marker in result.stdout, f"{case_name}: selected input marker was not parsed\n{result.stdout}")
    for excluded in excluded_markers:
        require(excluded not in result.stdout, f"{case_name}: lower-precedence input was selected\n{result.stdout}")


def expect_error(result, expected, case_name):
    require(result.returncode != 0, f"{case_name}: invalid startup input unexpectedly succeeded\n{result.stdout}")
    require(expected in result.stdout, f"{case_name}: missing diagnostic {expected!r}\n{result.stdout}")


def core_json_with_marker(marker):
    return json.dumps(
        {
            "configs": [f"{marker}.json"],
            "misc": {
                "workers": 1,
                "ram-profile": "minimal",
                "try-enabling-bbr": False,
            },
        }
    )


def write_marker(path, marker):
    path.write_text(core_json_with_marker(marker), encoding="utf-8")


def test_version_arguments(binary, run_dir):
    for argument in ("-v", "--v", "-version", "--version", "version"):
        result = run_waterwall(binary, run_dir, [argument])
        require(result.returncode == 0, f"version alias {argument!r} failed\n{result.stdout}")
        require("Waterwall version " in result.stdout, f"version alias {argument!r} produced no version\n{result.stdout}")


def test_file_selection(binary, run_dir):
    default_file = run_dir / "core.json"
    relative_file = run_dir / "relative core:input.json"
    absolute_file = run_dir / "absolute-core.json"
    environment_file = run_dir / "environment-core.json"

    write_marker(default_file, "DEFAULT_INPUT_MARKER")
    write_marker(relative_file, "RELATIVE_CLI_INPUT_MARKER")
    write_marker(absolute_file, "ABSOLUTE_CLI_INPUT_MARKER")
    write_marker(environment_file, "ENVIRONMENT_INPUT_MARKER")

    result = run_waterwall(binary, run_dir)
    expect_selected(result, "DEFAULT_INPUT_MARKER", "default working-directory input")

    relative_value = relative_file.name
    for prefix in ("-c:", "--c:", "-config:", "--config:", "config:"):
        result = run_waterwall(binary, run_dir, [prefix + relative_value])
        expect_selected(result, "RELATIVE_CLI_INPUT_MARKER", f"CLI form {prefix}")

    result = run_waterwall(binary, run_dir, [f"--config:{absolute_file}"])
    expect_selected(result, "ABSOLUTE_CLI_INPUT_MARKER", "absolute CLI path")

    result = run_waterwall(binary, run_dir, environment_input=environment_file.name)
    expect_selected(
        result,
        "ENVIRONMENT_INPUT_MARKER",
        "relative environment path",
        excluded_markers=("DEFAULT_INPUT_MARKER",),
    )

    result = run_waterwall(binary, run_dir, environment_input=str(environment_file.resolve()))
    expect_selected(result, "ENVIRONMENT_INPUT_MARKER", "absolute environment path")

    result = run_waterwall(
        binary,
        run_dir,
        [f"--config:{absolute_file}"],
        environment_input=environment_file.name,
    )
    expect_selected(
        result,
        "ABSOLUTE_CLI_INPUT_MARKER",
        "CLI precedence over environment",
        excluded_markers=("ENVIRONMENT_INPUT_MARKER", "DEFAULT_INPUT_MARKER"),
    )

    result = run_waterwall(binary, run_dir, [f"-c:{relative_value}"], environment_input="")
    expect_selected(result, "RELATIVE_CLI_INPUT_MARKER", "CLI precedence over an empty environment value")


def test_stdin_selection(binary, run_dir):
    large_stdin = (" " * 5000) + core_json_with_marker("STDIN_INPUT_MARKER")

    result = run_waterwall(binary, run_dir, ["--config:stdin"], stdin_text=large_stdin)
    expect_selected(result, "STDIN_INPUT_MARKER", "CLI stdin input")

    result = run_waterwall(
        binary,
        run_dir,
        environment_input="stdin",
        stdin_text=core_json_with_marker("ENV_STDIN_INPUT_MARKER"),
    )
    expect_selected(result, "ENV_STDIN_INPUT_MARKER", "environment stdin input")

    result = run_waterwall(binary, run_dir, ["config:stdin"], stdin_text="")
    expect_error(result, "standard input ended before any JSON was received", "empty stdin input")


def test_invalid_inputs(binary, run_dir):
    missing_path = run_dir / "missing-core.json"
    invalid_json_path = run_dir / "invalid-core.json"
    invalid_json_path.write_text("{", encoding="utf-8")

    result = run_waterwall(binary, run_dir, [f"--config:{missing_path}"])
    expect_error(result, "Could not open core settings file", "missing config path")

    result = run_waterwall(binary, run_dir, [f"--config:{run_dir}"])
    expect_error(result, "Could not read core settings file", "directory config path")

    result = run_waterwall(binary, run_dir, [f"--config:{invalid_json_path}"])
    expect_error(result, "Could not parse core settings JSON from file", "invalid core JSON file")

    result = run_waterwall(binary, run_dir, ["--config:stdin"], stdin_text="{")
    expect_error(result, "Could not parse core settings JSON from standard input", "invalid core JSON stdin")

    result = run_waterwall(binary, run_dir, ["--unknown"])
    expect_error(result, "Invalid command-line argument", "unknown argument")

    result = run_waterwall(binary, run_dir, ["--config"])
    expect_error(result, "Invalid command-line argument", "missing config separator")

    result = run_waterwall(binary, run_dir, ["--config:"])
    expect_error(result, "requires a non-empty value after ':'", "empty CLI config value")

    result = run_waterwall(binary, run_dir, environment_input="")
    expect_error(result, "WW_CORE_JSON_INPUT is set but does not contain", "empty environment config value")

    result = run_waterwall(binary, run_dir, ["-c:first.json", "--config:second.json"])
    expect_error(result, "may only be specified once", "duplicate config options")

    result = run_waterwall(binary, run_dir, ["--version", "--config:core.json"])
    expect_error(result, "cannot be combined", "version and config combination")


def main():
    require(len(sys.argv) == 2, "usage: core_json_input_test.py <Waterwall-binary>")
    binary = Path(sys.argv[1]).resolve()
    require(binary.is_file(), f"Waterwall binary does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="waterwall-core-input-") as temp_dir:
        run_dir = Path(temp_dir)
        test_version_arguments(binary, run_dir)
        test_file_selection(binary, run_dir)
        test_stdin_selection(binary, run_dir)
        test_invalid_inputs(binary, run_dir)


if __name__ == "__main__":
    main()
