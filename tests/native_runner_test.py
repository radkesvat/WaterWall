#!/usr/bin/env python3
"""Independent CMake fixture checks private cwd/logs, nonzero/skip/timeout/interrupt retention,
same-tree Debug/Release locking, separate trees and focused missing/stale auto-build. Requires
CMake/CTest/compiler. Raw CMake subprocess boundaries remain intentional to test exact signals and
lock ownership. CTest: waterwall.native_runner."""
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import subprocess
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.run_directory import RunDirectory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--cmake", required=True)
    parser.add_argument("--ctest", required=True)
    parser.add_argument("--compiler", required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    runner = source / "unittests/run_unit_test.cmake"
    run_directory = RunDirectory("native-runner-", parent=args.build_dir)
    root = run_directory.create().resolve()
    env = dict(os.environ, WATERWALL_TEST_KEEP_RUN_DIR="")

    def command(cmd, expected=0, **kwargs):
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=90, env=kwargs.pop("env", env), **kwargs)
        assert (result.returncode == 0) == (expected == 0), result.stdout
        return result.stdout

    def configure(build, value="original"):
        command([args.cmake, "-S", str(source / "fixtures/native_runner"), "-B", str(build),
                 "-G", "Ninja Multi-Config", f"-DCMAKE_C_COMPILER={args.compiler}",
                 f"-DRUNNER={runner}", f"-DFIXTURE_VALUE={value}"])

    def executable(build, config):
        return (build / f"executable-{config}.txt").read_text()

    def run_command(build, config, mode, label, **overrides):
        values = dict(TARGET="runner_fixture", EXECUTABLE=executable(build, config),
                      BUILD_DIR=build, CONFIG=config, NAME="waterwall.runner_fixture",
                      SOURCE_DIR=source, FIXTURE_DIR=source / "fixtures/native_runner",
                      ARGUMENTS=f"{mode};{label}")
        values.update(overrides)
        return [args.cmake, *(f"-DUNIT_TEST_{key}={value}" for key, value in values.items()),
                "-P", str(runner)]

    def artifact(output):
        match = re.search(r"^(?:\d+: )?-- Run artifacts: (.+)$", output, re.M)
        assert match, output
        path = Path(match[1])
        assert path.is_relative_to(root), path
        return path

    def run(build, config, mode="pass", label="one", expected=0, keep=False, **overrides):
        output = command(run_command(build, config, mode, label, **overrides), expected,
                         env=dict(env, WATERWALL_TEST_KEEP_RUN_DIR="1" if keep else ""))
        path = artifact(output)
        assert path.parent.parent.name == config, path
        if expected or keep or mode == "skip":
            assert path.is_dir(), output
        else:
            assert not path.exists(), output
        return path, output

    try:
        build = root / "one"
        configure(build)
        for config in ("Debug", "Release"):
            # A focused CTest run must recreate a missing executable.
            output = command([args.ctest, "--test-dir", str(build), "-C", config,
                              "-V", "-R", "^fixture_pass$", "--no-tests=error"])
            assert Path(executable(build, config)).is_file(), output
            assert not artifact(output).exists()
            Path(executable(build, config)).unlink()
            command([args.ctest, "--test-dir", str(build), "-C", config,
                     "-R", "^fixture_pass$", "--no-tests=error"])
            assert Path(executable(build, config)).is_file()
            run(build, config)
            path, _ = run(build, config, keep=True)
            assert (path / "generated.txt").read_text() == f"{config}:one:original\n"
            path, output = run(build, config, "fail", expected=1)
            assert "execution failed: 7" in output, output
            assert f"{config}:one:fail:stdout" in (path / "child.stdout.log").read_text()
            assert f"{config}:one:fail:stderr" in (path / "child.stderr.log").read_text()
            _, output = run(build, config, "timeout", expected=1, TIMEOUT=1)
            assert "timeout" in output.lower(), output
            path, output = run(build, config, "skip", SKIP_CODE=77)
            assert "skipped (exit 77)" in output, output
            assert (path / "child.result.txt").read_text().strip() == "77"

        path, _ = run(build, "Debug", keep=True, BUILD_DIR=os.path.relpath(build))
        assert (path / "generated.txt").is_file()

        configure(build, "stale-rebuilt")
        for config in ("Debug", "Release"):
            command([args.ctest, "--test-dir", str(build), "-C", config,
                     "-R", "^fixture_pass$", "--no-tests=error"])
            path, _ = run(build, config, keep=True)
            assert "stale-rebuilt" in (path / "generated.txt").read_text()
        output = command([args.ctest, "--test-dir", str(build), "-C", "Debug", "-V",
                          "-R", "^fixture_build_failure$", "--no-tests=error"], expected=1)
        assert "Build failed for build_failure" in output, output
        path = artifact(output)
        assert (path / "build.stdout.log").stat().st_size > 0
        assert not (path / "child.result.txt").exists()
        _, output = run(build, "Debug", expected=1, TARGET="build_timeout", BUILD_TIMEOUT=1)
        assert "Build failed" in output and "timeout" in output.lower(), output

        def concurrent(config, label):
            return run(build, config, "hold", label, keep=True)[0]

        # Same identity/configuration, then Debug/Release in the same build tree.
        with ThreadPoolExecutor(max_workers=2) as pool:
            for configs in (("Debug", "Debug"), ("Debug", "Release")):
                jobs = [pool.submit(concurrent, config, f"invocation-{i}")
                        for i, config in enumerate(configs)]
                paths = [job.result() for job in jobs]
                assert paths[0] != paths[1]
                for i, (path, config) in enumerate(zip(paths, configs)):
                    for stream in ("stdout", "stderr"):
                        log = (path / f"child.{stream}.log").read_text()
                        assert f"{config}:invocation-{i}:hold:{stream}" in log, log
                        assert f"invocation-{1-i}" not in log, log

        active = subprocess.Popen(run_command(build, "Debug", "hold", "lock-holder"),
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        try:
            deadline = time.monotonic() + 15
            while not (build / "child-active").exists():
                assert active.poll() is None, active.stdout.read()
                assert time.monotonic() < deadline, "fixture did not start"
                time.sleep(0.02)
            _, output = run(build, "Release", expected=1, LOCK_TIMEOUT=1)
            assert "Lock acquisition failed" in output, output
            # Interrupt an initialized runner while it is waiting for the lock;
            # its announced artifacts must survive without starting a child.
            interrupted = subprocess.Popen(run_command(build, "Release", "pass", "interrupted"),
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
            try:
                announced = interrupted.stdout.readline()
                path = artifact(announced)
                interrupted.terminate()
                interrupted.communicate(timeout=15)
                assert path.is_dir(), announced
                assert not (path / "child.result.txt").exists()
            finally:
                if interrupted.poll() is None:
                    interrupted.kill()
                    interrupted.communicate(timeout=15)
        finally:
            output, _ = active.communicate(timeout=15)
            assert active.returncode == 0, output

        # A different tree must proceed despite the first tree's held lock.
        other = root / "two"
        configure(other)
        run(other, "Debug")
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(run, build, "Debug", "hold", "tree-one", keep=True)
            deadline = time.monotonic() + 15
            while not (build / "child-active").exists():
                assert time.monotonic() < deadline, "fixture did not start"
                time.sleep(0.02)
            second = pool.submit(run, other, "Debug", "pass", "tree-two", keep=True, LOCK_TIMEOUT=1)
            assert first.result()[0] != second.result()[0]

        # Keep the hard-abort boundary's exact numeric result, including signals.
        abort_runner = source / "unittests/run_tunnels_abort_runtime_test.cmake"
        for mode, expected in (("exit1", 0), ("signal", 1), ("pass", 1)):
            values = dict(TARGET="runner_fixture", EXECUTABLE=executable(build, "Release"),
                          BUILD_DIR=build, CONFIG="Release", CASES=mode,
                          NAME="waterwall.abort_fixture", SOURCE_DIR=source, FIXTURE_DIR=source)
            output = command([args.cmake, *(f"-DABORT_TEST_{k}={v}" for k, v in values.items()),
                              "-P", str(abort_runner)], expected)
            assert artifact(output).exists() == bool(expected), output

    except BaseException:
        print(f"Retained regression artifacts: {root}", flush=True)
        raise
    else:
        run_directory.finish(0)
        print("Native runner regression checks passed (Debug and Release)")


if __name__ == "__main__":
    main()
