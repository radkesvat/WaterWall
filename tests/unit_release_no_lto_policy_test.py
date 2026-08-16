#!/usr/bin/env python3
"""Practical regression check for WaterWall's Release/no-LTO unit lane.

This intentionally checks the configured build, not an adversarial build
environment. CMake cache values are the policy source of truth; generated Ninja
commands and representative linked archives catch accidental regressions.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys


class PolicyError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PolicyError(message)


def read_cache(build_dir: Path) -> dict[str, str]:
    cache_path = build_dir / "CMakeCache.txt"
    if not cache_path.is_file():
        fail(f"missing CMake cache: {cache_path}")
    values: dict[str, str] = {}
    for line in cache_path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line:
            continue
        key_and_type, value = line.split("=", 1)
        key = key_and_type.split(":", 1)[0]
        values[key] = value
    return values


def cmake_bool(value: str | None, name: str) -> bool:
    if value is None:
        fail(f"CMake cache is missing {name}")
    normalized = value.upper()
    if normalized in {"1", "ON", "TRUE", "YES", "Y"}:
        return True
    if normalized in {"0", "OFF", "FALSE", "NO", "N", "", "NOTFOUND"}:
        return False
    fail(f"invalid CMake boolean for {name}: {value}")


def ninja_commands(build_dir: Path, configuration: str, target: str, cache: dict[str, str]) -> str:
    ninja = cache.get("CMAKE_MAKE_PROGRAM") or shutil.which("ninja")
    if not ninja:
        fail("configured Ninja executable is unavailable")
    build_file = build_dir / f"build-{configuration}.ninja"
    if not build_file.is_file():
        build_file = build_dir / "build.ninja"
    if not build_file.is_file():
        fail(f"no Ninja graph found in {build_dir}")
    result = subprocess.run(
        [ninja, "-C", str(build_dir), "-f", build_file.name, "-t", "commands", target],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        fail(f"cannot query commands for {target}: {result.stderr.strip()}")
    if not result.stdout.strip():
        fail(f"Ninja returned no commands for {target}")
    return result.stdout


POSITIVE_LTO = re.compile(
    r"(?<![A-Za-z0-9_-])-flto(?:=[^\s\"']+)?(?=$|[\s\"'])|"
    r"(?<![A-Za-z0-9_-])-fuse-linker-plugin(?=$|[\s\"'])|"
    r"(?i:(?<![A-Za-z0-9_])/GL(?![-A-Za-z0-9_])|"
    r"(?<![A-Za-z0-9_])/LTCG(?!:OFF)(?=$|[\s\"']))"
)


def response_file_text(commands: str, build_dir: Path) -> str:
    expanded: list[str] = []
    for match in re.finditer(r"@(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))", commands):
        spelling = next(value for value in match.groups() if value is not None)
        path = Path(spelling)
        if not path.is_absolute():
            path = build_dir / path
        if path.is_file() and path.stat().st_size <= 4 * 1024 * 1024:
            expanded.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(expanded)


def check_no_positive_lto(commands: str, build_dir: Path) -> None:
    combined = commands + "\n" + response_file_text(commands, build_dir)
    match = POSITIVE_LTO.search(combined)
    if match:
        line = combined.count("\n", 0, match.start()) + 1
        fail(f"positive LTO option found in reachable command/response data at line {line}: {match.group(0)}")


def check_release_shape(commands: str) -> None:
    has_optimization = bool(re.search(r"(?:^|\s)(?:-O(?:[1-3sgz]|fast)|/O[12x])(?:\s|$)", commands))
    has_ndebug = bool(re.search(r"(?:^|\s)(?:-D|/D)NDEBUG(?:=\S+)?(?:\s|$)", commands))
    if not has_optimization:
        fail("reachable unit commands do not show Release optimization")
    if not has_ndebug:
        fail("reachable unit commands do not define NDEBUG")


def read_manifest(path: Path) -> dict[str, Path]:
    if not path.is_file():
        fail(f"missing representative artifact manifest: {path}")
    artifacts: dict[str, Path] = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1]:
            fail(f"malformed artifact manifest row: {line!r}")
        artifact = Path(fields[1])
        if not artifact.is_file():
            fail(f"representative artifact is missing: {artifact}")
        artifacts[fields[0]] = artifact
    if not artifacts:
        fail("representative artifact manifest is empty")
    return artifacts


IR_SECTION = re.compile(r"\.gnu\.lto_|\.llvmbc|\.llvmcmd|__LLVM")


def artifact_contains_ir(path: Path) -> bool | None:
    readelf = shutil.which("readelf")
    if readelf and path.suffix in {".a", ".o", ".so"}:
        result = subprocess.run(
            [readelf, "-SW", str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return bool(IR_SECTION.search(result.stdout))
    return None


def check_unit_artifacts(artifacts: dict[str, Path]) -> None:
    inspected = 0
    for name, artifact in artifacts.items():
        contains_ir = artifact_contains_ir(artifact)
        if contains_ir is None:
            continue
        inspected += 1
        if contains_ir:
            fail(f"representative unit artifact contains compiler IR: {name}: {artifact}")
    if sys.platform.startswith("linux") and inspected == 0:
        fail("no representative unit artifact could be inspected with readelf")


def check_production_artifacts(artifacts: dict[str, Path]) -> None:
    observations = [artifact_contains_ir(path) for path in artifacts.values()]
    available = [value for value in observations if value is not None]
    if sys.platform.startswith("linux") and not available:
        fail("no representative production artifact could be inspected with readelf")
    if available and not any(available):
        fail("representative production artifacts contain no compiler IR")


def default_manifest(build_dir: Path, configuration: str, production: bool) -> Path:
    name = "production_lto_contract" if production else "unit_lto_contract"
    under_tests = build_dir / "tests" / f"{name}-{configuration}.tsv"
    if under_tests.is_file():
        return under_tests
    return build_dir / f"{name}-{configuration}.tsv"


def check_unit(build_dir: Path, configuration: str, target: str, manifest: Path) -> None:
    cache = read_cache(build_dir)
    expected = {
        "BUILD_TESTING": True,
        "WW_BUILD_UNIT_TESTS": True,
        "WW_ENABLE_IPO": False,
    }
    for name, value in expected.items():
        if cmake_bool(cache.get(name), name) is not value:
            fail(f"unit cache requires {name}={'ON' if value else 'OFF'}")
    commands = ninja_commands(build_dir, configuration, target, cache)
    check_no_positive_lto(commands, build_dir)
    check_release_shape(commands)
    artifacts = read_manifest(manifest)
    check_unit_artifacts(artifacts)
    print(f"Release/no-LTO unit policy passed: {len(artifacts)} representative artifacts")


def check_production(build_dir: Path, configuration: str, target: str, manifest: Path) -> None:
    cache = read_cache(build_dir)
    if not cmake_bool(cache.get("WW_ENABLE_IPO"), "WW_ENABLE_IPO"):
        fail("production cache requires WW_ENABLE_IPO=ON")
    commands = ninja_commands(build_dir, configuration, target, cache)
    combined = commands + "\n" + response_file_text(commands, build_dir)
    if not POSITIVE_LTO.search(combined):
        fail("production commands contain no positive LTO option")
    artifacts = read_manifest(manifest)
    check_production_artifacts(artifacts)
    print(f"production IPO control passed: {len(artifacts)} representative artifacts")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    lane = parser.add_mutually_exclusive_group(required=True)
    lane.add_argument("--unit-build", type=Path)
    lane.add_argument("--production-build", type=Path)
    parser.add_argument("--configuration", default="Release")
    parser.add_argument("--target")
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.unit_build is not None:
            build_dir = arguments.unit_build.resolve()
            manifest = arguments.manifest or default_manifest(build_dir, arguments.configuration, False)
            check_unit(build_dir, arguments.configuration, arguments.target or "waterwall_unit_tests", manifest)
        else:
            build_dir = arguments.production_build.resolve()
            manifest = arguments.manifest or default_manifest(build_dir, arguments.configuration, True)
            check_production(build_dir, arguments.configuration, arguments.target or "Waterwall", manifest)
    except (OSError, subprocess.SubprocessError, PolicyError) as error:
        print(f"unit-release no-LTO policy failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
