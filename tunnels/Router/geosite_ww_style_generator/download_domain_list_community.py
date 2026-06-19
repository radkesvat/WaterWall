#!/usr/bin/env python3

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile


REPO_URL = "https://github.com/v2fly/domain-list-community.git"
ZIP_URL = "https://github.com/v2fly/domain-list-community/archive/refs/heads/master.zip"
OUTPUT_DIR_NAME = "domain-list-community"


def log(message):
    print(message, flush=True)


def run_command(args):
    log("+ " + " ".join(args))
    subprocess.run(args, check=True)


def safe_remove_tree(path, expected_parent):
    if not path.exists():
        return

    resolved_parent = path.resolve().parent
    if resolved_parent != expected_parent.resolve():
        raise RuntimeError(f"refusing to remove unexpected path: {path}")

    if path.is_symlink() or not path.is_dir():
        path.unlink()
        return

    shutil.rmtree(path)


def clone_with_git(work_dir):
    if shutil.which("git") is None:
        raise RuntimeError("git is not available")

    clone_dir = work_dir / "repo"
    run_command([
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--branch",
        "master",
        REPO_URL,
        str(clone_dir),
    ])
    return clone_dir


def download_zip(work_dir):
    zip_path = work_dir / "domain-list-community.zip"
    extract_dir = work_dir / "zip"

    log(f"Downloading {ZIP_URL}")
    urllib.request.urlretrieve(ZIP_URL, zip_path)

    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(extract_dir)

    candidates = [path for path in extract_dir.iterdir() if path.is_dir()]
    if len(candidates) != 1:
        raise RuntimeError("unexpected GitHub zip layout")

    return candidates[0]


def fetch_repo(work_dir):
    try:
        return clone_with_git(work_dir)
    except Exception as exc:
        log(f"git clone failed, falling back to zip download: {exc}")
        return download_zip(work_dir)


def replace_output(script_dir, repo_dir):
    source_data = repo_dir / "data"
    if not source_data.is_dir():
        raise RuntimeError("downloaded domain-list-community repository has no data directory")

    output_dir = script_dir / OUTPUT_DIR_NAME
    safe_remove_tree(output_dir, script_dir)
    output_dir.mkdir(parents=True)
    shutil.copytree(source_data, output_dir / "data")

    log(f"Prepared {output_dir} with only the data directory")


def main():
    script_dir = Path(__file__).resolve().parent

    with tempfile.TemporaryDirectory(prefix="domain-list-community-", dir=script_dir) as temp_name:
        work_dir = Path(temp_name)
        repo_dir = fetch_repo(work_dir)
        replace_output(script_dir, repo_dir)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
