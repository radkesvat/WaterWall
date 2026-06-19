#!/usr/bin/env python3

from pathlib import Path
import shutil

import download_domain_list_community
import generate


SCRIPT_DIR = Path(__file__).resolve().parent
ROUTER_DIR = SCRIPT_DIR.parent

DOWNLOADED_REPO_DIR = SCRIPT_DIR / download_domain_list_community.OUTPUT_DIR_NAME
FINAL_JSON = SCRIPT_DIR / "geosite_generated.json"
OLD_GENERATED_C = SCRIPT_DIR / "geosite_generated.c"
OLD_COMMON_C = ROUTER_DIR / "common" / "geosite_generated.c"


def remove_path(path: Path, expected_parent: Path) -> None:
    if not path.exists():
        return

    if path.resolve().parent != expected_parent.resolve():
        raise RuntimeError(f"refusing to remove unexpected path: {path}")

    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def cleanup_old_outputs() -> None:
    remove_path(DOWNLOADED_REPO_DIR, SCRIPT_DIR)
    remove_path(FINAL_JSON, SCRIPT_DIR)
    remove_path(OLD_GENERATED_C, SCRIPT_DIR)
    remove_path(OLD_COMMON_C, ROUTER_DIR / "common")

    for path in SCRIPT_DIR.iterdir():
        if path.name.startswith("domain-list-community-"):
            remove_path(path, SCRIPT_DIR)


def generate_final_json() -> None:
    generate.main()


def main() -> None:
    cleanup_old_outputs()
    download_domain_list_community.main()
    try:
        generate_final_json()
    finally:
        remove_path(DOWNLOADED_REPO_DIR, SCRIPT_DIR)
    print(f"Done: {FINAL_JSON}")


if __name__ == "__main__":
    main()
