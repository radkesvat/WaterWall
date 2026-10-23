#!/usr/bin/env python3
"""Provision the pinned V2Ray VMess interoperability peer before isolated tests.

Run explicitly, or build waterwall_vmess_reference. Network access is confined to
this setup command; vmess_interop.py only uses the resulting local executable.
The hashes are the v5.53.0 release's SHA2-256 archive digests. This helper supports
the native Linux x86_64 and aarch64 functional-test hosts.
"""

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import platform
import tempfile
import urllib.request
import zipfile


VERSION = "5.53.0"
ARCHIVES = {
    "x86_64": ("v2ray-linux-64.zip", "6bbb8aee65a57d0b12599b4b7c842b3ad0daca4436e661d94015c447cb31b4fa"),
    "aarch64": ("v2ray-linux-arm64-v8a.zip", "2bda03a3d6b93122cb418504dc1c9ada10f99ae6be58a1fcc4a5ca1a01e12a30"),
}


def provision(cache):
    if platform.system() != "Linux" or platform.machine() not in ARCHIVES:
        raise RuntimeError("V2Ray reference provisioning supports native Linux x86_64/aarch64 only")
    name, expected = ARCHIVES[platform.machine()]
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / ".provision.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        archive = cache / name
        if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            url = f"https://github.com/v2fly/v2ray-core/releases/download/v{VERSION}/{name}"
            print(f"Downloading V2Ray {VERSION}: {url}", flush=True)
            with urllib.request.urlopen(url, timeout=45) as response:
                data = response.read(32 * 1024 * 1024 + 1)
            if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError("V2Ray archive SHA-256 mismatch or archive exceeds 32 MiB")
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as output:
                temporary = Path(output.name)
                output.write(data)
            temporary.replace(archive)
        with zipfile.ZipFile(archive) as source:
            # Extract only the named executable; archive paths are never trusted.
            executable = source.read("v2ray")
        destination = cache / "v2ray"
        if not destination.exists() or destination.read_bytes() != executable:
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as output:
                temporary = Path(output.name)
                output.write(executable)
            os.chmod(temporary, 0o755)
            temporary.replace(destination)
        else:
            os.chmod(destination, 0o755)
        print(destination.resolve(), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", required=True, type=Path)
    provision(parser.parse_args().cache_dir)
