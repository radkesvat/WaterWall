#!/usr/bin/env python3
"""Provision pinned official VMess interoperability peers before isolated tests.

Run explicitly, or build waterwall_vmess_reference. Network access is confined to
this setup command; vmess_interop.py only uses the resulting local executable.
The hashes are pinned official release archive SHA-256 digests. This helper supports
the native Linux x86_64 and aarch64 functional-test hosts.
"""

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import platform
import tempfile
import tarfile
import urllib.request
import zipfile


REFERENCES = {
    "v2ray": {
        "version": "5.53.0", "repository": "v2fly/v2ray-core", "executable": "v2ray",
        "archives": {
            "x86_64": ("v2ray-linux-64.zip", "6bbb8aee65a57d0b12599b4b7c842b3ad0daca4436e661d94015c447cb31b4fa"),
            "aarch64": ("v2ray-linux-arm64-v8a.zip", "2bda03a3d6b93122cb418504dc1c9ada10f99ae6be58a1fcc4a5ca1a01e12a30"),
        },
    },
    # The release API's SHA-256 digests are pinned here, never queried at test time.
    # https://github.com/XTLS/Xray-core/releases/tag/v25.6.8
    "xray": {
        "version": "25.6.8", "repository": "XTLS/Xray-core", "executable": "xray",
        "archives": {
            "x86_64": ("Xray-linux-64.zip", "51bcd3304fdbd64b58048b056da005fbaa6c83577fc351cae34024760e111e4b"),
            "aarch64": ("Xray-linux-arm64-v8a.zip", "ca404752f27176cdaaddf929ec65a96cf18cceba403d6d97a66cdac48ef84dfe"),
        },
    },
    # https://github.com/SagerNet/sing-box/releases/tag/v1.12.0
    "sing-box": {
        "version": "1.12.0", "repository": "SagerNet/sing-box", "executable": "sing-box",
        "archives": {
            "x86_64": ("sing-box-1.12.0-linux-amd64.tar.gz", "f59b1253ae0143997cb46915af30d14a33431dcbd7e39edacfcde8d73050faaf"),
            "aarch64": ("sing-box-1.12.0-linux-arm64.tar.gz", "90e8b40320971db689b789ab95f54e9762bc24250f29ba59012049ab7867f456"),
        },
    },
}


def provision(cache, peer="v2ray"):
    reference = REFERENCES[peer]
    archives = reference["archives"]
    if platform.system() != "Linux" or platform.machine() not in archives:
        raise RuntimeError("VMess reference provisioning supports native Linux x86_64/aarch64 only")
    name, expected = archives[platform.machine()]
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / ".provision.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        archive = cache / name
        if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            url = f"https://github.com/{reference['repository']}/releases/download/v{reference['version']}/{name}"
            print(f"Downloading {peer} {reference['version']}: {url}", flush=True)
            with urllib.request.urlopen(url, timeout=45) as response:
                data = response.read(64 * 1024 * 1024 + 1)
            if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError("VMess archive SHA-256 mismatch or archive exceeds 64 MiB")
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as output:
                temporary = Path(output.name)
                output.write(data)
            temporary.replace(archive)
        # Read only the exact named executable; never extract untrusted paths.
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive) as source:
                executable = source.read(reference["executable"])
        else:
            member = name.removesuffix(".tar.gz") + "/" + reference["executable"]
            with tarfile.open(archive, "r:gz") as source:
                info = source.getmember(member)
                if not info.isfile() or info.size > 128 * 1024 * 1024:
                    raise RuntimeError("VMess executable archive member is not a bounded regular file")
                executable = source.extractfile(info).read()
        destination = cache / reference["executable"]
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
    parser.add_argument("--peer", choices=REFERENCES, default="v2ray")
    args = parser.parse_args()
    provision(args.cache_dir, args.peer)
