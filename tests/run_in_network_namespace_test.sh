#!/usr/bin/env bash

# Harness test for run_in_network_namespace.sh

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <wrapper-script> <python3>" >&2
  exit 2
fi

wrapper_script=$(realpath "$1")
python_bin=$(realpath "$2")

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Skipping network namespace test on non-Linux platform."
  exit 77
fi

# 1. Reject empty command with exit status 2
set +e
"$wrapper_script" >/dev/null 2>&1
status=$?
set -e
if [[ $status -ne 2 ]]; then
  echo "FAIL: Expected exit status 2 on empty invocation, got $status" >&2
  exit 1
fi

# 2. Child exit status is returned unchanged
for test_exit in 0 7 42 123; do
  set +e
  "$wrapper_script" bash -c "exit $test_exit"
  status=$?
  set -e
  if [[ $status -ne $test_exit ]]; then
    echo "FAIL: Expected exit status $test_exit, got $status" >&2
    exit 1
  fi
done

# 3. Root callers retain their user namespace so runner-owned workspace paths
# remain accessible from the isolated network namespace.
if ((EUID == 0)); then
  parent_user_namespace=$(readlink /proc/self/ns/user)
  child_user_namespace=$("$wrapper_script" "$python_bin" -c '
import os
print(os.readlink("/proc/self/ns/user"))
')

  if [[ "$child_user_namespace" != "$parent_user_namespace" ]]; then
    echo "FAIL: Root caller unexpectedly entered a nested user namespace" >&2
    exit 1
  fi
fi

# 4. Arguments containing spaces remain separate and intact
out=$("$wrapper_script" "$python_bin" -c '
import sys
assert len(sys.argv) == 4, f"expected 4 argv items, got {len(sys.argv)}: {sys.argv}"
assert sys.argv[1] == "first argument with spaces", sys.argv[1]
assert sys.argv[2] == "second   argument", sys.argv[2]
assert sys.argv[3] == "third\nwith\nnewlines", sys.argv[3]
print("args_ok")
' "first argument with spaces" "second   argument" $'third\nwith\nnewlines')

if [[ "$out" != "args_ok" ]]; then
  echo "FAIL: Argument handling failed: $out" >&2
  exit 1
fi

# 5. Loopback is usable and both IPv4 and IPv6 sockets can bind
"$wrapper_script" "$python_bin" -c '
import socket
# IPv4 TCP bind & connect
s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s4.bind(("127.0.0.1", 0))
port4 = s4.getsockname()[1]
s4.listen(1)
c4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c4.connect(("127.0.0.1", port4))
conn4, _ = s4.accept()
c4.sendall(b"ping4")
assert conn4.recv(5) == b"ping4"
c4.close()
conn4.close()
s4.close()

# IPv6 TCP bind & connect (if IPv6 supported in kernel)
try:
    s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s6.bind(("::1", 0))
    port6 = s6.getsockname()[1]
    s6.listen(1)
    c6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    c6.connect(("::1", port6))
    conn6, _ = s6.accept()
    c6.sendall(b"ping6")
    assert conn6.recv(5) == b"ping6"
    c6.close()
    conn6.close()
    s6.close()
except OSError:
    pass # IPv6 disabled in container/kernel is tolerated
'

# 6. Two concurrent wrappers can bind the same fixed port without collision
test_port=47891
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

ready1="$tmp_dir/ready1"
ready2="$tmp_dir/ready2"
done1="$tmp_dir/done1"
done2="$tmp_dir/done2"

"$wrapper_script" "$python_bin" -c "
import socket, time, os, pathlib
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
s.bind(('127.0.0.1', $test_port))
s.listen(1)
pathlib.Path('$ready1').touch()
for _ in range(50):
    if os.path.exists('$ready2'):
        break
    time.sleep(0.05)
assert os.path.exists('$ready2'), 'peer wrapper did not become ready'
time.sleep(0.2)
s.close()
pathlib.Path('$done1').touch()
" &
pid1=$!

"$wrapper_script" "$python_bin" -c "
import socket, time, os, pathlib
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
s.bind(('127.0.0.1', $test_port))
s.listen(1)
pathlib.Path('$ready2').touch()
for _ in range(50):
    if os.path.exists('$ready1'):
        break
    time.sleep(0.05)
assert os.path.exists('$ready1'), 'peer wrapper did not become ready'
time.sleep(0.2)
s.close()
pathlib.Path('$done2').touch()
" &
pid2=$!

wait "$pid1"
wait "$pid2"

if [[ ! -f "$done1" || ! -f "$done2" ]]; then
  echo "FAIL: Concurrent fixed-port bind in separate namespaces failed" >&2
  exit 1
fi

echo "run_in_network_namespace tests passed."
