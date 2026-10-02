#!/usr/bin/env bash
# Shared mechanics only. Callers keep traps, enclosing statuses, readiness,
# deadlines and roundtrip/probe/packet/speed/expected-failure verdicts explicit.
# Log path arguments are expanded by the caller, preserving selection/order.
ww_test_dump_logs() {
  local path
  for path in "$@"; do
    if [[ -f "$path" ]]; then
      echo "===== $(basename "$path") =====" >&2
      cat "$path" >&2
    fi
  done
}

ww_test_show_stdout_on_success() {
  case "${WATERWALL_TEST_SHOW_STDOUT_ON_SUCCESS:-}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
    *) return 1 ;;
  esac
}

ww_test_finish_directory() {
  local directory=$1
  local status=$2
  if [[ "$status" -eq 0 && "${WATERWALL_TEST_KEEP_RUN_DIR:-}" != 1 ]]; then
    rm -rf -- "$directory"
  else
    echo "Retained artifacts (status=$status): $directory" >&2
  fi
}

# Explicit PID ownership, TERM grace, KILL fallback and reap. Return the child's
# actual status so a caller can retain its own exact-exit policy. Cleanup traps
# use || true to preserve an existing body verdict. No trap is installed here.
ww_test_stop_child() {
  local child_pid=$1
  local checks=${2:-100}
  local interval=${3:-0.05}
  local i
  if kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "$child_pid" 2>/dev/null || true
    for ((i = 0; i < checks; i++)); do
      if ! kill -0 "$child_pid" 2>/dev/null; then break; fi
      sleep "$interval"
    done
    if kill -0 "$child_pid" 2>/dev/null; then
      kill -KILL "$child_pid" 2>/dev/null || true
    fi
  fi
  wait "$child_pid" 2>/dev/null
}

# Caller validates numeric workers and splice. Packet tests pass omit to keep
# that setting absent. Generated values match the existing client-RAM templates.
ww_test_write_core() {
  local ww_core_path=$1 ww_core_workers=$2 ww_core_profile=$3 ww_core_console=$4
  local ww_core_splice_line=""
  if [[ "$5" != omit ]]; then ww_core_splice_line="    \"splice\": $5,"; fi
cat >"$ww_core_path" <<EOF
{
  "log": {
    "path": "log/",
    "internal": { "loglevel": "DEBUG", "file": "internal.log", "console": ${ww_core_console} },
    "core":     { "loglevel": "DEBUG", "file": "core.log",     "console": ${ww_core_console} },
    "network":  { "loglevel": "DEBUG", "file": "network.log",  "console": ${ww_core_console} },
    "dns":      { "loglevel": "DEBUG", "file": "dns.log",      "console": ${ww_core_console} }
  },
  "configs": [
    "config.json"
  ],
  "misc": {
    "workers": ${ww_core_workers},
${ww_core_splice_line}
    "ram-profile": "${ww_core_profile}",
    "mtu": 1500,
    "try-enabling-bbr": false
  }
}
EOF
}
