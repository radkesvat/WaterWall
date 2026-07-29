#!/usr/bin/env bash

# Shared run-directory helper for the Waterwall case runners.
# This file is meant to be sourced, not executed.
#
# Purpose:
# - treat tests/cases/<name> as read-only input and run each test in its own
#   private directory outside the repository
# - keep generated artifacts (core.json, stdout.log, log/) out of the source tree
# - let tests that share a case directory run concurrently without fighting over
#   the same generated files
#
# The run directory mirrors the layout of the real tests tree:
#
#   <run-root>/tests/<group>/<case>   <- writable copy of the case under test
#   <run-root>/tests/<group>/<other>  -> symlink to the real sibling case
#   <run-root>/tests/<file>           -> symlink to the real tests/ entry
#
# Mirroring rather than flattening keeps every upward reference working: config
# entries such as "../tls_roundtrip/server.crt" and probe scripts that load a
# shared module through Path(__file__).resolve().parents[2] both still resolve.
#
# Usage:
#   source "$(dirname "$0")/case_run_dir.lib.sh"
#   prepare_case_run_dir "$case_dir"
#   run_dir=$case_run_dir
#   # call remove_case_run_dir from the runner's EXIT trap, after any log dump
#
# prepare_case_run_dir publishes its result through case_run_dir rather than
# stdout on purpose: command substitution would run it in a subshell and the
# run root needed for cleanup would never reach the caller.
#
# Set WATERWALL_TEST_KEEP_RUN_DIR=1 to keep the run directory for inspection.

case_run_root=""
case_run_dir=""

prepare_case_run_dir() {
  local case_dir
  local case_name
  local group_dir
  local group_name
  local tests_dir
  local run_tests_dir
  local run_group_dir
  local run_dir
  local entry
  local entry_name

  case_dir=$(realpath "$1")
  case_name=$(basename "$case_dir")
  group_dir=$(dirname "$case_dir")
  group_name=$(basename "$group_dir")
  tests_dir=$(dirname "$group_dir")

  case_run_root=$(mktemp -d "${TMPDIR:-/tmp}/waterwall-case-XXXXXX")
  run_tests_dir="$case_run_root/$(basename "$tests_dir")"
  run_group_dir="$run_tests_dir/$group_name"
  run_dir="$run_group_dir/$case_name"
  mkdir -p "$run_group_dir"

  # Everything except the case under test is linked, not copied: the tests tree
  # is read-only input and linking keeps this cheap enough to do per test.
  for entry in "$tests_dir"/*; do
    entry_name=$(basename "$entry")
    if [[ "$entry_name" != "$group_name" ]]; then
      ln -s "$entry" "$run_tests_dir/$entry_name"
    fi
  done

  for entry in "$group_dir"/*; do
    entry_name=$(basename "$entry")
    if [[ "$entry_name" != "$case_name" ]]; then
      ln -s "$entry" "$run_group_dir/$entry_name"
    fi
  done

  cp -R "$case_dir" "$run_dir"

  # A dirty source tree must not leak into the run: drop anything an older
  # in-place run may have left behind so log greps only see this run's output.
  rm -rf "$run_dir/core.json" "$run_dir/stdout.log" "$run_dir/log"

  case_run_dir=$run_dir
}

remove_case_run_dir() {
  if [[ -z "$case_run_root" ]]; then
    return 0
  fi

  case "${WATERWALL_TEST_KEEP_RUN_DIR:-}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On)
      echo "Keeping run directory: $case_run_root" >&2
      ;;
    *)
      rm -rf "$case_run_root"
      ;;
  esac

  case_run_root=""
}
