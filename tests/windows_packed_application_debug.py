"""Replay one saved packed-application failure under native Windows GDB.

This is best-effort evidence collection, never a replacement for the failed test.
The original fixture is left intact; the debugger uses a separate copy.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostics-dir', required=True, type=Path)
    args = parser.parse_args()
    original = args.diagnostics_dir.resolve()
    record_path = original/'failure.json'
    if not record_path.exists():
        print('No failed application command was recorded; skipping debugger replay.')
        return

    record = json.loads(record_path.read_text(encoding='utf-8'))
    replay = original.parent/'packed-application-debugger'
    shutil.copytree(original, replay)
    commands = [
        'set pagination off', 'set confirm off', 'set breakpoint pending on',
        'show version', 'break abort', 'break _assert', 'break _wassert',
        'break _amsg_exit',
    ]
    run = 'run'
    if 'stdin' in record:
        # A redirection on `run` replaces the arguments supplied via --args.
        arguments = record['command'][1:]
        quoted = subprocess.list2cmdline(arguments) if os.name == 'nt' else shlex.join(arguments)
        run += f' {quoted} < "{(replay/record["stdin"]).as_posix()}"'
    commands += [run, 'thread apply all bt full', 'info registers',
                 'info sharedlibrary', 'info files', 'x/16i $pc', 'x/32x $sp', 'kill']
    command = ['gdb', '--batch', '--nx']
    for instruction in commands:
        command += ['-ex', instruction]
    command += ['--args', *record['command']]
    (replay/'debugger-command.json').write_text(json.dumps(command, indent=2), encoding='utf-8')
    # Use files rather than pipes, so partial debugger output survives timeout.
    with (replay/'gdb.log').open('wb') as output:
        process = subprocess.Popen(command, cwd=replay/record['cwd'],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            status = process.wait(timeout=90)
            outcome = f'GDB exit status: {status}. A successful replay does not clear the original failure.'
        except subprocess.TimeoutExpired:
            outcome = 'Debugger replay timed out after 90 seconds.'
            # Include descendants: a packed launcher starts its own application.
            try:
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                   stdout=output, stderr=subprocess.STDOUT, timeout=15, check=False)
            finally:
                process.kill()
                process.wait(timeout=15)
    (replay/'debugger-result.txt').write_text(outcome + '\n', encoding='utf-8')
    print(outcome)


if __name__ == '__main__':
    main()
