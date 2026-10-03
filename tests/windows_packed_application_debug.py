"""Capture native application failures with GDB, on first execution or replay.

First execution retains its own fixture; failure-only replays use a separate copy.
Diagnostics never replace the ordinary and packed direct-execution checks.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess


def run_with_gdb(command, *, cwd, timeout, env=None, debugger='gdb', stdin_path=None):
    """Record fatal callers and return the inferior's status, never GDB's default zero."""
    cwd = Path(cwd).resolve()
    dump = ['thread apply all bt full', 'info registers', 'info sharedlibrary',
            'info files', 'x/16i $pc', 'x/32x $sp']
    commands = ['set pagination off', 'set confirm off', 'set breakpoint pending on',
                'show version']
    for symbol in ['abort', '_assert', '_wassert']:
        commands += [f'break {symbol}', 'commands', 'silent',
                     f'printf "Waterwall fatal breakpoint: {symbol}\\n"',
                     *dump, 'continue', 'end']
    commands += ['catch signal SIGABRT SIGSEGV SIGILL SIGFPE', 'commands', 'silent',
                 'printf "Waterwall signal stop\\n"', 'info program',
                 *dump, 'continue', 'end']
    # _amsg_exit also names a KernelBase file-opening stub on current Windows.
    # Breaking there stops healthy startup before the actual failure.
    run = 'run'
    if stdin_path is not None:
        # A redirection on `run` replaces --args arguments; retain them explicitly.
        arguments = (subprocess.list2cmdline(command[1:]) if os.name == 'nt'
                     else shlex.join(command[1:]))
        run += f' {arguments} < "{Path(stdin_path).resolve().as_posix()}"'
    commands += [run, 'if $_isvoid($_exitcode) && $_isvoid($_exitsignal)',
                 *dump, 'quit 1', 'end']
    script = cwd/'gdb-command.gdb'
    script.write_text('\n'.join(commands) + '\n', encoding='utf-8')
    invocation = [debugger, '--batch', '--nx', '--return-child-result',
                  '--command', str(script), '--args', *command]
    (cwd/'debugger-command.json').write_text(json.dumps(invocation, indent=2), encoding='utf-8')
    log = cwd/'gdb.log'
    with log.open('wb') as output:
        process = subprocess.Popen(invocation, cwd=cwd, env=env,
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Include descendants: a packed launcher starts its own application.
            try:
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                   stdout=output, stderr=subprocess.STDOUT, timeout=15, check=False)
            finally:
                process.kill()
                process.wait(timeout=15)
            raise subprocess.TimeoutExpired(command, timeout, output=log.read_bytes())
    return subprocess.CompletedProcess(command, status, log.read_bytes(), b'')


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
    if record.get('debugger'):
        print(f'First execution already captured under GDB: {original/record["debugger_log"]}')
        return
    replay = original.parent/'packed-application-debugger'
    shutil.copytree(original, replay)
    try:
        result = run_with_gdb(record['command'], cwd=replay/record['cwd'], timeout=90,
                              stdin_path=replay/record['stdin'] if 'stdin' in record else None)
        outcome = (f'Debugged application exit status: {result.returncode}. '
                   'A successful replay does not clear the original failure.')
    except subprocess.TimeoutExpired:
        outcome = 'Debugger replay timed out after 90 seconds.'
    (replay/'debugger-result.txt').write_text(outcome + '\n', encoding='utf-8')
    print(outcome)


if __name__ == '__main__':
    main()
