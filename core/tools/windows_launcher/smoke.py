"""Run the real launcher backend against a native-loader fixture, without a shell."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--launcher', required=True)
parser.add_argument('--application', required=True)
parser.add_argument('--wine')
args = parser.parse_args()
env = os.environ.copy()
env['WINEDEBUG'] = '-all'
prefix = [args.wine] if args.wine else []

with tempfile.TemporaryDirectory(prefix='Waterwall fixture spaces ') as temporary:
    root = Path(temporary)
    folder = 'deployment with spaces'
    if args.wine:
        folder = 'déployment with spaces'
    elif os.name == 'nt':
        try:
            'é'.encode('mbcs', errors='strict')
            folder = 'déployment with spaces'
        except UnicodeError:
            pass
    deployment = root / folder
    deployment.mkdir()
    for source in Path(args.launcher).parent.glob('*.dll'):
        shutil.copyfile(source, deployment / source.name)
    launcher = deployment / 'Waterwall.exe'
    application = deployment / 'ordinary.exe'
    shutil.copyfile(args.launcher, launcher)
    shutil.copyfile(args.application, application)
    unrelated = root / 'unrelated'
    unrelated.mkdir()
    extraction = root / 'extraction'
    extraction.mkdir()
    def windows_path(path):
        # MSYS2 Python renders native paths with '/', unlike GetModuleFileNameW.
        native = str(path).replace('/', '\\')
        return 'Z:' + native if args.wine else native
    env['TEMP'] = env['TMP'] = windows_path(extraction)
    env['WW_FIXTURE_ORIGINAL'] = windows_path(launcher)

    def run_with_full_stderr(command, data, run_env):
        # Linux Wine can inherit a pipe filled to its exact kernel capacity.
        # The child must observe stop and retirement before we make room for a diagnostic.
        import fcntl
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, 'rb', buffering=0) as reader, os.fdopen(write_fd, 'wb', buffering=0) as writer:
            capacity = fcntl.fcntl(write_fd, fcntl.F_GETPIPE_SZ)
            assert writer.write(b'x' * capacity) == capacity
            with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=writer,
                                  cwd=unrelated, env=run_env) as proc:
                proc.stdin.write(data)
                proc.stdin.close()
                proc.stdin = None
                try:
                    settled = {'retired', 'unlock'}
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline and proc.poll() is None:
                        if trace.exists() and settled.issubset(trace.read_text().splitlines()):
                            break
                        time.sleep(0.025)
                    assert trace.exists() and settled.issubset(trace.read_text().splitlines()), 'stderr blocked cleanup'
                finally:
                    reader.read(capacity)
                    out, _ = proc.communicate(timeout=15)
                return subprocess.CompletedProcess(command, proc.returncode, out, b'')

    def run(binary, arguments, data=b'{}', extra=None, blocked_stderr=False):
        run_env = env.copy()
        run_env.pop('WW_CORE_JSON_INPUT', None)
        run_env.update(extra or {})
        report = root / ('image-' + uuid.uuid4().hex)
        if binary == launcher:
            run_env['WW_FIXTURE_IMAGE_REPORT'] = windows_path(report)
        command = prefix + [str(binary)] + arguments
        if blocked_stderr and args.wine and sys.platform == 'linux':
            result = run_with_full_stderr(command, data, run_env)
        else:
            result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    cwd=unrelated, env=run_env, timeout=15)
        if binary == launcher and b'snapshot:' in result.stdout:
            assert report.exists(), 'child image path report missing'
            image = report.read_bytes().decode('utf-16-le')
            report.unlink()
            if args.wine:
                image = subprocess.check_output(['winepath', '-u', image], env=run_env, timeout=15).decode().strip()
            extracted = Path(image)
            assert not extracted.exists() and not extracted.parent.exists(), ('owned residue', image)
        return result.returncode, result.stdout.replace(b'\r\n', b'\n'), result.stderr.replace(b'\r\n', b'\n')

    for option in ('--version', '-v', 'version'):
        code, out, err = run(launcher, [option])
        assert code == 0 and b'Waterwall version' in out, (code, out, err)

    protected = b'{"configs":["first.json","second.json"],"windows-kill-switch":true}'
    # The launcher pins the extraction root and its ancestors against write sharing.
    # Keep simulated machine state in a sibling directory so owner publication can rename its file.
    switch_state = root / 'kill-switch'
    switch_state.mkdir()
    marker = switch_state / 'machine-lock'
    trace = switch_state / 'kill-switch-trace'
    transitions = switch_state / 'kill-switch-transitions'
    lease = switch_state / 'run.lock'
    switch_env = {
        'WW_FIXTURE_KILL_SWITCH_STATE': windows_path(marker),
        'WW_FIXTURE_KILL_SWITCH_LEASE': windows_path(lease),
        'WW_FIXTURE_KILL_SWITCH_TRACE': windows_path(trace),
        'WW_FIXTURE_KILL_SWITCH_TRANSITIONS': windows_path(transitions),
        'WW_FIXTURE_KILL_SWITCH_IMAGE': windows_path(switch_state / 'kill-switch-image'),
    }

    def check_switch_status(expected):
        code, out, err = run(launcher, ['--kill-switch-status'], extra=switch_env)
        assert code == 0 and out.strip() == expected, (code, out, err)

    def switch_start(expected, events, *, journal=None, blocked_stderr=False, **extra):
        trace.unlink(missing_ok=True)
        options = ['-c:stdin', '--restricted-config']
        if journal is not None:
            options.append('--session-file:' + windows_path(journal))
        result = run(launcher, options, protected, switch_env | extra, blocked_stderr=blocked_stderr)
        assert (result[0] == 0) == expected, result
        recorded = trace.read_text().splitlines() if trace.exists() else []
        assert recorded == events, (recorded, events, result)
        return result[0]

    def recovery_receipt(journal):
        code, out, err = run(launcher, ['--recover:' + windows_path(journal)], extra=switch_env)
        assert code == 0, (code, out, err)
        return json.loads(out)

    def unlock():
        code, out, err = run(launcher, ['--kill-switch-unlock'], extra=switch_env)
        assert code == 0 and out.strip() == b'unlocked', (code, out, err)

    def policy_events():
        return transitions.read_text().splitlines() if transitions.exists() else []

    def check_ordinary_launches():
        before = policy_events()
        for core in ({"configs": ["first.json"]}, {"configs": ["first.json"], "windows-kill-switch": False}):
            result = run(launcher, ['-c:stdin'], json.dumps(core).encode(), switch_env)
            assert result[0] == 0 and b'snapshot:' in result[1], result
        assert policy_events() == before, 'ordinary startup or exit accessed the filtering backend'

    @contextmanager
    def start_switch_process(name, *, journal=None, data=protected, **extra):
        options = ['--restricted-config', '-c:stdin']
        if journal is not None:
            options.append('--session-file:' + windows_path(journal))
        run_env = env | switch_env | {'WW_FIXTURE_KILL_SWITCH_RUN': name} | extra
        run_env.pop('WW_CORE_JSON_INPUT', None)
        proc = subprocess.Popen(prefix + [str(launcher)] + options,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=unrelated, env=run_env)
        try:
            proc.stdin.write(data)
            proc.stdin.close()
            proc.stdin = None
            yield proc
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=30)

    def await_file(path, proc):
        deadline = time.monotonic() + 10
        while not path.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.025)
        if not path.exists():
            logs = proc.communicate(timeout=3) if proc.poll() is not None else None
            raise AssertionError((path, proc.poll(), logs, policy_events()))

    def await_process(proc, expected, *, timeout=20):
        out, err = proc.communicate(timeout=timeout)
        if expected is not None:
            assert (proc.returncode == 0) == expected, (proc.returncode, out, err, policy_events())
        return proc.returncode & (255 if args.wine else 0xffffffff)

    check_switch_status(b'unlocked')
    before = policy_events()
    malformed = b'{"configs":["first.json"],"windows-kill-switch":{"config":"first.json"}}'
    missing_configs = b'{"windows-kill-switch":true}'
    invalid_core = b'{"configs":["first.json"],"misc":{"mtu":2},"windows-kill-switch":true}'
    assert run(launcher, ['-c:stdin'], malformed, switch_env)[0] != 0
    assert run(launcher, ['-c:stdin'], missing_configs, switch_env)[0] != 0
    assert run(launcher, ['-c:stdin'], invalid_core, switch_env)[0] != 0
    assert policy_events() == before
    check_ordinary_launches()
    switch_start(False, ['unlock'], WW_FIXTURE_KILL_SWITCH_FAIL='arm')
    check_switch_status(b'unlocked')
    switch_start(False, ['arm', 'unlock'], WW_FIXTURE_KILL_SWITCH_FAIL='arm-after-commit')
    check_switch_status(b'unlocked')
    switch_start(False, ['arm', 'close', 'unlock'], WW_FIXTURE_KILL_SWITCH_FAIL='image')
    check_switch_status(b'unlocked')
    switch_start(False, ['arm', 'image', 'close', 'unlock'], WW_FIXTURE_FAIL_BEFORE_RESUME='1')
    check_switch_status(b'unlocked')
    switch_start(False, ['arm', 'image', 'child', 'close', 'retired', 'unlock'], WW_FIXTURE_KILL_SWITCH_MODE='mismatch')
    switch_start(False, ['arm', 'image', 'child', 'close', 'unlock'], WW_FIXTURE_KILL_SWITCH_MODE='missing')
    switch_start(False, ['arm', 'image', 'child', 'close', 'retired', 'unlock'], WW_FIXTURE_KILL_SWITCH_FAIL='tun')
    switch_start(False, ['arm', 'image', 'child', 'grant-tun', 'register-ack', 'close', 'retired', 'unlock'],
                 WW_FIXTURE_KILL_SWITCH_MODE='duplicate')
    switch_start(False, ['arm', 'image', 'child', 'grant-tun', 'register-ack', 'close', 'retired', 'unlock'],
                 WW_FIXTURE_KILL_SWITCH_FAIL='revoke')
    check_switch_status(b'unlocked')
    health_session = root / 'health-failure-session'
    code = switch_start(False, ['arm', 'image', 'child', 'grant-tun', 'register-ack', 'close', 'retired', 'unlock'],
                        journal=health_session, blocked_stderr=True, WW_FIXTURE_KILL_SWITCH_FAIL='health',
                        WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(root / 'wait-for-policy-loss'))
    assert code == 1, code
    receipt = recovery_receipt(health_session)
    assert receipt['reason'] == 4 and receipt['runtime_status_known'] and receipt['runtime_status'] == 94, receipt
    stopped_session = root / 'stop-at-registration'
    switch_start(True, ['arm', 'image', 'child', 'close', 'retired', 'unlock'], journal=stopped_session,
                 WW_FIXTURE_STOP_AT_REGISTER='1')
    receipt = recovery_receipt(stopped_session)
    assert receipt['reason'] == 1 and receipt['runtime_status_known'] and receipt['runtime_status'] == 0, receipt
    delayed_session = root / 'delayed-startup-failure'
    code = switch_start(False, ['arm', 'image', 'child', 'close', 'retired', 'child-exiting', 'unlock'],
                        journal=delayed_session,
                        WW_FIXTURE_KILL_SWITCH_MODE='missing', WW_FIXTURE_DELAY_EXIT_AFTER_CLOSE='1',
                        WW_FIXTURE_EXIT='0x8000002a')
    assert code & 0xffffffff == (42 if args.wine else 0x8000002a), code
    receipt = recovery_receipt(delayed_session)
    assert receipt['reason'] == 3 and receipt['runtime_status_known'] and receipt['runtime_status'] == 0x8000002a, receipt
    crash = switch_start(False, ['arm', 'image', 'child', 'grant-tun', 'register-ack', 'close', 'unlock'],
                         WW_FIXTURE_KILL_SWITCH_MODE='crash')
    assert crash & 0xffffffff == (5 if args.wine else 0xc0000005), crash
    crash_journal = root / 'crash-after-poll-session'
    trace.unlink()
    code, out, err = run(launcher, ['-c:stdin', '--session-file:' + windows_path(crash_journal)], protected,
                         switch_env | {'WW_FIXTURE_KILL_SWITCH_HOLD': windows_path(root / 'wait-for-crash'),
                                       'WW_FIXTURE_KILL_SWITCH_FAIL': 'crash-after-poll'})
    assert code & 0xffffffff == (5 if args.wine else 0xc0000005), (code, out, err)
    assert trace.read_text().splitlines() == ['arm', 'image', 'child', 'grant-tun', 'register-ack', 'poll', 'close',
                                             'unlock']
    receipt = recovery_receipt(crash_journal)
    assert receipt['runtime_status_known'] and receipt['runtime_status'] == 0xc0000005, receipt
    check_switch_status(b'unlocked')
    complete_switch = ['arm', 'image', 'child', 'grant-tun', 'register-ack', 'revoke-tun', 'revoke-ack', 'close',
                       'unlock']
    switch_start(True, complete_switch)
    check_switch_status(b'unlocked')
    helper_journal = root / 'delayed-job-member'
    switch_start(True, complete_switch, journal=helper_journal,
                 WW_FIXTURE_SETTLEMENT_HELPER='1', WW_FIXTURE_ADAPTER_STATE='absent')
    receipt = recovery_receipt(helper_journal)
    assert receipt['termination'] == 'orderly' and receipt['cleanup'] == 'settled', receipt
    check_switch_status(b'unlocked')

    crash_extraction = root / 'crash-extraction'
    crash_extraction.mkdir()
    crash_env = {'TEMP': windows_path(crash_extraction), 'TMP': windows_path(crash_extraction)}

    # The runtime has exited, but the adapter inventory still prevents automatic unlock.
    # An unsettled adapter can exhaust the stop deadline and leave extraction residue.
    for state in ('pending', 'present'):
        with start_switch_process('adapter-' + state, WW_FIXTURE_ADAPTER_STATE=state, **crash_env) as owner:
            await_process(owner, False, timeout=25)
        check_switch_status(b'locked')
        unlock()
    failed_session = root / 'failed-protected-session'
    code, out, err = run(launcher, ['-c:stdin', '--session-file:' + windows_path(failed_session)], protected,
                         switch_env | {'WW_FIXTURE_EXIT': '7'})
    assert code == 7, (code, out, err)
    receipt = recovery_receipt(failed_session)
    assert receipt['reason'] == 4 and receipt['runtime_status'] == 7 and receipt['runtime_status_known'], receipt
    result = run(launcher, ['-c:stdin'], protected, switch_env | {'WW_FIXTURE_KILL_SWITCH_FAIL': 'unlock'})
    assert result[0] != 0 and b'cleanup failed' in result[2] and marker.exists(), result
    check_switch_status(b'locked')
    unlock()
    result = run(launcher, ['-c:stdin'], protected, switch_env | {'WW_FIXTURE_KILL_SWITCH_FAIL': 'foreign-at-cleanup'})
    assert result[0] != 0 and b'incomplete' in result[1] + result[2] and not marker.exists(), result
    foreign_filter = switch_env | {'WW_FIXTURE_KILL_SWITCH_FAIL': 'foreign-filter'}
    for option in ('--kill-switch-status', '--kill-switch-unlock', '--kill-switch-status'):
        code, out, err = run(launcher, [option], extra=foreign_filter)
        assert code == 1 and out.strip() == b'incomplete', (code, out, err)
    assert not marker.exists(), 'unlock left the known WaterWall rules installed'
    unlock()
    unlock()
    check_switch_status(b'unlocked')

    with start_switch_process('abrupt-A', WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(root / 'crash-ready'),
                              WW_FIXTURE_KILL_SWITCH_FAIL='crash-launcher-after-poll', **crash_env) as abrupt:
        assert await_process(abrupt, False) == (5 if args.wine else 0xc0000005)
    check_switch_status(b'locked')
    check_ordinary_launches()
    check_switch_status(b'locked')
    switch_start(True, complete_switch)
    check_switch_status(b'unlocked')

    # Keep an ordinary runtime alive while a protected owner without a public
    # journal is replaced. Pause B after it requests stop to expose the reserved
    # interval to another successor and manual unlock.
    ordinary_journal = root / 'ordinary-session'
    ordinary_ready = root / 'ordinary-ready'
    held_a = root / 'A-ready'
    held_b = root / 'B-ready'
    journal_b = root / 'B-session'
    paused, proceed = root / 'handoff-paused', root / 'handoff-continue'
    with start_switch_process('ordinary', journal=ordinary_journal, data=b'{}',
                              WW_FIXTURE_ORDINARY_HOLD=windows_path(ordinary_ready)) as ordinary:
        await_file(ordinary_ready, ordinary)
        first_event = len(policy_events())
        with start_switch_process('A', WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(held_a)) as owner:
            await_file(held_a, owner)
            check_switch_status(b'locked')
            check_ordinary_launches()
            before = policy_events()
            assert run(launcher, ['-c:stdin'], malformed, switch_env)[0] != 0
            assert run(launcher, ['-c:stdin'], missing_configs, switch_env)[0] != 0
            assert run(launcher, ['-c:stdin'], invalid_core, switch_env)[0] != 0
            assert run(launcher, ['--kill-switch-unlock'], extra=switch_env)[0] != 0
            with start_switch_process('cancelled', WW_FIXTURE_HANDOFF_CANCEL='before') as cancelled:
                await_process(cancelled, False)
            assert policy_events() == before and owner.poll() is None and marker.exists(), policy_events()

            with start_switch_process('B', journal=journal_b, WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(held_b),
                                      WW_FIXTURE_HANDOFF_PAUSED=windows_path(paused),
                                      WW_FIXTURE_HANDOFF_CONTINUE=windows_path(proceed)) as successor:
                await_file(paused, successor)
                await_process(owner, True)
                assert marker.exists()
                assert run(launcher, ['--kill-switch-unlock'], extra=switch_env)[0] != 0
                with start_switch_process('C') as competitor:
                    await_process(competitor, False)
                assert marker.exists()
                proceed.touch()
                await_file(held_b, successor)
                assert ordinary.poll() is None
                check_switch_status(b'locked')
                assert 'A close locked' in policy_events() and 'B image locked' in policy_events(), policy_events()
                assert policy_events().index('A close locked') < policy_events().index('B image locked')
                assert 'B grant-tun locked' in policy_events()
                during_handoff = policy_events()[first_event:]
                assert during_handoff and all(line.endswith(' locked') for line in during_handoff), during_handoff
                assert all(not line.startswith('C ') for line in during_handoff), during_handoff
                assert recovery_receipt(journal_b)['runtime_status'] == 0
                await_process(successor, True)
                assert policy_events()[-1] == 'B unlock unlocked', policy_events()
        check_switch_status(b'unlocked')
        assert ordinary.poll() is None
        assert recovery_receipt(ordinary_journal)['runtime_status'] == 0
        await_process(ordinary, True)

    for name, after_stop in (('cancelled-replacement', {'WW_FIXTURE_HANDOFF_CANCEL': 'after'}),
                             ('failed-replacement', {'WW_FIXTURE_FAIL_BEFORE_RESUME': '1'})):
        ready = root / (name + '-ready')
        with start_switch_process(name + '-old', WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(ready)) as owner:
            await_file(ready, owner)
            with start_switch_process(name + '-new', **after_stop) as successor:
                await_process(successor, False)
            await_process(owner, True)
        check_switch_status(b'unlocked')

    slow_journal = root / 'slow-owner-session'
    slow_ready = root / 'slow-owner-ready'
    with start_switch_process('slow-A', journal=slow_journal, WW_FIXTURE_EXIT='7',
                              WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(slow_ready),
                              WW_FIXTURE_KILL_SWITCH_STOP_DELAY_MS='13000') as owner:
        await_file(slow_ready, owner)
        with start_switch_process('slow-B') as successor:
            await_process(successor, True, timeout=30)
        assert await_process(owner, False) == 7
    receipt = recovery_receipt(slow_journal)
    assert receipt['termination'] == 'orderly' and receipt['runtime_status_known'] and receipt['runtime_status'] == 7, receipt
    check_switch_status(b'unlocked')

    pending_ready = root / 'pending-owner-ready'
    with start_switch_process('pending-A', WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(pending_ready),
                              WW_FIXTURE_ADAPTER_STATE='pending') as owner:
        await_file(pending_ready, owner)
        with start_switch_process('pending-B') as successor:
            await_process(successor, False)
        await_process(owner, None)
    assert not any(event.startswith('pending-B ') for event in policy_events()), policy_events()
    check_switch_status(b'locked')
    unlock()

    stopped_journal = root / 'exit-race-session'
    stopped_ready = root / 'exit-race-ready'
    with start_switch_process('exit-race-A', journal=stopped_journal,
                              WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(stopped_ready)) as owner:
        await_file(stopped_ready, owner)
        with ThreadPoolExecutor(max_workers=1) as pool:
            stopping = pool.submit(recovery_receipt, stopped_journal)
            with start_switch_process('exit-race-B') as successor:
                await_process(successor, True)
            assert stopping.result()['runtime_status'] == 0
        await_process(owner, True)
    check_switch_status(b'unlocked')

    # The old owner has exited under the recorded handoff, then the successor
    # crashes before acquiring the lease. Its stale reservation can be reclaimed.
    stale_ready = root / 'stale-reservation-ready'
    stale_pause, stale_continue = root / 'stale-paused', root / 'stale-continue'
    with start_switch_process('stale-A', WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(stale_ready)) as owner:
        await_file(stale_ready, owner)
        with start_switch_process('stale-B', WW_FIXTURE_HANDOFF_PAUSED=windows_path(stale_pause),
                                  WW_FIXTURE_HANDOFF_CONTINUE=windows_path(stale_continue),
                                  WW_FIXTURE_HANDOFF_CRASH='1', **crash_env) as successor:
            await_file(stale_pause, successor)
            await_process(owner, True)
            stale_continue.touch()
            assert await_process(successor, False) == (5 if args.wine else 0xc0000005)
    check_switch_status(b'locked')
    switch_start(True, complete_switch)
    check_switch_status(b'unlocked')

    # An old child that ignores stop must settle within the handoff's bounded
    # Job recovery path, with the baseline still installed when B reaches TUN.
    hung_ready = root / 'hung-ready'
    survivor_ready = root / 'survivor-ready'
    survivor_journal = root / 'survivor-session'
    with start_switch_process('survivor', journal=survivor_journal, data=b'{}',
                              WW_FIXTURE_ORDINARY_HOLD=windows_path(survivor_ready)) as survivor:
        await_file(survivor_ready, survivor)
        with start_switch_process('hung-A', WW_FIXTURE_KILL_SWITCH_HOLD=windows_path(hung_ready),
                                  WW_FIXTURE_KILL_SWITCH_HANG_AT_STOP='1', **crash_env) as hung:
            await_file(hung_ready, hung)
            with start_switch_process('hung-B') as successor:
                await_process(successor, True, timeout=35)
            # Wine may return zero for a process terminated through its Job.
            forced_status = await_process(hung, None)
            if not args.wine:
                assert forced_status == 0xe0570001, forced_status
        assert survivor.poll() is None
        assert recovery_receipt(survivor_journal)['runtime_status'] == 0
        await_process(survivor, True)
    assert 'hung-B grant-tun locked' in policy_events()
    assert 'hung-A revoke-tun locked' not in policy_events() and 'hung-A close locked' not in policy_events()
    assert 'hung-A unlock unlocked' not in policy_events()
    check_switch_status(b'unlocked')

    for options, data in [(['--ww-internal-map=4'], b'{}'), (['unknown'], b'{}'),
                          (['-c:missing.json'], b'{}'), (['-c:stdin'], b'['),
                          (['--restricted-config', '-c:stdin'], b'{}\0bad')]:
        code, out, err = run(launcher, options, data)
        assert code != 0 and b'snapshot:' not in out, (code, out, err)
        if b'Extracted application binary:' in err:
            import re
            match = re.search(r'Extracted application binary:\s*(.*)', err.decode(errors='replace'))
            if match:
                win_path = match.group(1).strip()
                if args.wine:
                    posix_path = Path(subprocess.check_output(['winepath', '-u', win_path], env=env, timeout=15).decode().strip())
                else:
                    posix_path = Path(win_path)
                assert posix_path.exists(), f'fallback binary was not extracted: {posix_path}'
                posix_path.unlink()
        assert not list(extraction.iterdir()), list(extraction.iterdir())

    # Wine substitutes its own TEMP for an invalid directory before our process
    # starts. Native Windows preserves it, exercising this extraction failure.
    if not args.wine:
        invalid_root = windows_path(root / 'missing extraction root')
        code, out, err = run(launcher, ['-c:stdin'], extra={'TEMP': invalid_root, 'TMP': invalid_root})
        assert code != 0 and b'snapshot:' not in out and b'Packed runtime:' in err, (code, out, err)
        assert not list(extraction.iterdir()), list(extraction.iterdir())

    def compare(data, restricted=False, extra=None):
        options = ['-c:stdin'] + (['--restricted-config'] if restricted else [])
        ordinary = run(application, options, data, extra)
        packed = run(launcher, options, data, extra)
        assert ordinary == packed, (ordinary, packed)
        assert b'snapshot:' in packed[1], packed
        expected = int((extra or {}).get('WW_FIXTURE_EXIT', '0'), 0)
        assert packed[0] & 0xffffffff == expected & (255 if args.wine else 0xffffffff), packed

    for data in (b'{}', b'{"x":1}\r\n', b'{}\x1aafter', b'{}\0after',
                 b'\xef\xbb\xbf{}', b'{"x":"' + b'a' * (1024*1024) + b'"}'):
        compare(data)
    for data in (b'{}', b'{"x":1}\r\n', b'{"x":"' + b'a'*65536 + b'"}'):
        compare(data, True)
    for status in ('7', '0x80000001', '0xc0000005'):
        compare(b'{}', extra={'WW_FIXTURE_EXIT': status})
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(compare, [b'{}']*4))
    assert not list(extraction.iterdir()), list(extraction.iterdir())
    for options, extra in [([], {'WW_CORE_JSON_INPUT': 'stdin'}),
                           (['-c:stdin'], {'WW_CORE_JSON_INPUT': 'missing-core.json'})]:
        ordinary = run(application, options, b'{}', extra)
        packed = run(launcher, options, b'{}', extra)
        assert ordinary == packed and b'snapshot:' in packed[1], (ordinary, packed)
    (unrelated / 'core.json').write_bytes(b'{"default":true}')
    assert run(application, []) == run(launcher, [])
    config = unrelated / 'configuration with spaces.json'
    config.write_bytes(b'{"file":true}')
    for alias in ('-c:', '--c:', '-config:', '--config:', 'config:'):
        ordinary = run(application, [alias + windows_path(config)])
        packed = run(launcher, [alias + windows_path(config)])
        assert ordinary == packed, (ordinary, packed)
    expected = run(application, ['-c:' + windows_path(config)])
    captured = run(launcher, ['-c:' + windows_path(config)], extra={'WW_FIXTURE_REMOVE_SOURCE': '1'})
    assert captured == expected and not config.exists(), (captured, expected)
    if not args.wine:
        # Send WM_CLOSE to the private console and finish shutdown after the
        # old four-second handler limit, within the Windows default of five seconds.
        trace.unlink(missing_ok=True)
        console_journal = root / 'console-close-session'
        close_options = ['-c:stdin', '--console:visible', '--session-file:' + windows_path(console_journal)]
        result = run(launcher, close_options, protected, switch_env | {
            'WW_FIXTURE_CLOSE_CONSOLE': '1',
            'WW_FIXTURE_KILL_SWITCH_HOLD': windows_path(root / 'console-close-ready'),
            'WW_FIXTURE_KILL_SWITCH_STOP_DELAY_MS': '4200',
        })
        assert result[0] == 0 and trace.read_text().splitlines() == complete_switch, result
        assert recovery_receipt(console_journal)['termination'] == 'orderly'
        check_switch_status(b'unlocked')
    # The executable directory precedes CWD, but CWD remains a fallback when
    # there is no adjacent companion. Exercise the native implicit-import path.
    companions = list(deployment.glob('*.dll'))
    assert companions, 'fixture companion DLL missing'
    for companion in companions:
        (unrelated / companion.name).write_bytes(b'not a PE DLL')
    compare(b'{}')
    for companion in companions:
        companion.replace(unrelated / companion.name)
    compare(b'{}')
    assert not list(extraction.iterdir()), list(extraction.iterdir())
    print('Windows launcher fixture: startup, exact snapshots, DLL, TLS, exits, concurrent cleanup passed')
