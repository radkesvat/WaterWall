"""Focused release filtering and real GDB exit/fatal-caller regression checks."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from zipfile import ZipFile

sys.dont_write_bytecode = True
from package_release_artifacts import package_release_artifacts
from windows_packed_application_debug import run_with_gdb


class ReleaseArtifactsTest(unittest.TestCase):
    def test_release_archives_exclude_debug_and_diagnostics(self):
        with tempfile.TemporaryDirectory(prefix='Waterwall release regression ') as temporary:
            root = Path(temporary)
            artifacts, output = root/'downloaded', root/'zipped'
            linux = artifacts/'Waterwall-linux-gcc-x64'
            windows = artifacts/'Waterwall-windows-arm64'
            diagnostics = artifacts/'Waterwall-linux-unit-debug-test-diagnostics'
            for directory in [linux, windows, diagnostics]:
                directory.mkdir(parents=True)
            (linux/'Waterwall').write_bytes(b'final unix executable')
            (linux/'waterwall_application').write_bytes(b'private comparison executable')
            (windows/'Waterwall.exe').write_bytes(b'final windows executable')
            (windows/'Waterwall.pdb').write_bytes(b'debug symbols')
            (windows/'Waterwall.exe.map').write_bytes(b'linker map')
            (diagnostics/'Waterwall.exe').write_bytes(b'diagnostic executable')
            (diagnostics/'server.key').write_bytes(b'fixture key')
            package_release_artifacts(artifacts, output)
            self.assertEqual(sorted(path.name for path in output.iterdir()),
                             [linux.name + '.zip', windows.name + '.zip'])
            for directory, name in [(linux, 'Waterwall'), (windows, 'Waterwall.exe')]:
                with ZipFile(output/(directory.name + '.zip')) as archive:
                    self.assertEqual(archive.namelist(), [name])
                    self.assertEqual(archive.read(name), (directory/name).read_bytes())

    def test_missing_final_executable_rejects_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root/'Waterwall-linux-gcc-x64'
            artifacts.mkdir()
            (artifacts/'waterwall_application').write_bytes(b'private executable')
            with self.assertRaisesRegex(ValueError, 'No final Waterwall executable'):
                package_release_artifacts(root, root/'zipped')

    def test_diagnostics_alone_cannot_become_a_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'Waterwall-windows-shutdown-test-diagnostics').mkdir()
            with self.assertRaisesRegex(ValueError, 'No release executables'):
                package_release_artifacts(root, root/'zipped')


@unittest.skipUnless(shutil.which('gdb'), 'GDB is required for debugger execution checks')
class DebuggerTest(unittest.TestCase):
    def run_python(self, code, *arguments):
        self.temporary = tempfile.TemporaryDirectory(prefix='Waterwall debugger regression ')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        return run_with_gdb([sys.executable, '-c', code, *arguments],
                            cwd=self.directory, timeout=15)

    def test_success_preserves_arguments_and_records_first_command(self):
        arguments = ['spaces stay together', '$literal', '`literal`']
        result = self.run_python('import json,sys; print(json.dumps(sys.argv[1:]))', *arguments)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(json.dumps(arguments).encode(), result.stdout)
        invocation = json.loads((self.directory/'debugger-command.json').read_text())
        self.assertIn('--return-child-result', invocation)
        self.assertNotIn('_amsg_exit', (self.directory/'gdb-command.gdb').read_text())

    def test_nonzero_child_status_is_not_gdb_success(self):
        result = self.run_python('import sys; sys.exit(3)')
        self.assertEqual(result.returncode, 3, result.stdout)

    def test_abort_records_caller_and_fails(self):
        result = self.run_python('import os; os.abort()')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(b'Waterwall fatal breakpoint: abort', result.stdout)
        self.assertIn(b'#0', result.stdout)
        self.assertEqual(result.stdout, (self.directory/'gdb.log').read_bytes())

    @unittest.skipUnless(os.name == 'posix', 'POSIX signal handler fixture')
    def test_handled_signal_is_not_reported_as_a_fatal_exit(self):
        result = self.run_python('import os,signal; '
                                 'signal.signal(signal.SIGABRT, lambda *_: None); '
                                 'os.kill(os.getpid(), signal.SIGABRT); print("signal handled")')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(b'Waterwall signal stop', result.stdout)
        self.assertIn(b'signal handled', result.stdout)

    def test_replay_stdin_keeps_arguments(self):
        with tempfile.TemporaryDirectory(prefix='Waterwall debugger stdin ') as temporary:
            root = Path(temporary)
            source = root/'saved input.bin'
            source.write_bytes(b'saved startup input')
            result = run_with_gdb([sys.executable, '-c',
                                  'import sys; print(sys.argv[1]); print(sys.stdin.buffer.read())',
                                  'argument with spaces'],
                                  cwd=root, timeout=15, stdin_path=source)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn(b'argument with spaces', result.stdout)
            self.assertIn(b'saved startup input', result.stdout)


if __name__ == '__main__':
    unittest.main()
