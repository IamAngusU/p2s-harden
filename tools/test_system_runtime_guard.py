"""The destructive VM harness must refuse unmarked/unauthorized environments."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_system_runtime as system_test


class SystemGuard(unittest.TestCase):
    def invoke(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            code=system_test.main(['--expect-php','8.3','--json'])
        report=json.loads(output.getvalue())
        self.assertEqual(code,2)
        self.assertEqual(report['cases'],[])
        self.assertEqual(report['exit_code'],2)
        return report

    def test_without_explicit_environment_flag_never_runs_a_command(self):
        with patch.dict(os.environ,{'P2S_DISPOSABLE_SYSTEM_TEST':'0'}), patch.object(system_test,'run',side_effect=AssertionError('must not execute')):
            self.assertIn('explicitly authorized',self.invoke()['error'])

    def test_missing_marker_never_runs_a_command_even_as_linux_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ,{'P2S_DISPOSABLE_SYSTEM_TEST':'1'}), \
                    patch.object(system_test.sys,'platform','linux'), \
                    patch.object(system_test.os,'geteuid',return_value=0,create=True), \
                    patch.object(system_test,'MARKER',Path(temporary)/'absent'), \
                    patch.object(system_test,'run',side_effect=AssertionError('must not execute')):
                self.assertIn('marker',self.invoke()['error'])


if __name__=='__main__': unittest.main()
