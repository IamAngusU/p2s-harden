"""Resource ownership and incomplete-cleanup guards; no Docker daemon needed."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('upload_lab', Path(__file__).with_name('reproduce-nginx-upload-guard.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabGuards(unittest.TestCase):
    def test_missing_docker_never_starts_resource_commands(self):
        output = io.StringIO()
        with patch.object(lab.shutil, 'which', return_value=None),patch.object(lab, 'docker') as docker,contextlib.redirect_stdout(output):
            self.assertEqual(lab.main(['--json']), 2)
        docker.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertTrue(result['cleanup_complete'])
        self.assertIn('Docker CLI is missing', result['error'])

    def test_unavailable_daemon_is_never_mistaken_for_absent_resources(self):
        failure = subprocess.CompletedProcess([], 1, '', 'Cannot connect to the Docker daemon')
        with patch.object(lab, 'docker', return_value=failure),self.assertRaises(RuntimeError):
            lab.inspect('container', 'owned-lab-container')

    def test_explicit_missing_resource_is_recognized(self):
        for kind in ('container', 'volume'):
            failure = subprocess.CompletedProcess([], 1, '[]', 'Error: No such '+kind+': owned-lab-resource')
            with patch.object(lab, 'docker', return_value=failure):
                self.assertIsNone(lab.inspect(kind, 'owned-lab-resource'))

    def test_ownership_mismatch_never_removes_the_unowned_volume(self):
        output = io.StringIO()
        def docker(*args, **kwargs):
            return subprocess.CompletedProcess([], 0, 'linux\n' if args[0]=='info' else '', '')
        with patch.object(lab.shutil, 'which', return_value='docker'),patch.object(lab, 'docker', side_effect=docker) as calls, \
                patch.object(lab, 'inspect', return_value=dict(Labels={lab.LABEL:'not-ours'})),contextlib.redirect_stdout(output):
            self.assertEqual(lab.main(['--json']), 2)
        self.assertFalse(any('rm' in call.args for call in calls.call_args_list))
        result = json.loads(output.getvalue())
        self.assertFalse(result['cleanup_complete'])
        self.assertEqual(len(result['cleanup_incomplete_resources']), 1)


if __name__ == '__main__':unittest.main()
