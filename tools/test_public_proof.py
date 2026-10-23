"""A missing job or mismatched source commit must never become a green proof."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('proof', Path(__file__).with_name('render-public-proof-badge.py'))
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class ProofTests(unittest.TestCase):
    def run_data(self):
        return dict(id=123, run_attempt=1, name='CLI tests', event='push', head_branch='main',
                    head_repository={'full_name': proof.REPOSITORY}, head_sha='a' * 40,
                    status='completed', conclusion='success', html_url='https://github.com/example/run/123')

    def jobs(self):
        return [dict(name=name, status='completed', conclusion='success', steps=[])
                for name in proof.EXPECTED]

    def test_green_proof_requires_every_expected_job(self):
        svg, metadata, readme = proof.render(self.run_data(), self.jobs())
        self.assertEqual(metadata['jobs_success'], 3)
        self.assertEqual(metadata['jobs_total'], 3)
        self.assertEqual(metadata['head_sha'], 'a' * 40)
        self.assertEqual(metadata['source_repository'], 'IamAngusU/p2s-harden')
        self.assertIn('3/3', svg)
        self.assertIn('aaaa', readme)

    def test_missing_job_stays_visible(self):
        svg, metadata, _ = proof.render(self.run_data(), self.jobs()[:-1])
        self.assertEqual(metadata['jobs_success'], 2)
        self.assertEqual(metadata['jobs_total'], 3)
        self.assertIn('2/3', svg)
        self.assertEqual(metadata['jobs'][-1]['status'], 'missing')

    def test_failed_job_is_red_and_not_counted_passed(self):
        jobs = self.jobs()
        jobs[0]['conclusion'] = 'failure'
        svg, metadata, _ = proof.render(self.run_data(), jobs)
        self.assertEqual(metadata['jobs_success'], 2)
        self.assertIn('class="proof-failure"', svg)

    def test_duplicate_job_is_rejected(self):
        with self.assertRaises(ValueError):
            proof.render(self.run_data(), self.jobs() * 2)

    def test_job_names_are_escaped_in_svg(self):
        jobs = self.jobs() + [dict(name='<script>payload</script>', status='queued', conclusion=None, steps=[])]
        svg, _, _ = proof.render(self.run_data(), jobs)
        self.assertNotIn('<script>', svg)
        self.assertIn('&lt;script&gt;', svg)

    def test_newer_source_commit_prevents_proof_publication(self):
        run = self.run_data()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'proof'
            def api(path, repository=proof.REPOSITORY):
                if path == 'actions/runs/123':
                    return run
                return {'object': {'sha': ('b' if repository == proof.SOURCE_REPOSITORY else 'a') * 40}}
            with patch.object(proof, 'github_json', side_effect=api), patch.object(sys, 'argv', ['proof', '123', str(destination)]), contextlib.redirect_stdout(io.StringIO()):
                proof.main()
            self.assertFalse(destination.exists())

    def test_foreign_workflow_is_rejected(self):
        run = dict(self.run_data(), name='another workflow')
        with patch.object(proof, 'github_json', return_value=run), patch.object(sys, 'argv', ['proof', '123', '/unused']), self.assertRaises(SystemExit):
            proof.main()


if __name__ == '__main__':
    unittest.main(verbosity=2)
