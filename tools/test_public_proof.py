"""A missing job or mismatched source commit must never become a green proof."""
import contextlib
import importlib.util
import io
import json
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
        return dict(id=123, run_attempt=1, name='CLI tests', event='push', head_branch='release/2.2',
                    head_repository={'full_name': proof.REPOSITORY}, head_sha='a' * 40,
                    status='completed', conclusion='success', html_url='https://github.com/example/run/123')

    def jobs(self):
        return [dict(name=name, status='completed', conclusion='success', steps=[])
                for name in proof.EXPECTED]

    def test_green_proof_requires_every_expected_job(self):
        svg, metadata, readme = proof.render(self.run_data(), self.jobs())
        self.assertEqual(metadata['jobs_success'], 12)
        self.assertEqual(metadata['jobs_total'], 12)
        self.assertEqual(metadata['head_sha'], 'a' * 40)
        self.assertEqual(metadata['source_repository'], 'IamAngusU/php-fpm-audit')
        self.assertEqual(metadata['repository'], 'angusu-de/p2s-harden')
        self.assertEqual(metadata['source_branch'], 'release/2.2')
        self.assertEqual(metadata['source_ref'], 'refs/heads/release/2.2')
        self.assertIn('<title>php-fpm-audit release/2.2 CI: 12/12 jobs passed;', svg)
        self.assertIn('[Source repository](https://github.com/IamAngusU/php-fpm-audit)', readme)
        self.assertIn('CI fork `release/2.2` heads', readme)
        self.assertIn('12/12', svg)
        self.assertIn('aaaa', readme)

    def test_missing_job_stays_visible(self):
        svg, metadata, _ = proof.render(self.run_data(), self.jobs()[:-1])
        self.assertEqual(metadata['jobs_success'], 11)
        self.assertEqual(metadata['jobs_total'], 12)
        self.assertIn('11/12', svg)
        self.assertEqual(metadata['jobs'][-1]['status'], 'missing')

    def test_failed_job_is_red_and_not_counted_passed(self):
        jobs = self.jobs()
        jobs[0]['conclusion'] = 'failure'
        svg, metadata, _ = proof.render(self.run_data(), jobs)
        self.assertEqual(metadata['jobs_success'], 11)
        self.assertIn('class="proof-failure"', svg)

    def test_each_real_fpm_job_is_required_for_a_full_proof(self):
        for name in ('PHP-FPM 8.2', 'PHP-FPM 8.3', 'PHP-FPM 8.4', 'PHP-FPM 8.5',
                     'System Ubuntu 24.04 (PHP 8.3)', 'System Debian 12 (PHP 8.2)',
                     'System Ubuntu 22.04 (PHP 8.1)', 'System Debian 13 (PHP 8.4)', 'Release provenance'):
            with self.subTest(job=name):
                self.assertIn(name, proof.EXPECTED)
                jobs = [job for job in self.jobs() if job['name'] != name]
                svg, metadata, _ = proof.render(self.run_data(), jobs)
                self.assertEqual(metadata['jobs_success'], 11)
                self.assertEqual(metadata['jobs_total'], 12)
                self.assertEqual(next(job for job in metadata['jobs'] if job['name'] == name)['status'], 'missing')
                self.assertIn('11/12', svg)

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

    def test_main_and_other_release_branches_are_rejected(self):
        for branch in ('main', 'release/2.3', 'release/2.2-extra'):
            with self.subTest(branch=branch):
                run = dict(self.run_data(), head_branch=branch)
                with patch.object(proof, 'github_json', return_value=run) as api, patch.object(sys, 'argv', ['proof', '123', '/unused']), self.assertRaises(SystemExit):
                    proof.main()
                self.assertEqual(api.call_count, 1)

    def test_foreign_repository_and_pull_request_events_are_rejected(self):
        for fields in (dict(head_repository={'full_name': 'other/repository'}), dict(event='pull_request')):
            with self.subTest(fields=fields):
                run = dict(self.run_data(), **fields)
                with patch.object(proof, 'github_json', return_value=run) as api, patch.object(sys, 'argv', ['proof', '123', '/unused']), self.assertRaises(SystemExit):
                    proof.main()
                self.assertEqual(api.call_count, 1)

    def test_newer_fork_commit_prevents_proof_publication(self):
        run = self.run_data()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'proof'
            def api(path, repository=proof.REPOSITORY):
                if path == 'actions/runs/123':
                    return run
                self.assertEqual(path, 'git/ref/heads/release/2.2')
                return {'object': {'sha': ('b' if repository == proof.REPOSITORY else 'a') * 40}}
            with patch.object(proof, 'github_json', side_effect=api), patch.object(proof, 'load_jobs') as load_jobs, patch.object(sys, 'argv', ['proof', '123', str(destination)]), contextlib.redirect_stdout(io.StringIO()):
                proof.main()
            self.assertFalse(destination.exists())
            load_jobs.assert_not_called()

    def test_matching_release_heads_publish_branch_specific_evidence(self):
        for event in ('push', 'workflow_dispatch'):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as temporary:
                run = dict(self.run_data(), event=event)
                destination = Path(temporary) / 'proof'
                checked = []
                def api(path, repository=proof.REPOSITORY):
                    if path == 'actions/runs/123':
                        return run
                    self.assertEqual(path, 'git/ref/heads/release/2.2')
                    checked.append(repository)
                    return {'object': {'sha': 'a' * 40}}
                with patch.object(proof, 'github_json', side_effect=api), patch.object(proof, 'load_jobs', return_value=self.jobs()), patch.object(sys, 'argv', ['proof', '123', str(destination)]):
                    proof.main()
                self.assertEqual(checked, ['angusu-de/p2s-harden', 'IamAngusU/php-fpm-audit'])
                metadata = json.loads((destination / 'public-proof.json').read_text(encoding='utf-8'))
                self.assertEqual(metadata['source_ref'], 'refs/heads/release/2.2')
                self.assertEqual(metadata['head_sha'], run['head_sha'])
                self.assertEqual(metadata['jobs_success'], 12)


if __name__ == '__main__':
    unittest.main(verbosity=2)
