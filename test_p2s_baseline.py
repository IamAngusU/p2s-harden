"""Drafts require deliberate approval, exact bytes and protected file loading."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import p2s_harden as p


def fixture_report(path='/srv/site/index.php'):
    report=p.Report()
    for indicator in ('request-execution','encoded-execution'):
        row=report.add('OPEN','Fixture','Fixture',rule_id='P2S-WS001',resource=dict(path=path,indicator=indicator))
        row.update(sha256='a'*64,baseline_accepted=True)
    report.discovery=dict(webshell_scan=True,webshell_coverage=[dict(omitted_paths=2,paths=[
        dict(path='/srv/site/font.ttf',reason='window',sha256='b'*64),
        dict(path='/srv/site/slow.php',reason='file-time',sha256='c'*64),
        dict(path='/srv/site/access.php',reason='access')])])
    return report


class DraftProtocol(unittest.TestCase):
    def test_draft_groups_indicators_but_approves_nothing_even_from_accepted_rows(self):
        draft=p.webshell_baseline_draft(fixture_report())
        self.assertEqual(len(draft['files']),1)
        self.assertEqual(draft['files'][0]['indicators'],['encoded-execution','request-execution'])
        self.assertEqual(len(draft['reviewed_files']),1)
        self.assertFalse(draft['files'][0]['reviewed'])
        self.assertFalse(draft['reviewed_files'][0]['reviewed'])
        self.assertEqual(draft['source']['omitted_coverage_paths'],2)
        self.assertEqual(draft['source']['unreviewable_coverage_paths'],2)
        with self.assertRaisesRegex(p.CheckError,'Unreviewed'):p.webshell_baseline_entries(draft)
        for entry in draft['files']+draft['reviewed_files']:entry['reviewed']=True
        accepted=p.webshell_baseline_entries(draft)
        self.assertIn(('/srv/site/font.ttf','coverage:window'),accepted)

    def test_explicit_false_or_nonboolean_review_can_never_approve_legacy_entries(self):
        for reviewed in (False,0,1,'true',None):
            draft=p.webshell_baseline_draft(fixture_report())
            draft['reviewed_files']=[]
            draft['files'][0]['reviewed']=reviewed
            with self.subTest(reviewed=reviewed),self.assertRaises(p.CheckError):p.webshell_baseline_entries(draft)
        draft=p.webshell_baseline_draft(fixture_report())
        draft['reviewed_files']=[]
        del draft['files'][0]['reviewed']
        with self.assertRaises(p.CheckError):p.webshell_baseline_entries(draft)
        draft['files'][0]['reviewed']=True
        draft['requires_review']=False
        with self.assertRaises(p.CheckError):p.webshell_baseline_entries(draft)

    def test_byte_filename_draft_and_new_report_import_bind_original_bytes(self):
        path='/srv/site/invalid_\udcff\udcfe.php'
        report=fixture_report(path)
        draft=p.webshell_baseline_draft(report)
        resource=draft['files'][0]
        self.assertEqual(resource['path'],'/srv/site/invalid_\ufffd\ufffd.php')
        self.assertEqual(bytes.fromhex(resource['path_bytes_hex']),path.encode('utf-8','surrogateescape'))
        for entry in draft['files']+draft['reviewed_files']:entry['reviewed']=True
        entries=p.webshell_baseline_entries(draft)
        self.assertTrue(any(key[0]==path for key in entries))
        output=io.StringIO()
        with contextlib.redirect_stdout(output):report.show(True)
        self.assertTrue(any(key[0]==path for key in p.webshell_baseline_entries(json.loads(output.getvalue()))))

    def test_same_display_spelling_never_collapses_different_raw_paths(self):
        first=p.json_paths(dict(path='/srv/x\udcff.php',sha256='a'*64,indicators=[next(iter(p.WEBSHELL_INDICATORS))]))
        second=p.json_paths(dict(path='/srv/x\udcfe.php',sha256='b'*64,indicators=first['indicators']))
        self.assertEqual(first['path'],second['path'])
        result=p.webshell_baseline_entries(dict(schema_version=1,files=[first,second]))
        self.assertEqual(len(result),2)


@unittest.skipUnless(sys.platform=='linux','Linux filesystem safety')
class DraftFilesystem(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path.cwd(),prefix='p2s-test-draft-')
        self.root=Path(self.tmp.name)
        self.file=self.root/'draft.json'
        self.report=fixture_report()
    def tearDown(self):self.tmp.cleanup()

    def test_new_private_file_is_exact_draft_and_existing_file_is_untouched(self):
        result=p.write_baseline_draft(str(self.file),self.report)
        self.assertEqual(result['indicator_files'],1)
        self.assertEqual(self.file.stat().st_mode & 0o777,0o600)
        before=self.file.read_bytes()
        self.assertEqual(json.loads(before),p.webshell_baseline_draft(self.report))
        with self.assertRaises(FileExistsError):p.write_baseline_draft(str(self.file),self.report)
        self.assertEqual(self.file.read_bytes(),before)

    def test_leaf_ancestor_symlinks_and_fifo_are_never_followed(self):
        original=self.root/'original';original.write_bytes(b'untouched')
        self.file.symlink_to(original)
        with self.assertRaises(OSError):p.write_baseline_draft(str(self.file),self.report)
        self.assertEqual(original.read_bytes(),b'untouched')
        self.file.unlink();os.mkfifo(self.file)
        with self.assertRaises(OSError):p.write_baseline_draft(str(self.file),self.report)
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):p.write_baseline_draft(str(alias/'other.json'),self.report)
        self.assertFalse((self.root/'other.json').exists())

    def test_failed_partial_write_removes_only_own_new_file(self):
        with patch.object(p.os,'write',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):p.write_baseline_draft(str(self.file),self.report)
        self.assertFalse(self.file.exists())

    def test_cli_draft_keeps_scan_exit_and_json_clean_and_refuses_redaction_or_overwrite(self):
        source=self.root/'index.php';source.write_bytes(b"<?php eval($_GET['x']);")
        options=[sys.executable,'-B',p.__file__,'--scan-webshells','--root',str(self.root),
                 '--no-nice','--json','--write-baseline-draft',str(self.file)]
        run=subprocess.run(options,capture_output=True)
        self.assertEqual(run.returncode,1,run.stderr)
        self.assertTrue(json.loads(run.stdout)['has_open'])
        self.assertTrue(self.file.exists())
        before=self.file.read_bytes()
        again=subprocess.run(options,capture_output=True)
        self.assertEqual(again.returncode,2,again.stderr)
        self.assertTrue(json.loads(again.stdout)['has_unknown'])
        self.assertEqual(before,self.file.read_bytes())
        self.file.unlink()
        redacted=subprocess.run(options+['--redact'],capture_output=True)
        self.assertEqual(redacted.returncode,2)
        self.assertTrue(json.loads(redacted.stdout)['redacted'])
        self.assertFalse(self.file.exists())
        wrong=subprocess.run([sys.executable,'-B',p.__file__,'--doctor','--json','--write-baseline-draft',str(self.file)],capture_output=True)
        self.assertEqual(wrong.returncode,2)
        self.assertFalse(self.file.exists())

    def test_actual_draft_needs_review_and_hash_change_loses_acceptance(self):
        source=self.root/'index.php';source.write_bytes(b"<?php eval($_GET['x']);")
        options=[sys.executable,'-B',p.__file__,'--scan-webshells','--root',str(self.root),'--no-nice','--json']
        first=subprocess.run(options+['--write-baseline-draft',str(self.file)],capture_output=True)
        self.assertEqual(first.returncode,1,first.stderr)
        denied=subprocess.run(options+['--baseline',str(self.file)],capture_output=True)
        self.assertEqual(denied.returncode,2,denied.stderr)
        self.assertTrue(json.loads(denied.stdout)['has_open'])
        draft=json.loads(self.file.read_bytes())
        for entry in draft['files']+draft['reviewed_files']:entry['reviewed']=True
        self.file.write_text(json.dumps(draft))
        accepted=subprocess.run(options+['--baseline',str(self.file)],capture_output=True)
        self.assertEqual(accepted.returncode,0,accepted.stderr)
        source.write_bytes(source.read_bytes()+b'/* changed */')
        changed=subprocess.run(options+['--baseline',str(self.file)],capture_output=True)
        self.assertEqual(changed.returncode,1,changed.stderr)
        self.assertEqual(json.loads(changed.stdout)['suppressed_open'],0)


if __name__=='__main__':unittest.main()
