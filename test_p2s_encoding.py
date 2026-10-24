"""Strict byte transport and restricted terminal encodings, without PHP."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import p2s_harden as p


class OutputEncoding(unittest.TestCase):
    def test_json_is_unicode_interoperable_and_preserves_filesystem_bytes(self):
        path='/srv/invalid_\udcff\udcfe.php'
        report=p.Report()
        report.add('OPEN','PHP '+path,'Private details',resource=dict(path=path))
        raw=io.BytesIO()
        output=io.TextIOWrapper(raw,encoding='utf-8',errors='surrogateescape')
        with contextlib.redirect_stdout(output):report.show(True)
        output.flush()
        data=raw.getvalue()
        data.decode('ascii')
        restored=json.loads(data.decode('utf-8'))
        resource=restored['findings'][0]['resource']
        self.assertEqual(resource['path'],'/srv/invalid_\ufffd\ufffd.php')
        self.assertEqual(bytes.fromhex(resource['path_bytes_hex']),path.encode('utf-8','surrogateescape'))
        self.assertEqual(p.baseline_path(resource),path)
        self.assertEqual(restored['path_encoding'],p.PATH_ENCODING)
        self.assertNotIn(b'\\udcff',data)
        json.dumps(restored,ensure_ascii=False).encode('utf-8','strict')
        output.detach()

    def test_human_output_cannot_crash_on_ascii_or_latin1_terminals(self):
        for encoding in ('ascii','latin-1'):
            raw=io.BytesIO()
            output=io.TextIOWrapper(raw,encoding=encoding,errors='strict')
            report=p.Report()
            report.add('INFO','Prüfung 中文','Details')
            with contextlib.redirect_stdout(output):report.show(lang='de')
            output.flush()
            self.assertIn(b'p2s-harden',raw.getvalue())
            self.assertIn(b'\\u4e2d',raw.getvalue())
            output.detach()

    def test_real_cli_help_and_doctor_survive_legacy_output_environment(self):
        env=dict(os.environ,PYTHONUTF8='0',PYTHONIOENCODING='ascii:strict',LC_ALL='C',PYTHONCOERCECLOCALE='0')
        for options in (['--help','--lang','de'],['--doctor','--lang','de'],['--doctor','--json','--lang','de']):
            run=subprocess.run([sys.executable,'-B',str(Path(p.__file__)),*options],env=env,capture_output=True)
            self.assertIn(run.returncode,(0,1,2),run.stderr)
            self.assertNotIn(b'UnicodeEncodeError',run.stderr)
            if '--json' in options:json.loads(run.stdout.decode('utf-8'))

    @unittest.skipUnless(sys.platform=='linux','Linux byte filenames')
    def test_real_scan_roundtrips_non_utf8_filename_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            name=os.fsencode(temporary)+b'/invalid_\xff\xfe.php'
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(b"<?php eval($_GET['x']);")
            run=subprocess.run([sys.executable,'-B',str(Path(p.__file__)),'--scan-webshells','--root',temporary,'--no-nice','--json'],capture_output=True)
            self.assertEqual(run.returncode,1,run.stderr)
            data=json.loads(run.stdout.decode('utf-8'))
            row=next(row for row in data['findings'] if row['rule_id']=='P2S-WS001')
            self.assertEqual(bytes.fromhex(row['resource']['path_bytes_hex']),name)
            self.assertEqual(os.fsencode(p.baseline_path(row['resource'])),name)
            self.assertEqual(row['sha256'],p.digest(Path(os.fsdecode(name)).read_bytes()))

    def test_redaction_strips_byte_metadata_and_internal_identity_is_unchanged(self):
        path='/PRIVATE/invalid_\udcff.php'
        report=p.Report()
        row=report.add('OPEN','PHP '+path,path,resource=dict(path=path))
        original_id=row['id']
        output=io.StringIO()
        with contextlib.redirect_stdout(output):report.show(True,redact=True)
        self.assertNotIn('path_bytes_hex',output.getvalue())
        self.assertNotIn(path.encode('utf-8','surrogateescape').hex(),output.getvalue())
        self.assertEqual(row['resource']['path'],path)
        self.assertEqual(row['id'],original_id)

    def test_hex_display_mismatch_and_ambiguous_byte_encodings_are_rejected(self):
        good=p.json_paths(dict(path='/srv/x\udcff.php'))
        for change in (dict(path='/srv/other.php'),dict(path_bytes_hex='ff0'),dict(path_bytes_hex='FF'),
                       dict(path_encoding='unknown'),dict(path_bytes_hex='00'),dict(path_bytes_hex=False)):
            with self.subTest(change=change),self.assertRaises(p.CheckError):p.baseline_path(dict(good,**change))


if __name__=='__main__':unittest.main()
