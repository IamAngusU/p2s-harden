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
    def test_json_is_valid_utf8_ascii_and_preserves_filesystem_surrogates(self):
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
        self.assertEqual(restored['findings'][0]['resource']['path'],path)
        self.assertEqual(restored['path_encoding'],'filesystem-surrogateescape')
        self.assertIn(b'\\udcff\\udcfe',data)
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
            self.assertEqual(os.fsencode(row['resource']['path']),name)
            self.assertEqual(row['sha256'],p.digest(Path(os.fsdecode(name)).read_bytes()))


if __name__=='__main__':unittest.main()
