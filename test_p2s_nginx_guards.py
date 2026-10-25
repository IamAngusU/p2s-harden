"""Bounded Nginx routing and explicit UNKNOWN acknowledgement contracts."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import p2s_harden as p
import test_p2s_defenses as defenses


class CommonGuards(unittest.TestCase):
    php = defenses.UploadRoute.php
    def route(self, config, uri='/uploads/', **kwargs):
        return defenses.UploadRoute().route(config, uri, **kwargs)

    def test_standard_ordered_guard_keeps_static_files_out_of_its_language(self):
        weak = r'location ~* ^/uploads/.*\.php$ { deny all; } '
        self.assertEqual(self.route(weak+self.php), ('OPEN','regex_line_break_gap'))
        guard = weak.replace('^/', '(?s)^/')
        self.assertEqual(self.route(guard+self.php), ('OK','ordered_php_rejection'))
        self.assertEqual(self.route(self.php+guard), ('OPEN','php_fastcgi_mapping'))
        self.assertIsNone(p.nginx_php_pattern(r'(?s)^/uploads/.*\.jpg$'))

    def test_wordpress_literal_and_case_sensitive_variants(self):
        for modifier in ('~','~*'):
            guard = 'location '+modifier+r' (?s)^/wp-content/uploads/.*\.php$ { deny all; } '
            self.assertEqual(self.route(guard+self.php, '/wp-content/uploads/')[0], 'OK')

    def test_finite_directory_and_extension_alternatives(self):
        guard = r'location ~* (?s)^/(?:uploads|files)/.*\.(php|phtml|phar)$ { return 404; } '
        handler = self.php.replace(r'\.php$',r'\.(php|phtml|phar)$')
        for uri in ('/uploads/','/files/','/files/subdirectory/'):
            self.assertEqual(self.route(guard+handler,uri)[0], 'OK')
        self.assertEqual(self.route(guard+handler,'/other/')[0], 'OPEN')

    def test_every_supported_terminal_status_and_deny_all(self):
        for body in ('deny all;', 'return 403;', 'return 404;', 'return 410;', 'return 444;'):
            self.assertEqual(self.route(r'location ~ (?s)^/uploads/.*\.php$ { '+body+' } '+self.php)[0], 'OK')

    def test_guard_must_cover_case_of_the_handler(self):
        handler = self.php.replace('location ~ ', 'location ~* ')
        self.assertEqual(self.route(r'location ~ (?s)^/uploads/.*\.php$ { deny all; } '+handler)[0], 'OPEN')
        self.assertEqual(self.route(r'location ~* (?s)^/uploads/.*\.php$ { deny all; } '+handler)[0], 'OK')

    def test_guard_must_cover_all_handler_extensions(self):
        handler = self.php.replace(r'\.php$',r'\.(php|phtml|phar)$')
        self.assertEqual(self.route(r'location ~* (?s)^/uploads/.*\.php$ { deny all; } '+handler)[0], 'OPEN')

    def test_guard_must_cover_path_info(self):
        guard = r'location ~* (?s)^/uploads/.*\.php$ { deny all; } '
        handler = self.php.replace(r'\.php$',r'\.php(/|$)')
        self.assertEqual(self.route(guard+handler)[0], 'OPEN')
        self.assertEqual(self.route(guard.replace(r'\.php$',r'\.php(?:/|$)')+handler)[0], 'OK')

    def test_partial_directory_guard_does_not_cover_root(self):
        guard = r'location ~* (?s)^/uploads/private/.*\.php$ { deny all; } '
        self.assertEqual(self.route(guard+self.php)[0], 'OPEN')

    def test_earlier_unknown_regex_never_gets_skipped(self):
        guard = r'location ~* (?s)^/uploads/.*\.php$ { deny all; } '
        for prefix in (r'location ~ (a+)+$ { return 403; } ',r'location ~ /\. { fastcgi_pass backend; } '):
            self.assertEqual(self.route(prefix+guard+self.php)[0], 'UNKNOWN')

    def test_supported_disjoint_regex_can_be_skipped(self):
        other = r'location ~ (?s)^/private/.*\.php$ { fastcgi_pass backend; } '
        guard = r'location ~* (?s)^/uploads/.*\.php$ { deny all; } '
        self.assertEqual(self.route(other+guard+self.php)[0], 'OK')

    def test_access_bypasses_and_content_modules_never_prove_denial(self):
        for body in ('allow all; deny all;', 'satisfy any; deny all;', 'deny all; auth_basic restricted;',
                     'deny all; return 200;', 'deny all; fastcgi_pass backend;', 'deny all; js_content handler;',
                     'if ($arg_x) { return 403; }', 'error_page 403 = /index.php; deny all;'):
            self.assertEqual(self.route(r'location ~ (?s)^/uploads/.*\.php$ { '+body+' } '+self.php)[0], 'UNKNOWN')
        for parent in ('satisfy any;', 'auth_basic restricted;', 'error_page 403 = /index.php;'):
            self.assertEqual(self.route(r'location ~ (?s)^/uploads/.*\.php$ { deny all; } '+self.php,server=parent)[0], 'UNKNOWN')

    def test_competing_exact_and_preferred_descendant_are_not_green(self):
        guard = r'location ~* (?s)^/uploads/.*\.php$ { deny all; } '
        for competing in ('location = /uploads/else.php { fastcgi_pass backend; } ',
                          'location ^~ /uploads/private/ { fastcgi_pass backend; } '):
            self.assertEqual(self.route(competing+guard+self.php)[0], 'UNKNOWN')

    def test_executable_prefix_cannot_hide_behind_php_only_guard(self):
        prefix = self.php.replace(r'~ \.php$', '/uploads/')
        self.assertEqual(self.route(prefix+r' location ~ (?s)^/uploads/.*\.php$ { deny all; } '+self.php)[0], 'UNKNOWN')

    def test_one_nested_leaf_denies_php_without_rejecting_directory(self):
        for modifier in ('~','~*'):
            nested = 'location ^~ /uploads/ { location '+modifier+r' \.php$ { deny all; } } '
            self.assertEqual(self.route(nested+self.php), ('OK','nested_php_rejection'))

    def test_nested_executable_conditional_or_mapping_never_gets_ok(self):
        for extra in (self.php, r'location ~ \.php$ { deny all; if ($arg_x) { return 200; } }',
                      r'location ~ (?s)^/uploads/private/.*\.php$ { deny all; }',
                      r'location ~ \.php$ { location /uploads/private/ { return 403; } }'):
            self.assertEqual(self.route('location ^~ /uploads/ { '+extra+' } '+self.php)[0], 'UNKNOWN')
        for parent in ('root /elsewhere;', 'alias /elsewhere/;', 'try_files $uri /index.php;'):
            self.assertEqual(self.route('location ^~ /uploads/ { '+parent+r' location ~ \.php$ { deny all; } } '+self.php)[0], 'UNKNOWN')

    def test_unrestricted_regex_syntax_is_rejected_without_evaluation(self):
        for pattern in (r'(?s)^/upload.*/.*\.php$',r'(?s)^/(a+)+/.*\.php$',r'(?s)^/uploads/.*\.(php|exe)$',
                        r'(?s)^/uploads/.*\.php$',r'(?i)(?s)^/uploads/.*\.php$',r'(?s)^/uploads/.*\.php\z'):
            if pattern==r'(?s)^/uploads/.*\.php$':
                self.assertIsNotNone(p.nginx_php_pattern(pattern))
            else:
                self.assertIsNone(p.nginx_php_pattern(pattern))
        self.assertIsNone(p.nginx_php_pattern('(?s)^/'+('/'.join(['(a|b)']*7)) + r'/.*\.php$'))

    def test_disabled_slash_normalization_is_not_certified(self):
        guard = r'location ~* (?s)^/uploads/.*\.php$ { deny all; } '
        self.assertEqual(self.route(guard+self.php,server='merge_slashes off;')[0],'UNKNOWN')
        self.assertEqual(self.route(guard+self.php,http='merge_slashes off;')[0],'UNKNOWN')

    def test_location_budget_precedes_any_guard_language_comparison(self):
        config=' '.join('location /path'+str(index)+'/ { return 403; }' for index in range(513))
        with patch.object(p,'nginx_php_pattern',side_effect=AssertionError('must not compare')):
            self.assertEqual(self.route(config+self.php),('UNKNOWN','limit'))
        self.assertNotIn('limit',p.NGINX_REVIEWABLE)


class ReviewContract(unittest.TestCase):
    token = dict(finding_id='P2S-NGX001-'+'a'*16,snapshot_sha256='b'*64,outcome='unsupported_regex')
    def data(self):
        return dict(schema_version=1,kind='nginx-upload-review',requires_review=True,
                    entries=[dict(self.token,reviewed=True,reason='Compared included configuration and tested the actual virtual host.')])

    def report(self):
        report=p.Report()
        row=report.add('UNKNOWN','Nginx upload execution','Unresolved route',rule_id='P2S-NGX001',resource='/private/host',evidence=dict(outcome='unsupported_regex'))
        row['nginx_review']=dict(self.token)
        return report,row

    def test_only_explicit_complete_review_entries_accepted(self):
        self.assertEqual(len(p.nginx_review_entries(self.data())),1)
        for field,value in (('reviewed',False),('reviewed',1),('reason',''),('snapshot_sha256','b'*63),
                            ('finding_id','P2S-WS001-'+'a'*16),('outcome','not_assessed'),('extra',True)):
            data=self.data();data['entries'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(p.CheckError):p.nginx_review_entries(data)

    def test_global_ignore_does_not_accept_unknown(self):
        report,row=self.report();report.configure(ignore=['P2S-NGX001'])
        self.assertEqual(report.exit_code(),2);self.assertFalse(row['suppressed'])

    def test_acknowledgement_stays_visible_unknown_and_retains_raw_counts(self):
        report,row=self.report()
        with patch.object(p,'read_webshell_baseline',return_value=p.nginx_review_entries(self.data())):
            p.nginx_review_report(report,argparse.Namespace(nginx_baseline='review.json'))
        report.configure();self.assertEqual(report.exit_code(),0);self.assertTrue(report.has('UNKNOWN'))
        self.assertFalse(report.has_unaccepted_unknown());self.assertEqual(row['status'],'UNKNOWN');self.assertFalse(row['suppressed'])
        for redact in (False,True):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):report.show(True,redact=redact)
            data=json.loads(output.getvalue());self.assertTrue(data['has_unknown']);self.assertFalse(data['has_unaccepted_unknown'])
            self.assertEqual(data['accepted_unknown'],1);self.assertEqual(data['counts']['UNKNOWN'],1)
            if redact:
                self.assertNotIn('b'*64,output.getvalue());self.assertNotIn('nginx_review',data['findings'][0])
        output=io.StringIO()
        with contextlib.redirect_stdout(output):report.show()
        self.assertIn('[reviewed UNKNOWN]',output.getvalue())

    def test_any_token_change_requires_new_review(self):
        for field,value in (('finding_id','P2S-NGX001-'+'c'*16),('snapshot_sha256','c'*64),('outcome','nested_location')):
            report,row=self.report();row['nginx_review'][field]=value
            with patch.object(p,'read_webshell_baseline',return_value=p.nginx_review_entries(self.data())):
                p.nginx_review_report(report,argparse.Namespace(nginx_baseline='review.json'))
            self.assertEqual(report.exit_code(),2)

    def test_other_unknown_and_open_findings_keep_their_exit_impact(self):
        report,row=self.report();row['review_accepted']=True
        report.add('UNKNOWN','Coverage','Unvisited',rule_id='P2S-WS003')
        self.assertEqual(report.exit_code(),2)
        report.rows.pop();report.add('OPEN','Nginx upload execution','Executable',rule_id='P2S-NGX001')
        self.assertEqual(report.exit_code(),1)

    def test_unsafe_or_unreviewed_file_adds_independent_unknown(self):
        report,row=self.report()
        with patch.object(p,'read_webshell_baseline',side_effect=p.CheckError('invalid')):
            p.nginx_review_report(report,argparse.Namespace(nginx_baseline='review.json'))
        self.assertEqual(report.rows[-1]['rule_id'],'P2S-NGX002');self.assertEqual(report.exit_code(),2)

    def test_cli_review_never_runs_on_invalid_mode_or_failed_discovery(self):
        for options in (['--fix','--nginx-baseline','review.json'], ['--check','--redact','--write-nginx-review-draft','new.json']):
            with patch.object(p,'nginx_review_report') as review,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(p.main(options+['--json']),2)
            review.assert_not_called()

    def test_unstable_configuration_cannot_supply_a_review_token(self):
        self.assertNotIn('configuration_snapshot_incomplete',p.NGINX_REVIEWABLE)
        self.assertNotIn('regex_line_break_gap',p.NGINX_REVIEWABLE)


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:1)()==0,'Protected root-owned Linux configuration')
class SnapshotReview(unittest.TestCase):
    def test_complete_include_closure_order_comments_glob_and_empty_glob_are_bound(self):
        with tempfile.TemporaryDirectory(dir='/root') as temporary:
            root=Path(temporary);(root/'conf').mkdir()
            main=root/'nginx.conf';first=root/'conf/a.conf';second=root/'conf/b.conf'
            main.write_text('http { include conf/*.conf; include empty/*.conf; }')
            first.write_text('server { root /srv/site; }')
            snapshot=lambda:getattr(p.read_nginx(main,partial=True),'snapshot_sha256',None)
            initial=snapshot();self.assertIsNotNone(initial);self.assertEqual(snapshot(),initial)
            first.write_text(first.read_text()+'\n# comment edit')
            self.assertNotEqual(snapshot(),initial)
            first.write_text('server { root /srv/site; }');self.assertEqual(snapshot(),initial)
            second.write_text('server { root /srv/other; }');self.assertNotEqual(snapshot(),initial)
            second.unlink();self.assertEqual(snapshot(),initial)
            first.rename(second);self.assertNotEqual(snapshot(),initial)
            second.rename(first);self.assertEqual(snapshot(),initial)
            (root/'empty').mkdir();(root/'empty/new.conf').write_text('# new include')
            self.assertNotEqual(snapshot(),initial)
            main.write_text('http { include missing.conf; }')
            self.assertIsNone(snapshot())

    def test_real_draft_is_private_unreviewed_no_overwrite_and_expires_on_include_change(self):
        with tempfile.TemporaryDirectory(dir='/root') as temporary:
            root=Path(temporary);(root/'uploads').mkdir()
            config=root/'nginx.conf';included=root/'routes.conf';draft=root/'review.json'
            config.write_text('http { server { root '+str(root)+'; include routes.conf; } }')
            included.write_text('location ~ (a+)+$ { return 403; } '+defenses.UploadRoute.php)
            args=argparse.Namespace(root=str(root),roots=[str(root)],nginx_config=str(config),runtime_dirs=[str(root/'uploads')],
                                    nginx_baseline=None,write_nginx_review_draft=str(draft))
            def audit():
                report=p.Report();p.nginx_upload_security(report,args);p.nginx_review_report(report,args);return report
            report=audit();self.assertEqual(draft.stat().st_mode&0o777,0o600);data=json.loads(draft.read_text())
            self.assertFalse(data['entries'][0]['reviewed']);self.assertEqual(report.exit_code(),2)
            args.write_nginx_review_draft=None;args.nginx_baseline=str(draft)
            self.assertEqual(audit().exit_code(),2)
            data['entries'][0].update(reviewed=True,reason='Reviewed entire test fixture and route behavior.')
            draft.write_text(json.dumps(data));self.assertEqual(audit().exit_code(),0)
            included.write_text(included.read_text()+'\n# new configuration')
            self.assertEqual(audit().exit_code(),2)
            with self.assertRaises(FileExistsError):p.write_private_json(str(draft),data)
            unsafe=root/'unsafe.json';unsafe.write_text(json.dumps(data));unsafe.chmod(0o666)
            args.nginx_baseline=str(unsafe);self.assertEqual(audit().exit_code(),2)


if __name__=='__main__':unittest.main()
