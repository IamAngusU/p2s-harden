"""Policy boundaries and conservative upload-routing regression cases."""
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


class ResidualPolicy(unittest.TestCase):
    def instance(self):
        return dict(config='/private/fpm.conf',pid=123,service='php8.4-fpm.service',
                    values=dict(disable_functions=','.join(p.REQUIRED),enable_dl='Off',sendmail_path='/PRIVATE/MAIL --TOKEN=secret'),
                    pools=dict(a={},b={},c={'php_admin_value[disable_functions]':'putenv,mail'}))

    def test_grouped_policy_reports_possible_functions_without_claiming_availability(self):
        report=p.Report();p.residual_php_policy(report,self.instance())
        self.assertEqual(len(report.rows),2)
        shared=next(row for row in report.rows if row['affected_pools']==['a','b'])
        self.assertEqual(shared['status'],'INFO')
        self.assertTrue(shared['evidence']['policy_only'])
        self.assertIn('putenv',shared['evidence']['not_disabled_functions'])
        narrowed=next(row for row in report.rows if row['affected_pools']==['c'])
        self.assertNotIn('putenv',narrowed['evidence']['not_disabled_functions'])
        self.assertNotIn('mail',narrowed['evidence']['not_disabled_functions'])
        self.assertIn('unavailable in FPM',shared['detail'])
        self.assertNotIn('/PRIVATE/MAIL',json.dumps(report.rows))

    def test_disabled_residuals_and_empty_helper_never_become_a_sandbox_ok(self):
        instance=self.instance();instance['values'].update(disable_functions=','.join(p.RESIDUAL_FUNCTIONS),sendmail_path='')
        report=p.Report();p.residual_php_policy(report,instance)
        self.assertTrue(all(row['status']=='INFO' for row in report.rows))
        self.assertEqual(report.rows[0]['evidence']['not_disabled_functions'],[])
        self.assertEqual(report.rows[0]['evidence']['sendmail_path'],'empty')

    def test_redacted_posture_keeps_only_finite_fields(self):
        report=p.Report();p.residual_php_policy(report,self.instance())
        output=io.StringIO()
        with contextlib.redirect_stdout(output):report.show(True,redact=True)
        text=output.getvalue()
        for value in ('/private','/PRIVATE','secret','php8.4','affected_pools'):self.assertNotIn(value,text)
        self.assertIn('not_disabled_functions',text)

    def test_new_rule_privacy_and_human_german_output(self):
        report=p.Report()
        report.add('INFO','FPM systemd hardening /PRIVATE/FPM','Policy',rule_id='P2S-SYS002',resource=dict(service='/PRIVATE/UNIT'),
                   evidence=dict(assessment='manager_policy',no_new_privileges='yes',private_tmp='/PRIVATE/VALUE',worker_attestation=False,secret='/PRIVATE/EXTRA'))
        report.add('UNKNOWN','Nginx upload execution /PRIVATE/PATH','Policy',rule_id='P2S-NGX001',resource=dict(path='/PRIVATE/PATH'),
                   evidence=dict(outcome='unsupported_regex',candidate_count=1,configuration_only=True,secret='/PRIVATE/EXTRA'))
        output=io.StringIO()
        with contextlib.redirect_stdout(output):report.show(lang='de',redact=True)
        self.assertNotIn('/PRIVATE',output.getvalue())
        self.assertIn('Manager-Policy',output.getvalue())
        self.assertIn('nicht unterstützte Regex',output.getvalue())


class ServicePosture(unittest.TestCase):
    def invoke(self,changes=None,extra='',available=True):
        values=dict(Id='php8.4-fpm.service',LoadState='loaded',ActiveState='active',MainPID='123',
                    NoNewPrivileges='no',ProtectSystem='full',PrivateTmp='yes')
        values.update(changes or {})
        report=p.Report()
        instance=dict(config='/private/fpm.conf',service='php8.4-fpm.service' if available else None,pid=123)
        output='\n'.join(key+'='+value for key,value in values.items())+'\n'+extra
        with patch.object(p,'command',return_value=(output,'')) as run,patch.object(p.shutil,'which',return_value=sys.executable),patch.object(p,'trusted',side_effect=lambda value:value):
            p.fpm_service_posture(report,instance,dict(systemd=True,tools=dict(systemctl=True)))
        return report.rows[0],run

    def test_manager_policy_is_info_and_does_not_attest_workers_or_no_shell(self):
        row,run=self.invoke()
        self.assertEqual(row['status'],'INFO')
        self.assertEqual(row['evidence']['assessment'],'manager_policy')
        self.assertEqual(row['evidence']['no_new_privileges'],'no')
        self.assertFalse(row['evidence']['worker_attestation'])
        self.assertEqual(run.call_args.kwargs['timeout'],5)
        self.assertEqual(run.call_args.args[0][-2:],['--','php8.4-fpm.service'])

    def test_strict_and_disconnected_values_survive_as_policy_only(self):
        row,_=self.invoke(dict(NoNewPrivileges='yes',ProtectSystem='strict',PrivateTmp='disconnected'))
        self.assertEqual(row['status'],'INFO')
        self.assertEqual(row['evidence']['private_tmp'],'disconnected')

    def test_wrong_pid_service_inactive_or_unknown_values_never_pass(self):
        for changes in (dict(MainPID='124'),dict(ActiveState='inactive'),dict(Id='other.service'),dict(LoadState='not-found'),dict(PrivateTmp='perhaps')):
            with self.subTest(changes=changes):self.assertEqual(self.invoke(changes)[0]['status'],'UNKNOWN')
        self.assertEqual(self.invoke(extra='MainPID=123\n')[0]['status'],'UNKNOWN')

    def test_absent_context_is_explicitly_unassessed_without_running_a_helper(self):
        row,run=self.invoke(available=False)
        self.assertEqual(row['status'],'INFO')
        self.assertEqual(row['evidence']['assessment'],'not_assessed')
        run.assert_not_called()


class UploadRoute(unittest.TestCase):
    def route(self,locations,uri='/uploads/',server='',http=''):
        tree=p.parse_nginx('http { '+http+' server { root /srv/site; '+server+' '+locations+' } }')
        return p.nginx_upload_route(tree[0],next(node for node in tree[0]['children'] if node['name']=='server'),uri)

    php=r'location ~ \.php$ { fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass unix:/run/fpm.sock; }'

    def test_global_php_handler_can_process_a_stored_upload(self):
        self.assertEqual(self.route(self.php),('OPEN','php_fastcgi_mapping'))
        self.assertEqual(self.route(r'location / { try_files $uri $uri/ /index.php?$args; } '+self.php)[0],'OPEN')

    def test_nonpreferred_prefix_does_not_block_global_php_regex(self):
        self.assertEqual(self.route('location /uploads/ { return 403; } '+self.php)[0],'OPEN')

    def test_leaf_preferred_rejection_blocks_the_whole_selected_directory(self):
        for code in ('403','404','410','444'):
            self.assertEqual(self.route('location ^~ /uploads/ { return '+code+'; } '+self.php),('OK','static_directory_rejection'))

    def test_descendant_exact_and_longer_prefix_defeat_a_blanket_block_claim(self):
        guard='location ^~ /uploads/ { return 403; } '
        for other in ('location = /uploads/other.php { fastcgi_pass backend; }',
                      'location /uploads/private/ { fastcgi_pass backend; }'):
            self.assertNotEqual(self.route(guard+other+self.php)[0],'OK')
        self.assertNotEqual(self.route(guard+'location /uploads/private/ { fastcgi_pass backend; }',uri='/uploads/private/deeper/')[0],'OK')

    def test_error_pages_rewrites_conditions_or_unknown_modules_never_prove_blocking(self):
        guard='location ^~ /uploads/ { return 403; } '+self.php
        for server in ('error_page 403 = /index.php;', 'rewrite ^ /index.php last;', 'if ($arg_x) { return 200; }', 'js_rewrite handler;'):
            self.assertEqual(self.route(guard,server=server)[0],'UNKNOWN')
        self.assertEqual(self.route(guard,http='error_page 403 = /index.php;')[0],'UNKNOWN')

    def test_arbitrary_regex_is_not_executed_and_front_controller_is_not_uploaded_php(self):
        self.assertEqual(self.route('location ~ (a+)+$ { return 403; } '+self.php)[0],'UNKNOWN')
        front=self.php.replace('$document_root$fastcgi_script_name','$document_root/index.php')
        self.assertEqual(self.route(front)[0],'UNKNOWN')

    def test_nested_alias_named_and_predicate_locations_remain_unknown(self):
        for extra in (r'location /uploads/ { location ~ \.php$ { return 403; } }',
                      'location /files/ { alias /srv/site/uploads/; }',
                      'location @handler { fastcgi_pass backend; }',
                      'location $arg_x { return 403; }'):
            self.assertEqual(self.route(extra+' '+self.php)[0],'UNKNOWN')

    def test_literal_denial_regex_does_not_hide_a_php_handler_witness(self):
        self.assertEqual(self.route(r'location ~ /\.(env|git) { deny all; } '+self.php)[0],'OPEN')

    def test_special_uri_and_unknown_script_mapping_never_get_ok(self):
        self.assertEqual(self.route('location ^~ /uploads/ { return 403; }',uri='/uploads/?x/')[0],'UNKNOWN')
        self.assertEqual(self.route(self.php.replace('$document_root$fastcgi_script_name','$request_filename'))[0],'UNKNOWN')
        for directive in ('deny all;', 'auth_basic restricted;', 'set $uri /index.php;', 'try_files /index.php =404;', 'js_content handler;'):
            self.assertEqual(self.route(self.php.replace('fastcgi_pass',directive+' fastcgi_pass'))[0],'UNKNOWN')


@unittest.skipUnless(sys.platform=='linux','Linux path mapping')
class UploadScope(unittest.TestCase):
    def test_declared_and_automatic_candidates_and_missing_mapping_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'uploads').mkdir();(root/'cache').mkdir()
            tree=p.parse_nginx('http { server { root '+str(root)+'; '+UploadRoute.php+' } }')
            args=argparse.Namespace(root=str(root),roots=[str(root)],nginx_tree=tree,nginx_config=None,runtime_dirs=[str(root/'cache')])
            report=p.Report();p.nginx_upload_security(report,args)
            self.assertEqual(len(report.rows),2)
            self.assertTrue(all(row['status']=='OPEN' for row in report.rows))
            self.assertEqual({row['resource']['path'] for row in report.rows},{str(root/'cache'),str(root/'uploads')})
            args.nginx_tree=None
            report=p.Report();p.nginx_upload_security(report,args)
            self.assertEqual(report.rows[0]['status'],'UNKNOWN')

    def test_no_known_storage_is_unassessed_and_upload_only_vhost_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            args=argparse.Namespace(root=str(root),roots=[str(root)],nginx_tree=p.parse_nginx('http { server { root '+str(root)+'; } }'),nginx_config=None,runtime_dirs=[])
            report=p.Report();p.nginx_upload_security(report,args)
            self.assertEqual(report.rows[0]['evidence']['outcome'],'not_assessed')
            (root/'uploads').mkdir()
            args.runtime_dirs=[str(root/'uploads')]
            args.nginx_tree=p.parse_nginx('http { server { root '+str(root)+'; location ^~ /uploads/ { return 403; } } server { root '+str(root/'uploads')+'; '+UploadRoute.php+' } }')
            report=p.Report();p.nginx_upload_security(report,args)
            self.assertEqual([row['status'] for row in report.rows],['OK','OPEN'])
            args.nginx_tree=p.parse_nginx('http { server { root '+str(root)+'; location ^~ /uploads/ { return 403; } } server { root /elsewhere; location /files/ { alias '+str(root/'uploads')+'/; } } }')
            report=p.Report();p.nginx_upload_security(report,args)
            self.assertEqual(report.rows[0]['status'],'UNKNOWN')


if __name__=='__main__':unittest.main()
