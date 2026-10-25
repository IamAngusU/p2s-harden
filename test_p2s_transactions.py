"""Transaction recovery checks using disposable, root-owned Linux fixtures."""
import contextlib
import io
import os
from pathlib import Path
import pwd
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import p2s_harden as p


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "root Linux fixtures required")
class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="p2s-transactions-", dir=Path.cwd())
        self.root = Path(self.temp.name)
        lock_path = patch.object(p, "TRANSACTION_LOCK_ROOT", str(self.root / "system-transaction-lock"))
        lock_path.start()
        self.addCleanup(lock_path.stop)
        self.ini = self.make_ini("php.ini")
        self.backups = self.root / "backups"

    def tearDown(self):
        self.temp.cleanup()

    def make_ini(self, name):
        path = self.root / name
        path.write_bytes(b"allow_url_include=On\n")
        path.chmod(0o640)
        os.utime(path, ns=(1_600_000_000_000_000_000, 1_600_000_000_123_456_789))
        return path

    def prepare(self, *paths):
        tx = p.Transaction(self.backups)
        tx.prepare({str(path): {"allow_url_include": "Off"} for path in paths}, [], [])
        return tx

    def apply(self, tx):
        with contextlib.redirect_stdout(io.StringIO()):
            tx.apply([], [])

    def rollback(self, backup_id=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return p.Transaction.rollback(self.backups, backup_id)

    def stage_file(self, tx, item):
        item["started"] = True
        tx.save()
        path = Path(item["path"])
        data = p.set_ini(path.read_text(), item["values"]).encode()
        p.atomic_bytes(path, data, item["meta"], preserve_timestamps=False,
                       before_replace=lambda meta: tx.checkpoint(item, "after_meta", meta))

    def replace_same_state(self, path):
        original = p.metadata(path)
        replacement = path.with_suffix(".replacement")
        p.atomic_bytes(replacement, path.read_bytes(), original)
        os.replace(replacement, path)

    def rename_backup(self, tx, name, created_ns):
        destination = tx.root / name
        tx.path.rename(destination)
        tx.path = destination
        tx.data["created_ns"] = created_ns
        tx.save()

    def test_fix_has_fresh_mtime_and_rollback_restores_original_mtime(self):
        original, meta = self.ini.read_bytes(), p.metadata(self.ini)
        tx = self.prepare(self.ini)
        self.apply(tx)
        self.assertNotEqual(self.ini.stat().st_mtime_ns, meta["mtime_ns"])
        self.assertTrue(p.same_permissions(p.metadata(self.ini), meta))
        result = self.rollback()
        self.assertEqual(result.path, tx.path)
        self.assertFalse(result.noop)
        self.assertEqual(result.data["status"], "rolled_back")
        self.assertEqual(self.ini.read_bytes(), original)
        self.assertEqual(self.ini.stat().st_mtime_ns, meta["mtime_ns"])

    def test_timestamp_change_before_apply_is_not_overwritten(self):
        tx = self.prepare(self.ini)
        changed = self.ini.stat().st_mtime_ns + 1_000_000_000
        os.utime(self.ini, ns=(changed, changed))
        with self.assertRaises(p.CheckError):
            self.apply(tx)
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include=On\n")
        self.assertEqual(self.ini.stat().st_mtime_ns, changed)

    def test_timestamp_change_after_apply_blocks_rollback(self):
        tx = self.prepare(self.ini)
        self.apply(tx)
        changed = self.ini.stat().st_mtime_ns + 1_000_000_000
        os.utime(self.ini, ns=(changed, changed))
        with self.assertRaises(p.CheckError):
            self.rollback()
        self.assertIn(b"Off", self.ini.read_bytes())
        self.assertEqual(self.ini.stat().st_mtime_ns, changed)

    def test_replaced_file_before_apply_is_not_overwritten(self):
        tx = self.prepare(self.ini)
        self.replace_same_state(self.ini)
        inode = self.ini.stat().st_ino
        with self.assertRaises(p.CheckError):
            self.apply(tx)
        self.assertEqual(self.ini.stat().st_ino, inode)
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include=On\n")

    def test_replaced_file_after_apply_blocks_rollback(self):
        tx = self.prepare(self.ini)
        self.apply(tx)
        self.replace_same_state(self.ini)
        inode = self.ini.stat().st_ino
        with self.assertRaises(p.CheckError):
            self.rollback()
        self.assertEqual(self.ini.stat().st_ino, inode)
        self.assertIn(b"Off", self.ini.read_bytes())

    def test_permission_change_after_apply_blocks_rollback(self):
        tx = self.prepare(self.ini)
        self.apply(tx)
        self.ini.chmod(0o600)
        with self.assertRaises(p.CheckError):
            self.rollback()
        self.assertEqual(self.ini.stat().st_mode & 0o777, 0o600)
        self.assertIn(b"Off", self.ini.read_bytes())

    def test_xattr_change_after_apply_blocks_rollback(self):
        tx = self.prepare(self.ini)
        self.apply(tx)
        os.setxattr(self.ini, "user.external-change", b"keep")
        with self.assertRaises(p.CheckError):
            self.rollback()
        self.assertEqual(os.getxattr(self.ini, "user.external-change"), b"keep")

    def test_read_access_times_do_not_create_a_false_conflict(self):
        tx = self.prepare(self.ini)
        old_mtime = self.ini.stat().st_mtime_ns
        os.utime(self.ini, ns=(old_mtime + 9_000_000_000, old_mtime))
        self.apply(tx)
        changed_mtime = self.ini.stat().st_mtime_ns
        os.utime(self.ini, ns=(changed_mtime + 9_000_000_000, changed_mtime))
        self.rollback()
        self.assertEqual(self.ini.stat().st_mtime_ns, old_mtime)

    def test_repeated_default_rollback_never_selects_an_older_transaction(self):
        older = self.prepare(self.ini)
        self.apply(older)
        second = self.make_ini("z.ini")
        latest = self.prepare(second)
        self.apply(latest)
        self.rollback()
        result = self.rollback()
        self.assertEqual(result.path, latest.path)
        self.assertTrue(result.noop)
        self.assertIn(b"Off", self.ini.read_bytes())
        self.assertEqual(second.read_bytes(), b"allow_url_include=On\n")

    def test_concurrent_fix_prepare_apply_and_rollback_are_refused_without_changes(self):
        tx=self.prepare(self.ini)
        self.apply(tx)
        original=self.ini.read_bytes()
        before={path.name for path in self.backups.iterdir()}
        code='''import json,sys
from pathlib import Path
import p2s_harden as p
p.TRANSACTION_LOCK_ROOT=sys.argv[5]
try:
    tx=p.Transaction(sys.argv[1])
    if sys.argv[4].startswith('prepare'):tx.prepare({sys.argv[2]:{'allow_url_include':'Off'}},[],[])
    elif sys.argv[4]=='apply':
        tx.path=Path(sys.argv[3]);tx.data=json.loads((tx.path/'manifest.json').read_text());tx.apply([],[])
    else:p.Transaction.rollback(sys.argv[1])
except p.CheckError as exc:
    print(str(exc));sys.exit(3)
'''
        with tx.locked():
            for operation in ('prepare','apply','rollback','prepare-alternate-root'):
                with self.subTest(operation=operation):
                    backup_root=self.root/'alternate-backups' if operation=='prepare-alternate-root' else self.backups
                    run=subprocess.run([sys.executable,'-B','-c',code,str(backup_root),str(self.ini),str(tx.path),operation,p.TRANSACTION_LOCK_ROOT],capture_output=True,text=True,timeout=10)
                    self.assertEqual(run.returncode,3,run.stdout+run.stderr)
                    self.assertIn('Another fix or rollback',run.stdout)
                    self.assertEqual(self.ini.read_bytes(),original)
                    self.assertEqual({path.name for path in self.backups.iterdir()},before)
            self.assertFalse((self.root/'alternate-backups').exists())
        self.rollback()
        self.assertEqual(self.ini.read_bytes(),b'allow_url_include=On\n')

    def test_kernel_releases_transaction_lock_after_process_is_terminated(self):
        tx=self.prepare(self.ini)
        code="import sys,time; import p2s_harden as p; p.TRANSACTION_LOCK_ROOT=sys.argv[2]; tx=p.Transaction(sys.argv[1]); guard=tx.locked(); guard.__enter__(); print('locked',flush=True); time.sleep(30)"
        child=subprocess.Popen([sys.executable,'-B','-c',code,str(self.backups),p.TRANSACTION_LOCK_ROOT],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'locked')
            with self.assertRaisesRegex(p.CheckError,'Another fix or rollback'):
                self.apply(tx)
        finally:
            child.terminate()
            child.communicate(timeout=10)
        self.apply(tx)
        self.assertIn(b'Off',self.ini.read_bytes())

    def test_lock_refuses_symlinks_writable_roots_and_special_files(self):
        self.backups.mkdir(mode=0o700)
        alias=self.root/'alias'
        alias.symlink_to(self.backups,target_is_directory=True)
        with self.assertRaises(p.CheckError),p.Transaction(alias).locked():pass
        self.backups.chmod(0o770)
        with self.assertRaises(p.CheckError),p.Transaction(self.backups).locked():pass
        self.backups.chmod(0o700)
        fifo=self.root/'fifo'
        os.mkfifo(fifo,mode=0o600)
        with self.assertRaises(OSError),p.Transaction(fifo).locked():pass

    def test_global_lock_also_blocks_a_different_backup_root(self):
        tx=self.prepare(self.ini)
        other=p.Transaction(self.root/'different-backups')
        with tx.locked(),self.assertRaisesRegex(p.CheckError,'Another fix or rollback'):
            other.prepare({str(self.ini):{'allow_url_include':'Off'}},[],[])
        self.assertFalse(other.root.exists())
        other.prepare({str(self.ini):{'allow_url_include':'Off'}},[],[])

    def test_multiline_ini_is_refused_before_any_configuration_change(self):
        self.ini.write_bytes(b'disable_functions="exec,\nsystem"\nmemory_limit=379M\n')
        before=self.ini.read_bytes()
        with self.assertRaisesRegex(p.CheckError,'quotes'):
            self.prepare(self.ini)
        self.assertEqual(self.ini.read_bytes(),before)

    def test_ini_crlf_bom_roundtrip_preserves_unrelated_bytes_and_backup(self):
        original=b'\xef\xbb\xbf; keep this comment\r\nmemory_limit=379M\r\nallow_url_include=On\r\n'
        self.ini.write_bytes(original)
        tx=self.prepare(self.ini)
        self.assertEqual((tx.path/tx.data['files'][0]['backup']).read_bytes(),original)
        self.apply(tx)
        self.assertEqual(self.ini.read_bytes(),original.replace(b'allow_url_include=On',b'allow_url_include = Off'))
        self.rollback()
        self.assertEqual(self.ini.read_bytes(),original)

    def test_missing_fpm_instance_or_ambiguous_snapshot_refuses_before_target_write(self):
        instance=dict(pid=123,start='fixture',binary=str(self.ini),config=str(self.ini),service='fixture.service',
                      env={},inis=[str(self.ini)])
        for instances,command_result,message in (([],None,'Complete FPM'),([instance],('not an INI table',''),'snapshot')):
            with self.subTest(message=message):
                tx=p.Transaction(self.backups)
                tx.prepare({str(self.ini):{'allow_url_include':'Off'}},[],[instance])
                with patch.object(p,'command',return_value=command_result),patch.object(p,'reload_instances') as reload:
                    with self.assertRaisesRegex(p.CheckError,message):
                        tx.apply(instances,[])
                reload.assert_not_called()
                self.assertEqual(self.ini.read_bytes(),b'allow_url_include=On\n')
                self.assertFalse(tx.data['files'][0].get('started',False))

    def test_unrelated_effective_setting_change_is_restored_before_reload(self):
        instance=dict(pid=123,start='fixture',binary=str(self.ini),config=str(self.ini),service='fixture.service',
                      env={},inis=[str(self.ini)])
        tx=p.Transaction(self.backups)
        tx.prepare({str(self.ini):{'allow_url_include':'Off'}},[],[instance])
        table='Directive => Local Value => Master Value\ndisable_functions => '+','.join(sorted(p.REQUIRED))+' => '+','.join(sorted(p.REQUIRED))+'\n'
        before=table+'allow_url_include => On => On\nmemory_limit => 379M => 379M\n'
        after=table+'allow_url_include => Off => Off\nmemory_limit => 128M => 128M\n'
        infos=iter([before,after])
        def command(argv,**kwargs):
            return (next(infos),'') if '-i' in argv else ('123\n','')
        with patch.object(p,'command',side_effect=command),patch.object(p,'reload_instances') as reload, self.assertRaisesRegex(p.CheckError,'Unrelated effective'):
            tx.apply([instance],[])
        reload.assert_not_called()
        self.assertEqual(self.ini.read_bytes(),b'allow_url_include=On\n')
        self.assertEqual(tx.data['status'],'rolled_back')

    def test_latest_unstarted_transaction_does_not_fall_back(self):
        older = self.prepare(self.ini)
        self.apply(older)
        second = self.make_ini("z.ini")
        latest = self.prepare(second)
        result = self.rollback()
        self.assertEqual(result.path, latest.path)
        self.assertTrue(result.noop)
        self.assertEqual(result.data["status"], "prepared")
        self.assertIn(b"Off", self.ini.read_bytes())

    def test_unknown_latest_status_requires_explicit_selection(self):
        older = self.prepare(self.ini)
        self.apply(older)
        latest = self.prepare(self.make_ini("z.ini"))
        latest.data["status"] = "unrecognized"
        latest.save()
        with self.assertRaisesRegex(p.CheckError, "--backup-id"):
            self.rollback()
        self.assertIn(b"Off", self.ini.read_bytes())

    def test_creation_order_wins_over_random_id_within_the_same_second(self):
        older = self.prepare(self.ini)
        self.apply(older)
        latest = self.prepare(self.make_ini("z.ini"))
        self.rename_backup(older, "20260101T000000-ffffffffff", 10)
        self.rename_backup(latest, "20260101T000000-0000000000", 20)
        result = self.rollback()
        self.assertEqual(result.path, latest.path)
        self.assertTrue(result.noop)
        self.assertIn(b"Off", self.ini.read_bytes())

    def test_ambiguous_legacy_order_requires_backup_id(self):
        older = self.prepare(self.ini)
        latest = self.prepare(self.make_ini("z.ini"))
        self.rename_backup(older, "20260101T000000-ffffffffff", 10)
        self.rename_backup(latest, "20260101T000000-0000000000", 20)
        del older.data["created_ns"]
        older.save()
        with self.assertRaisesRegex(p.CheckError, "--backup-id"):
            self.rollback()

    def test_older_transaction_requires_and_accepts_its_explicit_id(self):
        older = self.prepare(self.ini)
        self.apply(older)
        latest = self.prepare(self.make_ini("z.ini"))
        self.apply(latest)
        self.rollback()
        result = self.rollback(older.path.name)
        self.assertEqual(result.path, older.path)
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include=On\n")

    def test_interruption_before_replacement_leaves_original_inode_intact(self):
        tx = self.prepare(self.ini)
        item = tx.data["files"][0]
        inode = self.ini.stat().st_ino
        real_replace = p.os.replace

        def interrupted(source, target):
            if Path(target) == self.ini:
                raise OSError("interrupted before target replacement")
            return real_replace(source, target)

        with patch.object(p.os, "replace", side_effect=interrupted), self.assertRaises(OSError):
            self.stage_file(tx, item)
        self.assertIn("after_meta", item)
        self.rollback()
        self.assertEqual(self.ini.stat().st_ino, inode)
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include=On\n")

    def test_interrupted_fix_with_fresh_mtime_can_be_recovered(self):
        tx = self.prepare(self.ini)
        original = p.metadata(self.ini)
        self.stage_file(tx, tx.data["files"][0])
        self.assertNotEqual(self.ini.stat().st_mtime_ns, original["mtime_ns"])
        result = self.rollback()
        self.assertEqual(result.data["status"], "rolled_back")
        self.assertEqual(self.ini.stat().st_mtime_ns, original["mtime_ns"])
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include=On\n")

    def test_interrupted_fix_preserves_unstarted_files(self):
        second = self.make_ini("z.ini")
        tx = self.prepare(self.ini, second)
        self.stage_file(tx, tx.data["files"][0])
        second.write_bytes(b"independent edit\n")
        self.rollback()
        self.assertEqual(second.read_bytes(), b"independent edit\n")
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include=On\n")

    def test_interrupted_rollback_resumes_without_replacing_restored_files(self):
        second = self.make_ini("z.ini")
        tx = self.prepare(self.ini, second)
        self.apply(tx)
        real_atomic = p.atomic_bytes

        def interrupted(path, *args, **kwargs):
            if Path(path) == second:
                raise OSError("interrupted during second restore")
            return real_atomic(path, *args, **kwargs)

        with patch.object(p, "atomic_bytes", side_effect=interrupted), self.assertRaises(OSError):
            self.rollback()
        inode = self.ini.stat().st_ino
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include=On\n")
        self.assertIn(b"Off", second.read_bytes())
        result = self.rollback()
        self.assertEqual(result.data["status"], "rolled_back")
        self.assertEqual(self.ini.stat().st_ino, inode)
        self.assertEqual(second.read_bytes(), b"allow_url_include=On\n")

    def test_service_recovery_failure_remains_retryable(self):
        tx = self.prepare(self.ini)
        self.apply(tx)
        tx.data["instances"] = [{"binary": str(self.ini), "config": str(self.ini), "service": "fixture.service"}]
        tx.save()
        with patch.object(p, "command", side_effect=p.CheckError("service recovery failed")), self.assertRaises(p.CheckError):
            self.rollback()
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include=On\n")
        with patch.object(p, "command", return_value=("123\n", "")):
            result = self.rollback()
        self.assertEqual(result.data["status"], "rolled_back")

    def test_all_file_conflicts_are_checked_before_any_restore(self):
        second = self.make_ini("z.ini")
        tx = self.prepare(self.ini, second)
        self.apply(tx)
        second.chmod(0o600)
        with self.assertRaises(p.CheckError):
            self.rollback()
        self.assertIn(b"Off", self.ini.read_bytes())
        self.assertIn(b"Off", second.read_bytes())

    def make_acl_directory(self):
        path = self.root / "code"
        path.mkdir()
        worker = pwd.getpwnam("www-data")
        os.chown(path, worker.pw_uid, worker.pw_gid)
        path.chmod(0o775)
        acl = struct.pack("<I", 2)
        for tag, perms, uid in ((1, 7, 0xffffffff), (2, 7, 65534), (4, 7, 0xffffffff), (16, 7, 0xffffffff), (32, 5, 0xffffffff)):
            acl += struct.pack("<HHI", tag, perms, uid)
        os.setxattr(path, "system.posix_acl_access", acl)
        tx = p.Transaction(self.backups)
        tx.prepare({}, [str(path)], [])
        return path, tx

    def test_interrupted_directory_chmod_restores_original_acl(self):
        path, tx = self.make_acl_directory()
        item = tx.data["directories"][0]
        before = item["meta"]
        item["started"] = True
        tx.save()
        os.chown(path, 0, before["gid"])
        os.chmod(path, before["mode"] & ~0o022)
        self.rollback()
        self.assertTrue(p.Transaction.same_state(p.metadata(path), before))

    def test_interrupted_directory_rollback_after_owner_restore_resumes(self):
        path, tx = self.make_acl_directory()
        self.apply(tx)
        before = tx.data["directories"][0]["meta"]
        tx.data["status"] = "rolling_back"
        tx.save()
        os.chown(path, before["uid"], before["gid"])
        self.rollback()
        self.assertTrue(p.Transaction.same_state(p.metadata(path), before))

    def test_directory_timestamp_conflict_is_not_overwritten(self):
        path, tx = self.make_acl_directory()
        self.apply(tx)
        changed = path.stat().st_mtime_ns + 1_000_000_000
        os.utime(path, ns=(changed, changed))
        with self.assertRaises(p.CheckError):
            self.rollback()
        self.assertEqual(path.stat().st_mtime_ns, changed)
        self.assertEqual(path.stat().st_uid, 0)


if __name__ == "__main__":
    unittest.main()
