"""Refuse ambiguous edits and preserve formatting without implementing PHP."""
import unittest

import p2s_harden as p


class IniEditing(unittest.TestCase):
    def test_multiline_quotes_in_targets_or_unrelated_values_are_refused(self):
        for text in ('disable_functions="exec,\nsystem"\nmemory_limit=379M\n',
                     "disable_functions='exec,\nsystem'\nmemory_limit=379M\n",
                     'custom="first\nallow_url_include=On\nlast"\n',
                     'disable_functions="exec,system\n',
                     'custom="line\\\nnext"\n'):
            with self.subTest(text=text),self.assertRaisesRegex(p.CheckError,'quotes'):
                p.set_ini(text,dict(disable_functions='exec,system',allow_url_include='Off'))

    def test_comments_and_balanced_escaped_quotes_do_not_look_multiline(self):
        for text in ('; a lone " in a comment\nallow_url_include=On ; "\n',
                     '# another lone "\nallow_url_include=On\n',
                     'custom="a \\" quoted value"\nallow_url_include=On\n',
                     'custom="it\'s valid"\nallow_url_include=On\n'):
            self.assertIn('allow_url_include = Off',p.set_ini(text,dict(allow_url_include='Off')))

    def test_crlf_bom_duplicate_and_missing_keys_preserve_other_bytes(self):
        old='\ufeffdisable_functions=exec\r\n; keep\r\nmemory_limit=379M\r\ndisable_functions="system"\r\n'
        new=p.set_ini(old,dict(disable_functions='exec,system',allow_url_include='Off'))
        self.assertTrue(new.startswith('\ufeffdisable_functions=exec\r\n; keep\r\nmemory_limit=379M\r\n'))
        self.assertNotIn('\n',new.replace('\r\n',''))
        self.assertEqual(new.count('[PHP]'),1)
        self.assertEqual(p.active_ini_lines(new,'disable_functions'),[0,3])
        one=p.set_ini('\ufeffdisable_functions=exec\r\n',dict(disable_functions='system'))
        self.assertEqual(one,'\ufeffdisable_functions = system\r\n')
        appended=p.set_ini('memory_limit=379M\r\n',dict(disable_functions='exec',allow_url_include='Off'))
        self.assertEqual(appended.count('[PHP]'),1)

    def test_snapshot_has_only_typed_directives_and_never_values_or_environment(self):
        text='Directive => Local Value => Master Value\n'
        text+='disable_functions => exec => exec\nallow_url_include => Off => Off\nmemory_limit => 379M => 379M\n'
        text+='\nEnvironment\nPRIVATE_ENV => TOP_SECRET\n'
        values=p.ini_snapshot(text)
        self.assertEqual(set(values),{'disable_functions','allow_url_include','memory_limit'})
        self.assertNotIn('379M',str(values))
        self.assertNotIn('TOP_SECRET',str(values))
        for malformed in ('PHP Version => 8.3\n',text+'Directive => Local Value => Master Value\nmemory_limit => 512M => 512M\n',text+'Directive => Local Value => Master Value\ncustom => bad => delimiter => ambiguity\n'):
            with self.assertRaises(p.CheckError):p.ini_snapshot(malformed)


if __name__=='__main__':unittest.main()
