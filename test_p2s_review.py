"""Independent causes, useful private facts and verified localhost resolution."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import p2s_harden as p


@unittest.skipUnless(sys.platform == "linux", "host audit fixtures")
class AggregatedPolicies(unittest.TestCase):
    def scan(self, overrides=None, missing=("popen",), include="On"):
        with tempfile.TemporaryDirectory() as temporary:
            ini=Path(temporary)/"php.ini"
            disabled=",".join(sorted(p.REQUIRED-set(missing)))
            ini.write_text("disable_functions="+disabled+"\nallow_url_include="+include+"\n")
            pools={str(index):dict(user="www-data",listen="127.0.0.1:9000") for index in range(20)}
            for name,values in (overrides or {}).items(): pools[name].update(values)
            instance=dict(config="/fixture/fpm.conf",values={"disable_functions":disabled,"allow_url_include":include},
                          pools=pools,inis=[str(ini)],pid=123)
            args=argparse.Namespace(web_user=[],root=temporary,site=[],no_progress=True)
            data=json.dumps(dict(files=0,directories=0,file_sample=[],directory_sample=[],errors=[]))
            with patch.object(p,"discover",return_value=([instance],[])), patch.object(p,"as_user",return_value=data):
                report,updates,_,_=p.scan(args)
        return report,updates

    def rows(self, report, rule): return [row for row in report.rows if row["rule_id"]==rule]

    def test_twenty_unchanged_pools_share_one_finding_per_global_policy(self):
        report,updates=self.scan()
        for rule in ("P2S-PHP001","P2S-PHP002"):
            rows=self.rows(report,rule)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]["evidence"]["affected_pool_count"],20)
            self.assertEqual(len(rows[0]["affected_pools"]),20)
            self.assertEqual(rows[0]["resource"],dict(config="/fixture/fpm.conf"))
        self.assertTrue(updates)

    def test_different_missing_function_sets_are_not_merged_just_because_both_are_open(self):
        report,_=self.scan({"0":{"php_admin_value[disable_functions]":"exec"}},missing=("exec","popen"))
        rows=self.rows(report,"P2S-PHP001")
        self.assertEqual([r["status"] for r in rows],["OPEN","OPEN"])
        self.assertEqual(rows[1]["evidence"]["missing_functions"],["popen"])
        self.assertEqual(rows[0]["evidence"]["affected_pool_count"],19)

    def test_distinct_pool_include_override_remains_visible(self):
        report,_=self.scan({"0":{"php_admin_flag[allow_url_include]":"On"}},include="Off")
        rows=self.rows(report,"P2S-PHP002")
        self.assertEqual([r["status"] for r in rows],["OK","OPEN"])
        self.assertEqual(rows[1]["resource"]["pool"],"0")

    def test_explicit_unsafe_override_is_a_separate_cause_even_when_equal_to_global(self):
        report,_=self.scan({"0":{"php_admin_flag[allow_url_include]":"On"}},include="On")
        rows=self.rows(report,"P2S-PHP002")
        self.assertEqual([r["status"] for r in rows],["OPEN","OPEN"])
        self.assertEqual(rows[0]["evidence"]["affected_pool_count"],19)

    def test_equivalent_false_spellings_do_not_duplicate_a_safe_policy(self):
        report,_=self.scan({"0":{"php_admin_value[allow_url_include]":"0"}},include="Off")
        self.assertEqual(len(self.rows(report,"P2S-PHP002")),1)


class PrivateFacts(unittest.TestCase):
    def test_useful_approved_facts_survive_in_text_and_json_without_host_strings(self):
        report=p.Report()
        secret="PRIVATE@example.test:/srv/tenant:9000"
        report.add("OPEN",secret,secret,rule_id="P2S-PHP001",resource=secret,
                   evidence=dict(missing_functions=["popen"],affected_pool_count=3,private=secret))
        report.add("OPEN",secret,secret,rule_id="P2S-FPM002",resource=secret,
                   evidence=dict(socket_mode="0666",source="observed",path=secret))
        for as_json in (True,False):
            output=io.StringIO()
            with contextlib.redirect_stdout(output): report.show(as_json,redact=True,verbose=True)
            text=output.getvalue()
            self.assertNotIn(secret,text)
            self.assertIn("popen",text)
            self.assertIn("0666",text)
            if as_json:
                rows=json.loads(text)["findings"]
                self.assertEqual(rows[0]["evidence"],dict(missing_functions=["popen"],affected_pool_count=3))
                self.assertEqual(rows[1]["evidence"],dict(socket_mode="0666",source="observed"))

    def test_unapproved_types_values_and_nested_diagnostics_are_removed(self):
        secret="PRIVATE-CANARY"
        for rule,evidence in (
            ("PHP001",dict(missing_functions=[secret],affected_pool_count=secret)),
            ("FPM002",dict(socket_mode=secret,source=secret)),
            ("FPM003",dict(allowed_known_extensions=[secret],other_extension_count=True)),
            ("PHP004",dict(ffi_policy=secret)),
            ("FPM001",dict(client_allowlist=secret,binding={secret:secret})),
        ):
            self.assertEqual(p.safe_evidence("P2S-"+rule,evidence),{})
        self.assertEqual(p.safe_evidence("P2S-CUSTOM",dict(private=secret)),{})

    def test_redaction_validates_again_after_future_code_mutates_evidence(self):
        report=p.Report()
        row=report.add("OPEN","title","detail",rule_id="P2S-FPM002",evidence=dict(socket_mode="0666"))
        row["evidence"]["socket_mode"]="PRIVATE-CANARY"
        row["affected_pools"]=["PRIVATE-CANARY"]
        out=io.StringIO()
        with contextlib.redirect_stdout(out): report.show(True,redact=True)
        self.assertNotIn("PRIVATE-CANARY",out.getvalue())


class LocalhostPolicy(unittest.TestCase):
    def report(self, pools=1):
        report=p.Report()
        p.pool_security(report,dict(config="/fixture",values={},pools={str(i):{"listen":"localhost:9000"} for i in range(pools)}))
        return [row for row in report.rows if row["rule_id"]=="P2S-FPM001"]

    def test_verified_localhost_resolution_is_cached_with_a_deadline(self):
        with patch.object(p,"command",return_value=('["127.0.0.1","::1"]',"")) as command:
            rows=self.report(3)
        self.assertEqual([r["status"] for r in rows],["OK"]*3)
        self.assertEqual(rows[0]["evidence"]["hostname_resolution"],"loopback")
        self.assertEqual(command.call_count,1)
        self.assertEqual(command.call_args.kwargs["timeout"],2)

    def test_non_loopback_localhost_mapping_never_passes(self):
        with patch.object(p,"command",return_value=('["127.0.0.1","192.0.2.10"]',"")):
            row=self.report()[0]
        self.assertEqual(row["status"],"OPEN")
        self.assertEqual(row["evidence"]["hostname_resolution"],"non_loopback")

    def test_resolution_failure_or_malformed_result_is_unknown_and_cached(self):
        for reply in ("[]", "{}", '["invalid"]'):
            with patch.object(p,"command",return_value=(reply,"")) as command:
                self.assertEqual([r["status"] for r in self.report(2)],["UNKNOWN","UNKNOWN"])
                self.assertEqual(command.call_count,1)
        with patch.object(p,"command",side_effect=p.CheckError("timeout")):
            self.assertEqual(self.report()[0]["status"],"UNKNOWN")

    @unittest.skipUnless(sys.platform=="linux", "real Linux name service")
    def test_actual_host_localhost_lookup_is_loopback(self):
        self.assertTrue(p.localhost_loopback("localhost",{}))


if __name__=="__main__": unittest.main()
