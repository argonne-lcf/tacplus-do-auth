import sys
import unittest
from TacplusCmd import (
  DoAuthExecutor,
  DOAUTH_UNCOND_PERMIT,
  DOAUTH_UNCOND_DENY,
  DOAUTH_COND_PERMIT
)
import TacplusMapping as tacmap

class TestUserGroups(unittest.TestCase):
    def setUp(self):
        self.cfg_found_template = "found in config"
        self.cfg_not_found_template = "not found in config"
        self.not_associated_template = "Error: associating"
        self.match_group_apply_template = "match_group_apply:"

        self.baduser = "zurg"
        self.badgroup = "clowns"

        tacmap.organize()

        initcmd = f"{tacmap.doauth_cmd} --conf={tacmap.doauth_cfg} --debug"
        self.doauth = DoAuthExecutor(initcmd, libpath=tacmap.doauth_lib)

    def test_badUser(self):
        search = f"{self.baduser} {self.cfg_not_found_template}"
        params = self.doauth.format_kwargs(
                   user=self.baduser,
                   nas="1.2.3.4",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_badGroup(self):
        search = f"{self.not_associated_template} {tacmap.gooduser0} to group option: {self.badgroup}.None"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser0,
                   nas="1.2.3.4",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_user1FoundInCfg(self):
        search = f"{tacmap.gooduser1} {self.cfg_found_template}"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas="1.2.3.4",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_user2FoundInCfg(self):
        search = f"{tacmap.gooduser2} {self.cfg_found_template}"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser2,
                   nas="1.2.3.4",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_user3FoundInCfg(self):
        search = f"{tacmap.gooduser3} {self.cfg_found_template}"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas="1.2.3.4",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_user4FoundInCfg(self):
        search = f"{tacmap.gooduser4} {self.cfg_found_template}"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas="1.2.3.4",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_user5FoundInCfg(self):
        search = f"{tacmap.gooduser5} {self.cfg_found_template}"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser5,
                   nas="1.2.3.4",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_noRulesEvaluated_validGroups(self):
        search = "no rules evaluted; no authorization given"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas="1.2.3.4",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr1_grp1(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp1_1}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas="10.10.0.10",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr1_grp2(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp1_2}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas="10.0.0.10",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr2_grp1(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp2_1}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser2,
                   nas="10.0.0.10",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr2_grp2(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp2_2}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser2,
                   nas="10.10.0.10",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr3_grp1(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp3_1}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas="10.0.0.10",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr3_grp2(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp3_2}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas="10.10.0.10",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr4_grp1(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp4_1}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas="10.0.0.10",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr4_grp2(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp4_2}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas="10.10.0.10",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_rulesEvaluated_usr5_grp1(self):
        search = f"{self.match_group_apply_template} {tacmap.goodusergrp5_1}.host_match_apply evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser5,
                   nas="1.1.1.1",
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.search_stderr(search), True)


if __name__ == '__main__':
    unittest.main(buffer=True)
