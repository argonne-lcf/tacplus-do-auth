import sys
import unittest
from TacplusCmd import (
  DoAuthExecutor,
  DOAUTH_UNCOND_PERMIT,
  DOAUTH_UNCOND_DENY,
  DOAUTH_COND_PERMIT
)
import TacplusMapping as tacmap

class TestHostCfgs(unittest.TestCase):
    def setUp(self):
        tacmap.organize()

        initcmd = f"{tacmap.doauth_cmd} --conf={tacmap.doauth_cfg} --debug"
        self.doauth = DoAuthExecutor(initcmd, libpath=tacmap.doauth_lib)

    def test_nasFoundInGroup_usr1_grp1(self):
        nas = "10.10.0.100"
        remote = "1.2.3.4"

        search = f"ipaddr match found: group: {tacmap.goodusergrp1_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasFoundInGroup_usr1_grp2(self):
        nas = "10.0.0.100"
        remote = "1.2.3.4"

        search = f"ipaddr match found: group: {tacmap.goodusergrp1_2} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_COND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasNotFoundInGroup_usr1_grp1(self):
        nas = "10.10.0.101"
        remote = "1.2.3.4"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp1_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasNotFoundInGroup_usr1_grp2(self):
        nas = "10.20.0.101"
        remote = "1.2.3.4"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp1_2} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasFoundInGroup_usr2_grp1(self):
        nas = "10.0.0.100"
        remote = "1.2.3.4"

        search = f"ipaddr match found: group: {tacmap.goodusergrp2_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser2,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_COND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasFoundInGroup_usr2_grp2(self):
        nas = "10.10.0.100"
        remote = "1.2.3.4"

        search = f"ipaddr match found: group: {tacmap.goodusergrp2_2} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser2,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasNotFoundInGroup_usr2_grp1(self):
        nas = "10.10.0.101"
        remote = "1.2.3.4"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp2_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser2,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasNotFoundInGroup_usr2_grp2(self):
        nas = "10.20.0.101"
        remote = "1.2.3.4"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp2_2} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser2,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasFoundInGroup_usr3_grp1(self):
        nas = "10.0.0.126"
        remote = "10.20.1.1"

        search = f"ipaddr match found: group: {tacmap.goodusergrp3_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasFoundInGroup_usr3_grp2(self):
        nas = "10.10.0.126"
        remote = "1.2.3.4"

        search = f"ipaddr match found: group: {tacmap.goodusergrp3_2} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasNotFoundInGroup_usr3_grp1(self):
        nas = "10.0.0.201"
        remote = "1.2.3.4"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp3_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasNotFoundInGroup_usr3_grp2(self):
        nas = "10.20.0.201"
        remote = "1.2.3.4"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp3_2} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasFoundInGroup_usr4_grp1(self):
        nas = "10.0.0.126"
        remote = "10.20.1.1"

        search = f"ipaddr match found: group: {tacmap.goodusergrp4_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasFoundInGroup_usr4_grp2(self):
        nas = "10.10.0.126"
        search = f"ipaddr match found: group: {tacmap.goodusergrp4_2} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas=nas,
                   remote="1.2.3.4"
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasNotFoundInGroup_usr4_grp1(self):
        nas = "10.0.0.129"
        remote = "1.2.3.4"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp4_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasNotFoundInGroup_usr4_grp2(self):
        nas = "10.20.0.129"
        remote = "1.2.3.4"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp4_2} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_nasFoundInGroup_usr5_grp1(self):
        nas = "10.0.0.201"
        remote = "1.2.3.4"

        search = f"ipaddr match found: group: {tacmap.goodusergrp5_1} - '{nas}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser5,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)


if __name__ == '__main__':
    unittest.main(buffer=True)
