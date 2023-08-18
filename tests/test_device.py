import sys
import unittest
from TacplusCmd import (
  DoAuthExecutor,
  DOAUTH_UNCOND_PERMIT,
  DOAUTH_UNCOND_DENY,
  DOAUTH_COND_PERMIT
)
import TacplusMapping as tacmap

class TestDeviceCfgs(unittest.TestCase):
    def setUp(self):
        tacmap.organize()

        initcmd = f"{tacmap.doauth_cmd} --conf={tacmap.doauth_cfg} --debug"
        self.doauth = DoAuthExecutor(initcmd, libpath=tacmap.doauth_lib)

    def test_deviceFoundInGroup_usr1_grp1(self):
        remote = "10.1.1.1"
        nas = "10.10.0.100"

        search = f"ipaddr match found: group: {tacmap.goodusergrp1_1} - '{remote}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_deviceFoundInGroup_usr1_grp2(self):
        remote = "1.1.1.1"
        nas = "10.0.0.100"

        search = f"ipaddr match found: group: {tacmap.goodusergrp1_2} - '{remote}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_COND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_deviceNotFoundInGroup_usr1_grp1(self):
        remote = "1.1.1.1"
        nas = "10.10.0.100"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp1_1} - '{remote}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_deviceFoundInGroup_usr3_grp1(self):
        remote = "10.1.1.1"
        nas = "10.0.0.100"

        search = f"ipaddr match found: group: {tacmap.goodusergrp3_1} - '{remote}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_deviceNotFoundInGroup_usr3_grp1(self):
        remote = "10.20.1.2"
        nas = "10.0.0.100"

        search = f"ipaddr match(es) not found: group: {tacmap.goodusergrp3_1} - '{remote}'"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas=nas,
                   remote=remote
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)


if __name__ == '__main__':
    unittest.main(buffer=True)
