import sys
import unittest
from TacplusCmd import (
  DoAuthExecutor,
  DOAUTH_UNCOND_PERMIT,
  DOAUTH_UNCOND_DENY,
  DOAUTH_COND_PERMIT
)
import TacplusMapping as tacmap

class TestCommandCfgs(unittest.TestCase):
    def setUp(self):
        tacmap.organize()

        initcmd = f"{tacmap.doauth_cmd} --conf={tacmap.doauth_cfg} --debug"
        self.doauth = DoAuthExecutor(initcmd, libpath=tacmap.doauth_lib)

    def test_commandPermit_usr1_grp1(self):
        remote = "10.1.1.1"
        nas = "10.10.0.100"
        avpairs = [("cmd","show"), ("cmd-arg","running-config")]

        search = f"match_group {tacmap.goodusergrp1_1}.command_permit: evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote,
                   avpairs=avpairs
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_commandNoPermit_usr1_grp1(self):
        remote = "10.1.1.1"
        nas = "10.10.0.100"
        avpairs = [("cmd","conf"), ("cmd-arg","terminal")]

        search = f"match_group {tacmap.goodusergrp1_1}.command_permit: evaluated False"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser1,
                   nas=nas,
                   remote=remote,
                   avpairs=avpairs
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_commandPermit_usr4_grp1(self):
        remote = "10.20.1.1"
        nas = "10.0.0.100"
        avpairs = [("cmd","show"), ("cmd-arg","me the money")]

        search = f"match_group {tacmap.goodusergrp4_1}.command_permit: evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas=nas,
                   remote=remote,
                   avpairs=avpairs
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_commandNoPermit_usr4_grp2(self):
        remote = "10.1.1.1"
        nas = "10.10.0.100"
        avpairs = [("cmd","reboot"), ("cmd-arg",None)]

        search = f"match_group {tacmap.goodusergrp4_2}.command_permit: evaluated False"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser4,
                   nas=nas,
                   remote=remote,
                   avpairs=avpairs
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_DENY)
        self.assertEqual(self.doauth.search_stderr(search), True)

    def test_commandPermit_usr5_grp1(self):
        remote = "10.20.1.1"
        nas = "10.0.0.100"
        avpairs = [("cmd","anything"), ("cmd-arg","i_want'")]

        search = f"match_group {tacmap.goodusergrp5_1}.command_permit: evaluated True"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser5,
                   nas=nas,
                   remote=remote,
                   avpairs=avpairs
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_UNCOND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(search), True)


if __name__ == '__main__':
    unittest.main(buffer=True)
