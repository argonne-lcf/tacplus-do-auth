import sys
import unittest
from TacplusCmd import (
  DoAuthExecutor,
  DOAUTH_UNCOND_PERMIT,
  DOAUTH_UNCOND_DENY,
  DOAUTH_COND_PERMIT
)
import TacplusMapping as tacmap

class TestAVPairsCfgs(unittest.TestCase):
    def setUp(self):
        tacmap.organize()

        initcmd = f"{tacmap.doauth_cmd} --conf={tacmap.doauth_cfg} --debug"
        self.doauth = DoAuthExecutor(initcmd, libpath=tacmap.doauth_lib)

    def test_avPairMatchSend_usr3_grp1(self):
        nas = "10.0.0.100"
        remote = "10.20.1.1"
        avcfg_key = "role*"
        avcfg_val = "action-figure"

        avpairs = [("role*","whoami")]

        outsearch = f"{avcfg_key}={avcfg_val}"
        logsearch = f"post match_send_av pairs: |['{outsearch}']|"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser3,
                   nas=nas,
                   remote=remote,
                   avpairs=avpairs
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_COND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(logsearch), True)
        self.assertEqual(self.doauth.search_stdout(outsearch), True)

    def test_avPairSend_usr2_grp1(self):
        nas = "10.0.0.100"
        remote = "10.20.1.1"
        avcfg_key = "role"
        avcfg_val = "leader"

        avpairs = [("","")]

        outsearch = f"{avcfg_key}={avcfg_val}"
        logsearch = f"post send_av pairs: |['{outsearch}']|"
        params = self.doauth.format_kwargs(
                   user=tacmap.gooduser2,
                   nas=nas,
                   remote=remote,
                   avpairs=avpairs
                 )

        self.doauth.run_with_args(params)
        self.doauth.search_stderr("ERROR")

        self.assertEqual(self.doauth.retcode, DOAUTH_COND_PERMIT)
        self.assertEqual(self.doauth.search_stderr(logsearch), True)
        self.assertEqual(self.doauth.search_stdout(outsearch), True)


if __name__ == '__main__':
    unittest.main(buffer=True)
