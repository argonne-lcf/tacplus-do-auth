import sys
import unittest

from TacplusCmd import (
  DoAuthExecutor,
)
import TacplusMapping as tacmap

class TestAVPairsCfgs(unittest.TestCase):
    def setUp(self):
        tacmap.organize()

        initcmd = f"{tacmap.doauth_cmd} --conf={tacmap.doauth_cfg} --debug"
        self.doauth = DoAuthExecutor(initcmd, libpath=tacmap.doauth_lib)

    def test_docopt_module_not_found(self):
        docopt_not_found = "ModuleNotFoundError: No module named 'docopt'"
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
        self.assertNotEqual(self.doauth.search_stderr(docopt_not_found), True)

if __name__ == '__main__':
    unittest.main(buffer=True)
