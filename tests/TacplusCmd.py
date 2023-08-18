import os
import sys
import re
from subprocess import Popen, PIPE

DEFAULT_MAXTIME = 3

DOAUTH_UNCOND_PERMIT = 0
DOAUTH_UNCOND_DENY = 1
DOAUTH_COND_PERMIT = 2


class DoAuthExecutor(object):
    def __init__(self, initcmd, maxtime=3, libpath=None):
        try:
            self._initcmd = self.__cmd_to_list(initcmd)
        except Exception as err:
            sys.stderr.write(f"DoAuthExecutor __init__() exception caught: {err}\n")
            sys.exit(1)

        self._maxtime = DEFAULT_MAXTIME
        if isinstance(maxtime, int):
            self._maxtime = maxtime

        self._env = os.environ
        if libpath:
            self._env['PYTHONPATH'] = libpath

        self._out = None
        self._err = None
        self._retcode = None

    def __cmd_to_list(self, cmd):
        if isinstance(cmd, str):
            cmd = cmd.lstrip()
            cmd = cmd.rstrip()
            return re.split(r'\s+', cmd)
        else:
            raise Exception("__cmd_to_list() failure: input cmd must be string!")

    def format_kwargs(self, user=None, nas=None, remote=None, avpairs=None):
        params = ""

        if user:
            params = f"{params} --user={user}"
        if nas:
            params = f"{params} --nas={nas}"
        if remote:
            params = f"{params} --remote={remote}"
        if avpairs:
            if isinstance(avpairs, list):
                for avpair in avpairs:
                    if isinstance(avpair, tuple):
                        attr = avpair[0]
                        val  = avpair[1]
                        params = f"{params} {attr} {val}"
        return params

    def run_with_args(self, params):
        try:
            params_list = self.__cmd_to_list(params)
            cmd = self._initcmd + params_list

            with Popen(cmd, stderr=PIPE, stdout=PIPE, env=self._env) as proc:
                self._out, self._err = proc.communicate(timeout=self._maxtime)
                self._retcode = proc.returncode
                self._out = self._out.decode('utf-8')
                self._err = self._err.decode('utf-8')
        except Exception as err:
            sys.stderr.write(f"DoAuthExecutor run() exception caught: {err}\n")
            sys.exit(1)

    def search_stdout(self, strsearch, printout=True):
        if self._out is not None:
            if re.search(re.escape(strsearch), self._out):
                if printout is True:
                    sys.stdout.write(f"{self._out}\n")
                return True
        return False

    def search_stderr(self, strsearch, printerr=True):
        if self._err is not None:
            if re.search(re.escape(strsearch), self._err):
                if printerr is True:
                    sys.stderr.write(f"{self._err}\n")
                return True
        return False

    @property
    def stdout(self):
        return self._out

    @property
    def stderr(self):
        return self._err

    @property
    def retcode(self):
        return self._retcode
