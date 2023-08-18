import sys
import tacplus.authlog
import tacplus.authcfg

class TacPlusAVException(Exception):
    """General Excpetion class for TacPlusAuthProcess"""
    pass


class TacPlusAVProcessor(object):
    def __init__(self, authconfig, authlogger):
        if isinstance(authlogger, tacplus.authlog.TacplusAuthCodeLogger) is True:
            if isinstance(authconfig, tacplus.authcfg.TacPlusUserCfg) is True:
                self.log = authlogger
                self.cfg = authconfig
                self._debug = authlogger.debug
                self._in_av = {}
                self._in_av_fullcmd = None
                self._out_av = []
            else:
                raise TacPlusAVException("Error: 'authconfig' passed in not a TacPlusUserCfg object")
        else:
            raise TacPlusAVException("Error: 'authlogger' passed in not a TacplusAuthCodeLogger object")
                
    def __handle_stdin_av(self):
        if self._debug is False:
            for line in sys.stdin:
                line = line.rstrip()
                try:
                    (key,val) = line.split('=')
                    key = key.rstrip()
                except ValueError:
                    key = line
                    val = None
                self._in_av[key] = val
        self.log.log_info(f"av pairs (stdin): |{self._in_av}|")

    def __handle_cli_debug_av(self, in_av_cli):
        if self._debug is True:
            for av_pair in in_av_cli:
                (av_k, av_v) = av_pair
                self._in_av[av_k] = av_v
        self.log.log_debug(f"av pairs (cli-debug): |{self._in_av}|")

    def __handle_fullcmd_av(self):
        try:
            cmd = self._in_av['cmd']
            cmd_arg = self._in_av['cmd-arg']
            self._in_av_fullcmd = f"{cmd} {cmd_arg}"
        except KeyError:
            self.log.log_debug("no fullcmd to process...skipping")
            pass
        self.log.log_info(f"processing fullcmd: {self._in_av_fullcmd}")

    def __process_send_av(self):
        out_av = []
        for opts in self.cfg.useropts:
            for _, opt in opts.items():
                if 'av_pairs_send' not in opt:
                    break
                for av_k, av_v in opt['av_pairs_send'].items():
                    out_av.append(f"{av_k}={av_v}")
        self.log.log_info(f"post send_av pairs: |{out_av}|")
        return out_av

    def __process_match_send_av(self):
        out_av = []
        for opts in self.cfg.useropts:
            for _, opt in opts.items():
                if 'av_pairs_match_send' not in opt:
                    break
                for av_k, av_v in opt['av_pairs_match_send'].items():
                    try:
                        in_av_v = self._in_av[av_k]
                        if in_av_v is not None:
                            out_av.append(f"{av_k}={av_v}")
                        else:
                            out_av.append(f"{av_k}{av_v}")
                    except KeyError:
                        self.log.log_debug(f"skipping {av_k}: not in input av list")
                        pass
        self.log.log_info(f"post match_send_av pairs: |{out_av}|")
        return out_av

    def process_in_av(self, in_av_cli=[]):
        if isinstance(in_av_cli, list) is True:
            self.__handle_stdin_av()
            self.__handle_cli_debug_av(in_av_cli)
            self.__handle_fullcmd_av()
        else:
            raise TacPlusAVException("Error: process_in_av() call 'in_av_cli' parameter isn't a list")

    def process_out_av(self):
        self._out_av = self.__process_match_send_av()
        self._out_av.extend(self.__process_send_av())

    @property
    def fullcmd(self):
        return self._in_av_fullcmd

    @property
    def out_av(self):
        return self._out_av
