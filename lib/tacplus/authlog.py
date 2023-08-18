import os
import sys
import logging
import hashlib
import inspect
import uuid
from logging.handlers import (
  TimedRotatingFileHandler,
  SysLogHandler
)


class HashLoggerAdapter(logging.LoggerAdapter, object):
    def __init__(self, logger, log_hash=None):
        extra = {}
        if log_hash is not None:
            extra['log_hash'] = log_hash
        else:
            data = uuid.uuid4().hex
            blk2s = hashlib.blake2s(digest_size=4)
            blk2s.update(data.encode('utf-8'))
            extra['log_hash'] = blk2s.hexdigest()

        super(HashLoggerAdapter, self).__init__(logger=logger, extra=extra)

    def process(self, msg, kwargs):
        log_hash = self.extra['log_hash']
        return f"{log_hash} {msg}", kwargs


class OnlyDebug(logging.Filter):
    """This returns true only if we're in debug mode """
    def filter(self, record):
        return True


class TacPlusRetAuthCode(object):
    """
    Return codes and their associated meanings can be
    found in the man tac_plus.conf(5) documentation
    """
    def __init__(self):
        self._authcode = -1
        self._msgmap = {
            -1: 'tacauth: Initialized',
            self.uncond_permit: 'tacauth: uncond_permit',
            self.uncond_deny: 'tacauth: uncond_deny',
            self.cond_permit: 'tacauth: cond_permit'
        }

    def set_uncond_permit(self):
        self._authcode = self.uncond_permit

    def set_uncond_deny(self):
        self._authcode = self.uncond_deny

    def set_cond_permit(self):
        self._authcode = self.cond_permit

    @property
    def status(self):
        return self._authcode

    @property
    def statusmsg(self):
        return self._msgmap[self._authcode]

    @property
    def uncond_permit(self):
        return 0

    @property
    def uncond_deny(self):
        return 1

    @property
    def cond_permit(self):
        return 2


class TacplusAuthCodeLogger(TacPlusRetAuthCode):
    def __init__(self, loggername, log_filename, debug=False):
        self._loggername = loggername
        self._logfile = log_filename
        self._debug = debug

        super(TacplusAuthCodeLogger, self).__init__()

        logger = self.__basic_logger(debug=debug)

        self._logger = HashLoggerAdapter(logger)
        self._loghash = self._logger.extra['log_hash']

    def __basic_logger(self, debug=False):
        fmt = '%(asctime)s.%(msecs)03d %(name)s: [%(levelname)-8s] - %(message)s'
        datefmt = '%b %d %H:%M:%S'

        i_logger = logging.getLogger(self._loggername)

        if debug is False:
            self.__basic_nodebug_logger(
                i_logger,
                fmt,
                datefmt
            )
        else:
            self.__basic_debug_logger(
                i_logger,
                fmt,
                datefmt
            )
        return i_logger

    def __basic_nodebug_logger(self, logger, fmt, datefmt):
        logfmter = logging.Formatter(fmt, datefmt=datefmt)

        try:
            slogh = SysLogHandler('/dev/log', facility='daemon')
        except Exception as err:
            sys.stderr.write(f"Error occurred instantiating SysLogHandler: {err}\n")
            self.set_uncond_deny()

        try:
            logh = TimedRotatingFileHandler(
                     self._logfile,
                     when='w6',
                     utc=True,
                     backupCount=12
                   )
        except Exception as err:
            sys.stderr.write(f"Error occurred instantiating TimedRotatingFileHandler for {self._logfile}: {err}\n")
            self.set_uncond_deny()

        if self.status == self.uncond_deny:
            sys.exit(self.status)

        slogh.setFormatter(logfmter)
        logh.setFormatter(logfmter)

        logger.setLevel(logging.INFO)
        logger.addHandler(logh)
        logger.addHandler(slogh)

    def __basic_debug_logger(self, logger, fmt, datefmt):
        logfmter = logging.Formatter(fmt, datefmt=datefmt)

        logh = logging.StreamHandler()
        logh.addFilter(OnlyDebug())
        logh.setFormatter(logfmter)

        logger.setLevel(logging.DEBUG)
        logger.addHandler(logh)

    def __logit_and_exit(self, av_pairs=[]):
        self._logger.info(self.statusmsg)
        if len(av_pairs) == 0:
            sys.exit(self.status)
        else:
            for av in av_pairs:
                sys.stdout.write(f"{av}\n")
            sys.exit(self.status)

    def log_info_uncond_permit(self):
        self.set_uncond_permit()
        self.__logit_and_exit()

    def log_info_cond_permit(self, av_pairs):
        self.set_cond_permit()
        if isinstance(av_pairs, list) is True:
            self.__logit_and_exit(av_pairs=av_pairs)
        else:
            self.__logit_and_exit()

    def log_info_uncond_deny(self):
        self.set_uncond_deny()
        self.__logit_and_exit()

    def log_info(self, msg):
        self._logger.info(msg)

    def log_error(self, msg):
        self._logger.error(msg)

    def log_warn(self, msg):
        self._logger.warn(msg)

    def log_debug(self, msg):
        self._logger.debug(msg)

    @property
    def debug(self):
        return self._debug
