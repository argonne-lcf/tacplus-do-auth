#!/usr/bin/env python3
"""
Usage:
    tacplus-do-auth.py [--help] [--debug] --conf=<conf> --user=<user> --nas=<ip_nas> --remote=<ip_remote> [(<av_key> <av_val>)...]


Arguments:
    <conf>      do_auth.ini configuration file path
    <user>      user name [see man tac_plus.conf(5)]
    <ip_nas>    client/NAS ip
                [see man tac_plus.conf(5) under AUTHORIZATION SCRIPTS]
    <ip_remote> remote ip
                [see man tac_plus.conf(5) under AUTHORIZATION SCRIPTS]

Options:
    --help      print usage docstring
    --debug     enable debug logging [default: False]
    <av_key>    DEBUG: set av_key string
    <av_val>    DEBUG: set av_val string
"""
import os
import sys

from docopt import docopt

from tacplus.authlog import TacplusAuthCodeLogger
from tacplus.authproc import TacPlusAuthProcessor
from tacplus.authav import TacPlusAVProcessor

if __name__ == '__main__':
    app = 'tacplus-do-auth'
    applog = '/var/log/tacplus-do-auth.log'

    args = docopt(__doc__)
    inifile = args['--conf']
    username = args['--user']
    debug = args['--debug']
    ip_nas = args['--nas']
    ip_remote = args['--remote']

    in_av_cli = []

    if debug is True:
        try:
            in_av_cli = list(
                          zip(
                            args['<av_key>'],
                            args['<av_val>']
                          )
                        )
        except KeyError:
            pass

    taclog = TacplusAuthCodeLogger(app, applog, debug=debug)
    tacproc = TacPlusAuthProcessor(username, inifile, taclog)
    tacav = TacPlusAVProcessor(tacproc, taclog)

    tacav.process_in_av(in_av_cli)
    tacproc.process(ip_nas, ip_remote, tacav.fullcmd)
    tacav.process_out_av()

    if len(tacav.out_av) > 0:
        taclog.log_info(f"All Checks Passed (w/ AV Pairs) for {username}")
        taclog.log_info_cond_permit(tacav.out_av)
    else:
        taclog.log_info(f"All Checks Passed for {username}")
        taclog.log_info_uncond_permit()
