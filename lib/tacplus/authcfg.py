import re
import configparser
import ipaddress
import enum
import tacplus.authlog


class TacPlusUserCfgException(Exception):
    """General Excpetion class for TacPlusUserCfg"""
    pass

@enum.unique
class TacPlusCfgKey(enum.Enum):
    HOST_MATCH_APPLY = 'host_match_apply'
    HOST_ALLOW = 'host_allow'
    HOST_DENY = 'host_deny'
    DEVICE_PERMIT = 'device_permit'
    DEVICE_DENY = 'device_deny'
    COMMAND_PERMIT = 'command_permit'
    COMMAND_DENY = 'command_deny'
    AV_PAIRS_MATCH_SEND = 'av_pairs_match_send'
    AV_PAIRS_SEND = 'av_pairs_send'

class TacPlusUserCfg(object):
    def __init__(self, username, inifile, authlogger):
        if isinstance(authlogger, tacplus.authlog.TacplusAuthCodeLogger) is True:
            self.log = authlogger
            self._username = username
            self._inifile = inifile
            self._optional = ['host_deny', 'device_deny', 'command_deny']
            self._ipaddr_cfgs = ['host_deny', 'host_allow', 'device_deny', 'device_permit', 'host_match_apply']
            self._ini = self.__get_config()

            self.__check_username()

            self._useropts = self.__associate_user_options()
        else:
            raise TacPlusUserCfgException("authlogger object reference passed in not TacplusAuthCodeLogger type")

    def __get_config(self):
        # opt to fail with unconditional deny if ini file
        # cannot be read in (via sys.exit(1))
        #
        # from man tac_plus.conf(5):
        #    If  the  program  returns   a   status   of   1,
        #    authorization  is  unconditionally denied. No AV
        #    pairs  are  returned  to  the  NAS.  No  further
        #    authorization processing occurs on this request.
        cfdct = {}
        cfobj = configparser.SafeConfigParser()

        try:
            cfobj.read(self._inifile)
            self.log.log_debug(f"read in {self._inifile}")
            cfobj = self.__scrub_cfg(cfobj)
            self.log.log_debug(f"scrubbed {self._inifile}")
            self.__verify_cfg_keys(cfobj)
            self.log.log_debug(f"verified {self._inifile} configuration keys")
        except Exception as err:
            errmsg = f"Error reading or scrubbing sections in {self._inifile}: {err}"
            self.log.log_error(errmsg)
            self.log.log_info_uncond_deny()

        return cfobj

    def __verify_cfg_keys(self, cfobj):
        '''
        __verify_cfg_keys: here we make sure that only group
                           configuration keys supported
                           are used for processing.

                           see TacPlusCfgKey class
        '''
        for section, optvals in cfobj.items():
            # there is a 'DEFAULT' section not defined that
            # you get for free..but we don't want that, so,
            # skip. We also don't want to process the groups
            # configured under the 'users' section...that
            # is checked / processed elsewhere because
            # entries under 'users' aren't directly referencing
            # supported keys used for group configurations
            if section == 'DEFAULT' or section == 'users':
                continue

            # attempt to access each opt (key) and
            # catch exception for ValueError per Enum class
            # defined above
            try:
                for opt,val in optvals.items():
                    opt_key = TacPlusCfgKey(opt)
            except Exception as err:
                errmsg = f"Error verifying key: {section}.{opt}: {err}"
                self.log.log_error(errmsg)
                self.log.log_info_uncond_deny()

    def __check_username(self):
        success_msg = f"{self._username} found in config"
        failure_msg = f"{self._username} not found in config section 'users'"
        try:
            check = self._ini['users'][self._username]
            self.log.log_info(success_msg)
        except Exception as err:
            self.log.log_info(failure_msg)
            self.log.log_info_uncond_deny()

    def __scrub_cfg(self, cfobj):
        '''
        __scrub_cfg: here you can define any other
                     actions to "scrub" configuration
                     parameters before being parsed / processed.
        '''
        scrub_cfobj = configparser.SafeConfigParser()

        for section, optvals in cfobj.items():
            # there is a 'DEFAULT' section not defined that
            # you get for free..but we don't want that, so,
            # skip.
            if section == 'DEFAULT':
                continue

            # see hex values here:
            #    https://www.asciitable.com/
            #
            # but initially, we allow [0-9][a-z][A-Z][_]
            key_scrub_patterns = [
              '[\x00-\x2f]',
              '[\x3a-\x40]',
              '[\x5b-\x5e]',
              '[\x60]',
              '[\x7b-\x7f]'
            ]

            key_scrub_regex = re.compile('|'.join(key_scrub_patterns))

            section_scrub = re.sub(key_scrub_regex, '', section)

            scrub_cfobj.add_section(section_scrub)
            for opt,val in optvals.items():
                opt_scrub = re.sub(key_scrub_regex, '', opt)
                scrub_cfobj.set(section_scrub, opt_scrub, val)

        return scrub_cfobj

    def __associate_user_options(self):
        '''
        USER CONFIGURATION:
        -------------------
        users are defined by a list of unique group assignments,
        under which determine authorization to NAS resources

        association of user(s) to defined groups happens
        in this function. the format for a user/group config
        is in the ini style as follows:

        [users]
        <username1> =
          <group1>
          <group2>
          ...
        <username2> =
          ...

        GROUP CONFIGURATION:
        --------------------
        groups are defined by attribute keys and list of values
        pairings. some lists are evaluated as regular
        expressions and are processed in order where first
        match wins.
        reasons for evaluating them in order and not as a long
        OR'd grouping is for ease of understanding which rule
        was either matched or not in determining authorization
        response. the format for a group config is also in the
        ini style as follows:

        [<group1>]
          host_match_apply =
            <ip/host regex>
            ...

          host_(allow|deny) =
            <ip/host regex>
            ...

          device_(permit|deny) =
            <ip/host regex>
            ...

          command_permit =
            <command regex>
            ...

          av_pairs_send =
            <attr1> = <val1>
            ...

          av_pairs_match_send = 
            <attr1> = <val1>
            ...
          
        '''

        user_options = []
        groups_per_user_set = set()
        current_group = None
        current_option = None

        try:
            groups = self._ini['users'][self._username]
            all_ipv4_net = ipaddress.ip_network('0.0.0.0/0')
            all_ipv6_net = ipaddress.ip_network('::/0')

            for group in groups.split("\n")[1:]:
                group = re.sub("^\s+", "", group)
                group = re.sub("\s+$", "", group)
                current_group = group

                # first check for duplicate groups configured
                # under a user. This is something that the
                # configuration manager needs to fix.
                # there should only be unique group assignments
                # under a single user.
                if group not in groups_per_user_set:
                    groups_per_user_set.add(group)
                else:
                    errmsg = f"Error: associating {self._username} to duplicate group configured: {group}"
                    self.log.log_error(errmsg)
                    self.log.log_info_uncond_deny()

                options = {}
                options[group] = {}
                group_options = self._ini[group].keys()

                for option in group_options:
                    current_option = option

                    # all values under ini key/value pairings
                    # are newline seperated, so we split on that
                    value = self._ini[group][option].split("\n")[1:]

                    # process any av_pairs group configuration
                    # (if any are defined) in order to strip
                    # out any whitespace around both key and
                    # value strings. this is important because
                    # later on we do matching from tacacs+
                    # process inputs
                    if re.match(r'^av_pairs_.*', option):
                        for av in value:
                            (av_key, av_val) = av.split('=')
                            av_key = re.sub("^\s+", "", av_key)
                            av_key = re.sub("\s+$", "", av_key)
                            av_val = re.sub("^\s+", "", av_val)
                            av_val = re.sub("\s+$", "", av_val)

                            try:
                                options[group][option][av_key] = av_val
                            except Exception:
                                options[group][option] = {}
                                options[group][option][av_key] = av_val
                    elif option in self._ipaddr_cfgs:
                        self.log.log_debug(f"ipaddr option: {option} declared value(s): {value}")
                        options[group][option] = []

                        for addr in value:
                            # first search for '/' character.
                            # if found, we coerce into a network
                            # object, otherwise assume we have
                            # an ip address i.e. /32
                            if re.search(r'/', addr):
                                addr = ipaddress.ip_network(addr)
                            else:
                                addr = ipaddress.ip_address(addr)
                            options[group][option].append(addr)
                    else:
                        options[group][option] = value

                # here we setup a generous allow set of rules
                # if they are not defined for the following:
                #
                # host_allow
                # command_permit
                # device_permit
                # host_match_apply
                #
                # the "match all" rule is only used if it
                # isn't already defined in the ini file.
                if 'command_permit' not in options[group]:
                    options[group]['command_permit'] = ['.*']
                if 'host_allow' not in options[group]:
                    options[group]['host_allow'] = [all_ipv4_net, all_ipv6_net]
                if 'device_permit' not in options[group]:
                    options[group]['device_permit'] = [all_ipv4_net, all_ipv6_net]
                if 'host_match_apply' not in options[group]:
                    options[group]['host_match_apply'] = [all_ipv4_net, all_ipv6_net]

                if self.log.debug is True:
                    debug_options_group = {}
                    for opt_key,opt_vals in options[group].items():
                        debug_options_group[opt_key] = []
                        for opt_val in opt_vals:
                            debug_options_group[opt_key].append(str(opt_val))
                    self.log.log_debug(f"set [{group}] for {self._username}: {debug_options_group}")

                user_options.append(options)
        except Exception as err:
            errmsg = f"Error: associating {self._username} to group option: {current_group}.{current_option}: {err}"
            self.log.log_error(errmsg)
            self.log.log_info_uncond_deny()

        return user_options

    def __get_group_index(self, group):
        for idx, grp_set in enumerate(self._useropts):
            if group in grp_set:
                return idx
        raise TacPlusUserCfgException(f"Error: no group_index found for {group}!")

    def get_group_rules(self, group, cfgkey):
        try:
            group_idx = self.__get_group_index(group)
            return self._useropts[group_idx][group][cfgkey]
        except KeyError:
            if cfgkey not in self._optional:
                errmsg = f"Error: '{cfgkey}' rules configuration is not optional and is missing!"
                self.log.log_error(errmsg)
                self.log.log_info_uncond_deny()
            return []
        except Exception as err:
            errmsg = f"Error: failure in get_group_rules() call using {group} section: {err}"
            self.log.log_error(errmsg)
            self.log.log_info_uncond_deny()

    @property
    def useropts(self):
        return self._useropts
