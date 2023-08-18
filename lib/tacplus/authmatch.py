import re
import ipaddress
import tacplus.authcfg

class TacPlusMatchException(Exception):
    """General Excpetion class for TacPlusUserCfg"""
    pass


class TacPlusAuthMatch(tacplus.authcfg.TacPlusUserCfg):
    def __init__(self, username, inifile, authlogger):
        try:
            super(TacPlusAuthMatch, self).__init__(username, inifile, authlogger)
        except tacplus.authcfg.TacPlusUserCfgException as err:
            raise TacPlusMatchException(err)

        try:
            self.pdeny = ['host_deny', 'device_deny', 'command_deny']
            self.ndeny = ['host_allow', 'device_permit', 'command_permit']
            self.papply = ['host_match_apply']
        except KeyError as err:
            errmsg = f"Error: 'matcher_table' kwarg missing required key: {err}"
            raise TacPlusMatchException(errmsg)

    def __match_ipaddr_op(self, group, opref, match_candidate):
        try:
            match_candidate = ipaddress.ip_address(match_candidate)

            for idx, curr_opref_val in enumerate(opref):
                if isinstance(curr_opref_val, ipaddress.IPv4Address) is True or isinstance(curr_opref_val, ipaddress.IPv6Address) is True:
                    if match_candidate == curr_opref_val:
                        self.log.log_info(f"ipaddr match found: group: {group} - '{match_candidate}' matched '{curr_opref_val}' rule_index: {idx}")
                        return True
                elif isinstance(curr_opref_val, ipaddress.IPv4Network) is True or isinstance(curr_opref_val, ipaddress.IPv6Network) is True:
                    if match_candidate in curr_opref_val:
                        self.log.log_info(f"ipaddr match found: group: {group} - '{match_candidate}' in network '{curr_opref_val}' rule_index: {idx}")
                        return True
            self.log.log_info(f"ipaddr match(es) not found: group: {group} - '{match_candidate}' using {opref}")
            return False
        except Exception as err:
            errmsg = f"Error: failure in __match_ipaddr_op() call using {opref} configuration under {group} section: {err}"
            self.log.log_error(errmsg)
            self.log.log_info_uncond_deny()

    def __match_op(self, group, opref, match_candidate):
        try:
            for idx, curr_opref_val in enumerate(opref):
                if re.match(rf'\b{curr_opref_val}\b', match_candidate):
                    self.log.log_info(f"match found: group: {group} - '{match_candidate}' matched '{curr_opref_val}' rule_index: {idx}")
                    return True
            self.log.log_info(f"match(es) not found: group: {group} -  '{match_candidate}' using {opref}")
            return False
        except Exception as err:
            errmsg = f"Error: failure in __match_op() call using {opref} configuration under {group} section: {err}"
            self.log.log_error(errmsg)
            self.log.log_info_uncond_deny()

    def __match_positive_uncond_deny(self, match, denymsg='', acceptmsg=''):
        if match is True:
            self.log.log_info(denymsg)
            self.log.log_info_uncond_deny()
        else:
            self.log.log_info(acceptmsg)

    def __match_negative_uncond_deny(self, match, denymsg='', acceptmsg=''):
        if match is False:
            self.log.log_info(denymsg)
            self.log.log_info_uncond_deny()
        else:
            self.log.log_info(acceptmsg)

    def match_group_deny(self, group, section, opref, match_candidate):
        match = self.__match_op(group, opref, match_candidate)
        msgtemplate = f"match_group {group}.{section}:"

        if section in self.pdeny:
            denymsg = f"{msgtemplate} evaluated True"
            acceptmsg = f"{msgtemplate} evaluated False"
            self.__match_positive_uncond_deny(match, denymsg=denymsg, acceptmsg=acceptmsg)
        elif section in self.ndeny:
            denymsg = f"{msgtemplate} evaluated False"
            acceptmsg = f"{msgtemplate} evaluated True"
            self.__match_negative_uncond_deny(match, denymsg=denymsg, acceptmsg=acceptmsg)
        else:
            bugmsg = f"BUG: unsupported section {section} caught being passed in to match_group_deny(). Please report this as a bug!"
            self.log.log_error(bugmsg)
            self.log.log_info_uncond_deny()

    def match_group_apply(self, group, section, opref, match_candidate):
        match = self.__match_ipaddr_op(group, opref, match_candidate)

        if section in self.papply:
            self.log.log_info(f"match_group_apply: {group}.{section} evaluated {match}")
        return match

    def match_group_ipaddr_deny(self, group, section, opref, match_candidate):
        match = self.__match_ipaddr_op(group, opref, match_candidate)
        msgtemplate = f"match_group_ipaddr {group}.{section}:"

        if section in self.pdeny:
            denymsg = f"{msgtemplate} evaluated True"
            acceptmsg = f"{msgtemplate} evaluated False"
            self.__match_positive_uncond_deny(match, denymsg=denymsg, acceptmsg=acceptmsg)
        elif section in self.ndeny:
            denymsg = f"{msgtemplate} evaluated False"
            acceptmsg = f"{msgtemplate} evaluated True"
            self.__match_negative_uncond_deny(match, denymsg=denymsg, acceptmsg=acceptmsg)
        else:
            bugmsg = f"BUG: unsupported section {section} caught being passed in to match_group_ipaddr_deny(). Please report this as a bug!"
            self.log.log_error(bugmsg)
            self.log.log_info_uncond_deny()
