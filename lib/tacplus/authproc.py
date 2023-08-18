import tacplus.authmatch

class TacPlusProcessException(Exception):
    """General Excpetion class for TacPlusAuthProcessor"""
    pass


class TacPlusAuthProcessor(tacplus.authmatch.TacPlusAuthMatch):
    def __init__(self, username, inifile, authlogger):
        try:
            super(TacPlusAuthProcessor, self).__init__(username, inifile, authlogger)
        except tacplus.authmatch.TacPlusMatchException as err:
            raise TacPlusProcessException(err)

    def __process_match_group_apply(self, group, ip_nas):
        section = 'host_match_apply'

        self.log.log_debug(f"determining {group}.{section}")
        group_opref = self.get_group_rules(group, section)
        return self.match_group_apply(group, section, group_opref, ip_nas)

    def __process_host_allow_deny(self, group, ip_nas):
        section = 'host_deny'
        group_opref = self.get_group_rules(group, section)

        if len(group_opref) > 0:
            self.log.log_debug(f"processing {group}.{section}")
            self.match_group_ipaddr_deny(group, section, group_opref, ip_nas)

        section = 'host_allow'
        group_opref = self.get_group_rules(group, section)

        if len(group_opref) > 0:
            self.log.log_debug(f"processing {group}.{section}")
            self.match_group_ipaddr_deny(group, section, group_opref, ip_nas)

    def __process_device_permit_deny(self, group, ip_remote):
        section = 'device_deny'
        group_opref = self.get_group_rules(group, section)

        if len(group_opref) > 0:
            self.log.log_debug(f"processing {group}.{section}")
            self.match_group_ipaddr_deny(group, section, group_opref, ip_remote)

        section = 'device_permit'
        group_opref = self.get_group_rules(group, section)

        if len(group_opref) > 0:
            self.log.log_debug(f"processing {group}.{section}")
            self.match_group_ipaddr_deny(group, section, group_opref, ip_remote)

    def __process_command_permit_deny(self, group, fullcmd):
        section = 'command_deny'
        group_opref = self.get_group_rules(group, section)

        if len(group_opref) > 0:
            self.log.log_debug(f"processing {group}.{section}")
            self.match_group_deny(group, section, group_opref, fullcmd)

        section = 'command_permit'
        group_opref = self.get_group_rules(group, section)

        if len(group_opref) > 0:
            self.log.log_debug(f"processing {group}.{section}")
            self.match_group_deny(group, section, group_opref, fullcmd)

    def __process(self, in_opts):
        (ip_nas, ip_remote, fullcmd) = in_opts
        mark_for_removal = []

        for idx, options in enumerate(self.useropts):
            for group, group_opts in options.items():
                # First, check to see if the NAS device 
                # is one that matches our list of whether
                # or not to apply the group rules at large to
                # our auth check processing:
                #
                #   if evaluated True:
                #       then yes
                #   if evaluated False:
                #       then no, skip to next group
                if self.__process_match_group_apply(group, ip_nas) is False:
                    mark_for_removal.append((idx, group))
                    break

                # Second process host_{allow,deny} options
                self.__process_host_allow_deny(group, ip_nas)

                # Third, process device_{permit,deny} options
                self.__process_device_permit_deny(group, ip_remote)

                # Fourth, process command_{permit,deny} options
                # if we have one passed in.
                if fullcmd is not None:
                    self.__process_command_permit_deny(group, fullcmd)

        # remove group from user_options where host_match_apply
        # evaluated as False
        deleted = 0
        for idx, group in mark_for_removal:
            idx = idx - deleted
            self.log.log_debug(f"removing {group} from user_options")
            del(self.useropts[idx])
            deleted += 1

        # Finally, check to see if we have *any* user_options
        # left, if we don't, then we do an uncond_deny
        if len(self.useropts) == 0:
            denymsg = f"no rules evaluted; no authorization given"
            self.log.log_info(denymsg)
            self.log.log_info_uncond_deny()

    def process(self, ip_nas, ip_remote, fullcmd=None):
        in_opts = (ip_nas, ip_remote, fullcmd)
        self.__process(in_opts)
