import sys

# NOTE:
# the tuple mappings are ordered based on
# order of the groups defined per user in
# the etc/test-do-auth.ini
USER_GROUP_MAPPINGS = [
("potatohead", "clowns"),
("andy", "starfleet_showgrp", "home_admingrp"),
("woody", "home_admingrp", "starfleet_showgrp"),
("buzz", "home_showgrp", "starfleet_admingrp"),
("rex", "home_showgrp", "starfleet_showgrp"),
("audience", "all_access"),
]

DOAUTH_LIB = "../lib"
DOAUTH_CMD = "../src/tacplus-do-auth.py"
DOAUTH_CFG = "./etc/test-do-auth.ini"

this = sys.modules[__name__]

def organize():
    setattr(this, "doauth_lib", DOAUTH_LIB)
    setattr(this, "doauth_cmd", DOAUTH_CMD)
    setattr(this, "doauth_cfg", DOAUTH_CFG)
    for idx, ug in enumerate(USER_GROUP_MAPPINGS):
        setattr(this, f"gooduser{idx}", ug[0])
        for gidx, grp in enumerate(list(ug[1:])):
            grpnum = gidx+1
            setattr(this, f"goodusergrp{idx}_{grpnum}", grp)
