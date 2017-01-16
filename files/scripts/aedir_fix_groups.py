#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This script performs two tasks:
1. Removes obsolete 'member' and 'memberUID' values and adds
   missing 'memberUID' values in all active aeGroup entries
2. TO DO: Fixes missing 'memberOf' values

It is designed to run as a CRON job rather rarely.

Author: Michael Ströder <michael@stroeder.com>
"""

__version__ = '0.1.0'

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

import sys
import os

# set LDAPRC env var *before* importing ldap
os.environ['LDAPRC'] = '/opt/ae-dir/etc/ldap.conf'
import ldap
import aedir
import aedir.process
from ldap.controls.deref import DereferenceControl

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# python-ldap trace level
PYLDAP_TRACELEVEL = int(os.environ.get('PYLDAP_TRACELEVEL', '0'))

# Attribute containing the group members references
MEMBER_ATTR = 'member'
# Attribute containing the group members' uid values
MEMBERUID_ATTR = 'memberUid'

# deref control for
AEUSER_DEREF_CONTROL = DereferenceControl(
    True,
    {
        MEMBER_ATTR: ['aeStatus', 'uid'],
    }
)

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEGroupFixer(aedir.process.AEProcess):
    """
    Group update process class
    """
    script_version = __version__
    pyldap_tracelevel = PYLDAP_TRACELEVEL

    def run_worker(self, state):
        """
        Removes obsolete 'member' and 'memberUID' values and adds
        missing 'memberUID' values in all active aeGroup entries
        """
        msg_id = self.ldap_conn.search_ext(
            self.ldap_conn.find_search_base(),
            ldap.SCOPE_SUBTREE,
            '(&(objectClass=aeGroup)(aeStatus=0))',
            attrlist=[
                MEMBER_ATTR,
                MEMBERUID_ATTR,
            ],
            serverctrls=[AEUSER_DEREF_CONTROL],
        )

        for _, ldap_results, _, _ in self.ldap_conn.allresults(
                msg_id,
                add_ctrls=1,
            ):

            for ldap_group_dn, ldap_group_entry, ldap_resp_controls in ldap_results:

                if not ldap_resp_controls:
                    continue

                member_deref_result = ldap_resp_controls[0].derefRes[MEMBER_ATTR]

                old_members = set(ldap_group_entry.get(MEMBER_ATTR, []))
                old_member_uids = set(ldap_group_entry.get(MEMBERUID_ATTR, []))
                new_members = set()
                new_member_uids = set()
                for deref_dn, deref_entry in member_deref_result:
                    if deref_entry['aeStatus'][0] == '0':
                        new_members.add(deref_dn)
                        new_member_uids.add(deref_entry['uid'][0])

                ldap_group_modlist = []

                remove_members = old_members - new_members
                if remove_members:
                    ldap_group_modlist.append(
                        (ldap.MOD_DELETE, MEMBER_ATTR, list(remove_members)),
                    )

                remove_member_uids = old_member_uids - new_member_uids
                if remove_member_uids:
                    ldap_group_modlist.append(
                        (ldap.MOD_DELETE, MEMBERUID_ATTR, list(remove_member_uids)),
                    )

                add_member_uids = new_member_uids - old_member_uids
                if add_member_uids:
                    ldap_group_modlist.append(
                        (ldap.MOD_ADD, MEMBERUID_ATTR, list(add_member_uids)),
                    )

                if ldap_group_modlist:
                    try:
                        self.ldap_conn.modify_s(ldap_group_dn, ldap_group_modlist)
                    except ldap.LDAPError, ldap_error:
                        self.logger.error(
                            u'LDAPError modifying %r: %s ldap_group_modlist = %r',
                            ldap_group_dn,
                            ldap_error,
                            ldap_group_modlist,
                        )
                    else:
                        self.logger.debug(
                            u'Updated %r: ldap_group_modlist = %r',
                            ldap_group_dn,
                            ldap_group_modlist,
                        )
                        self.logger.info(
                            (
                                u'Updated member values of group entry %r: '
                                u'remove_members=%d '
                                u'remove_member_uids=%d '
                                u'add_member_uids=%d'
                            ),
                            ldap_group_dn,
                            len(remove_members),
                            len(remove_member_uids),
                            len(add_member_uids)
                        )
                else:
                    self.logger.debug(u'Nothing to be done with %r', ldap_group_dn)

        return # end of fix_members()


if __name__ == '__main__':
    with AEGroupFixer() as ae_process:
        ae_process.run(max_runs=1)
