#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This script performs two tasks:
1. Fixes missing/obsolete 'memberUID' values in all active aeGroup entries
2. TO DO: Fixes missing 'memberOf' values

It is designed to run as a CRON job rather rarely.

Author: Michael Ströder <michael@stroeder.com>
"""

__version__ = '0.0.1'

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

import sys
import os

# set LDAPRC env var *before* importing ldap
os.environ['LDAPRC'] = '/opt/ae-dir/etc/ldap.conf'
import ldap
import ldapurl
import aedir

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# python-ldap trace level
PYLDAP_TRACELEVEL = int(os.environ.get('PYLDAP_TRACELEVEL', '0'))

# Attribute containing the group members references
MEMBER_ATTR = 'member'
# Attribute containing the group members' uid values
MEMBERUID_ATTR = 'memberUid'

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEGroupFixer(object):
    """
    Group update process class
    """

    def __init__(self):
        self.ldap_conn = aedir.AEDirObject(None, trace_level=PYLDAP_TRACELEVEL)

    def fix_memberuid(self):
        """
        1. Fixes missing/obsolete 'memberUID' values in all active aeGroup entries
        """
        msg_id = self.ldap_conn.search(
            self.ldap_conn.find_search_base(),
            ldap.SCOPE_SUBTREE,
            '(&(objectClass=aeGroup)(aeStatus=0))',
            attrlist=[
                MEMBER_ATTR,
                MEMBERUID_ATTR,
            ],
        )

        for _, ldap_results, _, _ in self.ldap_conn.allresults(msg_id):

            for ldap_group_dn, ldap_group_entry in ldap_results:

                members = ldap_group_entry.get(MEMBER_ATTR, [])
                old_member_uids = set(ldap_group_entry.get(MEMBERUID_ATTR, []))
                new_member_uids = set(aedir.members2uids(members))

                ldap_group_modlist = []
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
                    sys.stdout.write(u'Update members of group entry %r: remove %d, add %d\n' % (
                        ldap_group_dn,
                        len(remove_member_uids),
                        len(add_member_uids)
                    ))
                    try:
                        self.ldap_conn.modify_s(ldap_group_dn, ldap_group_modlist)
                    except ldap.LDAPError, ldap_error:
                        sys.stderr.write(
                            u'LDAPError modifying %r: %s\nldap_group_modlist = %r\n' % (
                                ldap_group_dn,
                                ldap_error,
                                ldap_group_modlist,
                            )
                        )

        return # end of update_memberurl_groups()

    def run(self):
        """
        the main program
        """
        try:
            self.fix_memberuid()
        finally:
            try:
                self.ldap_conn.unbind_s()
            except ldap.LDAPError:
                pass
        return # run()


if __name__ == '__main__':
    AEGroupFixer().run()
