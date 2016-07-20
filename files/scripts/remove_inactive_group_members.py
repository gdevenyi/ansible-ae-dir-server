#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This script removes inactive members from static group entries.

Requires attribute 'memberOf' to be set in member entries.

It is designed to run as a CRON job.
"""

__version__ = '0.0.1'

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# Modules from Python's standard library
import sys

# Import python-ldap modules/classes
import ldap

import aedir

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# Filter for searching inactive member entries
STALE_MEMBER_FILTER = (
    '(&'
      '(|'
        '(objectClass=aeUser)(objectClass=aeService)'
      ')'
      '(aeStatus>=1)'
      '(memberOf=*)'
    ')'
)

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

def main():
    """
    actually run the stuff
    """

    ldap_conn = aedir.AEDirObject(sys.argv[1], trace_level=PYLDAP_TRACE_LEVEL)
    aedir_searchbase = ldap_conn.find_search_base()

    stale_members = ldap_conn.search_s(
        ldap_conn.ldap_url_obj.dn,
        ldap.SCOPE_SUBTREE,
        STALE_MEMBER_FILTER,
        attrlist=['objectClass', 'memberOf', 'uid'],
    )

    for member_dn, member_entry in stale_members:
        for group_dn in member_entry.get('memberOf', []):
            try:
                ldap_conn.modify_s(
                    group_dn,
                    [
                        (ldap.MOD_DELETE, 'member', [member_dn]),
                        (ldap.MOD_DELETE, 'memberUID', [member_entry['uid'][0]]),
                    ]
                )
            except ldap.LDAPError, ldap_error:
                sys.stderr.write(u'LDAPError modifying group entry %r: %s\n' % (
                    group_dn,
                    ldap_error,
                ))

    ldap_conn.unbind_s()


if __name__ == '__main__':
    main()
