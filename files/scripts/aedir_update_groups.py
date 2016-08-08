#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This script performs two tasks:
1. Removes inactive members from static group entries referenced by 'memberOf'.
2. Updates all static aeGroup entries which contain attribute 'memberURL'

It is designed to run as a CRON job.

Author: Michael Ströder <michael@stroeder.com>
"""

__version__ = '0.4.2'

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
MEMBERUID_ATTR = 'memberUID'
# Attribute containing the LDAP URLs to be searched
MEMBERURL_ATTR = 'memberURL'

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

def members2uids(members):
    """
    transforms list of member DNs into list of uid values
    """
    return [
        dn[4:].split(',')[0]
        for dn in members
    ]


class AEGroupUpdater(object):
    """
    Process for updating "dynamic groups and remove
    """

    def __init__(self):
        self.ldap_conn = aedir.AEDirObject(None, trace_level=PYLDAP_TRACELEVEL)

    def remove_inactive_group_members(self):
        """
        1. Removes inactive members from static group entries referenced by 'memberOf'.
        """
        stale_members = self.ldap_conn.search_s(
            self.ldap_conn.find_search_base(),
            ldap.SCOPE_SUBTREE,
            STALE_MEMBER_FILTER,
            attrlist=['memberOf'],
        )
        for member_dn, member_entry in stale_members:
            for group_dn in member_entry.get('memberOf', []):
                try:
                    self.ldap_conn.modify_s(
                        group_dn,
                        [
                            (ldap.MOD_DELETE, 'member', [member_dn]),
                            (ldap.MOD_DELETE, 'memberUID', members2uids([member_dn])),
                        ]
                    )
                except ldap.LDAPError, ldap_error:
                    sys.stderr.write(u'LDAPError modifying group entry %r: %s\n' % (
                        group_dn,
                        ldap_error,
                    ))
        return # end of remove_inactive_group_members()

    def update_memberurl_groups(self):
        """
        2. Updates all static aeGroup entries which contain attribute 'memberURL'
        """
        dynamic_groups = self.ldap_conn.search_s(
            self.ldap_conn.find_search_base(),
            ldap.SCOPE_SUBTREE,
            '(%s=*)' % (MEMBERURL_ATTR),
            attrlist=[
                MEMBER_ATTR,
                MEMBERURL_ATTR,
            ],
        )
        for ldap_group_dn, ldap_group_entry in dynamic_groups:

            old_members = set(ldap_group_entry.get(MEMBER_ATTR, []))
            new_members = set()

            for member_url in ldap_group_entry[MEMBERURL_ATTR]:

                member_url_obj = ldapurl.LDAPUrl(member_url)
                try:
                    ldap_member_users = self.ldap_conn.search_s(
                        member_url_obj.dn,
                        member_url_obj.scope,
                        '(&%s(!(entryDN=%s)))' % (
                            member_url_obj.filterstr,
                            ldap_group_dn,
                        ),
                        attrlist=[
                            'cn',
                            'entryUUID',
                        ]+(member_url_obj.attrs or []),
                    )
                except ldap.LDAPError, ldap_error:
                    sys.stderr.write(
                        u'LDAPError searching members for %r with %r: %s\n' % (
                            ldap_group_dn,
                            member_url,
                            ldap_error,
                        )
                    )
                    continue
                if member_url_obj.attrs is None:
                    new_members.update([
                        ldap_user_dn
                        for ldap_user_dn, ldap_user_entry in ldap_member_users
                    ])
                else:
                    for ldap_user_dn, ldap_user_entry in ldap_member_users:
                        for attr_type in member_url_obj.attrs:
                            new_members.update(ldap_user_entry.get(attr_type, []))

            ldap_group_modlist = []

            remove_members = old_members-new_members
            if remove_members:
                ldap_group_modlist.extend([
                    (ldap.MOD_DELETE, MEMBER_ATTR, list(remove_members)),
                    (ldap.MOD_DELETE, MEMBERUID_ATTR, list(members2uids(remove_members))),
                ])

            add_members = new_members-old_members
            if add_members:
                ldap_group_modlist.extend([
                    (ldap.MOD_ADD, MEMBER_ATTR, list(add_members)),
                    (ldap.MOD_ADD, MEMBERUID_ATTR, list(members2uids(add_members))),
                ])

            if ldap_group_modlist:
                sys.stdout.write(u'Update members of group entry %r: remove %d, add %d\n' % (
                    ldap_group_dn,
                    len(remove_members),
                    len(add_members)
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
            self.remove_inactive_group_members()
            self.update_memberurl_groups()
        finally:
            try:
                self.ldap_conn.unbind_s()
            except ldap.LDAPError:
                pass
        return # run()


if __name__ == '__main__':
    AEGroupUpdater().run()
