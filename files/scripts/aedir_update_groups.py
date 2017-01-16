#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This script performs two tasks:
1. Removes inactive members from static group entries referenced by 'memberOf'.
2. Updates all static aeGroup entries which contain attribute 'memberURL'

It is designed to run as a CRON job.

Author: Michael Ströder <michael@stroeder.com>

Requires:
- Python 2.6+
- python-ldap 2.4.27+
- python-aedir 0.0.10+
"""

__version__ = '0.1.1'

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
import aedir.process

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

class AEGroupUpdater(aedir.process.AEProcess):
    """
    Group update process class
    """
    script_version = __version__
    pyldap_tracelevel = PYLDAP_TRACELEVEL

    def remove_inactive_group_members(self):
        """
        1. Remove inactive members from static group entries referenced by 'memberOf'.
        """
        stale_members = self.ldap_conn.search_s(
            self.ldap_conn.find_search_base(),
            ldap.SCOPE_SUBTREE,
            STALE_MEMBER_FILTER,
            attrlist=['memberOf'],
        )
        if not stale_members:
            self.logger.debug(u'No stale group members found')
            return
        for member_dn, member_entry in stale_members:
            for group_dn in member_entry.get('memberOf', []):
                try:
                    self.ldap_conn.modify_s(
                        group_dn,
                        [
                            (ldap.MOD_DELETE, 'member', [member_dn]),
                            (ldap.MOD_DELETE, 'memberUID', aedir.members2uids([member_dn])),
                        ]
                    )
                except ldap.LDAPError, ldap_error:
                    self.logger.error(
                        u'LDAPError modifying group entry %r: %s',
                        group_dn,
                        ldap_error,
                    )
                else:
                    self.logger.info(
                        u'Removed %r from group entry %r',
                        member_dn,
                        group_dn,
                    )
        return # end of remove_inactive_group_members()

    def update_memberurl_groups(self):
        """
        2. Update all static aeGroup entries which contain attribute 'memberURL'
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
                    self.logger.error(
                        u'LDAPError searching members for %r with %r: %s',
                        ldap_group_dn,
                        member_url,
                        ldap_error,
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

            remove_members = old_members - new_members
            if remove_members:
                ldap_group_modlist.extend([
                    (ldap.MOD_DELETE, MEMBER_ATTR, list(remove_members)),
                    (ldap.MOD_DELETE, MEMBERUID_ATTR, list(aedir.members2uids(remove_members))),
                ])

            add_members = new_members - old_members
            if add_members:
                ldap_group_modlist.extend([
                    (ldap.MOD_ADD, MEMBER_ATTR, list(add_members)),
                    (ldap.MOD_ADD, MEMBERUID_ATTR, list(aedir.members2uids(add_members))),
                ])

            if ldap_group_modlist:
                self.logger.debug(
                    u'Update group entry %r: %r',
                    ldap_group_dn,
                    ldap_group_modlist,
                )
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
                    self.logger.info(
                        u'Updated members of group entry %r: removed %d, added %d',
                        ldap_group_dn,
                        len(remove_members),
                        len(add_members),
                    )
            else:
                self.logger.debug(u'Nothing to be done with %r', ldap_group_dn)

        return # end of update_memberurl_groups()

    def run_worker(self, state):
        """
        the main program
        """
        self.remove_inactive_group_members()
        self.update_memberurl_groups()
        return # end of run_worker()


if __name__ == '__main__':
    with AEGroupUpdater() as ae_process:
        ae_process.run(max_runs=1)
