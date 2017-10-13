#!/opt/ae-dir/bin/python
# -*- coding: utf-8 -*-
"""
This script performs two tasks:
1. Removes inactive members from static group entries referenced by 'memberOf'.
2. Updates all static aeGroup entries which contain attribute 'memberURL'

It is designed to run as a CRON job.

Author: Michael Ströder <michael@stroeder.com>
"""

__version__ = '0.2.0'

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

import sys
import os

# set LDAPRC env var *before* importing ldap
os.environ['LDAPRC'] = '/opt/ae-dir/etc/ldap.conf'
import ldap
from ldap.filter import escape_filter_chars
from ldap.controls.deref import DereferenceControl
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
# Attribute containing the LDAP URLs to be searched
MEMBEROF_ATTR = 'memberOf'
# Attribute containing the LDAP URLs to be searched
MEMBERURL_ATTR = 'memberURL'
# Attribute containing the group members' uid values
MEMBER_ATTRS_MAP = {
    'aeGroup': ('memberUid', 'uid'),
    'aeMailGroup': ('rfc822MailMember', 'mail'),
}
MEMBER_ATTRS = [attr[0] for attr in MEMBER_ATTRS_MAP.values()]
USER_ATTRS = [attr[1] for attr in MEMBER_ATTRS_MAP.values()]

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEGroupUpdater(aedir.process.AEProcess):
    """
    Group update process class
    """
    script_version = __version__
    pyldap_tracelevel = PYLDAP_TRACELEVEL

    def _update_members(
            self,
            group_dn,
            member_map_attr,
            old_members,
            new_members,
            old_member_attr_values,
            new_member_attr_values,
        ):
        """
        update attribute 'member' and additional membership attribute
        """
        mod_list = []
        add_members = new_members - old_members
        if add_members:
            mod_list.append(
                (ldap.MOD_ADD, MEMBER_ATTR, list(add_members)),
            )

        remove_members = old_members - new_members
        if remove_members:
            mod_list.append(
                (ldap.MOD_DELETE, MEMBER_ATTR, list(remove_members)),
            )

        remove_member_attr_values = old_member_attr_values - new_member_attr_values
        if remove_member_attr_values:
            mod_list.append(
                (ldap.MOD_DELETE, member_map_attr, list(remove_member_attr_values)),
            )

        add_member_attr_values = new_member_attr_values - old_member_attr_values
        if add_member_attr_values:
            mod_list.append(
                (ldap.MOD_ADD, member_map_attr, list(add_member_attr_values)),
            )

        if mod_list:
            try:
                self.ldap_conn.modify_s(group_dn, mod_list)
            except ldap.LDAPError, ldap_error:
                self.logger.error(
                    u'LDAPError modifying %r: %s mod_list = %r',
                    group_dn,
                    ldap_error,
                    mod_list,
                )
            else:
                self.logger.debug(
                    u'Updated %r: mod_list = %r',
                    group_dn,
                    mod_list,
                )
                self.logger.info(
                    (
                        u'Updated member values of group entry %r: '
                        u'add_members=%d '
                        u'add_member_attr_values=%d '
                        u'remove_members=%d '
                        u'remove_member_attr_values=%d'
                    ),
                    group_dn,
                    len(add_members),
                    len(add_member_attr_values),
                    len(remove_members),
                    len(remove_member_attr_values),
                )
        else:
            self.logger.debug(u'Nothing to be done with %r', group_dn)
        return # end of _update_members()

    def fix_static_groups(self):
        """
        1. Removes obsolete 'member' and other member values and
        2. adds missing other member values
        in all active static aeGroup entries
        """
        for group_object_class, member_attrs in MEMBER_ATTRS_MAP.items():
            member_map_attr, member_user_attr = member_attrs
            msg_id = self.ldap_conn.search_ext(
                self.ldap_conn.find_search_base(),
                ldap.SCOPE_SUBTREE,
                '(&(objectClass={0})(!({1}=*))(aeStatus=0))'.format(
                    group_object_class,
                    MEMBERURL_ATTR,
                ),
                attrlist=[
                    MEMBER_ATTR,
                    member_map_attr,
                ],
                serverctrls=[
                    DereferenceControl(
                        True,
                        {
                            MEMBER_ATTR: [
                                'aeStatus',
                                MEMBEROF_ATTR,
                                member_user_attr
                            ],
                        }
                    )
                ],
            )

            for _, ldap_results, _, _ in self.ldap_conn.allresults(msg_id, add_ctrls=1):

                for ldap_group_dn, ldap_group_entry, ldap_resp_controls in ldap_results:

                    if not ldap_resp_controls:
                        continue

                    member_deref_result = ldap_resp_controls[0].derefRes[MEMBER_ATTR]

                    old_members = set(ldap_group_entry.get(MEMBER_ATTR, []))
                    old_member_attr_values = set(ldap_group_entry.get(member_map_attr, []))
                    new_members = set()
                    new_member_attr_values = set()
                    for deref_dn, deref_entry in member_deref_result:
                        if int(deref_entry['aeStatus'][0]) <= 0:
                            new_members.add(deref_dn)
                            try:
                                new_member_attr_values.add(deref_entry[member_user_attr][0])
                            except KeyError:
                                self.logger.error(
                                    'Attribute %r not found in entry %r: %r',
                                    member_user_attr,
                                    deref_dn,
                                    deref_entry,
                                )

                    self._update_members(
                        ldap_group_dn,
                        member_map_attr,
                        old_members,
                        new_members,
                        old_member_attr_values,
                        new_member_attr_values
                    )

        return # end of fix_static_groups()

    def update_memberurl_groups(self):
        """
        2. Update all static aeGroup entries which contain attribute 'memberURL'
        """
        dynamic_groups = self.ldap_conn.search_s(
            self.ldap_conn.find_search_base(),
            ldap.SCOPE_SUBTREE,
            '({0}=*)'.format(MEMBERURL_ATTR),
            attrlist=[
                'aeDept',
                'aeLocation',
                'aeMemberZone',
                'structuralObjectClass',
                MEMBER_ATTR,
                MEMBERURL_ATTR,
            ]+MEMBER_ATTRS,
        )
        for dyn_group_dn, dyn_group_entry in dynamic_groups:

            group_object_class = dyn_group_entry['structuralObjectClass'][0]
            member_map_attr, member_user_attr = MEMBER_ATTRS_MAP[group_object_class]

            try:
                member_zones = dyn_group_entry['aeMemberZone']
            except KeyError:
                member_zones_filter = ''
            else:
                member_zones_filter = '(|{})'.format(
                    ''.join([
                        '(entryDN:dnSubordinateMatch:={})'.format(
                            escape_filter_chars(zone_dn)
                        )
                        for zone_dn in member_zones
                    ])
                )

            self.logger.debug(
                'group_object_class=%r member_map_attr=%r member_user_attr=%r',
                group_object_class, member_map_attr, member_user_attr
            )

            old_members = set(dyn_group_entry.get(MEMBER_ATTR, []))
            old_member_attr_values = set(dyn_group_entry.get(member_map_attr, []))
            new_members = set()
            new_member_attr_values = set()

            for member_url in dyn_group_entry[MEMBERURL_ATTR]:

                member_url_obj = ldapurl.LDAPUrl(member_url)
                dyn_group_filter = '(&{0}(!(entryDN={1})){2})'.format(
                    member_url_obj.filterstr,
                    dyn_group_dn,
                    member_zones_filter,
                )
                self.logger.debug('dyn_group_filter=%r', dyn_group_filter)

                if member_url_obj.attrs:
                    server_ctrls = [DereferenceControl(
                        True,
                        {
                            member_url_obj.attrs[0]:[
                                'aeStatus',
                                'aePerson',
                                member_user_attr,
                            ],
                        }
                    )]
                else:
                    server_ctrls =None                

                try:
                    msg_id = ldap_member_users = self.ldap_conn.search_ext(
                        member_url_obj.dn,
                        member_url_obj.scope or ldap.SCOPE_SUBTREE,
                        dyn_group_filter,
                        attrlist=[
                            'cn',
                            'aeStatus',
                        ]+(member_url_obj.attrs or [])+USER_ATTRS,
                        serverctrls=server_ctrls,
                    )
                    for _, ldap_results, _, _ in self.ldap_conn.allresults(msg_id, add_ctrls=1):
                        for groupmember_dn, groupmember_entry, ldap_resp_controls in ldap_results:
                            if not member_url_obj.attrs or member_url_obj.attrs[0].lower()=='entrydn':
                                member_deref_result = [(groupmember_dn, groupmember_entry)]
                            elif member_url_obj.attrs and not ldap_resp_controls:
                                self.logger.debug('ignoring empty %r: %r', groupmember_dn, groupmember_entry)
                                continue
                            else:
                                member_deref_result = ldap_resp_controls[0].derefRes[MEMBER_ATTR]
                            for deref_dn, deref_entry in member_deref_result:
                                if int(deref_entry['aeStatus'][0]) <= 0:
                                    new_members.add(deref_dn)
                                    try:
                                        new_member_attr_values.add(deref_entry[member_user_attr][0])
                                    except KeyError:
                                        self.logger.error(
                                            'Attribute %r not found in entry %r: %r',
                                            member_user_attr,
                                            deref_dn,
                                            deref_entry,
                                        )

                except ldap.LDAPError, ldap_error:
                    self.logger.error(
                        u'LDAPError searching members for %r with %r and %r: %s',
                        dyn_group_dn,
                        member_url,
                        dyn_group_filter,
                        ldap_error,
                    )
                    continue

            self._update_members(
                dyn_group_dn,
                member_map_attr,
                old_members,
                new_members,
                old_member_attr_values,
                new_member_attr_values
            )
        return # end of update_memberurl_groups()

    def run_worker(self, state):
        """
        the main program
        """
        self.logger.debug('invoke update_memberurl_groups()')
        self.update_memberurl_groups()
        self.logger.debug('invoke fix_static_groups()')
        self.fix_static_groups()
        return # end of run_worker()


if __name__ == '__main__':
    with AEGroupUpdater() as ae_process:
        ae_process.run(max_runs=1)
