#!/opt/ae-dir/bin/python
# -*- coding: utf-8 -*-
"""
Prepare moving aeUser entries beneath aeZone with appropriate aeDept set
"""

__version__ = '0.1.0'

import sys
import os
import csv

# set LDAPRC env var *before* importing ldap
os.environ['LDAPRC'] = '/opt/ae-dir/etc/ldap.conf'
import ldap
import aedir
from ldap.controls.deref import DereferenceControl

PYLDAP_TRACE_LEVEL = 0

CACHE_TTL = 10

DEREF_CONTROL = DereferenceControl(
    True,
    {
        'aePerson': ['aeDept'],
    }
)

#---------------------------------------------------------------------------
# main()
#---------------------------------------------------------------------------

ldap._trace_level = PYLDAP_TRACE_LEVEL

ldap_conn = aedir.AEDirObject(
    None,
    trace_level=PYLDAP_TRACE_LEVEL,
    cache_ttl=CACHE_TTL,
)

aedir_search_base = ldap_conn.find_search_base()

aeuser_filter = (
  '(&'
    '(objectClass=aeUser)'
    '(uid=*)'
    '(aeStatus=0)'
    '(!'
      '(|'
        '(memberOf=cn=ae-all-zone-admins,cn=ae,{aedir_search_base})'
        '(memberOf=cn=ae-all-zone-auditors,cn=ae,{aedir_search_base})'
      ')'
    ')'
  ')'
).format(aedir_search_base=aedir_search_base)

msg_id = ldap_conn.search_ext(
    'cn={},'.format(sys.argv[1])+aedir_search_base,
    ldap.SCOPE_SUBTREE,
    aeuser_filter,
    attrlist=['uid'],
    serverctrls = [DEREF_CONTROL],
)

for res_type, res_data, res_msgid, res_controls in ldap_conn.allresults(
    msg_id,
    add_ctrls=1
):
    for dn, entry, controls in res_data:
        # process dn and entry
        if controls:
            deref_control = controls[0]
            deref_dn, deref_entry = deref_control.derefRes['aePerson'][0]
            try:
                ae_dept = deref_entry['aeDept'][0]
            except KeyError:
                # aePerson -> aeDept reference missing => ignore
                continue
        try:
            new_zone_dn = ldap_conn.find_unique_entry(
                aedir_search_base,
                ldap.SCOPE_ONELEVEL,
                '(&(objectClass=aeZone)(aeStatus=0)(aeDept={}))'.format(ae_dept),
                attrlist=['1.1'],
            )[0]
        except (ldap.LDAPError, KeyError), err:
            #  => ignore
            sys.stderr.write('searching new zone failed: %s\n' % (err))
        else:
            ldap_conn.rename_s(
                dn,
                'uid={}'.format(entry['uid'][0]),
                new_zone_dn,
            )
            sys.stdout.write('moved %r beneath %r\n' % (
                dn,
                new_zone_dn,
            ))
