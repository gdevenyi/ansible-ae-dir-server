#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Sets the password of the specified aeUser or aeService referenced by 
uid attribute

This script must run locally run on a Æ-DIR provider
"""

import sys
import os
import getpass

# from python-ldap
import ldap
import ldap.sasl

LDAP_URI = 'ldapi://%2Fusr%2Flocal%2Fopenldap%2Fvar%2Frun%2Fldapi'
LDAP_SEARCHBASE = 'ou=ae-dir'
LDAP_FILTER_TMPL = '(&(|(objectClass=aeUser)(objectClass=aeService)(objectClass=aeHost))(|(uid={0})(host={0})))'

try:
    arg_value = sys.argv[1]
except IndexError:
    sys.stderr.write('You have to provide a username or hostname (FQDN)!\n')
    sys.exit(9)
  

ldap_conn = ldap.initialize(LDAP_URI)
ldap_conn.sasl_external_bind_s()

ldap_result = ldap_conn.search_ext_s(
    LDAP_SEARCHBASE,
    ldap.SCOPE_SUBTREE,
    LDAP_FILTER_TMPL.format(arg_value),
    attrlist=['1.1'],
    sizelimit=2,
)

if not ldap_result:
    sys.stderr.write('\n')
    sys.exit(1)
elif len(ldap_result)>1:
    sys.stderr.write('\n')
    sys.exit(1)

dn, _ = ldap_result[0]

new_password1 = getpass.getpass('new password for {}: '.format(dn))
new_password2 = getpass.getpass('repeat password: ')

if new_password1!=new_password2:
    sys.stderr.write('2nd input for new password differs!\n')
    sys.exit(1)

try:
    ldap_conn.passwd_s(dn, None, new_password1)
except ldap.LDAPError, ldap_err:
    sys.stderr.write('LDAPError: {}\n'.format(str(ldap_err)))
    sys.exit(1)

ldap_conn.unbind_s()
