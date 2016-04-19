#!/bin/sh

/usr/local/sbin/slapd_checkmk.py \
  'ldapi://%2Fusr%2Flocal%2Fopenldap%2Fvar%2Frun%2Fldapi' \
  "ldaps://$(hostname -f)" \
  "dn:uid=system_slapd-repl-$(hostname),cn=ae,ou=ae-dir"
