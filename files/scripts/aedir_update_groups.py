#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This script updates static aeGroup entries which contain attribute
'memberURL'.

It is designed to run as a CRON job.

Author: Michael Ströder <michael@stroeder.com>
"""

__version__ = '0.3.3'

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# Number of times connecting to LDAP is tried
LDAP_MAXRETRYCOUNT = 3
LDAP_RETRYDELAY = 10.0

# LDAP timeout
LDAP_TIMEOUT = 10.0

# List of attribute values to be added if there were no valid group members found
#EMPTYGROUP_VALUES = ['cn=dummy']
EMPTYGROUP_VALUES = None

# Attribute containing the group member references
MEMBER_ATTR = 'member'
# Attribute containing the LDAP URLs to be searched
MEMBERURL_ATTR = 'memberURL'

# Only run if this CNAME RR in DNS points to this host.
# Set to None to disable this check.
ENSURE_DNS_CNAME = None

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# Modules from Python's standard library
import sys,os,getpass,time,logging,urllib
import socket

# Import python-ldap modules/classes
import ldap,ldap.sasl,ldap.modlist,ldap.resiter,ldapurl
from ldap.ldapobject import ReconnectLDAPObject
from logging.handlers import SysLogHandler

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


class MyLDAPUrl(ldapurl.LDAPUrl):
  attr2extype = {
    'who':'bindname',
    'cred':'X-BINDPW',
    'start_tls':'startTLS',
    'trace_level':'trace',
  }


class MyLDAPObject(ReconnectLDAPObject,ldap.resiter.ResultProcessor):

  def __init__(self,ldap_url):
    """
    Connect and bind

    Calling code has to handle errors!
    """
    lu = MyLDAPUrl(ldap_url)
    trace_level = int(lu.trace_level or '0')
    start_tls = int(lu.start_tls or '1')
    ReconnectLDAPObject.__init__(self,lu.initializeUrl(),trace_level=trace_level,trace_file=sys.stderr)
    # Switch of automatic referral chasing
    self.set_option(ldap.OPT_REFERRALS,0)
    # Set timeout values
    self.set_option(ldap.OPT_NETWORK_TIMEOUT,LDAP_TIMEOUT)
    self.set_option(ldap.OPT_TIMEOUT,LDAP_TIMEOUT)
    if lu.urlscheme.lower()=='ldap' and start_tls:
      self.start_tls_s()
    if lu.urlscheme.lower()=='ldapi' and lu.who==None:
      self.sasl_interactive_bind_s('',ldap.sasl.external())
    else:
      who = lu.who or ''
      cred = lu.cred or ''
      if who and not cred:
        cred = getpass.getpass('Password for %s:' % (who))
      # Temporarily disable trace log to protect the password
      self._trace_level = 0
      self.simple_bind_s(who,cred)
      # LDAP-Trace aus Sicherheitsgruenden nach dem Bind einschalten
      self._trace_level = trace_level
    return # MyLDAPObject.__init__()


def LDAPConnectionConsole(ldap_url):
  """
  Connect and bind to LDAP server and display status/errors on console
  """
  try:
    ldap_conn = MyLDAPObject(ldap_url)
    ldap_conn_whoami = ldap_conn.whoami_s()
  except ldap.LDAPError,e:
    sys.stderr.write(u'LDAP error while connecting/binding to %s: %s\n' % (repr(ldap_url),str(e)))
    sys.exit(1)
  else:
    sys.stdout.write(u'Bound as: %s\n' % (repr(ldap_conn_whoami)))
  return ldap_conn,ldap_conn_whoami


# Encoding der Ausgaben
OUTPUT_ENCODING = sys.stdout.encoding or 'utf-8'

# Check whether to run or not
if ENSURE_DNS_CNAME:
  host_fqdn = socket.getfqdn()
  if socket.gethostbyname(ENSURE_DNS_CNAME)!=socket.gethostbyname(host_fqdn):
    sys.stdout.write(u'Not running on %s as %s differs\n' % (repr(host_fqdn), repr(ENSURE_DNS_CNAME)))
    sys.exit(0)

# LDAP-URL
try:
  ldap_url = sys.argv[1]
except IndexError:
  ldap_url = 'ldapi://'

ldap_conn,ldap_conn_whoami = LDAPConnectionConsole(ldap_url)

lu = MyLDAPUrl(ldap_url)

dynamic_groups = ldap_conn.search_s(
  lu.dn,
  lu.scope or ldap.SCOPE_SUBTREE,
  lu.filterstr or '(%s=*)' % (MEMBERURL_ATTR),
  attrlist=['objectClass','cn',MEMBER_ATTR,MEMBERURL_ATTR],
)

for ldap_group_dn,ldap_group_entry in dynamic_groups:

  old_members = set(ldap_group_entry.get(MEMBER_ATTR,[]))

  new_members = set()

  for member_url in ldap_group_entry[MEMBERURL_ATTR]:

    member_url_obj = ldapurl.LDAPUrl(member_url)
    try:
      ldap_member_users = ldap_conn.search_s(
        member_url_obj.dn,
        member_url_obj.scope,
        member_url_obj.filterstr,
        attrlist=['cn','entryUUID']+(member_url_obj.attrs or []),
      )
    except ldap.LDAPError,e:
      sys.stderr.write(u'LDAPError searching members for %s with %s: %s\n' % (
        repr(ldap_group_dn),
        repr(member_url),
        str(e),
      ))
      continue

    if member_url_obj.attrs==None:
      new_members.update([
        ldap_user_dn
        for ldap_user_dn,ldap_user_entry in ldap_member_users
      ])
    else:
      for ldap_user_dn,ldap_user_entry in ldap_member_users:
        for attr_type in member_url_obj.attrs:
          new_members.update(ldap_user_entry.get(attr_type,[]))

  new_members = new_members or set(EMPTYGROUP_VALUES or [])

  ldap_group_modlist = []

  remove_members = old_members-new_members
  if remove_members:    
    ldap_group_modlist.append((ldap.MOD_DELETE,MEMBER_ATTR,list(remove_members)))

  add_members = new_members-old_members
  if add_members:
    ldap_group_modlist.append((ldap.MOD_ADD,MEMBER_ATTR,list(add_members)))

  if ldap_group_modlist:
    sys.stdout.write(u'Update members of group entry %s: remove %d, add %d\n' % (
      repr(ldap_group_dn),
      len(remove_members),
      len(add_members)
    ))
    try:
      ldap_conn.modify_s(ldap_group_dn,ldap_group_modlist)
    except ldap.LDAPError,e:
      sys.stderr.write(u'LDAPError modifying %s: %s\nldap_group_modlist = %s\n' % (repr(ldap_group_dn),str(e),repr(ldap_group_modlist)))

ldap_conn.unbind_s()
