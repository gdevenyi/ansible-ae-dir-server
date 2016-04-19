#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
check_mk script for OpenLDAP (local check)

Needs read access to rootDSE and cn=config and cn=monitor
(or whereever rootDSE attributes 'configContext' and 'monitorContext'
are pointing to)

Steps:
- Connect and bind to local slapd via LDAPI
- Determine naming, config and monitor contexts
- Read and parse syncrepl topology from cn=config
- Read performance data from cn=Monitor
- Read local contextCSN attribute(s)
- Connect and bind to local slapd via LDAPS to check server cert
- Connect and bind to all replicas to check whether they are reachable
- Read and compare attribute contextCSN of all replicas
"""

__version__ = '1.0.0'

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

STATE_FILENAME = 'slapd_checkmk.state'

PYLDAP_TRACE_LEVEL = 0

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap.OPT_NETWORK_TIMEOUT and ldap.OPT_TIMEOUT 
LDAP_TIMEOUT = 4.0

# Time in seconds for searching all entries with the noop search control
NOOP_SEARCH_TIMEOUT = 6.0
# at least search root entry should be present
MINIMUM_ENTRY_COUNT = 1

# acceptable time-delta [sec] of replication
# Using None disables checking the warn/critical level
SYNCREPL_TIMEDELTA_WARN = 5.0
SYNCREPL_TIMEDELTA_CRIT = 300.0
# hysteresis for syncrepl conditions
SYNCREPL_HYSTERESIS_WARN = 0.0
SYNCREPL_HYSTERESIS_CRIT = 10.0

# Exception used to catch all exceptions
# (set to None to get tracebacks of unhandled exceptions)
CATCH_ALL_EXCEPTION = Exception
#CATCH_ALL_EXCEPTION = None

# acceptable count of all outstanding operations
# Using None disables checking the warn/critical level
OPS_WAITING_WARN = 30
OPS_WAITING_CRIT = 60

CONNECTIONS_WARN_LOWER = 3
CONNECTIONS_WARN_UPPER = 3000

# Tresholds for thread-count-related warnings
# There should always be at least one active thread
THREADS_ACTIVE_WARN_LOWER = 0
# This should match what's configured on your server
THREADS_ACTIVE_WARN_UPPER = 6
# Many pending threads should not occur
THREADS_PENDING_WARN = 5

#-----------------------------------------------------------------------
# Import modules
#-----------------------------------------------------------------------

import os,sys,socket,time,pprint,traceback,logging

# from python-ldap
import ldap,ldap.sasl,ldapurl
from ldap import LDAPError
from ldap.ldapobject import ReconnectLDAPObject
from ldap.controls.simple import ValueLessRequestControl,ResponseControl
from ldapurl import LDAPUrl

# from pyasn1
from pyasn1.type import univ
from pyasn1.codec.ber import decoder
from pyasn1.error import PyAsn1Error

#-----------------------------------------------------------------------
# Classes
#-----------------------------------------------------------------------


class LocalCheck:
  """
  Simple class for writing check_mk output
  """
  CHECKMK_STATUS = {0:'OK',1:'WARNING',2:'ERROR',3:'UNKNOWN'}

  def __init__(self,item_names,output_file,output_encoding,state_filename=None):
    """
    item_names
        List/tuple of all known check_mk item names this check should output
    output_file
        fileobj where to write the output
    output_encoding
        encoding to use when writing output
        'ascii' is always safe, Nagios mandates 'utf-8'
    """
    self._item_names = []
    self._item_dict = {}
    for item_name in item_names:
      self.add_item(item_name)
    self._output_file = output_file
    self._output_encoding = output_encoding
    if state_filename!=None:
      # Initialize local state file and read old state if it exists
      self._state = CheckStateFile(STATE_FILENAME)
      # Generate *new* state dict to be updated within check and stored later
      self._next_state = {}
    self.script_name = os.path.basename(sys.argv[0])
    return # __init__()

  def checks(self):
    raise Exception("Not implemented.")

  def run(self):
    try:
      try:
        self.checks()
      except Exception,e:
        # Log unhandled exception
        err_lines = [66*'-']
        err_lines.append('----------- %s.__class__.__dict__ -----------' % (self.__class__.__name__))
        err_lines.append(pprint.pformat(self.__class__.__dict__,indent=1,width=66,depth=None))
        err_lines.append('----------- vars() -----------')
        err_lines.append(pprint.pformat(vars(),indent=1,width=66,depth=None))
        logging.exception('\n'.join(err_lines))
    finally:
      self.output()
      if self._state:
        self._state.write_state(self._next_state)

  def add_item(self,item_name):
    if item_name in self._item_names:
      raise ValueError,'Check item name %s already existent.' % (repr(item_name))
    self._item_names.append(item_name)
    self._item_dict[item_name] = None

  def _subst_item_name_chars(self,s):
    s_list = []
    for c in s:
      if c in ITEM_NAME_SPECIAL_CHARS:
        s_list.append('_')
      else:
        s_list.append(c)
    return ''.join(s_list) # _subst_item_name_chars()

  def result_line(self,status,item_name,performance_data=None,check_output=None):
    """
    Registers check_mk result to be output later
    status
       integer indicating status
    item_name
       the check_mk item name
    """
    # Provoke KeyError or ValueError if status is not known integer
    status_str = self.CHECKMK_STATUS[status]
    # Provoke KeyError if item_name is not known
    try:
      self._item_dict[item_name]
    except KeyError:
      raise ValueError,'item_name %s not in known item names %s' % (
        item_name,
        repr(self._item_names),
      )
    self._item_dict[item_name] = (
      str(status),
      self._subst_item_name_chars(item_name),
      performance_data or u'-',
      status_str,
      u'-',
      check_output or u'',
    )
    return # result_line()

  def output(self):
    """
    Outputs all check results registered before with method result_line()
    """
    item_names = self._item_names
    item_names.sort()
    for i in item_names:
      if not self._item_dict[i]:
        self.result_line(3,i,check_output='No defined check result yet!')
      sys.stdout.write(
        u'%s\n' % u' '.join(self._item_dict[i]).encode(self._output_encoding)
      )
    return # output()


class CheckStateFile:
  line_sep = '\n'

  def __init__(self,state_filename):
    self._state_filename = state_filename
    self.d = self.read_state()

  def read_state(self):
    try:
      state_tuple_list = []
      f = open(self._state_filename,'rb')
      state_string_list = f.read().split(self.line_sep)
      f.close()
      state_tuple_list = [
        line.split('=',1)
        for line in state_string_list
        if line
      ]
      return dict(state_tuple_list)
    except CATCH_ALL_EXCEPTION,e:
      return {}

  def write_state(self,d):
    state_string_list = [
      '='.join((str(k),str(v)))
      for k,v in d.items()
    ]
    state_string_list.append('')
    f = open(self._state_filename,'wb')
    f.write(self.line_sep.join(state_string_list))
    f.close()


class SyncReplDesc:
  known_keywords = (
    'rid','provider',
    'searchbase','scope','filter','attrs','exattrs','attrsonly',
    'binddn','bindmethod','credentials','authcid','authzid','saslmech','realm','secprops',
    'type','syncdata','logbase','logfilter','suffixmassage','schemachecking',
    'keepalive','interval', 'retry',
    'sizelimit','network-timeout','timelimit','timeout',
    'starttls','tls_cacert','tls_cacertdir','tls_cert','tls_ciphersuite','tls_crlcheck','tls_key','tls_reqcert',
  )

  def __init__(self,syncrepl_statement):
    """
    syncrepl_statement
       syncrepl statement without any line breaks
    """
    # strip all white spaces from syncrepl statement parameters
    syncrepl_statement = syncrepl_statement.strip()
    # Set class attributes for all known keywords
    for k in self.known_keywords:
      setattr(self,k.replace('-','_'),None)
    b = []
    for k in self.known_keywords:
      k_pos = syncrepl_statement.find(k)
      if k_pos==0 or (k_pos>0 and syncrepl_statement[k_pos-1]==' '):
        b.append(k_pos)
    b.sort()
    for i in range(len(b)-1):
      k,v = syncrepl_statement[b[i]:b[i+1]].split('=',1)
      k = k.strip()
      v = v.strip()
      if v[0]=='"' and v[-1]=='"':
        v = v[1:-1]
      setattr(self,k.replace('-','_'),v)

  def ldap_url(self):
    """
    Return ldapurl.LDAPUrl object representing some syncrepl parameters
    as close as possible.
    """
    lu = ldapurl.LDAPUrl(self.provider)
    lu.dn = self.searchbase
    lu.scope = {
      'sub':ldapurl.LDAP_SCOPE_SUBTREE,
      'one':ldapurl.LDAP_SCOPE_ONELEVEL,
      'base':ldapurl.LDAP_SCOPE_BASE,
      'subord':ldapurl.LDAP_SCOPE_SUBTREE, # FIX ME: this is a work-around
    }[self.scope]
    lu.filterstr = self.filter
    lu.who = self.authcid or self.binddn
    lu.cred = self.credentials
    lu.attrs = filter(None,[ a.strip() for a in (self.attrs or '').strip().replace(' ',',').split(',') ]) or ['*','+']
    return lu


class SearchNoOpControl(ValueLessRequestControl,ResponseControl):
  """
  No-op control attached to search operations implementing sort of a
  count operation

  see http://www.openldap.org/its/index.cgi?findid=6598
  """
  controlType = '1.3.6.1.4.1.4203.666.5.18'

  def __init__(self,criticality=False):
    self.criticality = criticality

  class SearchNoOpControlValue(univ.Sequence):
    pass

  def decodeControlValue(self,encodedControlValue):
    decodedValue,_ = decoder.decode(encodedControlValue,asn1Spec=self.SearchNoOpControlValue())
    self.resultCode = int(decodedValue[0])
    self.numSearchResults = int(decodedValue[1])
    self.numSearchContinuations = int(decodedValue[2])

ldap.controls.KNOWN_RESPONSE_CONTROLS[SearchNoOpControl.controlType] = SearchNoOpControl


class OpenLDAPMonitorCache:
  BDB_BACKENDS = set(('bdb','hdb'))

  def __init__(self,monitor_dict,monitor_context):
    self._c = monitor_context
    self._d = monitor_dict

  def get_value(self,dn_prefix,attribute):
    return int(self._d[','.join((dn_prefix,self._c))][attribute][0])

  def bdb_caches(self):
    database_suffix_lower = ','.join(('','cn=Databases',self._c)).lower()
    result = [
      (
        int(entry['cn'][0].split(' ')[1]),
        entry['namingContexts'][0],
        int(entry['olmBDBDNCache'][0]),
        int(entry['olmBDBEntryCache'][0]),
        int(entry['olmBDBIDLCache'][0]),
      )
      for dn,entry in self._d.items()
      if dn.lower().endswith(database_suffix_lower) and \
         entry['cn'][0].startswith('Database ') and \
         entry['monitoredInfo'][0] in self.BDB_BACKENDS
    ]
    return result # bdb_caches()

  def operation_counters(self):
    op_counter_suffix_lower = ','.join(('',   'cn=Operations',self._c)).lower()
    return [
      (
        entry['cn'][0],
        int(entry['monitorOpInitiated'][0]),
        int(entry['monitorOpCompleted'][0]),
      )
      for dn,entry in self._d.items()
      if dn.lower().endswith(op_counter_suffix_lower)
    ]


class OpenLDAPObject:

  def get_monitor_entries(self,monitor_context):
    return dict(self.search_s(
      monitor_context,
      ldap.SCOPE_SUBTREE,
      '(|(objectClass=monitorOperation)(objectClass=monitoredObject)(objectClass=monitorCounterObject))',
      attrlist=['cn','monitorOpInitiated','monitorOpCompleted','monitorCounter','monitoredInfo','seeAlso','namingContexts'],
    ))

  def get_rootdse_attrs(self,attrlist=None):
    _,ldap_rootdse = self.search_s(
      '',
      ldap.SCOPE_BASE,
      '(objectClass=*)',
      attrlist=attrlist or ['*','+'],
    )[0]
    return ldap_rootdse # get_rootdse_attrs()

  def get_naming_context_attrs(self):
    return self.get_rootdse_attrs(attrlist=['configContext','namingContexts','monitorContext'])

  def _parse_csn_list(self,csnlist,strictcheck=False):
    csns = {}
    for csn in csnlist:
      try:
        # format example 20130701155956.727040Z#000000#00b#000000
        timestamp,_,server_id,_ = csn.split("#")
        csns[server_id] = time.mktime(time.strptime(timestamp,'%Y%m%d%H%M%S.%fZ'))
      except CATCH_ALL_EXCEPTION,e:
        if strictcheck:
          raise Exception('Cannot parse csn %s: %s' % (repr(csn), repr(e)))
        else:
          #ignore this value
          continue
    return csns # parse_csn_list()

  def get_context_csns(self,naming_context):
    ldap_result = self.search_s(naming_context,ldap.SCOPE_BASE,'(contextCSN=*)',attrlist=['objectClass','contextCSN'])
    try:
      return self._parse_csn_list(ldap_result[0][1]['contextCSN'])
    except (IndexError,KeyError),e:
      return None

  def get_syncrepl(self,config_context):
    ldap_result = self.search_s(
      config_context,
      ldap.SCOPE_ONELEVEL,
      '(&(objectClass=olcDatabaseConfig)(olcDatabase=*)(olcSyncrepl=*)(olcSuffix=*))',
      attrlist=['olcDatabase','olcSuffix','olcSyncrepl'],
    )
    result = []
    for _,ldap_entry in ldap_result:
      db_num = int(ldap_entry['olcDatabase'][0].split('}')[0][1:])
      sr = [
        SyncReplDesc(attr_value)
        for attr_value in ldap_entry['olcSyncrepl']
      ]
      result.append((
        db_num,
        ldap_entry['olcSuffix'][0],
        sr,
      ))
    return result # get_syncrepl()

  def db_suffixes(self,config_context):
    ldap_result = self.search_s(
      config_context,
      ldap.SCOPE_ONELEVEL,
      '(&(|(objectClass=olcBdbConfig)(objectClass=olcHdbConfig)(objectClass=olcMdbConfig))(olcDatabase=*)(olcDbDirectory=*)(olcSuffix=*))',
      attrlist=['olcDatabase','olcSuffix','olcDbDirectory'],
    )
    result = []
    for dn,entry in ldap_result:
      db_num,db_type = entry['olcDatabase'][0][1:].split('}',1)
      db_num = int(db_num)
      db_suffix = entry['olcSuffix'][0]
      db_dir = entry['olcDbDirectory'][0]
      result.append((db_num,db_suffix,db_type,db_dir))
    return result # db_suffixes()

  def noop_search_st(self,base,scope=ldap.SCOPE_SUBTREE,filterstr='(objectClass=*)',timeout=-1):
    try:
      msg_id = self.search_ext(
        base,
        scope,
        filterstr=filterstr,
        attrlist=['1.1'],
        timeout=timeout,
        serverctrls=[SearchNoOpControl(criticality=True)],
      )
      _,_,_,search_response_ctrls = self.result3(msg_id,all=1,timeout=timeout)
    except (ldap.TIMEOUT,ldap.TIMELIMIT_EXCEEDED,ldap.SIZELIMIT_EXCEEDED,ldap.ADMINLIMIT_EXCEEDED),e:
      self.abandon(msg_id)
      raise e
    else:
      noop_srch_ctrl = [
        c
        for c in search_response_ctrls
        if c.controlType==SearchNoOpControl.controlType
      ]
      if noop_srch_ctrl:
        return noop_srch_ctrl[0].numSearchResults,noop_srch_ctrl[0].numSearchContinuations
      else:
        return None


class SlapdCheckLDAPObject(ReconnectLDAPObject,OpenLDAPObject):

  def __init__(self,*args,**kwargs):
    ReconnectLDAPObject.__init__(self,*args,**kwargs)
    # Switch of automatic referral chasing
    self.set_option(ldap.OPT_REFERRALS,0)
    # Switch of automatic alias dereferencing
    self.set_option(ldap.OPT_DEREF,ldap.DEREF_NEVER)
    # Set timeout values
    self.set_option(ldap.OPT_NETWORK_TIMEOUT,LDAP_TIMEOUT)
    self.set_option(ldap.OPT_TIMEOUT,LDAP_TIMEOUT)


#-----------------------------------------------------------------------
# Functions
#-----------------------------------------------------------------------

ITEM_NAME_SPECIAL_CHARS = set(list('!:$%=\\'))

def subst_item_name_chars(s):
  s_list = []
  for c in s:
    if c in ITEM_NAME_SPECIAL_CHARS:
      s_list.append('_')
    else:
      s_list.append(c)
  return ''.join(s_list)

def derive_syncrepl_topology(sr_list):
  syncrepl_topology = {}
  for db_num,db_suffix,sr_obj_list in sr_list:
    for sr_obj in sr_obj_list:
      provider_uri = sr_obj.provider
      try:
        syncrepl_topology[provider_uri].append((db_num,db_suffix,sr_obj))
      except KeyError:
        syncrepl_topology[provider_uri] = [(db_num,db_suffix,sr_obj)]
  return syncrepl_topology # get_syncrepl_topology()


class SlapdCheck(LocalCheck):

  def checks(self):

    # Determine own fully-qualified domain name
    host_fqdn = socket.getfqdn()

    # Get command-line arguments
    local_ldapi_url = sys.argv[1] or 'ldapi:///'
    ldaps_uri = sys.argv[2] or 'ldaps://%s' % host_fqdn
    my_authz_id = sys.argv[3]

    # ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
    ldap._trace_level = PYLDAP_TRACE_LEVEL

    # Switch off processing .ldaprc or ldap.conf
    os.environ['LDAPNOINIT']='0'

    # Connect and bind with LDAPI mainly to read cn=config and cn=monitor later
    #--------------------------------------------------------------------------

    try:
      ldap_conn = SlapdCheckLDAPObject(
        local_ldapi_url,
        trace_level=PYLDAP_TRACE_LEVEL
      )
      # Send SASL/EXTERNAL bind request which really opens the connection
      ldap_conn.sasl_interactive_bind_s('',ldap.sasl.sasl({}, 'EXTERNAL'))
      # Find out whether bind worked
      local_wai = ldap_conn.whoami_s()
    except LDAPError,e:
      self.result_line(2,'LdapConfigBackend',check_output='LDAPError connecting to %s: %s' % (repr(local_ldapi_url),str(e)))
      sys.exit(1)
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapConfigBackend',check_output='Exception while connecting to %s: %s' % (repr(local_ldapi_url),str(e)))
      sys.exit(1)

    # 0. Connect and bind to local slapd like a remote client
    # mainly to check whether LDAPS with client cert works and maps expected authz-DN
    #--------------------------------------------------------------------------------

    try:
      naming_contexts = ldap_conn.get_naming_context_attrs()
      config_context = naming_contexts['configContext'][0]
      monitor_context = naming_contexts['monitorContext'][0]
    except LDAPError,e:
      self.result_line(2,'LdapConfigBackend',check_output='LDAPError getting local configuration on %s: %s' % (repr(ldap_conn._uri),str(e)))
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapConfigBackend',check_output='unknown error getting local configuration on %s: %s' % (repr(ldap_conn._uri),str(e)))
    else:
      self.result_line(0,'LdapConfigBackend',check_output='Successfully connected to %s as %s found %s and %s' % (
        repr(ldap_conn._uri),
        repr(local_wai),
        repr(config_context),
        repr(monitor_context),
      ))
      _,config_tls_attrs = ldap_conn.search_ext_s(
        config_context,
        ldap.SCOPE_BASE,
        [
          'olcTLSCACertificateFile',
          'olcTLSCertificateFile',
          'olcTLSCertificateKeyFile',
        ],
        '(objectClass=*)',
      )

    try:
      ldaps_conn = SlapdCheckLDAPObject(
        ldaps_uri,
        trace_level=PYLDAP_TRACE_LEVEL
      )
      # Force server cert validation
      ldaps_conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,ldap.OPT_X_TLS_DEMAND)
      # Set TLS connection options from TLS attribute read from configuration context
      for ldap_option,attr_type in (
        # path name of file containing all trusted CA certificates
        (ldap.OPT_X_TLS_CACERTFILE,'olcTLSCACertificateFile'),
        # Use slapd server cert/key for client authentication just like used for syncrepl
        (ldap.OPT_X_TLS_CERTFILE,'olcTLSCertificateFile'),
        (ldap.OPT_X_TLS_KEYFILE,'olcTLSCertificateKeyFile'),
      ):
        ldaps_conn.set_option(ldap_option,config_tls_attrs[attr_type])
      # Reinitialize SSL context
      ldaps_conn.set_option(ldap.OPT_X_TLS_NEWCTX,0)
      # Send SASL/EXTERNAL bind request which really opens the connection
      ldaps_conn.sasl_interactive_bind_s('',ldap.sasl.sasl({}, 'EXTERNAL'))
    except LDAPError,e:
      self.result_line(2,'LdapSelfConnection',check_output='LDAPError connecting to %s: %s' % (repr(ldaps_uri),str(e)))
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapSelfConnection',check_output='Exception while connecting to %s: %s' % (repr(ldaps_uri),str(e)))
    else:
      # Send LDAP Who Am I ? extended operation and check whether returned authz-DN is correct
      try:
        wai = ldaps_conn.whoami_s()
      except CATCH_ALL_EXCEPTION,e:
        self.result_line(2,'LdapSelfConnection',check_output='LDAPError during Who Am I? ext.op. on %s: %s' % (repr(ldaps_conn._uri),str(e)))
      else:
        if wai != my_authz_id:
          self.result_line(2,'LdapSelfConnection',check_output='Received unexpected authz-DN from %s: %s' % (repr(ldaps_conn._uri),repr(wai)))
        else:
          self.result_line(0,'LdapSelfConnection',check_output='successfully bound to %s as %s' % (
            repr(ldaps_conn._uri),
            repr(wai),
          ))
      ldaps_conn.unbind_s()

    syncrepl_list = []
    syncrepl_topology = {}
    try:
      syncrepl_list = ldap_conn.get_syncrepl(config_context)
    except LDAPError,e:
      self.result_line(1,'LdapReplTopology',check_output='LDAPError getting syncrepl topology on %s: %s' % (repr(ldap_conn._uri),str(e)))
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapReplTopology',check_output='unknown error getting getting syncrepl topology on %s: %s' % (repr(ldap_conn._uri),str(e)))
    else:
      syncrepl_topology = derive_syncrepl_topology(syncrepl_list)
      self.result_line(0,'LdapReplTopology',check_output='successfully retrieved syncrepl topology with %d items: %s' % (
        len(syncrepl_topology),
        syncrepl_topology,
      ))


    # 1. Read several data from cn=Monitor
    #-----------------------------------------------------------------------

    monitor_dict = {}
    try:
      monitor_dict = ldap_conn.get_monitor_entries(monitor_context)
    except LDAPError,e:
      self.result_line(2,'LdapMonitorBackend',check_output='LDAPError getting local monitor data on %s: %s' % (repr(ldap_conn._uri),str(e)))
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapMonitorBackend',check_output='unknown error getting local monitor data on %s: %s' % (repr(ldap_conn._uri),str(e)))
    else:
      self.result_line(0,'LdapMonitorBackend',check_output='Successfully retrieved %d entries from %s on %s' % (
        len(monitor_dict),
        repr(monitor_context),
        repr(ldap_conn._uri),
      ))

    try:
      monitor_cache = OpenLDAPMonitorCache(monitor_dict,monitor_context)
      c = monitor_cache.get_value('cn=Current,cn=Connections','monitorCounter')
      # We expect one per existing machine, plus a low number for web2ldap,
      # equally distributed over the nodes:
      state = int(c<CONNECTIONS_WARN_LOWER or c>CONNECTIONS_WARN_UPPER)
      self.result_line(
        state,'LdapConnectionCount',
        performance_data='count=%d' % (c),
        check_output='%d open connections' % (c)
      )
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapConnectionCount',check_output='error retrieving connection counter: %s' % (str(e)))

    try:
      threads_active = monitor_cache.get_value('cn=Active,cn=Threads','monitoredInfo')
      threads_pending = monitor_cache.get_value('cn=Pending,cn=Threads','monitoredInfo')
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapThreads',check_output='Error while retrieving thread counters: %s' % repr(e))
    else:
      state = int(
        threads_active<=THREADS_ACTIVE_WARN_LOWER or \
        threads_active>=THREADS_ACTIVE_WARN_UPPER or \
        threads_pending>=THREADS_PENDING_WARN
      )
      self.result_line(
        state,
        'LdapThreads',
        performance_data='threads_active=%d|threads_pending=%d' % (threads_active,threads_pending),
        check_output='Thread counts active:%d pending: %d' % (threads_active,threads_pending)
      )

    try:
      hdb_caches = monitor_cache.bdb_caches()
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapBdbCaches',check_output='error retrieving HDB caches: %s' % (str(e)))
    else:
      self.result_line(0,'LdapBdbCaches',check_output='Found %d BDB/HDB database entries.' % (len(hdb_caches)))
      for db_num,db_suffix,bdb_dn_cache,bdb_entry_cache,bdb_idl_cache in hdb_caches:
        item_name = '_'.join(('LdapBdbCache',str(db_num),subst_item_name_chars(db_suffix)))
        self.add_item(item_name)
        self.result_line(
          0,item_name,
          performance_data='bdb_dn_cache=%d|bdb_entry_cache=%d|bdb_idl_cache=%d' % (
            bdb_dn_cache,bdb_entry_cache,bdb_idl_cache,
          ),
          check_output='BDB %d cache %s: DN=%d entry=%d IDL=%d' % (
            db_num,repr(db_suffix),bdb_dn_cache,bdb_entry_cache,bdb_idl_cache,
          )
        )

    try:
      db_suffixes = ldap_conn.db_suffixes(config_context)
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapDBSuffixes',check_output='error retrieving DB suffixes: %s' % (str(e)))
    else:
      self.result_line(0,'LdapDBSuffixes',check_output='Found %d real databases: %s' % (
        len(db_suffixes),
        ' / '.join([ '{%d}%s: %s' % (n,t,s) for n,s,t,_ in db_suffixes ]),
      ))
      for db_num,db_suffix,db_type,db_dir in db_suffixes:
        # Check file sizes of MDB database files
        if db_type=='mdb':
          item_name = '_'.join(('LdapMDBSize',str(db_num),subst_item_name_chars(db_suffix)))
          self.add_item(item_name)
          mdb_filename = os.path.join(db_dir,'data.mdb')
          try:
            mdb_max_size = os.stat(mdb_filename).st_size
            mdb_real_size = os.stat(mdb_filename).st_blocks*512
          except OSError,e:
            self.result_line(2,item_name,check_output='OS error stating %s: %s' % (
              repr(mdb_filename),
              repr(e),
            ))
          else:
            mdb_use_percentage = 100 * float(mdb_real_size) / float(mdb_max_size)
            self.result_line(0,item_name,check_output='DB file %s has %d of max. %d bytes (%0.1f %%)' % (
              repr(mdb_filename),mdb_real_size,mdb_max_size,mdb_use_percentage
            ))
        # Count LDAP entries with no-op search controls
        item_name = '_'.join(('LdapEntryCount',str(db_num),subst_item_name_chars(db_suffix)))
        self.add_item(item_name)
        try:
          noop_start_timestamp = time.time()
          noop_result = ldap_conn.noop_search_st(db_suffix,timeout=NOOP_SEARCH_TIMEOUT)
        except ldap.TIMEOUT,e:
          self.result_line(1,item_name,check_output='Request timeout %0.1f s reached while retrieving entry count.' % (NOOP_SEARCH_TIMEOUT))
        except ldap.TIMELIMIT_EXCEEDED,e:
          self.result_line(1,item_name,check_output='Search time limit %0.1f s exceeded while retrieving entry count.' % (NOOP_SEARCH_TIMEOUT))
        except LDAPError,e:
          self.result_line(3,item_name,check_output='LDAPError retrieving entry count: %s' % (str(e)))
        except CATCH_ALL_EXCEPTION,e:
          self.result_line(3,item_name,check_output='error retrieving entry count: %s' % (str(e)))
        else:
          noop_response_time = time.time()-noop_start_timestamp
          if noop_result==None:
            self.result_line(1,item_name,check_output='Could not retrieve entry count (result was None)')
          else:
            num_all_search_results,num_all_search_continuations = noop_result
            if num_all_search_continuations:
              self.result_line(
                2,item_name,
                performance_data='count=%d' % (num_all_search_results),
                check_output='%s has %d referrals! (response time %0.1f s)' % (repr(db_suffix),num_all_search_continuations,noop_response_time)
              )
            elif num_all_search_results<MINIMUM_ENTRY_COUNT:
              self.result_line(
                1,item_name,
                performance_data='count=%d' % (num_all_search_results),
                check_output='%s only has %d entries (response time %0.1f s)' % (repr(db_suffix),num_all_search_results,noop_response_time)
              )
            else:
              self.result_line(
                0,item_name,
                performance_data='count=%d' % (num_all_search_results),
                check_output='%s has %d entries (response time %0.1f s)' % (repr(db_suffix),num_all_search_results,noop_response_time)
              )

    # For rate calculation we need the timespan since last run
    ops_counter_time = time.time()
    last_ops_counter_time = float(self._state.d.get('LdapOpsTime',ops_counter_time-60.0))
    last_time_span = ops_counter_time-last_ops_counter_time
    self._next_state['LdapOpsTime'] = ops_counter_time

    try:
      stats_bytes = monitor_cache.get_value('cn=Bytes,cn=Statistics','monitorCounter')
      stats_entries = monitor_cache.get_value('cn=Entries,cn=Statistics','monitorCounter')
      stats_pdu = monitor_cache.get_value('cn=PDU,cn=Statistics','monitorCounter')
      stats_referrals = monitor_cache.get_value('cn=Referrals,cn=Statistics','monitorCounter')
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapStats',check_output='Error while retrieving stats counters: %s' % repr(e))
    else:
      stats_bytes_rate = (stats_bytes - int(self._state.d.get('LdapStats_stats_bytes','0'))) / last_time_span
      stats_entries_rate = (stats_entries - int(self._state.d.get('LdapStats_stats_entries','0'))) / last_time_span
      stats_pdu_rate = (stats_pdu - int(self._state.d.get('LdapStats_stats_pdu','0'))) / last_time_span
      stats_referrals_rate = (stats_referrals - int(self._state.d.get('LdapStats_stats_referrals','0'))) / last_time_span
      self._next_state['LdapStats_stats_bytes'] = stats_bytes
      self._next_state['LdapStats_stats_entries'] = stats_entries
      self._next_state['LdapStats_stats_pdu'] = stats_pdu
      self._next_state['LdapStats_stats_referrals'] = stats_referrals
      self.result_line(
        0,
        'LdapStats',
        performance_data='bytes=%d|entries=%d|pdu=%d|referrals=%d' % (
          stats_bytes_rate,stats_entries_rate,stats_pdu_rate,stats_referrals_rate
        ),
        check_output='Stats: %d bytes (%0.1f bytes/sec) / %d entries (%0.1f entries/sec) / %d PDUs (%0.1f PDUs/sec) / %d referrals (%0.1f referrals/sec)' % (
          stats_bytes,stats_bytes_rate,
          stats_entries,stats_entries_rate,
          stats_pdu,stats_pdu_rate,
          stats_referrals,stats_referrals_rate,
        )
      )

    try:
      monitor_ops_counters = monitor_cache.operation_counters()
    except CATCH_ALL_EXCEPTION,e:
      self.result_line(3,'LdapOps_all',check_output='error retrieving operation counters: %s' % (str(e)))
    else:
      if monitor_ops_counters:
        self.result_line(0,'LdapOpsCounters',check_output='successfully retrieved operation %d counters' % (len(monitor_ops_counters)))
        ops_all_initiated = 0
        ops_all_completed = 0
        old_ops_all_initiated = 0
        old_ops_all_completed = 0
        ops_all_waiting = 0
        for ops_name,ops_initiated,ops_completed in monitor_ops_counters:
          item_name = 'LdapOps_%s' % (ops_name)
          self.add_item(item_name)
          old_ops_initiated = int(self._state.d.get(item_name+'_ops_initiated','0'))
          old_ops_all_initiated += old_ops_initiated
          old_ops_completed = int(self._state.d.get(item_name+'_ops_completed','0'))
          old_ops_all_completed += old_ops_completed
          self._next_state[item_name+'_ops_initiated'] = ops_initiated
          self._next_state[item_name+'_ops_completed'] = ops_completed
          ops_waiting = ops_initiated - ops_completed
          ops_all_waiting += ops_waiting
          ops_all_completed += ops_completed
          ops_all_initiated += ops_initiated
          ops_initiated_rate = max(0,ops_initiated-old_ops_initiated) / last_time_span
          ops_completed_rate = max(0,ops_completed-old_ops_completed) / last_time_span
          self.result_line(
            0,item_name,
            performance_data='ops_completed_rate=%0.2f|ops_initiated_rate=%0.2f|ops_waiting=%d' % (
              ops_completed_rate,ops_initiated_rate,ops_waiting,
            ),
            check_output='completed %d of %d operations (%0.2f/s completed, %0.2f/s initiated, %d waiting)' % (
              ops_completed,ops_initiated,
              ops_completed_rate,ops_initiated_rate,ops_waiting,
            ),
          )
        ops_all_initiated_rate = max(0,ops_all_initiated-old_ops_all_initiated) / last_time_span
        ops_all_completed_rate = max(0,ops_all_completed-old_ops_all_completed) / last_time_span
        if OPS_WAITING_CRIT!=None and ops_all_waiting>=OPS_WAITING_CRIT:
          state = 2
        elif OPS_WAITING_WARN!=None and ops_all_waiting>=OPS_WAITING_WARN:
          state = 1
        else:
          state = 0
        self.result_line(
          state,'LdapOps_all',
          performance_data='ops_completed_rate=%0.2f|ops_initiated_rate=%0.2f|ops_waiting=%d' % (
            ops_all_completed_rate,ops_all_initiated_rate,ops_all_waiting,
          ),
          check_output='completed %d of %d operations (%0.2f/s completed, %0.2f/s initiated, %d waiting)' % (
            ops_all_completed,ops_all_initiated,
            ops_all_completed_rate,ops_all_initiated_rate,ops_all_waiting,
          ),
        )

      else:
        self.result_line(3,'LdapOps_all',check_output='empty operation counter list')

    local_csn_dict = {}

    for db_num,db_suffix,_ in syncrepl_list:

      local_csn_dict[db_suffix] = []
      item_name = '_'.join(('LdapReplicationState',str(db_num),subst_item_name_chars(db_suffix)))
      self.add_item(item_name)
      try:
        local_csn_dict[db_suffix] = ldap_conn.get_context_csns(db_suffix)
      except LDAPError,e:
        self.result_line(3,item_name,check_output='LDAPError while retrieving local contextCSN of %s: %s' % (repr(db_suffix),str(e)))
      except CATCH_ALL_EXCEPTION,e:
        self.result_line(3,item_name,check_output='exception while retrieving local contextCSN of %s: %s' % (repr(db_suffix),str(e)))
      else:
        if not local_csn_dict[db_suffix]:
          self.result_line(3,item_name,check_output='no local contextCSN values for %s' % (repr(db_suffix)))

    # Close local LDAP connection
    ldap_conn.unbind_s()

    # Write current state to disk
    self._state.write_state(self._next_state)

    # 2. Connect and bind to all replicas to check whether they are reachable
    #-----------------------------------------------------------------------

    remote_csn_dict = {}

    for syncrepl_target_uri in syncrepl_topology.keys():

      syncrepl_target_lu_obj = LDAPUrl(syncrepl_target_uri)
      # FIX ME! Does not hurt here, but in theory TLS options could differ for each syncrepl statement!
      syncrepl_obj = syncrepl_topology[syncrepl_target_uri][0][2]
      syncrepl_target_hostport = syncrepl_target_lu_obj.hostport.lower()
      syncrepl_target_hostname = syncrepl_target_hostport.rsplit(':',1)[0]
      item_name = 'LdapConnect_%s' % (subst_item_name_chars(syncrepl_target_hostport))
      self.add_item(item_name)

      remote_csn_dict[syncrepl_target_uri] = {}

      # Resolve hostname separately for fine-grained error message
      try:
        syncrepl_target_ipaddr = socket.gethostbyname(syncrepl_target_hostname)
      except socket.error,e:
        self.result_line(2,item_name,check_output='Error resolving hostname %s: %s' % (repr(syncrepl_target_hostname),str(e)))
        continue
      except CATCH_ALL_EXCEPTION,e:
        self.result_line(3,item_name,check_output='Unknown error resolving hostname %s: %s' % (repr(syncrepl_target_hostname),str(e)))
        continue

      try:
        ldap_conn = SlapdCheckLDAPObject(
          syncrepl_target_uri,
          trace_level=PYLDAP_TRACE_LEVEL,
        )
        # Force server cert validation
        ldap_conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,ldap.OPT_X_TLS_DEMAND)
        # Set path name of file containing all trusted CA certificates
        ldap_conn.set_option(ldap.OPT_X_TLS_CACERTFILE,syncrepl_obj.tls_cacert)
        # Use slapd server cert for client authentication just like used for syncrepl
        ldap_conn.set_option(ldap.OPT_X_TLS_CERTFILE,syncrepl_obj.tls_cert)
        ldap_conn.set_option(ldap.OPT_X_TLS_KEYFILE,syncrepl_obj.tls_key)
        # Reinitialize SSL context
        ldap_conn.set_option(ldap.OPT_X_TLS_NEWCTX,0)
        # Send SASL/EXTERNAL bind request which really opens the connection
        ldap_conn.sasl_interactive_bind_s('',ldap.sasl.sasl({}, 'EXTERNAL'))
      except LDAPError,e:
        self.result_line(2,item_name,check_output='cannot connect to %s, because of error: %s' % (repr(syncrepl_target_uri),str(e)))
        continue
      except CATCH_ALL_EXCEPTION,e:
        self.result_line(3,item_name,check_output='unknown error initializing connection to %s: %s' % (repr(syncrepl_target_uri),str(e)))
        continue
      else:
        self.result_line(0,item_name,check_output='connection to replication target %s working' % (repr(syncrepl_target_uri)))
        remote_csn_dict[ldap_conn._uri.lower()] = {}
        syncrepl_target_uri = ldap_conn._uri.lower()

      item_name = '_'.join((
        'LdapContextCSNs',
        subst_item_name_chars(syncrepl_target_hostport),
        str(db_num),
        self._subst_item_name_chars(db_suffix),
      ))
      self.add_item(item_name)

      for db_num,db_suffix,_ in syncrepl_topology[syncrepl_target_uri]:

        try:
          remote_csn_dict[syncrepl_target_uri][db_suffix] = ldap_conn.get_context_csns(db_suffix)
        except LDAPError,e:
          self.result_line(2,item_name,check_output='LDAPError while retrieving remote contextCSN for %s from %s: %s' % (
            repr(db_suffix),repr(ldap_conn._uri),repr(e)
          ))
          continue
        except CATCH_ALL_EXCEPTION,e:
          self.result_line(3,item_name,check_output='Exception while retrieving remote contextCSN for %s from %s: %s' % (
            repr(db_suffix),repr(ldap_conn._uri),repr(e)
          ))
          continue
        else:
          if not remote_csn_dict[syncrepl_target_uri][db_suffix]:
            self.result_line(2,item_name,check_output='no attribute contextCSN for %s on %s' % (
              repr(db_suffix),repr(ldap_conn._uri)
            ))
          else:
            self.result_line(0,item_name,check_output='%d contextCSN attribute values retrieved for %s from %s' % (
              len(remote_csn_dict[syncrepl_target_uri][db_suffix]),repr(db_suffix),repr(ldap_conn._uri)
            ))

      # Close the LDAP connection to the remote replica
      try:
        ldap_conn.unbind_s()
      except CATCH_ALL_EXCEPTION,e:
        pass

    state = 1

    for db_num,db_suffix,_ in syncrepl_list:

      item_name = '_'.join(('LdapReplicationState',str(db_num),subst_item_name_chars(db_suffix)))
      issues = []

      if not local_csn_dict[db_suffix]:
        # Message output done before => silent here
        state = 3
        issues.append('no local CSNs avaiable, no comparison possible')
        continue

      oldest_csn_timestamp = 0.0
      newest_csn_timestamp = 0.0
      max_csn_timedelta = 0.0

      local_csn_parsed_dict = local_csn_dict[db_suffix]
      now = time.time()

      for syncrepl_target_uri in syncrepl_topology.keys():

        if not remote_csn_dict or \
           not remote_csn_dict[syncrepl_target_uri] or \
           not remote_csn_dict[syncrepl_target_uri][db_suffix]:
          state = 3
          issues.append('no remote CSNs retrieved from %s, no comparison possible' % (repr(syncrepl_target_uri)))
          continue

        for server_id,local_csn_timestamp in local_csn_parsed_dict.items():

          if local_csn_timestamp < oldest_csn_timestamp:
            oldest_csn_timestamp = local_csn_timestamp
          if local_csn_timestamp > newest_csn_timestamp:
            newest_csn_timestamp = local_csn_timestamp

          remote_csn_parsed_dict = remote_csn_dict[syncrepl_target_uri][db_suffix]

          if not server_id in remote_csn_parsed_dict:
            state = 1
            issues.append('contextCSN of %s missing on server %s' % (server_id,repr(syncrepl_target_uri)))
            continue

          remote_csn_timestamp = remote_csn_parsed_dict[server_id]
          if remote_csn_timestamp < oldest_csn_timestamp:
            oldest_csn_timestamp = remote_csn_timestamp
          if remote_csn_timestamp > newest_csn_timestamp:
            newest_csn_timestamp = remote_csn_timestamp

          csn_timedelta = abs(local_csn_timestamp-remote_csn_timestamp)

          if csn_timedelta > max_csn_timedelta:
            max_csn_timedelta = csn_timedelta
          if csn_timedelta:
            issues.append('%s contextCSN delta for %s: %0.1f s' % (syncrepl_target_uri,server_id,csn_timedelta))

      max_age = now - oldest_csn_timestamp
      min_age = now - newest_csn_timestamp

      if SYNCREPL_TIMEDELTA_CRIT!=None and max_csn_timedelta>=SYNCREPL_TIMEDELTA_CRIT:
        old_critical_timestamp = float(self._state.d.get(item_name+'_critical',str(now)))
        if now-old_critical_timestamp>=SYNCREPL_HYSTERESIS_CRIT:
          state = 2
        self._next_state[item_name+'_critical'] = old_critical_timestamp
      else:
        self._next_state[item_name+'_critical'] = -1.0
      if SYNCREPL_TIMEDELTA_WARN!=None and max_csn_timedelta>=SYNCREPL_TIMEDELTA_WARN:
        old_warn_timestamp = float(self._state.d.get(item_name+'_warning',str(now)))
        if now-old_warn_timestamp>=SYNCREPL_HYSTERESIS_WARN:
          state = 1
        self._next_state[item_name+'_warning'] = old_warn_timestamp
      else:
        self._next_state[item_name+'_warning'] = -1.0

      if not issues:
        state = 0
        issues.append('no replication issues determined')

      self.result_line(
        state,item_name,
        performance_data='max_csn_timedelta=%0.1f' % (max_csn_timedelta),
        check_output='%s max. contextCSN delta: %0.1f / %s' % (
          repr(db_suffix),
          max_csn_timedelta,
          ' / '.join(issues),
        ),
      )

    return # checks()

#-----------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------

slapd_check = SlapdCheck(
  (
    'LdapBdbCaches',
    'LdapConfigBackend',
    'LdapMonitorBackend',
    'LdapConnectionCount',
    'LdapDBSuffixes',
    'LdapOps_all',
    'LdapOpsCounters',
    'LdapReplTopology',
    'LdapSelfConnection',
    'LdapStats',
    'LdapThreads',
  ),
  output_file=sys.stdout,
  output_encoding='ascii',
  state_filename=STATE_FILENAME,
)
slapd_check.run()
