#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
monitoring check script for OpenLDAP

Needs full read access to rootDSE and cn=config and cn=monitor
(or whereever rootDSE attributes 'configContext' and 'monitorContext'
are pointing to)

Copyright 2015-2019 Michael Ströder <michael@stroeder.com>

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use files and content provided on this web site except in compliance
with the License. You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

#-----------------------------------------------------------------------
# Import modules
#-----------------------------------------------------------------------

import os
import sys
import socket
import time
import datetime
import pprint
import logging
import threading

import cryptography.x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import cryptography.hazmat.primitives.asymmetric.rsa

# from ldap0 package
import ldap0
from ldap0.ldapobject import LDAPObject
from ldap0.openldap import SyncReplDesc
from ldap0.ldapurl import LDAPUrl
from ldap0.ldif import LDIFParser

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

__version__ = '3.0.2'

STATE_FILENAME = 'slapd_checkmk.state'

# constants for the check result codes
CHECK_RESULT_OK = 0
CHECK_RESULT_WARNING = 1
CHECK_RESULT_ERROR = 2
CHECK_RESULT_UNKNOWN = 3

# which check result to return in case server responds with
# ldap0.UNAVAILABLE_CRITICAL_EXTENSION for no-op search control
# set this to CHECK_RESULT_ERROR if certain your server supports the control
CHECK_RESULT_NOOP_SRCH_UNAVAILABLE = CHECK_RESULT_OK

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap0.OPT_NETWORK_TIMEOUT and ldap0.OPT_TIMEOUT
LDAP_TIMEOUT = 4.0

# Timeout in seconds when connecting to slapd-sock listener
SLAPD_SOCK_TIMEOUT = 2.0

# Time in seconds for searching all entries with the noop search control
NOOP_SEARCH_TIMEOUT = 6.0
# at least search root entry should be present
MINIMUM_ENTRY_COUNT = 20

# acceptable time-delta [sec] of replication
# Using None disables checking the warn/critical level
SYNCREPL_TIMEDELTA_WARN = 5.0
SYNCREPL_TIMEDELTA_CRIT = 300.0
# hysteresis for syncrepl conditions
SYNCREPL_HYSTERESIS_WARN = 0.0
SYNCREPL_HYSTERESIS_CRIT = 10.0

# maximum percentage of failed syncrepl providers when to report error
SYNCREPL_PROVIDER_ERROR_PERCENTAGE = 50.0

# acceptable count of all outstanding operations
# Using None disables checking the warn/critical level
OPS_WAITING_WARN = 30
OPS_WAITING_CRIT = 60

# number of minimum connections expected
# if real connection count falls below this treshold it could mean
# that slapd is not reachable from LDAP clients
CONNECTIONS_WARN_LOWER = 3
# warn if this percentage of max. file descriptors is reached
CONNECTIONS_WARN_PERCENTAGE = 80.0

# Tresholds for thread-count-related warnings
# There should always be at least one active thread
THREADS_ACTIVE_WARN_LOWER = 1
# This should likely match what's configured in slapd.conf
THREADS_ACTIVE_WARN_UPPER = 6
# Too many pending threads should not occur
THREADS_PENDING_WARN = 5

class NoneException(BaseException):
    """
    A dummy exception class used for disabling exception handling
    """

CATCH_ALL_EXC = (Exception, ldap0.LDAPError)
#CATCH_ALL_EXC = NoneException

# days to warn/error when checking server cert validity
CERT_ERROR_DAYS = 10
CERT_WARN_DAYS = 50

# set debug parameters for development (normally not needed)
LDAP0_TRACE_LEVEL = int(os.environ.get('LDAP0_TRACE_LEVEL', '0'))
ldap0._trace_level = LDAP0_TRACE_LEVEL
# ldap0.set_option(ldap0.OPT_DEBUG_LEVEL,255)

#-----------------------------------------------------------------------
# Functions
#-----------------------------------------------------------------------

def slapd_pid_fromfile(config_attrs):
    """
    read slapd's PID from file
    """
    pid_filename = config_attrs['olcPidFile'][0]
    try:
        with open(pid_filename, 'r', encoding='utf-8') as pid_file:
            slapd_pid = pid_file.read().strip()
    except IOError:
        slapd_pid = None
    return slapd_pid # end of slapd_pid_fromfile()


#-----------------------------------------------------------------------
# Classes
#-----------------------------------------------------------------------

class MonitoringCheck:
    """
    base class for a monitoring check
    """

    item_names = None
    output_encoding = 'ascii'
    item_name_special_chars = set()

    def __init__(self, output_file, state_filename=None):
        """
        output_file
            fileobj where to write the output
        output_encoding
            encoding to use when writing output
            'ascii' is always safe, Nagios mandates 'utf-8'
        """
        self._item_dict = {}
        for item_name in self.item_names or []:
            self.add_item(item_name)
        self._output_file = output_file
        if state_filename is not None:
            # Initialize local state file and read old state if it exists
            self._state = CheckStateFile(state_filename)
            # Generate *new* state dict to be updated within check and stored
            # later
            self._next_state = {}
        self.script_name = os.path.basename(sys.argv[0])
        # end of __init__()

    def _get_rate(self, key, current_val, time_span):
        last_val = int(self._state.data.get(key, '0'))
        if current_val < last_val:
            val1, val2 = last_val, last_val+current_val
        else:
            val1, val2 = last_val, current_val
        return (val2 - val1) / time_span # end of _get_rate()

    def checks(self):
        """
        wrapper method implementing all checks, normally invoked by run()
        """
        raise Exception(
            "checks() not implemented in class %s.%s" % (
                self.__class__.__module__,
                self.__class__.__name__,
            )
        )

    def run(self):
        """
        wrapper method for running all checks with outer expcetion handling
        """
        try:
            try:
                self.checks()
            except Exception:
                # Log unhandled exception
                err_lines = [66 * '-']
                err_lines.append(
                    '----------- %s.__class__.__dict__ -----------' % (self.__class__.__name__))
                err_lines.append(
                    pprint.pformat(self.__class__.__dict__, indent=1, width=66, depth=None))
                err_lines.append('----------- vars() -----------')
                err_lines.append(
                    pprint.pformat(vars(), indent=1, width=66, depth=None))
                logging.exception('\n'.join(err_lines))
        finally:
            self.output()
            if self._state:
                self._state.write_state(self._next_state)

    def add_item(self, item_name):
        """
        Preregister a check item by name
        """
        # FIX ME! Protect the following lines with a lock!
        if item_name in self._item_dict:
            raise ValueError('Check item name %r already exists.' % (item_name))
        self._item_dict[item_name] = None

    def subst_item_name_chars(self, item_name):
        """
        Replace special chars in s
        """
        s_list = []
        for char in item_name:
            if char in self.item_name_special_chars:
                s_list.append('_')
            else:
                s_list.append(char)
        return ''.join(s_list)  # _subst_item_name_chars()

    @staticmethod
    def serialize_perf_data(performance_data):
        return str(performance_data)

    def result(self, status, item_name, performance_data=None, check_output=None):
        """
        Registers check_mk result to be output later
        status
           integer indicating status
        item_name
           the check_mk item name
        """
        assert performance_data is None or isinstance(performance_data, dict), \
            TypeError('Expected performance_data to be None or dict, but was %r' % performance_data)
        # Provoke KeyError if item_name is not known
        try:
            self._item_dict[item_name]
        except KeyError:
            raise ValueError('item_name %r not in known item names %r' % (
                item_name,
                self._item_dict.keys(),
            ))
        self._item_dict[item_name] = (
            status,
            item_name,
            performance_data or {},
            check_output or u'',
        )
        # end of result()

    def output(self):
        """
        Outputs all results registered before with method result()
        """
        # add default unknown result for all known check items
        # which up to now did not receive a particular result
        for i in sorted(self._item_dict.keys()):
            if not self._item_dict[i]:
                self.result(
                    CHECK_RESULT_UNKNOWN,
                    i,
                    check_output='No defined check result yet!',
                )


class CheckMkLocalCheck(MonitoringCheck):
    """
    Simple class for writing check_mk output
    """
    checkmk_status = {
        CHECK_RESULT_OK: 'OK',
        CHECK_RESULT_WARNING: 'WARNING',
        CHECK_RESULT_ERROR: 'ERROR',
        CHECK_RESULT_UNKNOWN: 'UNKNOWN',
    }
    output_format = '{status_code} {name} {perf_data} {status_text} - {msg}\n'
    item_name_special_chars = set(',!:$%=/\\')

    def serialize_perf_data(self, pdat):
        if not pdat:
            return '-'
        return '|'.join([
            '%s=%s' % (pkey, pval)
            for pkey, pval in pdat.items()
        ])

    def output(self):
        """
        Outputs all check_mk results registered before with method result()
        """
        MonitoringCheck.output(self)
        for i in sorted(self._item_dict.keys()):
            status, check_name, perf_data, check_msg = self._item_dict[i]
            sys.stdout.write(
                self.output_format.format(
                    status_code=status,
                    perf_data=self.serialize_perf_data(perf_data),
                    name=self.subst_item_name_chars(check_name),
                    status_text=self.checkmk_status[status],
                    msg=check_msg,
                )
            )
        # end of output()


class CheckStateFile:
    """
    Class for state file
    """
    line_sep = '\n'

    def __init__(self, state_filename):
        self._state_filename = state_filename
        if not os.path.isfile(self._state_filename):
            self.write_state({})
        self.data = self._read_state()

    def _read_state(self):
        """
        read state dict from file
        """
        try:
            state_tuple_list = []
            with open(self._state_filename, 'r', encoding='utf-8') as state_file:
                state_string_list = state_file.read().split(self.line_sep)
            state_tuple_list = [
                line.split('=', 1)
                for line in state_string_list
                if line
            ]
            return dict(state_tuple_list)
        except CATCH_ALL_EXC:
            return {}

    def write_state(self, state):
        """
        write state dict to file
        """
        state_string_list = [
            '%s=%s' % (key, val)
            for key, val in state.items()
        ]
        state_string_list.append('')
        with open(self._state_filename, 'w', encoding='utf-8') as state_file:
            state_file.write(self.line_sep.join(state_string_list))


class OpenLDAPMonitorCache:
    """
    Cache object for data read from back-monitor
    """

    def __init__(self, monitor_entries, monitor_context):
        self._ctx = monitor_context
        self._data = dict(monitor_entries)

    def __len__(self):
        return len(self._data)

    def get_value(self, dn_prefix, attribute):
        """
        Get a single monitoring value from entry cache
        """
        attr_value = self._data[','.join((dn_prefix, self._ctx))][attribute][0]
        if attribute == 'monitorTimestamp':
            res = datetime.datetime.strptime(attr_value, '%Y%m%d%H%M%SZ')
        else:
            res = int(attr_value)
        return res # end of get_value()

    def operation_counters(self):
        """
        return list of monitoring counters for various LDAP operations
        """
        op_counter_suffix_lower = ','.join(
            ('', 'cn=Operations', self._ctx)).lower()
        return [
            (
                entry['cn'][0],
                int(entry['monitorOpInitiated'][0]),
                int(entry['monitorOpCompleted'][0]),
            )
            for dn, entry in self._data.items()
            if dn.lower().endswith(op_counter_suffix_lower)
        ]


class OpenLDAPObject:
    """
    mix-in class for LDAPObject and friends which provides methods useful
    for OpenLDAP's slapd
    """
    syncrepl_filter = (
        '(&'
          '(objectClass=olcDatabaseConfig)'
          '(olcDatabase=*)'
          '(olcSyncrepl=*)'
          '(olcSuffix=*)'
        ')'
    )
    slapd_sock_filter = (
        '(&'
          '(|'
            '(objectClass=olcDbSocketConfig)'
            '(objectClass=olcOvSocketConfig)'
          ')'
          '(olcDbSocketPath=*)'
        ')'
    )
    naming_context_attrs = [
        'configContext',
        'namingContexts',
        'monitorContext',
    ]
    all_real_db_filter = (
        '(&'
          '(|'
            '(objectClass=olcBdbConfig)'
            '(objectClass=olcHdbConfig)'
            '(objectClass=olcMdbConfig)'
          ')'
            '(olcDatabase=*)'
            '(olcDbDirectory=*)'
            '(olcSuffix=*)'
        ')'
    )
    all_monitor_entries_filter = (
        '(|'
          '(objectClass=monitorOperation)'
          '(objectClass=monitoredObject)'
          '(objectClass=monitorCounterObject)'
        ')'
    )
    all_monitor_entries_attrs = [
        'cn',
        'monitorCounter',
        'monitoredInfo',
        'monitorOpCompleted',
        'monitorOpInitiated',
        'monitorTimestamp',
        'namingContexts'
        'seeAlso',
        # see OpenLDAP ITS#7770
        'olmMDBPagesMax',
        'olmMDBPagesUsed',
        'olmMDBPagesFree',
        'olmMDBReadersMax',
        'olmMDBReadersUsed',
    ]

    def __getattr__(self, name):
        if name not in self.__dict__ and name in self.naming_context_attrs:
            self.get_naming_context_attrs()
        return self.__dict__[name]

    def get_monitor_entries(self):
        """
        returns dict of all monitoring entries
        """
        return {
            res.dn_s: res.entry_s
            for res in self.search_s(
                self.monitorContext[0],
                ldap0.SCOPE_SUBTREE,
                self.all_monitor_entries_filter,
                attrlist=self.all_monitor_entries_attrs,
            )
        }

    def get_naming_context_attrs(self):
        """
        returns all naming contexts including special backends
        """
        rootdse = self.read_rootdse_s(attrlist=self.naming_context_attrs)
        for nc_attr in self.naming_context_attrs:
            if nc_attr in rootdse.entry_s:
                setattr(self, nc_attr, rootdse.entry_s[nc_attr])
        return rootdse

    def get_sock_listeners(self):
        """
        search `self.configContext[0]' for back-sock listeners (DB and overlay)
        """
        ldap_result = self.search_s(
            self.configContext[0],
            ldap0.SCOPE_SUBTREE,
            self.slapd_sock_filter,
            attrlist=['olcDbSocketPath', 'olcOvSocketOps'],
        )
        result = {}
        for ldap_res in ldap_result:
            socket_path = ldap_res.entry_s['olcDbSocketPath'][0]
            result['SlapdSock_'+socket_path] = (
                socket_path,
                '/'.join(sorted(ldap_res.entry_s['olcOvSocketOps'])),
            )
        return result

    def get_context_csn(self, naming_context):
        """
        read the contextCSN values from the backends root entry specified
        by `naming_context'
        """
        ldap_result = self.read_s(
            naming_context,
            '(contextCSN=*)',
            attrlist=['objectClass', 'contextCSN'],
        )
        csn_dict = {}
        try:
            context_csn_vals = ldap_result.entry_s['contextCSN']
        except KeyError:
            pass
        else:
            for csn_value in context_csn_vals:
                timestamp, _, server_id, _ = csn_value.split("#")
                csn_dict[server_id] = time.mktime(
                    time.strptime(timestamp, '%Y%m%d%H%M%S.%fZ')
                )
        return csn_dict

    def get_syncrepl_topology(self):
        """
        returns list, dict of syncrepl configuration
        """
        ldap_result = self.search_s(
            self.configContext[0],
            ldap0.SCOPE_ONELEVEL,
            self.syncrepl_filter,
            attrlist=['olcDatabase', 'olcSuffix', 'olcSyncrepl'],
        )
        syncrepl_list = []
        for ldap_res in ldap_result:
            db_num = int(ldap_res.entry_s['olcDatabase'][0].split('}')[0][1:])
            srd = [
                SyncReplDesc(attr_value)
                for attr_value in ldap_res.entry_s['olcSyncrepl']
            ]
            syncrepl_list.append((
                db_num,
                ldap_res.entry_s['olcSuffix'][0],
                srd,
            ))
        syncrepl_topology = {}
        for db_num, db_suffix, sr_obj_list in syncrepl_list:
            for sr_obj in sr_obj_list:
                provider_uri = sr_obj.provider
                try:
                    syncrepl_topology[provider_uri].append(
                        (db_num, db_suffix, sr_obj)
                    )
                except KeyError:
                    syncrepl_topology[provider_uri] = [
                        (db_num, db_suffix, sr_obj)
                    ]
        return syncrepl_list, syncrepl_topology  # get_syncrepl_topology()

    def db_suffixes(self):
        """
        Returns suffixes of all real database backends
        """
        ldap_result = self.search_s(
            self.configContext[0],
            ldap0.SCOPE_ONELEVEL,
            self.all_real_db_filter,
            attrlist=['olcDatabase', 'olcSuffix', 'olcDbDirectory'],
        )
        result = []
        for res in ldap_result:
            db_num, db_type = res.entry_s['olcDatabase'][0][1:].split('}', 1)
            db_num = int(db_num)
            db_suffix = res.entry_s['olcSuffix'][0]
            db_dir = res.entry_s['olcDbDirectory'][0]
            result.append((db_num, db_suffix, db_type, db_dir))
        return result  # db_suffixes()


class SlapdConnection(LDAPObject, OpenLDAPObject):
    """
    LDAPObject derivation especially for accesing OpenLDAP's slapd
    """
    tls_fileoptions = set((
        ldap0.OPT_X_TLS_CACERTFILE,
        ldap0.OPT_X_TLS_CERTFILE,
        ldap0.OPT_X_TLS_KEYFILE,
    ))

    def __init__(
            self,
            uri,
            trace_level=LDAP0_TRACE_LEVEL,
            tls_options=None,
            network_timeout=None,
            timeout=None,
            bind_method='sasl',
            sasl_mech='EXTERNAL',
            who=None,
            cred=None,
        ):
        self.connect_latency = None
        LDAPObject.__init__(
            self,
            uri,
            trace_level=trace_level,
        )
        # Set timeout values
        if network_timeout is None:
            network_timeout = LDAP_TIMEOUT
        if timeout is None:
            timeout = LDAP_TIMEOUT
        self.set_option(ldap0.OPT_NETWORK_TIMEOUT, network_timeout)
        self.set_option(ldap0.OPT_TIMEOUT, timeout)
        tls_options = {key: val.encode('utf-8') for key, val in (tls_options or {}).items()}
        self.set_tls_options(**tls_options)
        conect_start = time.time()
        # Send SASL/EXTERNAL bind which opens connection
        if bind_method == 'sasl':
            self.sasl_non_interactive_bind_s(sasl_mech)
        elif bind_method == 'simple':
            self.simple_bind_s(who or '', cred or '')
        else:
            raise ValueError('Unknown bind_method %r' % bind_method)
        self.connect_latency = time.time() - conect_start


class SyncreplProviderTask(threading.Thread):
    """
    thread for connecting to a slapd provider
    """

    def __init__(
            self,
            check_instance,
            syncrepl_topology,
            syncrepl_target_uri,
        ):
        threading.Thread.__init__(
            self,
            group=None,
            target=None,
            name=None,
            args=(),
            kwargs={}
        )
        self.check_instance = check_instance
        self.syncrepl_topology = syncrepl_topology
        self.syncrepl_target_uri = syncrepl_target_uri
        syncrepl_target_lu_obj = LDAPUrl(self.syncrepl_target_uri)
        self.syncrepl_target_hostport = syncrepl_target_lu_obj.hostport.lower()
        self.setName(
            '-'.join((
                self.__class__.__name__,
                self.syncrepl_target_hostport,
            ))
        )
        self.remote_csn_dict = {}
        self.err_msgs = []
        self.connect_latency = None

    def run(self):
        """
        connect to provider replica and retrieve contextCSN values for databases
        """
        # Resolve hostname separately for fine-grained error message
        syncrepl_target_hostname = self.syncrepl_target_hostport.rsplit(':', 1)[0]
        try:
            syncrepl_target_ipaddr = socket.gethostbyname(
                syncrepl_target_hostname
            )
        except CATCH_ALL_EXC as exc:
            self.err_msgs.append('Error resolving hostname %r: %s' % (
                syncrepl_target_hostname,
                exc,
            ))
            return

        syncrepl_obj = self.syncrepl_topology[self.syncrepl_target_uri][0][2]
        try:
            ldap_conn = SlapdConnection(
                self.syncrepl_target_uri,
                tls_options={
                    # Set TLS connection options from TLS attribute read from
                    # configuration context
                    # path name of file containing all trusted CA certificates
                    'cacert_filename': syncrepl_obj.tls_cacert,
                    # Use slapd server cert/key for client authentication
                    # just like used for syncrepl
                    'client_cert_filename': syncrepl_obj.tls_cert,
                    'client_key_filename': syncrepl_obj.tls_key,
                },
                network_timeout=syncrepl_obj.network_timeout,
                timeout=syncrepl_obj.timeout,
                bind_method=syncrepl_obj.bindmethod,
                sasl_mech=syncrepl_obj.saslmech,
                who=syncrepl_obj.binddn,
                cred=syncrepl_obj.credentials,
            )
        except CATCH_ALL_EXC as exc:
            self.err_msgs.append('Error connecting to %r (%s): %s' % (
                self.syncrepl_target_uri,
                syncrepl_target_ipaddr,
                exc,
            ))
            return
        else:
            syncrepl_target_uri = self.syncrepl_target_uri.lower()
            self.connect_latency = ldap_conn.connect_latency

        for db_num, db_suffix, _ in self.syncrepl_topology[syncrepl_target_uri]:
            item_name = '_'.join((
                'SlapdContextCSN',
                str(db_num),
                self.check_instance.subst_item_name_chars(db_suffix),
                self.check_instance.subst_item_name_chars(self.syncrepl_target_hostport),
            ))
            self.check_instance.add_item(item_name)
            try:
                self.remote_csn_dict[db_suffix] = \
                    ldap_conn.get_context_csn(db_suffix)
            except CATCH_ALL_EXC as exc:
                self.check_instance.result(
                    CHECK_RESULT_ERROR,
                    item_name,
                    check_output='Exception while retrieving remote contextCSN for %r from %r: %s' % (
                        db_suffix,
                        ldap_conn.uri,
                        exc,
                    )
                )
                continue
            else:
                if not self.remote_csn_dict[db_suffix]:
                    self.check_instance.result(
                        CHECK_RESULT_ERROR,
                        item_name,
                        performance_data=dict(
                            num_csn_values=len(self.remote_csn_dict[db_suffix]),
                            connect_latency=ldap_conn.connect_latency,
                        ),
                        check_output='no attribute contextCSN for %r on %r' % (
                            db_suffix,
                            ldap_conn.uri,
                        )
                    )
                else:
                    self.check_instance.result(
                        CHECK_RESULT_OK,
                        item_name,
                        performance_data=dict(
                            num_csn_values=len(self.remote_csn_dict[db_suffix]),
                            connect_latency=ldap_conn.connect_latency,
                        ),
                        check_output='%d contextCSN attribute values retrieved for %r from %r' % (
                            len(self.remote_csn_dict[db_suffix]),
                            db_suffix,
                            ldap_conn.uri,
                        )
                    )
        # Close the LDAP connection to the remote replica
        try:
            ldap_conn.unbind_s()
        except CATCH_ALL_EXC as exc:
            pass
        # end of SyncreplProviderTask.run()


class SlapdCheck(CheckMkLocalCheck):
    """
    Check class for OpenLDAP's slapd
    """
    item_names = (
        'SlapdCert',
        'SlapdConfig',
        'SlapdMonitor',
        'SlapdConns',
        'SlapdDatabases',
        'SlapdStart',
        'SlapdOps',
        'SlapdProviders',
        'SlapdReplTopology',
        'SlapdSASLHostname',
        'SlapdSelfConn',
        'SlapdSock',
        'SlapdStats',
        'SlapdThreads',
    )

    def __init__(self, output_file, state_filename=None):
        CheckMkLocalCheck.__init__(self, output_file, state_filename)
        # make pylint happy
        self._ldapi_conn = None
        self._config_attrs = {}
        self._monitor_cache = {}

    def _check_sasl_hostname(self, config_attrs):
        """
        check whether SASL hostname is resolvable
        """
        try:
            olc_sasl_host = config_attrs['olcSaslHost'][0]
        except (KeyError, IndexError):
            self.result(
                CHECK_RESULT_OK,
                'SlapdSASLHostname',
                check_output='olcSaslHost not set'
            )
        else:
            try:
                _ = socket.getaddrinfo(olc_sasl_host, None)
            except socket.gaierror as socket_err:
                self.result(
                    CHECK_RESULT_WARNING,
                    'SlapdSASLHostname',
                    check_output='olcSaslHost %r not found: %r' % (olc_sasl_host, socket_err),
                )
            else:
                self.result(
                    CHECK_RESULT_OK,
                    'SlapdSASLHostname',
                    check_output='olcSaslHost %r found' % (olc_sasl_host),
                )
        # end of _check_sasl_hostname()

    def _check_tls_file(self, config_attrs):
        # try to read CA and server cert/key files
        file_read_errors = []
        tls_pem = {}
        for tls_attr_name in (
                'olcTLSCACertificateFile',
                'olcTLSCertificateFile',
                'olcTLSCertificateKeyFile',
            ):
            try:
                fname = config_attrs[tls_attr_name][0]
            except KeyError:
                file_read_errors.append(
                    'Attribute %r not set' % (tls_attr_name)
                )
            try:
                with open(fname, 'rb') as tls_pem_file:
                    tls_pem[tls_attr_name] = tls_pem_file.read()
            except CATCH_ALL_EXC as exc:
                file_read_errors.append(
                    'Error reading %r: %s' % (fname, exc)
                )
        if file_read_errors:
            # no crypto modules present => abort
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdCert',
                check_output=' / '.join(file_read_errors)
            )
            return
        server_cert_obj = cryptography.x509.load_pem_x509_certificate(
            tls_pem['olcTLSCertificateFile'],
            crypto_default_backend(),
        )
        server_key_obj = cryptography.hazmat.primitives.serialization.load_pem_private_key(
            tls_pem['olcTLSCertificateKeyFile'],
            None,
            crypto_default_backend(),
        )
        cert_not_after = server_cert_obj.not_valid_after
        cert_not_before = server_cert_obj.not_valid_before
        modulus_match = server_cert_obj.public_key().public_numbers().n == server_key_obj.public_key().public_numbers().n
        utc_now = datetime.datetime.now(cert_not_after.tzinfo)
        cert_validity_rest = cert_not_after - utc_now
        if modulus_match is False or cert_validity_rest.days <= CERT_ERROR_DAYS:
            cert_check_result = CHECK_RESULT_ERROR
        elif cert_validity_rest.days <= CERT_WARN_DAYS:
            cert_check_result = CHECK_RESULT_WARNING
        else:
            cert_check_result = CHECK_RESULT_OK
        # less exact usage of .days because of older
        # Python versions without timedelta.total_seconds()
        elapsed_percentage = 100-100*float(cert_validity_rest.days)/float((cert_not_after-cert_not_before).days)
        self.result(
            cert_check_result,
            'SlapdCert',
            check_output=(
                'Server cert %r valid until %s UTC '
                '(%d days left, %0.1f %% elapsed), '
                'modulus_match==%r'
            ) % (
                config_attrs['olcTLSCertificateFile'][0],
                cert_not_after,
                cert_validity_rest.days,
                elapsed_percentage,
                modulus_match,
            ),
        )
        # end of _check_tls_file()

    def _check_local_ldaps(self, ldaps_uri, my_authz_id):
        """
        Connect and bind to local slapd like a remote client
        mainly to check whether LDAPS with client cert works and maps expected authz-DN
        """
        try:
            ldaps_conn = SlapdConnection(
                ldaps_uri,
                tls_options={
                    # Set TLS connection options from TLS attribute read from
                    # configuration context
                    # path name of file containing all trusted CA certificates
                    'cacert_filename': self._config_attrs['olcTLSCACertificateFile'][0],
                    # Use slapd server cert/key for client authentication
                    # just like used for syncrepl
                    'client_cert_filename': self._config_attrs['olcTLSCertificateFile'][0],
                    'client_key_filename': self._config_attrs['olcTLSCertificateKeyFile'][0],
                },
            )
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdSelfConn',
                check_output='Error connecting to %r: %s %s' % (
                    ldaps_uri,
                    exc,
                    self._config_attrs,
                )
            )
        else:
            # Send LDAP Who Am I ? extended operation and check whether
            # returned authz-DN is correct
            try:
                wai = ldaps_conn.whoami_s()
            except CATCH_ALL_EXC as exc:
                self.result(
                    CHECK_RESULT_ERROR,
                    'SlapdSelfConn',
                    check_output='Error during Who Am I? ext.op. on %r: %s' % (
                        ldaps_conn.uri,
                        exc,
                    ),
                )
            else:
                if wai != my_authz_id:
                    self.result(
                        CHECK_RESULT_ERROR,
                        'SlapdSelfConn',
                        performance_data={'connect_latency': ldaps_conn.connect_latency},
                        check_output='Received unexpected authz-DN from %r: %r' % (
                            ldaps_conn.uri,
                            wai,
                        ),
                    )
                else:
                    self.result(
                        CHECK_RESULT_OK,
                        'SlapdSelfConn',
                        performance_data={'connect_latency': ldaps_conn.connect_latency},
                        check_output='successfully bound to %r as %r' % (
                            ldaps_conn.uri,
                            wai,
                        ),
                    )
            ldaps_conn.unbind_s()
        # end of _check_local_ldaps()

    def _check_slapd_sock(self):
        """
        Send MONITOR request to all back-sock listeners
        """
        def _read_sock_monitor(sock_path):
            """
            Send MONITOR request to Unix domain socket in `sock_path'
            """
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as _sock:
                _sock.connect(sock_path)
                _sock.settimeout(SLAPD_SOCK_TIMEOUT)
                _sock_f = _sock.makefile('rwb')
                _sock_f.write(b'MONITOR\n')
                _sock_f.flush()
                res = _sock_f.read()
            return res
            # end of _read_sock_monitor

        def _parse_sock_response(sock_response):
            # strip ENTRY\n from response and parse the rest as LDIF
            _, sock_monitor_entry = LDIFParser.frombuf(
                sock_response[6:],
                ignored_attr_types=['sockLogLevel'],
                max_entries=1
            ).list_entry_records()[0]
            sock_perf_data = {}
            # only add numeric monitor data to performance metrics
            for metric_key in sock_monitor_entry.keys():
                try:
                    sock_perf_data[metric_key.decode('ascii')] = float(sock_monitor_entry[metric_key][0])
                except ValueError:
                    continue
            return sock_perf_data # end of _parse_sock_response()

        try:
            sock_listeners = self._ldapi_conn.get_sock_listeners()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdSock',
                check_output='error retrieving back-sock listeners: %s' % (exc)
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdSock',
                check_output='Found %d back-sock listeners' % (len(sock_listeners))
            )
            for item_name, sock_listener in sock_listeners.items():
                self.add_item(item_name)
                sock_path, sock_ops = sock_listener
                try:
                    sock_response = _read_sock_monitor(sock_path)
                except CATCH_ALL_EXC as exc:
                    self.result(
                        CHECK_RESULT_ERROR,
                        item_name,
                        check_output='Connecting to %s listener %r failed: %s' % (
                            sock_ops, sock_path, exc,
                        ),
                    )
                else:
                    check_msgs = ['Connected to %s listener %r and received %d bytes' % (
                        sock_ops,
                        sock_path,
                        len(sock_response),
                    )]
                    try:
                        sock_perf_data = _parse_sock_response(sock_response)
                    except (IndexError, ValueError) as err:
                        sock_perf_data = {}
                        check_result = CHECK_RESULT_ERROR
                        check_msgs.append('parsing error: %s' % (err))
                    else:
                        check_result = CHECK_RESULT_OK
                    self.result(
                        check_result,
                        item_name,
                        performance_data=sock_perf_data,
                        check_output=', '.join(check_msgs),
                    )
        # end of _check_slapd_sock()

    def _check_slapd_start(self, config_attrs):
        """
        check whether slapd should be restarted
        """
        start_time = self._monitor_cache.get_value('cn=Start,cn=Time', 'monitorTimestamp')
        utc_now = datetime.datetime.now()
        newer_files = []
        for fattr in (
                'olcConfigDir',
                'olcConfigFile',
                'olcTLSCACertificateFile',
                'olcTLSCertificateFile',
                'olcTLSCertificateKeyFile',
                'olcTLSDHParamFile',
            ):
            if not fattr in config_attrs:
                continue
            check_filename = config_attrs[fattr][0]
            try:
                check_file_mtime = datetime.datetime.utcfromtimestamp(int(os.stat(check_filename).st_mtime))
            except OSError:
                pass
            else:
                if check_file_mtime > start_time:
                    newer_files.append('%r (%s)' % (check_filename, check_file_mtime))
        if newer_files:
            self.result(
                CHECK_RESULT_WARNING,
                'SlapdStart',
                check_output='slapd[%s] needs restart! Started at %s, %s ago, now newer config: %s' % (
                    slapd_pid_fromfile(config_attrs),
                    start_time,
                    utc_now-start_time,
                    ' / '.join(newer_files),
                )
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdStart',
                check_output='slapd[%s] started at %s, %s ago' % (
                    slapd_pid_fromfile(config_attrs),
                    start_time,
                    utc_now-start_time,
                )
            )
        # end of _check_slapd_start()

    def _get_local_csns(self, syncrepl_list):
        local_csn_dict = {}
        for db_num, db_suffix, _ in syncrepl_list:
            local_csn_dict[db_suffix] = []
            item_name = '_'.join((
                'SlapdSyncRepl',
                str(db_num),
                self.subst_item_name_chars(db_suffix),
            ))
            self.add_item(item_name)
            try:
                local_csn_dict[db_suffix] = self._ldapi_conn.get_context_csn(db_suffix)
            except CATCH_ALL_EXC as exc:
                self.result(
                    CHECK_RESULT_ERROR,
                    item_name,
                    check_output='Error while retrieving local contextCSN of %r: %s' % (
                        db_suffix,
                        exc,
                    ),
                )
            else:
                if not local_csn_dict[db_suffix]:
                    self.result(
                        CHECK_RESULT_UNKNOWN,
                        item_name,
                        check_output='no local contextCSN values for %r' % (
                            db_suffix,
                        ),
                    )
        return local_csn_dict # end of _get_local_csns()

    def _open_ldapi_conn(self, local_ldapi_url):
        """
        Open local LDAPI connection, exits on error
        """
        try:
            self._ldapi_conn = SlapdConnection(local_ldapi_url)
            # Find out whether bind worked
            local_wai = self._ldapi_conn.whoami_s()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdConfig',
                check_output='Error while connecting to %r: %s' % (
                    local_ldapi_url,
                    exc,
                )
            )
            sys.exit(1)
        return local_wai # end of _open_ldapi_conn()

    def _check_conns(self):
        """
        check whether current connection count is healthy
        """
        current_connections = self._monitor_cache.get_value(
            'cn=Current,cn=Connections',
            'monitorCounter',
        )
        max_connections = self._monitor_cache.get_value(
            'cn=Max File Descriptors,cn=Connections',
            'monitorCounter',
        )
        current_connections_percentage = 100.0 * current_connections / max_connections
        state = CHECK_RESULT_WARNING * int(
            current_connections < CONNECTIONS_WARN_LOWER or
            current_connections_percentage >= CONNECTIONS_WARN_PERCENTAGE
        )
        self.result(
            state,
            'SlapdConns',
            performance_data={
                'count': current_connections,
                'percent': current_connections_percentage,
            },
            check_output='%d open connections (max. %d)' % (current_connections, max_connections),
        )
        # end of _check_conns()

    def _check_threads(self):
        """
        check whether current thread count is healthy
        """
        threads_active = self._monitor_cache.get_value(
            'cn=Active,cn=Threads',
            'monitoredInfo',
        )
        threads_pending = self._monitor_cache.get_value(
            'cn=Pending,cn=Threads',
            'monitoredInfo',
        )
        state = int(
            threads_active < THREADS_ACTIVE_WARN_LOWER or
            threads_active > THREADS_ACTIVE_WARN_UPPER or
            threads_pending > THREADS_PENDING_WARN
        )
        self.result(
            state,
            'SlapdThreads',
            performance_data={
                'threads_active': threads_active,
                'threads_pending': threads_pending,
            },
            check_output='Thread counts active:%d pending: %d' % (
                threads_active, threads_pending)
        )
        # end of _check_threads()

    def _get_slapd_perfstats(self):
        """
        Get operation counters
        """
        # For rate calculation we need the timespan since last run
        ops_counter_time = time.time()
        last_ops_counter_time = float(
            self._state.data.get(
                'ops_counter_time',
                ops_counter_time-60.0
            )
        )
        last_time_span = ops_counter_time - last_ops_counter_time
        self._next_state['ops_counter_time'] = ops_counter_time
        stats_bytes = self._monitor_cache.get_value(
            'cn=Bytes,cn=Statistics', 'monitorCounter')
        stats_entries = self._monitor_cache.get_value(
            'cn=Entries,cn=Statistics', 'monitorCounter')
        stats_pdu = self._monitor_cache.get_value(
            'cn=PDU,cn=Statistics', 'monitorCounter')
        stats_referrals = self._monitor_cache.get_value(
            'cn=Referrals,cn=Statistics', 'monitorCounter')
        stats_bytes_rate = self._get_rate('stats_bytes', stats_bytes, last_time_span)
        stats_entries_rate = self._get_rate('stats_entries', stats_entries, last_time_span)
        stats_pdu_rate = self._get_rate('stats_pdu', stats_pdu, last_time_span)
        stats_referrals_rate = self._get_rate('stats_referrals', stats_pdu, last_time_span)
        self._next_state['stats_bytes'] = stats_bytes
        self._next_state['stats_entries'] = stats_entries
        self._next_state['stats_pdu'] = stats_pdu
        self._next_state['stats_referrals'] = stats_referrals
        self.result(
            CHECK_RESULT_OK,
            'SlapdStats',
            performance_data={
                'bytes': stats_bytes_rate,
                'entries': stats_entries_rate,
                'pdu': stats_pdu_rate,
                'referrals': stats_referrals_rate,
            },
            check_output='Stats: %d bytes (%0.1f bytes/sec) / %d entries (%0.1f entries/sec) / %d PDUs (%0.1f PDUs/sec) / %d referrals (%0.1f referrals/sec)' % (
                stats_bytes,
                stats_bytes_rate,
                stats_entries,
                stats_entries_rate,
                stats_pdu,
                stats_pdu_rate,
                stats_referrals,
                stats_referrals_rate,
            )
        )
        monitor_ops_counters = self._monitor_cache.operation_counters()
        if monitor_ops_counters:
            ops_all_initiated = 0
            ops_all_completed = 0
            ops_all_waiting = 0
            for ops_name, ops_initiated, ops_completed in monitor_ops_counters:
                item_name = 'SlapdOps_%s' % (ops_name)
                self.add_item(item_name)
                self._next_state[ops_name+'_ops_initiated'] = ops_initiated
                self._next_state[ops_name+'_ops_completed'] = ops_completed
                ops_waiting = ops_initiated - ops_completed
                ops_all_waiting += ops_waiting
                ops_all_completed += ops_completed
                ops_all_initiated += ops_initiated
                ops_initiated_rate = self._get_rate(ops_name+'_ops_initiated', ops_initiated, last_time_span)
                ops_completed_rate = self._get_rate(ops_name+'_ops_completed', ops_completed, last_time_span)
                self.result(
                    CHECK_RESULT_OK,
                    item_name,
                    performance_data={
                        'ops_completed_rate': ops_completed_rate,
                        'ops_initiated_rate': ops_initiated_rate,
                        'ops_waiting': ops_waiting,
                    },
                    check_output='completed %d of %d operations (%0.2f/s completed, %0.2f/s initiated, %d waiting)' % (
                        ops_completed,
                        ops_initiated,
                        ops_completed_rate,
                        ops_initiated_rate,
                        ops_waiting,
                    ),
                )
            ops_all_initiated_rate = self._get_rate('ops_all_initiated', ops_all_initiated, last_time_span)
            ops_all_completed_rate = self._get_rate('ops_all_completed', ops_all_completed, last_time_span)
            self._next_state['ops_all_initiated'] = ops_all_initiated
            self._next_state['ops_all_completed'] = ops_all_completed
            if OPS_WAITING_CRIT is not None and ops_all_waiting > OPS_WAITING_CRIT:
                state = CHECK_RESULT_ERROR
            elif OPS_WAITING_WARN is not None and ops_all_waiting > OPS_WAITING_WARN:
                state = CHECK_RESULT_WARNING
            else:
                state = CHECK_RESULT_OK
            self.result(
                state, 'SlapdOps',
                performance_data={
                    'ops_completed_rate': ops_all_completed_rate,
                    'ops_initiated_rate': ops_all_initiated_rate,
                    'ops_waiting': ops_all_waiting,
                },
                check_output='%d operation types / completed %d of %d operations (%0.2f/s completed, %0.2f/s initiated, %d waiting)' % (
                    len(monitor_ops_counters),
                    ops_all_completed,
                    ops_all_initiated,
                    ops_all_completed_rate,
                    ops_all_initiated_rate,
                    ops_all_waiting,
                ),
            )
        # end of _get_slapd_perfstats()

    def _check_mdb_size(self, db_num, db_suffix, db_type, db_dir):
        if db_type != 'mdb':
            return
        item_name = '_'.join((
            'SlapdMDBSize',
            str(db_num),
            self.subst_item_name_chars(db_suffix),
        ))
        self.add_item(item_name)
        try:
            mdb_pages_max = self._monitor_cache.get_value(
                'cn=Database %d,cn=Databases' % (db_num),
                'olmMDBPagesMax',
            )
            mdb_pages_used = self._monitor_cache.get_value(
                'cn=Database %d,cn=Databases' % (db_num),
                'olmMDBPagesUsed',
            )
        except KeyError:
            # ITS#7770 not available (prior to OpenLDAP 2.4.48)
            # => fall back to naive file stat method
            mdb_filename = os.path.join(db_dir, 'data.mdb')
            try:
                mdb_max_size = os.stat(mdb_filename).st_size
                mdb_real_size = os.stat(mdb_filename).st_blocks * 512
            except OSError as exc:
                self.result(
                    CHECK_RESULT_ERROR,
                    item_name,
                    check_output='OS error stating %r: %s' % (
                        mdb_filename,
                        exc,
                    ),
                )
            else:
                mdb_use_percentage = 100 * \
                    float(mdb_real_size) / float(mdb_max_size)
                self.result(
                    CHECK_RESULT_OK,
                    item_name,
                    check_output='DB file %r has %d of max. %d bytes (%0.1f %%)' % (
                        mdb_filename,
                        mdb_real_size,
                        mdb_max_size,
                        mdb_use_percentage,
                    ),
                    performance_data=dict(
                        mdb_pages_used=mdb_real_size/4096,
                        mdb_pages_max=mdb_max_size/4096,
                        mdb_use_percentage=mdb_use_percentage,
                    ),
                )
        else:
            mdb_use_percentage = 100 * float(mdb_pages_used) / float(mdb_pages_max)
            self.result(
                CHECK_RESULT_OK,
                item_name,
                check_output='LMDB in %r uses %d of max. %d pages (%0.1f %%)' % (
                    db_dir,
                    mdb_pages_used,
                    mdb_pages_max,
                    mdb_use_percentage,
                ),
                performance_data=dict(
                    mdb_pages_used=mdb_pages_used,
                    mdb_pages_max=mdb_pages_max,
                    mdb_use_percentage=mdb_use_percentage,
                ),
            )
        # end of _check_mdb_size()

    def _check_databases(self):
        try:
            db_suffixes = self._ldapi_conn.db_suffixes()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdDatabases',
                check_output='error retrieving DB suffixes: %s' % (exc)
            )
            return
        self.result(
            CHECK_RESULT_OK,
            'SlapdDatabases',
            check_output='Found %d real databases: %s' % (
                len(db_suffixes),
                ' / '.join([
                    '{%d}%s: %s' % (n, t, s)
                    for n, s, t, _ in db_suffixes
                ]),
            )
        )
        for db_num, db_suffix, db_type, db_dir in db_suffixes:
            # Check file sizes of MDB database files
            self._check_mdb_size(db_num, db_suffix, db_type, db_dir)

            # Count LDAP entries with no-op search controls
            item_name = '_'.join((
                'SlapdEntryCount',
                str(db_num),
                self.subst_item_name_chars(db_suffix),
            ))
            self.add_item(item_name)
            try:
                noop_start_timestamp = time.time()
                noop_result = self._ldapi_conn.noop_search(
                    db_suffix,
                    timeout=NOOP_SEARCH_TIMEOUT,
                )
            except ldap0.TIMEOUT:
                self.result(
                    CHECK_RESULT_WARNING,
                    item_name,
                    check_output='Request timeout %0.1f s reached while retrieving entry count for %r.' % (
                        LDAP_TIMEOUT,
                        db_suffix,
                    )
                )
            except ldap0.TIMELIMIT_EXCEEDED:
                self.result(
                    CHECK_RESULT_WARNING,
                    item_name,
                    check_output='Search time limit %0.1f s exceeded while retrieving entry count for %r.' % (
                        NOOP_SEARCH_TIMEOUT,
                        db_suffix,
                    )
                )
            except ldap0.UNAVAILABLE_CRITICAL_EXTENSION:
                self.result(
                    CHECK_RESULT_NOOP_SRCH_UNAVAILABLE,
                    item_name,
                    check_output='no-op search control not supported'
                )
            except CATCH_ALL_EXC as exc:
                self.result(
                    CHECK_RESULT_ERROR,
                    item_name,
                    check_output='Error retrieving entry count for %r: %s' % (db_suffix, exc)
                )
            else:
                noop_response_time = time.time() - noop_start_timestamp
                if noop_result is None:
                    self.result(
                        CHECK_RESULT_WARNING,
                        item_name,
                        check_output='Could not retrieve entry count (result was None)',
                    )
                else:
                    num_all_search_results, num_all_search_continuations = noop_result
                    if num_all_search_continuations:
                        self.result(
                            CHECK_RESULT_ERROR,
                            item_name,
                            performance_data={
                                'count': num_all_search_results,
                            },
                            check_output='%r has %d referrals! (response time %0.1f s)' % (
                                db_suffix,
                                num_all_search_continuations,
                                noop_response_time,
                            )
                        )
                    elif num_all_search_results < MINIMUM_ENTRY_COUNT:
                        self.result(
                            CHECK_RESULT_WARNING,
                            item_name,
                            performance_data={
                                'count': num_all_search_results,
                            },
                            check_output='%r only has %d entries (response time %0.1f s)' % (
                                db_suffix,
                                num_all_search_results,
                                noop_response_time,
                            )
                        )
                    else:
                        self.result(
                            CHECK_RESULT_OK,
                            item_name,
                            performance_data={
                                'count': num_all_search_results,
                            },
                            check_output='%r has %d entries (response time %0.1f s)' % (
                                db_suffix,
                                num_all_search_results,
                                noop_response_time,
                            )
                        )
        # end of _check_databases()

    def _check_providers(self, syncrepl_topology):
        """
        test connection to each provider
        """
        remote_csn_dict = {}
        syncrepl_target_fail_msgs = []
        task_dict = {}
        task_connect_latency = {}

        for syncrepl_target_uri in syncrepl_topology.keys():
            # start separate threads for parallelly connecting to slapd providers
            task_dict[syncrepl_target_uri] = SyncreplProviderTask(
                self,
                syncrepl_topology,
                syncrepl_target_uri,
            )
            task_dict[syncrepl_target_uri].start()

        # now wait for the spawned threads to finish and collect the results
        for syncrepl_target_uri in syncrepl_topology.keys():
            task = task_dict[syncrepl_target_uri]
            task.join()
            if task.remote_csn_dict:
                remote_csn_dict[syncrepl_target_uri] = task.remote_csn_dict
            if task.err_msgs:
                syncrepl_target_fail_msgs.extend(task.err_msgs)
            if task.connect_latency is not None:
                task_connect_latency[syncrepl_target_uri] = task.connect_latency

        if syncrepl_target_fail_msgs or \
           len(remote_csn_dict) < len(syncrepl_topology):
            slapd_provider_percentage = float(len(remote_csn_dict))/float(len(syncrepl_topology))*100
            if slapd_provider_percentage >= SYNCREPL_PROVIDER_ERROR_PERCENTAGE:
                check_result = CHECK_RESULT_WARNING
            else:
                check_result = CHECK_RESULT_ERROR
        else:
            slapd_provider_percentage = 100.0
            check_result = CHECK_RESULT_OK
        self.result(
            check_result,
            'SlapdProviders',
            performance_data={
                'count': len(remote_csn_dict),
                'total': len(syncrepl_topology),
                'percent': slapd_provider_percentage,
                'avg_latency': sum(task_connect_latency.values())/len(task_connect_latency) if task_connect_latency else 0.0,
                'max_latency': max(task_connect_latency.values()) if task_connect_latency else 0.0,
            },
            check_output='Connected to %d of %d (%0.1f%%) providers: %s' % (
                len(remote_csn_dict),
                len(syncrepl_topology),
                slapd_provider_percentage,
                ' / '.join(syncrepl_target_fail_msgs),
            ),
        )
        return remote_csn_dict # end of _check_providers()

    def checks(self):

        # Get command-line arguments
        ldaps_uri = sys.argv[2] or 'ldaps://%s' % socket.getfqdn()
        my_authz_id = sys.argv[3]

        local_wai = self._open_ldapi_conn(sys.argv[1] or 'ldapi:///')

        # read cn=config
        #---------------
        try:
            _ = self._ldapi_conn.get_naming_context_attrs()
            self._config_attrs = self._ldapi_conn.read_s(
                self._ldapi_conn.configContext[0],
                attrlist=[
                    'olcArgsFile',
                    'olcConfigDir',
                    'olcConfigFile',
                    'olcPidFile',
                    'olcSaslHost',
                    'olcServerID',
                    'olcThreads',
                    'olcTLSCACertificateFile',
                    'olcTLSCertificateFile',
                    'olcTLSCertificateKeyFile',
                    'olcTLSDHParamFile',
                ],
            ).entry_s
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdConfig',
                check_output='Error getting local configuration on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdConfig',
                check_output='Successfully connected to %r as %r found %r and %r' % (
                    self._ldapi_conn.uri,
                    local_wai,
                    self._ldapi_conn.configContext[0],
                    self._ldapi_conn.monitorContext[0],
                )
            )

            self._check_sasl_hostname(self._config_attrs)
            self._check_tls_file(self._config_attrs)

        syncrepl_topology = {}
        try:
            syncrepl_list, syncrepl_topology = self._ldapi_conn.get_syncrepl_topology()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdReplTopology',
                check_output='Error getting syncrepl topology on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdReplTopology',
                check_output='successfully retrieved syncrepl topology with %d items: %s' % (
                    len(syncrepl_topology),
                    syncrepl_topology,
                )
            )

        # read cn=Monitor
        #----------------------------------------------------------------------
        try:
            self._monitor_cache = OpenLDAPMonitorCache(
                self._ldapi_conn.get_monitor_entries(),
                self._ldapi_conn.monitorContext[0],
            )
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdMonitor',
                check_output='Error getting local monitor data on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdMonitor',
                check_output='Successfully retrieved %d entries from %r on %r' % (
                    len(self._monitor_cache),
                    self._ldapi_conn.monitorContext[0],
                    self._ldapi_conn.uri,
                ),
            )

        self._check_slapd_start(self._config_attrs)
        self._check_conns()
        self._check_threads()
        self._check_slapd_sock()
        self._check_databases()
        self._get_slapd_perfstats()

        local_csn_dict = self._get_local_csns(syncrepl_list)

        # Close LDAPI connection
        self._ldapi_conn.unbind_s()

        self._check_local_ldaps(ldaps_uri, my_authz_id)

        # Write current state to disk
        self._state.write_state(self._next_state)

        # 2. Connect and bind to all replicas to check whether they are reachable
        #----------------------------------------------------------------------

        remote_csn_dict = self._check_providers(syncrepl_topology)

        state = CHECK_RESULT_WARNING

        now = time.time()

        for db_num, db_suffix, _ in syncrepl_list:

            item_name = '_'.join((
                'SlapdSyncRepl',
                str(db_num),
                self.subst_item_name_chars(db_suffix),
            ))
            issues = []

            if not local_csn_dict[db_suffix]:
                # Message output done before => silent here
                state = CHECK_RESULT_UNKNOWN
                issues.append('no local CSNs avaiable => skip')
                continue

            max_csn_timedelta = 0.0

            for syncrepl_target_uri in syncrepl_topology:

                try:
                    remote_csn_parsed_dict = remote_csn_dict[syncrepl_target_uri][db_suffix]
                except KeyError as key_error:
                    issues.append(
                        'KeyError for %r / %r: %s' % (
                            syncrepl_target_uri,
                            db_suffix,
                            key_error,
                        )
                    )
                    continue

                for server_id, local_csn_timestamp in local_csn_dict[db_suffix].items():

                    if not server_id in remote_csn_parsed_dict:
                        state = CHECK_RESULT_WARNING
                        issues.append(
                            'contextCSN of %s missing on replica %r' % (
                                server_id,
                                syncrepl_target_uri,
                            )
                        )
                        continue

                    remote_csn_timestamp = remote_csn_parsed_dict[server_id]

                    csn_timedelta = abs(local_csn_timestamp-remote_csn_timestamp)

                    if csn_timedelta > max_csn_timedelta:
                        max_csn_timedelta = csn_timedelta
                    if csn_timedelta:
                        issues.append(
                            '%s contextCSN delta for %s: %0.1f s' % (
                                syncrepl_target_uri,
                                server_id,
                                csn_timedelta
                            )
                        )

            if SYNCREPL_TIMEDELTA_CRIT is not None and \
               max_csn_timedelta > SYNCREPL_TIMEDELTA_CRIT:
                old_critical_timestamp = float(
                    self._state.data.get(
                        item_name+'_critical',
                        str(now))
                    )
                if now - old_critical_timestamp > SYNCREPL_HYSTERESIS_CRIT:
                    state = CHECK_RESULT_ERROR
                self._next_state[item_name+'_critical'] = old_critical_timestamp
            else:
                self._next_state[item_name + '_critical'] = -1.0
            if SYNCREPL_TIMEDELTA_WARN is not None and \
                max_csn_timedelta > SYNCREPL_TIMEDELTA_WARN:
                old_warn_timestamp = float(
                    self._state.data.get(
                        item_name + '_warning',
                        str(now)
                    )
                )
                if now - old_warn_timestamp > SYNCREPL_HYSTERESIS_WARN:
                    state = CHECK_RESULT_WARNING
                self._next_state[item_name+'_warning'] = old_warn_timestamp
            else:
                self._next_state[item_name+'_warning'] = -1.0

            if not issues:
                state = 0
                issues.append('no replication issues determined')

            self.result(
                state,
                item_name,
                performance_data={
                    'max_csn_timedelta': max_csn_timedelta
                },
                check_output='%r max. contextCSN delta: %0.1f / %s' % (
                    db_suffix,
                    max_csn_timedelta,
                    ' / '.join(issues),
                ),
            )

        # end of checks()

#-----------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------

def run():
    """
    run the script
    """
    slapd_check = SlapdCheck(
        output_file=sys.stdout,
        state_filename=STATE_FILENAME,
    )
    slapd_check.run()


if __name__ == '__main__':
    run()
