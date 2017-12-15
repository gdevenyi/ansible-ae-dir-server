#!/usr/bin/python -OO
# -*- coding: utf-8 -*-
"""
slapd-sock listener demon which sends intercepted BIND requests
to a remote LDAP server in case the request 'dn' and 'peername'
information matches
"""

from __future__ import absolute_import

import os
import logging

__version__ = '0.4.0'
__author__ = u'Michael Ströder <michael@stroeder.com>'

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# If
# 1. 'peername' matches any item in
#    LDAP_PROXY_PEER_ADDRS or LDAP_PROXY_PEER_NETS *and*
# 2. BIND request's 'dn' matches LDAP_PROXY_BINDDN_PATTERN
# then bind request must be validated by upstream provider replica
LDAP_PROXY_PEER_ADDRS = (
    '/opt/ae-dir/run/slapd/ldapi',
    '127.0.0.1',
)
LDAP_PROXY_PEER_NETS = (
    '0.0.0.0/0',
)
# Regex pattern for HOTP user DNs
# If bind-DN does not match this pattern, request will be continued by slapd
LDAP_PROXY_BINDDN_PATTERN = u'^uid=[a-z]+,cn=[a-z]+,dc=ae-dir,dc=example,dc=org$'

# UIDs and peer GIDS of peers which are granted access
# (list of int/strings)
ALLOWED_UIDS = [0, 'ae-dir-slapd']
ALLOWED_GIDS = [0]

# String with octal representation of socket permissions
SOCKET_PERMISSIONS = '0666'

# Trace level for python-ldap logs
PYLDAP_TRACELEVEL = 0

# Number of times connecting to local LDAPI is retried before sending a
# failed response for a query
LDAP_MAXRETRYCOUNT = 10
# Time to wait before retrying to connect within one query
LDAP_RETRYDELAY = 0.1

# SASL authz-ID to be sent along with SASL/EXTERNAL bind
#LDAP_SASL_AUTHZID = 'dn:uid=simple_bind_proxy,dc=example,dc=com'
LDAP_SASL_AUTHZID = None

# Time in seconds for which normal LDAP searches will be valid in cache
LDAP_CACHE_TTL = 5.0
# Time in seconds for which pwdPolicy and oathHOTPParams entries will be
# valid in cache
LDAP_LONG_CACHE_TTL = 100 * LDAP_CACHE_TTL

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap.OPT_NETWORK_TIMEOUT and ldap.OPT_TIMEOUT
LDAP_TIMEOUT = 3.0

# Template filter string for reading the bind-DN's entry to determine
# whether to proxy the simple bind (None for disabling this search request)
LDAP_PROXY_FILTER_TMPL = '(&(objectClass=aeUser)(objectClass=oathHOTPUser)(oathHOTPToken=*))'

LDAP_USERNAME_ATTR = 'uid'

# Timeout in seconds for the server (Unix domain) socket
SOCKET_TIMEOUT = 2 * LDAP_TIMEOUT

# Logging formats
SYS_LOG_FORMAT = '%(levelname)s %(message)s'
CONSOLE_LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'

# Base number for floating average value of response delay
AVERAGE_COUNT = 100

# Default log level to use
LOG_LEVEL = logging.INFO

# Time (seconds) for assuming an userPassword+OTP value to be valid in cache
CACHE_TTL = -1.0

DEBUG_VARS = [
    'request_dn_utf8',
    'pwd_changed_time',
    'pwd_failure_times',
    'pwd_policy_subentry_dn',
    'pwd_policy_subentry',
    'pwd_max_age',
    'pwd_expired',
    'remote_ldap_uris',
    'user_filterstr',
]

# Error messages
if __debug__:
    DEBUG_VARS.extend([
    ])

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# from Python's standard lib
import sys, datetime, re, socket, collections

import netaddr

# python-ldap
import ldap
from ldap import LDAPError
from ldap.controls.sessiontrack import \
   SessionTrackingControl, SESSION_TRACKING_FORMAT_OID_USERNAME

# local modules
from slapdsock.ldaphelper import RESULT_CODE
from slapdsock.ldaphelper import ldap_datetime_str
from slapdsock.ldaphelper import MyLDAPUrl, is_expired
from slapdsock.loghelper import combined_logger
from slapdsock.handler import SlapdSockHandler, SlapdSockHandlerError
from slapdsock.message import RESULTResponse, InvalidCredentialsResponse

# run multi-threaded
from slapdsock.service import SlapdSockThreadingServer as SlapdSockServer

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


class SimpleBindProxyServer(SlapdSockServer):

    """
    This is used to pass in more parameters to the server instance
    """
    ldapi_authz_id = LDAP_SASL_AUTHZID
    ldap_retry_max = LDAP_MAXRETRYCOUNT
    ldap_retry_delay = LDAP_RETRYDELAY
    ldap_cache_ttl = LDAP_CACHE_TTL

    def __init__(
            self,
            server_address,
            RequestHandlerClass,
            logger,
            average_count,
            socket_timeout,
            socket_permissions,
            allowed_uids,
            allowed_gids,
            bind_and_activate=True,
            log_vars=None,
        ):
        self._ldap_conn = None
        SlapdSockServer.__init__(
            self,
            server_address,
            RequestHandlerClass,
            logger,
            average_count,
            socket_timeout,
            socket_permissions,
            allowed_uids,
            allowed_gids,
            bind_and_activate,
            monitor_dn=None,
            log_vars=log_vars,
        )


class BindProxyHandler(SlapdSockHandler):

    """
    Handler class which proxies some simple bind requests to remote server
    """

    cache_ttl = {
        'BIND': CACHE_TTL,
    }
    ldap_proxy_peer_addrs = set(LDAP_PROXY_PEER_ADDRS)
    ldap_proxy_peer_nets = [
        netaddr.IPNetwork(p)
        for p in LDAP_PROXY_PEER_NETS
    ]
    ldap_proxy_filter_tmpl = LDAP_PROXY_FILTER_TMPL

    def _check_peername(self, peer):
        peer_type, peer_addr = peer.lower().rsplit(':')[0].split('=')
        if peer_addr in self.ldap_proxy_peer_addrs:
            return True
        if not peer_type == 'ip':
            return False
        peer_ip_address = netaddr.IPAddress(peer_addr)
        for peer_net in self.ldap_proxy_peer_nets:
            if not isinstance(peer_net, netaddr.IPNetwork):
                continue
            if peer_ip_address in peer_net:
                return True
        return False # end of _check_peername()

    def _shuffle_remote_ldap_uris(self, dn):
        # Generate list of upstream LDAP URIs shifted based on bind-DN hash
        remote_ldap_uris = collections.deque(self.server.remote_ldap_uris)
        remote_ldap_uris.rotate(hash(dn) % len(remote_ldap_uris))
        self._log(logging.DEBUG, 'remote_ldap_uris=%s', repr(remote_ldap_uris))
        return remote_ldap_uris # end of _shuffle_remote_ldap_uris()

    def _gen_session_tracking_ctrl(self, request, request_dn_utf8):
        # Prepare Session Track control for bind request to upstream
        return SessionTrackingControl(
            request.peername,
            socket.getfqdn(),
            SESSION_TRACKING_FORMAT_OID_USERNAME,
            request_dn_utf8
        )

    def _check_regex(self, request):
        """
        Returns True if request.dn matches LDAP_PROXY_BINDDN_PATTERN
        """
        # Preliminary request DN pattern check
        proxy_binddn_regex = re.compile(LDAP_PROXY_BINDDN_PATTERN.format(
            suffix=request.suffix,
        ))
        return proxy_binddn_regex.match(request.dn)

    def do_bind(self, request):
        """
        This method first checks whether the BIND request must be sent
        to the upstream replica
        """

        if not self._check_peername(request.peername):
            self._log(
                logging.DEBUG,
                'Peer %s not in %s and %s => let slapd continue',
                repr(request.peername),
                repr(self.ldap_proxy_peer_addrs),
                repr(self.ldap_proxy_peer_nets),
            )
            return 'CONTINUE\n'

        if not self._check_regex(request):
            self._log(
                logging.DEBUG,
                'Bind-DN %s (from %s) does not match %s => let slapd continue',
                repr(request.dn),
                repr(request.peername),
                repr(LDAP_PROXY_BINDDN_PATTERN),
            )
            return 'CONTINUE\n'

        # We need current time in GeneralizedTime syntax later
        now_dt = datetime.datetime.utcnow()
        now_str = unicode(ldap_datetime_str(now_dt))

        # We need UTF-8 encoded DN several times later
        request_dn_utf8 = request.dn.encode('utf-8')

        if self.ldap_proxy_filter_tmpl:

            # Get LDAPObject instance for local LDAPI access
            user_filterstr = self.ldap_proxy_filter_tmpl.format(now=now_str).encode('utf-8')

            # Try to read the user entry for the given request dn
            try:
                try:
                    local_ldap_conn = self.server.get_ldapi_conn()
                    ldap_result = local_ldap_conn.search_s(
                        request_dn_utf8,
                        ldap.SCOPE_BASE,
                        '(&{0}({1}=*))'.format(
                            user_filterstr,
                            LDAP_USERNAME_ATTR,
                        ),
                        attrlist=[
                            LDAP_USERNAME_ATTR,
                            'pwdChangedTime',
                            'pwdFailureTime',
                            'pwdPolicySubentry',
                        ],
                    )
                except ldap.SERVER_DOWN, ldap_error:
                    self.server.disable_ldapi_conn()
                    raise ldap_error
            except LDAPError, ldap_error:
                raise SlapdSockHandlerError(
                    ldap_error,
                    log_level=logging.WARN,
                    response=InvalidCredentialsResponse(request.msgid),
                    log_vars=self.server._log_vars,
                )

            # Check whether we want handle this
            if not ldap_result:
                raise SlapdSockHandlerError(
                    Exception('No result reading %s with filter %s' % (
                        repr(request.dn), repr(user_filterstr),
                    )),
                    log_level=logging.WARN,
                    response='CONTINUE\n',
                    log_vars=self.server._log_vars,
                )

            user_entry = ldap_result[0][1]
            self._log(logging.DEBUG, 'user_entry = %s', repr(user_entry))

            # Attributes from user entry
            pwd_changed_time = user_entry.get('pwdChangedTime', [None])[0]
            pwd_failure_times = user_entry.get('pwdFailureTime', [])

            # Try to read password policy subentry
            try:
                pwd_policy_subentry_dn = user_entry['pwdPolicySubentry'][0]
                pwd_policy_subentry = local_ldap_conn.read_s(
                    pwd_policy_subentry_dn,
                    '(objectClass=pwdPolicy)',
                    attrlist=[
                        'pwdAttribute',
                        'pwdFailureCountInterval',
                        'pwdMaxAge',
                        'pwdMaxFailure',
                    ],
                    cache_time=LDAP_LONG_CACHE_TTL,
                )
            except ldap.SERVER_DOWN:
                self.server.disable_ldapi_conn()
            except (LDAPError, KeyError):
                pass
            else:
                pwd_max_age = pwd_policy_subentry.get('pwdMaxAge', ['-1'])[0]
                # Check whether OATH secret exceeds max age (is expired)
                pwd_expired = is_expired(
                    pwd_changed_time,
                    pwd_max_age,
                    now_dt
                )
                if pwd_expired:
                    raise SlapdSockHandlerError(
                        Exception('Password of %s is expired' % (
                            repr(request.dn),
                        )),
                        log_level=logging.INFO,
                        response='CONTINUE\n',
                        log_vars=self.server._log_vars,
                    )

        # Generate list of upstream LDAP URIs shifted based on bind-DN hash
        remote_ldap_uris = collections.deque(self.server.remote_ldap_uris)
        remote_ldap_uris.rotate(hash(request_dn_utf8) % len(remote_ldap_uris))
        self._log(logging.DEBUG, 'remote_ldap_uris=%s', repr(remote_ldap_uris))

        try:
            try:
                remote_ldap_conn = ldap.initialize(
                    ' '.join(remote_ldap_uris),
                    trace_level=0,
                    trace_file=self.server._logger_fileobj,
                )
                remote_ldap_conn.simple_bind_s(
                    request_dn_utf8,
                    request.cred,
                    serverctrls=[
                        self._gen_session_tracking_ctrl(request, request_dn_utf8)
                    ]
                )
            except ldap.LDAPError, ldap_error:
                try:
                    result_code = RESULT_CODE[type(ldap_error)]
                except KeyError:
                    result_code = RESULT_CODE['other']
                try:
                    info = ldap_error.args[0]['info']
                except (AttributeError, KeyError):
                    info = None
                self._log(
                    logging.ERROR,
                    'LDAPError from upstream: %s => return %s',
                    str(ldap_error),
                    result_code,
                )
            else:
                # Prepare the sucess result returned
                result_code = 'success'
                info = None
                self._log(
                    logging.INFO,
                    'Validation ok for %s (from %s) => RESULT: %s',
                    repr(request.dn),
                    repr(request.peername),
                    result_code,
                )
        finally:
            try:
                remote_ldap_conn.unbind_s()
            except Exception:
                pass

        self._log(
            logging.DEBUG,
            'msgid=%s result_code=%s info=%s',
            request.msgid,
            result_code,
            info,
        )
        return RESULTResponse(
            request.msgid,
            result_code,
            info=info
        )
        # end of do_bind()


#-----------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------

def run_this():
    """
    The main script
    """

    script_name = os.path.abspath(sys.argv[0])

    log_level = LOG_LEVEL
    console_log_format = None
    if __debug__ and os.environ.get('DEBUG', 'no') == 'yes':
        log_level = logging.DEBUG
        console_log_format = CONSOLE_LOG_FORMAT

    my_logger = combined_logger(
        os.path.basename(script_name),
        log_level,
        sys_log_format=SYS_LOG_FORMAT,
        console_log_format=console_log_format,
    )

    my_logger.info(
        'Starting %s %s (log level %d)',
        script_name,
        __version__,
        my_logger.level
    )

    if __debug__:
        my_logger.error(
            '!!! Running in debug mode (log level %d)! Secret data will be logged! Don\'t do that!!!',
            my_logger.level
        )

    try:
        socket_path = sys.argv[1]
        local_ldap_uri = sys.argv[2]
        remote_ldap_uris = tuple(sys.argv[3:])
    except IndexError:
        my_logger.error('Not enough arguments => abort')
        sys.exit(1)

    if not remote_ldap_uris:
        my_logger.error('No remote LDAP URIs => abort')
        sys.exit(1)

    local_ldap_uri_obj = MyLDAPUrl(local_ldap_uri)

    try:
        slapd_sock_listener = SimpleBindProxyServer(
            socket_path,
            BindProxyHandler,
            my_logger,
            AVERAGE_COUNT,
            SOCKET_TIMEOUT, SOCKET_PERMISSIONS,
            ALLOWED_UIDS, ALLOWED_GIDS,
            log_vars=DEBUG_VARS,
        )
        slapd_sock_listener.ldapi_uri = local_ldap_uri_obj.initializeUrl()
        slapd_sock_listener.ldap_trace_level = int(local_ldap_uri_obj.trace_level or '0') or PYLDAP_TRACELEVEL
        slapd_sock_listener.remote_ldap_uris = remote_ldap_uris
        try:
            slapd_sock_listener.serve_forever()
        except KeyboardInterrupt:
            my_logger.warn('Received interrupt signal => shutdown')
    finally:
        my_logger.debug('Remove socket path %s', repr(socket_path))
        try:
            os.remove(socket_path)
        except OSError:
            pass

    return # end of main()


if __name__ == '__main__':
    run_this()
