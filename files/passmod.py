#!/usr/bin/python -OO
# -*- coding: utf-8 -*-
"""
slapd-sock listener demon queried by OpenLDAP's slapd-sock

this demon intercepts password changes in ADD and MODIFY operations
and exports the userPassword value
"""

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# from Python's standard lib
import logging
import os
import sys
import Queue
import threading
import time
from collections import OrderedDict

# python-ldap
import ldap
from ldap.dn import str2dn
from ldap.functions import strf_secs as ldap_strf_secs

# from pyasn1
from pyasn1.type.univ import OctetString, Sequence
from pyasn1.type.namedtype import NamedTypes, OptionalNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1.codec.ber import decoder as pyasn1_decoder
from pyasn1.error import PyAsn1Error

# local modules
from slapdsock.ldaphelper import MyLDAPUrl, MyLDAPObject, LocalLDAPConn
from slapdsock.loghelper import combined_logger, LoggerFileobj
from slapdsock.handler import SlapdSockHandler
from slapdsock.service import SlapdSockThreadingServer

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

__version__ = '0.0.1'
__author__ = u'Michael Ströder <michael@stroeder.com>'

# DN of default pwdPolicy entry used
# in case attribute pwdPolicySubentry is missing
#PWD_POLICY_SUBENTRY_DEFAULT = 'cn=ppolicy-default,cn=ae,ou=ae-dir'
PWD_POLICY_SUBENTRY_DEFAULT = None

PWD_MIN_LENGTH = 0
PWD_MIN_AGE = 0
PWD_SCHEME = '{CRYPT}'
PWD_CRYPT_SCHEME = 'sha512_crypt'
PWD_CRYPT_SCHEME_ARGS = {
    'rounds': 5000,
}

# UIDs and peer GIDS of peers which are granted access
# (list of int/strings)
ALLOWED_UIDS = [0, 'ldap', os.getuid()]
ALLOWED_GIDS = [0]

# String with octal representation of socket permissions
SOCKET_PERMISSIONS = '0666'

# Trace level for python-ldap logs
PYLDAP_TRACELEVEL = int(os.environ.get('PYLDAP_TRACELEVEL', 0))

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
LDAP_LONG_CACHE_TTL = 20 * LDAP_CACHE_TTL

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap.OPT_NETWORK_TIMEOUT and ldap.OPT_TIMEOUT
LDAP_TIMEOUT = 3.0

# attribute containing username
LDAP_USERNAME_ATTR = 'uid'

# Timeout in seconds for the server (Unix domain) socket
SOCKET_TIMEOUT = 2 * LDAP_TIMEOUT

# Logging formats
SYS_LOG_FORMAT = '%(name)s %(levelname)s %(message)s'
CONSOLE_LOG_FORMAT = '%(name)s %(asctime)s %(levelname)s %(message)s'

# Base number for floating average value of response delay
AVERAGE_COUNT = 100

# Default log level to use
LOG_LEVEL = int(os.environ.get('LOG_LEVEL', logging.INFO))

# Time (seconds) for assuming an userPassword+OTP value to be valid in cache
CACHE_TTL = -1.0

DEBUG_VARS = [
    'user_dn',
]

# Error messages
if __debug__:
    DEBUG_VARS.extend([
        'old_passwd',
        'new_passwd',
    ])

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

def unicode_pwd(password):
    """
    returns password or random generated password as properly encoded
    'unicodePwd' value for MS AD

    see also:
    https://msdn.microsoft.com/en-us/library/cc223248.aspx
    https://support.microsoft.com/en-us/help/269190/how-to-change-a-windows-active-directory-and-lds-user-password-through-ldap
    """
    return u'"{}"'.format(password).encode('utf-16-le')


class DictQueue(Queue.Queue):
    """
    modified Queue class which internally stores items in a dict
    """

    def _init(self, maxsize):
        self.queue = OrderedDict()

    # Put a new item in the queue
    def _put(self, item):
        key, value = item
        self.queue[key] = value

    # Get an item from the queue
    def _get(self):
        key, value = self.queue.popitem()
        return (key, value)


class PWSyncWorker(threading.Thread, LocalLDAPConn):
    """
    Thread class for the password synchronization worker
    """
    passwd_update_delay = 1.0
    source_id_attr = 'uid'
    target_filter_format = '({0}={1})'
    target_id_attr = 'uid'
    target_password_attr = 'userPassword'
    target_password_encoding = 'utf-8'
    # MS AD
    #target_password_attr = 'unicodePwd'

    def __init__(
            self,
            target_ldap_url,
            queue,
        ):
        self._target_ldap_url = target_ldap_url
        if target_ldap_url.attrs is not None and \
           len(target_ldap_url.attrs) == 2:
            self.target_id_attr, self.target_password_attr = target_ldap_url.attrs
        self.logger = combined_logger(
            self.__class__.__name__,
            LOG_LEVEL,
            sys_log_format=SYS_LOG_FORMAT,
            console_log_format=CONSOLE_LOG_FORMAT,
        )
        self._queue = queue
        threading.Thread.__init__(self, name=self.__class__.__module__+self.__class__.__name__)
        LocalLDAPConn.__init__(self, self.logger)
        # open connection to target LDAP server
        self.target_conn = MyLDAPObject(
            target_ldap_url.initializeUrl(),
            trace_level=PYLDAP_TRACELEVEL,
            trace_file=LoggerFileobj(self.logger, logging.DEBUG),
            retry_max=LDAP_MAXRETRYCOUNT,
            retry_delay=LDAP_RETRYDELAY,
            who=target_ldap_url.who or '',
            cred=target_ldap_url.cred or '',
            cache_time=LDAP_CACHE_TTL,
        )
        # end of PWSyncWorker.__init__()

    def _check_password(self, user_dn, new_passwd):
        password_correct = False
        self.logger.debug('Check password of %r', user_dn)
        checkpw_conn = None
        try:
            try:
                # check whether user_dn, new_passwd is correct
                # by new connect with simple bind
                checkpw_conn = MyLDAPObject(
                    self.ldapi_uri,
                    trace_level=PYLDAP_TRACELEVEL,
                    trace_file=LoggerFileobj(self.logger, logging.DEBUG),
                    retry_max=LDAP_MAXRETRYCOUNT,
                    retry_delay=LDAP_RETRYDELAY,
                    who=user_dn,
                    cred=new_passwd,
                    cache_time=LDAP_CACHE_TTL,
                )
            except ldap.INVALID_CREDENTIALS:
                password_correct = False
            else:
                password_correct = True
        finally:
            if checkpw_conn is not None:
                checkpw_conn.unbind_s()
        return password_correct # end of _check_password()

    def get_target_id(self, source_dn):
        """
        determine target identifier based on user's source DN
        """
        rdn_attr_type, uid, _ = str2dn(source_dn)[0][0]
        if rdn_attr_type.lower() != self.source_id_attr:
            # check accepted attribute in RDN
            self.logger.warn(
                'RDN attribute %r is not %r => ignore password change of %r',
                rdn_attr_type,
                self.source_id_attr,
                source_dn,
            )
            return None
        self.logger.debug('Extracted %s=%r from source_dn=%r', self.source_id_attr, uid, source_dn)
        target_conn = self.target_conn
        target_filter = self.target_filter_format.format(self.target_id_attr, uid)
        ldap_result = target_conn.search_ext_s(
            self._target_ldap_url.dn,
            self._target_ldap_url.scope or ldap.SCOPE_SUBTREE,
            target_filter,
            attrlist=['1.1'],
            sizelimit=8,
        )
        # strip LDAPv3 referrals received
        ldap_result = [
            (dn, entry)
            for dn, entry in ldap_result
            if dn is not None
        ]
        self.logger.debug('ldap_result=%r', ldap_result)
        if len(ldap_result) != 1:
            return None
        target_id = ldap_result[0][0]
        return target_id # end of PWSyncWorker.get_target_id()

    def encode_target_password(self, password):
        """
        encode argument password for target system
        """
        pwu = password.decode('utf-8')
        if self.target_password_attr.lower()=='unicodepwd':
            return unicode_pwd(pwu)
        else:
            return pwu.encode(self.target_password_encoding)

    def update_target_password(self, target_id, old_passwd, new_passwd, req_time):
        """
        write new password to target
        """
        target_conn = self.target_conn
        modlist = [(
            ldap.MOD_REPLACE,
            self.target_password_attr,
            [self.encode_target_password(new_passwd)],
        )]
        target_conn.modify_s(
            target_id,
            modlist,
        )
        return # end of PWSyncWorker.update_target_password()

    def run(self):
        """
        Thread runner function
        """
        while True:
            user_dn, val = self._queue.get()
            old_passwd, new_passwd, req_time = val
            self.logger.debug(
                'Received password change for %r (at %s)',
                user_dn,
                ldap_strf_secs(req_time),
            )
            try:
                sleep_time = max(
                    0,
                    time.time()-req_time+self.passwd_update_delay
                )
                self.logger.debug('Deferring syncing password for %r for %f secs', user_dn, sleep_time)
                time.sleep(sleep_time)
                if not self._check_password(user_dn, new_passwd):
                    # simply ignore wrong passwords
                    self.logger.warn('Ignoring wrong password for %r', user_dn)
                    continue
                target_id = self.get_target_id(user_dn)
                if target_id is None:
                    # simply ignore non-existent targets
                    self.logger.warn(
                        'No unique ID found with %r => ignore password change of %r',
                        target_filter,
                        source_dn,
                    )
                    continue
                self.logger.debug('Try to sync password for %r to %r', user_dn, target_id)
                self.update_target_password(target_id, old_passwd, new_passwd, req_time)
            except Exception:
                self.logger.error(
                    'Error syncing password for %r:\n',
                    user_dn,
                    exc_info=True,
                )
            else:
                self.logger.info('Synced password for %r to %r', user_dn, target_id)
            self._queue.task_done()
        # end of PWSyncWorker.run()


class PasswdModifyRequestValue(Sequence):
    """
    PasswdModifyRequestValue ::= SEQUENCE {
        userIdentity [0] OCTET STRING OPTIONAL
        oldPasswd [1] OCTET STRING OPTIONAL
        newPasswd [2] OCTET STRING OPTIONAL }
    """

    class UserIdentity(OctetString):
        """
        userIdentity [0] OCTET STRING OPTIONAL
        """
        tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))

    class OldPasswd(OctetString):
        """
        oldPasswd [1] OCTET STRING OPTIONAL
        """
        tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 1))

    class NewPasswd(OctetString):
        """
        newPasswd [2] OCTET STRING OPTIONAL
        """
        tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 2))

    componentType = NamedTypes(
        OptionalNamedType('userIdentity', UserIdentity()),
        OptionalNamedType('oldPasswd', OldPasswd('')),
        OptionalNamedType('newPasswd', NewPasswd('')),
    )


class PassModHandler(SlapdSockHandler):

    """
    Handler class which extracts new userPassword value
    from EXTENDED operation
    """

    def do_extended(self, request):
        """
        Handle EXTENDED operation
        """
        if request.oid != '1.3.6.1.4.1.4203.1.11.1':
            # ignore all other extended operations
            return 'CONTINUE'
        try:
            decoded_value, _ = pyasn1_decoder.decode(
                request.value,
                asn1Spec=PasswdModifyRequestValue(),
            )
            try:
                user_dn = str(decoded_value.getComponentByName('userIdentity'))
            except PyAsn1Error:
                user_dn = request.binddn
            self._log(
                logging.INFO,
                'Intercepted PASSMOD operation for %r',
                user_dn,
            )
            old_passwd = str(decoded_value.getComponentByName('oldPasswd')) or None
            new_passwd = str(decoded_value.getComponentByName('newPasswd')) or None
        except Exception, err:
            self._log(
                logging.ERROR,
                'Unhandled exception processing PASSMOD request: %r',
                err,
                exc_info=True
            )
        else:
            # push the password change into queue
            self.server.pwsync_queue.put((
                user_dn,
                (old_passwd, new_passwd, time.time()),
            ))
        return 'CONTINUE' # end of do_modify()


class PassModServer(SlapdSockThreadingServer):

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
            average_count,
            socket_timeout,
            socket_permissions,
            allowed_uids,
            allowed_gids,
            pwsync_queue,
            bind_and_activate=True,
            log_vars=None,
        ):
        self._ldap_conn = None
        self.pwsync_queue = pwsync_queue
        SlapdSockThreadingServer.__init__(
            self,
            server_address,
            RequestHandlerClass,
            combined_logger(
                self.__class__.__name__,
                LOG_LEVEL,
                sys_log_format=SYS_LOG_FORMAT,
                console_log_format=CONSOLE_LOG_FORMAT,
            ),
            average_count,
            socket_timeout,
            socket_permissions,
            allowed_uids,
            allowed_gids,
            bind_and_activate,
            monitor_dn=None,
            log_vars=log_vars,
        )


#-----------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------

def run_this():
    """
    The main script
    """

    script_name = os.path.abspath(sys.argv[0])
    pwsync_queue = DictQueue()

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
            '!!! Running in debug mode (log level %d)! '
            'Secret data will be logged! Don\'t do that!!!',
            my_logger.level
        )

    try:
        socket_path = sys.argv[1]
        local_ldap_uri = sys.argv[2]
        target_ldap_url = sys.argv[3]
    except IndexError:
        my_logger.error('Not enough arguments => abort')
        sys.exit(1)

    local_ldap_uri_obj = MyLDAPUrl(local_ldap_uri)
    target_ldap_url_obj = MyLDAPUrl(target_ldap_url)

    # initialize password sync consumer thread
    pwsync_worker = PWSyncWorker(
        target_ldap_url_obj,
        pwsync_queue,
    )
    pwsync_worker.ldapi_uri = local_ldap_uri_obj.initializeUrl()
    pwsync_worker.setDaemon(True)
    pwsync_worker.start()

    try:
        slapd_sock_listener = PassModServer(
            socket_path,
            PassModHandler,
            AVERAGE_COUNT,
            SOCKET_TIMEOUT, SOCKET_PERMISSIONS,
            ALLOWED_UIDS, ALLOWED_GIDS,
            pwsync_queue,
            log_vars=DEBUG_VARS,
        )
        slapd_sock_listener.ldapi_uri = local_ldap_uri_obj.initializeUrl()
        slapd_sock_listener.ldap_trace_level = PYLDAP_TRACELEVEL
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
