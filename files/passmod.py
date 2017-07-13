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
import datetime
import logging
import os
import sys

# passlib
import passlib.context

# from jwcrypto
#from jwcrypto.jwk import JWK
#from jwcrypto.jwe import JWE

# python-ldap
import ldap
from ldap import LDAPError
from ldap.controls.simple import ProxyAuthzControl

# local modules
from slapdsock.ldaphelper import ldap_datetime
from slapdsock.ldaphelper import MyLDAPUrl
from slapdsock.loghelper import combined_logger
from slapdsock.handler import SlapdSockHandler, SlapdSockHandlerError
from slapdsock.message import RESULTResponse

# run multi-threaded
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
SYS_LOG_FORMAT = '%(levelname)s %(message)s'
CONSOLE_LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'

# Base number for floating average value of response delay
AVERAGE_COUNT = 100

# Default log level to use
LOG_LEVEL = int(os.environ.get('LOG_LEVEL', logging.DEBUG))

# Time (seconds) for assuming an userPassword+OTP value to be valid in cache
CACHE_TTL = -1.0

DEBUG_VARS = [
    'pwd_changed_time',
    'pwd_policy_subentry_dn',
    'pwd_policy_subentry',
    'user_class',
    'user_entry',
]

# Error messages
if __debug__:
    DEBUG_VARS.extend([
        'new_passwd',
        'user_password_hash',
    ])

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


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
        SlapdSockThreadingServer.__init__(
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


class PassModHandler(SlapdSockHandler):

    """
    Handler class which proxies some simple bind requests to remote server
    """

    def _read_user_entry(self, request):
        # Try to read the user entry for the given request dn
        try:
            try:
                local_ldap_conn = self.server.get_ldapi_conn()
                ldap_result = local_ldap_conn.search_s(
                    request.dn.encode('utf-8'),
                    ldap.SCOPE_BASE,
                    '(objectClass=*)',
                    attrlist=[
                        'objectClass',
                        'structuralObjectClass',
                        'pwdChangedTime',
                        'pwdPolicySubentry',
                        'uid',
                        'uidNumber',
                        'userPassword',
                    ],
                )
            except ldap.SERVER_DOWN, ldap_error:
                self.server.disable_ldapi_conn()
                raise ldap_error
        except LDAPError, ldap_error:
            raise SlapdSockHandlerError(
                ldap_error,
                log_level=logging.WARN,
                response=RESULTResponse(request.msgid, ldap_error),
                log_vars=self.server._log_vars,
            )
        return ldap_result[0][1] # _read_user_entry()

    def _compare_old_pwd(self, user_entry, new_passwd):
        try:
            user_password_hash = user_entry['userPassword'][0]
        except KeyError:
            self._log(logging.DEBUG, 'no old password hash to check')
            return False
        pw_context = passlib.context.CryptContext(schemes=['sha512_crypt'])
        self._log(logging.DEBUG, 'will check old password hash')
        try:
            return pw_context.verify(new_passwd, user_password_hash[7:])
        except ValueError:
            return False

    def _get_new_passwd(self, request):
        """
        Try to extract userPassword from request
        """
        for mod_op, mod_type, mod_vals in request.modops:
            if mod_op in (ldap.MOD_REPLACE, ldap.MOD_ADD) and \
               (mod_type.lower() == 'userpassword' or mod_type == '2.5.4.35'):
                if len(set(mod_vals)) != 1:
                    raise SlapdSockHandlerError(
                        '%d != 1 different userPassword values in %s for %r' % (
                            len(set(mod_vals)),
                            request.__class__.__name__,
                            request.dn,
                        ),
                        log_level=logging.ERROR,
                        response=RESULTResponse(
                            request.msgid,
                            'constraintViolation',
                            info='Multiple password values not allowed!',
                        ),
                        log_vars=self.server._log_vars,
                    )
                new_passwd = mod_vals[0]
                if new_passwd.startswith(PWD_SCHEME):
                    raise SlapdSockHandlerError(
                        'userPassword value already begins with %r' % PWD_SCHEME,
                        log_level=logging.DEBUG,
                        response='CONTINUE\n',
                        log_vars=self.server._log_vars,
                    )
                pw_context = passlib.context.CryptContext(schemes=[PWD_CRYPT_SCHEME])
                # save hashed password into request
                mod_vals[0] = '{0}{1}'.format(
                    PWD_SCHEME,
                    pw_context.hash(new_passwd, **PWD_CRYPT_SCHEME_ARGS),
                )
                return new_passwd
        # nothing to do because there's no userPassword attribute in request
        raise SlapdSockHandlerError(
            'No userPassword value in %s for %r' % (
                request.__class__.__name__,
                request.dn,
            ),
            log_level=logging.DEBUG,
            response='CONTINUE\n',
            log_vars=self.server._log_vars,
        )
        # end of _get_new_passwd()

    def _check_pwd_policy(self, request, new_passwd_len, pwd_policy_subentry_dn, pwd_changed_time):
        if pwd_policy_subentry_dn is None:
            self._log(logging.DEBUG, 'no password policy to check')
            return
        # Try to determine password policy
        pwd_min_age = PWD_MIN_AGE
        pwd_min_length = PWD_MIN_LENGTH
        try:
            try:
                local_ldap_conn = self.server.get_ldapi_conn()
                pwd_policy_subentry = local_ldap_conn.read_s(
                    pwd_policy_subentry_dn,
                    '(objectClass=pwdPolicy)',
                    attrlist=[
                        'pwdMinAge',
                        'pwdMinLength',
                    ],
                    cache_time=LDAP_LONG_CACHE_TTL,
                )
            except ldap.SERVER_DOWN, ldap_error:
                self.server.disable_ldapi_conn()
                raise ldap_error
        except LDAPError, ldap_error:
            raise SlapdSockHandlerError(
                ldap_error,
                log_level=logging.WARN,
                response=RESULTResponse(request.msgid, ldap_error),
                log_vars=self.server._log_vars,
            )
        else:
            pwd_min_age = int(pwd_policy_subentry.get('pwdMinAge', [PWD_MIN_AGE])[0])
            pwd_min_length = int(pwd_policy_subentry.get('pwdMinLength', [PWD_MIN_LENGTH])[0])
        # Check if minimum password length is ok
        if new_passwd_len < pwd_min_length:
            raise SlapdSockHandlerError(
                'Password for %r too short!' % (request.dn),
                log_level=logging.INFO,
                response=RESULTResponse(
                    request.msgid,
                    'constraintViolation',
                    info='Password too short! Required minimum length is %d.' % (
                        pwd_min_length
                    ),
                ),
                log_vars=self.server._log_vars,
            )
        # Check if next password change is already allowed
        if pwd_changed_time is not None and \
           (datetime.datetime.utcnow()-ldap_datetime(pwd_changed_time)).total_seconds < pwd_min_age:
            raise SlapdSockHandlerError(
                'Password of %r too young to change!' % (request.dn),
                log_level=logging.INFO,
                response=RESULTResponse(
                    request.msgid,
                    'constraintViolation',
                    info='Password too young to change!',
                ),
                log_vars=self.server._log_vars,
            )
        return # end of _check_pwd_policy()

    def _export_password(self, request, user_entry, password):
        """
        write reversible encrypted new password to sync queue
        """
        try:
            # all export actions which could fail goes here
            _ = user_entry
            self._log(logging.ERROR, 'Exported password: %r', password)
        except Exception, err:
            raise SlapdSockHandlerError(
                'Error exporting password of %r: %s' % (request.dn, err),
                log_level=logging.ERROR,
                response=RESULTResponse(
                    request.msgid,
                    'operationsError',
                    info='export error',
                ),
                log_vars=self.server._log_vars,
            )
        else:
            self._log(logging.INFO, 'Exported password of %r', request.dn)
        return # end of _export_password()

    def _update_user_entry(self, request):
        """
        write modifications of request to LDAP entry
        """
        try:
            local_ldap_conn = self.server.get_ldapi_conn()
            local_ldap_conn.modify_ext_s(
                request.dn.encode('utf-8'),
                request.modops,
                serverctrls=[
                    ProxyAuthzControl(
                        True,
                        'dn:{0}'.format(request.binddn.encode('utf-8')),
                    ),
                ],
            )
        except ldap.LDAPError, ldap_error:
            raise SlapdSockHandlerError(
                'LDAPError modifying entry %r: %s' % (request.dn, ldap_error),
                log_level=logging.ERROR,
                response=RESULTResponse(request.msgid, ldap_error),
                log_vars=self.server._log_vars,
            )
        else:
            self._log(
                logging.INFO,
                'Successfully modified userPassword for %r (from %r)',
                request.dn,
                request.peername,
            )
        return # end of _update_user_entry()

    def do_modify(self, request):
        """
        Handle MODIFY operation
        """
        new_passwd = self._get_new_passwd(request)
        user_entry = self._read_user_entry(request)
        self._log(logging.DEBUG, 'user entry attributes: %r', user_entry.keys())
        # Attributes from user entry
        #user_class = user_entry.get('structuralObjectClass', [None])[0]
        if self._compare_old_pwd(user_entry, new_passwd):
            # setting old password again triggers export once more
            self._log(logging.INFO, 'user entry already has password => re-export and return success')
            self._export_password(request, user_entry, new_passwd)
            return RESULTResponse(request.msgid, 'success')
        pwd_changed_time = user_entry.get('pwdChangedTime', [None])[0]
        pwd_policy_subentry_dn = user_entry.get(
            'pwdPolicySubentry',
            [PWD_POLICY_SUBENTRY_DEFAULT]
        )[0]
        self._check_pwd_policy(
            request,
            len(new_passwd),
            pwd_policy_subentry_dn,
            pwd_changed_time
        )
        self._update_user_entry(request)
        self._export_password(request, user_entry, new_passwd)
        return RESULTResponse(request.msgid, 'success') # end of do_modify()


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
            '!!! Running in debug mode (log level %d)! '
            'Secret data will be logged! Don\'t do that!!!',
            my_logger.level
        )

    try:
        socket_path = sys.argv[1]
        local_ldap_uri = sys.argv[2]
    except IndexError:
        my_logger.error('Not enough arguments => abort')
        sys.exit(1)

    local_ldap_uri_obj = MyLDAPUrl(local_ldap_uri)

    try:
        slapd_sock_listener = PassModServer(
            socket_path,
            PassModHandler,
            my_logger,
            AVERAGE_COUNT,
            SOCKET_TIMEOUT, SOCKET_PERMISSIONS,
            ALLOWED_UIDS, ALLOWED_GIDS,
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
