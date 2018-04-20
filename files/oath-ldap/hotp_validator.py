# -*- coding: utf-8 -*-
"""
slapd-sock listener demon which performs password checking and
HOTP validation on intercepted BIND requests
"""

from __future__ import absolute_import

__version__ = '0.10.1'
__author__ = u'Michael Ströder <michael@stroeder.com>'

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# from Python's standard lib
import os
import logging
import re
import sys
import json
import glob

# from cryptography
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.twofactor.hotp
import cryptography.hazmat.primitives.hashes

# passlib
import passlib.context

# from jwcrypto
try:
    from jwcrypto.jwk import JWK
    from jwcrypto.jwe import JWE
except ImportError:
    JWE = JWK = None

# from ldap0 package
import ldap0
from ldap0 import LDAPError
from ldap0.ldapurl import LDAPUrl
from ldap0.controls.simple import RelaxRulesControl
from ldap0.controls.libldap import AssertionControl

# local modules
from slapdsock.ldaphelper import ldap_datetime
from slapdsock.ldaphelper import is_expired
from slapdsock.loghelper import combined_logger
from slapdsock.handler import SlapdSockHandler, SlapdSockHandlerError
from slapdsock.message import \
    CONTINUE_RESPONSE, \
    InternalErrorResponse, \
    SuccessResponse, \
    InvalidCredentialsResponse, \
    CompareFalseResponse, \
    CompareTrueResponse


# run single-threaded
from slapdsock.service import SlapdSockServer
# run multi-threaded
#from slapdsock.service import SlapdSockThreadingServer as SlapdSockServer

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# Regex pattern for HOTP user DNs
# If bind-DN does not match this pattern, request will be continued by slapd
USER_DN_PATTERN = u'^uid=[a-z]+,cn=[a-z0-9]+,(cn|ou|o|dc)=.*ae-dir.*$'

# LDAP filter string for reading HOTP user entry
USER_FILTER = u'(&(objectClass=oathHOTPUser)(oathHOTPToken=*))'

# LDAP filter string for reading fully initialized HOTP token entry
OATH_TOKEN_FILTER = u'(&(objectClass=oathHOTPToken)(oathHOTPCounter>=0)(oathSecret=*))'
# Attribute for saving the last login timestamp
LOGIN_TIMESTAMP_ATTR = 'authTimestamp'

# Timestamp attributes which, if present, limit the
# validity period of user entries
USER_NOTBEFORE_ATTR = 'aeNotBefore'
#USER_NOTBEFORE_ATTR = None
USER_NOTAFTER_ATTR = 'aeNotAfter'
#USER_NOTAFTER_ATTR = None

# UIDs and peer GIDS of peers which are granted access
# (list of int/strings)
ALLOWED_UIDS = [0, 'ae-dir-slapd']
ALLOWED_GIDS = [0, 'ae-dir-slapd']

# String with octal representation of socket permissions
SOCKET_PERMISSIONS = '0666'

# Trace level for ldap0 logs
PYLDAP_TRACELEVEL = 0

# Number of times connecting to local LDAPI is retried before sending a
# failed response for a query
LDAP_MAXRETRYCOUNT = 10
# Time to wait before retrying to connect within one query
LDAP_RETRYDELAY = 0.1

# SASL authz-ID to be sent along with SASL/EXTERNAL bind
#LDAP_SASL_AUTHZID = 'dn:uid=hotp_validator,dc=example,dc=com'
LDAP_SASL_AUTHZID = None

# Time in seconds for which normal LDAP searches will be valid in cache
LDAP_CACHE_TTL = 3.0
# Time in seconds for which pwdPolicy and oathHOTPParams entries will be
# valid in cache
OATH_PARAMS_CACHE_TTL = 30 * LDAP_CACHE_TTL

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap0.OPT_NETWORK_TIMEOUT and ldap0.OPT_TIMEOUT
LDAP_TIMEOUT = 3.0

# Globbing pattern for searching JSON web key files (private keys)
# used for decrypting the shared secrets
# Setting this to None disables it and 'oathSecret'
# is always assumed to contain the raw shared secret bytes
JWK_KEY_FILES = '/opt/ae-dir/etc/oath-master-keys/*.priv'
#JWK_KEY_FILES = None

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

# Set to True to return more information about what went wrong
# in the response to the LDAP client
RESPONSE_INFO = __debug__

DEBUG_VARS = [
    'oath_hotp_current_counter',
    'oath_hotp_lookahead',
    'oath_hotp_next_counter',
    'oath_max_usage_count',
    'oath_otp_length',
    'oath_params_dn',
    'oath_params_entry',
    'oath_secret_max_age',
    'oath_token_dn',
    'oath_token_identifier',
    'oath_token_identifier_length',
    'oath_token_identifier_req',
    'oath_token_secret_time',
    'otp_compare',
    'otp_value',
    'user_password_compare',
    'user_password_length',
]
if __debug__:
    # Only some sensitive variables if DEBUG=yes and in Python debug mode
    DEBUG_VARS.extend([
        'otp_token_entry',
        'user_entry',
        #'user_password_clear',
        'user_password_hash',
    ])

# Error messages
if RESPONSE_INFO:
    class ResponseInfo(object):
        """
        message catalog with informative messages
        """
        HOTP_COUNTER_EXCEEDED = 'HOTP counter limit exceeded'
        OTP_TOKEN_EXPIRED = 'HOTP token expired'
        VERIFICATION_FAILED = (
            'user_password_compare={user_password_compare}'
            '/'
            'otp_compare={otp_compare}'
        )
        HOTP_WRONG_TOKEN_ID = 'wrong token identifier'
        ENTRY_NOT_VALID = 'not within validity period'
        OTP_TOKEN_ERROR = 'Error reading OTP token'
else:
    class ResponseInfo(object):
        """
        message catalog with no messages to avoid giving hints to attackers
        """
        HOTP_COUNTER_EXCEEDED = ''
        OTP_TOKEN_EXPIRED = ''
        VERIFICATION_FAILED = ''
        HOTP_WRONG_TOKEN_ID = ''
        ENTRY_NOT_VALID = ''
        OTP_TOKEN_ERROR = ''

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class HOTPValidationServer(SlapdSockServer):

    """
    This is used to pass in more parameters to the server instance.

    By purpose this is a single-threaded listener serializing all requests!
    """
    ldapi_authz_id = LDAP_SASL_AUTHZID
    ldap_retry_max = LDAP_MAXRETRYCOUNT
    ldap_retry_delay = LDAP_RETRYDELAY
    ldap_timeout = LDAP_TIMEOUT
    ldap_cache_ttl = LDAP_CACHE_TTL

    def __init__(
            self,
            server_address,
            RequestHandlerClass,
            logger,
            average_count,
            socket_timeout, socket_permissions,
            allowed_uids, allowed_gids,
            bind_and_activate=True,
            log_vars=None,
            key_files=None,
        ):
        SlapdSockServer.__init__(
            self,
            server_address,
            RequestHandlerClass,
            logger,
            average_count,
            socket_timeout, socket_permissions,
            allowed_uids, allowed_gids,
            bind_and_activate=bind_and_activate,
            monitor_dn=None,
            log_vars=log_vars,
        )
        self.max_lookahead_seen = 0
        if JWK:
            self._load_keys(key_files, reset=True)
        # end of HOTPValidationServer.__init__()

    def _load_keys(self, key_files, reset=False):
        """
        Load JWE keys defined by globbing pattern in :key_files:
        """
        if reset:
            self.master_keys = {}
        if not key_files:
            return
        self.logger.debug('Read JWK files with glob pattern %r', key_files)
        for private_key_filename in glob.glob(key_files):
            try:
                privkey_json = open(private_key_filename, 'rb').read()
                private_key = JWK(**json.loads(privkey_json))
            except (IOError, ValueError) as err:
                self.logger.error(
                    'Error reading/decoding JWK file %r: %s',
                    private_key_filename,
                    err,
                )
            else:
                self.master_keys[private_key.key_id] = private_key
        self.logger.info(
            'Read %d JWK files, key IDs: %s',
            len(self.master_keys),
            ' '.join(self.master_keys.keys()),
        )
        return # end of _load_keys()

    def monitor_entry(self):
        """
        Returns entry dictionary with monitoring data.
        """
        monitor_entry = SlapdSockServer.monitor_entry(self)
        monitor_entry.update({
            'sockHOTPMaxLookAheadSeen': [str(self.max_lookahead_seen)],
            'sockHOTPKeyCount': [str(len(self.master_keys))],
            'sockHOTPKeyIDs': self.master_keys.keys(),
        })
        return monitor_entry


class HOTPValidationHandler(SlapdSockHandler):

    """
    Handler class which validates user's password and HOTP value
    """
    infomsg = ResponseInfo
    cache_ttl = {
        'BIND': CACHE_TTL,
    }
    user_dn_regex = re.compile(USER_DN_PATTERN)
    user_filter = USER_FILTER
    token_filter = OATH_TOKEN_FILTER
    token_attr_list = [
        'createTimestamp',
        'oathHOTPCounter',
        'oathHOTPParams',
        'oathSecret',
        'oathSecretTime',
        'oathTokenIdentifier',
        'oathTokenSerialNumber',
        'oathFailureCount',
    ]
    not_before_attr = USER_NOTBEFORE_ATTR
    not_after_attr = USER_NOTAFTER_ATTR
    oath_params_cache_ttl = OATH_PARAMS_CACHE_TTL
    compare_assertion_type = 'oathHOTPValue'

    def _check_validity_period(
            self,
            entry,
            not_before_attr,
            not_after_attr,
        ):
        """
        Check validity period, returns True if within period, else False.
        """
        not_before = entry.get(not_before_attr, [None])[0]
        not_after = entry.get(not_after_attr, [None])[0]
        return \
            (not_before is None or ldap_datetime(not_before) <= self.now_dt) and \
            (not_after is None or ldap_datetime(not_after) >= self.now_dt)
        # end of _check_validity_period()

    def _update_token_entry(
            self,
            request,
            token_dn,
            success,
            oath_hotp_next_counter,
            otp_token_entry,
        ):
        """
        update OATH token entry
        """
        mod_ctrls = None
        if success:
            # Success case
            mods = [
                # Reset failure counter
                (ldap0.MOD_REPLACE, 'oathFailureCount', ['0']),
                # Store last login
                (ldap0.MOD_REPLACE, 'oathLastLogin', [str(self.now_str)]),
            ]
            # let slapd assert old value <= new value
        else:
            # Update failure counter and timestamp
            mods = [
                (
                    {
                        False: ldap0.MOD_ADD,
                        True: ldap0.MOD_INCREMENT,
                    }['oathFailureCount' in otp_token_entry],
                    'oathFailureCount',
                    ['1']
                ),
                (ldap0.MOD_REPLACE, 'oathLastFailure', [str(self.now_str)]),
            ]
        if oath_hotp_next_counter is not None:
            # Update HOTP counter value!
            mods.append(
                (ldap0.MOD_REPLACE, 'oathHOTPCounter', [str(oath_hotp_next_counter)]),
            )
            mod_ctrls = [
                AssertionControl(True, '(oathHOTPCounter<=%d)' % oath_hotp_next_counter),
            ]
        # Update the token entry
        try:
            self.ldap_conn.modify_s(
                token_dn,
                mods,
                serverctrls=mod_ctrls,
            )
        except LDAPError as err:
            # Return unwillingToPerform to let clients fail hard
            # so they hopefully not present login form again
            self._log(
                logging.ERROR,
                'LDAPError updating token entry %r with %r: %s => unwillingToPerform',
                token_dn,
                mods,
                err,
            )
            raise SlapdSockHandlerError(
                err,
                log_level=logging.ERROR,
                response=InternalErrorResponse(request.msgid),
                log_vars=self.server._log_vars,
            )
        else:
            self._log(
                logging.DEBUG,
                'Updated token entry %r with %r',
                token_dn,
                mods,
            )
        return # end of _update_token_entry()

    def _update_pwdfailuretime(self, user_dn, user_entry, success):
        """
        update user's entry after successful login
        """
        if not success:
            # record failed login
            mods = [(ldap0.MOD_ADD, 'pwdFailureTime', [str(self.now_str)])]
        elif 'pwdFailureTime' in user_entry:
            mods = [(ldap0.MOD_DELETE, 'pwdFailureTime', None)]
        else:
            # nothing to be done
            self._log(logging.DEBUG, 'No update of user entry %r', user_dn)
            return
        # Update the login attribute in user's entry
        try:
            self.ldap_conn.modify_s(
                user_dn.encode('utf-8'),
                mods,
                serverctrls=[RelaxRulesControl(True)],
            )
        except LDAPError as err:
            self._log(
                logging.ERROR,
                'Error updating user entry %r with %r: %s',
                user_dn,
                mods,
                err,
            )
        else:
            self._log(logging.DEBUG, 'Updated user entry %r with %r', user_dn, mods)
        return # end of _update_pwdfailuretime()

    def _check_userpassword(self, user_dn, user_entry, user_password_clear):
        """
        validate user's clear-text password against {CRYPT} password hash
        in attribute 'userPassword' of user's entry
        """
        try:
            # Strip scheme prefix {CRYPT} from password hash
            user_password_hash = user_entry['userPassword'][0][7:]
        except KeyError:
            self._log(
                logging.WARN,
                'No userPassword attribute found %r',
                user_dn,
            )
            result = False
        else:
            # Compare password with local hash in attribute userPassword
            pw_context = passlib.context.CryptContext(schemes=['sha512_crypt'])
            result = pw_context.verify(
                user_password_clear,
                user_password_hash
            )
        return result # _check_userpassword()

    def _get_user_entry(self, request, failure_response_class):
        """
        Read user entry
        """
        user_entry = response = None
        try:
            user_entry = self.ldap_conn.read_s(
                request.dn.encode('utf-8'),
                self.user_filter.encode('utf-8'),
                attrlist=filter(
                    None,
                    [
                        'oathHOTPToken',
                        'pwdFailureTime',
                        'userPassword',
                        self.not_before_attr,
                        self.not_after_attr,
                    ]
                )
            )
        except ldap0.NO_SUCH_OBJECT as err:
            self._log(
                logging.INFO,
                'Entry %r not found: %s => CONTINUE',
                request.dn,
                err,
            )
            response = CONTINUE_RESPONSE
        except LDAPError as err:
            self._log(
                logging.WARN,
                'Error reading %r: %s => %s',
                request.dn,
                err,
                failure_response_class.__name__,
            )
            response = failure_response_class(request.msgid)
        else:
            # Check whether entry was really received
            if not user_entry:
                self._log(
                    logging.INFO,
                    'No result reading %r with filter %r => CONTINUE',
                    request.dn,
                    self.user_filter,
                )
                response = CONTINUE_RESPONSE
            else:
                response = None
        assert (not user_entry and response) or (user_entry and not response), \
            ValueError('user_entry XOR response is violated!')
        return user_entry, response # end of _get_user_entry()

    def _get_oath_token_entry(self, user_dn, user_entry):
        """
        Read the OATH token entry
        """
        # Pointer to OATH token entry, default is user entry's DN
        try:
            oath_token_dn = user_entry['oathHOTPToken'][0]
        except KeyError:
            oath_token_dn = user_dn.encode('utf-8')
        # Try to read the token entry
        try:
            otp_token_entry = self.ldap_conn.read_s(
                oath_token_dn,
                self.token_filter.encode('utf-8'),
                attrlist=self.token_attr_list,
                cache_ttl=0, # caching disabled! (because of counter or similar)
            )
        except LDAPError as err:
            self._log(
                logging.ERROR,
                'Error reading token %r: %s',
                oath_token_dn,
                err,
            )
            otp_token_entry = None
        else:
            if not otp_token_entry:
                # No available token entry => invalidCredentials
                self._log(
                    logging.ERROR,
                    'Empty result reading token %r',
                    oath_token_dn,
                )
        return oath_token_dn, otp_token_entry # end of _get_oath_token_entry()

    def _get_oath_token_params(self, otp_token_entry):
        """
        Read OATH token parameters from referenced oathHOTPParams entry
        """
        oath_params_entry = {}
        if 'oathHOTPParams' in otp_token_entry:
            oath_params_dn = otp_token_entry['oathHOTPParams'][0]
            # Try to read the parameter entry
            try:
                oath_params_entry = self.ldap_conn.read_s(
                    oath_params_dn,
                    '(objectClass=oathHOTPParams)',
                    attrlist=[
                        'oathMaxUsageCount',
                        'oathHOTPLookAhead',
                        'oathOTPLength',
                        'oathSecretMaxAge',
                    ],
                    cache_ttl=self.oath_params_cache_ttl,
                )
            except LDAPError as err:
                self._log(
                    logging.ERROR,
                    'Error reading OATH params from %r: %s => use defaults',
                    oath_params_dn,
                    err,
                )
            else:
                oath_params_entry = oath_params_entry or {}
        # Attributes from referenced parameter entry
        if not oath_params_entry:
            self._log(logging.WARN, 'No OATH params! Using defaults.')
        oath_otp_length = int(oath_params_entry.get('oathOTPLength', ['6'])[0])
        oath_hotp_lookahead = int(oath_params_entry.get('oathHOTPLookAhead', ['5'])[0])
        oath_max_usage_count = int(oath_params_entry.get('oathMaxUsageCount', ['-1'])[0])
        oath_secret_max_age = oath_params_entry.get('oathSecretMaxAge', ['-1'])[0]
        return oath_otp_length, oath_hotp_lookahead, oath_max_usage_count, oath_secret_max_age
        # end of _get_oath_token_params()

    def _decrypt_oath_secret(self, oath_secret):
        """
        This methods extracts and decrypts the token's OATH shared
        secret from the token's LDAP entry given in argument
        :token_entry:
        """
        if not JWE or not self.server.master_keys:
            self._log(
                logging.DEBUG,
                'no JWK keys configured => return raw oathSecret value',
            )
            return oath_secret
        try:
            json_s = json.loads(oath_secret)
        except ValueError as err:
            self._log(
                logging.DEBUG,
                'error decoding JWE data: %s => return raw oathSecret value',
                err,
            )
            return oath_secret
        key_id = json_s['header']['kid']
        self._log(logging.DEBUG, 'JWE references key ID: %r', key_id)
        jwe_decrypter = JWE()
        try:
            oath_master_secret = self.server.master_keys[key_id]
        except KeyError:
            raise KeyError('OATH master key with key-id %r not found' % key_id)
        jwe_decrypter.deserialize(oath_secret, oath_master_secret)
        return jwe_decrypter.plaintext

    def _check_hotp(
            self,
            oath_secret,
            otp_value,
            counter,
            length=6,
            drift=0,
        ):
        """
        this function validates HOTP value
        """
        if drift < 0:
            raise ValueError('OATH counter drift must be >= 0, but was %d' % drift)
        otp_instance = cryptography.hazmat.primitives.twofactor.hotp.HOTP(
            self._decrypt_oath_secret(oath_secret),
            length,
            cryptography.hazmat.primitives.hashes.SHA1(),
            backend=cryptography.hazmat.backends.default_backend(),
        )
        result = None
        max_counter = counter + drift
        while counter <= max_counter:
            try:
                otp_instance.verify(otp_value, counter)
            except cryptography.hazmat.primitives.twofactor.hotp.InvalidToken:
                counter += 1
            else:
                result = counter + 1
                break
        return result # end of _check_hotp()

    def do_bind(self, request):
        """
        This method checks whether the request DN is a oathHOTPUser entry.
        If yes, userPassword and OATH/HOTP validation is performed.
        If no, CONTINUE is returned to let slapd handle the bind request.
        """

        # Preliminary request DN pattern check
        if not self.user_dn_regex.match(request.dn):
            self._log(
                logging.INFO,
                'Bind-DN %r does not match %r => CONTINUE',
                request.dn,
                self.user_dn_regex.pattern,
            )
            return CONTINUE_RESPONSE

        # Get LDAPObject instance for local LDAPI access
        self.ldap_conn = self.server.get_ldapi_conn()

        # Read user's entry
        user_entry, response = self._get_user_entry(request, InvalidCredentialsResponse)
        if user_entry is None:
            return response

        # Read OTP token entry
        oath_token_dn, otp_token_entry = self. _get_oath_token_entry(request.dn, user_entry)
        if not otp_token_entry:
            # we have to insist on existing/readable OTP token entry
            return InvalidCredentialsResponse(request.msgid, self.infomsg.OTP_TOKEN_ERROR)

        # Attributes from token entry
        oath_token_identifier = otp_token_entry.get('oathTokenIdentifier', [''])[0]
        oath_token_identifier_length = len(oath_token_identifier)
        oath_token_secret_time = otp_token_entry.get(
            'oathSecretTime',
            otp_token_entry.get(
                'createTimestamp',
                [None]
            )
        )[0]

        # Try to extract/decrypt OATH counter and secret
        try:
            oath_hotp_current_counter = int(otp_token_entry['oathHOTPCounter'][0])
            oath_secret = otp_token_entry['oathSecret'][0]
        except KeyError as err:
            self._log(
                logging.ERROR,
                'Missing OATH attributes in %r: %s => %s',
                oath_token_dn,
                err,
                InvalidCredentialsResponse.__name__,
            )
            return InvalidCredentialsResponse(request.msgid)

        oath_otp_length, oath_hotp_lookahead, oath_max_usage_count, oath_secret_max_age = \
            self._get_oath_token_params(otp_token_entry)

        #-------------------------------------------------------------------
        # from here on we don't exit with a return-statement
        # and set only a result if policy checks fail

        user_password_length = len(request.cred) - oath_otp_length - oath_token_identifier_length
        # Split simple bind password and OTP part
        user_password_clear, oath_token_identifier_req, otp_value = (
            request.cred[0:user_password_length],
            request.cred[user_password_length:-oath_otp_length],
            request.cred[-oath_otp_length:]
        )
        # check the password hash
        user_password_compare = self._check_userpassword(
            request.dn,
            user_entry,
            user_password_clear
        )

        # Check OTP value
        if not otp_value:
            oath_hotp_next_counter = None
            # An empty OTP value is always considered wrong here
            self._log(
                logging.WARN,
                'Empty OTP value sent for %r',
                request.dn,
            )
            # Do not(!) exit here because we need to update
            # failure attributes later
        else:
            oath_hotp_next_counter = self._check_hotp(
                oath_secret,
                otp_value,
                oath_hotp_current_counter,
                length=oath_otp_length,
                drift=oath_hotp_lookahead,
            )
            if oath_hotp_next_counter is not None:
                oath_hotp_drift = oath_hotp_next_counter - oath_hotp_current_counter
                self._log(
                    logging.DEBUG,
                    'OTP value valid (drift %d) for %r',
                    oath_hotp_drift,
                    oath_token_dn,
                )
                # Update largest drift seen
                self.server.max_lookahead_seen = max(
                    self.server.max_lookahead_seen,
                    oath_hotp_drift
                )
            else:
                self._log(
                    logging.DEBUG,
                    'OTP value invalid for %r',
                    oath_token_dn,
                )

        otp_compare = (oath_hotp_next_counter is not None)

        # updating counter in token entry has highest priority!
        # => do it now!
        self._update_token_entry(
            request,
            oath_token_dn,
            otp_compare and oath_token_identifier == oath_token_identifier_req,
            oath_hotp_next_counter,
            otp_token_entry,
        )

        # now do all the additional policy checks

        if not self._check_validity_period(
                user_entry,
                self.not_before_attr,
                self.not_after_attr,
            ):
            # fail because user account validity period violated
            self._log(
                logging.WARN,
                'Validity period of %r violated! => %s',
                request.dn,
                InvalidCredentialsResponse.__name__,
            )
            response = InvalidCredentialsResponse(request.msgid, self.infomsg.ENTRY_NOT_VALID)

        elif oath_token_identifier != oath_token_identifier_req:
            # fail because stored and requested token identifiers different
            self._log(
                logging.WARN,
                'Token ID mismatch! oath_token_identifier=%r / oath_token_identifier_req=%r => %s',
                oath_token_identifier,
                oath_token_identifier_req,
                InvalidCredentialsResponse.__name__,
            )
            response = InvalidCredentialsResponse(request.msgid, self.infomsg.HOTP_WRONG_TOKEN_ID)

        elif oath_max_usage_count >= 0 and \
           oath_hotp_current_counter > oath_max_usage_count:
            # fail because token counter exceeded
            self._log(
                logging.INFO,
                'counter limit %d exceeded for %r => %s',
                oath_max_usage_count,
                request.dn,
                InvalidCredentialsResponse.__name__,
            )
            response = InvalidCredentialsResponse(request.msgid, self.infomsg.HOTP_COUNTER_EXCEEDED)

        elif is_expired(oath_token_secret_time, oath_secret_max_age, self.now_dt):
            # fail because token's shared secret too old (is expired)
            self._log(
                logging.INFO,
                (
                    'Token %r of %r is expired '
                    '(oath_token_secret_time=%r, oath_secret_max_age=%r) => %s'
                ),
                oath_token_dn,
                request.dn,
                oath_token_secret_time,
                oath_secret_max_age,
                InvalidCredentialsResponse.__name__,
            )
            response = InvalidCredentialsResponse(request.msgid, self.infomsg.OTP_TOKEN_EXPIRED)

        elif not user_password_compare or not otp_compare:
            # user password or OTP value wrong
            self._log(
                logging.INFO,
                (
                    'Verification failed for %r (user_password_compare=%s / otp_compare=%s) => %s'
                ),
                request.dn,
                user_password_compare,
                otp_compare,
                InvalidCredentialsResponse.__name__,
            )
            response = InvalidCredentialsResponse(
                request.msgid,
                info=self.infomsg.VERIFICATION_FAILED.format(
                    user_password_compare=user_password_compare,
                    otp_compare=otp_compare,
                )
            )

        else:
            # Finally! Success!
            self._log(
                logging.INFO,
                'Validation ok for %r => response = success',
                request.dn,
            )
            response = SuccessResponse(request.msgid)

        self._update_pwdfailuretime(
            request.dn,
            user_entry,
            isinstance(response, SuccessResponse),
        )

        return response # end of HOTPValidationHandler.do_bind()

    def do_compare(self, request):
        """
        This method checks whether the request DN is a oathHOTPUser entry
        and whether assertion type is oathHOTPValue.
        If yes, OATH/HOTP validation is performed against assertion value.
        If no, CONTINUE is returned to let slapd handle the compare request.
        """

        if request.atype != self.compare_assertion_type:
            self._log(
                logging.DEBUG,
                'Assertion type %r does not match %r => CONTINUE',
                request.atype,
                self.compare_assertion_type,
            )
            return CONTINUE_RESPONSE

        # Preliminary request DN pattern check
        if not self.user_dn_regex.match(request.dn):
            self._log(
                logging.DEBUG,
                'Request DN %r does not match %r => CONTINUE',
                request.dn,
                self.user_dn_regex.pattern,
            )
            return CONTINUE_RESPONSE

        # Get LDAPObject instance for local LDAPI access
        self.ldap_conn = self.server.get_ldapi_conn()

        # Read user's entry
        user_entry, response = self._get_user_entry(request, InternalErrorResponse)
        if user_entry is None:
            return response

        # Read OTP token entry
        oath_token_dn, otp_token_entry = self. _get_oath_token_entry(request.dn, user_entry)
        if not otp_token_entry:
            # we have to insist on existing/readable OTP token entry
            return InvalidCredentialsResponse(request.msgid, self.infomsg.OTP_TOKEN_ERROR)

        # Attributes from token entry
        oath_token_identifier = otp_token_entry.get('oathTokenIdentifier', [''])[0]
        oath_token_secret_time = otp_token_entry.get(
            'oathSecretTime',
            otp_token_entry.get(
                'createTimestamp',
                [None]
            )
        )[0]

        # Try to extract/decrypt OATH counter and secret
        try:
            oath_hotp_current_counter = int(otp_token_entry['oathHOTPCounter'][0])
            oath_secret = otp_token_entry['oathSecret'][0]
        except KeyError as err:
            self._log(
                logging.ERROR,
                'Missing OATH attributes in %r: %s => %s',
                oath_token_dn,
                err,
                InvalidCredentialsResponse.__name__,
            )
            return InvalidCredentialsResponse(request.msgid)

        oath_otp_length, oath_hotp_lookahead, oath_max_usage_count, oath_secret_max_age = \
            self._get_oath_token_params(otp_token_entry)

        #-------------------------------------------------------------------
        # from here on we don't exit with a return-statement
        # and set only a result if policy checks fail

        oath_token_identifier_req, otp_value = (
            request.avalue[0:-oath_otp_length],
            request.avalue[-oath_otp_length:]
        )

        # Check OTP value
        if not otp_value:
            oath_hotp_next_counter = None
            # An empty OTP value is always considered wrong here
            self._log(
                logging.WARN,
                'Empty OTP value sent for %r',
                request.dn,
            )
            # Do not(!) exit here because we need to update
            # failure attributes later
        else:
            oath_hotp_next_counter = self._check_hotp(
                oath_secret,
                otp_value,
                oath_hotp_current_counter,
                length=oath_otp_length,
                drift=oath_hotp_lookahead,
            )
            if oath_hotp_next_counter is not None:
                oath_hotp_drift = oath_hotp_next_counter - oath_hotp_current_counter
                self._log(
                    logging.DEBUG,
                    'OTP value valid (drift %d) for %r',
                    oath_hotp_drift,
                    oath_token_dn,
                )
                # Update largest drift seen
                self.server.max_lookahead_seen = max(
                    self.server.max_lookahead_seen,
                    oath_hotp_drift
                )
            else:
                self._log(
                    logging.DEBUG,
                    'OTP value invalid for %r',
                    oath_token_dn,
                )

        otp_compare = (oath_hotp_next_counter is not None)

        # updating counter in token entry has highest priority!
        # => do it now!
        self._update_token_entry(
            request,
            oath_token_dn,
            otp_compare and oath_token_identifier == oath_token_identifier_req,
            oath_hotp_next_counter,
            otp_token_entry,
        )

        # now do all the additional policy checks

        if not self._check_validity_period(
                user_entry,
                self.not_before_attr,
                self.not_after_attr,
            ):
            # fail because user account validity period violated
            self._log(
                logging.WARN,
                'Validity period of %r violated! => %s',
                request.dn,
                InvalidCredentialsResponse.__name__,
            )
            response = CompareFalseResponse(request.msgid, self.infomsg.ENTRY_NOT_VALID)

        elif oath_token_identifier != oath_token_identifier_req:
            # fail because stored and requested token identifiers different
            self._log(
                logging.WARN,
                'Token ID mismatch! oath_token_identifier=%r / oath_token_identifier_req=%r => %s',
                oath_token_identifier,
                oath_token_identifier_req,
                InvalidCredentialsResponse.__name__,
            )
            response = CompareFalseResponse(request.msgid, self.infomsg.HOTP_WRONG_TOKEN_ID)

        elif oath_max_usage_count >= 0 and \
           oath_hotp_current_counter > oath_max_usage_count:
            # fail because token counter exceeded
            self._log(
                logging.INFO,
                'counter limit %d exceeded for %r => %s',
                oath_max_usage_count,
                request.dn,
                InvalidCredentialsResponse.__name__,
            )
            response = CompareFalseResponse(request.msgid, self.infomsg.HOTP_COUNTER_EXCEEDED)

        elif is_expired(oath_token_secret_time, oath_secret_max_age, self.now_dt):
            # fail because token's shared secret too old (is expired)
            self._log(
                logging.INFO,
                (
                    'Token %r of %r is expired '
                    '(oath_token_secret_time=%r, oath_secret_max_age=%r) => %s'
                ),
                oath_token_dn,
                request.dn,
                oath_token_secret_time,
                oath_secret_max_age,
                InvalidCredentialsResponse.__name__,
            )
            response = CompareFalseResponse(request.msgid, self.infomsg.OTP_TOKEN_EXPIRED)

        elif not otp_compare:
            # OTP value wrong
            self._log(
                logging.INFO,
                'HOTP verification failed for %r => %s',
                request.dn,
                InvalidCredentialsResponse.__name__,
            )
            response = CompareFalseResponse(request.msgid)

        else:
            # Finally! Success!
            self._log(
                logging.INFO,
                'Validation ok for %r => response = success',
                request.dn,
            )
            response = CompareTrueResponse(request.msgid)

        return response # end of HOTPValidationHandler.do_compare()


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
    if os.environ.get('DEBUG', 'no') == 'yes':
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
            (
                '!!! Running in debug mode (log level %d)! '
                'Secret data will be logged! Don\'t do that!!!'
            ),
            my_logger.level
        )

    try:
        socket_path = sys.argv[1]
        local_ldap_uri = sys.argv[2]
    except IndexError:
        my_logger.error('Not enough arguments => abort')
        sys.exit(1)

    local_ldap_uri_obj = LDAPUrl(local_ldap_uri)

    try:
        slapd_sock_listener = HOTPValidationServer(
            socket_path,
            HOTPValidationHandler,
            my_logger,
            AVERAGE_COUNT,
            SOCKET_TIMEOUT, SOCKET_PERMISSIONS,
            ALLOWED_UIDS, ALLOWED_GIDS,
            log_vars=DEBUG_VARS,
            key_files=JWK_KEY_FILES,
        )
        slapd_sock_listener.ldapi_uri = local_ldap_uri_obj.initializeUrl()
        slapd_sock_listener.ldap_trace_level = \
            int(local_ldap_uri_obj.trace_level or '0') or PYLDAP_TRACELEVEL
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

    return # run_this()


if __name__ == '__main__':
    run_this()
