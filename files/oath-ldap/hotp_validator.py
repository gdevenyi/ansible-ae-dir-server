#!/usr/bin/python -ROO
# -*- coding: utf-8 -*-
"""
slapd-sock listener demon which performs password checking and
HOTP validation on intercepted BIND requests
"""

import os, logging, re

__version__ = '0.5.4'
__author__ = u'Michael Ströder <michael@stroeder.com>'

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# Regex pattern for HOTP user DNs
# If bind-DN does not match this pattern, request will be continued by slapd
USER_DN_PATTERN = ur'^uid=[a-z]+,(|cn=[a-z0-9]+,)ou=ae-dir$'

# Filter template for reading HOTP user entry
USER_FILTER_TMPL = u'(&(objectClass=aeUser)(objectClass=oathHOTPUser)(oathHOTPToken=*))'

# Filter template for reading fully initialized HOTP token entry
OTP_TOKEN_FILTER_TMPL = u'(&(objectClass=oathHOTPToken)(oathHOTPCounter=*)(oathSecret=*))'
# Attribute for saving the last login timestamp
LOGIN_TIMESTAMP_ATTR = 'authTimestamp'

# Timestamp attributes which, if present, limit the
# validity period of user entries
USER_NOTBEFORE_ATTR = 'aeNotBefore'
USER_NOTAFTER_ATTR = 'aeNotAfter'

# UIDs and peer GIDS of peers which are granted access
# (list of int/strings)
ALLOWED_UIDS = [0, 'ldap', os.getuid()]
ALLOWED_GIDS = [0, 'ldap']

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
#LDAP_SASL_AUTHZID = 'dn:uid=hotp_validator,dc=example,dc=com'
LDAP_SASL_AUTHZID = None

# Time in seconds for which normal LDAP searches will be valid in cache
LDAP_CACHE_TTL = 5.0
# Time in seconds for which pwdPolicy and oathHOTPParams entries will be
# valid in cache
LDAP_LONG_CACHE_TTL = 20 * LDAP_CACHE_TTL

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap.OPT_NETWORK_TIMEOUT and ldap.OPT_TIMEOUT
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

DEBUG_VARS = [
    'oath_max_usage_count',
    'oath_hotp_current_counter',
    'oath_hotp_lookahead',
    'oath_hotp_next_counter',
    'oath_otp_length',
    'oath_secret_expired',
    'oath_secret_max_age',
    'oath_token_failure_count',
    'oath_token_identifier',
    'oath_token_identifier_length',
    'oath_token_identifier_req',
    'oath_token_secret_time',
    'otp_compare',
    'otp_compare1',
    'otp_compare2',
    'otp_format',
    'otp_params_dn',
    'otp_params_entry',
    'otp_token_dn',
    'otp_token_mods',
    'otp_value',
    'pwd_changed_time',
    'pwd_expired',
    'pwd_max_age',
    'pwd_policy_dn',
    'pwd_policy_subentry',
    'request_dn_utf8',
    'user_password_compare',
    'user_password_length',
]

# Error messages
if __debug__:
    MSG_HOTP_COUNTER_EXCEEDED = 'HOTP counter limit exceeded'
    MSG_HOTP_VALUE_WRONG = 'HOTP value wrong'
    MSG_OTP_TOKEN_EXPIRED = 'HOTP token expired'
    MSG_VERIFICATION_FAILED = 'user_password_compare={user_password_compare} / otp_compare={otp_compare}'
    # Only log credentials if DEBUG=yes and in Python debug mode
    DEBUG_VARS.extend([
        'oath_secret',
        'otp_token_entry',
        'user_entry',
        'user_password_clear',
        'user_password_hash',
    ])
else:
    MSG_HOTP_COUNTER_EXCEEDED = ''
    MSG_HOTP_VALUE_WRONG = ''
    MSG_OTP_TOKEN_EXPIRED = ''
    MSG_VERIFICATION_FAILED = ''

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# from Python's standard lib
import sys, datetime, json, glob

import oath

# passlib
import passlib.context

# from jwcrypto
try:
    from jwcrypto.jwk import JWK
    from jwcrypto.jwe import JWE
except ImportError:
    JWE = JWK = None

# python-ldap
import ldap
from ldap import LDAPError
from ldap.controls.simple import RelaxRulesControl
from ldap.controls.libldap import AssertionControl

# local modules
from slapdsock.ldaphelper import RESULT_CODE
from slapdsock.ldaphelper import ldap_datetime, ldap_datetime_str
from slapdsock.ldaphelper import MyLDAPUrl, is_expired
from slapdsock.loghelper import combined_logger
from slapdsock.handler import SlapdSockHandler
from slapdsock.message import RESULTResponse

# run single-threaded
from slapdsock.service import SlapdSockServer
# run multi-threaded
#from slapdsock.service import SlapdSockThreadingServer as SlapdSockServer

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


class HOTPValidationServer(SlapdSockServer):

    """
    This is used to pass in more parameters to the server instance.

    By purpose this is a single-threaded listener serializing all requests!
    """
    jwk_key_files = JWK_KEY_FILES
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
        self.max_lookahead_seen = 0
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
        if JWK:
            self._load_keys(self.jwk_key_files, reset=True)
        # end of HOTPValidationServer.__init__()

    def _load_keys(self, jwk_key_files, reset=False):
        """
        Load JWE keys defined by globbing pattern in :jwk_key_files:
        """
        if reset:
            self.master_keys = {}
        if not jwk_key_files:
            return
        for private_key_filename in glob.glob(jwk_key_files):
            privkey_json = open(private_key_filename, 'rb').read()
            private_key = JWK(**json.loads(privkey_json))
            self.master_keys[private_key.key_id] = private_key
        if self.master_keys:
            self.logger.info(
                'Read %d JWK files with pattern %r, key IDs: %r',
                len(self.master_keys),
                jwk_key_files,
                ' '.join(self.master_keys.keys()),
            )
        else:
            self.logger.error(
                'No JWK files found with pattern %r => expect failures!',
                jwk_key_files,
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

    cache_ttl = {
        'BIND': CACHE_TTL,
    }
    user_dn_regex = re.compile(USER_DN_PATTERN)
    user_filter_tmpl = USER_FILTER_TMPL
    token_filter_tmpl = OTP_TOKEN_FILTER_TMPL

    def _get_oath_secret(self, token_entry):
        """
        This methods extracts and decrypts the token's OATH shared
        secret from the token's LDAP entry given in argument
        :oath_token_entry:
        """
        oath_secret = token_entry['oathSecret'][0]
        if self.server.jwk_key_files is None:
            self._log(
                logging.DEBUG,
                'no JWK keys configured => return raw oathSecret value',
            )
            return oath_secret.encode('hex')
        try:
            json_s = json.loads(oath_secret)
        except ValueError, e:
            self._log(
                logging.DEBUG,
                'error decoding JWE data: %s => return raw oathSecret value',
                str(e),
            )
            return oath_secret.encode('hex')
        key_id = json_s['header']['kid']
        self._log(logging.DEBUG, 'JWE references key ID: %s', repr(key_id))
        jwe_decrypter = JWE()
        jwe_decrypter.deserialize(oath_secret, self.server.master_keys[key_id])
        return jwe_decrypter.plaintext.encode('hex')

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
                'Bind-DN %s does not match %s => let slapd continue',
                repr(request.dn),
                repr(self.user_dn_regex.pattern),
            )
            return 'CONTINUE\n'

        # We need current time in GeneralizedTime syntax later
        now_dt = datetime.datetime.utcnow()
        now_str = unicode(ldap_datetime_str(now_dt))

        # We need UTF-8 encoded DN several times later
        request_dn_utf8 = request.dn.encode('utf-8')

        # Get LDAPObject instance for local LDAPI access
        ldap_conn = self.server.get_ldapi_conn()

        user_attr_list = [
            'oathHOTPToken',
            'pwdChangedTime',
            'pwdFailureTime',
            'pwdPolicySubentry',
            'userPassword',
            USER_NOTBEFORE_ATTR,
            USER_NOTAFTER_ATTR,
        ]
        user_filterstr = self.user_filter_tmpl.format(now=now_str).encode('utf-8')
        # First try to read a user entry for the given request dn
        try:
            user_entry = ldap_conn.read_s(
                request_dn_utf8,
                user_filterstr,
                attrlist=user_attr_list,
            )
        except ldap.NO_SUCH_OBJECT, e:
            self._log(
                logging.INFO,
                'Exception %s.%s reading %s: %s => let slapd continue',
                e.__class__.__module__,
                e.__class__.__name__,
                repr(request.dn),
                str(e),
            )
            return 'CONTINUE\n'
        except LDAPError, e:
            ldap_result_code = 'invalidCredentials'
            self._log(
                logging.WARN,
                'Exception %s.%s reading %s: %s => return %s',
                e.__class__.__module__,
                e.__class__.__name__,
                repr(request.dn),
                str(e),
                ldap_result_code,
            )
            return RESULTResponse(
                request.msgid,
                ldap_result_code,
                info='',
            )

        # Check whether we want handle this
        if not user_entry:
            self._log(
                logging.INFO,
                'No result reading %s with filter %s => let slapd continue',
                repr(request_dn_utf8),
                repr(user_filterstr),
            )
            return 'CONTINUE\n'

        # Attributes from user entry
        pwd_changed_time = user_entry.get('pwdChangedTime', [None])[0]
        pwd_failure_times = user_entry.get('pwdFailureTime', [])
        pwd_policy_dn = user_entry['pwdPolicySubentry'][0]
        otp_token_dn = user_entry.get('oathHOTPToken', [request_dn_utf8])[0]
        # Check validity period
        user_not_before = user_entry.get(USER_NOTBEFORE_ATTR, [None])[0]
        user_not_after = user_entry.get(USER_NOTAFTER_ATTR, [None])[0]
        user_within_validity_period = \
            (user_not_before == None or ldap_datetime(user_not_before) <= now_dt) and \
            (user_not_after == None or ldap_datetime(user_not_after) >= now_dt)
        if not user_within_validity_period:
            ldap_result_code = 'invalidCredentials'
            self._log(
                logging.WARN,
                'User entry %s invalid (outside %s..%s) => return %s',
                repr(request.dn),
                repr(user_not_before),
                repr(user_not_after),
                ldap_result_code,
            )
            return RESULTResponse(
                request.msgid,
                ldap_result_code,
                info='',
            )

        # Try to read password policy subentry
        try:
            pwd_policy_subentry = ldap_conn.read_s(
                pwd_policy_dn,
                '(objectClass=pwdPolicy)',
                attrlist=[
                    'pwdAttribute',
                    'pwdFailureCountInterval',
                    'pwdMaxAge',
                    'pwdMaxFailure',
                ],
                cache_time=LDAP_LONG_CACHE_TTL,
            )
        except (LDAPError, KeyError), e:
            pwd_policy_subentry = {}

        pwd_max_age = pwd_policy_subentry.get('pwdMaxAge', ['-1'])[0]

        # Check whether OATH secret exceeds max age (is expired)
        pwd_expired = is_expired(
            pwd_changed_time,
            pwd_max_age,
            now_dt
        )
        if pwd_expired:
            self._log(
                logging.INFO,
                'Password of %s is expired (pwd_changed_time=%s, pwd_max_age=%s) => let slapd continue',
                repr(request.dn),
                repr(pwd_changed_time),
                repr(pwd_max_age),
            )
            return 'CONTINUE\n'

        # Try to read the token entry
        # (disable caching because of oathHOTPCounter)
        try:
            otp_token_entry = ldap_conn.read_s(
                otp_token_dn,
                self.token_filter_tmpl.format(now=now_str).encode('utf-8'),
                attrlist=[
                    'createTimestamp',
                    'oathHOTPCounter',
                    'oathHOTPParams',
                    'oathSecret',
                    'oathSecretTime',
                    'oathTokenIdentifier',
                    'oathTokenSerialNumber',
                    'oathFailureCount',
                ],
                nocache=1,
            )
        except LDAPError, e:
            ldap_result_code = 'invalidCredentials'
            self._log(
                logging.WARN,
                'Exception %s.%s reading token %s: %s => return %s',
                e.__class__.__module__,
                e.__class__.__name__,
                repr(otp_token_dn),
                str(e),
                ldap_result_code,
            )
            return RESULTResponse(
                request.msgid,
                ldap_result_code,
                info='',
            )

        if not otp_token_entry:
            # No available token entry => invalidCredentials
            ldap_result_code = 'invalidCredentials'
            self._log(
                logging.WARN,
                'No result reading token %s => return %s',
                repr(otp_token_dn),
                ldap_result_code,
            )
            return RESULTResponse(
                request.msgid,
                ldap_result_code,
                info='',
            )

        otp_params_dn = otp_token_entry['oathHOTPParams'][0]
        # Try to read the parameter entry
        try:
            otp_params_entry = ldap_conn.read_s(
                otp_params_dn,
                '(objectClass=oathHOTPParams)',
                attrlist=[
                    'oathMaxUsageCount',
                    'oathHOTPLookAhead',
                    'oathOTPLength',
                    'oathSecretMaxAge',
                ],
                cache_time=LDAP_LONG_CACHE_TTL,
            )
        except LDAPError, e:
            otp_params_entry = {}
        else:
            otp_params_entry = otp_params_entry or {}

        if not otp_params_entry:
            self._log(
                logging.WARN,
                'OATH params entry %s is empty!',
                repr(otp_params_dn)
            )

        # Attributes from password policy subentry
        # Attributes from token entry
        oath_hotp_current_counter = otp_token_entry.get('oathHOTPCounter', [None])[0]
        oath_secret = self._get_oath_secret(otp_token_entry)
        oath_token_identifier = otp_token_entry.get('oathTokenIdentifier', [''])[0]
        oath_token_identifier_length = len(oath_token_identifier)
        oath_token_failure_count = int(otp_token_entry.get('oathFailureCount', ['0'])[0])
        oath_token_secret_time = otp_token_entry.get(
            'oathSecretTime',
            otp_token_entry.get(
                'createTimestamp',
                [None]
            )
        )[0]
        # Attributes from referenced parameter entry
        oath_otp_length = int(otp_params_entry.get('oathOTPLength', ['6'])[0])
        oath_hotp_lookahead = int(otp_params_entry.get('oathHOTPLookAhead', ['5'])[0])
        oath_max_usage_count = int(otp_params_entry.get('oathMaxUsageCount', ['-1'])[0])
        oath_secret_max_age = otp_params_entry.get('oathSecretMaxAge', ['-1'])[0]

        # Check whether OATH secret exceeds max age (is expired)
        oath_secret_expired = is_expired(
            oath_token_secret_time,
            oath_secret_max_age,
            now_dt
        )

        user_password_length = len(request.cred) - oath_otp_length - oath_token_identifier_length
        # Split simple bind password and OTP part
        user_password_clear, oath_token_identifier_req, otp_value = (
            request.cred[0:user_password_length],
            request.cred[user_password_length:-oath_otp_length],
            request.cred[-oath_otp_length:]
        )

        try:
            # Strip scheme prefix {CRYPT} from password hash
            user_password_hash = user_entry['userPassword'][0][7:]
        except KeyError:
            self._log(
                logging.WARN,
                'No userPassword attribute found %s',
                repr(request.dn)
            )
            user_password_compare = False
        else:
            # Compare password with local hash in attribute userPassword
            pw_context = passlib.context.CryptContext(schemes=['sha512_crypt'])
            user_password_compare = pw_context.verify(
                user_password_clear,
                user_password_hash
            )

        otp_format = 'dec%d' % (oath_otp_length)

        # Check OTP value
        if not otp_value:
            # An empty OTP value is always considered wrong here
            otp_compare, oath_hotp_next_counter = (False, 0)
            self._log(
                logging.WARN,
                'Empty OTP value sent for %s',
                repr(request.dn)
            )
            # Do not(!) exit here because we need to update
            # failure attributes later
        else:
            otp_compare1, oath_hotp_next_counter = (
                oath_hotp_current_counter != None and
                oath.accept_hotp(
                    oath_secret,
                    otp_value,
                    int(oath_hotp_current_counter),
                    format=otp_format,
                    drift=oath_hotp_lookahead,
                    backward_drift=0,  # don't change this!!!
                )
            )
            otp_compare2 = (oath_token_identifier == oath_token_identifier_req)
            otp_compare = otp_compare1 and otp_compare2

        # Update largest drift seen
        if oath_hotp_current_counter != None:
            self.server.max_lookahead_seen = max(
                self.server.max_lookahead_seen,
                oath_hotp_next_counter - int(oath_hotp_current_counter)
            )

        otp_token_mods = []
        otp_token_mod_ctrls = []

        # In any case try to update counter
        # but let slapd assert old value <= new value
        if (oath_hotp_current_counter != None and
              int(oath_hotp_current_counter) < oath_hotp_next_counter
           ):
            otp_token_mods.append((ldap.MOD_REPLACE, 'oathHOTPCounter', [str(oath_hotp_next_counter)]))
            otp_token_mod_ctrls.append(
                AssertionControl(True, '(oathHOTPCounter<=%d)' % oath_hotp_next_counter)
            )

        # Update failure counter
        if otp_compare:
            # Reset failure counter
            otp_token_mods.extend([
                (ldap.MOD_REPLACE, 'oathFailureCount', ['0']),
                (ldap.MOD_REPLACE, 'oathLastLogin', [str(now_str)]),
            ])
        else:
            otp_token_mods.extend([
                # MOD_INCREMENT let slapd prior release 2.4.43 seg fault
                #(ldap.MOD_INCREMENT, 'oathFailureCount', ['1']),
                # work-around:
                # second best solution to increment 'oathFailureCount'
                (
                    ldap.MOD_REPLACE,
                    'oathFailureCount',
                    [str(oath_token_failure_count+1)]
                ),
                (ldap.MOD_REPLACE, 'oathLastFailure', [str(now_str)]),
            ])

        if otp_token_mods:

            # Modify the token entry
            try:
                ldap_conn.modify_ext_s(
                    otp_token_dn,
                    otp_token_mods,
                    serverctrls=otp_token_mod_ctrls,
                )
            except LDAPError, e:
                # Hard fail for OTP validation because otherwise OTP would be re-usable
                ldap_result_code = 'unwillingToPerform'
                self._log(
                    logging.ERROR,
                    'LDAPError updating token entry %s from %d to %d: %s => %s',
                    repr(otp_token_dn),
                    oath_hotp_current_counter,
                    oath_hotp_next_counter,
                    str(e),
                    ldap_result_code,
                )
                return RESULTResponse(
                    request.msgid,
                    ldap_result_code,
                    info='internal error'
                )

        if oath_max_usage_count >= 0 and \
           oath_hotp_current_counter > oath_max_usage_count:
            ldap_result_code = 'invalidCredentials'
            # Let slapd process the bind failure triggering slapo-ppolicy
            self._log(
                logging.INFO,
                'counter limit %d exceeded for %s => %s',
                oath_max_usage_count,
                repr(request.dn),
                ldap_result_code,
            )
            return RESULTResponse(
                request.msgid,
                ldap_result_code,
                info=MSG_HOTP_COUNTER_EXCEEDED
            )

        elif oath_secret_expired:
            ldap_result_code = 'invalidCredentials'
            self._log(
                logging.INFO,
                'Token %s of %s is expired (oath_token_secret_time=%s, oath_secret_max_age=%s) => %s',
                repr(otp_token_dn),
                repr(request.dn),
                repr(oath_token_secret_time),
                repr(oath_secret_max_age),
                ldap_result_code,
            )
            return RESULTResponse(
                request.msgid,
                ldap_result_code,
                info=MSG_OTP_TOKEN_EXPIRED
            )

        elif user_password_compare and otp_compare:
            # Prepare the sucess result returned
            ldap_result_code = RESULT_CODE['success']
            self._log(
                logging.INFO,
                'Validation ok for %s => return success(%d)',
                repr(request.dn),
                ldap_result_code,
            )
            user_mods_successful = [
                (ldap.MOD_REPLACE, LOGIN_TIMESTAMP_ATTR, [str(now_str)]),
            ]
            if pwd_failure_times:
                user_mods_successful.append(
                    (ldap.MOD_DELETE, 'pwdFailureTime', None),
                )
            # Update the login timestamp attribute
            try:
                ldap_conn.modify_ext_s(
                    request_dn_utf8,
                    user_mods_successful,
                    serverctrls=[RelaxRulesControl(True)],
                )
            except LDAPError, e:
                self._log(
                    logging.WARN,
                    'LDAPError updating user entry %s with %s: %s',
                    repr(request.dn),
                    repr(user_mods_successful),
                    str(e),
                )
            return RESULTResponse(request.msgid, 'success')

        else:
            ldap_result_code = RESULT_CODE['invalidCredentials']
            ldap_diagnostic_message = MSG_VERIFICATION_FAILED.format(
                user_password_compare=user_password_compare,
                otp_compare=otp_compare,
            )
            self._log(
                logging.INFO,
                'Verification failed for %s (user_password_compare=%s / otp_compare=%s) => invalidCredentials(%d)',
                repr(request.dn),
                user_password_compare,
                otp_compare,
                ldap_result_code,
            )
            # Update the login timestamp attribute
            try:
                ldap_conn.modify_ext_s(
                    request_dn_utf8,
                    [(ldap.MOD_ADD, 'pwdFailureTime', [str(now_str)])],
                    serverctrls=[RelaxRulesControl(True)],
                )
            except LDAPError, e:
                self._log(
                    logging.ERROR,
                    'LDAPError updating pwdFailureTime in user entry %s: %s',
                    repr(request.dn),
                    str(e),
                )
            return RESULTResponse(
                request.msgid,
                ldap_result_code,
                info=ldap_diagnostic_message,
            )

        # end of HOTPValidationHandler.do_bind()


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
            '!!! Running in debug mode (log level %d)! Secret data will be logged! Don\'t do that!!!',
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
        slapd_sock_listener = HOTPValidationServer(
            socket_path,
            HOTPValidationHandler,
            my_logger,
            AVERAGE_COUNT,
            SOCKET_TIMEOUT, SOCKET_PERMISSIONS,
            ALLOWED_UIDS, ALLOWED_GIDS,
            log_vars=DEBUG_VARS,
        )
        slapd_sock_listener.ldapi_uri = local_ldap_uri_obj.initializeUrl()
        slapd_sock_listener.ldap_trace_level = int(local_ldap_uri_obj.trace_level or '0') or PYLDAP_TRACELEVEL
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
