#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Web-interface for resetting/changing user passwords in a LDAP server

Author: Michael Ströder <michael@stroeder.com>

Tested with:
Python 2.7+ (see https://www.python.org/)
web.py 0.37+ (see http://webpy.org/)
python-ldap 2.4.22+ (see https://www.python-ldap.org/)
"""

__version__ = '0.1.1'

# from Python's standard lib
import sys
import os
import time
import socket
import smtplib
import hashlib
import random
import logging
from urllib import quote_plus as url_quote_plus
import email.utils

# web.py
import web

# from python-ldap
import ldap
import ldap.dn
import ldap.filter
import ldap.sasl
import ldapurl
from ldap import LDAPError
from ldap.controls.sessiontrack import SessionTrackingControl, SESSION_TRACKING_FORMAT_OID_USERNAME

# from mailutil
import mailutil

# Import constants from configuration module
sys.path.append(sys.argv[2])
from oathenroll_cnf import *

#---------------------------------------------------------------------------
# constants
#---------------------------------------------------------------------------

# Mapping of request URL path to Python handler class
URL2CLASS_MAPPING = (
  '/','Default',
#  '/register', 'RegisterToken',
  '/reset', 'ResetToken',
)

#---------------------------------------------------------------------------
# basic functions and classes
#---------------------------------------------------------------------------

class ExtLDAPUrl(ldapurl.LDAPUrl):
    """
    Special class for handling additional LDAP URL extensions
    """
    attr2extype = {
        'who': 'bindname',
        'cred': 'X-BINDPW',
        'start_tls': 'startTLS',
        'trace_level': 'trace',
    }


PWD_BYTES_ALPHABET = ''.join([
    chr(i)
    for i in range(0, 256)
])

def random_string(length, alphabet=PWD_BYTES_ALPHABET):
    """
    Create a random random string of given length.

    :length:
        Requested length of random string.
    :alphabet:
        If non-zero this string is assumed to contain all valid chars for
        the generated string. If zero-length or None the result is an
        arbitrary octet string.
    """
    sys_rand = random.SystemRandom()
    chars_bounce = len(alphabet)-1
    return ''.join([
        alphabet[sys_rand.randint(0, chars_bounce)]
        for i in range(length)
    ])


#---------------------------------------------------------------------------
# The web application classes
#---------------------------------------------------------------------------

# Safety check for URL chars
if PWD_TMP_CHARS != url_quote_plus(PWD_TMP_CHARS):
    raise ValueError('URL special chars in PWD_TMP_CHARS: %s' % repr(PWD_TMP_CHARS))

# Set some webpy configuration vars
if WEB_CONFIG_DEBUG is False:
    web.config.debug = False

# Initialize template rendering with layout information
RENDER = web.template.render(TEMPLATES_DIRNAME, base=LAYOUT)

# Declaration for text input field for 'username'
ADMIN_FIELD = web.form.Textbox(
    'admin',
    web.form.notnull,
    web.form.regexp('^[a-zA-Z]+$', u'Invalid 2FA admin user name.'),
    description=u'2FA admin user name'
)

# Declaration for text input field for old password
PASSWORD_FIELD = web.form.Password(
    'password',
    web.form.notnull,
    web.form.regexp(r'^.+$', u'Invalid password'),
    description=u'2FA admin password'
)

# Declaration for text input field for 'email'
SERIAL_FIELD = web.form.Textbox(
    'serial',
    web.form.notnull,
    web.form.regexp(r'^[0-9]+$', u'Invalid token serial number'),
    description=u'E-mail address'
)

# Declaration for text input field for 'confirm' (hex-encoded hash)
CONFIRM_FIELD = web.form.Textbox(
    'confirm',
    web.form.regexp(r'^[0-9a-fA-F]*$', u'Invalid confirmation hash'),
    description=u'Confirmation hash'
)

class Default(object):
    """
    Handle requests to base URL
    """

    def __init__(self, *args, **kwargs):
        # Set additional headers in response
        self.remote_ip = web.ctx.env.get(
            'FORWARDED_FOR',
            web.ctx.env.get('HTTP_X_FORWARDED_FOR', web.ctx.ip)
        )
        self._add_headers()
        self.ldap_conn = None
        self.user_ldap_conn = None

    def _add_headers(self):
        """
        Add more HTTP headers to response
        """
        csp_value = ';'.join((
            "default-src 'self'",
            "script-src 'none'",
        ))
        for header, value in (
                ('Cache-Control', 'no-store,no-cache,max-age=0,must-revalidate'),
                ('X-XSS-Protection', '1; mode=block'),
                ('X-DNS-Prefetch-Control', 'off'),
                ('X-Content-Type-Options', 'nosniff'),
                ('X-Frame-Options', 'deny'),
                ('Server', 'unknown'),
                ('Content-Security-Policy', csp_value),
                ('X-Webkit-CSP', csp_value),
                ('X-Content-Security-Policy', csp_value),
        ):
            web.header(header, value)
        return # end of Default._add_headers()

    def GET(self, message=u''):
        """
        Simply display the entry landing page
        """
        return RENDER.default()


class BaseApp(Default):
    """
    Request handler base class which is not used directly
    """

    def ldap_connect(self, ldap_url, authz_id=None):
        """
        Connect and bind to the LDAP directory as local system account
        """
        self.ldap_url = ExtLDAPUrl(ldap_url)
        self.ldap_conn = ldap.initialize(
            self.ldap_url.initializeUrl(),
            trace_level=PYLDAP_TRACELEVEL,
            trace_file=sys.stderr,
        )
        # Send SASL bind request with mechanism EXTERNAL
        self.ldap_conn.sasl_external_bind_s(authz_id=authz_id)
        return # end of ldap_connect()

    def check_login(self, username, password):
        """
        Search a user entry specified by :username: and check
        :password: with LDAP simple bind.
        """
        if not password:
            # empty password is always wrong!
            return False
        try: # finally-block
            login_conn = None
            try:
                user_dn, _ = self.ldap_conn.find_unique_entry(
                    self.ldap_url.dn,
                    scope=self.ldap_url.scope,
                    filterstr=FILTERSTR_ADMIN_LOGIN.format(
                        uid=username.encode('utf-8'),
                    ),
                    attrlist=['1.1'],
                )
                self.user_ldap_conn = ldap.initialize(
                    self.ldap_url.initializeUrl(),
                    trace_level=PYLDAP_TRACELEVEL,
                    trace_file=sys.stderr,
                )
                self.user_ldap_conn.simple_bind_s(user_dn, password.encode('utf-8'))
            except LDAPError:
                self.user_uid = u''
                self.user_dn = u''
                result = self.login_ok = False
            else:
                self.user_uid = username
                self.user_dn = user_dn.decode('utf-8')
                result = self.login_ok = True
        finally:
            # Anyway we should try to close the LDAP connection
            try:
                if login_conn:
                    login_conn.unbind_s()
            except (AttributeError, LDAPError):
                pass
        return result # end of BaseApp.login()

    def search_token(self, token_serial):
        """
        Search a token entry specified by serial number
        """
        token_dn, token_entry = self.user_ldap_conn.find_unique_entry(
            self.ldap_url.dn,
            scope=self.ldap_url.scope,
            filterstr=FILTERSTR_TOKEN_SEARCH.format(
                owner_attr=ATTR_OWNER_DN,
                serial=token_serial.encode('utf-8'),
            ),
            attrlist=[
                'createTimestamp',
                'displayName',
                'oathFailureCount',
                'oathHOTPCounter',
                'oathHOTPParams',
                'oathLastFailure',
                'oathLastLogin',
                'oathSecretTime',
                'oathTokenIdentifier',
                'oathTokenSerialNumber',
                ATTR_OWNER_DN,
            ],
        )
        token_displayname = token_entry['displayName'][0].decode('utf-8')
        return token_displayname, token_dn, token_entry
        # endof BaseApp.search_token()

    def clean_up(self):
        """
        Clean up initialized stuff
        """
        for conn in (self.ldap_conn, self.user_ldap_conn):
            if conn:
                try:
                    self.ldap_conn.unbind_s()
                except (AttributeError, LDAPError):
                    pass
        return # end of BaseApp.clean_up()

    def POST(self):
        """
        Process a POST request likely resulting in some write access

        In this wrapper method only form is validated and LDAP connection
        is opened. Afterwards self.do_the_work() is called which does the
        real use-case specific work.
        """
        # Parse and validate the form input
        self.form = self.post_form()
        if not self.form.validates():
            return self.GET(message=u'Incomplete or invalid input!')
        # Make connection to LDAP server
        try:
            self.ldap_connect(LDAP_URL, authz_id=LDAPI_AUTHZ_ID)
        except ldap.SERVER_DOWN:
            return self.GET(message=u'LDAP server not reachable!')
        except LDAPError:
            return self.GET(message=u'Internal LDAP error!')
        # Check the login
        if not self.check_login(self.form.d.admin, self.form.d.password):
            return self.GET(message=u'Admin login failed!')
        # Do the real work
        try:
            res = self.do_the_work()
        except Exception as err:
            logging.error('Unhandled exception: %s', repr(err), exc_info=True)
            res = self.GET(message=u'Internal error!')
        self.clean_up()
        return res # end of BaseApp.POST()


class ResetToken(BaseApp):
    """
    Resets token to unusable state but with temporary enrollment password.

    LDAP operations are authenticated with LDAPI/SASL/EXTERNAL
    """

    # Declaration for the change password input form
    post_form = web.form.Form(
        ADMIN_FIELD,
        PASSWORD_FIELD,
        SERIAL_FIELD,
        CONFIRM_FIELD,
        web.form.Button(
            'submit',
            type='submit',
            description=u'Reset token'
        ),
    )

    def GET(self, message=u''):
        """
        Process the GET request mainly for displaying input form
        """
        try:
            get_input = web.input(
                serial=u'',
                admin=u'',
                password=u'',
            )
        except UnicodeError:
            return RENDER.reset_form(u'Invalid Unicode input')
        else:
            if not get_input.serial:
                message = u'Enter a serial number of token to be (re-)initialized.'
            elif not get_input.admin:
                message = u'Login with your 2FA admin account.'
            return RENDER.reset_form(
                message,
                admin=get_input.admin,
                serial=get_input.serial,
            )

    def _send_pw(self, token_serial, owner_entry, enroll_pw1):
        """
        Send 2nd part of temporary password to token owner
        """

        # Open connection to SMTP relay
        #---------------------------------------------------------------
        smtp_conn = mailutil.smtp_connection(
            SMTP_URL,
            local_hostname=SMTP_LOCALHOSTNAME,
            tls_args=SMTP_TLSARGS,
            debug_level=SMTP_DEBUGLEVEL
        )

        # Construct the message
        #---------------------------------------------------------------
        smtp_message_tmpl = open(EMAIL_TEMPLATE, 'rb').read().decode('utf-8')
        to_addr = owner_entry['mail']
        default_headers = (
            ('From', SMTP_FROM),
            ('Date', email.utils.formatdate(time.time(), True)),
        )
        owner_data = {
            'serial': token_serial,
            'admin': self.user_uid,
            'enrollpw1': enroll_pw1,
            'remote_ip': self.remote_ip,
            'fromaddr': SMTP_FROM,
            'web_ctx_host': web.ctx.host,
            'app_path_prefix': APP_PATH_PREFIX,
        }
        smtp_message = smtp_message_tmpl % owner_data
        smtp_subject = EMAIL_SUBJECT % owner_data

        # Send the message
        #---------------------------------------------------------------
        smtp_conn.send_simple_message(
            SMTP_FROM,
            [to_addr.encode('utf-8')],
            'utf-8',
            default_headers+(
                ('Subject', smtp_subject),
                ('To', to_addr),
            ),
            smtp_message,
        )
        smtp_conn.quit()
        return # _send_pw()

    def search_accounts(self, dn):
        """
        Search all accounts using the token
        """
        ldap_result = self.user_ldap_conn.search_s(
            self.ldap_url.dn,
            ldap.SCOPE_SUBTREE,
            filterstr='(&(objectClass=account)(oathToken={dn}))'.format(
                dn=ldap.filter.escape_filter_chars(dn),
            ),
            attrlist=['uid', 'description']
        )
        if not ldap_result:
            return None
        return [
            (
                entry['uid'][0].decode('utf-8'),
                entry.get('description', [''])[0].decode('utf-8'),
            )
            for dn, entry in ldap_result
        ]

    def read_owner(self, dn):
        """
        Read a token owner entry
        """
        ldap_result = self.user_ldap_conn.read_s(
            dn,
            filterstr=FILTERSTR_OWNER_READ,
            attrlist=[
                'displayName',
                'mail',
                'telePhoneNumber',
                'mobile',
                'l',
            ],
        )
        if ldap_result:
            result = dict([
                (at, av[0].decode('utf-8'))
                for at, av in ldap_result.items()
            ])
        else:
            return ldap.NO_SUCH_OBJECT('No result')
        return result # end of read_owner()

    def update_token(self, token_dn, token_entry, token_password):
        """
        Resets token to unusable state by
        - overwriting 'oathSecret'
        - removing 'oathLastLogin'
        - resetting 'oathHOTPCounter' to 0
        - removing failure attributes 'oathFailureCount' and 'oathLastFailure'
        - setting temporary enrollment password in 'userPassword'
        - resetting 'oathSecretTime' to current time
        """
        session_tracking_ctrl = SessionTrackingControl(
            self.remote_ip,
            web.ctx.homedomain,
            SESSION_TRACKING_FORMAT_OID_USERNAME,
            self.user_uid.encode('utf-8'),
        )
        current_time = time.strftime(
            '%Y%m%d%H%M%SZ',
            time.gmtime(time.time())
        )
        # Set an invalid shared secret because we cannot determine
        # whether shared secret is set
        token_mods = [
            (ldap.MOD_REPLACE, 'oathFailureCount', ['0']),
            (ldap.MOD_REPLACE, 'oathSecretTime', [current_time]),
        ]
        for del_attr in ('oathHOTPCounter', 'oathLastLogin', 'oathLastFailure'):
            if del_attr in token_entry:
                token_mods.append(
                    (ldap.MOD_DELETE, del_attr, None)
                )
        # Reset the token entry
        self.user_ldap_conn.modify_ext_s(
            token_dn,
            token_mods,
            serverctrls=[session_tracking_ctrl],
        )
        # Try to remove shared secret
        try:
            self.user_ldap_conn.modify_ext_s(
                token_dn,
                [(ldap.MOD_DELETE, 'oathSecret', None)],
                serverctrls=[session_tracking_ctrl],
            )
        except ldap.NO_SUCH_ATTRIBUTE:
            # We can happily ignore this case
            pass
        # Set the new userPassword with Modify Password ext.op.
        # for server-side hashing
        self.ldap_conn.passwd_s(
            token_dn,
            None, token_password,
            serverctrls=[session_tracking_ctrl],
        )
        return # end of ResetToken.update_token()

    def do_the_work(self):
        """
        Actually do the work herein
        """
        token_serial = self.form.d.serial
        try:
            token_displayname, token_dn, token_entry = self.search_token(
                token_serial
            )
            owner_dn = token_entry[ATTR_OWNER_DN][0]
            owner_entry = self.read_owner(owner_dn)
            accounts = self.search_accounts(token_dn)
            confirm_hash = hashlib.sha256(
                ' || '.join((
                    repr(token_serial),
                    repr(owner_dn),
                    repr(sorted(accounts or [])),
                ))
            ).hexdigest()
            if self.form.d.confirm != confirm_hash:
                return RENDER.reset_form(
                    'Please confirm token reset. Examine this information carefully!',
                    admin=self.form.d.admin,
                    serial=self.form.d.serial,
                    token=token_displayname,
                    owner=owner_entry['displayName'],
                    email=owner_entry['mail'],
                    accounts=accounts,
                    confirm=confirm_hash,
                )
            enroll_pw1 = random_string(PWD_LENGTH-PWD_ADMIN_LEN, PWD_TMP_CHARS)
            enroll_pw2 = random_string(PWD_ADMIN_LEN, PWD_TMP_CHARS)
            enroll_pw = enroll_pw1 + enroll_pw2
            self.update_token(token_dn, token_entry, enroll_pw)
        except ldap.NO_UNIQUE_ENTRY as ldap_err:
            logging.error('LDAPError: %s', repr(ldap_err), exc_info=True)
            res = self.GET(message=u'Serial no. not found!')
        except LDAPError as ldap_err:
            logging.error('LDAPError: %s', repr(ldap_err), exc_info=True)
            res = self.GET(message=u'Internal LDAP error!')
        except Exception as err:
            logging.error('Unhandled exception: %s', repr(err), exc_info=True)
            res = self.GET(message=u'Internal error!')
        else:
            # try to send 2nd enrollment password part to token owner
            try:
                self._send_pw(self.form.d.serial, owner_entry, enroll_pw1)
            except (socket.error, smtplib.SMTPException):
                res = self.GET(message=u'Error sending e-mail via SMTP!')
            else:
                res = RENDER.reset_action(
                    'Token was reset',
                    serial=token_serial,
                    token=token_entry['displayName'][0].decode('utf-8'),
                    owner=owner_entry['displayName'],
                    email=owner_entry['mail'],
                    enrollpw2=enroll_pw2,
                )
        return res # end of ResetToken.do_the_work()


def start():
    """
    Start the web application service
    """
    # Change to directory where the script is located
    os.chdir(os.path.dirname(sys.argv[0]))
    # Initialize web application
    app = web.application(URL2CLASS_MAPPING, globals())
    # Set error handling
    if WEB_ERROR is False:
        app.internalerror = False
    # Start the internal web server
    app.run()


if __name__ == '__main__':
    start()
