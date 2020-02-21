#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Web-interface for OATH-LDAP token enrollment

Author: Michael Ströder <michael@stroeder.com>
"""

__version__ = '0.5.0'

# from Python's standard lib
import os
import time
import socket
import smtplib
import hashlib
import logging
from urllib.parse import quote_plus as url_quote_plus
import email.utils

# web.py
import web

# from ldap0 package
import ldap0
import ldap0.filter
import ldap0.err
from ldap0 import LDAPError
from ldap0.ldapobject import ReconnectLDAPObject
from ldap0.controls.sessiontrack import SessionTrackingControl, SESSION_TRACKING_FORMAT_OID_USERNAME
from ldap0.ldapurl import LDAPUrl
from ldap0.pw import random_string

# from mailutil
import mailutil

# Import constants from configuration module
from oathenroll_cnf import \
    APP_PATH_PREFIX, ATTR_OWNER_DN, \
    EMAIL_SUBJECT, EMAIL_TEMPLATE, \
    FILTERSTR_ADMIN_LOGIN, FILTERSTR_OWNER_READ, FILTERSTR_TOKEN_SEARCH, \
    LDAPI_AUTHZ_ID, LDAP_URL, \
    PWD_ADMIN_LEN, PWD_LENGTH, PWD_TMP_CHARS, \
    LDAP0_TRACE_LEVEL, \
    SMTP_DEBUGLEVEL, SMTP_FROM, SMTP_LOCALHOSTNAME, SMTP_TLS_CACERTS, SMTP_URL, \
    LAYOUT, TEMPLATES_DIRNAME,  \
    WEB_CONFIG_DEBUG, WEB_ERROR

#---------------------------------------------------------------------------
# constants
#---------------------------------------------------------------------------

# Mapping of request URL path to Python handler class
URL2CLASS_MAPPING = (
    '/', 'Default',
    '/reset', 'ResetToken',
    '/init', 'InitToken',
)

#---------------------------------------------------------------------------
# basic functions and classes
#---------------------------------------------------------------------------

def init_logger():
    """
    Create logger instance
    """
    if 'LOG_CONFIG' in os.environ:
        from logging.config import fileConfig
        fileConfig(os.environ['LOG_CONFIG'])
    else:
        logging.basicConfig(
            level=os.environ.get('LOG_LEVEL', '').upper() or logging.INFO,
            format='%(asctime)s %(name)s %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    _logger = logging.getLogger(os.environ.get('LOG_QUALNAME', None))
    _logger.name = 'oathenroll'
    return _logger

APP_LOGGER = init_logger()


class ExtLDAPUrl(LDAPUrl):
    """
    Special class for handling additional LDAP URL extensions
    """
    attr2extype = {
        'who': 'bindname',
        'cred': 'X-BINDPW',
        'start_tls': 'startTLS',
        'trace_level': 'trace',
    }


class RequestLogAdaptor(logging.LoggerAdapter):
    """
    wrapper for adding more request-specific information to log messages
    """

    def process(self, msg, kwargs):
        return (
            'IP=%s CLASS=%s REQID=%d - %s' % (
                self.extra['remote_ip'],
                self.extra['req_class'],
                self.extra['req_id'],
                msg,
            ),
            kwargs,
        )


#---------------------------------------------------------------------------
# The web application classes
#---------------------------------------------------------------------------

# Safety check for URL chars
if PWD_TMP_CHARS != url_quote_plus(PWD_TMP_CHARS):
    raise ValueError('URL special chars in PWD_TMP_CHARS: %r' % (PWD_TMP_CHARS,))

# Set some webpy configuration vars
if WEB_CONFIG_DEBUG is False:
    web.config.debug = False

# Initialize template rendering with layout information
RENDER = web.template.render(TEMPLATES_DIRNAME, base=LAYOUT)

# Declaration for text input field for 'username'
ADMIN_FIELD = web.form.Textbox(
    'admin',
    web.form.notnull,
    web.form.regexp('^[a-zA-Z]+$', 'Invalid 2FA admin user name.'),
    description='2FA admin user name'
)

# Declaration for text input field for old password
PASSWORD_FIELD = web.form.Password(
    'password',
    web.form.notnull,
    web.form.regexp('^.+$', 'Invalid password'),
    description='2FA admin password'
)

# Declaration for text input field for 'email'
SERIAL_FIELD = web.form.Textbox(
    'serial',
    web.form.notnull,
    web.form.regexp('^[0-9]+$', 'Invalid token serial number'),
    description='E-mail address'
)

# Declaration for text input field for 'confirm' (hex-encoded hash)
CONFIRM_FIELD = web.form.Textbox(
    'confirm',
    web.form.regexp('^[0-9a-fA-F]*$', 'Invalid confirmation hash'),
    description='Confirmation hash'
)


class Default:
    """
    Handle requests to base URL
    """
    ldap_url = ExtLDAPUrl(LDAP_URL)

    def __init__(self):
        # Set additional headers in response
        self.remote_ip = web.ctx.env.get(
            'FORWARDED_FOR',
            web.ctx.env.get('HTTP_X_FORWARDED_FOR', web.ctx.ip)
        )
        self.logger = RequestLogAdaptor(
            APP_LOGGER,
            {
                'remote_ip': self.remote_ip,
                'req_class': '.'.join((self.__class__.__module__, self.__class__.__name__)),
                'req_id': id(self),
            }
        )
        self.logger.debug(
            '%s request from %s (via %s)',
            web.ctx.env['REQUEST_METHOD'],
            self.remote_ip,
            web.ctx.ip,
        )
        self._add_headers()
        self.ldap_conn = None
        self.user_ldap_conn = None

    @staticmethod
    def _add_headers():
        """
        Add more HTTP headers to response
        """
        csp_value = ' '.join((
            "base-uri 'none';",
            "child-src 'none';",
            "connect-src 'none';",
            "default-src 'none';",
            "font-src 'self';",
            "form-action 'self';",
            "frame-ancestors 'none';",
            "frame-src 'none';",
            "img-src 'self' data:;",
            "media-src 'none';",
            "object-src 'none';",
            "script-src 'none';",
            "style-src 'self';",
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
                ('Referrer-Policy', 'same-origin'),
            ):
            web.header(header, value)
        # end of Default._add_headers()

    def GET(self, message=''):
        """
        Simply display the entry landing page
        """
        return RENDER.default()


class BaseApp(Default):
    """
    Request handler base class which is not used directly
    """
    post_form = None

    def _sess_track_ctrl(self):
        """
        return LDAPv3 session tracking control representing current user
        """
        return SessionTrackingControl(
            self.remote_ip,
            web.ctx.homedomain,
            SESSION_TRACKING_FORMAT_OID_USERNAME,
            str(id(self)),
        )

    def ldap_connect(self, authz_id=None):
        """
        Connect and bind to the LDAP directory as local system account
        """
        self.ldap_conn = ReconnectLDAPObject(
            self.ldap_url.connect_uri(),
            trace_level=LDAP0_TRACE_LEVEL,
        )
        # Send SASL bind request with mechanism EXTERNAL
        self.ldap_conn.sasl_non_interactive_bind_s('EXTERNAL', authz_id=authz_id)
        # end of ldap_connect()

    def open_user_conn(self, username, password):
        """
        Search a user entry specified by :username: and check
        :password: with LDAP simple bind.
        """
        self.user_ldap_conn = None
        user = self.ldap_conn.find_unique_entry(
            self.ldap_url.dn,
            scope=self.ldap_url.scope,
            filterstr=FILTERSTR_ADMIN_LOGIN.format(uid=username),
            attrlist=['1.1'],
        )
        self.user_ldap_conn = ReconnectLDAPObject(
            self.ldap_url.connect_uri(),
            trace_level=LDAP0_TRACE_LEVEL,
        )
        self.user_ldap_conn.simple_bind_s(user.dn_s, password.encode('utf-8'))
        # end of BaseApp.open_user_conn()

    def search_token(self, token_serial):
        """
        Search a token entry specified by serial number
        """
        token = self.user_ldap_conn.find_unique_entry(
            self.ldap_url.dn,
            scope=self.ldap_url.scope,
            filterstr=FILTERSTR_TOKEN_SEARCH.format(
                owner_attr=ATTR_OWNER_DN,
                serial=token_serial,
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
            req_ctrls=[self._sess_track_ctrl()],
        )
        return token.entry_s['displayName'][0], token.dn_s, token.entry_s
        # endof BaseApp.search_token()

    def do_the_work(self):
        """
        this method contains the real work and is implemented by derived classes
        """
        return


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
        # end of BaseApp.clean_up()

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
            return self.GET(message='Incomplete or invalid input!')
        # Make connection to LDAP server
        try:
            self.ldap_connect(authz_id=LDAPI_AUTHZ_ID)
        except ldap0.SERVER_DOWN as ldap_err:
            self.logger.error('Error connectiong to %r: %s', self.ldap_url.connect_uri(), ldap_err)
            return self.GET(message='LDAP server not reachable!')
        except LDAPError as ldap_err:
            self.logger.error('Other LDAPError connecting to %r: %s', self.ldap_url.connect_uri(), ldap_err)
            return self.GET(message='Internal LDAP error!')
        # Do the real work
        try:
            res = self.do_the_work()
        except Exception as err:
            self.logger.error('Unhandled exception: %s', err, exc_info=__debug__)
            res = self.GET(message='Internal error!')
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
            description='Reset token'
        ),
    )

    def GET(self, message=''):
        """
        Process the GET request mainly for displaying input form
        """
        try:
            get_input = web.input(
                serial='',
                admin='',
                password='',
            )
        except UnicodeError:
            return RENDER.reset_form('Invalid Unicode input')
        else:
            if not get_input.serial:
                message = 'Enter a serial number of token to be (re-)initialized.'
            elif not get_input.admin:
                message = 'Login with your 2FA admin account.'
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
            ca_certs=SMTP_TLS_CACERTS,
            debug_level=SMTP_DEBUGLEVEL
        )

        # Construct the message
        #---------------------------------------------------------------
        smtp_message_tmpl = open(EMAIL_TEMPLATE, 'rb').read().decode('utf-8')
        to_addr = owner_entry['mail'][0]
        default_headers = (
            ('From', SMTP_FROM),
            ('Date', email.utils.formatdate(time.time(), True)),
        )
        owner_data = {
            'serial': token_serial,
            'admin': self.form.d.admin,
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
            [to_addr],
            'utf-8',
            default_headers+(
                ('Subject', smtp_subject),
                ('To', to_addr),
            ),
            smtp_message,
        )
        smtp_conn.quit()
        self.logger.info('Sent reset password to %r.', to_addr)
        # end of _send_pw()

    def search_accounts(self, token_dn):
        """
        Search all accounts using the token
        """
        ldap_result = self.user_ldap_conn.search_s(
            self.ldap_url.dn,
            ldap0.SCOPE_SUBTREE,
            filterstr='(&(objectClass=oathUser)(oathToken={dn}))'.format(
                dn=ldap0.filter.escape_str(token_dn),
            ),
            attrlist=['uid', 'description']
        )
        if not ldap_result:
            return None
        return [
            (
                res.entry_s['uid'][0],
                res.entry_s.get('description', [''])[0],
            )
            for res in ldap_result
        ]

    def read_owner(self, owner_dn):
        """
        Read a token owner entry
        """
        ldap_result = self.user_ldap_conn.read_s(
            owner_dn,
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
            result = ldap_result.entry_s
        else:
            raise ldap0.NO_SUCH_OBJECT('No result with %r' % (FILTERSTR_OWNER_READ,))
        return result
        # end of read_owner()

    def update_token(self, token_dn, token_entry, token_password):
        """
        Resets token to unusable state by
        - overwriting 'oathSecret'
        - removing 'oathLastLogin'
        - removing 'oathHOTPCounter'
        - removing failure attributes 'oathFailureCount' and 'oathLastFailure'
        - setting temporary enrollment password in 'userPassword'
        - resetting 'oathSecretTime' to current time
        """
        session_tracking_ctrl = self._sess_track_ctrl()
        token_mods = [
            # We don't fully trust enrollment client
            # => set shared secret time to current time here
            (
                ldap0.MOD_REPLACE,
                b'oathSecretTime',
                [time.strftime('%Y%m%d%H%M%SZ', time.gmtime(time.time())).encode('ascii')],
            ),
        ]
        for del_attr in (
                'oathHOTPCounter',
                'oathLastLogin',
                'oathFailureCount',
                'oathLastFailure',
            ):
            if del_attr in token_entry:
                token_mods.append(
                    (ldap0.MOD_DELETE, del_attr.encode('ascii'), None)
                )
        # Reset the token entry
        self.user_ldap_conn.modify_s(
            token_dn,
            token_mods,
            req_ctrls=[session_tracking_ctrl],
        )
        # Try to remove shared secret separately because with
        # strict access control we don't know whether it's set or not
        try:
            self.user_ldap_conn.modify_s(
                token_dn,
                [(ldap0.MOD_DELETE, b'oathSecret', None)],
                req_ctrls=[session_tracking_ctrl],
            )
        except ldap0.NO_SUCH_ATTRIBUTE:
            # We can happily ignore this case
            pass
        # Set the new userPassword with Modify Password ext.op.
        # for server-side hashing
        self.ldap_conn.passwd_s(
            token_dn,
            None, token_password,
            req_ctrls=[session_tracking_ctrl],
        )
        # end of ResetToken.update_token()

    def do_the_work(self):
        """
        Actually do the work herein
        """
        # Check the user login and open user connection
        try:
            self.open_user_conn(self.form.d.admin, self.form.d.password)
        except LDAPError as ldap_err:
            self.logger.error(
                'Error opening user connection to %r as user %r: %s',
                self.ldap_url.connect_uri(),
                self.form.d.admin,
            )
            return self.GET(message='Admin login failed!')
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
                )).encode('ascii')
            ).hexdigest()
            if self.form.d.confirm != confirm_hash:
                return RENDER.reset_form(
                    'Please confirm token reset. Examine this information carefully!',
                    admin=self.form.d.admin,
                    serial=self.form.d.serial,
                    token=token_displayname,
                    owner=owner_entry['displayName'][0],
                    email=owner_entry['mail'][0],
                    accounts=accounts,
                    confirm=confirm_hash,
                )
            enroll_pw1 = random_string(alphabet=PWD_TMP_CHARS, length=PWD_LENGTH-PWD_ADMIN_LEN)
            enroll_pw2 = random_string(alphabet=PWD_TMP_CHARS, length=PWD_ADMIN_LEN)
            enroll_pw = enroll_pw1 + enroll_pw2
            self.update_token(token_dn, token_entry, enroll_pw)
        except ldap0.err.NoUniqueEntry as ldap_err:
            self.logger.warning('LDAPError: %s', ldap_err)
            res = self.GET(message='Serial no. not found!')
        except LDAPError as ldap_err:
            self.logger.error('LDAPError: %s', ldap_err, exc_info=__debug__)
            res = self.GET(message='Internal LDAP error!')
        except Exception as err:
            self.logger.error('Unhandled exception: %s', err, exc_info=__debug__)
            res = self.GET(message='Internal error!')
        else:
            # try to send 2nd enrollment password part to token owner
            try:
                self._send_pw(self.form.d.serial, owner_entry, enroll_pw1)
            except (socket.error, socket.gaierror, smtplib.SMTPException) as mail_error:
                self.logger.error('Error sending e-mail: %s', mail_error, exc_info=__debug__)
                res = self.GET(message='Error sending e-mail via SMTP!')
            else:
                self.logger.info('Finished resetting token %r.', token_dn)
                res = RENDER.reset_action(
                    'Token was reset',
                    serial=token_serial,
                    token=token_entry['displayName'][0],
                    owner=owner_entry['displayName'][0],
                    email=owner_entry['mail'][0],
                    enrollpw2=enroll_pw2,
                )
        return res # end of ResetToken.do_the_work()


application = web.application(URL2CLASS_MAPPING, globals(), autoreload=bool(WEB_ERROR)).wsgifunc()
