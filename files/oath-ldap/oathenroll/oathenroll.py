#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Web-interface for OATH-LDAP token enrollment

Author: Michael Ströder <michael@stroeder.com>
"""

from __future__ import absolute_import

__version__ = '0.2.1'

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

# from ldap0 package
import ldap0
from ldap0 import LDAPError
from ldap0.ldapobject import ReconnectLDAPObject
from ldap0.controls.sessiontrack import SessionTrackingControl, SESSION_TRACKING_FORMAT_OID_USERNAME
from ldap0.ldapurl import LDAPUrl
from ldap0.filter import escape_filter_chars
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
    SMTP_DEBUGLEVEL, SMTP_FROM, SMTP_LOCALHOSTNAME, SMTP_TLSARGS, SMTP_URL, \
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
    ldap_url = ExtLDAPUrl(LDAP_URL)

    def __init__(self, *args, **kwargs):
        # Set additional headers in response
        self.remote_ip = web.ctx.env.get(
            'FORWARDED_FOR',
            web.ctx.env.get('HTTP_X_FORWARDED_FOR', web.ctx.ip)
        )
        self._add_headers()
        self.ldap_conn = None
        self.user_ldap_conn = None
        self.token_ldap_conn = None

    def _add_headers(self):
        """
        Add more HTTP headers to response
        """
        csp_value = ' '.join((
            "child-src 'none';",
            "connect-src 'none';",
            "default-src 'none';",
            "font-src 'self';",
            "form-action 'self';",
            "frame-ancestors 'none';",
            "frame-src 'none';",
            "img-src 'self' data:;",
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
        self.ldap_conn = ReconnectLDAPObject(
            self.ldap_url.initializeUrl(),
            trace_level=LDAP0_TRACE_LEVEL,
            trace_file=sys.stderr,
        )
        # Send SASL bind request with mechanism EXTERNAL
        self.ldap_conn.sasl_non_interactive_bind_s('EXTERNAL', authz_id=authz_id)
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
            self.user_ldap_conn = None
            try:
                user_dn, _ = self.ldap_conn.find_unique_entry(
                    self.ldap_url.dn,
                    scope=self.ldap_url.scope,
                    filterstr=FILTERSTR_ADMIN_LOGIN.format(
                        uid=username.encode('utf-8'),
                    ),
                    attrlist=['1.1'],
                )
                self.user_ldap_conn = ReconnectLDAPObject(
                    self.ldap_url.initializeUrl(),
                    trace_level=LDAP0_TRACE_LEVEL,
                    trace_file=sys.stderr,
                )
                self.user_ldap_conn.simple_bind_s(user_dn, password.encode('utf-8'))
            except LDAPError:
                self.user_uid = u''
                result = False
            else:
                self.user_uid = username
                result = True
        finally:
            # Anyway we should try to close the LDAP connection
            try:
                self.user_ldap_conn.unbind_s()
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
        except ldap0.SERVER_DOWN:
            return self.GET(message=u'LDAP server not reachable!')
        except LDAPError:
            return self.GET(message=u'Internal LDAP error!')
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
            ldap0.SCOPE_SUBTREE,
            filterstr='(&(objectClass=oathUser)(oathToken={dn}))'.format(
                dn=escape_filter_chars(dn),
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
            raise ldap0.NO_SUCH_OBJECT('No result with %s' % repr(FILTERSTR_OWNER_READ))
        return result # end of read_owner()

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
        session_tracking_ctrl = SessionTrackingControl(
            self.remote_ip,
            web.ctx.homedomain,
            SESSION_TRACKING_FORMAT_OID_USERNAME,
            self.user_uid.encode('utf-8'),
        )
        token_mods = [
            # We don't fully trust enrollment client
            # => set shared secret time to current time here
            (
                ldap0.MOD_REPLACE,
                'oathSecretTime',
                [time.strftime('%Y%m%d%H%M%SZ', time.gmtime(time.time()))],
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
                    (ldap0.MOD_DELETE, del_attr, None)
                )
        # Reset the token entry
        self.user_ldap_conn.modify_s(
            token_dn,
            token_mods,
            serverctrls=[session_tracking_ctrl],
        )
        # Try to remove shared secret separately because with
        # strict access control we don't know whether it's set or not
        try:
            self.user_ldap_conn.modify_s(
                token_dn,
                [(ldap0.MOD_DELETE, 'oathSecret', None)],
                serverctrls=[session_tracking_ctrl],
            )
        except ldap0.NO_SUCH_ATTRIBUTE:
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
        # Check the login
        if not self.check_login(self.form.d.admin, self.form.d.password):
            return self.GET(message=u'Admin login failed!')
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
            enroll_pw1 = random_string(alphabet=PWD_TMP_CHARS, length=PWD_LENGTH-PWD_ADMIN_LEN)
            enroll_pw2 = random_string(alphabet=PWD_TMP_CHARS, length=PWD_ADMIN_LEN)
            enroll_pw = enroll_pw1 + enroll_pw2
            self.update_token(token_dn, token_entry, enroll_pw)
        except ldap0.NO_UNIQUE_ENTRY as ldap_err:
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
            except (socket.error, socket.gaierror, smtplib.SMTPException) as mail_error:
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


class InitToken(BaseApp):
    """
    Initializes token with (encrypted) shared secret.

    LDAP operations are authenticated with temporary token enrollment password.
    """

    # Declaration for the change password input form
    post_form = web.form.Form(
        SERIAL_FIELD,
        web.form.Password(
            'epw1',
            web.form.notnull,
            web.form.regexp(r'^.+$', u'Invalid password'),
            description=u'Enrollment password #1'
        ),
        web.form.Password(
            'epw2',
            web.form.notnull,
            web.form.regexp(r'^.+$', u'Invalid password'),
            description=u'Enrollment password #2'
        ),
        web.form.Textbox(
            'secret',
            web.form.notnull,
            web.form.regexp(r'^.+$', u'Invalid shared secret'),
            description=u'(Encrypted) Shared Secret'
        ),
        web.form.Button(
            'submit',
            type='submit',
            description=u'Initialize token'
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
            return RENDER.init_form(u'Invalid Unicode input')
        else:
            if not get_input.serial:
                message = (
                    u'Enter a serial number of token to be (re-)initialized'
                    u' and enrollment passwords.'
                )
            return RENDER.init_form(
                message,
                PWD_LENGTH-PWD_ADMIN_LEN,
                PWD_ADMIN_LEN,
                serial=get_input.serial,
            )

    def do_the_work(self):
        token_serial = self.form.d.serial.encode('utf-8')
        token_password = (self.form.d.epw1 + self.form.d.epw2).encode('utf-8')
        token_binddn = 'serialNumber={0},{1}'.format(token_serial, self.ldap_url.dn)
        oath_secret = self.form.d.secret.encode('utf-8')
        try:
            token_ldap_conn = ReconnectLDAPObject(
                self.ldap_url.initializeUrl(),
                trace_level=LDAP0_TRACE_LEVEL,
                trace_file=sys.stderr,
            )
            token_ldap_conn.simple_bind_s(token_binddn, token_password)
            token_dn = token_ldap_conn.whoami_s()[3:]
            token_ldap_conn.modify_s(
                token_dn,
                [
                    (ldap0.MOD_ADD, 'oathHOTPCounter', ['0']),
                    (ldap0.MOD_ADD, 'oathSecret', [oath_secret]),
                    #(ldap0.MOD_DELETE, 'userPassword', None),
                ],
                serverctrls=[
                    SessionTrackingControl(
                        self.remote_ip,
                        web.ctx.homedomain,
                        SESSION_TRACKING_FORMAT_OID_USERNAME,
                        id(self),
                    ),
                ],
            )
        except Exception as err:
            logging.error('Unhandled exception: %s', repr(err), exc_info=True)
            res = self.GET(message=u'Internal error!')
        else:
            res = RENDER.init_action(
                'Token was initialized',
                serial=self.form.d.serial,
            )
        return res # end of InitToken.do_the_work()

application = web.application(URL2CLASS_MAPPING, globals(), autoreload=bool(WEB_ERROR)).wsgifunc()

def run():
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
    run()
