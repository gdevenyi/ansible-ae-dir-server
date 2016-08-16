#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Web-interface for resetting/changing user passwords in a LDAP server

Author: Michael Ströder <michael@stroeder.com>

Tested with:
Python 2.7+ (see http://www.python.org/)
web.py 0.37+ (see http://webpy.org/)
python-ldap 2.4.25+ (see http://www.python-ldap.org/)
"""

__version__ = '0.2.1'

# from Python's standard lib
import string
import re
import sys
import os
import time
import socket
import smtplib
import hashlib
import random

from calendar import timegm
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
from ldap.filter import escape_filter_chars
from ldap.controls.ppolicy import PasswordPolicyControl
from ldap.controls.sessiontrack import SessionTrackingControl
from ldap.controls.sessiontrack import SESSION_TRACKING_FORMAT_OID_USERNAME

# mail utility module
import mailutil

import aedir

# Import constants from configuration module
sys.path.append(sys.argv[2])
from aedirpwd_cnf import *

#-----------------------------------------------------------------------
# utility functions
#-----------------------------------------------------------------------


def pwd_hash(pw_clear):
    """
    Generate un-salted hash as hex-digest
    """
    return hashlib.new(PWD_TMP_HASH_ALGO, pw_clear).hexdigest()


def read_template_file(filename):
    """
    return UTF-8 encoded text file as decoded Unicode string
    """
    file_obj = open(filename, 'rb')
    file_content = file_obj.read().decode('utf-8')
    file_obj.close()
    return file_content

#-----------------------------------------------------------------------
# Some custom exception classes for password policy handling
#-----------------------------------------------------------------------


class PasswordPolicyException(ldap.LDAPError):
    """
    Base class for raising password policy related exceptions
    """

    def __init__(self, who=None, desc=None):
        self.who = who
        self.desc = desc

    def __str__(self):
        return self.desc


class PasswordPolicyChangeAfterReset(PasswordPolicyException):
    """
    Exception class for password change after reset warning
    """
    pass


class PasswordPolicyExpirationWarning(PasswordPolicyException):
    """
    Exception class for password expiry warning
    """

    def __init__(self, who=None, desc=None, timeBeforeExpiration=None):
        PasswordPolicyException.__init__(self, who, desc)
        self.timeBeforeExpiration = timeBeforeExpiration


class PasswordPolicyExpiredError(PasswordPolicyException):
    """
    Exception class for password expired error
    """

    def __init__(self, who=None, desc=None, graceAuthNsRemaining=None):
        PasswordPolicyException.__init__(self, who, desc)
        self.graceAuthNsRemaining = graceAuthNsRemaining


#-----------------------------------------------------------------------
# The web application
#-----------------------------------------------------------------------

RENDER = web.template.render(TEMPLATES_DIRNAME, base=LAYOUT)

# Safety check for URL chars
if PWD_TMP_CHARS != url_quote_plus(PWD_TMP_CHARS):
    raise ValueError('URL special chars in PWD_TMP_CHARS: %r' % (PWD_TMP_CHARS))

# Set some webpy configuration vars
if not WEB_CONFIG_DEBUG:
    web.config.debug = False

# Declaration for text input field for 'username'
USERNAME_FIELD = web.form.Textbox(
    'username',
    web.form.notnull,
    web.form.regexp('^[a-zA-Z0-9._-]+$', u'Invalid user name.'),
    description=u'User name:'
)

# Declaration for text input field for 'email'
EMAIL_FIELD = web.form.Textbox(
    'email',
    web.form.notnull,
    web.form.regexp(
        r'^[a-zA-Z0-9@.+=/_ -]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$',
        u'Invalid e-mail address.'
    ),
    description=u'E-mail address:'
)

# Declaration for text input field for old password
USERPASSWORD_FIELD = web.form.Password(
    'oldpassword',
    web.form.notnull,
    web.form.regexp(r'^.*$', u''),
    description=u'Old password'
)

TEMP1PASSWORD_FIELD = web.form.Password(
    'temppassword1',
    web.form.notnull,
    web.form.regexp(
        ur'^[%s]+$' % re.escape(PWD_TMP_CHARS),
        u'Invalid input format.'
    ),
    description=u'Temporary password part #1'
)

TEMP2PASSWORD_FIELD = web.form.Password(
    'temppassword2',
    #web.form.notnull,
    web.form.regexp(
        ur'^[%s]*$' % re.escape(PWD_TMP_CHARS),
        u'Invalid input format.'
    ),
    description=u'Temporary password part #2'
)

# Declarations for new password fields

valid_newpassword_regexp = web.form.regexp(r'^.+$', u'Passwort rules violated!')

NEWPASSWORD1_FIELD = web.form.Password(
    'newpassword1',
    web.form.notnull,
    valid_newpassword_regexp,
    description=u'New password'
)

NEWPASSWORD2_FIELD = web.form.Password(
    'newpassword2',
    web.form.notnull,
    valid_newpassword_regexp,
    description=u'New password (repeat)'
)

NEWPASSWORD_VALIDATOR = web.form.Validator(
    u'New password input does not match',
    lambda i: i.newpassword1 == i.newpassword2
)


class Default(object):
    """
    Handle default index request
    """
    ldap_url = aedir.AEDirUrl(PWD_LDAP_URL)
    http_headers = (
        ('Cache-Control', 'no-store,no-cache,max-age=0,must-revalidate'),
        ('X-XSS-Protection', '1; mode=block'),
        ('X-DNS-Prefetch-Control', 'off'),
        ('X-Content-Type-Options', 'nosniff'),
        ('X-Frame-Options', 'deny'),
        ('Server', 'unknown'),
        ('Content-Security-Policy', "default-src 'self';script-src 'none'"),
        ('X-Webkit-CSP', "default-src 'self';script-src 'none'"),
        ('X-Content-Security-Policy', "default-src 'self';script-src 'none'"),
    )

    def __init__(self, *args, **kwargs):
        self.remote_ip = web.ctx.env.get(
            'FORWARDED_FOR',
            web.ctx.env.get('HTTP_X_FORWARDED_FOR', web.ctx.ip)
        )
        # Set additional headers in response
        for header, value in self.http_headers:
            web.header(header, value)
        return # end of __init__()

    def GET(self):
        """
        handle GET request by returning default entry page
        """
        return RENDER.default()


class BaseApp(Default):
    """
    Request handler base class which is not used directly
    """

    post_form = None

    get_form = web.form.Form(USERNAME_FIELD)

    def _sess_track_ctrl(self, username='-/-'):
        """
        return LDAPv3 session tracking control representing current user
        """
        return SessionTrackingControl(
            self.remote_ip,
            web.ctx.homedomain,
            SESSION_TRACKING_FORMAT_OID_USERNAME,
            username,
        )

    def search_user_entry(self, inputs):
        """
        Search a user entry for the user specified by username
        """
        filterstr_inputs_dict = dict([
            (i.name, escape_filter_chars(i.get_value()))
            for i in inputs
        ])
        filterstr_inputs_dict['currenttime'] = escape_filter_chars(
            ldap.strf_secs(time.time())
        )
        return self.ldap_conn.find_unique_entry(
            self.ldap_conn.ldap_url_obj.dn,
            ldap.SCOPE_SUBTREE,
            filterstr=(
                self.filterstr_template % filterstr_inputs_dict
            ).encode('utf-8'),
            attrlist=[
                'objectClass',
                'uid',
                'cn',
                'mail',
                'pwdChangedTime',
                'pwdPolicySubentry',
            ],
        )

    def POST(self):
        """
        handle POST request processing input form

        mainly this opens and binds LDAP connection for user
        """
        self.form = self.post_form()
        if not self.form.validates():
            return self.GET(message=u'Invalid input!')
        # Make connection to LDAP server
        try:
            self.ldap_conn = aedir.AEDirObject(PWD_LDAP_URL)
        except ldap.SERVER_DOWN:
            res = self.GET(message=u'LDAP server not reachable!')
        except ldap.LDAPError:
            res = self.GET(message=u'Internal LDAP error!')
        else:
            # Call specific handler for LDAP user
            try:
                user_dn, user_entry = self.search_user_entry(self.form.inputs)
            except ValueError:
                res = self.GET(message=u'Error searching user entry!')
            except ldap.LDAPError:
                res = self.GET(message=u'Internal LDAP error!')
            else:
                res = self.handle_user_request(user_dn, user_entry)
        # Anyway we should try to close the LDAP connection
        try:
            self.ldap_conn.unbind_s()
        except (AttributeError, ldap.LDAPError):
            pass
        return res


class CheckPassword(BaseApp):
    """
    Handler for checking user's password
    """

    filterstr_template = FILTERSTR_CHANGEPW

    post_form = web.form.Form(
        USERNAME_FIELD,
        USERPASSWORD_FIELD,
        web.form.Button('submit', type='submit', description=u'Check password'),
    )

    def GET(self, message=u''):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        try:
            get_input = web.input(username=u'')
        except UnicodeError:
            return RENDER.checkpw_form(u'', u'Invalid input')
        else:
            return RENDER.checkpw_form(get_input.username, message)

    def _ldap_user_operations(self, user_dn, old_password_ldap):
        """
        - bind as user
        - check password policy response control
        """
        # Prepare LDAPv3 extended request controls
        ppolicy_control = PasswordPolicyControl()
        session_tracking_control = self._sess_track_ctrl()
        # Do the password check itself by sending LDAP simple bind
        _, _, _, bind_srv_ctrls = self.ldap_conn.simple_bind_s(
            user_dn,
            old_password_ldap,
            serverctrls=[
                ppolicy_control,
                session_tracking_control,
            ]
        )
        # Extract the password policy response control and raise appropriate
        # warning exceptions
        if bind_srv_ctrls:
            ppolicy_ctrls = [
                c
                for c in bind_srv_ctrls
                if c.controlType == PasswordPolicyControl.controlType
            ]
            if ppolicy_ctrls and len(ppolicy_ctrls) == 1:
                ppolicy_ctrl = ppolicy_ctrls[0]
                if ppolicy_ctrl.error == 2:
                    raise PasswordPolicyChangeAfterReset(
                        who=user_dn,
                        desc='Password change is needed after reset!',
                    )
                elif ppolicy_ctrl.timeBeforeExpiration != None:
                    raise PasswordPolicyExpirationWarning(
                        who=user_dn,
                        desc='Password will expire in %d seconds!' % (
                            ppolicy_ctrl.timeBeforeExpiration
                        ),
                        timeBeforeExpiration=ppolicy_ctrl.timeBeforeExpiration,
                    )
                elif ppolicy_ctrl.graceAuthNsRemaining != None:
                    raise PasswordPolicyExpiredError(
                        who=user_dn,
                        desc='Password expired! %d grace logins left.' % (
                            ppolicy_ctrl.graceAuthNsRemaining
                        ),
                        graceAuthNsRemaining=ppolicy_ctrl.graceAuthNsRemaining,
                    )
        return

    def handle_user_request(self, user_dn, user_entry):
        """
        check the user password and display password expiry information
        """
        current_time = time.time()
        old_password_ldap = self.form.d.oldpassword.encode('utf-8')
        try:
            self._ldap_user_operations(user_dn, old_password_ldap)
        except ldap.INVALID_CREDENTIALS:
            return self.GET(message=u'Wrong password!')
        except PasswordPolicyExpirationWarning, ppolicy_error:
            expire_time_str = unicode(time.strftime(
                TIME_DISPLAY_FORMAT,
                time.localtime(current_time+ppolicy_error.timeBeforeExpiration)
            ))
            return RENDER.changepw_form(
                self.form.d.username,
                u'Password will expire soon at %s !' % (expire_time_str)
            )
        except PasswordPolicyException, ppolicy_error:
            return RENDER.changepw_form(
                self.form.d.username,
                unicode(str(ppolicy_error))
            )
        except ldap.LDAPError:
            return self.GET(message=u'Internal error!')
        # Try to display until when password is still valid
        valid_until = u'unknown'
        pwd_changed_timestamp = ldap.strp_secs(user_entry['pwdChangedTime'][0])
        pwd_policy_subentry_dn = user_entry['pwdPolicySubentry'][0]
        try:
            pwd_policy_subentry = self.ldap_conn.read_s(
                pwd_policy_subentry_dn,
                attrlist=['pwdMaxAge', 'pwdExpireWarning'],
            )
        except ldap.LDAPError:
            return self.GET(message=u'Internal error!')
        try:
            pwd_max_age = int(pwd_policy_subentry['pwdMaxAge'][0])
        except (ValueError, KeyError):
            pass
        else:
            expire_timestamp = pwd_changed_timestamp+pwd_max_age
            valid_until = unicode(
                time.strftime(
                    TIME_DISPLAY_FORMAT,
                    time.localtime(expire_timestamp)
                )
            )
        # Finally render output page with success message
        return RENDER.checkpw_action(
            self.form.d.username,
            user_dn,
            valid_until
        )


class ChangePassword(BaseApp):
    """
    Handler for changing user's own password
    """

    filterstr_template = FILTERSTR_CHANGEPW

    post_form = web.form.Form(
        USERNAME_FIELD,
        USERPASSWORD_FIELD,
        NEWPASSWORD1_FIELD,
        NEWPASSWORD2_FIELD,
        web.form.Button(
            'submit',
            type='submit',
            description=u'Change password'
        ),
        validators=[NEWPASSWORD_VALIDATOR],
    )

    def GET(self, message=u''):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        try:
            get_input = web.input(username=u'')
        except UnicodeError:
            return RENDER.changepw_form(u'', u'Invalid input')
        else:
            return RENDER.changepw_form(get_input.username, message)

    def _ldap_user_operations(
            self,
            user_dn,
            old_password_ldap,
            new_password_ldap
        ):
        self.ldap_conn.simple_bind_s(
            user_dn,
            old_password_ldap,
            serverctrls=[self._sess_track_ctrl()],
        )
        self.ldap_conn.passwd_s(
            user_dn,
            None,
            new_password_ldap,
            serverctrls=[self._sess_track_ctrl(user_dn)],
        )
        return

    def handle_user_request(self, user_dn, user_entry):
        """
        set new password
        """
        old_password_ldap = self.form.d.oldpassword.encode('utf-8')
        new_password_ldap = self.form.d.newpassword1.encode('utf-8')
        try:
            self._ldap_user_operations(
                user_dn,
                old_password_ldap,
                new_password_ldap
            )
        except ldap.INVALID_CREDENTIALS:
            res = self.GET(message=u'Old password wrong!')
        except ldap.CONSTRAINT_VIOLATION:
            res = self.GET(
                message=(
                    u'Constraint violation! '
                    u'Probably password rules violated. '
                    u'Try again with stronger password.'
                )
            )
        except ldap.LDAPError:
            res = self.GET(message=u'Internal error!')
        else:
            res = RENDER.changepw_action(
                self.form.d.username,
                user_dn,
                self.ldap_conn.ldap_url_obj.initializeUrl()
            )
        return res


class RequestPasswordReset(BaseApp):
    """
    Handler for starting password reset procedure
    """

    filterstr_template = FILTERSTR_REQUESTPW

    # Declaration for the change password input form
    post_form = web.form.Form(
        USERNAME_FIELD,
        EMAIL_FIELD,
        web.form.Button(
            'submit',
            type='submit',
            description=u'Set new password'
        ),
    )

    def GET(self, message=u''):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        try:
            get_input = web.input(username=u'')
        except UnicodeError:
            return RENDER.requestpw_form(u'', u'Invalid input')
        else:
            return RENDER.requestpw_form(get_input.username, message)

    def _get_admin_mailaddrs(self, user_dn):
        try:
            ldap_results = self.ldap_conn.get_zoneadmins(
                user_dn,
                attrlist=['mail'],
                suppl_filter='(mail=*)',
            )
        except ldap.LDAPError:
            admin_addrs = None
        else:
            admin_addrs = [
                ldap_entry['mail'][0]
                for _, ldap_entry in ldap_results or []
            ]
        return admin_addrs or PWD_ADMIN_MAILTO

    def _send_pw(self, username, user_dn, user_entry, temp_pwd_clear):
        """
        send e-mails to user and zone-admins
        """
        smtp_conn = mailutil.smtp_connection(
            SMTP_URL,
            local_hostname=SMTP_LOCALHOSTNAME,
            tls_args=SMTP_TLSARGS,
            debug_level=SMTP_DEBUGLEVEL
        )
        to_addr = user_entry['mail'][0].decode('utf-8')
        default_headers = (
            ('From', SMTP_FROM),
            ('Date', email.utils.formatdate(time.time(), True)),
        )
        #-----------------------------------------------------------------------
        # First send notification to admin if PWD_ADMIN_LEN is non-zero
        #-----------------------------------------------------------------------
        if PWD_ADMIN_LEN:
            smtp_message_tmpl = read_template_file(EMAIL_TEMPLATE_ADMIN)
            user_data_admin = {
                'username':username,
                'temppassword2':temp_pwd_clear[
                    len(temp_pwd_clear)-PWD_ADMIN_LEN:
                ],
                'remote_ip':self.remote_ip,
                'fromaddr':SMTP_FROM,
                'userdn':user_dn.decode('utf-8'),
                'web_ctx_host':web.ctx.host,
                'app_path_prefix':APP_PATH_PREFIX,
                'ldap_uri':self.ldap_conn.ldap_url_obj.initializeUrl(),
            }
            smtp_message = smtp_message_tmpl % user_data_admin
            smtp_subject = EMAIL_SUBJECT_ADMIN % user_data_admin
            admin_addrs = self._get_admin_mailaddrs(user_dn)
            smtp_conn.send_simple_message(
                SMTP_FROM,
                admin_addrs,
                'utf-8',
                default_headers+(
                    ('Subject', smtp_subject),
                    ('To', ','.join(admin_addrs)),
                ),
                smtp_message,
            )
        #-----------------------------------------------------------------------
        # Now send (rest of) clear-text password to user
        #-----------------------------------------------------------------------

        smtp_message_tmpl = read_template_file(EMAIL_TEMPLATE_PERSONAL)
        user_data_user = {
            'username':username,
            'temppassword1':temp_pwd_clear[:len(temp_pwd_clear)-PWD_ADMIN_LEN],
            'remote_ip':self.remote_ip,
            'fromaddr':SMTP_FROM,
            'userdn':user_dn.decode('utf-8'),
            'web_ctx_host':web.ctx.host,
            'app_path_prefix':APP_PATH_PREFIX,
            'ldap_uri':self.ldap_conn.ldap_url_obj.initializeUrl(),
        }
        smtp_message = smtp_message_tmpl % user_data_user
        smtp_subject = EMAIL_SUBJECT_PERSONAL % user_data_user
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

    def handle_user_request(self, user_dn, user_entry):
        """
        add password reset object class and attributes
        to user's entry and send e-mails
        """
        current_time = time.time()
        temp_pwd_clear = aedir.random_string(PWD_TMP_CHARS, PWD_LENGTH)
        temp_pwd_hash = pwd_hash(temp_pwd_clear)
        ldap_mod_list = [
            (
                ldap.MOD_REPLACE,
                'msPwdResetPasswordHash',
                [temp_pwd_hash],
            ),
            (
                ldap.MOD_REPLACE,
                'msPwdResetTimestamp',
                [ldap.strf_secs(current_time)]
            ),
            (
                ldap.MOD_REPLACE,
                'msPwdResetExpirationTime',
                [ldap.strf_secs(current_time+PWD_EXPIRETIMESPAN)]
            ),
            (
                ldap.MOD_REPLACE,
                'msPwdResetEnabled',
                [PWD_RESET_ENABLED]
            ),
        ]
        old_objectclasses = [
            oc.lower()
            for oc in user_entry['objectClass']
        ]
        if not 'mspwdresetobject' in old_objectclasses:
            ldap_mod_list.append(
                (ldap.MOD_ADD, 'objectClass', ['msPwdResetObject'])
            )
        if PWD_ADMIN_LEN:
            ldap_mod_list.append(
                (
                    ldap.MOD_REPLACE,
                    'msPwdResetAdminPw',
                    [temp_pwd_clear[-PWD_ADMIN_LEN:].encode('utf-8')]
                ),
            )
        try:
            self.ldap_conn.modify_ext_s(
                user_dn,
                ldap_mod_list,
                serverctrls=[self._sess_track_ctrl()],
            )
        except ldap.LDAPError:
            res = self.GET(message=u'Internal error!')
        else:
            try:
                self._send_pw(
                    self.form.d.username,
                    user_dn,
                    user_entry,
                    temp_pwd_clear,
                )
            except (socket.error, smtplib.SMTPException):
                res = self.GET(message=u'Error sending e-mail via SMTP!')
            else:
                res = RENDER.requestpw_action(
                    self.form.d.username,
                    self.form.d.email,
                    user_dn
                )
        return res


class FinishPasswordReset(BaseApp):
    """
    Handler for finishing password reset procedure
    """

    filterstr_template = '(&(msPwdResetEnabled=TRUE)%s)' % (FILTERSTR_RESETPW)

    get_form = web.form.Form(
        USERNAME_FIELD,
        TEMP1PASSWORD_FIELD,
    )

    post_form = web.form.Form(
        USERNAME_FIELD,
        TEMP1PASSWORD_FIELD,
        TEMP2PASSWORD_FIELD,
        NEWPASSWORD1_FIELD,
        NEWPASSWORD2_FIELD,
        web.form.Button(
            'submit',
            type='submit',
            description=u'Change password'
        ),
        validators=[NEWPASSWORD_VALIDATOR],
    )

    def GET(self, message=u''):
        """
        handle GET request by returning input form with username and
        1st temporary password part pre-filled
        """
        try:
            get_input = web.input(username=u'', temppassword1=u'')
        except UnicodeError:
            return RENDER.resetpw_form(u'', u'', u'Invalid input')
        else:
            return RENDER.resetpw_form(
                get_input.username,
                PWD_LENGTH-PWD_ADMIN_LEN,
                PWD_ADMIN_LEN,
                get_input.temppassword1,
                message
            )

    def _ldap_user_operations(self, user_dn, temp_pwd_hash, new_password_ldap):
        ldap_mod_list = [
            (ldap.MOD_DELETE, attr_type, attr_values)
            for attr_type, attr_values in (
                ('objectClass', ['msPwdResetObject']),
                ('msPwdResetPasswordHash', [temp_pwd_hash]),
                ('msPwdResetTimestamp', None),
                ('msPwdResetExpirationTime', None),
                ('msPwdResetEnabled', None),
            )
        ]
        ldap_mod_list.append(
            (ldap.MOD_REPLACE, 'userPassword', [new_password_ldap]),
        )
        if PWD_ADMIN_LEN:
            ldap_mod_list.append(
                (ldap.MOD_DELETE, 'msPwdResetAdminPw', None)
            )
        self.ldap_conn.modify_ext_s(
            user_dn,
            ldap_mod_list,
            serverctrls=[self._sess_track_ctrl(user_dn)],
        )
        return

    def handle_user_request(self, user_dn, user_entry):
        """
        set new password if temporary reset password matches
        """
        temppassword1 = self.form.d.temppassword1
        temppassword2 = self.form.d.temppassword2
        if len(temppassword1)+len(temppassword2) != PWD_LENGTH:
            return self.GET(message=u'Temporary password parts wrong!')
        temp_pwd_hash = pwd_hash(
            u''.join((
                self.form.d.temppassword1,
                self.form.d.temppassword2,
            )).encode('utf-8')
        )
        new_password_ldap = self.form.d.newpassword1.encode('utf-8')
        try:
            self._ldap_user_operations(
                user_dn,
                temp_pwd_hash,
                new_password_ldap
            )
        except ldap.NO_SUCH_ATTRIBUTE:
            res = self.GET(message=u'Temporary password wrong!')
        except ldap.CONSTRAINT_VIOLATION:
            res = self.GET(
                message=(
                    u'Constraint violation! '
                    u'Probably password rules violated.'
                )
            )
        except ldap.LDAPError:
            res = self.GET(message=u'Internal error!')
        else:
            res = RENDER.resetpw_action(self.form.d.username, user_dn)
        return res


def run():
    """
    run the web application
    """
    # Initialize web application
    app = web.application(URL2CLASS_MAPPING, globals())
    # Change to directory where the script is located
    os.chdir(os.path.dirname(sys.argv[0]))
    # Set error handling
    if not WEB_ERROR:
        app.internalerror = False
    # Start the internal web server
    app.run()


if __name__ == '__main__':
    run()
