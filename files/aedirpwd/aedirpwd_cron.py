#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This CRON script performs two tasks:
1. Remove expired msPwdResetObject attributes
2. Send welcome e-mail to new users which have not set a password yet

Author: Michael Ströder <michael@stroeder.com>
"""

__version__ = '0.2.0'

# from Python's standard lib
import sys
import os
import time
import smtplib
import email.utils
from socket import getfqdn
import logging
from logging.handlers import SysLogHandler

# from python-ldap
import ldap

# the separate mailutil module
import mailutil

# the separate python-aedir module
import aedir

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# Import constants from configuration module
sys.path.append(sys.argv[1])
from aedirpwd_cnf import *

# Logging level and log formats
SYSLOG_LOG_FORMAT = '%(levelname)s %(message)s'
if os.environ.get('DEBUG', 'no') == 'yes':
    LOG_LEVEL = logging.DEBUG
    CONSOLE_LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
else:
    LOG_LEVEL = logging.INFO
    CONSOLE_LOG_FORMAT = None

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


def combined_logger(
        log_name,
        log_level=logging.INFO,
        sys_log_format=None,
        sys_log_facility=None,
        console_log_format=None,
    ):
    """
    Returns a combined SysLogHandler/StreamHandler logging instance
    with formatters
    """

    # for writing to syslog
    new_logger = logging.getLogger(log_name)

    if sys_log_format:
        my_syslog_formatter = logging.Formatter(
            fmt=' '.join((log_name, sys_log_format)))
        my_syslog_handler = logging.handlers.SysLogHandler(
            address='/dev/log',
            facility=sys_log_facility or SysLogHandler.LOG_CRON,
        )
        my_syslog_handler.setFormatter(my_syslog_formatter)
        new_logger.addHandler(my_syslog_handler)

    if console_log_format:
        my_stream_formatter = logging.Formatter(fmt=console_log_format)
        my_stream_handler = logging.StreamHandler()
        my_stream_handler.setFormatter(my_stream_formatter)
        new_logger.addHandler(my_stream_handler)

    new_logger.setLevel(log_level)

    return new_logger  # end of combined_logger()


class AEDIRPwdJob(object):
    """
    Job instance
    """
    notify_oldest_timespan = NOTIFY_OLDEST_TIMESPAN
    user_attrs = [
        'objectClass',
        'uid',
        'cn',
        'displayName',
        'description',
        'mail',
        'creatorsName',
        'modifiersName'
    ]

    def __init__(self):
        script_name = sys.argv[0]
        self._log = combined_logger(
            script_name,
            log_level=LOG_LEVEL,
            sys_log_format=SYSLOG_LOG_FORMAT,
            sys_log_facility=None,
            console_log_format=CONSOLE_LOG_FORMAT,
        )
        self.host_fqdn = getfqdn()
        self.server_id = SERVER_ID
        self.notification_counter = 0
        self._ldap_conn = None
        self._ldap_conn_lock = ldap.LDAPLock(
            desc='_ldap_connection() in %s' % (repr(self.__class__))
        )
        self._smtp_conn = None
        self._log.debug(
            'Initializing %s %s on %s (%s)',
            script_name,
            __version__,
            self.host_fqdn,
            self.server_id,
        )

    def _get_time_strings(self):
        """
        Determine
        1. oldest possible last timestamp (sounds strange, yeah!)
        2. and current time
        """
        current_time = time.time()
        current_run_timestr = aedir.ldap_strf_secs(current_time)
        last_run_timestr = aedir.ldap_strf_secs(
            current_time-self.notify_oldest_timespan
        )
        return last_run_timestr, current_run_timestr

    def _smtp_connection(self):
        """
        Open SMTP connection if there's not one yet
        """
        if self._smtp_conn is not None:
            return self._smtp_conn
        self._log.debug(
            'Open SMTP connection to %r from %r',
            SMTP_URL,
            SMTP_LOCALHOSTNAME
        )
        self._smtp_conn = mailutil.smtp_connection(
            SMTP_URL, local_hostname=SMTP_LOCALHOSTNAME,
            tls_args=SMTP_TLSARGS,
            debug_level=SMTP_DEBUGLEVEL
        )
        return self._smtp_conn

    def _ldap_connection(self):
        """
        Open LDAP connection if there's not one yet
        """
        if isinstance(self._ldap_conn, aedir.AEDirObject):
            self._log.debug(
                'Reuse existing LDAP connection to %r bound as %r',
                str(self._ldap_conn.ldap_url_obj),
                self._ldap_conn.whoami_s(),
            )
            return self._ldap_conn
        try:
            self._ldap_conn_lock.acquire()
            try:
                self._ldap_conn = aedir.AEDirObject(PWD_LDAP_URL)
            except ldap.LDAPError, ldap_error:
                self._log.error(
                    'LDAPError during connecting to %r: %s',
                    PWD_LDAP_URL,
                    ldap_error,
                )
                raise
            else:
                self._log.debug(
                    'Successfully bound to %r as %r',
                    str(self._ldap_conn.ldap_url_obj),
                    self._ldap_conn.whoami_s(),
                )
        finally:
            self._ldap_conn_lock.release()
        return self._ldap_conn # end of _ldap_connection()

    def expire_pwd_reset(self, last_run_timestr, current_run_timestr):
        """
        Remove expired msPwdResetObject attributes
        """
        expiration_filterstr = (
            FILTERSTR_EXPIRE.format(
                currenttime=current_run_timestr,
                lasttime=last_run_timestr,
                serverid=self.server_id,
            )
        ).encode('utf-8')
        ldap_conn = self._ldap_connection()
        ldap_results = ldap_conn.search_ext_s(
            ldap_conn.ldap_url_obj.dn,
            ldap_conn.ldap_url_obj.scope,
            filterstr=expiration_filterstr,
            attrlist=[
                'objectClass',
                'msPwdResetExpirationTime',
                'msPwdResetTimestamp',
                'msPwdResetAdminPw',
            ],
        )
        for ldap_dn, ldap_entry in ldap_results:
            self._log.debug('Found %r: %r', ldap_dn, ldap_entry)
            # Prepare the modification list
            ldap_mod_list = [
                # explictly delete by value
                (
                    ldap.MOD_DELETE,
                    'objectClass',
                    ['msPwdResetObject']
                ),
                (
                    ldap.MOD_DELETE,
                    'msPwdResetTimestamp',
                    [ldap_entry['msPwdResetTimestamp'][0]]
                ),
                (
                    ldap.MOD_DELETE,
                    'msPwdResetExpirationTime',
                    [ldap_entry['msPwdResetExpirationTime'][0]]
                ),
                # delete whole value no matter what
                (ldap.MOD_DELETE, 'msPwdResetEnabled', None),
                (ldap.MOD_DELETE, 'msPwdResetPasswordHash', None),
            ]
            if PWD_ADMIN_LEN or 'msPwdResetAdminPw' in ldap_entry:
                ldap_mod_list.append(
                    (ldap.MOD_DELETE, 'msPwdResetAdminPw', None),
                )
            # Actually perform the modify operation
            try:
                ldap_conn.modify_s(ldap_dn, ldap_mod_list)
            except ldap.LDAPError, ldap_error:
                self._log.warn(
                    'LDAPError removing msPwdResetObject attrs in %r: %s',
                    ldap_dn,
                    ldap_error
                )
            else:
                self._log.info(
                    'Removed msPwdResetObject attributes from %r',
                    ldap_dn,
                )
            return # end of expire_pwd_reset()

    def _send_welcome_message(self, to_addr, smtp_message_tmpl, msg_attrs):
        """
        Send single welcome message for a user
        """
        self._log.debug('msg_attrs = %r', msg_attrs)
        smtp_conn = self._smtp_connection()
        smtp_message = smtp_message_tmpl.format(**msg_attrs)
        smtp_subject = NOTIFY_EMAIL_SUBJECT.format(**msg_attrs)
        self._log.debug('smtp_subject = %r', smtp_subject)
        self._log.debug('smtp_message = %r', smtp_message)
        try:
            smtp_conn.send_simple_message(
                SMTP_FROM,
                [to_addr.encode('utf-8')],
                'utf-8',
                (
                    ('From', SMTP_FROM),
                    ('Date', email.utils.formatdate(time.time(), True)),
                    ('Subject', smtp_subject),
                    ('To', to_addr),
                ),
                smtp_message,
            )
        except smtplib.SMTPRecipientsRefused, smtp_error:
            self._log.error(
                'Recipient %r rejected: %s',
                to_addr,
                smtp_error
            )
        else:
            self._log.info(
                'Sent notification for user %r with e-mail address %r',
                msg_attrs['user_displayname'],
                to_addr,
            )
            self.notification_counter += 1
        return # end of _send_welcome_message()

    def welcome_notifications(self, last_run_timestr, current_run_timestr):
        """
        Send welcome e-mail to new users which have not set a password yet
        """
        nopassword_filterstr = (
            FILTERSTR_NO_WELCOME_YET.format(
                currenttime=current_run_timestr,
                lasttime=last_run_timestr,
                serverid=self.server_id,
            )
        ).encode('utf-8')
        self._log.debug(
            'User search filter: %r',
            nopassword_filterstr,
        )
        ldap_conn = self._ldap_connection()
        ldap_results = ldap_conn.search_ext_s(
            ldap_conn.ldap_url_obj.dn,
            ldap_conn.ldap_url_obj.scope,
            filterstr=nopassword_filterstr,
            attrlist=self.user_attrs,
        )
        if not ldap_results:
            self._log.debug('No results => no notifications')
            return

        for ldap_dn, ldap_entry in ldap_results:
            to_addr = ldap_entry['mail'][0].decode('utf-8')
            self._log.debug(
                'Prepare notification for %r sent to %r',
                ldap_dn,
                to_addr,
            )
            smtp_message_tmpl = open(
                NOTIFY_EMAIL_TEMPLATE, 'rb'
            ).read().decode('utf-8')
            msg_attrs = {
                'ldap_uri':str(ldap_conn.ldap_url_obj.initializeUrl()),
                'user_uid':ldap_entry['uid'][0].decode('utf-8'),
                'user_cn':ldap_entry.get('cn', [''])[0].decode('utf-8'),
                'user_displayname':ldap_entry.get(
                    'displayName', ['']
                )[0].decode('utf-8'),
                'user_description':ldap_entry.get(
                    'description', ['']
                )[0].decode('utf-8'),
                'emailadr':to_addr,
                'fromaddr':SMTP_FROM,
                'user_dn':ldap_dn.decode('utf-8'),
                'web_ctx_host':(
                    WEB_CTX_HOST or self.host_fqdn
                ).decode('ascii'),
                'app_path_prefix':APP_PATH_PREFIX,
                'admin_cn':u'unknown',
                'admin_mail':u'unknown',
            }
            admin_dn = ldap_entry['creatorsName'][0]
            try:
                admin_entry = ldap_conn.read_s(
                    admin_dn,
                    filterstr=FILTERSTR_USER.encode('utf-8'),
                    attrlist=['objectClass', 'uid', 'cn', 'mail'],
                )
            except ldap.LDAPError, ldap_error:
                self._log.debug(
                    'LDAPError reading %r: %s',
                    admin_dn,
                    ldap_error
                )
                return
            if admin_entry is None:
                self._log.debug('No admin entry found for %r', admin_dn)
            msg_attrs['admin_cn'] = admin_entry.get(
                'cn', ['unknown']
            )[0].decode('utf-8')
            msg_attrs['admin_mail'] = admin_entry.get(
                'mail', ['unknown']
            )[0].decode('utf-8')
            self._send_welcome_message(to_addr, smtp_message_tmpl, msg_attrs)
            if NOTIFY_SUCCESSFUL_MOD:
                ldap_conn.modify_s(ldap_dn, NOTIFY_SUCCESSFUL_MOD)
        if self.notification_counter:
            self._log.info('Sent %d notifications', self.notification_counter)
        return # endof welcome_notifications()

    def run_once(self):
        """
        Run the job
        """
        try:
            last_run_timestr, current_run_timestr = self._get_time_strings()
            self.expire_pwd_reset(last_run_timestr, current_run_timestr)
            self.welcome_notifications(last_run_timestr, current_run_timestr)
        except Exception:
            self._log.error(
                'Unhandled exception:',
                exc_info=True
            )
        return # end of run_once()


def run():
    """
    the main function
    """
    aedirpwd_job = AEDIRPwdJob()
    aedirpwd_job.run_once()
    sys.exit(0)
    return # end of run()

if __name__ == '__main__':
    run()
