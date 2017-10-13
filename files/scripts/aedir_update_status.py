#!/opt/ae-dir/bin/python
# -*- coding: utf-8 -*-
"""
This script updates aeStatus of expired AE-DIR entries (aeObject)

It is designed to run as a CRON job.

Author: Michael Ströder <michael@stroeder.com>
"""

__version__ = '0.1.0'

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

import os
import time

# set LDAPRC env var *before* importing ldap
os.environ['LDAPRC'] = '/opt/ae-dir/etc/ldap.conf'
import ldap
import aedir
import aedir.process

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# python-ldap trace level
PYLDAP_TRACELEVEL = int(os.environ.get('PYLDAP_TRACELEVEL', '0'))

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEStatusUpdater(aedir.process.AEProcess):
    """
    Status update process class
    """
    script_version = __version__
    pyldap_tracelevel = PYLDAP_TRACELEVEL

    def __init__(self):
        aedir.process.AEProcess.__init__(self)
        self.aeobject_counter = 0
        self.modify_counter = 0
        self.error_counter = 0

    def exit(self):
        """
        Log a summary of actions and errors, mainly counters
        """
        self.logger.debug('Found %d auto-expiry AE-DIR entries', self.aeobject_counter)
        if self.modify_counter:
            self.logger.info('Modifed %d auto-expiry AE-DIR entries.', self.modify_counter)
        if self.error_counter:
            self.logger.error('%d errors.', self.error_counter)

    def run_worker(self, state):
        """
        the main program
        """
        current_time_str = ldap.strf_secs(time.time())
        self.logger.debug('current_time_str = %r', current_time_str)
        expiry_filter = (
          '(&'
            '(objectClass=aeObject)'
            '(aeNotAfter<={0})'
            '(|'
              '(&(aeStatus<=0)(aeExpiryStatus>=1))'
              '(&(aeStatus<=1)(aeExpiryStatus>=2))'
            ')'
          ')'
        ).format(current_time_str)
        self.logger.debug('expiry_filter = %r', expiry_filter)
        try:
            msg_id = self.ldap_conn.search(
                self.ldap_conn.find_search_base(),
                ldap.SCOPE_SUBTREE,
                expiry_filter,
                attrlist=['aeStatus', 'aeExpiryStatus'],
            )
        except ldap.LDAPError, ldap_error:
            self.logger.warn('LDAPError searching %r: %s', expiry_filter, ldap_error)
            return
        # process LDAP results
        for _, res_data, _, _ in self.ldap_conn.allresults(msg_id):
            for aeobj_dn, aeobj_entry in res_data:
                self.aeobject_counter += 1
                modlist = [
                    (ldap.MOD_DELETE, 'aeStatus', aeobj_entry['aeStatus']),
                    (ldap.MOD_ADD, 'aeStatus', aeobj_entry['aeExpiryStatus']),
                ]
                try:
                    self.ldap_conn.modify_s(
                        aeobj_dn,
                        [
                            (ldap.MOD_DELETE, 'aeStatus', aeobj_entry['aeStatus']),
                            (ldap.MOD_ADD, 'aeStatus', aeobj_entry['aeExpiryStatus']),
                        ]
                    )
                except ldap.LDAPError, ldap_error:
                    self.logger.warn('LDAPError modifying %r: %s', aeobj_dn, ldap_error)
                    self.error_counter += 1
                else:
                    self.logger.info('Updated aeStatus in %r: %s', aeobj_dn, modlist)
                    self.modify_counter += 1
        return # end of run_worker()


if __name__ == '__main__':
    with AEStatusUpdater() as ae_process:
        ae_process.run(max_runs=1)
