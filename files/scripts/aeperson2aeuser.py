#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Sync the personnel attributes (cn, sn, givenName, mail)
from aePerson to aeUser entries
"""

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# Modules from Python's standard library
import sys
import os
import time
import logging
from logging.handlers import SysLogHandler

# set LDAPRC env var *before* importing ldap
os.environ['LDAPRC'] = '/opt/ae-dir/etc/ldap.conf'
# Import python-ldap modules/classes
import ldap
import ldap.modlist
from ldap.filter import time_span_filter

import aedir
import aedir.process

#-----------------------------------------------------------------------
# Constants (configuration)
#-----------------------------------------------------------------------

__version__ = '0.1.0'

# python-ldap trace level
PYLDAP_TRACELEVEL = int(os.environ.get('PYLDAP_TRACELEVEL', '0'))

# List of attributes copied from aePerson to aeUser entries
AEDIR_AEPERSON_ATTRS = [
    'cn',
    'givenName',
    'sn',
    'mail',
    'aeStatus'
]

# Exception class used for catching all exceptions
CatchAllException = Exception

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


class SyncProcess(aedir.process.AEProcess):
    """
    The sync process
    """
    script_version = __version__
    pyldap_tracelevel = PYLDAP_TRACELEVEL

    def __init__(self, state_filename, max_runs=1, run_sleep=60.0):
        self.state_filename = state_filename
        self.aeperson_counter = 0
        self.modify_counter = 0
        self.error_counter = 0
        self.deactivate_counter = 0
        self.current_time = time.time()
        # must be called last since it also calls method _run()
        aedir.process.AEProcess.__init__(self, max_runs=max_runs, run_sleep=run_sleep)

    def get_state(self):
        """
        Read the timestamp of last run from file `sync_state_filename'
        """
        try:
            last_run_timestr = open(self.state_filename, 'rb').read().strip()
        except CatchAllException, err:
            self.logger.warn(
                'Error reading file %r: %s',
                self.state_filename,
                err
            )
            last_run_timestr = None
        else:
            self.logger.debug(
                'Read last run timestamp %r from file %r',
                last_run_timestr,
                self.state_filename,
            )
        last_run_timestr = last_run_timestr or None
        last_run_time = 0
        if last_run_timestr:
            try:
                last_run_time = ldap.strp_secs(last_run_timestr)
            except ValueError, err:
                self.logger.warn(
                    'Error parsing timestamp %r: %s',
                    last_run_timestr,
                    err,
                )
        return last_run_time # get_state()

    def set_state(self, current_time):
        """
        Write the current state
        """
        current_time_str = ldap.strf_secs(self.current_time)
        try:
            # Write the last run timestamp
            open(self.state_filename, 'wb').write(current_time_str)
        except CatchAllException, err:
            self.logger.warn(
                'Could not write %r: %s',
                self.state_filename,
                err,
            )
        else:
            self.logger.debug(
                'Wrote %r to %r',
                current_time_str,
                self.state_filename,
            )
        return # set_state()

    def exit(self):
        """
        Log a summary of actions and errors, mainly counters
        """
        self.logger.debug('Found %d aePerson entries', self.aeperson_counter)
        if self.modify_counter:
            self.logger.info(
                'Updated %d AE-DIR entries (%d deactivated).',
                self.modify_counter,
                self.deactivate_counter
            )
        else:
            self.logger.debug('No modifications.')
        if self.error_counter:
            self.logger.error('%d errors.', self.error_counter)

    def run_worker(self):
        """
        the main worker part
        """

        # Determine current state
        #-----------------------------------------------------------------------

        last_run_time = self.get_state()
        self.logger.debug(
            'current_time=%r last_run_time=%r',
            self.current_time,
            last_run_time,
        )

        # Update aeUser entries
        #-----------------------------------------------------------------------

        aeperson_filterstr = time_span_filter(
            '(objectClass=aePerson)',
            last_run_time,
            self.current_time
        )

        self.logger.debug(
            'Searching in %r with filter %r',
            self.ldap_conn.find_search_base(),
            aeperson_filterstr,
        )
        msg_id = self.ldap_conn.search(
            self.ldap_conn.find_search_base(),
            ldap.SCOPE_SUBTREE,
            aeperson_filterstr,
            attrlist=AEDIR_AEPERSON_ATTRS,
        )

        for _, res_data, _, _ in self.ldap_conn.allresults(msg_id):

            for aeperson_dn, aeperson_entry in res_data:

                self.aeperson_counter += 1

                aeuser_result = self.ldap_conn.search_s(
                    self.ldap_conn.find_search_base(),
                    ldap.SCOPE_SUBTREE,
                    '(&(objectClass=aeUser)(aePerson=%s))' % (aeperson_dn),
                    attrlist=AEDIR_AEPERSON_ATTRS+['uid', 'uidNumber', 'displayName'],
                )

                # Process the aeUser entries
                for aeuser_dn, aeuser_entry in aeuser_result:

                    new_aeuser_entry = {}
                    new_aeuser_entry.update(aeperson_entry)
                    del new_aeuser_entry['aeStatus']
                    new_aeuser_entry['displayName'] = ['{cn} ({uid}/{uidNumber})'.format(
                        cn=aeperson_entry['cn'][0],
                        uid=aeuser_entry['uid'][0],
                        uidNumber=aeuser_entry['uidNumber'][0],
                    )]

                    # Check whether aeStatus must be updated
                    # First preserve old status
                    aeperson_status = int(aeperson_entry['aeStatus'][0])
                    aeuser_status = int(aeuser_entry['aeStatus'][0])
                    if aeperson_status > 0 and aeuser_status <= 0:
                        new_aeuser_entry['aeStatus'] = '1'
                        self.deactivate_counter += 1
                    else:
                        new_aeuser_entry['aeStatus'] = aeuser_entry['aeStatus']

                    # Generate diff of general person attributes
                    modlist = ldap.modlist.modifyModlist(
                        aeuser_entry,
                        new_aeuser_entry,
                        ignore_attr_types=['uid', 'uidNumber']
                    )

                    if not modlist:
                        self.logger.debug(
                            'Nothing to do in %r => skipped',
                            aeuser_dn,
                        )
                    else:
                        self.logger.debug(
                            'Update existing entry %r: %r',
                            aeuser_dn,
                            modlist,
                        )
                        try:
                            self.ldap_conn.modify_s(aeuser_dn, modlist)
                        except ldap.LDAPError, ldap_err:
                            self.logger.error(
                                'LDAP error modifying %r: %s',
                                aeuser_dn,
                                ldap_err,
                            )
                            self.error_counter += 1
                        else:
                            self.logger.info(
                                'Updated entry %r: %r',
                                aeuser_dn,
                                modlist,
                            )
                            self.modify_counter += 1

        # Write state
        self.set_state(self.current_time)

        return # end of run_worker()


if __name__ == '__main__':
    SyncProcess(sys.argv[1], max_runs=1)
