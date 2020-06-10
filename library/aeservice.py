# -*- coding: utf-8 -*-
"""
ansible module for adding aeService entries to Æ-DIR

Copyright: (c) 2020, Michael Stroeder <michael@stroeder.com>
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: aeservice

short_description: Create or update an aeService entry

description:
    - "This module creates/updates aeService entries"

options:
    name:
        description:
            - Value to put in attribute 'cn'
        required: true
    state:
        description:
            - The target state of the entry.
        required: false
        choices: [present, absent]
        default: present
    uid_number:
        description:
            - Numeric POSIX-UID
        required: false
    gid_number:
        description:
            - Numeric POSIX-UID
        required: false
    host:
        description:
            - DN of aeService entry where the service runs on
        required: false
    zone:
        description:
            - name of parent aeZone entry
        required: false
    srvgroup:
        description:
            - name of parent aeSrvGroup entry
        required: false
    groups:
        description:
            - names of user groups to add the service to
        required: false
    description:
        description:
            - Purpose description of aeService object
        required: false
    home_directory:
        description:
            - Home directory (default /home/<user name>)
        required: false
    login_shell:
        description:
            - Login shell (default /usr/sbin/nologin)
        required: false
    ldapurl:
        description:
            - LDAP URI of Æ-DIR server (default ldapi://)
        required: false
    ticket_id:
        description:
            - Value for attribute aeTicketId
        required: false
    ppolicy:
        description:
            - DN of the pwdPolicySubentry entry (default cn=ppolicy-systems,cn=ae,<aedir_suffix>)
        required: false
    see_also:
        description:
            - Value for seeAlso attribute, e.g. used for subject DN of TLS server cert
        required: false

author:
    - Michael Stroeder <michael@stroeder.com>
'''

EXAMPLES = '''
# Pass in a message
- name: "Create aeService for host1.example.com"
  aeservice:
    name: www_host1
    host: host1.example.com
    description: "Example host for owner John Doe"
'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
message:
    description: The output message that the sample module generates
'''

import logging
import os
import uuid

from ansible.module_utils.basic import AnsibleModule

try:
    import aedir
    from aedir import AEDirObject
    from aedir.models import AEService, AEStatus
    import ldap0
    from ldap0 import LDAPError
    from ldap0.dn import DNObj
except ImportError:
    HAS_AEDIR = False
else:
    HAS_AEDIR = True


def get_module_args():
    return dict(
        name=dict(type='str', required=True),
        uid_number=dict(type='int', required=False),
        gid_number=dict(type='int', required=False),
        state=dict(
            required=False,
            default='present',
            choices=['present', 'absent'],
            type='str'
        ),
        host=dict(type='str', required=False),
        zone=dict(type='str', required=False),
        srvgroup=dict(type='str', required=False),
        groups=dict(type='list', required=False),
        description=dict(type='str', required=False),
        ticket_id=dict(type='str', required=False),
        home_directory=dict(type='str', required=False),
        login_shell=dict(type='str', default='/usr/sbin/nologin', required=False),
        ldapurl=dict(
            required=False,
            default='ldapi://%2Fopt%2Fae-dir%2Frun%2Fslapd%2Fldapi',
            type='str'
        ),
        ppolicy=dict(type='str', required=False),
        see_also=dict(type='str', required=False),
    )


def main():

    # set log level
    logger = logging.getLogger()
    logger.setLevel(os.environ.get('LOG_LEVEL', logging.ERROR))

    module = AnsibleModule(
        argument_spec=get_module_args(),
        supports_check_mode=True
    )

    # we exit here when in check mode
    if module.check_mode:
        module.exit_json(
            changed=False,
            original_message=module.params['name'],
            message='Nothing done in check mode',
        )

    changed = False

    if not HAS_AEDIR:
        module.fail_json(msg="Missing required 'aedir' module (pip install aedir).")

    state = module.params['state']

    ldap_url = module.params['ldapurl']

    # open LDAP connection to AD domain controller
    try:
        ldap_conn = AEDirObject(ldap_url)
    except LDAPError as ldap_err:
        module.fail_json(msg='Error connecting to %r: %s' % (ldap_url, ldap_err))

    logging.debug(
        'Successfully bound to %s as %r',
        ldap_conn.uri,
        ldap_conn.whoami_s(),
    )

    if module.params['ppolicy'] is None:
        module.params['ppolicy'] = 'cn=ppolicy-systems,cn=ae,'+ldap_conn.search_base

    if module.params['home_directory'] is None:
        module.params['home_directory'] = '/home/{}'.format(module.params['name'])

    if module.params['srvgroup']:
        parent_dn = ldap_conn.find_aesrvgroup(module.params['srvgroup']).dn_o
    elif module.params['zone']:
        parent_dn = DNObj(((('cn', module.params['zone']),),)) + DNObj.from_str(ldap_conn.search_base)
    else:
        module.fail_json(msg="Either 'zone' or 'srvgroup' must be set.")

    host_dn = None
    if module.params['host']:
        host_dn = ldap_conn.find_aehost(module.params['host']).dn_o

    ae_service = AEService(
        parent_dn=parent_dn,
        cn=module.params['name'],
        uid=module.params['name'],
        uidNumber=-1,
        gidNumber=-1,
        homeDirectory=module.params['home_directory'],
        loginShell=module.params['login_shell'],
        aeHost=host_dn,
        aeTicketId=module.params['ticket_id'],
        aeStatus=AEStatus.active,
        description=module.params['description'],
        pwdPolicySubentry=DNObj.from_str(module.params['ppolicy']),
    )

    if module.params['uid_number'] is None and module.params['gid_number'] is None:
        try:
            old = ldap_conn.read_s(ae_service.dn_s, attrlist=['uidNumber', 'gidNumber'])
        except ldap0.NO_SUCH_OBJECT:
            posix_id = ldap_conn.get_next_id()
            ae_service.uidNumber = ae_service.gidNumber = posix_id
        else:
            ae_service.uidNumber = int(old.entry_s['uidNumber'][0])
            ae_service.gidNumber = int(old.entry_s['gidNumber'][0])

    if module.params['see_also']:
        ae_service.objectClass.add('pkiUser')
        ae_service.seeAlso = [DNObj.from_str(module.params['see_also'])]

    message = ''
    changed = False

    if state == 'absent':

        ldap_conn.delete_s(ae_service.dn_s)

        module.exit_json(
            changed=True,
            original_message=module.params['name'],
            message='Deleted entry %r' % (ae_service.dn_s),
            dn=ae_service.dn_s,
        )

    try:
        ldap_ops = ldap_conn.ensure_entry(
            ae_service.dn_s,
            ae_service.ldap_entry(),
            old_attrs=list((AEService.__must__|AEService.__may__)-frozenset(('userPassword',))),
        )
    except LDAPError as ldap_err:
        module.fail_json(
            msg='LDAP operations on entry {0} failed: {1}'.format(
                ae_service.dn_s,
                ldap_err,
            )
        )

    if ldap_ops:
        message = '%d LDAP operations on %r' % (len(ldap_ops), ae_service.dn_s,)
        changed = True

    # finally return a result message to ansible
    module.exit_json(
        changed=changed,
        original_message=module.params['name'],
        message=message,
        dn=ae_service.dn_s,
        cn=ae_service.cn,
        ppolicy=str(ae_service.pwdPolicySubentry),
    )


if __name__ == '__main__':
    main()
