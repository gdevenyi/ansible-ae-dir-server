# -*- coding: utf-8 -*-
"""
ansible module for adding aeHost entries to Æ-DIR

Copyright: (c) 2020, Michael Stroeder <michael@stroeder.com>
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: aehost

short_description: Create or update an aeHost entry

description:
    - "This module creates/updates aeHost entries"

options:
    name:
        description:
            - Hostname to put in attribute 'cn'
        required: true
    host:
        description:
            - Fully-qualified domain name to put in attribute 'host'
        required: true
    srvgroup:
        description:
            - name of parent aeSrvGroup entry
        required: true
    description:
        description:
            - Purpose description of aeHost object
        required: false
    ldapurl:
        description:
            - LDAP URI of Æ-DIR server (default ldapi://)
        required: false

author:
    - Michael Stroeder <michael@stroeder.com>
'''

EXAMPLES = '''
# Pass in a message
- name: "Create aeHost for host1.example.com"
  aehost:
    name: host1
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
    from aedir.models import AEHost, AEStatus
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
        state=dict(
            required=False,
            default='present',
            choices=['present', 'reset', 'absent'],
            type='str'
        ),
        host=dict(type='str', required=False),
        srvgroup=dict(type='str', required=True),
        description=dict(type='str', required=False),
        ldapurl=dict(
            required=False,
            default='ldapi://%2Fopt%2Fae-dir%2Frun%2Fslapd%2Fldapi',
            type='str'
        ),
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

    if module.params['host'] is None:
        module.params['host'] = module.params['name']

    ae_srvgroup = ldap_conn.find_aesrvgroup(module.params['srvgroup'])

    ae_host = AEHost(
        parent_dn=ae_srvgroup.dn_o,
        cn=module.params['name'],
        aeStatus=AEStatus.active,
        host=module.params['host'],
        description=module.params['description'],
        pwdPolicySubentry=DNObj.from_str('cn=ppolicy-systems,cn=ae,'+ldap_conn.search_base),
    )

    message = ''
    changed = False

    if state == 'absent':

        ldap_conn.delete_s(ae_host.dn_s)

        module.exit_json(
            changed=True,
            original_message=module.params['name'],
            message='Deleted entry %r' % (ae_host.dn_s),
            dn=ae_host.dn_s,
        )

    ldap_ops = ldap_conn.ensure_entry(
        ae_host.dn_s,
        ae_host.ldap_entry(),
        old_attrs=list(AEHost.__must__|AEHost.__may__)
    )
    if ldap_ops:
        message = '%d LDAP operations on %r' % (len(ldap_ops), ae_host.dn_s,)
        changed = True

    new_password = None

    if (
            state == 'reset'
            or ldap_ops and ldap_ops[0].rtype == ldap0.RES_ADD
        ):
        _, new_password = ldap_conn.set_password(module.params['host'], None)
        message='Set new password for %r' % (ae_host.dn_s,)
        changed = True


    # finally return a result message to ansible
    module.exit_json(
        changed=changed,
        original_message=module.params['name'],
        message=message,
        password=new_password,
        dn=ae_host.dn_s,
        cn=ae_host.cn,
    )


if __name__ == '__main__':
    main()
