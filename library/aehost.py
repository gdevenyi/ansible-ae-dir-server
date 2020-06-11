# -*- coding: utf-8 -*-
"""
ansible module for adding aeHost entries to Æ-DIR

Copyright: (c) 2020, Michael Stroeder <michael@stroeder.com>
"""

from ansible.module_utils.basic import AnsibleModule

try:
    from aedir import AEDirObject
    from aedir.models import AEHost, AEStatus
    import ldap0
    from ldap0 import LDAPError
    from ldap0.dn import DNObj
except ImportError:
    HAS_AEDIR = False
else:
    HAS_AEDIR = True


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
    state:
        description:
            - The target state of the entry.
        required: false
        choices: [present, absent, reset]
        default: present
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
    ticket_id:
        description:
            - Value for attribute aeTicketId
        required: false
    ppolicy:
        description:
            - DN of the pwdPolicySubentry entry (default cn=ppolicy-systems,cn=ae,<aedir_suffix>)
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

def get_module_args():
    """
    returns dict with ansible module argument declaration
    """
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
        ticket_id=dict(type='str', required=False),
        ldapurl=dict(
            required=False,
            default='ldapi://%2Fopt%2Fae-dir%2Frun%2Fslapd%2Fldapi',
            type='str'
        ),
        ppolicy=dict(
            required=False,
            type='str'
        ),
    )


def main():
    """
    actually do the stuff
    """

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

    if module.params['host'] is None:
        module.params['host'] = module.params['name']

    if module.params['ppolicy'] is None:
        module.params['ppolicy'] = 'cn=ppolicy-systems,cn=ae,'+ldap_conn.search_base

    ae_srvgroup = ldap_conn.find_aesrvgroup(module.params['srvgroup'])

    ae_host = AEHost(
        parent_dn=ae_srvgroup.dn_o,
        cn=module.params['name'],
        host=module.params['host'],
        aeTicketId=module.params['ticket_id'],
        aeStatus=AEStatus.active,
        description=module.params['description'],
        pwdPolicySubentry=DNObj.from_str(module.params['ppolicy']),
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

    try:
        ldap_ops = ldap_conn.ensure_entry(
            ae_host.dn_s,
            ae_host.ldap_entry(),
            old_attrs=list((AEHost.__must__|AEHost.__may__)-frozenset(('userPassword',))),
        )
    except LDAPError as ldap_err:
        module.fail_json(
            msg='LDAP operations on entry {0} failed: {1}'.format(
                ae_host.dn_s,
                ldap_err,
            )
        )

    if ldap_ops:
        message = '%d LDAP operations on %r' % (len(ldap_ops), ae_host.dn_s,)
        changed = True

    new_password = None

    if (
            state == 'reset'
            or (ldap_ops and ldap_ops[0].rtype == ldap0.RES_ADD)
        ):
        _, new_password = ldap_conn.set_password(module.params['host'], None)
        message = 'Set new password for {0!r}'.format(ae_host.dn_s)
        changed = True


    # finally return a result message to ansible
    module.exit_json(
        changed=changed,
        original_message=module.params['name'],
        message=message,
        password=new_password,
        dn=ae_host.dn_s,
        cn=ae_host.cn,
        ppolicy=str(ae_host.pwdPolicySubentry),
    )


if __name__ == '__main__':
    main()
