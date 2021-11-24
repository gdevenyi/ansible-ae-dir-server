# -*- coding: ascii -*-
"""
ansible module for adding aeHost entries to xC6-DIR

Copyright: (c) 2020-2021, Michael Stroeder <michael@stroeder.com>
"""

import getpass

from ansible.module_utils.basic import AnsibleModule

try:
    from aedir import AEDirObject
    from aedir.models import AEHost, AEStatus
    import ldap0
    from ldap0 import LDAPError
    from ldap0.dn import DNObj
    from ldap0.filter import escape_str as escape_filter_str, map_filter_parts
except ImportError:
    HAS_AEDIR = False
else:
    HAS_AEDIR = True

# set of attribute types ignored when modifying aeHost entry
IGNORED_AEHOST_ATTRS = frozenset((
    'aeExpiryStatus',
    'aeHwSerialNumber',
    'aeLocation',
    'aeNotAfter',
    'aeNotBefore',
    'aeOwner',
    'aeRemoteHost',
    'aeStockId',
    'aeTag',
    'displayName',
    'l',
    'serialNumber',
    'sshPublicKey',
    'userPassword',
))

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: aehost

short_description: Create or update an aeHost entries in xC6-DIR

description:
    - "This module creates/updates aeHost entries in xC6-DIR"

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
        required: false
    srvgroup:
        description:
            - Name of parent aeSrvGroup entry beneath which to add new aeHost entry.
              If not set an existing aeHost entry will be searched.
        required: false
    srvgroups:
        description:
            - names of supplemental aeSrvGroup entries to be added
              to attribute aeSrvGroup in aeHost entry
        required: false
    description:
        description:
            - Purpose description of aeHost object
        required: false
    ticket_id:
        description:
            - Value for attribute aeTicketId
        required: false
    ppolicy:
        description:
            - DN to put in attribute pwdPolicySubentry
              (default cn=ppolicy-systems,cn=ae,<aeRoot>)
        required: false
    ldapurl:
        description:
            - LDAP URI of xC6-DIR server
        required: false
        default: "ldapi://%2Fopt%2Fae-dir%2Frun%2Fslapd%2Fldapi"
    binddn:
        description:
            - Bind-DN used for authentication with simple bind.
        required: false
    bindpw:
        description:
            - Password used for authentication with simple bind.
        required: false
    cacert:
        description:
            - Path name of trusted CA certificate bundle file.
        required: false
    clcert:
        description:
            - Path name of client certificate to be used for SASL/EXTERNAL bind.
        required: false
    clkey:
        description:
            - Path name of client key to be used for SASL/EXTERNAL bind.
        required: false
    askotp:
        description:
            - If set to yes, the module asks interactively for an OTP part
              used for binding as setup admin.
        required: false
        default: no

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
        # LDAP connection arguments
        ldapurl=dict(
            required=False,
            default='ldapi://%2Fopt%2Fae-dir%2Frun%2Fslapd%2Fldapi',
            type='str'
        ),
        binddn=dict(type='str', required=False),
        bindpw=dict(type='str', required=False),
        cacert=dict(type='str', required=False),
        clcert=dict(type='str', required=False),
        clkey=dict(type='str', required=False),
        askotp=dict(type='bool', default=False, required=False),
        # general arguments
        name=dict(type='str', required=True),
        state=dict(
            required=False,
            default='present',
            choices=['present', 'reset', 'absent'],
            type='str'
        ),
        ticket_id=dict(type='str', required=False),
        description=dict(type='str', required=False),
        ppolicy=dict(
            required=False,
            type='str'
        ),
        host=dict(type='str', required=False),
        srvgroup=dict(type='str', required=False),
        srvgroups=dict(type='list', default=[], required=False),
        object_classes=dict(type='list', default=list(AEHost.__object_classes__), required=False),
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

    if module.params['binddn'] and module.params['bindpw'] and module.params['askotp']:
        otp_value = getpass.getpass('Enter OTP:')
        bind_password = module.params['bindpw'] + otp_value
    else:
        bind_password = module.params['bindpw']

    # Open LDAP connection to AE-DIR provider
    try:
        ldap_conn = AEDirObject(
            module.params['ldapurl'],
            who=module.params['binddn'],
            cred=bind_password,
            cacert_filename=module.params['cacert'],
            client_cert_filename=module.params['clcert'],
            client_key_filename=module.params['clkey'],
        )
    except LDAPError as ldap_err:
        module.fail_json(msg='Error connecting to %r: %s' % (module.params['ldapurl'], ldap_err))

    if module.params['host'] is None:
        module.params['host'] = module.params['name']

    if module.params['ppolicy'] is None:
        module.params['ppolicy'] = 'cn=ppolicy-systems,cn=ae,'+ldap_conn.search_base

    if module.params['srvgroup'] is None:
        parent_dn = ldap_conn.find_aehost(module.params['host']).dn_o.parent()
    else:
        ae_srvgroup = ldap_conn.find_aesrvgroup(module.params['srvgroup'])
        parent_dn = ae_srvgroup.dn_o

    if module.params['srvgroups']:
        srv_groups_filter = '(&(objectClass=aeSrvGroup)(|{0}))'.format(
            ''.join(map_filter_parts(
                'cn',
                [
                    grp_name
                    for grp_name in module.params['srvgroups']
                    if grp_name
                ],
            )),
        )
        try:
            ldap_res = ldap_conn.search_s(
                ldap_conn.search_base,
                ldap0.SCOPE_SUBTREE,
                filterstr=srv_groups_filter,
                attrlist=['1.1'],
            )
        except LDAPError as ldap_err:
            module.fail_json(
                msg='Searching host groups with filter {0!r} failed: {1}'.format(
                    srv_groups_filter,
                    ldap_err,
                )
            )
        else:
            srv_groups = [res.dn_o for res in ldap_res]
    else:
        srv_groups = []

    ae_host = AEHost(
        parent_dn=parent_dn,
        objectClass=set(module.params['object_classes']),
        cn=module.params['name'],
        host=module.params['host'],
        aeTicketId=module.params['ticket_id'],
        aeSrvGroup=srv_groups,
        aeStatus=AEStatus.active,
        description=module.params['description'],
        pwdPolicySubentry=DNObj.from_str(module.params['ppolicy']),
    )

    # deleting the entry can be done right now
    if module.params['state'] == 'absent':
        ldap_conn.delete_s(ae_host.dn_s)
        module.exit_json(
            changed=True,
            original_message=module.params['name'],
            message='Deleted entry %r' % (ae_host.dn_s),
            who=ldap_conn.get_whoami_dn(),
            dn=ae_host.dn_s,
        )

    message = ''
    changed = False

    try:
        ldap_ops = ldap_conn.ensure_entry(
            ae_host.dn_s,
            ae_host.ldap_entry(),
            old_attrs=list((AEHost.__must__|AEHost.__may__)-IGNORED_AEHOST_ATTRS),
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
            module.params['state'] == 'reset'
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
        who=ldap_conn.get_whoami_dn(),
        password=new_password,
        dn=ae_host.dn_s,
        cn=ae_host.cn,
        ppolicy=str(ae_host.pwdPolicySubentry),
    )


if __name__ == '__main__':
    main()
