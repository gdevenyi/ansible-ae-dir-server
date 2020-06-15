# -*- coding: utf-8 -*-
"""
ansible module for adding aeService entries to Æ-DIR

Copyright: (c) 2020, Michael Stroeder <michael@stroeder.com>
"""

from ansible.module_utils.basic import AnsibleModule

try:
    from aedir import AEDirObject
    from aedir.models import AEService, AEStatus
    import ldap0
    from ldap0 import LDAPError
    from ldap0.filter import escape_str as escape_filter_str
    from ldap0.filter import map_filter_parts
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
module: aeservice

short_description: Create or update an aeService entry

description:
    - "This module creates/updates aeService entries"

options:
    name:
        description:
            - Value to put in attribute 'cn'
        required: true
    uid:
        description:
            - Value to put in attribute 'uid' (default is name:)
        required: false
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
            - names of user groups to add the service to (empty names and non-existent group names are silently ignored)
        required: false
    object_classes:
        description:
            - names of objectClass values to set
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
            - LDAP URI of Æ-DIR server (default ldapi://%2Fopt%2Fae-dir%2Frun%2Fslapd%2Fldapi)
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
        # general arguments
        name=dict(type='str', required=True),
        state=dict(
            required=False,
            default='present',
            choices=['present', 'absent'],
            type='str'
        ),
        ticket_id=dict(type='str', required=False),
        description=dict(type='str', required=False),
        ppolicy=dict(type='str', required=False),
        uid=dict(type='str', required=False),
        uid_number=dict(type='int', required=False),
        gid_number=dict(type='int', required=False),
        host=dict(type='str', required=False),
        srvgroup=dict(type='str', required=False),
        zone=dict(type='str', required=False),
        groups=dict(type='list', default=[], required=False),
        home_directory=dict(type='str', required=False),
        login_shell=dict(type='str', default='/usr/sbin/nologin', required=False),
        see_also=dict(type='str', required=False),
        object_classes=dict(type='list', default=list(AEService.__object_classes__), required=False),
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

    if not HAS_AEDIR:
        module.fail_json(msg="Missing required 'aedir' module (pip install aedir).")

    # Open LDAP connection to AE-DIR provider
    try:
        ldap_conn = AEDirObject(
            module.params['ldapurl'],
            who=module.params['binddn'],
            cred=module.params['bindpw'],
        )
    except LDAPError as ldap_err:
        module.fail_json(msg='Error connecting to %r: %s' % (module.params['ldapurl'], ldap_err))

    if module.params['ppolicy'] is None:
        module.params['ppolicy'] = 'cn=ppolicy-systems,cn=ae,'+ldap_conn.search_base

    if module.params['uid'] is None:
        module.params['uid'] = module.params['name']

    if module.params['home_directory'] is None:
        module.params['home_directory'] = '/home/{}'.format(module.params['name'])

    if module.params['srvgroup']:
        parent_dn = ldap_conn.find_aesrvgroup(module.params['srvgroup']).dn_o
    elif module.params['zone']:
        parent_dn = (
            DNObj(((('cn', module.params['zone']),),))
            + DNObj.from_str(ldap_conn.search_base)
        )
    else:
        module.fail_json(msg="Either 'zone' or 'srvgroup' must be set.")

    host_dn = None
    if module.params['host']:
        host_dn = ldap_conn.find_aehost(module.params['host']).dn_o

    ae_service = AEService(
        parent_dn=parent_dn,
        objectClass=set(module.params['object_classes']),
        cn=module.params['name'],
        uid=module.params['uid'],
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
    else:
        ae_service.uidNumber = module.params['uid_number']
        ae_service.gidNumber = module.params['gid_number']

    if module.params['see_also']:
        ae_service.objectClass.add('pkiUser')
        ae_service.seeAlso = [DNObj.from_str(module.params['see_also'], at_sanitizer=str.lower)]

    message = ''

    if module.params['state'] == 'absent':

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
            old_base=ldap_conn.search_base,
            old_filter='(|(uid={0})(uidNumber={1}))'.format(
                escape_filter_str(ae_service.uid),
                escape_filter_str(str(ae_service.uidNumber)),
            ),
            old_attrs=list((AEService.__must__|AEService.__may__)-frozenset(('userPassword',))),
        )
    except LDAPError as ldap_err:
        module.fail_json(
            msg='{0}.ensure_entry() failed for entry {1!r}: {2}'.format(
                ldap_conn.__class__.__name__,
                ae_service.dn_s,
                ldap_err,
            )
        )

    if module.params['groups']:
        for group_filter_tmpl, mod_op in (
            ('(&(objectClass=aeGroup)(|{0})(!(member={1})))', ldap0.MOD_ADD),
            ('(&(objectClass=aeGroup)(!(|{0}))(member={1}))', ldap0.MOD_DELETE),
        ):
            group_filter = group_filter_tmpl.format(
                ''.join(map_filter_parts(
                    'cn',
                    [
                        grp_name
                        for grp_name in module.params['groups']
                        if grp_name
                    ],
                )),
                escape_filter_str(ae_service.dn_s),
            )
            try:
                ldap_res = ldap_conn.search_s(
                    ldap_conn.search_base,
                    ldap0.SCOPE_SUBTREE,
                    filterstr=group_filter,
                    attrlist=['1.1'],
                )
            except LDAPError as ldap_err:
                module.fail_json(
                    msg='Search groups with filter {0!r} failed: {1}'.format(
                        group_filter,
                        ldap_err,
                    )
                )

            for grp in ldap_res:
                ldap_ops.append(
                    ldap_conn.modify_s(
                        grp.dn_s,
                        [
                            (mod_op, b'member', [ae_service.dn_s.encode('utf-8')]),
                            (mod_op, b'memberUid', [ae_service.uid.encode('utf-8')]),
                        ],
                    )
                )

    if ldap_ops:
        message = '%d LDAP operations on %r' % (len(ldap_ops), ae_service.dn_s,)

    # finally return a result message to ansible
    module.exit_json(
        changed=bool(message),
        original_message=module.params['name'],
        message=message,
        dn=ae_service.dn_s,
        cn=ae_service.cn,
        ops_count=len(ldap_ops),
        ppolicy=str(ae_service.pwdPolicySubentry),
    )


if __name__ == '__main__':
    main()
