# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for

Æ-DIR -- Yet another LDAP user and systems management
"""

# Python's standard lib
import re,time,calendar,socket

# from python-ldap
import ldap,ldap.filter
from ldap.filter import escape_filter_chars

# from pyweblib
from pyweblib.forms import HiddenInput

# from internal base modules
import ldaputil.base
from ldap.controls.readentry import PreReadControl

# web2ldap's internal application modules
import w2lapp.searchform,w2lapp.schema.plugins.inetorgperson,w2lapp.schema.plugins.sudoers

from w2lapp.schema.syntaxes import \
  DirectoryString,DistinguishedName,SelectList,GeneralizedTime, \
  DynamicValueSelectList,IA5String,DNSDomain,NumericString, \
  DynamicDNSelectList,RFC822Address,IntegerRange,ComposedAttribute, \
  NotBefore,NotAfter,syntax_registry

from w2lapp.schema.plugins.nis import UidNumber,GidNumber,MemberUID
from w2lapp.schema.plugins.ppolicy import PwdExpireWarning,PwdMaxAge
from w2lapp.schema.plugins.inetorgperson import DisplayNameInetOrgPerson
from w2lapp.schema.plugins.groups import GroupEntryDN
from w2lapp.schema.plugins.opensshlpk import ParamikoSshPublicKey
from w2lapp.schema.plugins.posixautogen import HomeDirectory

# OID arc for AE-DIR, see stroeder.com-oid-macros.schema
AE_OID_PREFIX = '1.3.6.1.4.1.5427.1.389.100'

# OIDs of AE-DIR's structural object classes
AE_USER_OID = AE_OID_PREFIX+'.6.2'
AE_GROUP_OID = AE_OID_PREFIX+'.6.1'
AE_SRVGROUP_OID = AE_OID_PREFIX+'.6.13'
AE_SUDORULE_OID = AE_OID_PREFIX+'.6.7'
AE_HOST_OID = AE_OID_PREFIX+'.6.6.1'
AE_SERVICE_OID = AE_OID_PREFIX+'.6.4'
AE_ZONE_OID = AE_OID_PREFIX+'.6.20'
AE_PERSON_OID = AE_OID_PREFIX+'.6.8'
AE_TAG_OID = AE_OID_PREFIX+'.6.24'
AE_DEPT_OID = AE_OID_PREFIX+'.6.29'


syntax_registry.registerAttrType(
  DNSDomain.oid,[
    AE_OID_PREFIX+'.4.10',   # aeFqdn
  ]
)


def ae_validity_filter(secs=None):
  if secs is None:
    secs = time.time()
  return (
    '(&'
      '(|'
        '(!(aeNotBefore=*))'
        '(aeNotBefore<={0})'
      ')'
      '(|'
        '(!(aeNotAfter=*))'
        '(aeNotAfter>={0})'
      ')'
    ')'
  ).format(
    time.strftime('%Y%m%d%H%M%SZ', time.gmtime(secs))
  )


class AEObjectUtil:

  def _zone_entry(self,attrlist=None):
    zone_dn = ','.join(ldap.dn.explode_dn(self._dn.encode(self._ls.charset))[-2:])
    try:
      ldap_result = self._ls.readEntry(
        zone_dn,
        attrtype_list=attrlist,
        search_filter='(objectClass=aeZone)',
      )
    except ldap.LDAPError:
      zone_entry = {}
    else:
      if ldap_result:
        _,zone_entry = ldap_result[0]
      else:
        zone_entry = {}
      return zone_entry

  def _get_zone_name(self):
    dn_list = ldap.dn.str2dn(self._dn.encode(self._ls.charset))
    try:
      zone_cn = dict([
        (at,av)
        for at,av,flags in dn_list[-2]
      ])['cn'].decode(self._ls.charset)
    except (KeyError,IndexError):
      result = None
    else:
      result = zone_cn
    return result # _get_zone_name()


class AEHomeDirectory(HomeDirectory):
  oid = 'AEHomeDirectory-oid'

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )
    input_field.charset = self._form.accept_charset
    return input_field

syntax_registry.registerAttrType(
  AEHomeDirectory.oid,[
    '1.3.6.1.1.1.1.3', # homeDirectory
  ],
  structural_oc_oids=[AE_USER_OID,AE_SERVICE_OID], # aeUser and aeService
)


class AEUIDNumber(UidNumber):
  oid = 'AEUIDNumber-oid'
  desc = 'numeric Unix-UID'

  def transmute(self,attrValues):
    return self._entry.get('gidNumber',[''])

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )
    input_field.charset = self._form.accept_charset
    return input_field

syntax_registry.registerAttrType(
  AEUIDNumber.oid,[
    '1.3.6.1.1.1.1.0', # uidNumber
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_SERVICE_OID, # aeService
  ],
)


class AEGIDNumber(GidNumber):
  oid = 'AEGIDNumber-oid'
  desc = 'numeric Unix-GID'
  minNewValue = 30000L
  maxNewValue = 49999L

  def _get_next_gid(self):
      """
      consumes next ID by sending MOD_INCREMENT modify operation with
      pre-read entry control
      """
      id_pool_dn = self._ls.getSearchRoot(self._dn)
      id_pool_attr = 'aeGidNumberNext'
      prc = PreReadControl(criticality=True, attrList=[id_pool_attr])
      msg_id = self._ls.l.modify_ext(
          id_pool_dn,
          [(ldap.MOD_INCREMENT, id_pool_attr, '1')],
          serverctrls=[prc],
      )
      _, _, _, resp_ctrls = self._ls.l.result3(msg_id)
      return int(resp_ctrls[0].entry[id_pool_attr][0])

  def transmute(self,attrValues):
    attrValues = GidNumber.transmute(self,attrValues)
    if attrValues and attrValues[0]:
      return attrValues
    # first try to re-read gidNumber from existing entry
    try:
      ldap_result = self._ls.readEntry(
        self._dn,
        attrtype_list=['gidNumber'],
        search_filter='(gidNumber=*)',
      )
    except (
      ldap.NO_SUCH_OBJECT,
      ldap.INSUFFICIENT_ACCESS,
    ):
      # search failed => ignore
      pass
    else:
      if ldap_result:
        return ldap_result[0][1]['gidNumber']
    # consume next ID from pool entry
    try:
      next_gid = self._get_next_gid()
    except (
      ldap.NO_SUCH_OBJECT,
      ldap.INSUFFICIENT_ACCESS,
    ):
      # search failed => no value suggested
      return ['']
    else:
      result = [str(next_gid)]
    return result # formValue()

  def formValue(self):
    return IntegerRange.formValue(self)

  def formField(self):
    return IntegerRange.formField(self)

syntax_registry.registerAttrType(
  AEGIDNumber.oid,[
    '1.3.6.1.1.1.1.1', # gidNumber
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_GROUP_OID,   # aeGroup
    AE_SERVICE_OID, # aeService
  ],
)


class AEUserId(IA5String):
  """
  Class for auto-generating values for aeUser -> uid
  """
  oid = 'AEUserId-oid'
  desc = 'AE-DIR: User name'
  maxValues = 1
  maxLen = 4
  maxCollisionChecks = 15
  UID_LETTERS = 'abcdefghijklmnopqrstuvwxyz'
  reobj = re.compile('^%s$' % (UID_LETTERS))

  def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    IA5String.__init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=entry)
    self.minLen = self.maxLen

  def _genUid(self):
    gen_collisions = 0
    while gen_collisions < self.maxCollisionChecks:
      # generate new random UID candidate
      uid_candidate = ldaputil.passwd.RandomString(self.maxLen,self.UID_LETTERS)
      # check whether UID candidate already exists
      uid_result = self._ls.l.search_s(
        self._ls.currentSearchRoot,
        ldap.SCOPE_SUBTREE,
        '(uid=%s)' % (uid_candidate),
        attrlist=['1.1'],
      )
      if not uid_result:
        return uid_candidate
      gen_collisions += 1
    raise w2lapp.core.ErrorExit(
      u'Gave up generating new unique <em>uid</em> after %d attempts.' % (gen_collisions)
    )
    return  # _genUid()

  def formValue(self):
    form_value = IA5String.formValue(self)
    if not self.attrValue:
      form_value = self._genUid().decode()
    return form_value

  def formField(self):
    return HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )

  def sanitizeInput(self,attrValue):
    return attrValue.strip().lower()

syntax_registry.registerAttrType(
  AEUserId.oid,[
    '0.9.2342.19200300.100.1.1', # uid
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ],
)


class AETicketId(IA5String):
  oid = 'AETicketId-oid'
  desc = 'AE-DIR: Ticket no. related to last change of entry'
  simpleSanitizers = (
    str.upper,
    str.strip,
  )

syntax_registry.registerAttrType(
  AETicketId.oid,[
    AE_OID_PREFIX+'.4.3', # aeTicketId
  ]
)


class AEHost(DynamicDNSelectList):
  oid = 'AEHost-oid'
  desc = 'AE-DIR: Host'
  ldap_url = 'ldap:///_?host?sub?(&(objectClass=aeHost)(aeStatus=0))'
  ref_attrs = (
    (None,u'Same host',None,u'Search all services running on same host'),
  )

syntax_registry.registerAttrType(
  AEHost.oid,[
    AE_OID_PREFIX+'.4.28', # aeHost
  ]
)


class AEGroupMember(DynamicDNSelectList):
  oid = 'AEGroupMember-oid'
  desc = 'AE-DIR: Member of a group'
  ldap_url = 'ldap:///_?displayName?sub?(&(|(objectClass=aeUser)(objectClass=aeService))(aeStatus=0))'

  def _determineFilter(self):
    aeperson_filter = None
    aedept_filters = [
      '(aeDept={0})'.format(escape_filter_chars(d))
      for d in self._entry.get('aeDept',[])
    ]
    if len(aedept_filters)>1:
      aedept_filter = '(|{})'.format(''.join(aedept_filters))
    elif len(aedept_filters)==1:
      aedept_filter = aedept_filters[0]
    else:
      aedept_filter = ''
    if aedept_filter:
      try:
        ldap_result = self._ls.l.search_s(
          self._determineSearchDN(self._dn,self.lu_obj.dn),
          ldap.SCOPE_SUBTREE,
          '(&(objectClass=aePerson)(aeStatus=0){})'.format(aedept_filter),
          attrlist=['1.1'],
        )
      except (
        ldap.NO_SUCH_OBJECT,
        ldap.INSUFFICIENT_ACCESS,
        ldap.SIZELIMIT_EXCEEDED,
        ldap.TIMELIMIT_EXCEEDED,
      ):
        aeperson_filters = []
      else:
        aeperson_filters = [
          '(aePerson={0})'.format(escape_filter_chars(dn))
          for dn,_ in ldap_result
        ]
      if len(aeperson_filters)>1:
        aeperson_filter = '(|{})'.format(''.join(aeperson_filters))
      elif len(aeperson_filters)==1:
        aeperson_filter = aeperson_filters[0]
    if aeperson_filter!=None:
      filter_str = '(&(objectClass=aeUser)(aeStatus=0){0})'.format(
        aeperson_filter,
      )
    else:
      filter_str = DynamicDNSelectList._determineFilter(self)
    return filter_str

syntax_registry.registerAttrType(
  AEGroupMember.oid,[
    '2.5.4.31', # member
  ],
  structural_oc_oids=[
    AE_GROUP_OID, # aeGroup
  ],
)


class AEMemberUid(MemberUID):
  oid = 'AEMemberUid-oid'
  desc = 'AE-DIR: username (uid) of member of a group'
  ldap_url = None

  def _member_uids_from_member(self):
    return [
      dn[4:].split(',')[0]
      for dn in self._entry.get('member',[])
    ]

  # Because AEMemberUid.transmute() always resets all attribute values it's
  # ok to not validate values thoroughly
  def _validate(self,attrValue):
    return MemberUID._validate(self,attrValue) and \
           attrValue in set(self._member_uids_from_member())

  def transmute(self,attrValues):
    return filter(None,self._member_uids_from_member())

  def formValue(self):
    return u''

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
    )
    input_field.charset = self._form.accept_charset
    input_field.setDefault(self.formValue())
    return input_field

syntax_registry.registerAttrType(
  AEMemberUid.oid,[
    '1.3.6.1.1.1.1.12', # memberUID
  ],
  structural_oc_oids=[
    AE_GROUP_OID,     # aeGroup
  ],
)


class AEGroupDN(DynamicDNSelectList):
  oid = 'AEGroupDN-oid'
  desc = 'AE-DIR: DN of user group entry'
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeGroup)(aeStatus=0))'
  ref_attrs = (
    ('memberOf',u'Members',None,u'Search all member entries of this user group'),
  )

syntax_registry.registerAttrType(
  AEGroupDN.oid,[
    '1.2.840.113556.1.2.102', # memberOf
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_SERVICE_OID, # aeService
  ],
)


class AEZoneAdminGroupDN(DynamicDNSelectList):
  oid = 'AEZoneAdminGroupDN-oid'
  desc = 'AE-DIR: DN of zone admin group entry'
  ldap_url = (
    'ldap:///_?cn?sub?'
    '(&'
      '(objectClass=aeGroup)'
      '(aeStatus=0)'
      '(cn=*-zone-admins)'
      '(!'
        '(|'
          '(cn:dn:=pub)'
          '(cn:dn:=ae)'
        ')'
      ')'
    ')'
  )
  ref_attrs = (
    ('memberOf',u'Members',None,u'Search all member entries of this user group'),
  )

syntax_registry.registerAttrType(
  AEZoneAdminGroupDN.oid,[
    AE_OID_PREFIX+'.4.31',  # aeZoneAdmins
  ]
)


class AEZoneAuditorGroupDN(DynamicDNSelectList):
  oid = 'AEZoneAuditorGroupDN-oid'
  desc = 'AE-DIR: DN of zone auditor group entry'
  ldap_url = (
    'ldap:///_?cn?sub?'
    '(&'
      '(objectClass=aeGroup)'
      '(aeStatus=0)'
      '(|'
        '(cn=*-zone-admins)'
        '(cn=*-zone-auditors)'
      ')'
      '(!'
        '(|'
          '(cn:dn:=pub)'
          '(cn:dn:=ae)'
        ')'
      ')'
    ')'
  )
  ref_attrs = (
    ('memberOf',u'Members',None,u'Search all member entries of this user group'),
  )

syntax_registry.registerAttrType(
  AEZoneAuditorGroupDN.oid,[
    AE_OID_PREFIX+'.4.32',  # aeZoneAuditors
  ]
)


class AESrvGroupRightsGroupDN(DynamicDNSelectList):
  oid = 'AESrvGroupRightsGroupDN-oid'
  desc = 'AE-DIR: DN of user group entry'
  ldap_url = (
    'ldap:///_?cn?sub?'
    '(&'
      '(objectClass=aeGroup)'
      '(aeStatus=0)'
      '(!'
        '(|'
          '(cn:dn:=pub)'
          '(cn:dn:=ae)'
          '(cn=*-zone-admins)'
          '(cn=*-zone-auditors)'
        ')'
      ')'
    ')'
  )
  ref_attrs = (
    ('memberOf',u'Members',None,u'Search all member entries of this user group'),
  )

syntax_registry.registerAttrType(
  AESrvGroupRightsGroupDN.oid,[
    AE_OID_PREFIX+'.4.4',  # aeLoginGroups
    AE_OID_PREFIX+'.4.6',  # aeSetupGroups
    AE_OID_PREFIX+'.4.7',  # aeLogStoreGroups
    AE_OID_PREFIX+'.4.30', # aeDisplayNameGroups
  ]
)


class AEVisibleGroups(AESrvGroupRightsGroupDN):
  oid = 'AEVisibleGroups-oid'
  desc = 'AE-DIR: DN of visible user group entry'
  always_add_groups = (
    'aeLoginGroups',
    'aeDisplayNameGroups',
  )

  def transmute(self,attrValues):
    attrValues = set(attrValues)
    for attr_type in self.always_add_groups:
      attrValues.update(self._entry.get(attr_type,[]))
    return list(attrValues)

syntax_registry.registerAttrType(
  AEVisibleGroups.oid,[
    AE_OID_PREFIX+'.4.20', # aeVisibleGroups
  ]
)


class AESameZoneObject(DynamicDNSelectList):
  oid = 'AESameZoneObject-oid'
  desc = 'AE-DIR: DN of referenced aeSrvGroup entry this is proxy for'
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeObject)(aeStatus=0))'

  def _determineSearchDN(self,current_dn,ldap_url_dn):
    dn_list = ldap.dn.explode_dn(self._dn.encode(self._ls.charset))
    return  ','.join(dn_list[-2:])


class AESrvGroup(AESameZoneObject):
  oid = 'AESrvGroup-oid'
  desc = 'AE-DIR: DN of referenced aeSrvGroup entry'
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0))'

  def _determineFilter(self):
    filter_str = self.lu_obj.filterstr or '(objectClass=*)'
    dn_u = self._dn.decode(self._ls.charset)
    parent_dn = ldaputil.base.ParentDN(dn_u)
    return '(&%s(!(entryDN=%s)))' % (
      filter_str,
      parent_dn.encode(self._ls.charset),
    )

syntax_registry.registerAttrType(
  AESrvGroup.oid,[
    AE_OID_PREFIX+'.4.27',  # aeSrvGroup
  ]
)


class AEProxyFor(AESameZoneObject):
  oid = 'AEProxyFor-oid'
  desc = 'AE-DIR: DN of referenced aeSrvGroup entry this is proxy for'
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0)(!(aeProxyFor=*)))'

  def _determineFilter(self):
    filter_str = self.lu_obj.filterstr or '(objectClass=*)'
    return '(&%s(!(entryDN=%s)))' % (
      filter_str,
      self._dn,
    )

syntax_registry.registerAttrType(
  AEProxyFor.oid,[
    AE_OID_PREFIX+'.4.25',  # aeProxyFor
  ]
)


class AETag(DynamicValueSelectList):
  oid = 'AETag-oid'
  desc = 'AE-DIR: cn of referenced aeTag entry'
  ldap_url = 'ldap:///_?cn,cn?sub?(&(objectClass=aeTag)(aeStatus=0))'

syntax_registry.registerAttrType(
  AETag.oid,[
    AE_OID_PREFIX+'.4.24',  # aeTag
  ]
)


class AEEntryDNAEPerson(DistinguishedName):
  oid = 'AEEntryDNAEPerson-oid'
  desc = 'AE-DIR: entryDN of aePerson entry'
  ref_attrs = (
    ('manager',u'Manages',None,u'Search all entries managed by this person'),
    ('aePerson',u'Users',None,'aeUser',u'Search all personal AE-DIR user accounts (aeUser entries) of this person.'),
    ('aePerson',u'Devices',None,'aeDevice',u'Search all devices (aeDevice entries) assigned to this person.'),
  )

syntax_registry.registerAttrType(
  AEEntryDNAEPerson.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
  ],
)


class AEEntryDNAEUser(DistinguishedName):
  oid = 'AEEntryDNAEUser-oid'
  desc = 'AE-DIR: entryDN of aeUser entry'

  def _additional_links(self):
    attr_value_u = self.attrValue.decode(self._ls.charset)
    r = DistinguishedName._additional_links(self)
    audit_context = self._ls.getAuditContext(self._ls.currentSearchRoot)
    if audit_context:
      r.append(self._form.applAnchor(
        'search','Activity',self._sid,
        (
          ('dn',audit_context),
          ('searchform_mode','adv'),
          ('search_attr','objectClass'),
          ('search_option',w2lapp.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string','auditObject'),
          ('search_attr','reqAuthzID'),
          ('search_option',w2lapp.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string',attr_value_u),
        ),
        title=u'Search modifications made by %s in accesslog DB' % (attr_value_u),
      ))
    return r

syntax_registry.registerAttrType(
  AEEntryDNAEUser.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ],
)


class AEEntryDNAEHost(DistinguishedName):
  oid = 'AEEntryDNAEHost-oid'
  desc = 'AE-DIR: entryDN of aeUser entry'
  ref_attrs = (
    ('aeHost',u'Services',None,u'Search all services running on this host'),
  )

  def _additional_links(self):
    attr_value_u = self.attrValue.decode(self._ls.charset)
    parent_dn = ldaputil.base.ParentDN(attr_value_u)
    aesrvgroup_filter = u''.join([
      u'(aeSrvGroup=%s)' % av.decode(self._ls.charset)
      for av in self._entry.get('aeSrvGroup',[])
    ])
    r = DistinguishedName._additional_links(self)
    r.extend([
      self._form.applAnchor(
        'search','Siblings',self._sid,
        (
          ('dn',self._dn),
          ('search_root',self._ls.currentSearchRoot),
          ('searchform_mode',u'exp'),
          (
            'filterstr',
            u'(&(|(objectClass=aeHost)(objectClass=aeService))(|(entryDN:dnSubordinateMatch:=%s)%s))' % (
              parent_dn,
              aesrvgroup_filter,
            )
          ),
        ),
        title=u'Search all host entries which are member in at least one common server group(s) with this host',
      ),
    ])
    return r

syntax_registry.registerAttrType(
  AEEntryDNAEHost.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_HOST_OID, # aeHost
  ],
)


class AEEntryDNAEZone(DistinguishedName):
  oid = 'AEEntryDNAEZone-oid'
  desc = 'AE-DIR: entryDN of aeZone entry'

  def _additional_links(self):
    attr_value_u = self.attrValue.decode(self._ls.charset)
    r = DistinguishedName._additional_links(self)
    zone_cn = self._entry['cn'][0].decode('utf-8')
    if zone_cn=='ae':
      group_name_ext = ''
    else:
      group_name_ext = '-zone'
    zone_admins_group_dn = u'cn={group_name},{entry_dn}'.format(
      group_name=zone_cn+group_name_ext+u'-admins',
      entry_dn=self._dn,
    )
    zone_auditors_group_dn = u'cn={group_name},{entry_dn}'.format(
      group_name=zone_cn+group_name_ext+u'-auditors',
      entry_dn=self._dn,
    )
    audit_context = self._ls.getAuditContext(self._ls.currentSearchRoot)
    if audit_context:
      r.append(self._form.applAnchor(
        'search','Audit all',self._sid,
        (
          ('dn',audit_context),
          ('searchform_mode','adv'),
          ('search_attr','objectClass'),
          ('search_option',w2lapp.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string','auditObject'),
          ('search_attr','reqDN'),
          ('search_option',w2lapp.searchform.SEARCH_OPT_DN_SUBTREE),
          ('search_string',attr_value_u),
        ),
        title=u'Search all audit log entries for sub-tree %s' % (attr_value_u),
      ))
      r.append(self._form.applAnchor(
        'search','Audit writes',self._sid,
        (
          ('dn',audit_context),
          ('searchform_mode','adv'),
          ('search_attr','objectClass'),
          ('search_option',w2lapp.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string','auditObject'),
          ('search_attr','reqDN'),
          ('search_option',w2lapp.searchform.SEARCH_OPT_DN_SUBTREE),
          ('search_string',attr_value_u),
        ),
        title=u'Search audit log entries for write operation within sub-tree %s' % (attr_value_u),
      ))
    return r

syntax_registry.registerAttrType(
  AEEntryDNAEZone.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_ZONE_OID, # aeZone
  ],
)


class AEEntryDNAEGroup(GroupEntryDN):
  oid = 'AEEntryDNAEGroup-oid'
  desc = 'AE-DIR: entryDN of aeGroup entry'
  ref_attrs = (
    ('memberOf',u'Members',None,u'Search all member entries of this user group'),
    ('aeLoginGroups',u'Login',None,u'Search all server/service groups (aeSrvGroup)\non which this user group has login right'),
    ('aeLogStoreGroups',u'View Logs',None,u'Search all server/service groups (aeSrvGroup)\non which this user group has log view right'),
    ('aeSetupGroups',u'Setup',None,u'Search all server/service groups (aeSrvGroup)\non which this user group has setup/installation rights'),
    ('aeVisibleGroups',u'Visible',None,u'Search all server/service groups (aeSrvGroup)\non which this user group is at least visible'),
  )

  def _additional_links(self):
    r = DistinguishedName._additional_links(self)
    r.append(self._form.applAnchor(
      'search','SUDO rules',self._sid,
      (
        ('dn',self._dn),
        ('search_root',self._ls.currentSearchRoot),
        ('searchform_mode','adv'),
        ('search_attr','sudoUser'),
        ('search_option',w2lapp.searchform.SEARCH_OPT_IS_EQUAL),
        (
          'search_string','%'+self._entry['cn'][0].decode(self._ls.charset),
        ),
      ),
      title=u'Search for SUDO rules\napplicable with this user group',
    ))
    return r

syntax_registry.registerAttrType(
  AEEntryDNAEGroup.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_GROUP_OID, # aeGroup
  ],
)


class AEEntryDNAESrvGroup(DistinguishedName):
  oid = 'AEEntryDNAESrvGroup-oid'
  desc = 'AE-DIR: entryDN'
  ref_attrs = (
    ('aeProxyFor',u'Proxy',None,u'Search access gateway/proxy group for this server group'),
  )

  def _additional_links(self):
    attr_value_u = self.attrValue.decode(self._ls.charset)
    r = DistinguishedName._additional_links(self)
    r.append(
      self._form.applAnchor(
        'search','All members',self._sid,
        (
          ('dn',self._dn),
          ('search_root',self._ls.currentSearchRoot),
          ('searchform_mode',u'exp'),
          (
            'filterstr',
            u'(&(|(objectClass=aeHost)(objectClass=aeService))(|(entryDN:dnSubordinateMatch:={0})(aeSrvGroup={0})))'.format(attr_value_u)
          ),
        ),
        title=u'Search all host entries which are member in this server group {0}'.format(attr_value_u),
      )
    )
    return r


syntax_registry.registerAttrType(
  AEEntryDNAESrvGroup.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_SRVGROUP_OID, # aeSrvGroup
  ],
)


class AEEntryDNSudoRule(DistinguishedName):
  oid = 'AEEntryDNSudoRule-oid'
  desc = 'AE-DIR: entryDN'
  ref_attrs = (
    ('aeVisibleSudoers',u'Used on',None,u'Search all server groups (aeSrvGroup entries) referencing this SUDO rule'),
  )

syntax_registry.registerAttrType(
  AEEntryDNSudoRule.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_SUDORULE_OID, # aeSudoRule
  ],
)


class AEEntryDNAEDept(DistinguishedName):
  oid = 'AEEntryDNAEDept-oid'
  desc = 'AE-DIR: entryDN of aePerson entry'
  ref_attrs = (
    ('aeDept',u'Persons',None,'aePerson',u'Search all persons assigned to this department.'),
    ('aeDept',u'Zones',None,'aeZone',u'Search all team-related zones associated with this department.'),
  )

syntax_registry.registerAttrType(
  AEEntryDNAEDept.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_DEPT_OID, # aeDept
  ],
)


class AEDept(DynamicDNSelectList):
  oid = 'AEDept-oid'
  desc = 'AE-DIR: DN of department entry'
  ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aeDept)(aeStatus=0))'
  ref_attrs = (
    ('aeDept',u'Persons',None,'aePerson',u'Search all persons assigned to this department.'),
    ('aeDept',u'Zones',None,'aeZone',u'Search all team-related zones associated with this department.'),
  )

syntax_registry.registerAttrType(
  AEDept.oid,[
    AE_OID_PREFIX+'.4.29', # aeDept
  ]
)


class AEPerson(DynamicDNSelectList,AEObjectUtil):
  oid = 'AEPerson-oid'
  desc = 'AE-DIR: DN of person entry'
  ldap_url = 'ldap:///_?displayName?sub?(objectClass=aePerson)'
  ref_attrs = (
    ('aePerson',u'Users',None,'aeUser',u'Search all personal AE-DIR user accounts (aeUser entries) of this person.'),
    ('aePerson',u'Devices',None,'aeDevice',u'Search all devices (aeDevice entries) assigned to this person.'),
  )
  mail_zones = set(('base',))
  ae_status_map = {
    -1:(0,),
    0:(0,),
    1:(0,1,2),
    2:(0,1,2),
  }

  def _determineFilter(self):
    filter_components = [
      DynamicDNSelectList._determineFilter(self),
      ae_validity_filter(),
    ]
    aedept_filters = [
      '(aeDept={0})'.format(escape_filter_chars(d))
      for d in self._zone_entry(attrlist=['aeDept']).get('aeDept',[])
    ]
    if len(aedept_filters)>1:
      filter_components.append('(|{})'.format(''.join(aedept_filters)))
    elif len(aedept_filters)==1:
      filter_components.append(aedept_filters[0])
    ae_status = int(self._entry.get('aeStatus',['0'])[0])
    aeperson_aestatus_filters = [
      '(aeStatus={0})'.format(escape_filter_chars(st))
      for st in map(str,self.ae_status_map.get(ae_status,[]))
    ]
    if len(aeperson_aestatus_filters)>1:
      filter_components.append('(|{})'.format(''.join(aeperson_aestatus_filters)))
    elif len(aeperson_aestatus_filters)==1:
      filter_components.append(aeperson_aestatus_filters[0])
    if self.mail_zones is None or not self._get_zone_name() in self.mail_zones:
      filter_components.append('(mail=*)')
    filter_str = '(&{})'.format(''.join(filter_components))
    return filter_str


class AEPerson2(AEPerson):
  oid = 'AEPerson2-oid'
  sanitize_filter_tmpl = '(|(cn={av}*)(uniqueIdentifier={av})(employeeNumber={av})(displayName={av})(mail={av}))'

  def formValue(self):
    form_value = DistinguishedName.formValue(self)
    if self.attrValue:
      person_entry = self._readReferencedEntry(self.attrValue)
      if person_entry:
        form_value = person_entry.get('displayName',[form_value])[0].decode(self._form.accept_charset)
    return form_value

  def formField(self):
    return DistinguishedName.formField(self)

  def transmute(self,attrValues):
    if not attrValues or not attrValues[0]:
      return attrValues
    sanitize_filter = '(&{0}{1})'.format(
        self._determineFilter(),
        self.sanitize_filter_tmpl.format(
          av=escape_filter_chars(attrValues[0]),
        )
    )
    try:
      ldap_result = self._ls.l.search_s(
        self._determineSearchDN(self._dn,self.lu_obj.dn),
        ldap.SCOPE_SUBTREE,
        sanitize_filter,
        attrlist=self.lu_obj.attrs,
      )
    except (
      ldap.NO_SUCH_OBJECT,
      ldap.INSUFFICIENT_ACCESS,
      ldap.SIZELIMIT_EXCEEDED,
      ldap.TIMELIMIT_EXCEEDED,
    ):
      return attrValues
    else:
      if ldap_result and len(ldap_result)==1:
        return [ldap_result[0][0]]
      else:
        return attrValues

syntax_registry.registerAttrType(
  AEPerson.oid,[
    AE_OID_PREFIX+'.4.16', # aePerson
  ]
)


class AEManager(DynamicDNSelectList):
  oid = 'AEManager-oid'
  desc = 'AE-DIR: Manager responsible for a person/department'
  ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aePerson)(aeStatus=0))'

syntax_registry.registerAttrType(
  AEManager.oid,[
    '0.9.2342.19200300.100.1.10', # manager
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
    AE_DEPT_OID, # aeDept
  ]
)


class AEDerefAttribute(DirectoryString):
  oid = 'AEDerefAttribute-oid'
  maxValues = 1
  deref_object_class = None
  deref_attribute_type = None
  deref_filter_tmpl = '(&(objectClass={deref_object_class})(aeStatus=0)({attribute_type}=*))'

  def _readPersonAttribute(self):
    try:
      ldap_result = self._ls.readEntry(
        self._entry[self.deref_attribute_type][0].decode(self._ls.charset),
        attrtype_list=[self.attrType],
        search_filter=self.deref_filter_tmpl.format(
          deref_object_class=self.deref_object_class,
          attribute_type=self.attrType,
        ),
      )
    except ldap.LDAPError:
      result = None
    else:
      if ldap_result:
        _,person_entry = ldap_result[0]
        result = person_entry[self.attrType][0].decode(self._ls.charset)
      else:
        result = None
    return result

  def transmute(self,attrValues):
    if self.deref_attribute_type in self._entry:
      ae_person_attribute = self._readPersonAttribute()
      if ae_person_attribute!=None:
        result = [ae_person_attribute.encode(self._ls.charset)]
      else:
        raise KeyError
    else:
      result = attrValues
    return result

  def formValue(self):
    return u''

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
    )
    input_field.charset = self._form.accept_charset
    input_field.setDefault(self.formValue())
    return input_field


class AEPersonAttribute(AEDerefAttribute):
  oid = 'AEPersonAttribute-oid'
  maxValues = 1
  deref_object_class = 'aePerson'
  deref_attribute_type = 'aePerson'


class AEUserNames(AEPersonAttribute,DirectoryString):
  oid = 'AEUserNames-oid'

syntax_registry.registerAttrType(
  AEUserNames.oid,[
    '2.5.4.4', # sn
    '2.5.4.42', # givenName
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ],
)


class AEUserMailaddress(AEPersonAttribute,RFC822Address):
  oid = 'AEUserMailaddress-oid'
  html_tmpl = RFC822Address.html_tmpl
  maxValues = 1

  def transmute(self,attrValues):
    try:
      attrValues = [self._entry['mailLocalAddress'][0]]
    except KeyError:
      attrValues = AEPersonAttribute.transmute(self,attrValues)
    return attrValues

syntax_registry.registerAttrType(
  AEUserMailaddress.oid,[
    '0.9.2342.19200300.100.1.3', # mail
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ],
)


class AEPersonMailaddress(RFC822Address):
  oid = 'AEPersonMailaddress-oid'
  maxValues = 1

  def _search_base_user_mail(self):
    result = None
    try:
      ldap_result = self._ls.l.search_ext_s(
        self._ls.currentSearchRoot,
        ldap.SCOPE_SUBTREE,
        '(&'
          '(objectClass=aeUser)'
          '(objectClass=inetLocalMailRecipient)'
          '(aeStatus=0)'
          '(aePerson=%s)'
          '(mailLocalAddress=*)'
        ')' % (self._dn),
        attrlist=[
          'mailLocalAddress',
        ],
        sizelimit=2,
      )
    except ldap.LDAPError:
      pass
    else:
      if ldap_result and len(ldap_result)==1:
        result = ldap_result[0][1]['mailLocalAddress'][0]
    return result

  def transmute(self,attrValues):
    mail_local_address = self._search_base_user_mail()
    if mail_local_address:
      attrValues = [mail_local_address]
    else:
      attrValues = RFC822Address.transmute(self,attrValues)
    return attrValues

syntax_registry.registerAttrType(
  AEPersonMailaddress.oid,[
    '0.9.2342.19200300.100.1.3', # mail
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
  ],
)


class AEDeptAttribute(AEDerefAttribute,DirectoryString):
  oid = 'AEDeptAttribute-oid'
  maxValues = 1
  deref_object_class = 'aeDept'
  deref_attribute_type = 'aeDept'

syntax_registry.registerAttrType(
  AEDeptAttribute.oid,[
    '2.16.840.1.113730.3.1.2', # departmentNumber
    '2.5.4.11',                # ou, organizationalUnitName
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
  ],
)


class AEHostname(DNSDomain):
  oid = 'AEHostname-oid'
  desc = 'Canonical hostname / FQDN'
  host_lookup = 0

  def _validate(self,attrValue):
    if not DNSDomain._validate(self,attrValue):
      return False
    if self.host_lookup:
      try:
        ip_addr = socket.gethostbyname(attrValue)
      except (socket.gaierror,socket.herror):
        return False
      if self.host_lookup>=2:
        try:
          reverse_hostname = socket.gethostbyaddr(ip_addr)[0]
        except (socket.gaierror,socket.herror):
          return False
        else:
          return reverse_hostname==attrValue
    return True

  def transmute(self,attrValues):
    result = []
    for attr_value in attrValues:
      attr_value.lower().strip()
      if self.host_lookup:
        try:
          ip_addr = socket.gethostbyname(attr_value)
          reverse_hostname = socket.gethostbyaddr(ip_addr)[0]
        except (socket.gaierror,socket.herror):
          pass
        else:
          attr_value = reverse_hostname
      result.append(attr_value)
    return attrValues

syntax_registry.registerAttrType(
  AEHostname.oid,[
    '0.9.2342.19200300.100.1.9', # host
  ],
  structural_oc_oids=[
    AE_HOST_OID, # aeHost
  ],
)


class AECommonNameAEHost(DirectoryString):
  oid = 'AECommonNameAEHost-oid'
  desc = 'Canonical hostname'
  maxValues = 1
  derive_from_host = True

  def transmute(self,attrValues):
    if self.derive_from_host:
      return list(set([
        av.split('.')[0].strip().lower()
        for av in self._entry['host']
      ]))
    else:
      return attrValues

syntax_registry.registerAttrType(
  AECommonNameAEHost.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_HOST_OID, # aeHost
  ],
)


class AEDisplayNameUser(ComposedAttribute,DirectoryString):
  oid = 'AEDisplayNameUser-oid'
  desc = 'Attribute displayName in object class aeUser'
  compose_templates = (
    '{givenName} {sn} ({uid}/{uidNumber})',
    '{givenName} {sn} ({uid})',
  )

syntax_registry.registerAttrType(
  AEDisplayNameUser.oid,[
    '2.16.840.1.113730.3.1.241', # displayName
  ],
  structural_oc_oids=[AE_USER_OID], # aeUser
)


class AEDisplayNameDept(ComposedAttribute,DirectoryString):
  oid = 'AEDisplayNameDept-oid'
  desc = 'Attribute displayName in object class aeDept'
  compose_templates = (
    '{ou} ({departmentNumber})',
    '{ou}',
    '#{departmentNumber}',
  )

syntax_registry.registerAttrType(
  AEDisplayNameDept.oid,[
    '2.16.840.1.113730.3.1.241', # displayName
  ],
  structural_oc_oids=[AE_DEPT_OID], # aeDept
)


class AEDisplayNamePerson(DisplayNameInetOrgPerson):
  oid = 'AEDisplayNamePerson-oid'
  desc = 'Attribute displayName in object class aePerson'
  # do not stuff confidential employeeNumber herein!
  compose_templates = (
    '{givenName} {sn} / {ou}',
    '{givenName} {sn} / #{departmentNumber}',
    '{givenName} {sn} ({uniqueIdentifier})',
    '{givenName} {sn}',
  )

syntax_registry.registerAttrType(
  AEDisplayNamePerson.oid,[
    '2.16.840.1.113730.3.1.241', # displayName
  ],
  structural_oc_oids=[AE_PERSON_OID], # aePerson
)


class AEUniqueIdentifier(DirectoryString):
  oid = 'AEUniqueIdentifier-oid'
  maxValues = 1
  gen_template = 'web2ldap-{timestamp}'

  def transmute(self,attrValues):
    if not attrValues or not attrValues[0].strip():
      return [self.gen_template.format(timestamp=time.time())]
    else:
      return attrValues

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )
    input_field.charset = self._form.accept_charset
    return input_field

syntax_registry.registerAttrType(
  AEUniqueIdentifier.oid,[
    '0.9.2342.19200300.100.1.44', # uniqueIdentifier
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
  ]
)


class AEDepartmentNumber(DirectoryString):
  oid = 'AEDepartmentNumber-oid'
  maxValues = 1

syntax_registry.registerAttrType(
  AEDepartmentNumber.oid,[
    '2.16.840.1.113730.3.1.2', # departmentNumber
  ],
  structural_oc_oids=[
    AE_DEPT_OID,   # aeDept
  ]
)


class AECommonNameAEZone(DirectoryString):
  oid = 'AECommonNameAEZone-oid'
  maxValues = 1

  def sanitizeInput(self,attrValue):
    return attrValue.strip()

syntax_registry.registerAttrType(
  AECommonNameAEZone.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_ZONE_OID, # aeZone
  ]
)


class AEZonePrefixCommonName(DirectoryString,AEObjectUtil):
  oid = 'AEZonePrefixCommonName-oid'
  desc = 'AE-DIR: Attribute values have to be prefixed with zone name'
  maxValues = 1
  reObj = re.compile('^[a-z0-9]+-[a-z0-9-]+$')
  special_names = ('zone-admins','zone-auditors')

  def sanitizeInput(self,attrValue):
    return attrValue.strip()

  def transmute(self,attrValues):
    attrValues = [attrValues[0].lower()]
    return attrValues

  def _validate(self,attrValue):
    result = DirectoryString._validate(self,attrValue)
    if result and attrValue:
      zone_cn = self._get_zone_name()
      result = zone_cn and (zone_cn=='pub' or attrValue.startswith(zone_cn+u'-'))
    return result

  def formValue(self):
    result = DirectoryString.formValue(self)
    zone_cn = self._get_zone_name()
    if zone_cn:
      if not self.attrValue:
        result = zone_cn+u'-'
      elif self.attrValue in self.special_names:
        result = '-'.join((zone_cn,self.attrValue.decode(self._ls.charset)))
    return result # formValue()


class AECommonNameAEGroup(AEZonePrefixCommonName):
  oid = 'AECommonNameAEGroup-oid'
  maxValues = 1

syntax_registry.registerAttrType(
  AECommonNameAEGroup.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_GROUP_OID,    # aeGroup
  ]
)


class AECommonNameAESrvGroup(AEZonePrefixCommonName):
  oid = 'AECommonNameAESrvGroup-oid'
  maxValues = 1

syntax_registry.registerAttrType(
  AECommonNameAESrvGroup.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_SRVGROUP_OID, # aeSrvGroup
  ]
)


class AECommonNameAETag(AEZonePrefixCommonName):
  oid = 'AECommonNameAETag-oid'
  maxValues = 1

  def displayValue(self,valueindex=0,commandbutton=0):
    display_value = AEZonePrefixCommonName.displayValue(self,valueindex,commandbutton)
    if commandbutton:
      search_anchor = self._form.applAnchor(
        'searchform','&raquo;',self._sid,
        [
          ('dn',self._dn),
          ('search_root',self._ls.currentSearchRoot),
          ('searchform_mode',u'adv'),
          ('search_attr',u'aeTag'),
          ('search_option',w2lapp.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string',self._ls.uc_decode(self.attrValue)[0]),
        ],
        title=u'Search all entries tagged with this tag',
      )
    else:
      search_anchor = ''
    return ''.join((display_value,search_anchor))

syntax_registry.registerAttrType(
  AECommonNameAETag.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_TAG_OID, # aeTag
  ]
)


class AECommonNameAESudoRule(AEZonePrefixCommonName):
  oid = 'AECommonNameAESudoRule-oid'
  maxValues = 1

syntax_registry.registerAttrType(
  AECommonNameAESudoRule.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_SUDORULE_OID, # aeSudoRule
  ]
)


syntax_registry.registerAttrType(
  w2lapp.schema.plugins.inetorgperson.CNInetOrgPerson.oid,[
    '2.5.4.3', # commonName
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
    AE_USER_OID,   # aeUser
  ]
)


class AESudoRuleDN(DynamicDNSelectList):
  oid = 'AESudoRuleDN-oid'
  desc = 'AE-DIR: DN(s) of visible SUDO rules'
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSudoRule)(aeStatus=0))'

syntax_registry.registerAttrType(
  AESudoRuleDN.oid,[
    AE_OID_PREFIX+'.4.21', # aeVisibleSudoers
  ]
)


class AENotBefore(NotBefore):
  oid = 'AENotBefore-oid'
  desc = 'AE-DIR: begin of validity period'

syntax_registry.registerAttrType(
  AENotBefore.oid,[
    AE_OID_PREFIX+'.4.22', # aeNotBefore
  ]
)


class AENotAfter(NotAfter):
  oid = 'AENotAfter-oid'
  desc = 'AE-DIR: begin of validity period'

  def _validate(self,attrValue):
    result = NotAfter._validate(self,attrValue)
    if result:
      ae_not_after = time.strptime(attrValue,r'%Y%m%d%H%M%SZ')
      try:
        ae_not_before = time.strptime(self._entry['aeNotBefore'][0],r'%Y%m%d%H%M%SZ')
      except (KeyError,ValueError):
        result = True
      else:
        result = (ae_not_before<=ae_not_after)
    return result

syntax_registry.registerAttrType(
  AENotAfter.oid,[
    AE_OID_PREFIX+'.4.23', # aeNotAfter
  ]
)


class AEStatus(SelectList,IntegerRange):
  oid = 'AEStatus-oid'
  desc = 'AE-DIR: Status of object'
  attr_value_dict = {
    u'-1':u'requested',
    u'0':u'active',
    u'1':u'deactivated',
    u'2':u'archived',
  }

  def _validate(self,attrValue):
    result = SelectList._validate(self,attrValue)
    if not result or not attrValue:
      return result
    ae_status = int(attrValue)
    current_time = time.gmtime(time.time())
    try:
      ae_not_before = time.strptime(self._entry['aeNotBefore'][0],r'%Y%m%d%H%M%SZ')
    except (KeyError, ValueError):
      ae_not_before = time.strptime('19700101000000Z',r'%Y%m%d%H%M%SZ')
    try:
      ae_not_after = time.strptime(self._entry['aeNotAfter'][0],r'%Y%m%d%H%M%SZ')
    except (KeyError, ValueError):
      ae_not_after = current_time
    # see https://www.ae-dir.com/docs.html#schema-validity-period
    result = ae_not_before <= current_time <= ae_not_after
    if current_time > ae_not_after:
      result = ae_status>=1
    elif current_time < ae_not_before:
      result = ae_status==-1
    return result

  def transmute(self,attrValues):
    if not attrValues or not attrValues[0]:
      return attrValues
    ae_status = int(attrValues[0])
    current_time = time.gmtime(time.time())
    try:
      ae_not_before = time.strptime(self._entry['aeNotBefore'][0],r'%Y%m%d%H%M%SZ')
    except (KeyError, ValueError):
      pass
    else:
      if ae_status==0 and current_time < ae_not_before:
        ae_status = -1
    try:
      ae_not_after = time.strptime(self._entry['aeNotAfter'][0],r'%Y%m%d%H%M%SZ')
    except (KeyError, ValueError):
      pass
    else:
      if ae_status<=0 and current_time > ae_not_after:
        ae_status = 1
    return [str(ae_status)]

  def displayValue(self,valueindex=0,commandbutton=0):
    if not commandbutton:
      return IntegerRange.displayValue(self,valueindex)
    else:
      return SelectList.displayValue(self,valueindex,commandbutton)

syntax_registry.registerAttrType(
  AEStatus.oid,[
    AE_OID_PREFIX+'.4.5', # aeStatus
  ]
)


class AESudoUser(w2lapp.schema.plugins.sudoers.SudoUserGroup):
  oid = 'AESudoUser-oid'
  desc = 'AE-DIR: sudoUser'
  ldap_url = (
    'ldap:///_?cn,cn?sub?'
    '(&'
      '(objectClass=aeGroup)'
      '(aeStatus=0)'
      '(!(|'
        '(cn=ae-admins)'
        '(cn=ae-auditors)'
        '(cn=ae-providers)'
        '(cn=ae-replicas)'
        '(cn=ae-login-proxies)'
        '(cn=*-zone-admins)'
        '(cn=*-zone-auditors)'
      '))'
    ')'
  )

syntax_registry.registerAttrType(
  AESudoUser.oid,[
    '1.3.6.1.4.1.15953.9.1.1', # sudoUser
  ],
  structural_oc_oids=[
    AE_SUDORULE_OID, # aeSudoRule
  ]
)


class AEServiceSshPublicKey(ParamikoSshPublicKey):
  oid = 'AEServiceSshPublicKey-oid'
  desc = 'AE-DIR: aeService:sshPublicKey'
  reObj = re.compile('(^|.* )(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? .+$')

syntax_registry.registerAttrType(
  AEServiceSshPublicKey.oid,[
    '1.3.6.1.4.1.24552.500.1.1.1.13', # sshPublicKey
  ],
  structural_oc_oids=[
    AE_SERVICE_OID, # aeService
  ]
)


class AEUserSshPublicKey(ParamikoSshPublicKey):
  oid = 'AEUserSshPublicKey-oid'
  desc = 'AE-DIR: aeUser:sshPublicKey'
  reObj = re.compile('(^|.* )(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) .+$')

syntax_registry.registerAttrType(
  AEUserSshPublicKey.oid,[
    '1.3.6.1.4.1.24552.500.1.1.1.13', # sshPublicKey
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ]
)


# Register all syntax classes in this module
for name in dir():
  syntax_registry.registerSyntaxClass(eval(name))


import ldapsession,ldaputil.base
from ldapsession import LDAPSession as LDAPSessionOrig

class AEDirLDAPSession(LDAPSessionOrig):
  binddn_tmpl = u'uid={username},{searchroot}'

  def getBindDN(self,username,searchroot,filtertemplate):
    if not username:
      return u''
    elif ldaputil.base.is_dn(username):
      return username
    else:
      return self.binddn_tmpl.format(
        username=username,searchroot=searchroot
      )
