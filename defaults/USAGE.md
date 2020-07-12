
### `./main/main.yml`

#### `aedir_accesslog_suffix`:
  - used in **`templates/slapd/accesslog.conf.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/hosts.py.j2`**
#### `aedir_addressbook_attrs`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_aeauthctoken_serial_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_aedept_deptnumber_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aegroup_cn_regex`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aehost_state`:
  - used in _`tasks/main.yml`_
#### `aedir_aelocation_cn_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aenwdevice_visibility_sets`:
  - used in **`templates/slapd/service_access.conf.j2`**
#### `aedir_aeperson_uniqueid_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_aeservice_sshpubkey_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aeservice_uid_regex`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aesrvgroup_cn_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aesudorule_cn_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aetag_cn_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_aeuser_sshpubkey_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aeuser_uid_regex`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_aezone_cn_regex`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_base_zone`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/web2ldap/templates/ae-dir/add_aeUser_inetLocalMailRecipient.ldif.j2`**
#### `aedir_bin`:
  - used in _`tasks/main.yml`_
  - used in **`templates/profile-ae-dir.sh.j2`**
#### `aedir_confidential_person_attrs`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_cron_file`:
  - used in _`tasks/cron_provider.yml`_
  - used in _`tasks/cron.yml`_
#### `aedir_cron_minutes`:
  - used in _`tasks/cron_provider.yml`_
#### `aedir_cron_offset`:
  - used in _`defaults/main/main.yml`_
#### `aedir_etc`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_init.yml`_
  - used in _`tasks/aedir_tools.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in _`tasks/tls_keygen.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/ae-dir-csrgen.sh.j2`**
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
  - used in **`templates/apparmor/abstractions/cli.j2`**
  - used in **`templates/apparmor/abstractions/python.j2`**
  - used in **`templates/apparmor/uwsgi-python.j2`**
  - used in **`templates/oath-ldap/bind_proxy.cfg.j2`**
  - used in **`templates/oath-ldap/hotp_validator.cfg.j2`**
  - used in **`templates/profile-ae-dir.sh.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/systemd/ae-dir-pwd.service.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
  - used in **`templates/systemd/web2ldap.service.j2`**
#### `aedir_etc_openldap`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/global.conf.j2`**
#### `aedir_fake_search_roots`:
  - used in **`templates/slapd/slapo-rwm.conf.j2`**
#### `aedir_files_dirs`:
#### `aedir_homedirectory_hidden`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/service_access.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_homedirectory_prefixes`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_hosts`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/hosts.py.j2`**
#### `aedir_htdocsdir`:
  - used in _`tasks/main.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
#### `aedir_htdocs_layout`:
  - used in _`tasks/main.yml`_
#### `aedir_htdocs_templates`:
  - used in _`tasks/main.yml`_
#### `aedir_init_aeadmins`:
  - used in **`templates/ae-dir-base.ldif.j2`**
#### `aedir_init_aepersons`:
  - used in **`templates/ae-dir-base.ldif.j2`**
#### `aedir_init_aezones`:
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/searchform_aedir.html.j2`**
#### `aedir_init_become`:
  - used in _`tasks/main.yml`_
#### `aedir_init_ticket_id`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/main.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
#### `aedir_ldapi_services`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/pwsync.yml`_
  - used in _`tasks/system_accounts.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
#### `aedir_logging_conf`:
  - used in _`tasks/aedir_tools.yml`_
#### `aedir_login_shells`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_main_provider_hostname`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/main.yml`_
#### `aedir_malloc_ld_preload`:
  - used in **`templates/systemd/ae-apache.service.j2`**
  - used in **`templates/systemd/ae-dir-pwd.service.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
  - used in **`templates/systemd/pwsync.service.j2`**
  - used in **`templates/systemd/web2ldap.service.j2`**
#### `aedir_malloc_package`:
  - used in _`tasks/baseos_CentOS.yml`_
  - used in _`tasks/baseos_Debian.yml`_
  - used in _`tasks/baseos_SUSE.yml`_
#### `aedir_max_gid`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/ae-dir-conf.prom.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_max_uid`:
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_metricsdir`:
  - used in _`tasks/cron.yml`_
  - used in _`tasks/monitoring.yml`_
#### `aedir_metrics_owner_group`:
  - used in _`tasks/monitoring.yml`_
#### `aedir_min_gid`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/ae-dir-conf.prom.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_min_uid`:
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_news`:
  - used in _`tasks/main.yml`_
#### `aedir_nologin_shell`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/pwsync.yml`_
  - used in _`tasks/system_accounts.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeService.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeService_posixAccount.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_login-proxy.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_slapd-replica.ldif.j2`**
#### `aedir_org_zone`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeDept.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeLocation.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aePerson.ldif.j2`**
#### `aedir_pip_extra_args`:
  - used in _`tasks/aedir_tools_venv.yml`_
  - used in _`tasks/monitoring.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/web2ldap.yml`_
#### `aedir_pip_index_url`:
  - used in _`defaults/main/main.yml`_
#### `aedir_pip_install`:
  - used in _`defaults/main/main.yml`_
#### `aedir_pip_install_options`:
  - used in _`defaults/main/main.yml`_
#### `aedir_pip_needs_compiler`:
#### `aedir_pkg_repos`:
  - used in _`tasks/baseos_SUSE.yml`_
  - used in _`tasks/install_openldap_CentOS.yml`_
  - used in _`tasks/install_openldap_Debian.yml`_
#### `aedir_prefix`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools_CentOS.yml`_
  - used in _`tasks/aedir_tools_Debian.yml`_
  - used in _`tasks/aedir_tools_venv.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/monitoring.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/apparmor/abstractions/python.j2`**
  - used in **`templates/apparmor/bind_proxy.j2`**
  - used in **`templates/apparmor/hotp_validator.j2`**
  - used in **`templates/apparmor/uwsgi-python.j2`**
  - used in **`templates/uwsgi.ini.j2`**
  - used in _`vars/CentOS.yml`_
  - used in _`vars/Debian.yml`_
#### `aedir_provider_lb_hostname`:
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/web2ldap/opensearch-ae-dir.xml.j2`**
#### `aedir_providers_restrictions`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_pwsync_cacert_filename`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/pwsync.yml`_
#### `aedir_pwsync_cacert_pathname`:
  - used in _`tasks/pwsync.yml`_
  - used in **`templates/systemd/pwsync.service.j2`**
#### `aedir_pwsync_dn_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_pwsync_listener_user`:
  - used in _`tasks/pwsync.yml`_
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/systemd/pwsync.service.j2`**
#### `aedir_pwsync_socket_dir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/pwsync.yml`_
#### `aedir_pwsync_socket_path`:
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/systemd/pwsync.service.j2`**
#### `aedir_pwsync_targetpassword`:
  - used in _`tasks/pwsync.yml`_
#### `aedir_pwsync_targetpwfile`:
  - used in _`tasks/pwsync.yml`_
  - used in **`templates/systemd/pwsync.service.j2`**
#### `aedir_python`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools_CentOS.yml`_
  - used in _`tasks/aedir_tools_Debian.yml`_
  - used in _`tasks/cron_provider.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/install_apache2_CentOS.yml`_
  - used in _`tasks/main.yml`_
  - used in **`templates/apparmor/abstractions/python.j2`**
  - used in **`templates/apparmor/abstractions/uwsgi-python.j2`**
  - used in **`templates/oath-ldap/oath-ldap-decpin.sh.j2`**
  - used in **`templates/slapd_checkmk.sh.j2`**
  - used in **`templates/slapd_metrics.sh.j2`**
  - used in **`templates/systemd/ae-dir-pwd.service.j2`**
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
  - used in **`templates/systemd/pwsync.service.j2`**
  - used in **`templates/systemd/web2ldap.service.j2`**
  - used in **`templates/uwsgi.ini.j2`**
  - used in _`vars/CentOS.yml`_
  - used in _`vars/Debian.yml`_
  - used in _`vars/SUSE.yml`_
#### `aedir_python_env`:
  - used in _`tasks/cron.yml`_
  - used in **`templates/oath-ldap/oath-ldap-decpin.sh.j2`**
  - used in **`templates/slapd_checkmk.sh.j2`**
  - used in **`templates/slapd_metrics.sh.j2`**
  - used in **`templates/systemd/ae-dir-pwd.service.j2`**
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
  - used in **`templates/systemd/pwsync.service.j2`**
  - used in **`templates/systemd/web2ldap.service.j2`**
#### `aedir_python_sitepackages`:
  - used in **`templates/apparmor/abstractions/python.j2`**
  - used in **`templates/uwsgi.ini.j2`**
#### `aedir_python_warnings`:
  - used in _`defaults/main/main.yml`_
#### `aedir_replicas_restrictions`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_rootdn_gid_number`:
  - used in **`templates/slapd/global.conf.j2`**
#### `aedir_rootdn_uid_number`:
  - used in **`templates/slapd/global.conf.j2`**
#### `aedir_rundir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/cron_provider.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/system_accounts.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
  - used in **`templates/apparmor/uwsgi-python.j2`**
  - used in **`templates/uwsgi.ini.j2`**
#### `aedir_sbin`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools_provider.yml`_
  - used in _`tasks/aedir_tools.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/monitoring.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in **`templates/apparmor/abstractions/oath_bind_listener.j2`**
  - used in **`templates/profile-ae-dir.sh.j2`**
#### `aedir_schema_prefix`:
  - used in _`tasks/configure_slapd.yml`_
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/slapd/global.conf.j2`**
#### `aedir_service_manager`:
#### `aedir_session_suffix`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `aedir_srvgroup`:
  - used in _`tasks/main.yml`_
  - used in **`templates/slapd/global.conf.j2`**
#### `aedir_sshkey_perms`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_sshpublickey_self_filter`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_suffix`:
  - used in _`defaults/main/main.yml`_
  - used in **`files/ae-dir-pwd/templates/en/notify_user.txt`**
  - used in _`tasks/aedir_init.yml`_
  - used in _`tasks/main.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
  - used in **`templates/ldap.conf.j2`**
  - used in **`templates/oath-ldap/oathenroll_cnf.py.j2`**
  - used in **`templates/oath-ldap/oath-ldap-decpin.sh.j2`**
  - used in **`templates/slapd/accesslog.conf.j2`**
  - used in **`templates/slapd/config.conf.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/monitor.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/rootDSE.ldif.j2`**
  - used in **`templates/slapd/service_access.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
  - used in **`templates/slapd/slapo-rwm.conf.j2`**
  - used in **`templates/web2ldap/opensearch-ae-dir.xml.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeDept.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeHost.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeLocation.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aePerson.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeService.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeService_posixAccount.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeUser_inetLocalMailRecipient.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeUser.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeZone.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_login-proxy.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_oathHOTPParams.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_oath_hotp_token.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_pwdPolicy.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_slapd-replica.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/login.html.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/read_aeHost.html.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/read_aeService.html.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/read_aeUser.html.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/searchform_aedir.html.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/searchform_null.html.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/hosts.py.j2`**
#### `aedir_systemd_dir`:
  - used in _`tasks/configure_apache2.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/pwsync.yml`_
  - used in _`tasks/web2ldap.yml`_
#### `aedir_systemd_hardening`:
  - used in **`templates/systemd/ae-apache.service.j2`**
  - used in **`templates/systemd/ae-dir-pwd.service.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
  - used in **`templates/systemd/pwsync.service.j2`**
  - used in **`templates/systemd/web2ldap.service.j2`**
#### `aedir_systemd_logging`:
  - used in **`templates/systemd/ae-apache.service.j2`**
  - used in **`templates/systemd/ae-dir-pwd.service.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
  - used in **`templates/systemd/pwsync.service.j2`**
  - used in **`templates/systemd/web2ldap.service.j2`**
#### `aedir_templates_dirs`:
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in _`tasks/web2ldap.yml`_
#### `aedir_unique_person_zones`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `aedir_user_mail_enabled`:
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
#### `aedir_username_gen_trials`:
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_username_length`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_username_maxlen`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_username_minlen`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `aedir_uwsgi_params`:
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/web2ldap.yml`_
#### `aedir_who_srvgroup`:
  - used in **`templates/slapd/service_access.conf.j2`**
#### `ae_expiry_status_defaults`:
  - used in **`templates/web2ldap/templates/ae-dir/add_aeContact.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeGroup.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeGroup_zone-admins.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeGroup_zone-auditors.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeHost.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeMailGroup.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aePerson.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeService.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeService_posixAccount.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeUser_inetLocalMailRecipient.ldif.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeUser.ldif.j2`**
#### `aeticketid_regex`:
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/plugins.py.j2`**
#### `apache_access_log`:
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
  - used in **`templates/logrotate_ae-apache.j2`**
#### `apache_cacert_filename`:
  - used in _`tasks/configure_apache2.yml`_
#### `apache_cacert_pathname`:
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
#### `apache_cert_filename`:
  - used in _`tasks/configure_apache2.yml`_
#### `apache_cert_pathname`:
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
#### `apache_conf`:
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apparmor/ae-apache.j2`**
  - used in **`templates/systemd/ae-apache.service.j2`**
#### `apache_error_log`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_group`:
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/systemd/ae-apache.service.j2`**
#### `apache_htdocs_requires`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_key_filename`:
  - used in _`tasks/configure_apache2.yml`_
#### `apache_key_pathname`:
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
#### `apache_log_format`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_log_level`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_oath_requires`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_pid_file`:
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
  - used in **`templates/systemd/ae-apache.service.j2`**
#### `apache_pwd_requires`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_rundir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_apache2.yml`_
#### `apache_server_admin`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_service_fqdn`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/__init__.py.j2`**
#### `apache_ssl_cipher_suite`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_ssl_protocol`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_status_urlpath`:
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
#### `apache_user`:
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/systemd/ae-apache.service.j2`**
#### `apache_web2ldap_requires`:
  - used in **`templates/apache2.conf.j2`**
#### `apparmor_enabled`:
  - used in **`templates/systemd/ae-apache.service.j2`**
  - used in **`templates/systemd/ae-dir-pwd.service.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
  - used in **`templates/systemd/web2ldap.service.j2`**
#### `apparmor_profiles_dir`:
  - used in _`tasks/apparmor.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/web2ldap.yml`_
#### `cron_pkg_name`:
  - used in _`tasks/baseos_CentOS.yml`_
  - used in _`tasks/baseos_Debian.yml`_
  - used in _`tasks/baseos_SUSE.yml`_
#### `cron_service_name`:
  - used in _`tasks/services.yml`_
#### `local_openldap_csr_dir`:
  - used in _`tasks/tls_keygen.yml`_
#### `lsb_id`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools_CentOS.yml`_
  - used in _`tasks/aedir_tools_Debian.yml`_
  - used in _`tasks/aedir_tools_SUSE.yml`_
  - used in _`tasks/apparmor_Debian.yml`_
  - used in _`tasks/apparmor_SUSE.yml`_
  - used in _`tasks/apparmor.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/install_apache2_CentOS.yml`_
  - used in _`tasks/install_apache2_Debian.yml`_
  - used in _`tasks/install_apache2_SUSE.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in **`templates/apparmor/abstractions/ldapclient.j2`**
  - used in **`templates/apparmor/abstractions/python.j2`**
  - used in **`templates/apparmor/ae-slapd.j2`**
#### `oath_bind_listener`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools.yml`_
  - used in _`tasks/apparmor.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/services.yml`_
  - used in **`templates/apparmor/abstractions/oath_bind_listener.j2`**
  - used in **`templates/apparmor/bind_proxy.j2`**
  - used in **`templates/apparmor/hotp_validator.j2`**
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
#### `oath_dict`:
  - used in _`defaults/main/main.yml`_
#### `oath_ldap_cfg_dir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in **`templates/apparmor/bind_proxy.j2`**
  - used in **`templates/apparmor/hotp_validator.j2`**
  - used in **`templates/oath-ldap/oathenroll_cnf.py.j2`**
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
#### `oath_ldap_dn_regex`:
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
#### `oath_ldap_enabled`:
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/slapo-rwm.conf.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aeUser.ldif.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
#### `oath_ldap_keys_dir`:
  - used in _`tasks/oath_ldap.yml`_
  - used in **`templates/apparmor/hotp_validator.j2`**
  - used in **`templates/oath-ldap/hotp_validator.cfg.j2`**
  - used in **`templates/oath-ldap/oath-ldap-decpin.sh.j2`**
#### `oath_ldap_oathenroll_web_group`:
  - used in _`tasks/oathenroll.yml`_
  - used in **`templates/systemd/oathenroll.service.j2`**
#### `oath_ldap_oathenroll_web_user`:
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/systemd/oathenroll.service.j2`**
#### `oath_ldap_socket_dir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/oath_ldap.yml`_
#### `oath_ldap_socket_path`:
  - used in **`templates/apparmor/abstractions/oath_bind_listener.j2`**
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/oath-ldap/bind_proxy.cfg.j2`**
  - used in **`templates/oath-ldap/hotp_validator.cfg.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
#### `oath_listener_user`:
  - used in _`tasks/oath_ldap.yml`_
  - used in **`templates/systemd/bind_proxy.service.j2`**
  - used in **`templates/systemd/hotp_validator.service.j2`**
#### `openldap_backup_compressor`:
  - used in **`templates/scripts/ae-dir-slapcat.sh.j2`**
#### `openldap_backup_cron_args`:
  - used in _`tasks/cron_provider.yml`_
#### `openldap_backup_max_days`:
  - used in **`templates/scripts/ae-dir-slapcat.sh.j2`**
#### `openldap_backup_path`:
  - used in **`templates/scripts/ae-dir-slapcat.sh.j2`**
#### `openldap_backup_script`:
  - used in _`tasks/cron_provider.yml`_
#### `openldap_cacert_filename`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/tls_files.yml`_
#### `openldap_cacert_pathname`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in **`templates/apparmor/abstractions/oath_bind_listener.j2`**
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/apparmor/uwsgi-python.j2`**
  - used in **`templates/ldap.conf.j2`**
  - used in **`templates/oath-ldap/bind_proxy.cfg.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/hosts.py.j2`**
#### `openldap_cert_filename`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/tls_files.yml`_
#### `openldap_cert_pathname`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/ldap.conf.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_conn_max_pending`:
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_conn_max_pending_auth`:
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_csr_subjectaltnames`:
  - used in **`templates/tls/gen_csr.cnf.j2`**
#### `openldap_csr_subjectdn`:
  - used in _`tasks/tls_keygen.yml`_
  - used in **`templates/ae-dir-csrgen.sh.j2`**
#### `openldap_data`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/scripts/ae-dir-fix-db-permissions.sh.j2`**
  - used in **`templates/scripts/ae-dir-replica-reset.sh.j2`**
  - used in **`templates/slapd/accesslog.conf.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_db_params`:
  - used in **`templates/slapd/accesslog.conf.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_dhparam_numbits`:
  - used in _`tasks/tls_files.yml`_
#### `openldap_dhparam_pathname`:
  - used in _`tasks/tls_files.yml`_
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_idletimeout`:
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_key_filename`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_apache2.yml`_
#### `openldap_key_pathname`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in _`tasks/tls_keygen.yml`_
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/ldap.conf.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_ldapi_socket`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/apparmor/abstractions/ldapclient.j2`**
  - used in **`templates/oath-ldap/bind_proxy.cfg.j2`**
#### `openldap_ldapi_uri`:
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
  - used in **`templates/ldap.conf.j2`**
  - used in **`templates/oath-ldap/bind_proxy.cfg.j2`**
  - used in **`templates/oath-ldap/hotp_validator.cfg.j2`**
  - used in **`templates/oath-ldap/oathenroll_cnf.py.j2`**
  - used in **`templates/oath-ldap/oath-ldap-decpin.sh.j2`**
  - used in **`templates/slapd_checkmk.sh.j2`**
  - used in **`templates/slapd_metrics.sh.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
  - used in **`templates/systemd/pwsync.service.j2`**
  - used in **`templates/web2ldap/opensearch-ae-dir.xml.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/hosts.py.j2`**
#### `openldap_limit_nofile`:
  - used in **`templates/systemd/ae-slapd.service.j2`**
#### `openldap_listener_threads`:
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_log_level`:
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_log_purge`:
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
#### `openldap_password_crypt_salt_format`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `openldap_password_hash`:
  - used in **`templates/slapd/provider.conf.j2`**
#### `openldap_role`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools_SUSE.yml`_
  - used in _`tasks/aedir_tools_venv.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/monitoring.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/ae-dir-conf.prom.j2`**
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/slapo-rwm.conf.j2`**
#### `openldap_rootdse_alt_servers`:
  - used in **`templates/slapd/rootDSE.ldif.j2`**
#### `openldap_rundir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
#### `openldap_schema_files`:
  - used in _`tasks/configure_slapd.yml`_
#### `openldap_service_fqdn`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/tls_keygen.yml`_
  - used in **`templates/ae-dir-base.ldif.j2`**
  - used in **`templates/ae-dir-csrgen.sh.j2`**
  - used in **`templates/oath-ldap/bind_proxy.cfg.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/rootDSE.ldif.j2`**
  - used in **`templates/slapd/session.conf.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_aePerson.ldif.j2`**
  - used in **`templates/web2ldap/templates/connect.html.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/hosts.py.j2`**
#### `openldap_slapd_conf`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in **`templates/apparmor/ae-slapd.j2`**
  - used in **`templates/scripts/ae-dir-slapcat.sh.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
#### `openldap_slapd_group`:
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/pwsync.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in **`templates/scripts/ae-dir-fix-db-permissions.sh.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
#### `openldap_slapd_user`:
  - used in _`tasks/configure_slapd.yml`_
  - used in **`templates/scripts/ae-dir-fix-db-permissions.sh.j2`**
  - used in **`templates/systemd/ae-slapd.service.j2`**
#### `openldap_sockbuf_max_incoming`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_sockbuf_max_incoming_auth`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_syncrepl_network_timeout`:
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_syncrepl_providers`:
  - used in **`templates/oath-ldap/bind_proxy.cfg.j2`**
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_syncrepl_timeout`:
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_syncrepl_tls_cipher_suite`:
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_syncrepl_tls_protocol_min`:
  - used in **`templates/slapd/consumer.conf.j2`**
  - used in **`templates/slapd/provider.conf.j2`**
  - used in **`templates/slapd/session.conf.j2`**
#### `openldap_syslog_facility`:
  - used in **`templates/systemd/ae-slapd.service.j2`**
#### `openldap_syslog_level`:
  - used in **`templates/systemd/ae-slapd.service.j2`**
#### `openldap_threads`:
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_tls_cert_suffixes`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/slapd/global.conf.j2`**
  - used in **`templates/web2ldap/templates/ae-dir/add_slapd-replica.ldif.j2`**
#### `openldap_tls_cipher_suite`:
  - used in **`templates/slapd/global.conf.j2`**
#### `openldap_tls_protocol_min`:
  - used in **`templates/slapd/global.conf.j2`**
#### `slapd_check_authz_id`:
  - used in **`templates/slapd_checkmk.sh.j2`**
  - used in **`templates/slapd_metrics.sh.j2`**
#### `slapd_check_ldaps_uri`:
  - used in **`templates/slapd_checkmk.sh.j2`**
  - used in **`templates/slapd_metrics.sh.j2`**
#### `slapd_checkmk_local`:
  - used in _`tasks/monitoring.yml`_
#### `slapd_check_service_fqdn`:
  - used in _`defaults/main/main.yml`_
#### `smtp_admin_address`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
#### `smtp_cacert_filename`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools.yml`_
#### `smtp_cacert_pathname`:
  - used in _`tasks/aedir_tools.yml`_
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
  - used in **`templates/apparmor/uwsgi-python.j2`**
  - used in **`templates/oath-ldap/oathenroll_cnf.py.j2`**
#### `smtp_from_address`:
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
  - used in **`templates/oath-ldap/oathenroll_cnf.py.j2`**
#### `smtp_relay_url`:
  - used in **`templates/ae-dir-pwd/aedirpwd_cnf.py.j2`**
  - used in **`templates/oath-ldap/oathenroll_cnf.py.j2`**
#### `web2ldapcnf_prefix`:
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/apparmor/ae-apache.j2`**
#### `web2ldap_group`:
  - used in **`templates/systemd/web2ldap.service.j2`**
#### `web2ldap_min_version`:
  - used in _`tasks/web2ldap.yml`_
#### `web2ldap_monitor_access_allowed`:
  - used in **`templates/web2ldap/web2ldapcnf/__init__.py.j2`**
#### `web2ldap_session_limit`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/systemd/web2ldap.service.j2`**
  - used in **`templates/web2ldap/web2ldapcnf/__init__.py.j2`**
#### `web2ldap_session_per_ip_limit`:
  - used in **`templates/web2ldap/web2ldapcnf/__init__.py.j2`**
#### `web2ldap_session_remove`:
  - used in **`templates/web2ldap/web2ldapcnf/__init__.py.j2`**
#### `web2ldap_user`:
  - used in **`templates/systemd/web2ldap.service.j2`**
