Usage files printed **bold** might benefit from a config interface

### `./main/main.yml`

#### `aedir_accesslog_suffix`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_addressbook_attrs`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_aeauthctoken_serial_regex`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_aedept_deptnumber_regex`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aegroup_cn_regex`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aehost_state`:
  - used in _`tasks/main.yml`_
#### `aedir_aelocation_cn_regex`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aenwdevice_visibility_sets`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_aeperson_uniqueid_regex`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_aeservice_sshpubkey_regex`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aeservice_uid_regex`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aesrvgroup_cn_regex`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aesudorule_cn_regex`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aetag_cn_regex`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_aeuser_sshpubkey_regex`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aeuser_uid_regex`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_aezone_cn_regex`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_base_zone`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_bin`:
  - used in _`tasks/main.yml`_
  - used in **`templates/profile-ae-dir.sh.j2`**
#### `aedir_confidential_person_attrs`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_cron_file`:
  - used in _`tasks/cron_provider.yml`_
  - used in _`tasks/cron.yml`_
#### `aedir_cron_minutes`:
#### `aedir_cron_offset`:
#### `aedir_etc`:
  - used in _`defaults/main/ae-dir-pwd.yml`_
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/aedir_init.yml`_
  - used in _`tasks/aedir_tools.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in _`tasks/tls_keygen.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/ae-dir-csrgen.sh.j2`**
  - used in **`templates/profile-ae-dir.sh.j2`**
#### `aedir_etc_openldap`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
#### `aedir_fake_search_roots`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_files_dirs`:
#### `aedir_homedirectory_hidden`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_homedirectory_prefixes`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_hosts`:
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_htdocsdir`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `aedir_htdocs_layout`:
  - used in _`tasks/main.yml`_
#### `aedir_htdocs_templates`:
  - used in _`tasks/main.yml`_
#### `aedir_init_aeadmins`:
  - used in _`defaults/main/seeding.yml`_
#### `aedir_init_aepersons`:
  - used in _`defaults/main/seeding.yml`_
#### `aedir_init_aezones`:
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_init_become`:
  - used in _`tasks/main.yml`_
#### `aedir_init_ticket_id`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`tasks/main.yml`_
#### `aedir_ldapi_services`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/system_accounts.yml`_
#### `aedir_logging_conf`:
  - used in _`tasks/aedir_tools.yml`_
#### `aedir_login_shells`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_main_provider_hostname`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/main.yml`_
#### `aedir_malloc_ld_preload`:
  - used in _`defaults/main/systemd.yml`_
#### `aedir_malloc_package`:
  - used in _`tasks/baseos_CentOS.yml`_
  - used in _`tasks/baseos_Debian.yml`_
  - used in _`tasks/baseos_SUSE.yml`_
#### `aedir_max_gid`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in **`templates/ae-dir-conf.prom.j2`**
#### `aedir_max_uid`:
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_metricsdir`:
  - used in _`tasks/cron.yml`_
  - used in _`tasks/monitoring.yml`_
#### `aedir_metrics_owner_group`:
  - used in _`tasks/monitoring.yml`_
#### `aedir_min_gid`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in **`templates/ae-dir-conf.prom.j2`**
#### `aedir_min_uid`:
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_news`:
  - used in _`tasks/main.yml`_
#### `aedir_nologin_shell`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/pwsync.yml`_
  - used in _`tasks/system_accounts.yml`_
#### `aedir_org_zone`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_pip_extra_args`:
  - used in _`tasks/aedir_tools_venv.yml`_
  - used in _`tasks/monitoring.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/web2ldap.yml`_
#### `aedir_pip_index_url`:
  - used in _`defaults/main/main.yml`_
#### `aedir_pip_install`:
#### `aedir_pip_install_options`:
#### `aedir_pip_needs_compiler`:
#### `aedir_pkg_repos`:
  - used in _`tasks/baseos_SUSE.yml`_
  - used in _`tasks/install_openldap_Debian.yml`_
#### `aedir_prefix`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools_CentOS.yml`_
  - used in _`tasks/aedir_tools_Debian.yml`_
  - used in _`tasks/aedir_tools_venv.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/monitoring.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/uwsgi.ini.j2`**
  - used in _`vars/CentOS.yml`_
  - used in _`vars/Debian.yml`_
#### `aedir_provider_lb_hostname`:
  - used in _`defaults/main/ae-dir-pwd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `aedir_providers_restrictions`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
#### `aedir_pwsync_cacert_filename`:
  - used in _`tasks/pwsync.yml`_
#### `aedir_pwsync_cacert_pathname`:
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/pwsync.yml`_
#### `aedir_pwsync_dn_regex`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_pwsync_listener_user`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/pwsync.yml`_
#### `aedir_pwsync_socket_dir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/pwsync.yml`_
#### `aedir_pwsync_socket_path`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/systemd.yml`_
#### `aedir_pwsync_targetpassword`:
  - used in _`tasks/pwsync.yml`_
#### `aedir_pwsync_targetpwfile`:
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/pwsync.yml`_
#### `aedir_python`:
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/aedir_tools_CentOS.yml`_
  - used in _`tasks/aedir_tools_Debian.yml`_
  - used in _`tasks/cron_provider.yml`_
  - used in _`tasks/main.yml`_
  - used in **`templates/slapd_checkmk.sh.j2`**
  - used in **`templates/slapd_metrics.sh.j2`**
#### `aedir_python_env`:
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/cron.yml`_
  - used in **`templates/slapd_checkmk.sh.j2`**
  - used in **`templates/slapd_metrics.sh.j2`**
#### `aedir_python_sitepackages`:
  - used in _`defaults/main/apparmor.yml`_
#### `aedir_python_warnings`:
  - used in _`defaults/main/main.yml`_
#### `aedir_replicas_restrictions`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_rootdn_gid_number`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_rootdn_uid_number`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_rundir`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/cron_provider.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/uwsgi.ini.j2`**
#### `aedir_sbin`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/aedir_tools_provider.yml`_
  - used in _`tasks/aedir_tools.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/monitoring.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in **`templates/profile-ae-dir.sh.j2`**
#### `aedir_schema_prefix`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`tasks/configure_slapd.yml`_
#### `aedir_service_manager`:
#### `aedir_session_suffix`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_srvgroup`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`tasks/main.yml`_
#### `aedir_sshkey_perms`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_sshpublickey_self_filter`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_suffix`:
  - used in _`defaults/main/ae-dir-pwd.yml`_
  - used in _`defaults/main/client.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in **`files/ae-dir-pwd/templates/en/notify_user.txt`**
  - used in _`tasks/aedir_init.yml`_
  - used in _`tasks/main.yml`_
#### `aedir_systemd_dir`:
  - used in _`tasks/configure_apache2.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/pwsync.yml`_
  - used in _`tasks/web2ldap.yml`_
#### `aedir_systemd_hardening`:
  - used in _`defaults/main/systemd.yml`_
#### `aedir_systemd_logging`:
  - used in _`defaults/main/systemd.yml`_
#### `aedir_templates_dirs`:
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/pwd.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in _`tasks/web2ldap.yml`_
#### `aedir_unique_person_zones`:
  - used in _`defaults/main/slapd.yml`_
#### `aedir_user_mail_enabled`:
  - used in _`defaults/main/ae-dir-pwd.yml`_
#### `aedir_username_gen_trials`:
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_username_length`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_username_maxlen`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_username_minlen`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `aedir_uwsgi_params`:
#### `aedir_who_srvgroup`:
  - used in _`defaults/main/slapd.yml`_
#### `ae_expiry_status_defaults`:
  - used in _`defaults/main/web2ldap.yml`_
#### `aeticketid_regex`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `apache_access_log`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
  - used in **`templates/logrotate_ae-apache.j2`**
#### `apache_cacert_filename`:
  - used in _`tasks/configure_apache2.yml`_
#### `apache_cacert_pathname`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_cert_filename`:
  - used in _`tasks/configure_apache2.yml`_
#### `apache_cert_pathname`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_conf`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/configure_apache2.yml`_
#### `apache_error_log`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_group`:
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_htdocs_requires`:
  - used in _`defaults/main/main.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_key_filename`:
  - used in _`tasks/configure_apache2.yml`_
#### `apache_key_pathname`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_log_format`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_log_level`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_oath_requires`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_pid_file`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_pwd_requires`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_rundir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_apache2.yml`_
#### `apache_server_admin`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_service_fqdn`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_ssl_cipher_suite`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_ssl_protocol`:
  - used in **`templates/apache2.conf.j2`**
#### `apache_status_urlpath`:
  - used in _`defaults/main/apparmor.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_user`:
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `apache_web2ldap_requires`:
  - used in **`templates/apache2.conf.j2`**
#### `apparmor_enabled`:
  - used in _`defaults/main/systemd.yml`_
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
  - used in _`defaults/main/apparmor.yml`_
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
#### `oath_bind_listener`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/aedir_tools.yml`_
  - used in _`tasks/apparmor.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/services.yml`_
#### `oath_dict`:
#### `oath_ldap_cfg_dir`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/oathenroll.yml`_
  - used in _`tasks/oath_ldap.yml`_
#### `oath_ldap_dn_regex`:
  - used in _`defaults/main/slapd.yml`_
#### `oath_ldap_enabled`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `oath_ldap_keys_dir`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`tasks/oath_ldap.yml`_
#### `oath_ldap_oathenroll_web_group`:
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/oathenroll.yml`_
#### `oath_ldap_oathenroll_web_user`:
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/systemd.yml`_
#### `oath_ldap_socket_dir`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/oath_ldap.yml`_
#### `oath_ldap_socket_path`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/slapd.yml`_
#### `oath_listener_user`:
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/oath_ldap.yml`_
#### `openldap_backup_compressor`:
  - used in **`templates/scripts/ae-dir-slapcat.sh.j2`**
#### `openldap_backup_cron_args`:
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
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/client.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in _`tasks/tls_files.yml`_
#### `openldap_cert_filename`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/tls_files.yml`_
#### `openldap_cert_pathname`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/client.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`tasks/tls_files.yml`_
#### `openldap_conn_max_pending`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_conn_max_pending_auth`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_csr_subjectaltnames`:
#### `openldap_csr_subjectdn`:
  - used in _`tasks/tls_keygen.yml`_
  - used in **`templates/ae-dir-csrgen.sh.j2`**
#### `openldap_data`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in **`templates/scripts/ae-dir-fix-db-permissions.sh.j2`**
  - used in **`templates/scripts/ae-dir-replica-reset.sh.j2`**
#### `openldap_db_params`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_dhparam_numbits`:
  - used in _`tasks/tls_files.yml`_
#### `openldap_dhparam_pathname`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`tasks/tls_files.yml`_
#### `openldap_idletimeout`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_key_filename`:
  - used in _`defaults/main/main.yml`_
  - used in _`tasks/configure_apache2.yml`_
#### `openldap_key_pathname`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/client.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`tasks/configure_apache2.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in _`tasks/tls_keygen.yml`_
#### `openldap_ldapi_socket`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
#### `openldap_ldapi_uri`:
  - used in _`defaults/main/ae-dir-pwd.yml`_
  - used in _`defaults/main/client.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in **`templates/slapd_checkmk.sh.j2`**
  - used in **`templates/slapd_metrics.sh.j2`**
#### `openldap_limit_nofile`:
  - used in _`defaults/main/systemd.yml`_
#### `openldap_listener_threads`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_log_level`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_log_purge`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_password_crypt_salt_format`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_password_hash`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_role`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`tasks/aedir_tools_SUSE.yml`_
  - used in _`tasks/aedir_tools_venv.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/cron.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/monitoring.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/ae-dir-conf.prom.j2`**
#### `openldap_rootdse_alt_servers`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_rundir`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/configure_slapd.yml`_
#### `openldap_schema_files`:
  - used in _`tasks/configure_slapd.yml`_
#### `openldap_service_fqdn`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/seeding.yml`_
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
  - used in _`tasks/main.yml`_
  - used in _`tasks/tls_keygen.yml`_
  - used in **`templates/ae-dir-csrgen.sh.j2`**
#### `openldap_slapd_conf`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in **`templates/scripts/ae-dir-slapcat.sh.j2`**
#### `openldap_slapd_group`:
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in _`tasks/oath_ldap.yml`_
  - used in _`tasks/pwsync.yml`_
  - used in _`tasks/tls_files.yml`_
  - used in **`templates/scripts/ae-dir-fix-db-permissions.sh.j2`**
#### `openldap_slapd_user`:
  - used in _`defaults/main/systemd.yml`_
  - used in _`tasks/configure_slapd.yml`_
  - used in **`templates/scripts/ae-dir-fix-db-permissions.sh.j2`**
#### `openldap_sockbuf_max_incoming`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_sockbuf_max_incoming_auth`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_syncrepl_network_timeout`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_syncrepl_providers`:
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`defaults/main/slapd.yml`_
#### `openldap_syncrepl_timeout`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_syncrepl_tls_cipher_suite`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_syncrepl_tls_protocol_min`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_syslog_facility`:
  - used in _`defaults/main/systemd.yml`_
#### `openldap_syslog_level`:
  - used in _`defaults/main/systemd.yml`_
#### `openldap_threads`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_tls_cert_suffixes`:
  - used in _`defaults/main/slapd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `openldap_tls_cipher_suite`:
  - used in _`defaults/main/slapd.yml`_
#### `openldap_tls_protocol_min`:
  - used in _`defaults/main/slapd.yml`_
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
  - used in _`defaults/main/ae-dir-pwd.yml`_
  - used in _`defaults/main/main.yml`_
#### `smtp_cacert_filename`:
  - used in _`tasks/aedir_tools.yml`_
#### `smtp_cacert_pathname`:
  - used in _`defaults/main/ae-dir-pwd.yml`_
  - used in _`defaults/main/apparmor.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
  - used in _`tasks/aedir_tools.yml`_
#### `smtp_from_address`:
  - used in _`defaults/main/ae-dir-pwd.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
#### `smtp_relay_url`:
  - used in _`defaults/main/ae-dir-pwd.yml`_
  - used in _`defaults/main/oath-ldap.yml`_
#### `web2ldapcnf_prefix`:
  - used in _`defaults/main/apparmor.yml`_
  - used in _`tasks/web2ldap.yml`_
  - used in **`templates/apache2.conf.j2`**
#### `web2ldap_group`:
  - used in _`defaults/main/systemd.yml`_
#### `web2ldap_min_version`:
  - used in _`tasks/web2ldap.yml`_
#### `web2ldap_monitor_access_allowed`:
  - used in _`defaults/main/web2ldap.yml`_
#### `web2ldap_session_limit`:
  - used in _`defaults/main/main.yml`_
  - used in _`defaults/main/systemd.yml`_
  - used in _`defaults/main/web2ldap.yml`_
#### `web2ldap_session_per_ip_limit`:
  - used in _`defaults/main/web2ldap.yml`_
#### `web2ldap_session_remove`:
  - used in _`defaults/main/web2ldap.yml`_
#### `web2ldap_user`:
  - used in _`defaults/main/systemd.yml`_
