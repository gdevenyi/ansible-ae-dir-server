#!/bin/bash

PREFIX="./defaults"
MAIN="$PREFIX/main/01-main.yml"
SLAPD="$PREFIX/main/slapd.yml"
SEEDING="$PREFIX/main/seeding.yml"
CLIENT="$PREFIX/main/client.yml"
WEB2LDAP="$PREFIX/main/web2ldap.yml"
AEDIRPWD="$PREFIX/main/ae-dir-pwd.yml"
OATHLDAP="$PREFIX/main/oath-ldap.yml"
SYSTEMD="$PREFIX/main/systemd.yml"
APPARMOR="$PREFIX/main/apparmor.yml"

cd ..

for p in $(yq r $MAIN --printMode p "*" | sort); do
    for r in $(rg -l "\{.* $p.*\}|\.get\(.$p." | sort | uniq); do
        if [[ $r == "templates/slapd/"* ]]; then
            sd $p slapd_$p $r
            [ ! -f $SLAPD ] && touch $SLAPD
            yq w -i $SLAPD slapd_$p "{{ $p }}"
        fi
        if [[ $r == "templates/ae-dir-base.ldif.j2" ]]; then
            sd $p seeding_$p $r
            [ ! -f $SEEDING ] && touch $SEEDING
            yq w -i $SEEDING seeding_$p "{{ $p }}"
        fi
        if [[ $r == "templates/ldap.conf.j2" ]]; then
            sd $p client_$p $r
            [ ! -f $CLIENT ] && touch $CLIENT
            yq w -i $CLIENT client_$p "{{ $p }}"
        fi
        if [[ $r == "templates/web2ldap/"* ]]; then
            sd $p w2ldap_$p $r
            [ ! -f $WEB2LDAP ] && touch $WEB2LDAP
            yq w -i $WEB2LDAP w2ldap_$p "{{ $p }}"
        fi
        if [[ $r == "templates/ae-dir-pwd/"* ]]; then
            sd $p aedirpwd_$p $r
            [ ! -f $AEDIRPWD ] && touch $AEDIRPWD
            yq w -i $AEDIRPWD aedirpwd_$p "{{ $p }}"
        fi
        if [[ $r == "templates/oath-ldap/"* ]]; then
            sd $p oathldap_$p $r
            [ ! -f $OATHLDAP ] && touch $OATHLDAP
            yq w -i $OATHLDAP oathldap_$p "{{ $p }}"
        fi
        if [[ $r == "templates/systemd/"* ]]; then
            sd $p systemd_$p $r
            [ ! -f $SYSTEMD ] && touch $SYSTEMD
            yq w -i $SYSTEMD systemd_$p "{{ $p }}"
        fi
        if [[ $r == "templates/apparmor/"* ]]; then
            sd $p apparmor_$p $r
            [ ! -f $APPARMOR ] && touch $APPARMOR
            yq w -i $APPARMOR apparmor_$p "{{ $p }}"
        fi
    done
done
cd $PREFIX
