#!/bin/bash

PREFIX="./defaults"
MAIN="$PREFIX/main/main.yml"
SLAPD="$PREFIX/main/slapd.yml"
SEEDING="$PREFIX/main/seeding.yml"
CLIENT="$PREFIX/main/client.yml"
WEB2LDAP="$PREFIX/main/web2ldap.yml"
AEDIRPWD="$PREFIX/main/ae-dir-pwd.yml"
OATHLDAP="$PREFIX/main/oath-ldap.yml"

cd ..

for p in $(yq r $MAIN --printMode p "*" | sort); do
    for r in $(rg -l "\{.*$p.*\}" | sort | uniq); do
        if [[ $r == "templates/slapd/"* ]]; then
            sd $p slapd_$p $r
            yq w -i $SLAPD slapd_$p "{{ $p }}"
        fi
        if [[ $r == "templates/ae-dir-base.ldif.j2" ]]; then
            sd $p seeding_$p $r
            yq w -i $SEEDING seeding_$p "{{ $p }}"
        fi
        if [[ $r == "templates/ldap.conf.j2" ]]; then
            sd $p client_$p $r
            yq w -i $CLIENT client_$p "{{ $p }}"
        fi
        if [[ $r == "templates/web2ldap/"* ]]; then
            sd $p w2ldap_$p $r
            yq w -i $WEB2LDAP w2ldap_$p "{{ $p }}"
        fi
        if [[ $r == "templates/ae-dir-pwd/"* ]]; then
            sd $p aedirpwd_$p $r
            yq w -i $AEDIRPWD aedirpwd_$p "{{ $p }}"
        fi
        if [[ $r == "templates/oath-ldap/"* ]]; then
            sd $p oathldap_$p $r
            yq w -i $OATHLDAP oathldap_$p "{{ $p }}"
        fi
    done
done
cd $PREFIX
