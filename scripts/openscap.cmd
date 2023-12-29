@echo off
echo =====Start download for openscap=======

curl --ssl-no-revoke https://access.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2 -o %OPENSCAP_DIR%\rhel-8.oval.xml.bz2

:completed
echo =====Complete download for openscap=======
