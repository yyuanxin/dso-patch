@echo off
echo =====Start download for Semgrep=======
curl --ssl-no-revoke https://semgrep.dev/c/p/default -o %SEMGREP_DIR%\rules.yml 
echo =====Start download for Semgrep=======
