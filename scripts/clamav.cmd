@echo off
echo =====Start download for clamav=======
curl --ssl-no-revoke -O https://database.clamav.net/main.cvd -H "user-agent: CVDUPDATE" --output-dir %CLAMAV_DIR% 
curl --ssl-no-revoke -O https://database.clamav.net/daily.cvd -H "user-agent: CVDUPDATE" --output-dir %CLAMAV_DIR%
curl --ssl-no-revoke -O https://database.clamav.net/bytecode.cvd -H "user-agent: CVDUPDATE" --output-dir %CLAMAV_DIR%
echo =====Start download for clamav=======
