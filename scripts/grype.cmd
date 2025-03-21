@echo off
echo =====Start download for grype=======

rem for old db v5; to be removed after db v6 process and app v0.88.0 & above implemented
call scripts\grype_v5.cmd

curl --ssl-no-revoke https://grype.anchore.io/databases/v6/latest.json -o %GRYPE_DIR%\latest.json

set grype_pattern="vulnerability-db_v6*"

for /F "tokens=* USEBACKQ" %%F in (`findstr path %GRYPE_DIR%\latest.json`) do ( set var=%%F )
set "zst_file=%var:~9,-3%"
set "zst_path=https://grype.anchore.io/databases/v6/%zst_file%"

echo Grype db package path is %zst_path%
set "modified_file=%zst_file::=_%"
echo Get package and rename file to %modified_file%
curl --ssl-no-revoke -L %zst_path% -o %GRYPE_DIR%\%modified_file%

echo =====Complete download for grype=======