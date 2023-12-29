@echo off
echo =====Start download for trivy=======

curl --ssl-no-revoke https://api.github.com/repos/oras-project/oras/releases/latest -o scripts\oras-latest.json

set oras_pattern="https://github.com/oras-project/oras/releases/download.*windows.*tar.gz"

for /F "tokens=2" %%a in ('FINDSTR /r /c:%oras_pattern% scripts\oras-latest.json') do (
  set url=%%a

  setlocal enabledelayedexpansion

  if "!url:asc=!"=="!url!" (
    set filename=oras_windows.tar.gz
  ) else (
    set filename=oras_windows.tar.gz.asc
  )

  curl -L !url! -o scripts/!filename!

  endlocal
)

tar -xzf scripts\oras_windows.tar.gz -C scripts

scripts\oras pull ghcr.io/aquasecurity/trivy-db:2 -a -o %TRIVY_DIR%

scripts\oras pull ghcr.io/aquasecurity/trivy-java-db:1 -a -o %TRIVY_DIR%


echo =====Completed download for trivy=======