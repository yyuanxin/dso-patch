
if exist "%~dp0db" (
    rmdir /S /Q "%~dp0db"
)

if exist "%~dp0db.zip" (
    del /F "%~dp0db.zip"
)

mkdir "%~dp0db"
SET TRIVY_DIR=%~dp0db\trivy
mkdir %TRIVY_DIR%
call scripts\trivy.cmd
SET GRYPE_DIR=%~dp0db\grype
mkdir %GRYPE_DIR%
call scripts\grype.cmd
SET CLAMAV_DIR=%~dp0db\clamav
mkdir %CLAMAV_DIR%
call scripts\clamav.cmd
SET OPENSCAP_DIR=%~dp0db\openscap
mkdir %OPENSCAP_DIR%
call scripts\openscap.cmd
SET SEMGREP_DIR=%~dp0db\semgrep
mkdir %SEMGREP_DIR%
call scripts\semgrep.cmd

powershell -Command "Compress-Archive -Path '%~dp0db' -DestinationPath 'db.zip'"
