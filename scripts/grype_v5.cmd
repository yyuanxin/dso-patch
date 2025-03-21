@echo off
echo =====Start download for grype=======

curl --ssl-no-revoke https://toolbox-data.anchore.io/grype/databases/listing.json -o %GRYPE_DIR%\listing.json

powershell -Command "(gc %GRYPE_DIR%\listing.json) -replace '}, {', \"}`n {\" -replace '], ', \"]`n \" | Out-File -encoding ASCII %GRYPE_DIR%\listing_modified.json"

set grype_pattern="vulnerability-db_v5_*"

for /F "tokens=1,2,3,* delims=," %%a in ('FINDSTR /r /c:%grype_pattern% %GRYPE_DIR%\listing_modified.json') do (

  setlocal enabledelayedexpansion

  for /F "tokens=2" %%A in ("%%c") do (
    set url=%%A

    for %%1 in ("!url:/= !") do (
      set original_filename=%%1
    )
    set original_filename=!original_filename:"=!
    set output_filename=!original_filename::=_!

    for /F "tokens=1,2 delims==" %%1 in ("!original_filename!=!output_filename!") do (
      set url=!url:%%1=%%2!
    )

    curl --ssl-no-revoke -L %%A -o %GRYPE_DIR%\!output_filename!
  )
  
  echo {"available":{%%a,%%b,"url": !url!,%%d]}} > %GRYPE_DIR%\listing.json

  endlocal
  
  goto :completed
)

:completed
echo =====Complete download for grype=======