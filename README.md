# dso-patch
Script to pull installers for monthly patches and update database
For Windows

## How to use:

1. Unzip the folder

### To get latest installer files:

1. Edit software versions in `.\run.ps1`
2. Open up powershell and run `.\run.ps1`
    
    If encounter error that the script is not digitally signed and unable to execute, run this command in the powershell session
    
    ```c
    Set-ExecutionPolicy Unrestricted -Scope CurrentUser
    ```
    

Files will be downloaded and stored in `.\latest` folder.

- The hash values of installers files will be stored and generated in `.\latest\sha256.txt`

### To get latest database for grype, trivy, clamav:

1. Open up command prompt and run `.\db.cmd`

Files will be downloaded and zipped in `.\db.zip`

### What's Next
- Upload to s3 bucket (Refer to notion)