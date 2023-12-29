<#
.SYNOPSIS
	Downloads installer files to ./latest folder
    Generates and stores hash values of installer files to ./latest/sha256 file
.DESCRIPTION
	This PowerShell script downloads the specified version installer files to ./latest folder. Administrator rights are required.
    
    Constraints:
    - [Maintenance of URLs] Download paths may be outdated over time. Update of url links will be required when path is no longer valid.

    Exclusions:
    - Fortify
    - Parasoft
    _________________________________________________________________________
    Tool                | Expected output
    ____________________|____________________________________________________
    PGADMIN             | pgadmin-<VERSION>-x64.exe
    OPENSSL             | Win64OpenSSL-<VERSION>.exe
    IAM_AUTHENTICATOR   | aws-iam-authenticator_<VERSION>_windows_amd64.exe
    HELM                | helm-v<VERSION>-windows-amd64.zip
    MYSQLWORKBENCH      | mysql-workbench-community-<VERSION>-winx64.msi
    UBI 8               | ubi8_<VERSION>.tar
    UBI 8 MINIMAL       | ubi8-minimal_<VERSION>.tar
    AWS_CLI             | awscli-exe-linux-x86_64-<VERSION>.zip
    CORRETO 11          | amazon-correto-<VERSION>-linux-x64.tar.gz 
    CORRETO 17          | amazon-correto-<VERSION>-linux-x64.tar.gz 
    DEPENDENCY CHECK    | dependency-check-<VERSION>-release.zip
    MAVEN               | apache-maven-<VERSION>-bin.tar.gz 
    NODEJS 14           | node-v<VERSION>-linux-x64.tar.gz 
    NODEJS 18           | node-v<VERSION>-linux-x64.tar.gz 
    NODEJS 20           | node-v<VERSION>-linux-x64.tar.gz 
    PYTHON 39           | Python-<VERSION>.tgz 
    PYTHON 310          | Python-<VERSION>.tgz
    SONARQUBE           | sonarqube-<VERSION>.zip
    SONAR SCANNER CLI   | sonar-scanner-cli-<VERSION>-linux.zip
    OPENSCAP            | scap-security-guide-<VERSION>.zip
    CLAMAV              | clamav-<VERSION>.tar.gz
    GRYPE               | grype_<VERSION>_linux_amd64.tar.gz
    TRIVY               | trivy_<VERSION>_Linux-64bit.tar.gz
    COSIGN              | cosign-linux-amd64
    HADOLINT            | hadolint-v<VERSION>.tar.gz
    __________________________________________________________________________

.NOTES
	Last updated on 11 October 2023
#>

################### VERSIONS ###################
# COMMENT OUT THOSE WITH NO UPDATE TO DOWNLOAD #
################################################
################ For DSO tools ################# 
# $BURP_VERSION="2023.11.1"
# $GITLAB_VERSION="16.5.3"
# $GITLAB_RUNNER_VERSION="16.6.1"
# $GITLAB_CHART_VERSION="0.59.2"
################ For Mgt-client ################
# $PGADMIN_VERSION="8.0" 
# $OPENSSL_VERSION="1.1.1w"
# $KUBECTL_VERSION="1.26.1"
# $IAM_AUTHENTICATOR_VERSION="0.6.14"
# $HELM_VERSION="3.13.2" 
# $MYSQLWORKBENCH_VERSION="8.0.34"
############### For Runner Images ###############
# $UBI8_VERSION="8.9-1028"
# $UBI8_MINIMAL_VERSION="8.9-1029"
# $AWS_CLI_VERSION="2.15.0" 
# $PYTHON_39_VERSION="3.9.18"
# $PYTHON_310_VERSION="3.10.13"
# $CORRETO_11_VERSION="11.0.21.9.1"
# $CORRETO_17_VERSION="17.0.9.8.1"
$DEPENDENCY_CHECK_VERSION="9.0.7"
# $MAVEN_VERSION="3.9.6"
# $NODE_18_VERSION="18.18.2"
# $NODE_20_VERSION="20.10.0"
# $SONARQUBE_VERSION_9="9.9.3.79811"
# $SONAR_SCANNER_CLI_VERSION="5.0.1.3006"
# $OPENSCAP_VERSION="0.1.71"
# $CLAMAV_VERSION="1.2.1"
# $GRYPE_VERSION="0.73.4"
# $TRIVY_VERSION="0.48.0"
# $COSIGN_VERSION="2.0.2"
# $HADOLINT_VERSION="2.12.0"
# $NODE_14_VERSION="14.21.3"
# $SONARQUBE_VERSION_8="8.9.10.61524"
# $LOMBOK_VERSION="1.18.30"
################################################
# HELPER FUNCTIONS                             #
################################################
$WGET=".\tools\wget\wget.exe"
$CRANE=".\tools\crane\crane.exe"
$DOWNLOAD_DIR=".\latest"
$HASH_TXTFILE="sha256.txt"
function downloadFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$URL
    )
    if (![string]::IsNullOrEmpty($Version)) {
        Write-Output "Starting download for $Name"
        Start-Process -NoNewWindow -FilePath $WGET -ArgumentList "--no-check-certificate -P $DOWNLOAD_DIR --content-disposition $URL" -Wait
    }
}

function downloadAndRenameFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$URL,
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )
    if (![string]::IsNullOrEmpty($Version)) {
        Write-Output "Starting download for $Name"
        Start-Process -NoNewWindow -FilePath $WGET -ArgumentList "--content-disposition $URL -O $DOWNLOAD_DIR\$FileName" -Wait
    }
} 

function craneFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$URL,
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    if (![string]::IsNullOrEmpty($Version)) {
        Write-Output "Starting crane pull for $Name"
        Start-Process -NoNewWindow -FilePath $CRANE -ArgumentList "pull $URL $DOWNLOAD_DIR\$FilePath" -Wait
    }
}

function wipeLatest {
    Remove-Item $DOWNLOAD_DIR\* -Recurse -Force
}

function hashFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )
    $FilePath = "$DOWNLOAD_DIR\$FileName"
    $HashAlgorithm = "sha256"
    
    # Use CertUtil to calculate the hash
    $certUtilOutput = & certutil -hashfile "$FilePath" $HashAlgorithm

    # Extract the hash from the output
    $hash = $certUtilOutput | Select-String -Pattern "^([A-F0-9]+)"

    if ($hash) {
        return $hash.Matches.Groups[1].Value
    } else {
        Write-Host "Failed to calculate hash for file: $FilePath"
        return $null
    }
}

function writeTextFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [Parameter(Mandatory = $true)]
        [string]$HashValue
    )
    # Append content to the file
    try {
        $contentWithNewLine = $FileName + "," + $HashValue + [Environment]::NewLine
        Add-Content -Path "$DOWNLOAD_DIR\$HASH_TXTFILE" -Value $contentWithNewLine -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write sha256 text file: $($_.Exception.Message)"
    }
}

################### URLS #######################
# Main Implementation + Specify URLs here      #
################################################

function DSO_TOOLS {param()
    Write-Output "Downloading DSO Tools"
    ## Burpsuite
    if ($global:BURP_VERSION -eq $null -and ![string]::IsNullOrEmpty($BURP_VERSION)) {
        $BURP_LINK_PREFIX="https://portswigger.net/burp/releases/download?product=enterprise&"
        $BURP_SERVER_LINK="${BURP_LINK_PREFIX}${BURP_VERSION}&type=updater"
        $BURP_AGENT_LINK="${BURP_LINK_PREFIX}${BURP_VERSION}&type=agentupdate&component=1"

        downloadFile "Burpsuite Server" $BURP_VERSION $BURP_SERVER_LINK
        downloadFile "Burpsuite Agent" $BURP_VERSION $BURP_AGENT_LINK
    } else {
        Write-Output "Skipping Burpsuite"
    }

    ## Gitlab
    if ($global:GITLAB_VERSION -eq $null -and ![string]::IsNullOrEmpty($GITLAB_VERSION)) {
        $GITLAB_EE_LINK="https://packages.gitlab.com/gitlab/gitlab-ee/packages/el/8/gitlab-ee-${GITLAB_VERSION}-ee.0.el8.x86_64.rpm/download.rpm"
        $GITLAB_CHART_LINK="https://gitlab.com/gitlab-org/charts/gitlab-runner/-/archive/v${GITLAB_CHART_VERSION}/gitlab-runner-v${GITLAB_CHART_VERSION}.tar.gz"
        $GITLAB_RUNNER_ALPINE_LINK="registry.gitlab.com/gitlab-org/gitlab-runner:alpine-v$GITLAB_RUNNER_VERSION"
        $GITLAB_RUNNER_HELPER_LINK="registry.gitlab.com/gitlab-org/gitlab-runner/gitlab-runner-helper:x86_64-v$GITLAB_RUNNER_VERSION"
        $GITLAB_RUNNER_UBI_LINK="https://gitlab-runner-downloads.s3.amazonaws.com/ubi-images/v$GITLAB_RUNNER_VERSION/gitlab-runner"
        $GITLAB_RUNNER_HELPER_UBI_LINK="https://gitlab-runner-downloads.s3.amazonaws.com/ubi-images/v$GITLAB_RUNNER_VERSION/gitlab-runner-helper"
        $GITLAB_TINI_UBI_LINK="https://gitlab-runner-downloads.s3.amazonaws.com/ubi-images/v$GITLAB_RUNNER_VERSION/tini"

        downloadFile "Gitlab EE" $GITLAB_VERSION $GITLAB_EE_LINK
        downloadFile "Gitlab EE Chart" $GITLAB_CHART_VERSION $GITLAB_CHART_LINK
        downloadFile "Gitlab Runner - Ubi Image" $GITLAB_RUNNER_VERSION $GITLAB_RUNNER_UBI_LINK
        downloadFile "Gitlab Runner Helper - Ubi Image" $GITLAB_RUNNER_VERSION $GITLAB_RUNNER_UBI_LINK
        downloadFile "Gitlab Tini - Ubi Image" $GITLAB_RUNNER_VERSION $GITLAB_TINI_UBI_LINK
        craneFile "Gitlab Runner Alpine" $GITLAB_RUNNER_VERSION $GITLAB_RUNNER_ALPINE_LINK "gitlab-runner_alpine-v$GITLAB_RUNNER_VERSION.tar"
        craneFile "Gitlab Runner Helper" $GITLAB_RUNNER_VERSION $GITLAB_RUNNER_HELPER_LINK "gitlab-runner-helper_x86_64-v$GITLAB_RUNNER_VERSION.tar"
    } else {
        Write-Output "Skipping Gitlab"
    }

}

function MGT_CLIENT_TOOLS {param()
    Write-Output "Downloading Management Client Tools"
    ## PGadmin
    if ($global:PGADMIN_VERSION -eq $null -and ![string]::IsNullOrEmpty($PGADMIN_VERSION)) {
        $PGADMIN_LINK="https://ftp.postgresql.org/pub/pgadmin/pgadmin4/v${PGADMIN_VERSION}/windows/pgadmin4-${PGADMIN_VERSION}-x64.exe"

        downloadFile "PGadmin" $PGADMIN_VERSION $PGADMIN_LINK
    } else {
        Write-Output "Skipping Pgadmin"
    }

    ## OpenSSL
    if ($global:OPENSSL_VERSION -eq $null -and ![string]::IsNullOrEmpty($OPENSSL_VERSION)) {
        $OPENSSL_VERSION=$OPENSSL_VERSION.replace('.','_')
        $OPENSSL_LINK="https://slproweb.com/download/Win64OpenSSL-${OPENSSL_VERSION}.exe"

        downloadFile "OpenSSL" $OPENSSL_VERSION $OPENSSL_LINK
    } else {
        Write-Output "Skipping Openssl"
    }

    ## Kubectl
    if ($global:KUBECTL_VERSION -eq $null -and ![string]::IsNullOrEmpty($KUBECTL_VERSION)) {
        $KUBECTL_LINK="https://dl.k8s.io/release/v$KUBECTL_VERSION/bin/windows/amd64/kubectl.exe"

        downloadFile "KubeCTL" $KUBECTL_VERSION $KUBECTL_LINK
    } else {
        Write-Output "Skipping Kubectl"
    }

    ## IAM Authenticator
    if ($global:IAM_AUTHENTICATOR_VERSION -eq $null -and ![string]::IsNullOrEmpty($IAM_AUTHENTICATOR_VERSION)) {
        $IAM_AUTHENTICATOR_LINK="https://github.com/kubernetes-sigs/aws-iam-authenticator/releases/download/v${IAM_AUTHENTICATOR_VERSION}/aws-iam-authenticator_${IAM_AUTHENTICATOR_VERSION}_windows_amd64.exe"

        downloadFile "Iam Authenticator" $IAM_AUTHENTICATOR_VERSION $IAM_AUTHENTICATOR_LINK
    } else {
        Write-Output "Skipping IAM Authenticator"
    }

    ## Helm
    if ($global:HELM_VERSION -eq $null -and ![string]::IsNullOrEmpty($HELM_VERSION)) {
        $HELM_LINK="https://get.helm.sh/helm-v${HELM_VERSION}-windows-amd64.zip"

        downloadFile "Helm" $HELM_VERSION $HELM_LINK
    } else {
        Write-Output "Skipping Helm"
    }

    ## MySQL Workbench
    if ($global:MYSQLWORKBENCH_VERSION -eq $null -and ![string]::IsNullOrEmpty($MYSQLWORKBENCH_VERSION)) {
        $MYSQLWORKBENCH_LINK="https://dev.mysql.com/get/Downloads/MySQLGUITools/mysql-workbench-community-${MYSQLWORKBENCH_VERSION}-winx64.msi"

        downloadFile "MySQL Workbench" $MYSQLWORKBENCH_VERSION $MYSQLWORKBENCH_LINK
    } else {
        Write-Output "Skipping MySQL Workbench"
    }

}

function RUNNER_IMAGES {param()
    Write-Output "Downloading Gitlab Runner Images"
    ## UBI8
    if ($global:UBI8_VERSION -eq $null -and ![string]::IsNullOrEmpty($UBI8_VERSION)) {
        $UBI8_LINK="registry.access.redhat.com/ubi8/ubi:${UBI8_VERSION}"

        craneFile "UBI8" $UBI8_VERSION $UBI8_LINK "ubi8_$UBI8_VERSION.tar"
    } else {
        Write-Output "Skipping Ubi8"
    }

    ## UBI8 MINIMAL
    if ($global:UBI8_MINIMAL_VERSION -eq $null -and ![string]::IsNullOrEmpty($UBI8_MINIMAL_VERSION)) {
        $UBI8_MINIMAL_LINK="registry.access.redhat.com/ubi8/ubi-minimal:${UBI8_MINIMAL_VERSION}"

        craneFile "Ubi8 Minimal" $UBI8_MINIMAL_VERSION $UBI8_MINIMAL_LINK "ubi8-minimal_$UBI8_MINIMAL_VERSION.tar"
    } else {
        Write-Output "Skipping Ubi8 Minimal"
    }

    ## AWS CLI
    if ($global:AWS_CLI_VERSION -eq $null -and ![string]::IsNullOrEmpty($AWS_CLI_VERSION)) {
        $AWS_CLI_LINK="https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${AWS_CLI_VERSION}.zip"

        downloadFile "AWS CLI" $AWS_CLI_VERSION $AWS_CLI_LINK
    } else {
        Write-Output "Skipping AWS CLI"
    }

    ## Python 3.9
    if ($global:PYTHON_39_VERSION -eq $null -and ![string]::IsNullOrEmpty($PYTHON_39_VERSION)) {
        $PYTHON_39_LINK="https://www.python.org/ftp/python/${PYTHON_39_VERSION}/Python-${PYTHON_39_VERSION}.tgz"

        downloadFile "Python 3.9" $PYTHON_39_VERSION $PYTHON_39_LINK
    } else {
        Write-Output "Skipping Python 3.9"
    }

    ## Python 3.10
    if ($global:PYTHON_310_VERSION -eq $null -and ![string]::IsNullOrEmpty($PYTHON_310_VERSION)) {
        $PYTHON_310_LINK="https://www.python.org/ftp/python/${PYTHON_310_VERSION}/Python-${PYTHON_310_VERSION}.tgz"

        downloadFile "Python 3.10" $PYTHON_310_VERSION $PYTHON_310_LINK
    } else {
        Write-Output "Skipping Python 3.10"
    }

    ## Correto 11
    if ($global:CORRETO_11_VERSION -eq $null -and ![string]::IsNullOrEmpty($CORRETO_11_VERSION)) {
        $CORRETO_11_LINK="https://corretto.aws/downloads/resources/${CORRETO_11_VERSION}/amazon-corretto-${CORRETO_11_VERSION}-linux-x64.tar.gz"
        
        downloadFile "Correto 11" $CORRETO_11_VERSION $CORRETO_11_LINK
    } else {
        Write-Output "Skipping Correto 11"
    }

    ## Correto 17
    if ($global:CORRETO_17_VERSION -eq $null -and ![string]::IsNullOrEmpty($CORRETO_17_VERSION)) {
        $CORRETO_17_LINK="https://corretto.aws/downloads/resources/${CORRETO_17_VERSION}/amazon-corretto-${CORRETO_17_VERSION}-linux-x64.tar.gz"
        
        downloadFile "Correto 17" $CORRETO_17_VERSION $CORRETO_17_LINK
    } else {
        Write-Output "Skipping Correto 17"
    }

    ## Dependency Check
    if ($global:DEPENDENCY_CHECK_VERSION -eq $null -and ![string]::IsNullOrEmpty($DEPENDENCY_CHECK_VERSION)) {
        $DEPENDENCY_CHECK_LINK="https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip"

        downloadFile "Dependency Check" $DEPENDENCY_CHECK_VERSION $DEPENDENCY_CHECK_LINK
    } else {
        Write-Output "Skipping Dependency Check"
    }

    ## Maven
    if ($global:MAVEN_VERSION -eq $null -and ![string]::IsNullOrEmpty($MAVEN_VERSION)) {
        $MAVEN_PREFIX="3"
        $MAVEN_LINK="https://dlcdn.apache.org/maven/maven-${MAVEN_PREFIX}/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz"

        downloadFile "Maven" $MAVEN_VERSION $MAVEN_LINK
    } else {
        Write-Output "Skipping Maven"
    }

    ## NodeJS 14
    if ($global:NODE_14_VERSION -eq $null -and ![string]::IsNullOrEmpty($NODE_14_VERSION)) {
        $NODE_14_LINK="https://nodejs.org/dist/v${NODE_14_VERSION}/node-v${NODE_14_VERSION}-linux-x64.tar.gz"

        downloadFile "NodeJS 14" $NODE_14_VERSION $NODE_14_LINK
    } else {
        Write-Output "Skipping NodeJS 14"
    }
    
    ## NodeJS 18
    if ($global:NODE_18_VERSION -eq $null -and ![string]::IsNullOrEmpty($NODE_18_VERSION)) {
        $NODE_18_LINK="https://nodejs.org/dist/v${NODE_18_VERSION}/node-v${NODE_18_VERSION}-linux-x64.tar.gz"

        downloadFile "NodeJS 18" $NODE_18_VERSION $NODE_18_LINK
    } else {
        Write-Output "Skipping NodeJS 18"
    }

    ## NodeJS 20
    if ($global:NODE_20_VERSION -eq $null -and ![string]::IsNullOrEmpty($NODE_20_VERSION)) {
        $NODE_20_LINK="https://nodejs.org/dist/v${NODE_20_VERSION}/node-v${NODE_20_VERSION}-linux-x64.tar.gz"

        downloadFile "NodeJS 20" $NODE_20_VERSION $NODE_20_LINK
    } else {
        Write-Output "Skipping NodeJS 20"
    }

    ## Sonarqube8
    if ($global:SONARQUBE_VERSION_8 -eq $null -and ![string]::IsNullOrEmpty($SONARQUBE_VERSION_8)) {
        $SONARQUBE_8_LINK="https://github.com/SonarSource/sonarqube/archive/refs/tags/${SONARQUBE_VERSION_8}.zip"

        downloadFile "Sonarqube" $SONARQUBE_VERSION_8 $SONARQUBE_8_LINK
    } else {
        Write-Output "Skipping Sonarqube8"
    }

    ## Sonarqube9
    if ($global:SONARQUBE_VERSION_9 -eq $null -and ![string]::IsNullOrEmpty($SONARQUBE_VERSION_9)) {
        $SONARQUBE_9_LINK="https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-${SONARQUBE_VERSION_9}.zip"

        downloadFile "Sonarqube" $SONARQUBE_VERSION_9 $SONARQUBE_9_LINK
    } else {
        Write-Output "Skipping Sonarqube9"
    }

    ## Sonar Scanner CLI
    if ($global:SONAR_SCANNER_CLI_VERSION -eq $null -and ![string]::IsNullOrEmpty($SONAR_SCANNER_CLI_VERSION)) {
        $SONAR_SCANNER_CLI_LINK="https://repo1.maven.org/maven2/org/sonarsource/scanner/cli/sonar-scanner-cli/${SONAR_SCANNER_CLI_VERSION}/sonar-scanner-cli-${SONAR_SCANNER_CLI_VERSION}-linux.zip"
        
        downloadFile "Sonar Scanner CLI" $SONAR_SCANNER_CLI_VERSION $SONAR_SCANNER_CLI_LINK
    } else {
        Write-Output "Skipping Sonar Scanner CLI"
    }

    ## Openscap
    if ($global:OPENSCAP_VERSION -eq $null -and ![string]::IsNullOrEmpty($OPENSCAP_VERSION)) {
        $OPENSCAP_LINK="https://github.com/ComplianceAsCode/content/releases/download/v${OPENSCAP_VERSION}/scap-security-guide-${OPENSCAP_VERSION}.zip"
        
        downloadFile "Openscap" $OPENSCAP_VERSION $OPENSCAP_LINK
    } else {
        Write-Output "Skipping Openscap"
    }

    ## Clamav 
    if ($global:CLAMAV_VERSION -eq $null -and ![string]::IsNullOrEmpty($CLAMAV_VERSION)) {
        $CLAMAV_LINK="https://www.clamav.net/downloads/production/clamav-${CLAMAV_VERSION}.tar.gz"

        downloadAndRenameFile "Clamav" $CLAMAV_VERSION $CLAMAV_LINK "clamav-${CLAMAV_VERSION}.tar.gz"
    } else {
        Write-Output "Skipping Clamav"
    }

    ## Grype
    if ($global:GRYPE_VERSION -eq $null -and ![string]::IsNullOrEmpty($GRYPE_VERSION)) {
        $GRYPE_LINK="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz"

        downloadFile "Grype" $GRYPE_VERSION $GRYPE_LINK
    } else {
        Write-Output "Skipping Grype"
    }

    ## Trivy 
    if ($global:TRIVY_VERSION -eq $null -and ![string]::IsNullOrEmpty($TRIVY_VERSION)) {
        $TRIVY_LINK="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"

        downloadFile "Trivy" $TRIVY_VERSION $TRIVY_LINK
    } else {
        Write-Output "Skipping Trivy"
    }

    ## Cosign
    if ($global:COSIGN_VERSION -eq $null -and ![string]::IsNullOrEmpty($COSIGN_VERSION)) {
        $COSIGN_LINK="https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64"

        downloadFile "Cosign" $COSIGN_VERSION $COSIGN_LINK
    } else {
        Write-Output "Skipping Cosign"
    }

    ## Hadolint
    if ($global:HADOLINT_VERSION -eq $null -and ![string]::IsNullOrEmpty($HADOLINT_VERSION)) {
        $HADOLINT_LINK="https://github.com/hadolint/hadolint/archive/refs/tags/v${HADOLINT_VERSION}.tar.gz"

        downloadFile "Hadolint" $HADOLINT_VERSION $HADOLINT_LINK
    } else {
        Write-Output "Skipping Hadolint"
    }

    ## Lombok
    if ($global:LOMBOK_VERSION -eq $null -and ![string]::IsNullOrEmpty($LOMBOK_VERSION)) {
        $LOMBOK_LINK="https://projectlombok.org/downloads/lombok-${LOMBOK_VERSION}.jar"

        downloadFile "Lombok" $LOMBOK_VERSION $LOMBOK_LINK
    } else {
        Write-Output "Skipping Lombok"
    }

}

################### HASH #######################
# Generate sha256 hash for downloaded files    #
################################################

function HASHER {param()
    
    Write-Output "Generating hash values for downloaded files"
    # Check if the file exist, else create text file if doesn't exist
    if (-not (Test-Path -Path "$DOWNLOAD_DIR\$HASH_TXTFILE" -PathType Leaf)) {
        New-Item -Path "$DOWNLOAD_DIR\$HASH_TXTFILE" -ItemType File | Out-Null
    }

    # Get the list of files in the folder
    $files = Get-ChildItem $DOWNLOAD_DIR -File
    
    # Loop through each file and generate sha256 hash
    foreach ($file in $files) {
        if ($file.Name -eq $HASH_TXTFILE) {
            continue # skip sha256 text file
        }
        $hash = hashFile $file.Name
        if ($hash -ne $null) {
            writeTextFile $file.Name $hash
        }
    }
}


# Remove contents in .\latest dir
wipeLatest
# Download
DSO_TOOLS
MGT_CLIENT_TOOLS
RUNNER_IMAGES
# Generate sha256 file
HASHER