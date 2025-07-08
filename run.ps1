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
    - Checkmarx
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
    CORRETTO 11         | amazon-corretto-<VERSION>-linux-x64.tar.gz
    CORRETTO 17         | amazon-corretto-<VERSION>-linux-x64.tar.gz
    CORRETTO 21         | amazon-corretto-<VERSION>-linux-x64.tar.gz
    DEPENDENCY CHECK    | dependency-check-<VERSION>-release.zip
    MAVEN               | apache-maven-<VERSION>-bin.tar.gz
    NODEJS 14           | node-v<VERSION>-linux-x64.tar.gz
    NODEJS 18           | node-v<VERSION>-linux-x64.tar.gz
    NODEJS 20           | node-v<VERSION>-linux-x64.tar.gz
    NODEJS 22           | node-v<VERSION>-linux-x64.tar.gz
    PYTHON 39           | Python-<VERSION>.tgz
    PYTHON 310          | Python-<VERSION>.tgz
    PYTHON 311          | Python-<VERSION>.tgz
    PYTHON 312          | Python-<VERSION>.tgz
    SONARQUBE           | sonarqube-<VERSION>.zip
    SONAR SCANNER CLI   | sonar-scanner-cli-<VERSION>-linux.zip
    OPENSCAP            | scap-security-guide-<VERSION>.zip
    CLAMAV              | clamav-<VERSION>.tar.gz
    GRYPE               | grype_<VERSION>_linux_amd64.tar.gz
    TRIVY               | trivy_<VERSION>_Linux-64bit.tar.gz
    COSIGN              | cosign-linux-amd64
    HADOLINT            | hadolint-v<VERSION>.tar.gz
    LOMBOK              | lombok-<VERSION>.jar
    TFLINT              | tflint-<VERSION>-linux-amd64.zip
    TERRAFORM           | terraform_<VERSION>_linux_amd64.zip
    OPENSHIFT INSTALL   | openshift-install-linux-<VERSION>.tar.gz
    OPENSHIFT CLIENT    | openshift-client-linux-<VERSION>.tar.gz
    CCOCTL              | ccoctl-linux-<VERSION>.tar.gz
    ROXCTL              | roxctl-<VERSION>
    GO                  | go<VERSION>.linux-amd64.tar.gz
    KUBERNETES CORE     | kubernetes-core-<VERSION>.tar.gz
    ROCKETCHAT          | rocketchat_<VERSION>.tar
    MONGOSH             | mongosh-<VERSION>-linux-x64.tgz
    MONGODB             | mongodb-linux-x86_64-rhel80-<VERSION>.tgz
    JIRA                | atlassian-jira-software-<VERSION>.tar.gz
    CONFLUENCE          | atlassian-confluence-software-<VERSION>.tar.gz
    BURPSUITE PRO	| burpsuite_pro_windows-x64_v<VERSION>.exe
    CHROME              |
    __________________________________________________________________________

.NOTES
	Last updated on 12 Dec 2024
#>

. .\variables.ps1

################################################
# HELPER FUNCTIONS                             #
################################################
$WGET=".\tools\wget\wget.exe"
$CRANE=".\tools\crane\crane.exe"
$DOWNLOAD_DIR=".\latest"
$DOWNLOAD_ZIP=".\latest.zip"
$COLLAB_DOWNLOAD_DIR=".\latest\collab"
$COLLAB_DOWNLOAD_ZIP=".\collab.zip"
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
    if (-Not (Test-Path -Path $DOWNLOAD_DIR)) {
        New-Item -ItemType Directory -Path $DOWNLOAD_DIR
    }
    Remove-Item $DOWNLOAD_DIR\* -Recurse -Force
    Remove-Item $DOWNLOAD_ZIP -Force
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

function zipFolder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$dir,
        [Parameter(Mandatory = $true)]
        [string]$zip
    )
    Compress-Archive -Path $dir -DestinationPath $zip
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
    ## Burpsuite PRO
    if ($global:BURP_PRO_VERSION -eq $null -and ![string]::IsNullOrEmpty($BURP_PRO_VERSION)) {
        $BURP_PRO_LINK_PREFIX="https://portswigger.net/burp/releases/startdownload?product=pro"
        $BURP_PRO_LINK="${BURP_PRO_LINK_PREFIX}&version=${BURP_PRO_VERSION}&type=windowsx64"

        downloadFile "Burpsuite Pro" $BURP_PRO_VERSION $BURP_PRO_LINK
    } else {
        Write-Output "Skipping Burpsuite"
    }

    ## Gitlab
    if ($global:GITLAB_VERSIONS -eq $null -and $GITLAB_VERSIONS -is [array] -and $GITLAB_VERSIONS.Length -gt 0) {
        foreach ($version in $GITLAB_VERSIONS) {
            $GITLAB_EE_LINK="https://packages.gitlab.com/gitlab/gitlab-ee/packages/el/8/gitlab-ee-${version}-ee.0.el8.x86_64.rpm/download.rpm"
            downloadFile "Gitlab EE" $version $GITLAB_EE_LINK
        }
    } else {
        Write-Output "Skipping Gitlab"
    }

    if ($global:GITLAB_RUNNER_VERSION -eq $null -and ![string]::IsNullOrEmpty($GITLAB_RUNNER_VERSION)) {
        $GITLAB_CHART_LINK="https://gitlab.com/gitlab-org/charts/gitlab-runner/-/archive/v${GITLAB_CHART_VERSION}/gitlab-runner-v${GITLAB_CHART_VERSION}.tar.gz"
        $GITLAB_RUNNER_ALPINE_LINK="registry.gitlab.com/gitlab-org/gitlab-runner:alpine-v$GITLAB_RUNNER_VERSION"
        $GITLAB_RUNNER_HELPER_LINK="registry.gitlab.com/gitlab-org/gitlab-runner/gitlab-runner-helper:x86_64-v$GITLAB_RUNNER_VERSION"
        $GITLAB_RUNNER_UBI_LINK="https://gitlab-runner-downloads.s3.amazonaws.com/ubi-images/v$GITLAB_RUNNER_VERSION/gitlab-runner"
        $GITLAB_RUNNER_HELPER_UBI_LINK="https://gitlab-runner-downloads.s3.amazonaws.com/ubi-images/v$GITLAB_RUNNER_VERSION/gitlab-runner-helper"
        $GITLAB_TINI_UBI_LINK="https://gitlab-runner-downloads.s3.amazonaws.com/ubi-images/v$GITLAB_RUNNER_VERSION/tini"

        downloadFile "Gitlab EE Chart" $GITLAB_CHART_VERSION $GITLAB_CHART_LINK
        downloadFile "Gitlab Runner - Ubi Image" $GITLAB_RUNNER_VERSION $GITLAB_RUNNER_UBI_LINK
        downloadFile "Gitlab Runner Helper - Ubi Image" $GITLAB_RUNNER_VERSION $GITLAB_RUNNER_HELPER_UBI_LINK
        downloadFile "Gitlab Tini - Ubi Image" $GITLAB_RUNNER_VERSION $GITLAB_TINI_UBI_LINK
        craneFile "Gitlab Runner Alpine" $GITLAB_RUNNER_VERSION $GITLAB_RUNNER_ALPINE_LINK "gitlab-runner_alpine-v$GITLAB_RUNNER_VERSION.tar"
        craneFile "Gitlab Runner Helper" $GITLAB_RUNNER_VERSION $GITLAB_RUNNER_HELPER_LINK "gitlab-runner-helper_x86_64-v$GITLAB_RUNNER_VERSION.tar"
    } else {
        Write-Output "Skipping Gitlab Runner"
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

    ## UBI9
    if ($global:UBI9_VERSION -eq $null -and ![string]::IsNullOrEmpty($UBI9_VERSION)) {
        $UBI9_LINK="registry.access.redhat.com/ubi9/ubi:${UBI9_VERSION}"

        craneFile "UBI9" $UBI9_VERSION $UBI9_LINK "ubi9_$UBI9_VERSION.tar"
    } else {
        Write-Output "Skipping Ubi9"
    }

    ## UBI9 MINIMAL
    if ($global:UBI9_MINIMAL_VERSION -eq $null -and ![string]::IsNullOrEmpty($UBI9_MINIMAL_VERSION)) {
        $UBI9_MINIMAL_LINK="registry.access.redhat.com/ubi9/ubi-minimal:${UBI9_MINIMAL_VERSION}"

        craneFile "Ubi9 Minimal" $UBI9_MINIMAL_VERSION $UBI9_MINIMAL_LINK "ubi9-minimal_$UBI9_MINIMAL_VERSION.tar"
    } else {
        Write-Output "Skipping Ubi9 Minimal"
    }

    ## UBI9 MICRO
    if ($global:UBI9_MICRO_VERSION -eq $null -and ![string]::IsNullOrEmpty($UBI9_MICRO_VERSION)) {
        $UBI9_MICRO_LINK="registry.access.redhat.com/ubi9/ubi-micro:${UBI9_MICRO_VERSION}"

        craneFile "Ubi9 Micro" $UBI9_MICRO_VERSION $UBI9_MICRO_LINK "ubi9-micro_$UBI9_MICRO_VERSION.tar"
    } else {
        Write-Output "Skipping Ubi9 Micro"
    }

    ## GITLAB SECRETS
    if ($global:GITLAB_SECRETS_VERSION -eq $null -and ![string]::IsNullOrEmpty($GITLAB_SECRETS_VERSION)) {
        $GITLAB_SECRETS_LINK="registry.gitlab.com/security-products/secrets:${GITLAB_SECRETS_VERSION}-fips"

        craneFile "GITLAB_SECRETS" $GITLAB_SECRETS_VERSION $GITLAB_SECRETS_LINK "gitlab-secrets_v$GITLAB_SECRETS_VERSION.tar"
    } else {
        Write-Output "Skipping GitLab Secrets"
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

    ## Python 3.11
    if ($global:PYTHON_311_VERSION -eq $null -and ![string]::IsNullOrEmpty($PYTHON_311_VERSION)) {
        $PYTHON_311_LINK="https://www.python.org/ftp/python/${PYTHON_311_VERSION}/Python-${PYTHON_311_VERSION}.tgz"

        downloadFile "Python 3.11" $PYTHON_311_VERSION $PYTHON_311_LINK
    } else {
        Write-Output "Skipping Python 3.11"
    }

    ## Python 3.12
    if ($global:PYTHON_312_VERSION -eq $null -and ![string]::IsNullOrEmpty($PYTHON_312_VERSION)) {
        $PYTHON_312_LINK="https://www.python.org/ftp/python/${PYTHON_312_VERSION}/Python-${PYTHON_312_VERSION}.tgz"

        downloadFile "Python 3.12" $PYTHON_312_VERSION $PYTHON_312_LINK
    } else {
        Write-Output "Skipping Python 3.12"
    }

    ## Python 3.13
    if ($global:PYTHON_313_VERSION -eq $null -and ![string]::IsNullOrEmpty($PYTHON_313_VERSION)) {
        $PYTHON_313_LINK="https://www.python.org/ftp/python/${PYTHON_313_VERSION}/Python-${PYTHON_313_VERSION}.tgz"

        downloadFile "Python 3.13" $PYTHON_313_VERSION $PYTHON_313_LINK
    } else {
        Write-Output "Skipping Python 3.13"
    }

    ## Corretto 11
    if ($global:CORRETTO_11_VERSION -eq $null -and ![string]::IsNullOrEmpty($CORRETTO_11_VERSION)) {
        $CORRETTO_11_LINK="https://corretto.aws/downloads/resources/${CORRETTO_11_VERSION}/amazon-corretto-${CORRETTO_11_VERSION}-linux-x64.tar.gz"

        downloadFile "Corretto 11" $CORRETTO_11_VERSION $CORRETTO_11_LINK
    } else {
        Write-Output "Skipping Corretto 11"
    }

    ## Corretto 17
    if ($global:CORRETTO_17_VERSION -eq $null -and ![string]::IsNullOrEmpty($CORRETTO_17_VERSION)) {
        $CORRETTO_17_LINK="https://corretto.aws/downloads/resources/${CORRETTO_17_VERSION}/amazon-corretto-${CORRETTO_17_VERSION}-linux-x64.tar.gz"

        downloadFile "Corretto 17" $CORRETTO_17_VERSION $CORRETTO_17_LINK
    } else {
        Write-Output "Skipping Corretto 17"
    }

    ## Corretto 21
    if ($global:CORRETTO_21_VERSION -eq $null -and ![string]::IsNullOrEmpty($CORRETTO_21_VERSION)) {
        $CORRETTO_21_LINK="https://corretto.aws/downloads/resources/${CORRETTO_21_VERSION}/amazon-corretto-${CORRETTO_21_VERSION}-linux-x64.tar.gz"

        downloadFile "Corretto 21" $CORRETTO_21_VERSION $CORRETTO_21_LINK
    } else {
        Write-Output "Skipping Corretto 21"
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

    ## NodeJS 22
    if ($global:NODE_22_VERSION -eq $null -and ![string]::IsNullOrEmpty($NODE_22_VERSION)) {
        $NODE_22_LINK="https://nodejs.org/dist/v${NODE_22_VERSION}/node-v${NODE_22_VERSION}-linux-x64.tar.gz"

        downloadFile "NodeJS 22" $NODE_22_VERSION $NODE_22_LINK
    } else {
        Write-Output "Skipping NodeJS 22"
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
        $SONAR_SCANNER_CLI_LINK="https://repo1.maven.org/maven2/org/sonarsource/scanner/cli/sonar-scanner-cli/${SONAR_SCANNER_CLI_VERSION}/sonar-scanner-cli-${SONAR_SCANNER_CLI_VERSION}-linux-x64.zip"

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

        downloadAndRenameFile "Cosign" $COSIGN_VERSION $COSIGN_LINK cosign-linux-amd64-${COSIGN_VERSION}
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

    ## Tflint
    if ($global:TFLINT_VERSION -eq $null -and ![string]::IsNullOrEmpty($TFLINT_VERSION)) {
        $TFLINT_LINK="https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_amd64.zip"

        downloadAndRenameFile "Tflint" $TFLINT_VERSION $TFLINT_LINK "tflint-${TFLINT_VERSION}-linux-amd64.zip"
    } else {
        Write-Output "Skipping Tflint"
    }

    ## Terraform
    if ($global:TERRAFORM_VERSION -eq $null -and ![string]::IsNullOrEmpty($TERRAFORM_VERSION)) {
        $TERRAFORM_LINK="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip"

        downloadFile "Terraform" $TERRAFORM_VERSION $TERRAFORM_LINK
    } else {
        Write-Output "Skipping Terraform"
    }

    ## Openshift Install
    if ($global:OPENSHIFT_INSTALL_VERSION -eq $null -and ![string]::IsNullOrEmpty($OPENSHIFT_INSTALL_VERSION)) {
        $OPENSHIFT_INSTALL_LINK="https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OPENSHIFT_INSTALL_VERSION}/openshift-install-linux-${OPENSHIFT_INSTALL_VERSION}.tar.gz"

        downloadFile "Openshift Installer" $OPENSHIFT_INSTALL_VERSION $OPENSHIFT_INSTALL_LINK
    } else {
        Write-Output "Skipping Openshift Installer"
    }

    ## Openshift Client
    if ($global:OPENSHIFT_CLIENT_VERSION -eq $null -and ![string]::IsNullOrEmpty($OPENSHIFT_CLIENT_VERSION)) {
        $OPENSHIFT_CLIENT_LINK="https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OPENSHIFT_CLIENT_VERSION}/openshift-client-linux-${OPENSHIFT_CLIENT_VERSION}.tar.gz"

        downloadFile "Openshift Client" $OPENSHIFT_CLIENT_VERSION $OPENSHIFT_CLIENT_LINK
    } else {
        Write-Output "Skipping Openshift Client"
    }

    ## Cloud Credential Operator
    if ($global:CCOCTL_VERSION -eq $null -and ![string]::IsNullOrEmpty($CCOCTL_VERSION)) {
        $CCOCTL_LINK="https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${CCOCTL_VERSION}/ccoctl-linux-${CCOCTL_VERSION}.tar.gz"

        downloadFile "Cloud Credential Operator (CCOCTL)" $CCOCTL_VERSION $CCOCTL_LINK
    } else {
        Write-Output "Skipping Cloud Credential Operator (CCOCTL)"
    }

    ## Roxctl
    if ($global:ROXCTL_VERSION -eq $null -and ![string]::IsNullOrEmpty($ROXCTL_VERSION)) {
        $ROXCTL_LINK="https://mirror.openshift.com/pub/rhacs/assets/${ROXCTL_VERSION}/bin/Linux/roxctl"

        # downloadFile "Roxctl" $ROXCTL_VERSION $ROXCTL_LINK
        downloadAndRenameFile "Roxctl" $ROXCTL_VERSION $ROXCTL_LINK "roxctl-${ROXCTL_VERSION}"
    } else {
        Write-Output "Skipping Roxctl"
    }

    ## Go
    if ($global:GO_VERSION -eq $null -and ![string]::IsNullOrEmpty($GO_VERSION)) {
        $GO_LINK="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"

        downloadFile "Go" $GO_VERSION $GO_LINK
    } else {
        Write-Output "Skipping Go"
    }

    ## Kubernetes Core
    if ($global:KUBERNETES_CORE_VERSION -eq $null -and ![string]::IsNullOrEmpty($KUBERNETES_CORE_VERSION)) {
        $KUBERNETES_CORE_LINK="https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/kubernetes-core-${KUBERNETES_CORE_VERSION}.tar.gz"

        downloadFile "Kubernetes Core" $KUBERNETES_CORE_VERSION $KUBERNETES_CORE_LINK
    } else {
        Write-Output "Skipping Kubernetes Core"
    }

    ## Chrome
    if ($global:CHROME_VERSION -eq $null -and ![string]::IsNullOrEmpty($CHROME_VERSION)) {
        $CHROME_LINK="https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip"
        $CHROMEDRIVER_LINK="https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chromedriver-linux64.zip"
        downloadFile "Chrome" $CHROME_VERSION $CHROME_LINK
        downloadFile "Chrome Driver" $CHROME_VERSION $CHROMEDRIVER_LINK

        # Extract Chrome and Chrome Driver
        $chromeZip = Join-Path -Path $DOWNLOAD_DIR -ChildPath "chrome-linux64.zip"
        $chromedriverZip = Join-Path -Path $DOWNLOAD_DIR -ChildPath "chromedriver-linux64.zip"

        Expand-Archive -Path $chromeZip -DestinationPath $DOWNLOAD_DIR
        Expand-Archive -Path $chromedriverZip -DestinationPath $DOWNLOAD_DIR

        # Create tar.gz archives
        $chromeTar = Join-Path -Path $DOWNLOAD_DIR -ChildPath "chrome-linux64-${CHROME_VERSION}.tar.gz"
        $chromedriverTar = Join-Path -Path $DOWNLOAD_DIR -ChildPath "chromedriver-linux64-${CHROME_VERSION}.tar.gz"

        tar -cvf $chromeTar -C $DOWNLOAD_DIR "chrome-linux64"
        tar -cvf $chromedriverTar -C $DOWNLOAD_DIR "chromedriver-linux64"

        # Clean up extracted folders and zip files
        Remove-Item -Path $chromeZip -Force
        Remove-Item -Path $chromedriverZip -Force
        Remove-Item -Path "$DOWNLOAD_DIR/chrome-linux64" -Recurse -Force
        Remove-Item -Path "$DOWNLOAD_DIR/chromedriver-linux64" -Recurse -Force

    } else {
        Write-Output "Skipping Chrome"
    }

}

function COLLAB_TOOLS {param()
    Write-Output "Downloading Collab Tools"
    if (-Not (Test-Path -Path $COLLAB_DOWNLOAD_DIR)) {
        New-Item -ItemType Directory -Path $COLLAB_DOWNLOAD_DIR
    }

    ## Rocketchat
    if ($global:ROCKETCHAT_VERSION -eq $null -and ![string]::IsNullOrEmpty($ROCKETCHAT_VERSION)) {
        $ROCKETCHAT_LINK="rocketchat/rocket.chat:${ROCKETCHAT_VERSION}"

        $VERSION=$ROCKETCHAT_VERSION -replace '\.', '_'
        craneFile "Rocketchat" $ROCKETCHAT_VERSION $ROCKETCHAT_LINK "rocketchat_$VERSION.tar"
    } else {
        Write-Output "Skipping Rocketchat"
    }

    ## Mongosh
    if ($global:MONGOSH_VERSION -eq $null -and ![string]::IsNullOrEmpty($MONGOSH_VERSION)) {
        $MONGOSH_LINK="https://downloads.mongodb.com/compass/mongosh-${MONGOSH_VERSION}-linux-x64.tgz"

        downloadFile "Mongosh" $MONGOSH_VERSION $MONGOSH_LINK
    } else {
        Write-Output "Skipping Mongosh"
    }

    ## MongoDB
    if ($global:MONGODB_VERSION -eq $null -and ![string]::IsNullOrEmpty($MONGODB_VERSION)) {
        $MONGODB_LINK="https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-rhel80-${MONGODB_VERSION}.tgz"

        downloadFile "MongoDB" $MONGODB_VERSION $MONGODB_LINK
    } else {
        Write-Output "Skipping MongoDB"
    }

    ## Jira
    if ($global:JIRA_VERSION -eq $null -and ![string]::IsNullOrEmpty($JIRA_VERSION)) {
        $JIRA_LINK="https://www.atlassian.com/software/jira/downloads/binary/atlassian-jira-software-${JIRA_VERSION}.tar.gz"

        downloadFile "Jira" $JIRA_VERSION $JIRA_LINK
    } else {
        Write-Output "Skipping Jira"
    }

    ## Confluence
    if ($global:CONFLUENCE_VERSION -eq $null -and ![string]::IsNullOrEmpty($CONFLUENCE_VERSION)) {
        $CONFLUENCE_LINK="https://www.atlassian.com/software/confluence/downloads/binary/atlassian-confluence-${CONFLUENCE_VERSION}.tar.gz"

        downloadFile "Confluence" $CONFLUENCE_VERSION $CONFLUENCE_LINK
    } else {
        Write-Output "Skipping Confluence"
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

##
## Set download path
$DOWNLOAD_DIR=".\latest"
##

# Remove contents in .\latest dir
wipeLatest
# Download
DSO_TOOLS
MGT_CLIENT_TOOLS
RUNNER_IMAGES
# Generate sha256 file
HASHER
# Zip .\latest to .\latest.zip
zipFolder -dir $DOWNLOAD_DIR -zip $DOWNLOAD_ZIP

##
## Set download path - will refactor code
$DOWNLOAD_DIR=$COLLAB_DOWNLOAD_DIR
##

# Download Collab
COLLAB_TOOLS
# Zip .\latest\collab to .\collab.zip
zipFolder -dir $COLLAB_DOWNLOAD_DIR -zip $COLLAB_DOWNLOAD_ZIP
