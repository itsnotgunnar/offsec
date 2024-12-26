<#
.SYNOPSIS
    Searches for sensitive information in specified files across the system.
    TAKES A LOT OF TIME BUT IS GOLD.

.DESCRIPTION
    This script scans through various file types to identify potential sensitive information such as usernames, passwords, and other credentials. It logs the findings for further analysis.

.PARAMETER customWords
    Path to the file containing custom words (e.g., usernames) to search for.

.EXAMPLE
    .\amorous.ps1 -w "C:\Path\to\customWords.txt"
#>

#### MAKE IT WHERE PEOPLE DONT NEED TO PUT WORDS FILE

#### Since we have all of our file types sorted.. we can do additional checks that would otherwise be inconvenient, like checking the imports of exes and exports off dlls -> matching them up

#### For name in get-process, get executable path, check rights to that folder and file (for every user/group that you have)

#### Build framework that indexes the computer, collects information, you take notes whenever new access or information is uncovered, it'll trigger if a new path is available. For example, it'd recognize that the DLL in that one folder is modifiable by the one group that you now have access to after triggering a shell from webroot. 

param(
    [Parameter(Mandatory = $false)]
    [Alias("w")]
    [string]$customWords  # File containing user names
)

# ===========================
# Configuration and Setup
# ===========================

# Define directories and log files
$dir = "C:\Windows\Tasks"
$listingsdir = $dir

# Create necessary directories
New-Item -ItemType Directory -Path $dir -Force | Out-Null

# Define log files
$logfile = "$dir\log.out"
$passwordfile = "$dir\PasswordSearch.out"

# Define timeout (if needed for future enhancements)
$timeout = 4

# Search configurations
$dopasswordsearch = $true  # Set to $false to disable password search

# Regex search flags
$password = $true
$username = $true
$detailed = $true

# Define file extensions to search
$fileExtensions = @("*.txt","*.pdf","*.xls","*.xlsx","*.doc","*.docx","*.log","*.kdbx","*.git","*.rdp","*.config","*.bat","*.bak","*.conf","*.vbs","*.sql","*.reg","*password*","*sensitive*","*admin*","*login*","*secret*","*.vmdk","*cups*","*print*","*secret*","*cred*","*.ini","*oscp*","*ms01*","*pass*","*ms02*","*dc01*","SYSTEM","SAM","SECURITY","ntds.dit","id_rsa","authorized_keys")

# Initialize search paths (limit to essential directories for performance)
#$Drives = Get-PSDrive | Where-Object { $_.Root -like "*:\" }
#$searchPaths = @("C:\")  # Add or modify as needed
#$searchPaths = Get-PSDrive | Where-Object { $_.Root -like "*:\" }

# Initializing more complex regex search
$regexSearch = @{}

if ($password) {
  $regexSearch.add("Simple Passwords1", "pass.*[=:].+")
  $regexSearch.add("Simple Passwords2", "pwd.*[=:].+")
  $regexSearch.add("Apr1 MD5", '\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $regexSearch.add("Apache SHA", "\{SHA\}[0-9a-zA-Z/_=]{10,}")
  $regexSearch.add("Blowfish", '\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*')
  $regexSearch.add("Drupal", '\$S\$[a-zA-Z0-9_/\.]{52}')
  $regexSearch.add("Joomlavbulletin", "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}")
  $regexSearch.add("Linux MD5", '\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $regexSearch.add("phpbb3", '\$H\$[a-zA-Z0-9_/\.]{31}')
  $regexSearch.add("sha512crypt", '\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}')
  $regexSearch.add("Wordpress", '\$P\$[a-zA-Z0-9_/\.]{31}')
  $regexSearch.add("md5", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{32}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha1", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{40}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha256", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{64}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha512", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)")
  $regexSearch.add("Base64", "(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+\/]+={0,2}")
}

# For username in usernames
if ($username) {
  $regexSearch.add("Usernames1", "username[=:].+")
  $regexSearch.add("Usernames2", "user[=:].+")
  $regexSearch.add("Usernames3", "login[=:].+")
  $regexSearch.add("Emails", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}")
  $regexSearch.add("Net user add", "net user .+ /add")
}

if ($detailed) {
  $regexSearch.add("Authorization Basic", "basic [a-zA-Z0-9_:\.=\-]+")
  $regexSearch.add("Authorization Bearer", "bearer [a-zA-Z0-9_\.=\-]+")
  $regexSearch.add("Basic Auth Credentials", "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+")
  $regexSearch.add("Private Keys", "\-\-\-\-\-BEGIN PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN OPENSSH PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN PGP PRIVATE KEY BLOCK\-\-\-\-\-|\-\-\-\-\-BEGIN DSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN EC PRIVATE KEY\-\-\-\-\-")
  $regexSearch.add("Travis CI Access Token", "([a-z0-9]{22})")
  $regexSearch.add("Jenkins Creds", "<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<")
  $regexSearch.add("Generic Secret", "[sS][eE][cC][rR][eE][tT].*['""][0-9a-zA-Z]{32,45}['""]")
  $regexSearch.add("Basic Auth", "//(.+):(.+)@")
  $regexSearch.add("PHP Passwords", "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass|pass').*[=:].+|define ?\('(\w*pass|\w*pwd|\w*user|\w*datab)")
  $regexSearch.add("Config Secrets (Passwd / Credentials)", "passwd.*|creden.*|^kind:[^a-zA-Z0-9_]?Secret|[^a-zA-Z0-9_]env:|secret:|secretName:|^kind:[^a-zA-Z0-9_]?EncryptionConfiguration|\-\-encryption\-provider\-config")
  $regexSearch.add("Generic API Key", "((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
  $regexSearch.add("Generiac API tokens search", "(access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key| amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret| api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret| application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket| aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password| bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key| bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver| cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret| client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password| cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login| connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test| datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password| digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd| docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid| dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password| env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
}

# ===========================
# Function Definitions
# ===========================

function Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logfile -Append -Encoding UTF8
}

# ===========================
# Initial Cleanup
# ===========================

# Delete old log files safely with logging
$filesToDelete = @($logfile, $passwordfile)
foreach ($file in $filesToDelete) {
    if (Test-Path $file) {
        try {
            Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
            Log "Deleted old log file: ${file}"
        }
        catch {
            Log "Failed to delete file ${file}: $_"
        }
    }
}

# ===========================
# Validate and Read Custom Words
# ===========================

# Basic patterns to search for
$pattern = @("user","pass","svc\.", "admin", "secret", "cred", "key", "ms01", "ms02", "dc01", "oscp")

# If customWords is provided, read and integrate them
if ($customWords -and (Test-Path $customWords -PathType Leaf)) {
    $words = Get-Content -Path $customWords | Where-Object { $_.Trim() -ne '' }

    if ($words.Count -gt 0) {
        foreach ($customWord in $words) {
            $fileExtensions += "*${customWord}*"
            $pattern += "${customWord}"
            $regexSearch.Add("Custom_${customWord}", "${customWord}.*[=:].+")
        }
        Log "Loaded custom words from '$customWords'."
    } else {
        Log "No valid words found in the custom words file. Proceeding without custom words."
    }
} else {
    Log "No custom words file provided. Proceeding with default patterns only."
}

Write-Host "Current Patterns: $pattern"
Write-Host "Current File Extensions: $fileExtensions"

# ===========================
# Prepare Search Patterns
# ===========================

# Add custom words to patterns and filestosearch
foreach ($customWord in $words) {
    $fileExtensions += "*${customWord}*"
    $pattern += "${customWord}"
    $regexSearch.Add("Custom_${customWord}", "${customWord}.*[=:].+")
}

Write-Host "Words: ${words}       Ext's: ${fileExtensions}       Pattern: ${pattern}     Regex Search: ${regexSearch}     Search Path:$Drive"

# ===========================
# Search for Interesting Files
# ===========================

Write-Host "Searching for interesting files..." -ForegroundColor Cyan
Log "Starting search for interesting files."

# Initialize an array to hold interesting files
$interestingFiles = @()

try {
    # Define the log file to record found interesting files
    $foundLogFile = "$dir\InterestingFiles.log"
    # Ensure the log file exists; create it if it doesn't
    if (-not (Test-Path $foundLogFile)) {
        New-Item -Path $foundLogFile -ItemType File -Force | Out-Null
        Log "Created new log file for found files: $foundLogFile"
    }
    # Start searching for files
    Get-ChildItem -Path "C:\" -Recurse -Include $fileExtensions -File -ErrorAction SilentlyContinue -Force | 
    Where-Object {
        ($_.FullName -notlike "C:\Program Files*\windows nt\tabletextservice*") -and
        ($_.FullName -notlike "C:\Windows\Microsoft.NET\Framework64\*") -and
        ($_.FullName -notlike "C:\Windows\Microsoft.NET\Framework\*") -and
        ($_.FullName -notlike "C:\Windows\SystemResources\Windows.*") -and
        ($_.FullName -notlike "C:\Windows\Microsoft.NET\assembly\*") -and
        ($_.FullName -notlike "C:\Windows\System32\DriverStore\*") -and
        ($_.FullName -notlike "C:\Windows\SystemApps\*.Windows.*") -and
        ($_.FullName -notlike "C:\Windows\SystemApps\Microsoft*") -and
        ($_.FullName -notlike "C:\Windows\assembly\Native*") -and
        ($_.FullName -notlike "C:\Users\All Users\VMware\*") -and
        ($_.FullName -notlike "C:\Program Files\VMware\*") -and
        ($_.FullName -notlike "C:\Windows\diagnostics\*") -and
        ($_.FullName -notlike "C:\ProgramData\VMware\*") -and
        ($_.FullName -notlike "C:\Windows\servicing\*") -and
        ($_.FullName -notlike "C:\Windows\WinSxS\*") -and
        ($_.FullName -notlike "C:\Windows\Policy*") -and
        ($_.FullName -notlike "C:\Windows\Tasks\*") -and
        ($_.FullName -notlike "C:\Windows\Help*") -and
        ($_.FullName -notlike "C:\Windows\INF\*") -and
    } | ForEach-Object {
            if (
            ($_.FullName | Select-String "C:\\Windows\\.*\\(\.exe\..*|\.dll|\.vbs)" -notMatch ) -and
            ($_.FullName | Select-String "C:\\.*(en-US|amd64|WindowsPowerShell|ThirdParty|Desktop\.ini)" -notMatch ) 
            ) {
                $Path = $_
                $interestingFiles += $Path.FullName
                Write-Host "Path: ${path}"
                "${Path}" | Out-File -FilePath $foundLogFile -Append -Encoding UTF8
            }
    }
} catch {
  Log "Error during file search: $_"
  Write-Warning "Error during file search: $_"
}

# Remove duplicate files (shouldnt need). Is there a way to say, remove all files with duplicate leafs (filenames)?
$interestingFiles = $interestingFiles | Select-Object -Unique
Log "Found $(${interestingFiles}.Count) interesting files."

# ===========================
# Analyze Found Files
# ===========================

Write-Host "Analyzing found files..." -ForegroundColor Cyan

foreach ($file in $interestingFiles) {
    $filePath = $file

    # Skip files with 'lang' in their path
    if ($filePath -match "(?i).*lang.*") {
        continue
    }

    # Check if the file name contains 'pass'
    if ($filePath -match "(?i).*\\.*Pass.*") {
        Write-Host "${filePath} contains the word 'pass'" -ForegroundColor Blue
        Log "Found 'pass' in: ${filePath}"
    }

    # Check if the file name contains 'user' but exclude specific directories if needed
    if ($filePath -match "(?i).*\\.*user.*") {
        Write-Host "${filePath} contains the word 'user'" -ForegroundColor Blue
        Log "Found 'user' in: ${filePath}"
    }

    # If the file is an Excel file, perform additional search (optional)
    if ($filePath -match ".*\.(xls|xlsx|xlsm)$") {
        Write-Host "Check out the Excel files manually" -ForegroundColor Yellow
        Log "Excel file detected: ${filePath}"
    }

    # Perform regex searches for custom patterns
    foreach ($key in $regexSearch.Keys) {
        try {
            $passwordFound = Get-Content -Path $filePath -ErrorAction Stop | Select-String -Pattern $regexSearch[$key] -Context 1,1
            if ($passwordFound) {
                Write-Host "Possible sensitive data found with pattern '$key' in: ${filePath}" -ForegroundColor Yellow
                Log "Pattern '$key' matched in: ${filePath}"
                Log $passwordFound.Context.PreContext
                Log $passwordFound.Context.PostContext
            }
        }
        catch {
            Log "Error reading file ${filePath}: $_"
        }
    }
}

# ===========================
# Completion Message
# ===========================

Write-Host "Scan completed. Check the log file at $logfile for details." -ForegroundColor Green
Log "Scan completed."

# ===========================
# End of Script
# ===========================
