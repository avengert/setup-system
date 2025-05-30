# Command line parameters
param(
    [string]$Source,  # Can be "local", "beta", or "production"
    [string]$LocalPath,  # Custom local path for XAML file
    [switch]$CheckVersion,  # Force version check
    [switch]$UpdateConfig,  # Update config file with new values
    [string]$BetaUrl,  # Custom beta URL
    [string]$ProductionUrl,  # Custom production URL
    [switch]$ValidateOnly  # Only validate XAML without loading
)

$currentUser = ${env:Username}

# Configuration settings
$configFile = "$env:TEMP\wintool_config.json"
$versionFile = "$env:TEMP\wintool_version.json"
$defaultConfig = @{
    "source" = "production"
    "localPath" = "C:\users\$currentUser\Development\wintool\main.xaml"
    "githubUrls" = @{
        "beta" = "https://raw.githubusercontent.com/avengert/setup-system/beta/main.xaml"
        "production" = "https://raw.githubusercontent.com/avengert/setup-system/main/main.xaml"
    }
    "lastCheck" = (Get-Date).ToString("o")
    "version" = @{
        "local" = $null
        "beta" = $null
        "production" = $null
    }
    "autoUpdate" = $true
    "validateXAML" = $true
}

# Function to validate XAML content
function Test-XAMLContent {
    param([string]$xamlContent)
    try {
        [xml]$xaml = $xamlContent
        $reader = New-Object System.Xml.XmlNodeReader $xaml
        [Windows.Markup.XamlReader]::Load($reader) | Out-Null
        return $true
    } catch {
        Write-Error "XAML validation failed: $_"
        return $false
    }
}

# Function to get file version (hash)
function Get-FileVersion {
    param([string]$content)
    return [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($content)
    ) | ForEach-Object { $_.ToString("x2") } | Join-String
}

# Function to check for updates
function Test-XAMLUpdates {
    param([hashtable]$config)
    
    $updates = @{}
    $webClient = New-Object Net.WebClient
    
    # Check beta version
    try {
        $betaContent = $webClient.DownloadString($config.githubUrls.beta)
        $betaVersion = Get-FileVersion $betaContent
        $updates.beta = @{
            "version" = $betaVersion
            "content" = $betaContent
            "isNew" = $betaVersion -ne $config.version.beta
        }
    } catch {
        Write-Warning "Failed to check beta version: $_"
    }
    
    # Check production version
    try {
        $prodContent = $webClient.DownloadString($config.githubUrls.production)
        $prodVersion = Get-FileVersion $prodContent
        $updates.production = @{
            "version" = $prodVersion
            "content" = $prodContent
            "isNew" = $prodVersion -ne $config.version.production
        }
    } catch {
        Write-Warning "Failed to check production version: $_"
    }
    
    return $updates
}

# Load or create config
if (Test-Path $configFile) {
    $config = Get-Content $configFile | ConvertFrom-Json
} else {
    $config = $defaultConfig
    $config | ConvertTo-Json -Depth 10 | Set-Content $configFile
}

# Update config with command line parameters
if ($Source) { $config.source = $Source }
if ($LocalPath) { $config.localPath = $LocalPath }
if ($BetaUrl) { $config.githubUrls.beta = $BetaUrl }
if ($ProductionUrl) { $config.githubUrls.production = $ProductionUrl }

# Check for updates if needed
$shouldCheck = $CheckVersion -or 
               $config.autoUpdate -or 
               ((Get-Date) - [DateTime]::Parse($config.lastCheck)).TotalHours -gt 24

if ($shouldCheck) {
    Write-Host "Checking for XAML updates..."
    $updates = Test-XAMLUpdates $config
    
    # Update version information
    if ($updates.beta) {
        $config.version.beta = $updates.beta.version
        if ($updates.beta.isNew) {
            Write-Host "New beta version available!"
        }
    }
    if ($updates.production) {
        $config.version.production = $updates.production.version
        if ($updates.production.isNew) {
            Write-Host "New production version available!"
        }
    }
    
    $config.lastCheck = (Get-Date).ToString("o")
}

# Load XAML based on configuration
try {
    $inputXAML = switch ($config.source) {
        "local" { 
            if (Test-Path $config.localPath) {
                $content = Get-Content $config.localPath
                $config.version.local = Get-FileVersion $content
                $content
            } else {
                Write-Warning "Local XAML file not found at $($config.localPath). Falling back to production."
                $updates.production.content
            }
        }
        "beta" { 
            if ($updates.beta) {
                $updates.beta.content
            } else {
                (new-object Net.WebClient).DownloadString($config.githubUrls.beta)
            }
        }
        "production" { 
            if ($updates.production) {
                $updates.production.content
            } else {
                (new-object Net.WebClient).DownloadString($config.githubUrls.production)
            }
        }
        default { 
            Write-Warning "Invalid source specified. Falling back to local file."
            Get-Content $config.localPath
        }
    }
    
    # Validate XAML if enabled
    if ($config.validateXAML -and -not (Test-XAMLContent $inputXAML)) {
        throw "XAML validation failed"
    }
    
    if ($ValidateOnly) {
        Write-Host "XAML validation successful"
        exit
    }
    
} catch {
    Write-Error "Failed to load XAML: $_"
    Write-Warning "Falling back to local file."
    $inputXAML = Get-Content $config.localPath
}

# Save the current configuration
$config | ConvertTo-Json -Depth 10 | Set-Content $configFile

# Continue with existing XAML processing
$inputXAML = $inputXAML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $inputXAML
$reader = (New-Object System.Xml.XmlNodeReader $XAML)
try { $Form = [Windows.Markup.XamlReader]::Load($reader) }
catch { Write-Host $_.Exception }
$XAML.SelectNodes("//*[@Name]") | ForEach-Object {Set-Variable -Name $($_.Name) -Value $Form.FindName($_.Name)}

# Update version information label
$currentVersion = switch ($config.source) {
    "local" { $config.version.local }
    "beta" { $config.version.beta }
    "production" { $config.version.production }
    default { "unknown" }
}

$versionInfo = "Version: $($config.source.ToUpper()) ($($currentVersion.Substring(0,8)))"
$lblVersionInfo.Content = $versionInfo

# Add tooltip with full version info
$tooltip = New-Object System.Windows.Controls.ToolTip
$tooltip.Content = @"
Source: $($config.source)
Version: $currentVersion
Last Check: $($config.lastCheck)
Auto Update: $($config.autoUpdate)
"@
$lblVersionInfo.ToolTip = $tooltip

Add-Type -AssemblyName System.Windows.Forms

# Group all $Form.FindName assignments
$btnClose = $Form.FindName("btnClose")
$btnSetDomain = $Form.FindName("btnSetDomain")
$btnShowOptionalFeatures = $Form.FindName("btnShowOptionalFeatures")
$btnShowApplications = $Form.FindName("btnShowApplications")
$btnControlPanel = $Form.FindName("btnControlPanel")
$btnEnableRDP = $Form.FindName("btnEnableRDP")
$btnNetworkConnections = $Form.FindName("btnNetworkConnections")
$btnUserPanel = $Form.FindName("btnUserPanel")
$btnOpenPowershell = $Form.FindName("btnOpenPowershell")
$btnExecutePowershell = $Form.FindName("btnExecutePowershell")
$btnSetComputersToMonitor = $Form.FindName("btnSetComputersToMonitor")
$btnUpgradeAll = $Form.FindName("btnUpgradeAll")
$btnSystemInfo = $Form.FindName("btnSystemInfo")
$btnDeviceManager = $Form.FindName("btnDeviceManager")
$btnEventViewer = $Form.FindName("btnEventViewer")
$btnServices = $Form.FindName("btnServices")
$btnTaskManager = $Form.FindName("btnTaskManager")
$btnWindowsUpdate = $Form.FindName("btnWindowsUpdate")
$btnSystemProperties = $Form.FindName("btnSystemProperties")
$btnRegistryEditor = $Form.FindName("btnRegistryEditor")
$btnDiskManagement = $Form.FindName("btnDiskManagement")
$btnNetworkConnections2 = $Form.FindName("btnNetworkConnections2")
$btnControlPanel2 = $Form.FindName("btnControlPanel2")
$btnCmd = $Form.FindName("btnCmd")
$btnPowerShell = $Form.FindName("btnPowerShell")
$btnEnableUser = $Form.FindName("btnEnableUser")
$btnDisableUser = $Form.FindName("btnDisableUser")
$btnRemoveUser = $Form.FindName("btnRemoveUser")
$btnResetPassword = $Form.FindName("btnResetPassword")
$btnRestartAsAdmin = $Form.FindName("btnRestartAsAdmin")
$btnPing = $Form.FindName("btnPing")
$btnTracert = $Form.FindName("btnTracert")
$btnNSLookup = $Form.FindName("btnNSLookup")
$btnShowIPConfig = $Form.FindName("btnShowIPConfig")
$btnReleaseDHCP = $Form.FindName("btnReleaseDHCP")
$btnRenewDHCP = $Form.FindName("btnRenewDHCP")
$btnFlushDNS = $Form.FindName("btnFlushDNS")
$txtNetworkTarget = $Form.FindName("txtNetworkTarget")
$txtNetworkOutput = $Form.FindName("txtNetworkOutput")
$lstLocalUsers = $Form.FindName("lstLocalUsers")
$btnAddUser = $Form.FindName("btnAddUser")
$txtNewUserName = $Form.FindName("txtNewUserName")
$txtNewUserPassword = $Form.FindName("txtNewUserPassword")
$lstPowershell = $Form.FindName("lstPowershell")
$lstInstalledApps = $Form.FindName("lstInstalledApps")
$txtAppSearch = $Form.FindName("txtAppSearch")
$btnChangeApp = $Form.FindName("btnChangeApp")
$btnUninstallApp = $Form.FindName("btnUninstallApp")
$btnInstallLatestCU = $Form.FindName("btnInstallLatestCU")
$lstScripts = $Form.FindName("lstScripts")
$btnBrowseScripts = $Form.FindName("btnBrowseScripts")
$txtScriptPreview = $Form.FindName("txtScriptPreview")
$txtScriptArgs = $Form.FindName("txtScriptArgs")
$chkRunAsAdmin = $Form.FindName("chkRunAsAdmin")
$btnExecuteScript = $Form.FindName("btnExecuteScript")
$btnClearOutput = $Form.FindName("btnClearOutput")
$txtScriptOutput = $Form.FindName("txtScriptOutput")
$btnSaveOutput = $Form.FindName("btnSaveOutput")
$chkThemeToggle = $Form.FindName("chkThemeToggle")
$lblThemeStatus = $Form.FindName("lblThemeStatus")
$btnSetPCName = $Form.FindName("btnSetPCName")
$txtPCName = $Form.FindName("txtPCName")
$txtSetDomain = $Form.FindName("txtSetDomain")
$btnSetDNS = $Form.FindName("btnSetDNS")
$txtSetDNS = $Form.FindName("txtSetDNS")
$btnSetIP = $Form.FindName("btnSetIP")
$txtSetIP = $Form.FindName("txtSetIP")
$chkSelectAllPUPs = $Form.FindName("chkSelectAllPUPs")
$lstPUPs = $Form.FindName("lstPUPs")
$btnRemovePUPs = $Form.FindName("btnRemovePUPs")
$btnRefreshPUPs = $Form.FindName("btnRefreshPUPs")

$themeConfigFile = "$env:TEMP\wintool_theme.conf"

# PUP list configuration
$pupListUrl = "https://raw.githubusercontent.com/avengert/setup-system/main/pups.json"
$localPupListPath = "$env:TEMP\wintool_pups.json"

# Function to load PUP list
function Load-PUPList {
    try {
        # Try to download from URL first
        $webClient = New-Object System.Net.WebClient
        $jsonContent = $webClient.DownloadString($pupListUrl)
        $pupList = $jsonContent | ConvertFrom-Json
        # Save to local file for offline use
        $jsonContent | Set-Content -Path $localPupListPath
    } catch {
        # If download fails, try to load from local file
        if (Test-Path $localPupListPath) {
            $jsonContent = Get-Content -Path $localPupListPath -Raw
            $pupList = $jsonContent | ConvertFrom-Json
        } else {
            # If no local file exists, create empty list
            $pupList = @{ pups = @() }
        }
    }
    return $pupList
}

Function ReadConfigFile(){
    $confFile = "$env:temp\adminConfig.conf"
    if(Test-Path -Path $confFile){
        foreach($i in $(Get-Content $confFile)){
            Set-Variable -Name $i.split("=")[0] -Value $i.split("=",2)[1]
            $lblConfigStatus.Content = "Config Loaded"
        }
    } else {
        $dns = "8.8.8.8"
        $lblConfigStatus.Content = "Config Not Loaded"
    }
}

ReadConfigFile

$btnDeviceManager.Add_Click({Start-Process devmgmt.msc})
$btnEventViewer.Add_Click({Start-Process eventvwr.msc})
$btnServices.Add_Click({Start-Process services.msc})
$btnTaskManager.Add_Click({Start-Process taskmgr})
$btnWindowsUpdate.Add_Click({Start-Process "ms-settings:windowsupdate"})
$btnSystemProperties.Add_Click({Start-Process sysdm.cpl})
$btnRegistryEditor.Add_Click({Start-Process regedit})
$btnDiskManagement.Add_Click({Start-Process diskmgmt.msc})
$btnNetworkConnections2.Add_Click({Start-Process ncpa.cpl})
$btnControlPanel2.Add_Click({Start-Process control})
$btnCmd.Add_Click({Start-Process cmd.exe})
$btnPowerShell.Add_Click({Start-Process powershell.exe})

$btnSystemInfo.Add_Click({
    $currentUser = ${env:Username}
    $sysInfoXAML = Get-Content "C:\users\$currentUser\Development\wintool\SystemInfoWindow.xaml"
    $sysInfoXAML = $sysInfoXAML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
    [xml]$sysXAML = $sysInfoXAML
    $sysReader = (New-Object System.Xml.XmlNodeReader $sysXAML)
    try { $SystemInfoForm = [Windows.Markup.XamlReader]::Load($sysReader) }
    catch { Write-Host $_.Exception }
    $txtSystemInfo = $SystemInfoForm.FindName("txtSystemInfo")
    $btnCopyInfo = $SystemInfoForm.FindName("btnCopyInfo")
    $btnCloseInfo = $SystemInfoForm.FindName("btnCloseInfo")

    # Gather system info
    $info = @()
    $info += "Computer Name: $env:COMPUTERNAME"
    $info += "User Name: $env:USERNAME"
    $info += "OS Version: $([System.Environment]::OSVersion.VersionString)"
    $info += "64-bit OS: $([System.Environment]::Is64BitOperatingSystem)"
    $info += "Processor: $((Get-WmiObject Win32_Processor).Name)"
    $info += "RAM: $([math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)) GB"
    $info += "System Drive Free Space: $([math]::Round((Get-WmiObject Win32_LogicalDisk -Filter \"DeviceID='C:'\").FreeSpace / 1GB, 2)) GB"
    $info += "IP Addresses: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' }).IPAddress -join ', ')"
    $info += "Uptime: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime | %{(Get-Date) - $_} | %{[math]::Floor($_.TotalHours)}h $($_.Minutes)m)"
    $txtSystemInfo.Text = $info -join "`r`n"

    $btnCopyInfo.Add_Click({
        Set-Clipboard -Value $txtSystemInfo.Text
    })
    $btnCloseInfo.Add_Click({
        $SystemInfoForm.Close()
    })
    $SystemInfoForm.ShowDialog() | Out-Null
})

$btnClose.Add_Click({
  $Form.Close()
})

$btnSetDomain.Add_Click({
    $domain = $txtSetDomain.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($domain)) {
        [System.Windows.MessageBox]::Show("Please enter a domain name.", "Input Required", "OK", "Warning")
        return
    }
    $cred = $null
    try {
        $cred = Get-Credential -Message "Enter credentials to join domain $domain"
        Add-Computer -DomainName $domain -Credential $cred -Force
        [System.Windows.MessageBox]::Show("Successfully joined domain. Please restart for changes to take effect.", "Success", "OK", "Information")
        Refresh-AdminInputs
    } catch {
        [System.Windows.MessageBox]::Show("Failed to join domain: $_", "Error", "OK", "Error")
    }
})

$btnShowOptionalFeatures.Add_Click({Start-Process optionalfeatures.exe})
$btnShowApplications.Add_Click({appwiz.cpl})
$btnEnableRDP.Add_Click({systempropertiesremote})

[void]$lstPowershell.Items.Add("cmd.exe")

$btnExecutePowershell.Add_Click({
  $i = $lstPowershell.SelectedItem
  start-process ${i}
})

$btnSetComputersToMonitor.Add_Click({
    # Put this section on a loop checking every 5 minutes possibly in a seperate thread so it doesn't lock up the app.
    # Then let it loop through a list comma seperated showing the status of each machine.
    if($txtComputersToMonitor.Text -eq ""){
        $lblMachine1Status.Content = "Status: "   
        $lblMachine2Status.Content = "Status: "
    } else{
        #This needs to be in a loop
        if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $txtComputersToMonitor.Text -Quiet){
           $lblMachine1Status.Foreground = "Green"
         $lblMachine1Status.Content = "Status: Up"   
        } else {
            $lblMachine1Status.Foreground = "Red"
            $lblMachine1Status.Content = "Status: Down"
        }
    }
})

# Function to check if winget is installed
Function CheckWinget {
    $wingetInstalled = Get-Command winget -ErrorAction SilentlyContinue
    return $wingetInstalled -ne $null
}

# Function to install winget
Function InstallWinget {
    Start-Process "powershell.exe" -ArgumentList "Start-Process -FilePath 'winget.exe' -ArgumentList 'install Microsoft.DesktopAppInstaller' -Wait" -NoNewWindow
}

# Button click event for upgrading all applications
$btnUpgradeAll.Add_Click({
    if (-not (CheckWinget)) {
        InstallWinget
        Start-Sleep -Seconds 10 # Adjust time as necessary
    }
    Start-Process "winget" -ArgumentList "upgrade --all"
})

Function Refresh-UserList {
    $lstLocalUsers.Items.Clear()
    try {
        $users = Get-LocalUser
    } catch {
        $users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
    }
    foreach ($user in $users) {
        $lstLocalUsers.Items.Add($user.Name)
    }
}

# Populate user list on startup
Refresh-UserList

$btnAddUser.Add_Click({
    $username = $txtNewUserName.Text
    $password = $txtNewUserPassword.Password

    if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
        [System.Windows.MessageBox]::Show("Please enter both a username and password.", "Input Required", "OK", "Warning")
        return
    }

    try {
        # Try to use New-LocalUser (PowerShell 5+)
        New-LocalUser -Name $username -Password (ConvertTo-SecureString $password -AsPlainText -Force) -FullName $username -Description "Created by Wintool" -ErrorAction Stop
        Add-LocalGroupMember -Group "Users" -Member $username
        [System.Windows.MessageBox]::Show("User added successfully.", "Success", "OK", "Information")
    } catch {
        # Fallback for older systems
        net user $username $password /add
        net localgroup Users $username /add
        [System.Windows.MessageBox]::Show("User added (legacy method).", "Success", "OK", "Information")
    }

    # Clear fields and refresh list
    $txtNewUserName.Text = ""
    $txtNewUserPassword.Password = ""
    Refresh-UserList
})

# Enable User
$btnEnableUser.Add_Click({
    $selected = $lstLocalUsers.SelectedItem
    if (-not $selected) {
        [System.Windows.MessageBox]::Show("Please select a user to enable.", "No User Selected", "OK", "Warning")
        return
    }
    try {
        Enable-LocalUser -Name $selected -ErrorAction Stop
        [System.Windows.MessageBox]::Show("User enabled.", "Success", "OK", "Information")
    } catch {
        net user $selected /active:yes
        [System.Windows.MessageBox]::Show("User enabled (legacy method).", "Success", "OK", "Information")
    }
    Refresh-UserList
})

# Disable User
$btnDisableUser.Add_Click({
    $selected = $lstLocalUsers.SelectedItem
    if (-not $selected) {
        [System.Windows.MessageBox]::Show("Please select a user to disable.", "No User Selected", "OK", "Warning")
        return
    }
    try {
        Disable-LocalUser -Name $selected -ErrorAction Stop
        [System.Windows.MessageBox]::Show("User disabled.", "Success", "OK", "Information")
    } catch {
        net user $selected /active:no
        [System.Windows.MessageBox]::Show("User disabled (legacy method).", "Success", "OK", "Information")
    }
    Refresh-UserList
})

# Remove User
$btnRemoveUser.Add_Click({
    $selected = $lstLocalUsers.SelectedItem
    if (-not $selected) {
        [System.Windows.MessageBox]::Show("Please select a user to remove.", "No User Selected", "OK", "Warning")
        return
    }
    $confirm = [System.Windows.MessageBox]::Show("Are you sure you want to remove user '$selected'?", "Confirm Remove", "YesNo", "Warning")
    if ($confirm -ne "Yes") { return }
    try {
        Remove-LocalUser -Name $selected -ErrorAction Stop
        [System.Windows.MessageBox]::Show("User removed.", "Success", "OK", "Information")
    } catch {
        net user $selected /delete
        [System.Windows.MessageBox]::Show("User removed (legacy method).", "Success", "OK", "Information")
    }
    Refresh-UserList
})

# Reset Password
$btnResetPassword.Add_Click({
    $selected = $lstLocalUsers.SelectedItem
    if (-not $selected) {
        [System.Windows.MessageBox]::Show("Please select a user to reset password.", "No User Selected", "OK", "Warning")
        return
    }
    $newPassword = [System.Windows.Forms.Interaction]::InputBox("Enter new password for user '$selected':", "Reset Password", "")
    if ([string]::IsNullOrWhiteSpace($newPassword)) {
        return
    }
    try {
        Set-LocalUser -Name $selected -Password (ConvertTo-SecureString $newPassword -AsPlainText -Force) -ErrorAction Stop
        [System.Windows.MessageBox]::Show("Password reset.", "Success", "OK", "Information")
    } catch {
        net user $selected $newPassword
        [System.Windows.MessageBox]::Show("Password reset (legacy method).", "Success", "OK", "Information")
    }
})

function Test-IsAdmin {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (Test-IsAdmin) {
    $btnRestartAsAdmin.Visibility = 'Collapsed'
}

function Show-NetworkOutput {
    param($text)
    $txtNetworkOutput.Text = $text
}

$btnPing.Add_Click({
    $target = $txtNetworkTarget.Text
    if ([string]::IsNullOrWhiteSpace($target)) {
        Show-NetworkOutput "Please enter a hostname or IP to ping."
        return
    }
    $result = ping $target
    Show-NetworkOutput ($result -join "`r`n")
})

$btnTracert.Add_Click({
    $target = $txtNetworkTarget.Text
    if ([string]::IsNullOrWhiteSpace($target)) {
        Show-NetworkOutput "Please enter a hostname or IP for tracert."
        return
    }
    $result = tracert $target
    Show-NetworkOutput ($result -join "`r`n")
})

$btnNSLookup.Add_Click({
    $target = $txtNetworkTarget.Text
    if ([string]::IsNullOrWhiteSpace($target)) {
        Show-NetworkOutput "Please enter a hostname or IP for nslookup."
        return
    }
    $result = nslookup $target
    Show-NetworkOutput ($result -join "`r`n")
})

$btnShowIPConfig.Add_Click({
    $result = ipconfig /all
    Show-NetworkOutput ($result -join "`r`n")
})

$btnReleaseDHCP.Add_Click({
    $result = ipconfig /release
    Show-NetworkOutput ($result -join "`r`n")
})

$btnRenewDHCP.Add_Click({
    $result = ipconfig /renew
    Show-NetworkOutput ($result -join "`r`n")
})

$btnFlushDNS.Add_Click({
    $result = ipconfig /flushdns
    Show-NetworkOutput ($result -join "`r`n")
})

function Refresh-AppInventory {
    $lstInstalledApps.Items.Clear()
    $global:AppInventory = @()
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $regPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.DisplayName) {
                $global:AppInventory += [PSCustomObject]@{
                    Name = $_.DisplayName
                    UninstallString = $_.UninstallString
                    QuietUninstallString = $_.QuietUninstallString
                    ModifyPath = $_.ModifyPath
                }
            }
        }
    }
    $global:AppInventory = $global:AppInventory | Sort-Object Name -Unique
    foreach ($app in $global:AppInventory) {
        $lstInstalledApps.Items.Add($app.Name)
    }
}

# Filter the list as you type
$txtAppSearch.Add_TextChanged({
    $lstInstalledApps.Items.Clear()
    $search = $txtAppSearch.Text.ToLower()
    foreach ($app in $global:AppInventory) {
        if ($app.Name.ToLower() -like "*$search*") {
            $lstInstalledApps.Items.Add($app.Name)
        }
    }
})

# Change button
$btnChangeApp.Add_Click({
    $selected = $lstInstalledApps.SelectedItem
    if (-not $selected) {
        [System.Windows.MessageBox]::Show("Please select an application to change.", "No App Selected", "OK", "Warning")
        return
    }
    $app = $global:AppInventory | Where-Object { $_.Name -eq $selected }
    if ($app.ModifyPath) {
        Start-Process cmd.exe -ArgumentList "/c", $app.ModifyPath
    } elseif ($app.UninstallString) {
        Start-Process cmd.exe -ArgumentList "/c", $app.UninstallString
    } else {
        [System.Windows.MessageBox]::Show("No change/modify command found for this application.", "Not Available", "OK", "Warning")
    }
})

# Uninstall button
$btnUninstallApp.Add_Click({
    $selected = $lstInstalledApps.SelectedItem
    if (-not $selected) {
        [System.Windows.MessageBox]::Show("Please select an application to uninstall.", "No App Selected", "OK", "Warning")
        return
    }
    $app = $global:AppInventory | Where-Object { $_.Name -eq $selected }
    $confirm = [System.Windows.MessageBox]::Show("Are you sure you want to uninstall '$($app.Name)'?", "Confirm Uninstall", "YesNo", "Warning")
    if ($confirm -ne "Yes") { return }
    if ($app.QuietUninstallString) {
        Start-Process cmd.exe -ArgumentList "/c", $app.QuietUninstallString
    } elseif ($app.UninstallString) {
        Start-Process cmd.exe -ArgumentList "/c", $app.UninstallString
    } else {
        [System.Windows.MessageBox]::Show("No uninstall command found for this application.", "Not Available", "OK", "Warning")
    }
})

# Populate on startup
Refresh-AppInventory

$btnInstallLatestCU.Add_Click({
    $currentUser = ${env:Username}
    $wuXAML = Get-Content "C:\users\$currentUser\Development\wintool\WindowsUpdateWindow.xaml"
    $wuXAML = $wuXAML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
    [xml]$wuXML = $wuXAML
    $wuReader = (New-Object System.Xml.XmlNodeReader $wuXML)
    try { $WUForm = [Windows.Markup.XamlReader]::Load($wuReader) }
    catch { Write-Host $_.Exception }
    $txtWUStatus = $WUForm.FindName("txtWUStatus")
    $pbWUProgress = $WUForm.FindName("pbWUProgress")
    $btnOpenTempFolder = $WUForm.FindName("btnOpenTempFolder")
    $btnCloseWU = $WUForm.FindName("btnCloseWU")

    $tempFolder = "$env:TEMP\\WintoolUpdates"
    if (-not (Test-Path $tempFolder)) { New-Item -ItemType Directory -Path $tempFolder | Out-Null }

    function Update-Status($msg) {
        $txtWUStatus.Dispatcher.Invoke([action]{ $txtWUStatus.AppendText("$msg`r`n"); $txtWUStatus.ScrollToEnd() })
    }
    function Set-Progress($val) {
        $pbWUProgress.Dispatcher.Invoke([action]{ $pbWUProgress.Value = $val })
    }

    $btnOpenTempFolder.Add_Click({ Start-Process explorer.exe $tempFolder })
    $btnCloseWU.Add_Click({ $WUForm.Close() })

    # Async job to avoid freezing UI
    Start-Job -ScriptBlock {
        param($tempFolder)
        function Get-WindowsVersion {
            $os = Get-CimInstance Win32_OperatingSystem
            return $os.Version
        }
        function Get-LatestCU {
            $version = Get-WindowsVersion
            $year = (Get-Date).Year
            $month = (Get-Date).Month.ToString("00")
            $search = "cumulative update $year-$month windows $version"
            $url = "https://www.catalog.update.microsoft.com/Search.aspx?q=$($search -replace ' ', '+')"
            $html = Invoke-WebRequest -Uri $url -UseBasicParsing
            $matches = [regex]::Matches($html.Content, 'downloadInformation\"\s*,\s*\[\s*\{\s*\"size\":.*?\"url\":\"(http.*?\.msu)\"')
            if ($matches.Count -gt 0) {
                return $matches[0].Groups[1].Value
            } else {
                return $null
            }
        }
        $msuUrl = Get-LatestCU
        if (-not $msuUrl) {
            return @{Status='No update found for this month.'}
        }
        $fileName = $msuUrl.Split('/')[-1]
        $filePath = Join-Path $tempFolder $fileName
        if (Test-Path $filePath) {
            $status = 'Update already downloaded. Installing...'
        } else {
            $status = 'Downloading update...'
            Invoke-WebRequest -Uri $msuUrl -OutFile $filePath
        }
        $status += "`r`nInstalling update..."
        $install = Start-Process wusa.exe -ArgumentList "/quiet /norestart `"$filePath`"" -Wait -PassThru
        return @{Status=$status; FilePath=$filePath; ExitCode=$install.ExitCode}
    } -ArgumentList $tempFolder | Out-Null

    # Poll for job completion
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds(2)
    $timer.Tag = $true
    $timer.Add_Tick({
        $jobs = Get-Job | Where-Object { $_.State -eq 'Completed' }
        if ($jobs) {
            $timer.Stop()
            foreach ($job in $jobs) {
                $result = Receive-Job $job
                Remove-Job $job
                if ($result.Status) { Update-Status $result.Status }
                if ($result.FilePath) { Update-Status "File: $($result.FilePath)" }
                if ($result.ExitCode -eq 0) {
                    Update-Status "Update installed successfully."
                } elseif ($result.ExitCode) {
                    Update-Status "Installer exited with code $($result.ExitCode)."
                }
            }
        } else {
            Set-Progress ($pbWUProgress.Value + 10)
        }
    })
    $timer.Start()
    $WUForm.ShowDialog() | Out-Null
})

function Refresh-ScriptList {
    $lstScripts.Items.Clear()
    foreach ($file in $global:ScriptFiles) {
        $lstScripts.Items.Add([System.IO.Path]::GetFileName($file))
    }
}

# Drag-and-drop support
$lstScripts.Add_Drop({
    $files = $_.Data.GetData("FileDrop")
    foreach ($file in $files) {
        if ($file -match '\.(ps1|bat)$' -and -not ($global:ScriptFiles -contains $file)) {
            $global:ScriptFiles += $file
        }
    }
    Refresh-ScriptList
})

# Browse button
$btnBrowseScripts.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "Script Files (*.ps1;*.bat)|*.ps1;*.bat|All Files (*.*)|*.*"
    $ofd.Multiselect = $true
    if ($ofd.ShowDialog() -eq 'OK') {
        foreach ($file in $ofd.FileNames) {
            if (-not ($global:ScriptFiles -contains $file)) {
                $global:ScriptFiles += $file
            }
        }
        Refresh-ScriptList
    }
})

# Show script preview on selection
$lstScripts.Add_SelectionChanged({
    $idx = $lstScripts.SelectedIndex
    if ($idx -ge 0 -and $idx -lt $global:ScriptFiles.Count) {
        $file = $global:ScriptFiles[$idx]
        $txtScriptPreview.Text = Get-Content $file -Raw
    } else {
        $txtScriptPreview.Text = ""
    }
})

# Execute script
$btnExecuteScript.Add_Click({
    $idx = $lstScripts.SelectedIndex
    if ($idx -lt 0 -or $idx -ge $global:ScriptFiles.Count) {
        [System.Windows.MessageBox]::Show("Please select a script to execute.", "No Script Selected", "OK", "Warning")
        return
    }
    $file = $global:ScriptFiles[$idx]
    $args = $txtScriptArgs.Text
    $asAdmin = $chkRunAsAdmin.IsChecked
    $txtScriptOutput.Text = "Running $file...`r`n"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    if ($file -like "*.ps1") {
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$file`" $args"
    } elseif ($file -like "*.bat") {
        $psi.FileName = $file
        $psi.Arguments = $args
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    if ($asAdmin) { $psi.Verb = "runas" }
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $null = $proc.Start()
    $output = ""
    while (-not $proc.HasExited) {
        $output += $proc.StandardOutput.ReadToEnd()
        $output += $proc.StandardError.ReadToEnd()
        $txtScriptOutput.Dispatcher.Invoke([action]{ $txtScriptOutput.Text = $output })
        Start-Sleep -Milliseconds 200
    }
    $output += $proc.StandardOutput.ReadToEnd()
    $output += $proc.StandardError.ReadToEnd()
    $txtScriptOutput.Dispatcher.Invoke([action]{ $txtScriptOutput.Text = $output })
})

# Clear output
$btnClearOutput.Add_Click({ $txtScriptOutput.Text = "" })

# Save output
$btnSaveOutput.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    if ($sfd.ShowDialog() -eq 'OK') {
        Set-Content -Path $sfd.FileName -Value $txtScriptOutput.Text
    }
})

function Set-ControlTheme {
    param($control, $theme)
    if ($null -eq $control) { return }
    $darkBG = [Windows.Media.Brushes]::Black
    $darkFG = [Windows.Media.Brushes]::White
    $lightBG = [Windows.Media.Brushes]::White
    $lightFG = [Windows.Media.Brushes]::Black
    if ($theme -eq 'dark') {
        if ($control -is [Windows.Controls.Panel]) {
            $control.Background = $darkBG
            foreach ($child in $control.Children) { Set-ControlTheme $child $theme }
        } elseif ($control -is [Windows.Controls.TabControl]) {
            foreach ($tab in $control.Items) { Set-ControlTheme $tab.Content $theme }
        } elseif ($control -is [Windows.Controls.ContentControl]) {
            if ($control -is [Windows.Controls.Label] -or $control -is [Windows.Controls.TextBlock]) {
                $control.Foreground = $darkFG
            } elseif ($control -is [Windows.Controls.TextBox] -or $control -is [Windows.Controls.PasswordBox]) {
                $control.Background = $darkBG
                $control.Foreground = $darkFG
            } elseif ($control -is [Windows.Controls.Button] -or $control -is [Windows.Controls.CheckBox]) {
                $control.Background = $darkBG
                $control.Foreground = $darkFG
            }
            if ($control -is [Windows.Controls.Label] -and $control.Name -eq "lblVersionInfo") {
                $control.Foreground = $darkFG
            }
            if ($control.Content -is [Windows.UIElement]) {
                Set-ControlTheme $control.Content $theme
            }
        }
    } else {
        if ($control -is [Windows.Controls.Panel]) {
            $control.Background = $lightBG
            foreach ($child in $control.Children) { Set-ControlTheme $child $theme }
        } elseif ($control -is [Windows.Controls.TabControl]) {
            foreach ($tab in $control.Items) { Set-ControlTheme $tab.Content $theme }
        } elseif ($control -is [Windows.Controls.ContentControl]) {
            if ($control -is [Windows.Controls.Label] -or $control -is [Windows.Controls.TextBlock]) {
                $control.Foreground = $lightFG
            } elseif ($control -is [Windows.Controls.TextBox] -or $control -is [Windows.Controls.PasswordBox]) {
                $control.Background = $lightBG
                $control.Foreground = $lightFG
            } elseif ($control -is [Windows.Controls.Button] -or $control -is [Windows.Controls.CheckBox]) {
                $control.Background = $lightBG
                $control.Foreground = $lightFG
            }
            if ($control -is [Windows.Controls.Label] -and $control.Name -eq "lblVersionInfo") {
                $control.Foreground = $lightFG
            }
            if ($control.Content -is [Windows.UIElement]) {
                Set-ControlTheme $control.Content $theme
            }
        }
    }
}

function Set-AppTheme {
    param([string]$theme)
    Set-ControlTheme $Form $theme
    if ($theme -eq 'dark') {
        $lblThemeStatus.Content = 'Dark Theme'
    } else {
        $lblThemeStatus.Content = 'Light Theme'
    }
}

function Set-WindowsTheme {
    param([string]$theme)
    $appsTheme = if ($theme -eq 'dark') { 0 } else { 1 }
    $systemTheme = if ($theme -eq 'dark') { 0 } else { 1 }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value $appsTheme -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value $systemTheme -Force
}

function Save-ThemeConfig {
    param([string]$theme)
    Set-Content -Path $themeConfigFile -Value $theme
}

function Load-ThemeConfig {
    if (Test-Path $themeConfigFile) {
        return (Get-Content $themeConfigFile -Raw).Trim()
    } else {
        Set-Content -Path $themeConfigFile -Value 'light'
        return 'light'
    }
}

# On startup, load theme config and set toggle
$theme = Load-ThemeConfig
if ($theme -eq 'dark') {
    $chkThemeToggle.IsChecked = $true
} else {
    $chkThemeToggle.IsChecked = $false
}
Set-AppTheme $theme

# Add event handler for theme toggle
$chkThemeToggle.Add_Checked({
    Set-AppTheme 'dark'
    Set-WindowsTheme 'dark'
    Save-ThemeConfig 'dark'
})
$chkThemeToggle.Add_Unchecked({
    Set-AppTheme 'light'
    Set-WindowsTheme 'light'
    Save-ThemeConfig 'light'
})

# Set PC Name
$btnSetPCName.Add_Click({
    $newName = $txtPCName.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($newName)) {
        [System.Windows.MessageBox]::Show("Please enter a new computer name.", "Input Required", "OK", "Warning")
        return
    }
    try {
        Rename-Computer -NewName $newName -Force
        [System.Windows.MessageBox]::Show("Computer name changed. Please restart for changes to take effect.", "Success", "OK", "Information")
        Refresh-AdminInputs
    } catch {
        [System.Windows.MessageBox]::Show("Failed to change computer name: $_", "Error", "OK", "Error")
    }
})

# Set DNS
$btnSetDNS.Add_Click({
    $dns = $txtSetDNS.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($dns)) {
        [System.Windows.MessageBox]::Show("Please enter a DNS server address.", "Input Required", "OK", "Warning")
        return
    }
    try {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        if ($null -eq $adapter) { throw "No active Ethernet adapter found." }
        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $dns
        [System.Windows.MessageBox]::Show("DNS server set to $dns on $($adapter.Name).", "Success", "OK", "Information")
        Refresh-AdminInputs
    } catch {
        [System.Windows.MessageBox]::Show("Failed to set DNS: $_", "Error", "OK", "Error")
    }
})

# Set IP Address
$btnSetIP.Add_Click({
    $ip = $txtSetIP.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($ip)) {
        [System.Windows.MessageBox]::Show("Please enter an IP address.", "Input Required", "OK", "Warning")
        return
    }
    try {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        if ($null -eq $adapter) { throw "No active Ethernet adapter found." }
        $existing = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne $null }
        if ($existing) {
            Set-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip -PrefixLength 24 -DefaultGateway $existing.DefaultGateway -ErrorAction Stop
        } else {
            New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip -PrefixLength 24 -ErrorAction Stop
        }
        [System.Windows.MessageBox]::Show("IP address set to $ip on $($adapter.Name).", "Success", "OK", "Information")
        Refresh-AdminInputs
    } catch {
        [System.Windows.MessageBox]::Show("Failed to set IP address: $_", "Error", "OK", "Error")
    }
})

# Initialize PUP list
$global:PUPItems = @()
$pupList = Load-PUPList
foreach ($pup in $pupList.pups) {
    $global:PUPItems += [PSCustomObject]@{
        Name = $pup.name
        UninstallString = $pup.uninstallString
        IsSelected = $false
    }
}
$lstPUPs.ItemsSource = $global:PUPItems

# Refresh PUP list handler
$btnRefreshPUPs.Add_Click({
    $pupList = Load-PUPList
    $global:PUPItems.Clear()
    foreach ($pup in $pupList.pups) {
        $global:PUPItems += [PSCustomObject]@{
            Name = $pup.name
            UninstallString = $pup.uninstallString
            IsSelected = $false
        }
    }
    $lstPUPs.Items.Refresh()
    [System.Windows.MessageBox]::Show("PUP list has been updated.", "Success", "OK", "Information")
})

# Select All checkbox handler
$chkSelectAllPUPs.Add_Checked({
    foreach ($item in $global:PUPItems) {
        $item.IsSelected = $true
    }
    $lstPUPs.Items.Refresh()
})

$chkSelectAllPUPs.Add_Unchecked({
    foreach ($item in $global:PUPItems) {
        $item.IsSelected = $false
    }
    $lstPUPs.Items.Refresh()
})

# Remove selected PUPs
$btnRemovePUPs.Add_Click({
    $selectedPUPs = $global:PUPItems | Where-Object { $_.IsSelected }
    if ($selectedPUPs.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one program to remove.", "No Selection", "OK", "Warning")
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "Are you sure you want to remove the selected programs?`nThis action cannot be undone.",
        "Confirm Removal",
        "YesNo",
        "Warning"
    )
    
    if ($confirm -eq "Yes") {
        foreach ($pup in $selectedPUPs) {
            try {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $($pup.UninstallString)" -Wait -NoNewWindow
                [System.Windows.MessageBox]::Show("Successfully removed $($pup.Name)", "Success", "OK", "Information")
            } catch {
                [System.Windows.MessageBox]::Show("Failed to remove $($pup.Name): $_", "Error", "OK", "Error")
            }
        }
    }
})

function Refresh-AdminInputs {
    try {
        $txtPCName.Text = $env:COMPUTERNAME
    } catch { $txtPCName.Text = '' }
    try {
        $os = Get-WmiObject Win32_ComputerSystem
        if ($os.PartOfDomain) {
            $txtSetDomain.Text = $os.Domain
        } else {
            $txtSetDomain.Text = $os.Workgroup
        }
    } catch { $txtSetDomain.Text = '' }
    try {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        if ($adapter) {
            $dns = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4).ServerAddresses -join ', '
            $txtSetDNS.Text = $dns
            $ip = (Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne $null }).IPAddress | Select-Object -First 1
            $txtSetIP.Text = $ip
        } else {
            $txtSetDNS.Text = ''
            $txtSetIP.Text = ''
        }
    } catch {
        $txtSetDNS.Text = ''
        $txtSetIP.Text = ''
    }
}

# Call on startup
Refresh-AdminInputs

# After each change, refresh the inputs
$btnSetPCName.Add_Click({
    $newName = $txtPCName.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($newName)) {
        [System.Windows.MessageBox]::Show("Please enter a new computer name.", "Input Required", "OK", "Warning")
        return
    }
    try {
        Rename-Computer -NewName $newName -Force
        [System.Windows.MessageBox]::Show("Computer name changed. Please restart for changes to take effect.", "Success", "OK", "Information")
        Refresh-AdminInputs
    } catch {
        [System.Windows.MessageBox]::Show("Failed to change computer name: $_", "Error", "OK", "Error")
    }
})

$btnSetDomain.Add_Click({
    $domain = $txtSetDomain.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($domain)) {
        [System.Windows.MessageBox]::Show("Please enter a domain name.", "Input Required", "OK", "Warning")
        return
    }
    $cred = $null
    try {
        $cred = Get-Credential -Message "Enter credentials to join domain $domain"
        Add-Computer -DomainName $domain -Credential $cred -Force
        [System.Windows.MessageBox]::Show("Successfully joined domain. Please restart for changes to take effect.", "Success", "OK", "Information")
        Refresh-AdminInputs
    } catch {
        [System.Windows.MessageBox]::Show("Failed to join domain: $_", "Error", "OK", "Error")
    }
})

$btnSetDNS.Add_Click({
    $dns = $txtSetDNS.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($dns)) {
        [System.Windows.MessageBox]::Show("Please enter a DNS server address.", "Input Required", "OK", "Warning")
        return
    }
    try {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        if ($null -eq $adapter) { throw "No active Ethernet adapter found." }
        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $dns
        [System.Windows.MessageBox]::Show("DNS server set to $dns on $($adapter.Name).", "Success", "OK", "Information")
        Refresh-AdminInputs
    } catch {
        [System.Windows.MessageBox]::Show("Failed to set DNS: $_", "Error", "OK", "Error")
    }
})

$btnSetIP.Add_Click({
    $ip = $txtSetIP.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($ip)) {
        [System.Windows.MessageBox]::Show("Please enter an IP address.", "Input Required", "OK", "Warning")
        return
    }
    try {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -First 1
        if ($null -eq $adapter) { throw "No active Ethernet adapter found." }
        $existing = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne $null }
        if ($existing) {
            Set-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip -PrefixLength 24 -DefaultGateway $existing.DefaultGateway -ErrorAction Stop
        } else {
            New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip -PrefixLength 24 -ErrorAction Stop
        }
        [System.Windows.MessageBox]::Show("IP address set to $ip on $($adapter.Name).", "Success", "OK", "Information")
        Refresh-AdminInputs
    } catch {
        [System.Windows.MessageBox]::Show("Failed to set IP address: $_", "Error", "OK", "Error")
    }
})

# Settings configuration
$settingsConfigFile = "$env:TEMP\wintool_settings.json"

# Function to save settings
function Save-Settings {
    $settings = @{
        General = @{
            AutoUpdate = $chkAutoUpdate.IsChecked
            SaveWindowSize = $chkSaveWindowSize.IsChecked
            StartMinimized = $chkStartMinimized.IsChecked
            DefaultDNS = $txtDefaultDNS.Text
            DefaultUsername = $txtDefaultUsername.Text
            DefaultPassword = $txtDefaultPassword.Password
        }
        Network = @{
            DefaultGateway = $txtDefaultGateway.Text
            SubnetMask = $txtSubnetMask.Text
            PreferredDNS = $txtPreferredDNS.Text
            AlternateDNS = $txtAlternateDNS.Text
        }
        Remote = @{
            RemotePort = $txtRemotePort.Text
            EnableRDP = $chkEnableRDP.IsChecked
            AllowRemoteAssistance = $chkAllowRemoteAssistance.IsChecked
            TrustedComputers = @($lstTrustedComputers.Items | ForEach-Object { $_.ToString() })
        }
        Backup = @{
            BackupLocation = $txtBackupLocation.Text
            AutoBackup = $chkAutoBackup.IsChecked
            BackupSchedule = $cmbBackupSchedule.SelectedItem.Content
        }
        Security = @{
            EnableFirewall = $chkEnableFirewall.IsChecked
            EnableDefender = $chkEnableDefender.IsChecked
            AutoScan = $chkAutoScan.IsChecked
            ScanSchedule = $cmbScanSchedule.SelectedItem.Content
        }
    }
    $settings | ConvertTo-Json -Depth 10 | Set-Content -Path $settingsConfigFile
}

# Function to load settings
function Load-Settings {
    if (Test-Path $settingsConfigFile) {
        $settings = Get-Content $settingsConfigFile | ConvertFrom-Json
        # General Settings
        $chkAutoUpdate.IsChecked = $settings.General.AutoUpdate
        $chkSaveWindowSize.IsChecked = $settings.General.SaveWindowSize
        $chkStartMinimized.IsChecked = $settings.General.StartMinimized
        $txtDefaultDNS.Text = $settings.General.DefaultDNS
        $txtDefaultUsername.Text = $settings.General.DefaultUsername
        $txtDefaultPassword.Password = $settings.General.DefaultPassword
        # Network Settings
        $txtDefaultGateway.Text = $settings.Network.DefaultGateway
        $txtSubnetMask.Text = $settings.Network.SubnetMask
        $txtPreferredDNS.Text = $settings.Network.PreferredDNS
        $txtAlternateDNS.Text = $settings.Network.AlternateDNS
        # Remote Settings
        $txtRemotePort.Text = $settings.Remote.RemotePort
        $chkEnableRDP.IsChecked = $settings.Remote.EnableRDP
        $chkAllowRemoteAssistance.IsChecked = $settings.Remote.AllowRemoteAssistance
        $lstTrustedComputers.Items.Clear()
        foreach ($computer in $settings.Remote.TrustedComputers) {
            $lstTrustedComputers.Items.Add($computer)
        }
        # Backup Settings
        $txtBackupLocation.Text = $settings.Backup.BackupLocation
        $chkAutoBackup.IsChecked = $settings.Backup.AutoBackup
        $cmbBackupSchedule.SelectedItem = $cmbBackupSchedule.Items | Where-Object { $_.Content -eq $settings.Backup.BackupSchedule }
        # Security Settings
        $chkEnableFirewall.IsChecked = $settings.Security.EnableFirewall
        $chkEnableDefender.IsChecked = $settings.Security.EnableDefender
        $chkAutoScan.IsChecked = $settings.Security.AutoScan
        $cmbScanSchedule.SelectedItem = $cmbScanSchedule.Items | Where-Object { $_.Content -eq $settings.Security.ScanSchedule }
    }
}

# Settings navigation
$lstSettingsCategories.Add_SelectionChanged({
    $selected = $lstSettingsCategories.SelectedItem.Content
    $generalSettings.Visibility = if ($selected -eq "General Settings") { "Visible" } else { "Collapsed" }
    $networkSettings.Visibility = if ($selected -eq "Network Settings") { "Visible" } else { "Collapsed" }
    $remoteSettings.Visibility = if ($selected -eq "Remote Access") { "Visible" } else { "Collapsed" }
    $backupSettings.Visibility = if ($selected -eq "Backup Settings") { "Visible" } else { "Collapsed" }
    $securitySettings.Visibility = if ($selected -eq "Security Settings") { "Visible" } else { "Collapsed" }
})

# Add trusted computer
$btnAddTrustedComputer.Add_Click({
    $computer = $txtNewTrustedComputer.Text.Trim()
    if (-not [string]::IsNullOrWhiteSpace($computer)) {
        $lstTrustedComputers.Items.Add($computer)
        $txtNewTrustedComputer.Text = ""
    }
})

# Browse backup location
$btnBrowseBackup.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select Backup Location"
    if ($folderBrowser.ShowDialog() -eq 'OK') {
        $txtBackupLocation.Text = $folderBrowser.SelectedPath
    }
})

# Save settings
$btnSaveSettings.Add_Click({
    Save-Settings
    [System.Windows.MessageBox]::Show("Settings saved successfully.", "Success", "OK", "Information")
})

# Load settings on startup
Load-Settings

$Form.ShowDialog()
