$currentUser = ${env:Username}
#$inputXAML = Get-Content "C:\users\$currentUser\Development\wintool\main.xaml"
#$inputXAML = (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/avengert/setup-system/beta/main.xaml") #uncomment for Testing
$inputXAML = (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/avengert/setup-system/main/main.xaml") #uncomment for Production
$inputXAML = $inputXAML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $inputXAML
$reader = (New-Object System.Xml.XmlNodeReader $XAML)
try { $Form = [Windows.Markup.XamlReader]::Load($reader) }
catch {
  Write-Host $_.Exception
}
$XAML.SelectNodes("//*[@Name]") | ForEach-Object {Set-Variable -Name $($_.Name) -Value $Form.FindName($_.Name)}

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
  $i = $txtSetDomain.Text
  Write-Host "You have requested to set your domain as ${i}"
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

$lstLocalUsers = $Form.FindName("lstLocalUsers")

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

$btnAddUser = $Form.FindName("btnAddUser")
$txtNewUserName = $Form.FindName("txtNewUserName")
$txtNewUserPassword = $Form.FindName("txtNewUserPassword")

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
$btnRestartAsAdmin = $Form.FindName("btnRestartAsAdmin")

$btnRestartAsAdmin.Add_Click({
    $scriptPath = $MyInvocation.MyCommand.Path
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -File `"$scriptPath`"" -Verb RunAs
        [System.Windows.MessageBox]::Show("If you do not see a UAC prompt or a new window, check your execution policy and script path.", "Restart Attempted", "OK", "Information")
    } catch {
        [System.Windows.MessageBox]::Show("Failed to restart as administrator: $_", "Error", "OK", "Error")
    }
    $Form.Close()
})
# Improve spacing and layout for existing buttons
$btnClose.Margin = "10"
$btnSetDomain.Margin = "10"
$btnShowOptionalFeatures.Margin = "10"
$btnShowApplications.Margin = "10"
$btnEnableRDP.Margin = "10"

function Test-IsAdmin {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (Test-IsAdmin) {
    $btnRestartAsAdmin.Visibility = 'Collapsed'
}
$btnPing = $Form.FindName("btnPing")
$btnTracert = $Form.FindName("btnTracert")
$btnNSLookup = $Form.FindName("btnNSLookup")
$btnShowIPConfig = $Form.FindName("btnShowIPConfig")
$btnReleaseDHCP = $Form.FindName("btnReleaseDHCP")
$btnRenewDHCP = $Form.FindName("btnRenewDHCP")
$btnFlushDNS = $Form.FindName("btnFlushDNS")
$txtNetworkTarget = $Form.FindName("txtNetworkTarget")
$txtNetworkOutput = $Form.FindName("txtNetworkOutput")

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
$Form.ShowDialog()
