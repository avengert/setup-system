$currentUser = ${env:Username}
$inputXAML = Get-Content "C:\users\$currentUser\setup-system\main.xaml"
#$inputXAML = (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/avengert/setup-system/beta/main.xaml") #uncomment for Testing
#$inputXAML = (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/avengert/setup-system/main/main.xaml") #uncomment for Production
$confFile = "$env:temp\adminConfig.conf"
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
  if(Test-Path -Path $confFile){
      foreach($i in $(Get-Content $confFile)){
        if($i -eq ""){
          # This fixes the name null error
        } else {
        Set-Variable -Name $i.split("=")[0] -Value $i.split("=",2)[1] -Scope Global
        $lblConfigStatus.Content = "Config Loaded"
        #$dns
        $txtSetDNS.Text = $dns
        }
      }
  } else {
      $dns = "8.8.8.8"
      $lblConfigStatus.Content = "Config Not Loaded"
      echo "dns=1.1.1.1" | Out-File $confFile
  }
}

ReadConfigFile

$btnClose.Add_Click({
  $Form.Close()
})

$btnSetDomain.Add_Click({
  $i = $txtSetDomain.Text
  Write-Host "You have requested to set your domain as ${i}"
})

$btnShowOptionalFeatures.Add_Click({optionalfeatures})
$btnShowApplications.Add_Click({appwiz.cpl})
$btnControlPanel.Add_Click({control})
$btnEnableRDP.Add_Click({systempropertiesremote})
$btnNetworkConnections.Add_Click({ncpa.cpl})
$btnUserPanel.Add_Click({control userpasswords2})

#$btnOpenPowershell.Add_Click({Start-Process powershell.exe})

[void]$lstPowershell.Items.Add("cmd.exe")
[void]$lstPowershell.Items.Add("chrome.exe")
[void]$lstPowershell.Items.Add("powershell.exe")

$btnExecutePowershell.Add_Click({
  $i = $lstPowershell.SelectedItem
  start-process ${i}
})

$btnSetComputersToMonitor.Add_Click({
    # Put this section on a loop checking every 5 minutes possibly in a seperate thread so it doesn't lock up the app.
    # Then let it loop through a list comma seperated showing the status of each machine.
    # My understanding is that there is an issue with websites and specific machines. Ping doesn't always work when a website status code might for a website.
    if($txtComputersToMonitor.Text -eq ""){
        $lblMachine1Status.Content = "Status: "   
        $lblMachine2Status.Content = "Status: "
    } else{
        #This needs to be in a loop
        if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $txtComputersToMonitor.Text -Quiet){
            $lblMachine1Status.Foreground = "Green"
            $lblMachine1Status.Content = "$($txtComputersToMonitor.Text): Up"   
        } else {
            $lblMachine1Status.Foreground = "Red"
            $lblMachine1Status.Content = "Status: Down"
        }
    }
})

$btnSetDNS.Add_Click({
  # Here we want to edit the text file, but not the other items. Just update the specific record. How do I do that? Well obviously this works. 😊
  $filecontent = Get-Content -Path $confFile -Raw
  Write-Host $filecontent
  $filecontent -replace 'dns=$($dns)', 'dns=$($txtSetDNS.Text)' | Out-File $confFile
  Set-DnsClientServerAddress -InterfaceIndex 9 -ServerAddresses ("$($txtSetDNS.Text)")
  $lblCurrentdns.Content = "Current DNS: $($txtSetDNS.Text)"
  ReadConfigFile
})

$txtPCName.Text = hostname

$btnSetPCName.Add_Click({
  Rename-Computer -NewName $txtPCName.Text
})

$z = Get-netIPAddress | where -Property AddressFamily -eq IPV4 | select -Property IPAddress
$lblCurrentip.Content = "Current IP: $(z)"

if(Test-Connection -Ping google.com -BufferSize 32 -Count 1 -Quiet){
  Write-Host "Internet Access Available"
  try {
    $lblExternalIP.Content = "External IP: $(curl ifcfg.me)"
  }
  catch {
    <#Do this if a terminating exception happens#>
    $lblExternalIP.Content = "Error Getting Connection"
  }
} else {
  $lblExternalIP.Content = "External IP: Unavailable"
}

$Form.ShowDialog()