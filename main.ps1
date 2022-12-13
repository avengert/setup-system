$currentUser = ${env:Username}
#$inputXAML = Get-Content "C:\users\$currentUser\Desktop\main.xaml"
$inputXAML = (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/avengert/setup-system/beta/main.xaml") #uncomment for Testing
#$inputXAML = (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/avengert/setup-system/main/main.xaml") #uncomment for Production
$inputXAML = $inputXAML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $inputXAML
$reader = (New-Object System.Xml.XmlNodeReader $XAML)
try { $Form = [Windows.Markup.XamlReader]::Load($reader) }
catch {
  Write-Host $_.Exception
}
$XAML.SelectNodes("//*[@Name]") | ForEach-Object {Set-Variable -Name $($_.Name) -Value $Form.FindName($_.Name)}

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

$btnOpenPowershell.Add_Click({Start-Process powershell.exe})

[void]$lstPowershell.Items.Add("cmd.exe")

$btnExecutePowershell.Add_Click({
  $i = $lstPowershell.SelectedItem
  start-process ${i}
})

$Form.ShowDialog()
$Form.Dispose()
