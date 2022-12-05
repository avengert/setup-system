$inputXAML = Get-Content "C:\users\$env:/Userprofile\Desktop\main.xaml"
$inputXAML = $inputXAML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $inputXAML
$reader = (New-Object System.Xml.XmlNodeReader $XAML)
try { $Form = [Windows.Markup.XamlReader]::Load($reader) }
catch {
  Write-Host $_.Exception
}
$XAML.SelectNodes("//*[@Name]") | ForEach-Object {Set-Variable -Name "$($_.Name_" -Value $Form.FindName($_.Name)}
$btnClose.Add_Click({
  Write-Host "Hello World"
})
$Form.ShowDialog()
$Form.Dispose()
