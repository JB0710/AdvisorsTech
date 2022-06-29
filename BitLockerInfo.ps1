Function Computer{
    hostname
    }

Function User {
    whoami
    }

Function WAN {
    (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
    }

Function WiFiMAC{
    $wifi = Get-CimInstance win32_networkadapterconfiguration | Where-Object { $_.description -notlike '*Virtual*' } | Where-Object { $_.description -like '*Wi-Fi*' }  | Select macaddress
    $wifi = $wifi -replace '@{macaddress',''
    $wifi = $wifi -replace '}',''
    $wifi = $wifi -replace '=',''
    $wifi = $wifi -replace '\s',''
    Write-Output $wifi
    }

Function EthernetMAC{
    $ethernet = (Get-CimInstance win32_networkadapterconfiguration | Where-Object { $_.description -notlike '*Virtual*' } | Where-Object { $_.description -like '*Ethernet*' } ) | Select macaddress
    $ethernet = $ethernet -replace '@{macaddress',''
    $ethernet = $ethernet -replace '}',''
    $ethernet = $ethernet -replace '=',''
    $ethernet = $ethernet -replace '\s',''
    Write-Output $ethernet
    }

Function ProtectionStatus{
    $computer = hostname
    $bde = manage-bde -cn $computer -status
    $ProtectionStatus = $bde | Select-String "Protection Status:"
    $ProtectionStatus = ($ProtectionStatus -split ": ")[1]
    $ProtectionStatus = $ProtectionStatus -replace '\s',''
    Write-Output $ProtectionStatus
    }

Function LockStatus{
    $computer = hostname
    $bde = manage-bde -cn $computer -status
    $LockStatus = $bde | Select-String "Lock Status:"
    $LockStatus = ($LockStatus -split ": ")[1]
    $LockStatus = $LockStatus -replace '\s',''
    Write-Output $LockStatus
    }

Function EncryptionMethod{
    $computer = hostname
    $bde = manage-bde -cn $computer -status
    $EncryptionMethod = $bde | Select-String "Encryption Method:"
    $EncryptionMethod = ($EncryptionMethod -split ": ")[1]
    $EncryptionMethod = $EncryptionMethod -replace '\s',''
    Write-Output $EncryptionMethod
    }

Function ConversionStatus{
    $computer = hostname
    $bde = manage-bde -cn $computer -status
    $ConversionStatus = $bde | Select-String "Conversion Status:"
    $ConversionStatus = ($ConversionStatus -split ": ")[1]
    $ConversionStatus = $ConversionStatus -replace '\s',''
    Write-Output $ConversionStatus
    }  

$BitlockerInfo =
[PSCustomObject]@{
    WAN = WAN
    WiFiMAC = WiFiMAC
    EthernetMAC = EthernetMAC
    ComputerName = Computer
    UserName = User
    ProtectionStatus = ProtectionStatus
    LockStatus = LockStatus
    EncryptionMethod = EncryptionMethod
    ConverstionStatus = ConversionStatus
    }

$nfldr0 = new-object -ComObject scripting.filesystemobject
$nfldr0.CreateFolder("C:\Logs")

$BitLockerInfo | Export-Csv c:\Logs\BitLocker.csv -NoTypeInformation