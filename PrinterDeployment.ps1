#Written by Jonathan Wood
#Printer Deployment

#Check to see if directory exists
$FolderName = "C:\IT_Department\Drivers\Printers\Brother"
if (Test-Path $FolderName) {
}
else
{
    New-Item $FolderName -ItemType Directory
}

#Download Drivers
$DriverFolder= 'C:\IT_Department\Drivers\Printers\Brother\MFC2750DW'
If (Test-Path $DriverFolder){
    Remove-Item $DriverFolder -Recurse   
}

#BrotherMFC2750DW
$Url = 'http://www.jenscom.com/printers/Brother/BrotherMFC2750DW.zip' 
New-Item -ItemType Directory -Force -Path $DriverFolder
$ZipFile = $DriverFolder + $(Split-Path -Path $Url -Leaf) 
$Destination = $DriverFolder
 
Invoke-WebRequest -Uri $Url -OutFile $ZipFile 
 
$ExtractShell = New-Object -ComObject Shell.Application 
$Files = $ExtractShell.Namespace($ZipFile).Items() 
$ExtractShell.NameSpace($Destination).CopyHere($Files) 

Remove-Item C:\IT_Department\Drivers\Printers\Brother\* -Include *.zip

#Load Drivers into Driver Store
invoke-command {pnputil /add-driver "C:\IT_Department\Drivers\Printers\Brother\MFC2750DW\*.inf" /install} #Universal Driver Install

#Remove Old VersaLink Printer
Remove-Printer -Name "SAVIN IM C4500 PCL 6" -ErrorAction SilentlyContinue
Remove-Printer -Name "OneNote (Desktop)" -ErrorAction SilentlyContinue
Remove-Printer -Name "BrotherMFC2750DW-Lab" -ErrorAction SilentlyContinue
Remove-Printer -Name "BrotherMFC2750DW-NurseSup" -ErrorAction SilentlyContinue

#Install Printer
$portName = "BackOfficePrinter"
$printDriverName = "Brother MFC-L2750DW series"

$portExists = Get-Printerport -Name $portname -ErrorAction SilentlyContinue
if (-not $portExists) {
  Add-PrinterPort -name $portName -PrinterHostAddress "10.1.1.245"
}
$printDriverExists = Get-PrinterDriver -name $printDriverName -ErrorAction SilentlyContinue
if ($printDriverExists) {
    Add-Printer -Name "BackOfficePrinter" -PortName $portName -DriverName $printDriverName
}else{
    Add-PrinterDriver -Name $printDriverName
    Add-Printer -Name "BackOfficePrinter" -PortName $portName -DriverName $printDriverName
}

#Sets Color Preference to Black and White Default
Set-PrintConfiguration -PrinterName "BackOfficePrinter" -Color $false