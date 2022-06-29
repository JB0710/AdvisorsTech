#Version 1.0 - Authour Jonathan Wood
# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
     $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
     Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
     Exit
    }
   }
# default setting is Restricted
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Confirm:$false

#Main Script
$script:LogFile = "C:\Logs\PrinterRemoval.log"
$script:Version = "1.0.0"
function Get-ScriptName()
{
    $tmp = $MyInvocation.ScriptName.Substring($MyInvocation.ScriptName.LastIndexOf('\') + 1)
    $tmp.Substring(0, $tmp.Length - 4)
}function Write-Log($Msg, [System.Boolean]$display = $true, $foregroundColor = '')
{
    $date = Get-Date -format MM/dd/yyyy
    $time = Get-Date -format HH:mm:ss
    Add-Content -Path $LogFile -Value ($date + " " + $time + "   " + $Msg)
    if ($display)
    {
        if ($foregroundColor -eq '')
        { Write-Host "$date $time   $Msg" }
        else
        { Write-Host "$date $time   $Msg" -ForegroundColor $foregroundColor }
    }
}function Initialize-LogFile([System.Boolean]$reset = $false)
{
    try
    {
        #Check if file exists
        if (Test-Path -Path $LogFile)
        {
            #Check if file should be reset
            if ($reset)
            {
                Clear-Content $LogFile -ErrorAction SilentlyContinue
            }
        }
        else
        {
            #Check if file is a local file
            if ($LogFile.Substring(1, 1) -eq ':')
            {
                #Check if drive exists
                $driveInfo = [System.IO.DriveInfo]($LogFile)
                if ($driveInfo.IsReady -eq $false)
                {
                    Write-Log -Msg ($driveInfo.Name + " not ready.")
                }                #Create folder structure if necessary
                $Dir = [System.IO.Path]::GetDirectoryName($LogFile)
                if (([System.IO.Directory]::Exists($Dir)) -eq $false)
                {
                    $objDir = [System.IO.Directory]::CreateDirectory($Dir)
                    Write-Log -Msg ($Dir + " created.")
                }
            }
        }
        #Write header
        Write-Log "************************************************************"
        Write-Log "   Version $Version"
        Write-Log "************************************************************"
    }
    catch
    {
        Write-Log $_
    }
}function Test-IsAdmin
{    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")}# MAIN SCRIPT PART
Initialize-LogFile
if (!(Test-IsAdmin))
{
    Write-Log "Please run this script with admin priviliges"
    exit
}[array]$printers = Get-WmiObject "Win32_Printer" | Where-Object { $_.Network -eq $false }
[array]$printersToDelete = $printers | Where-Object { $_.Network -eq $false }
Write-Log "Found $($printers.Count) local printers. Found $($printersToDelete.Count) local printers to delete..."
foreach ($printer in $printersToDelete)
{
    Write-Log "Deleting printer with name - $($printer.Name)..."
    try
    {
        $port = $printer.PortName
        $printer.Delete()
        Write-Log "`tsuccessfully deleted printer with name - $($printer.Name), going to delete printer port $($port)..."
        try
        {
            $portToDelete = $ports | Where-Object { $_.Name -eq $port }
            $portToDelete.Delete()
            Write-Log "`tprinter port $($port) deleted."
        }
        catch
        {
            Write-Log "`t!!!problem during deleting printer port $($port) - error:$($_)"
        }
    }
    catch
    {
        Write-Log "`t!!!problem during deleting printer $($printer.Name) - error:$($_)"
    }
}
[array]$ports = Get-WmiObject "Win32_TCPIPPrinterPort" | Where-Object { $_.PortNumber -eq 9100 }
[array]$printersToDelete = $printers | Where-Object { $_.PortName -in $ports.Name }
Write-Log "Found $($ports.Count) TCP/IP printer ports. Found $($printersToDelete.Count) direct IP printers to delete..."
foreach ($printer in $printersToDelete)
{
    Write-Log "Deleting printer with name - $($printer.Name)..."
    try
    {
        $port = $printer.PortName
        $printer.Delete()
        Write-Log "`tsuccessfully deleted printer with name - $($printer.Name), going to delete printer port $($port)..."
        try
        {
            $portToDelete = $ports | Where-Object { $_.Name -eq $port }
            $portToDelete.Delete()
            Write-Log "`tprinter port $($port) deleted."
        }
        catch
        {
            Write-Log "`t!!!problem during deleting printer port $($port) - error:$($_)"
        }
    }
    catch
    {
        Write-Log "`t!!!problem during deleting printer $($printer.Name) - error:$($_)"
    }
}
Write-Log "End of script..."
gpupdate /force
#