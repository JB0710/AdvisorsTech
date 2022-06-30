powershell Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
powershell Install-Module -Force PSWindowsUpdate
y

powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /hibernate off
powercfg /change monitor-timeout-ac 60
powercfg /change monitor-timeout-dc 15
powercfg /change disk-timeout-ac 0
powercfg /change disk-timeout-dc 0
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 60



