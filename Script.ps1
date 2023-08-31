###################################################################################################################################################################################################################################
#MOUNTED DRIVE DETAILS
$destinationFolder = "C:\Forensic_Collection\Mounted_Drive_Details"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$mountedDrives = Get-PSDrive | Select-Object *
$outputFile = Join-Path $destinationFolder "Mounted_Drive_Details.csv"
$mountedDrives | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "CSV file created successfully: $outputFile"
###################################################################################################################################################################################################################################
#NETWORK CONNECTIONS
$destinationFolder = "C:\Forensic_Collection\Network_Connections"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$tcpConnections = Get-NetTCPConnection | Select-Object *
$outputFile = Join-Path $destinationFolder "Network_Connections.csv"
$tcpConnections | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "CSV file created successfully: $outputFile"
###################################################################################################################################################################################################################################
#PREFETCH
$destinationFolder = "C:\Forensic_Collection\Prefetch"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$sourceFolder = "C:\Windows\Prefetch"
$prefetchlocation = Join-Path $destinationFolder "Prefetch"
Copy-Item -Path $sourceFolder\* -Destination $prefetchlocation -Force -Recurse
$prefetchFiles = Get-ChildItem -Path $prefetchlocation -Filter *.pf
$csvFile = Join-Path $prefetchlocation "1.Prefetch_Properties.csv"
$propertiesArray = @()
foreach ($file in $prefetchFiles) {
    $properties = Get-ItemProperty -Path $file.FullName | Select-Object -Property * -ExcludeProperty PS* | ConvertTo-Csv -NoTypeInformation
    $propertiesArray += $properties
}
$propertiesArray | Out-File -FilePath $csvFile -Encoding UTF8
Write-Host "Prefetch files copied to $destinationFolder"
Write-Host "CSV file created successfully: $csvFile"
###################################################################################################################################################################################################################################
#PROCESS LIST
$destinationFolder = "C:\Forensic_Collection\Process_List"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$tcpConnections = Get-Process | Select-Object *
$outputFile = Join-Path $destinationFolder "Process_List.csv"
$tcpConnections | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "CSV file created successfully: $outputFile"
###################################################################################################################################################################################################################################
#SCHEDULED TASKS
$destinationFolder = "C:\Forensic_Collection\Scheduled_Tasks"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$scheduledTask = Get-ScheduledTask | Select-Object *
$outputFile = Join-Path $destinationFolder  "Scheduled_Tasks.csv"
$scheduledTask | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "CSV file created successfully: $outputFile"
#SCHEDULED TASKS RUNTIMES
$scheduledTasks = Get-ScheduledTask | ForEach-Object {
    $task = $_
    $taskInfo = $task | Get-ScheduledTaskInfo

    if ($taskInfo) {
        [PSCustomObject]@{
            TaskName = $task.TaskName
            Path = $task.Path
            Description = $task.Description
            Author = $task.Author
            LastRunTime = $taskInfo.LastRunTime
            LastTaskResult = $taskInfo.LastTaskResult
            NextRunTime = $taskInfo.NextRunTime
            Triggers = $taskInfo.Triggers | ForEach-Object { $_.ToString() }
            Actions = $taskInfo.Actions | ForEach-Object { $_.ToString() }
        }
    }
}
$outputFile = Join-Path $destinationFolder "Scheduled_Tasks_RunTimes.csv"
$scheduledTasks | Export-Csv -Path $outputFile -NoTypeInformation
$csvFile = Get-Content $outputFile
$csvFile[0] = $csvFile[0] -replace '"',''
$csvFile[1] = $csvFile[1] -replace ',',' |'
$csvFile | Set-Content $outputFile
Write-Host "CSV file created successfully: $outputFile"
###################################################################################################################################################################################################################################
#SYSINFO
$destinationFolder = "C:\Forensic_Collection\SysInfo"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$classes = @(
    "Win32_OperatingSystem",
    "Win32_ComputerSystem",
    "Win32_Processor",
    "Win32_PhysicalMemory",
    "Win32_NetworkAdapterConfiguration"
)
foreach ($class in $classes) {
    $sysInfo = Get-WmiObject -Class $class
    $outputFile = Join-Path $destinationFolder "$class.txt"
    $sysInfo | Select-Object -Property * | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host "Text file created successfully: $outputFile"
}
###################################################################################################################################################################################################################################
#WINDOWS SERVICES
$destinationFolder = "C:\Forensic_Collection\Windows_Services"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$outputTable = @()
$services = Get-Service
foreach ($service in $services) {
    $serviceInfo = $service | Select-Object *
    $outputTable += $serviceInfo
}
$outputFile = Join-Path $destinationFolder "Windows_Services.csv"
$outputTable | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "CSV file created successfully: $outputFile"
###################################################################################################################################################################################################################################
#BROWSER HISTORY
$destinationFolder = "C:\Forensic_Collection\Browser_History"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$ieFolder = "IE_History"
$chromeFolder = "Chrome_History"
$firefoxFolder = "Firefox_History"
$edgeFolder = "Edge_History"
$ieSourcePath = "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache\Low\IE"
$ieDestinationPath = Join-Path -Path $destinationFolder -ChildPath $ieFolder
Copy-Item -Path $ieSourcePath -Filter * -Destination $ieDestinationPath -Recurse -Force
$chromeSourcePath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
$chromeDestinationPath = Join-Path -Path $destinationFolder -ChildPath $chromeFolder
Copy-Item -Path $chromeSourcePath -Destination $chromeDestinationPath -Force
$firefoxSourcePath = "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite"
$firefoxDestinationPath = Join-Path -Path $destinationFolder -ChildPath $firefoxFolder
Copy-Item -Path $firefoxSourcePath -Destination $firefoxDestinationPath -Force
$edgeSourcePath = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History"
$edgeDestinationPath = Join-Path -Path $destinationFolder -ChildPath $edgeFolder
Copy-Item -Path $edgeSourcePath -Destination $edgeDestinationPath -Force
Write-Host "Browser history data has been saved to $destinationFolder"
###################################################################################################################################################################################################################################
#JUMP LIST
$destinationFolder = "C:\Forensic_Collection\Jump_List"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$jumpListFolderName = "Jump_List"
$outputFolder = Join-Path -Path $destinationFolder -ChildPath $jumpListFolderName
if (-not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
}
$userProfiles = Get-ChildItem -Path "C:\Users\" -Directory -ErrorAction SilentlyContinue
foreach ($userProfile in $userProfiles) {
    $userName = $userProfile.Name
    $jumpListSourceFolder = "C:\Users\$userName\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
    $jumpListFiles = Get-ChildItem -Path $jumpListSourceFolder -File -Force -ErrorAction SilentlyContinue

    
    foreach ($jumpListFile in $jumpListFiles) {
        try {
            $outputFilePath = Join-Path -Path $outputFolder -ChildPath "$userName-$($jumpListFile.Name)"
            Copy-Item -Path $jumpListFile.FullName -Destination $outputFilePath -Force
        }
        catch {
            Write-Host "Failed to copy $jumpListFile"
        }
    }
}
Write-Host "Jump list files have been saved to $outputFolder"
###################################################################################################################################################################################################################################
#REGISTRY HIVES
$destinationFolder = "C:\Forensic_Collection\Registry_Hives"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$registryFolderName = "RegistryData"
$outputFolder = Join-Path -Path $destinationFolder -ChildPath $registryFolderName
if (-not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
}
$hives = @(
    "HKEY_LOCAL_MACHINE",
    "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_USER",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG"
)
foreach ($hive in $hives) {
    $hiveName = $hive -replace "HKEY_", ""
    $outputFile = Join-Path -Path $outputFolder -ChildPath "$hiveName.reg"
    Write-Host "Exporting $hive to $outputFile"
    reg export $hive $outputFile -y | Out-Null
}
Write-Host "Registry export completed. Exported .reg files saved to $outputFolder"
###################################################################################################################################################################################################################################
#EVENT LOGS
$destinationFolder = "C:\Forensic_Collection\Event_Logs"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$sourceFolder = "C:\Windows\System32\winevt\Logs"
$eventLogs = @('System.evtx', 'Security.evtx', 'Application.evtx', 'Windows PowerShell.evtx')
foreach ($eventLog in $eventLogs) {
    $sourcePath = Join-Path -Path $sourceFolder -ChildPath $eventLog
    $destinationPath = Join-Path -Path $destinationFolder -ChildPath $eventLog
    Copy-Item -Path $sourcePath -Destination $destinationPath -Force
}
Write-Host "Event log files have been collected and placed in the destination folder: $destinationFolder"
###################################################################################################################################################################################################################################
#NTUSER DATA
$destinationFolder = "C:\Forensic_Collection\NTUSER"
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
Add-Type -TypeDefinition @"
    using System;
    using System.IO;
"@
$userProfiles = Get-ChildItem -Path 'C:\Users' -Directory
foreach ($userProfile in $userProfiles) {
    $ntuserPath = Join-Path -Path $userProfile.FullName -ChildPath 'NTUSER.dat'

    if (Test-Path -Path $ntuserPath) {
        $newPath = [IO.Path]::Combine($destinationFolder, ($userProfile.Name + '_NTUSER.dat'))
        Move-Item -Path $ntuserPath -Destination $newPath -Force
    }
}
Write-Host "NTUSER.dat files collected and moved to $destinationFolder"
###################################################################################################################################################################################################################################
#CONFIG FOLDER
$destinationFolder = "C:\Forensic_Collection\Config"
if (-not (Test-Path -Path $destinationFolder -PathType Container)) {
    New-Item -Path $destinationFolder -ItemType Directory | Out-Null
}
$sourceFolder = "C:\Windows\System32\config"
Copy-Item -Path $sourceFolder\* -Destination $destinationFolder -Recurse -Force
reg export HKLM\SAM "$destinationFolder\SAM.reg"
reg export HKLM\SOFTWARE "$destinationFolder\SOFTWARE.reg"
reg export HKLM\SYSTEM "$destinationFolder\SYSTEM.reg"
reg export HKLM\SECURITY "$destinationFolder\SECURITY.reg"
Write-Host "Files and registry exports have been saved to $destinationFolder"
###################################################################################################################################################################################################################################
#ETC
$destinationFolder = 'C:\Forensic_Collection\ETC'
if (!(Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$sourceFolder = 'C:\Windows\System32\drivers\etc'
$files = Get-ChildItem -Path $sourceFolder -File
if ($files.Count -gt 0) {
    foreach ($file in $files) {
        $newPath = Join-Path -Path $destinationFolder -ChildPath $file.Name
        Copy-Item -Path $file.FullName -Destination $newPath -Force
    }
    Write-Host "Files copied to $destinationFolder"
} else {
    Write-Host "No files found in $sourceFolder"
}
###################################################################################################################################################################################################################################
#START MENU
$destinationFolder = 'C:\Forensic_Collection\StartUp_Data'
if (!(Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}
$outputFilePath = Join-Path -Path $destinationFolder -ChildPath 'Programs_List.csv'
$programItems = @()
$users = Get-ChildItem -Path 'C:\Users' -Directory
foreach ($user in $users) {
    $startMenuPath = Join-Path -Path $user.FullName -ChildPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
    if (Test-Path -Path $startMenuPath) {
        $items = Get-ChildItem -Path $startMenuPath -File -Recurse | Select-Object -Property Name, FullName
        $programItems += $items
    }
}
$programItems | Export-Csv -Path $outputFilePath -NoTypeInformation
Write-Host "Programs list saved to $outputFilePath"
###################################################################################################################################################################################################################################
