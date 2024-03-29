[CmdletBinding()]
Param (
# Make this parameter mandatory, so no default value
[Parameter(Mandatory=$true)]
$CMDs
)
$currentTime = Get-Date -format "dd-MMM-yyyy_HH-mm-ss"
$CDir = get-location
$WorkPath = $CDir.Path
$Autounattend = $CDir.Path + "\xml\autounattend.xml"
$ImagePath = $CDir.Path + "\Windows_23H2.iso"
$ModImagePath = $CDir.Path + "\Windows_23H2-trimmed.iso"
$WimPath = $CDir.Path + "\WindowsCached\sources\install.wim"
$Wim2Path = $CDir.Path + "\WindowsCached\sources\install.esd"
$Wim3Path = $CDir.Path + "\WindowsCached\sources\install.wim-2"
$WimBootPath = $CDir.Path+ "\WindowsCached\sources\boot.wim"
$WindowsCached = $CDir.Path + "\WindowsCached"
$WindowsSXSCached = $CDir.Path + "\WindowsCached\sources\sxs" 
$WindowsScratch = $CDir.Path + "\WindowsScratch"
$StartPin = $WindowsScratch + "Users\Default\Appdata\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start.bin"
$etfs = $CDir.Path + "\WindowsCached\boot\etfsboot.com"
$efisys = $CDir.Path + "\WindowsCached\efi\microsoft\boot\efisys.bin"
$SysprepScratch = $CDir.Path + "\WindowsScratch\Windows\System32\Sysprep"
$SCFile = $WorkPath + "\offlinereg.bat"
$SetupCPath = $WindowsScratch + "\Windows\Setup\Scripts"
$SetupCFile = $WindowsScratch + "\Windows\Setup\Scripts\SetupComplete.cmd"
$batchfile = $CDir.Path + "\mkimg.bat"	
$dismbat = $CDir.Path + "\dism.bat"	
$regfile = $CDir.Path + "\pins.reg"	
$appxlog = $CDir.Path + "\appx-remove_$currentTime.txt"	
$WindowsPackageLog = $CDir.Path + "\wplog_$currentTime.txt"	


$Applist = @(
	"*Microsoft.GamingApp*",
	"*Microsoft.GetHelp*",
	"*Microsoft.Getstarted*",
	"*Microsoft.MicrosoftOfficeHub*",
	"*Microsoft.MicrosoftSolitaireCollection*",
	"*Microsoft.People*",
	"*Microsoft.WindowsStore*",
	"*Microsoft.StorePurchase*",
	"*Microsoft.OutlookFor*",
	"*Microsoft.WindowsMaps*",
	"*Microsoft.WindowsAlarms*",
	"*Microsoft.XboxSpeechToTextOverlay*",
	"*Microsoft.XboxGameOverlay*",
	"*Microsoft.XboxGamingOverlay*",
	"*Microsoft.XboxIdentityProvider*",
	"*Microsoft.Xbox.TCUI*",
	"*Microsoft.Todos*",
	"*Microsoft.Bing*",
	"*Microsoft.Messaging*",
	"*Microsoft.BingFinance*",
	"*Microsoft.WindowsScan*",
	"*Microsoft.Reader*",
	"*Microsoft.CommsPhone*",
	"*Microsoft.ConnectivityStore*",
	"*Microsoft.WindowsReadingList*",
	"*Clipchamp.Clipchamp*",
	"*Microsoft.SkypeApp*",
	"*microsoft.windowscommunicationsapps*",
	"*microsoft.WindowsSoundRecorder*",
	"*Microsoft.WindowsFeedbackHub*",
	"*MicrosoftCorporationII.MicrosoftFamily*",
	"*Microsoft.YourPhone*",
	"*MicrosoftTeams*",
	"*Microsoft.549981C3F5F10*",
	"*Microsoft.Windows.DevHome*",
	"*Microsoft.ZuneMusic*",
	"*Microsoft.Ai.Copilot*",
	"*Microsoft.ZuneVideo*"
)

$Applist2 = @(
	"Microsoft-Windows-Kernel-LA57-FoD-Package*"
)

$makeSC = @"
@echo off
echo Disabling Teams:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SOFTWARE" "Microsoft\Windows\CurrentVersion\Communications" setvalue "ConfigureChatAutoInstall" 0 4
echo Disabling Sponsored Apps:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue "OemPreInstalledAppsEnabled" 0 4
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue "PreInstalledAppsEnabled" 0 4
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue "SilentInstalledAppsEnabled" 0 4
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\Windows\CloudContent" setvalue "DisableWindowsConsumerFeatures" 1 4
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SOFTWARE" " " import %~dp0pins.reg
echo Enabling Local Accounts on OOBE:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SOFTWARE" "Microsoft\Windows\CurrentVersion\OOBE" setvalue "BypassNRO" 1 4
echo Disabling Reserved Storage:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SOFTWARE" "Microsoft\Windows\CurrentVersion\ReserveManager" setvalue "ShippedWithReserves" 0 4
echo Disable Copilot:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\Windows\WindowsCopilot" setvalue "TurnOffWindowsCopilot" 1 4
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" setvalue "TurnOffWindowsCopilot" 1 4
echo Disabling Chat icon:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\Windows\Windows Chat" setvalue "ChatIcon" 3 4
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "TaskbarMn" 0 4
echo Disabling Search icon:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "ShowCortanaButton" 0 4
echo Disabling TaskViews icon:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "ShowTaskViewButton" 0 4
echo Aligning Taskbar to left:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "TaskbarAl" 0 4
echo Disabling Widgets icon:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "TaskbarDa" 0 4
echo Disabling Hibernate:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Control\Power" setvalue "HibernateEnabled" 0 4
echo Setting Time Service:
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Services\W32Time" setvalue "Start" 2 4
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Services\tzautoupdate" setvalue "Start" 2 4
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Services\W32Time\Parameters" setvalue "Type" "NTP" 1
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Services\W32Time\Parameters" setvalue "NtpServer" "time.windows.com,pool.ntp.org" 1
"@

$makeSetupC =@'
@echo off
del /s /q %WINDIR%\Setup\Scripts\SetupComplete.cmd
'@

$mkbat = @"
@echo off
"%~dp0bin\oscdimg.exe" -m -o -u2 -udfver102 -bootdata:2#p0,e,b"$etfs"#pEF,e,b"$efisys" "$WindowsCached" "$ModImagePath"
"@

$mkreg1 =@'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Start]
"ConfigureStartPins"="{"pinnedList":[{"packagedAppId":"windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"}]}"
"ConfigureStartPins_ProviderSet"=dword:00000001
'@


if ($CMDs -match "CreateISO") {

	write-output "Setting up image workspace..."
	
	If (Test-Path $ModImagePath) {
		Remove-Item -Path $ModImagePath -Force
	}
	
	If (!(Test-Path $WindowsCached)) {
		New-Item -ItemType Directory -Path $WindowsCached
	}
	
	If (!(Test-Path $WindowsScratch)) {
		New-Item -ItemType Directory -Path $WindowsScratch
	}
	
	$mountResult = Mount-DiskImage -ImagePath $ImagePath
	$driveLetter = ($mountResult | Get-Volume).DriveLetter
	$ExtractPath = $driveLetter + ":\*"
	Copy-Item -Path "$ExtractPath" -Destination $WindowsCached -Recurse -Force -Verbose -PassThru | Set-ItemProperty -name isreadonly -Value $false
	Dismount-DiskImage -ImagePath $ImagePath
	Get-WindowsImage -ImagePath $WimPath
	$indexNumber = read-host "Please enter your chosen Index Number:"
	Mount-WindowsImage -ImagePath $WimPath -Index $indexNumber -Path $WindowsScratch


	foreach ($app in $Applist)
	{
		Get-AppXProvisionedPackage -path $WindowsScratch | where-object {$_.PackageName -like $app} | Remove-AppxProvisionedPackage -LogPath $appxlog
	}

	foreach ($app2 in $Applist2)
	{
		Get-WindowsPackage -Path $WindowsScratch | where-object {$_.PackageName -like $app2} | Remove-WindowsPackage -LogPath $WindowsPackageLog
	}
	
	If (!(Test-Path $SetupCPath)) {
		New-Item -ItemType Directory -Path $SetupCPath
	}
	$makeSetupC | Out-File -filepath $SetupCFile -Encoding Oem

	$mkreg1 | Out-File -filepath $regfile -Encoding Oem
	$makeSC | Out-File -filepath $SCFile -Encoding Oem
	start-process "CMD.exe" -args @("/C","`"$SCFile`"") -Wait
	Remove-Item -Path $SCFile -Force
	Remove-Item -Path $regfile -Force
	Remove-Item -Path $StartPin -Force
	

	Copy-Item -Path $Autounattend  -Destination $SysprepScratch -Force -Verbose
	Repair-WindowsImage -Path $WindowsScratch -StartComponentCleanup -ResetBase -LimitAccess
	Enable-WindowsOptionalFeature -Path $WindowsScratch -FeatureName "NetFx3" -Source $WindowsSXSCached -LimitAccess
	Dismount-WindowsImage -Path $WindowsScratch -Save

$dismcmd = @" 
"%WINDIR%\System32\dism.exe" /Export-Image /SourceImageFile:"$WimPath" /SourceIndex:$indexNumber /DestinationImageFile:"$Wim2Path" /compress:recovery /CheckIntegrity
"@

	# $dismcmd | Out-File -filepath $dismbat -Encoding Oem
	# start-process "CMD.exe" -args @("/C","`"$dismbat`"") -Wait
	# Remove-Item -Path $dismbat -Force
	Export-WindowsImage -SourceImagePath $WimPath -SourceIndex $indexNumber -DestinationImagePath $Wim3Path -CompressionType max
	Remove-Item -Path $WimPath -Force
	Move-Item $Wim3Path $WimPath
	# Mount-WindowsImage -ImagePath $WimBootPath -Index 2 -Path $WindowsScratch
	# Dismount-WindowsImage -Path $WindowsScratch -Save

	$mkbat | Out-File  -filepath $batchfile -Encoding Oem
	Copy-Item -Path $Autounattend  -Destination $WindowsCached -Force -Verbose
	start-process "CMD.exe" -args @("/C","`"$batchfile`"") -Wait
	Remove-Item -Path $batchfile -Force

	write-output "Creation completed!"

	Remove-Item -Path $WindowsCached -Force -Recurse
	Remove-Item -Path $WindowsScratch -Force -Recurse


}

if ($CMDs -match "Fix") {
	write-output "Cleaning up..."
	Dismount-WindowsImage -Path $WindowsScratch -discard
	Clear-WindowsCorruptMountPoint


	Remove-Item -Path $WindowsCached -Force -Recurse
	Remove-Item -Path $WindowsScratch -Force -Recurse
}
