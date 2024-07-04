[CmdletBinding()]
Param (
# Make this parameter mandatory, so no default value
[Parameter(Mandatory=$true)]
$CMDs
)
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (! $myWindowsPrincipal.IsInRole($adminRole))
{
    Write-Host "Restarting image creator as admin in a new window, you can close this one."
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

$currentTime = Get-Date -format "dd-MMM-yyyy_HH-mm-ss"
$CDir = get-location
$WorkPath = $CDir.Path
$Autounattend = $CDir.Path + "\xml\autounattend.xml"
$ImagePath = (get-childitem -Path ".\input\" | Where-Object {$_.Name -like "*.iso"}).FullName
$ModImagePath = $CDir.Path + "\output\Windows_trimmed.iso"
$Wim2Path = $CDir.Path + "\WindowsCached\sources\install-1.esd"
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
$OOBEappsDir = $CDir.Path + "\oobe\Setup"
$OOBEapps = $OOBEappsDir + "\*"


$DisabledAPPS = @(
"Microsoft.WindowsStore",
"Microsoft.StorePurchaseApp",
"Microsoft.XboxSpeechToTextOverlay",
"Microsoft.XboxGameOverlay",
"Microsoft.XboxIdentityProvider",
"Microsoft.ZuneMusic",
"Microsoft.ZuneVideo",
"Microsoft.WindowsSoundRecorder",
"Microsoft.GamingApp",
"Microsoft.XboxGamingOverlay",
"Microsoft.Xbox.TCUI",
"Microsoft.WebMediaExtensions",
"Microsoft.RawImageExtension",
"Microsoft.HEIFImageExtension",
"Microsoft.HEVCVideoExtension",
"Microsoft.VP9VideoExtensions",
"Microsoft.WebpImageExtension",
"Microsoft.DolbyAudioExtensions",
"Microsoft.AVCEncoderVideoExtension",
"Microsoft.MPEG2VideoExtension",
"Microsoft.SecHealthUI",
"Microsoft.DesktopAppInstaller",
"Microsoft.Windows.Photos",
"Microsoft.WindowsCamera",
"Microsoft.WindowsNotepad",
"Microsoft.Paint",
"Microsoft.WindowsTerminal",
"Microsoft.WindowsAlarms",
"Microsoft.WindowsCalculator",
"Microsoft.MicrosoftStickyNotes"
)

$Applist = @(
"MicrosoftWindows.Client.WebExperience",
"Microsoft.WindowsMaps",
"Microsoft.ScreenSketch",
"microsoft.windowscommunicationsapps",
"Microsoft.People",
"Microsoft.BingNews",
"Microsoft.BingWeather",
"Microsoft.MicrosoftSolitaireCollection",
"Microsoft.MicrosoftOfficeHub",
"Microsoft.WindowsFeedbackHub",
"Microsoft.GetHelp",
"Microsoft.Getstarted",
"Microsoft.Todos",
"Microsoft.PowerAutomateDesktop",
"Microsoft.549981C3F5F10",
"MicrosoftCorporationII.QuickAssist",
"MicrosoftCorporationII.MicrosoftFamily",
"Microsoft.OutlookForWindows",
"MicrosoftTeams",
"Microsoft.Windows.DevHome",
"Microsoft.BingSearch",
"Microsoft.ApplicationCompatibilityEnhancements",
"MicrosoftWindows.CrossDevice",
"MSTeams",
"Microsoft.YourPhone",
"Clipchamp.Clipchamp",
"Microsoft.Whiteboard",
"microsoft.microsoftskydrive",
"Microsoft.MicrosoftTeamsforSurfaceHub",
"MicrosoftCorporationII.MailforSurfaceHub",
"Microsoft.MicrosoftPowerBIForWindows",
"Microsoft.SkypeApp",
"Microsoft.Office.Excel",
"Microsoft.Office.PowerPoint",
"Microsoft.Office.Word"
)

$Applist2 = @(
	"Microsoft-Windows-Kernel-LA57-FoD-Package"
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
"%~dp0bin\offlinereg-win64.exe" "%~dp0WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" setvalue "MailPin" 0 4

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
setlocal enableDelayedExpansion 

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
	
	$mountResult = Mount-DiskImage -ImagePath "$ImagePath"
	$driveLetter = ($mountResult | Get-Volume).DriveLetter
	$ExtractPath = $driveLetter + ":\*"
	Copy-Item -Path "$ExtractPath" -Destination $WindowsCached -Recurse -Force -Verbose -PassThru | Set-ItemProperty -name isreadonly -Value $false -ErrorAction Ignore
	Dismount-DiskImage -ImagePath "$ImagePath"
	Get-WindowsImage -ImagePath (get-childitem -Path ".\WindowsCached\sources\" | Where-Object {$_.Name -eq "install.wim" -or $_.Name -eq "install.esd"}).FullName
	$indexNumber = read-host "Please enter your chosen Index Number"

	Mount-WindowsImage -ImagePath (get-childitem -Path ".\WindowsCached\sources\" | Where-Object {$_.Name -eq "install.wim" -or $_.Name -eq "install.esd"}).FullName -Index $indexNumber -Path "$WindowsScratch"


	foreach ($app in $Applist)
	{
		Get-AppXProvisionedPackage -path $WindowsScratch | where-object {$_.DisplayName -match $app} | Remove-AppxProvisionedPackage -LogPath $appxlog -ErrorAction Ignore
	}

	foreach ($app2 in $Applist2)
	{
		Get-WindowsPackage -Path $WindowsScratch | where-object {$_.PackageName -match $app2} | Remove-WindowsPackage -LogPath $WindowsPackageLog -ErrorAction Ignore
	}
	
	If (!(Test-Path $SetupCPath)) {
		New-Item -ItemType Directory -Path $SetupCPath
		Copy-Item -Path $OOBEapps -Destination $SetupCPath -Verbose
	}
	$makeSetupC | Out-File -filepath $SetupCFile -Encoding Oem

	$mkreg1 | Out-File -filepath $regfile -Encoding Oem
	$makeSC | Out-File -filepath $SCFile -Encoding Oem
	start-process "CMD.exe" -args @("/C","`"$SCFile`"") -Wait
	Remove-Item -Path $SCFile -Force -ErrorAction Ignore
	Remove-Item -Path $regfile -Force -ErrorAction Ignore
	Remove-Item -Path $StartPin -Force -ErrorAction Ignore
	takeown /f "$PSScriptRoot\WindowsScratch\Windows\System32\OneDriveSetup.exe" /a
	takeown /f "$PSScriptRoot\WindowsScratch\Windows\System32\OneDrive.ico" /a
	icacls "$PSScriptRoot\WindowsScratch\Windows\System32\OneDriveSetup.exe" /grant:r administrators:F
	icacls "$PSScriptRoot\WindowsScratch\Windows\System32\OneDrive.ico" /grant:r administrators:F
	Remove-Item -Path "$PSScriptRoot\WindowsScratch\Windows\System32\OneDriveSetup.exe" -Force -Verbose -ErrorAction Ignore
	Remove-Item -Path "$PSScriptRoot\WindowsScratch\Windows\System32\OneDrive.ico" -Force -Verbose -ErrorAction Ignore

	Copy-Item -Path $Autounattend  -Destination $SysprepScratch -Force -Verbose -ErrorAction Ignore
	Repair-WindowsImage -Path $WindowsScratch -StartComponentCleanup -ResetBase -LimitAccess 
	Enable-WindowsOptionalFeature -Path $WindowsScratch -FeatureName "NetFx3" -Source $WindowsSXSCached -LimitAccess
	Dismount-WindowsImage -Path $WindowsScratch -Save

$dismcmd = @" 
"%WINDIR%\System32\dism.exe" /Export-Image /SourceImageFile:(get-childitem -Path ".\WindowsCached\sources\" | Where-Object {$_.Name -eq "install.wim" -or $_.Name -eq "install.esd"}).FullName /SourceIndex:$indexNumber /DestinationImageFile:"$Wim2Path" /compress:recovery /CheckIntegrity
"@

	Export-WindowsImage -SourceImagePath (get-childitem -Path ".\WindowsCached\sources\" | Where-Object {$_.Name -eq "install.wim" -or $_.Name -eq "install.esd"}).FullName -SourceIndex $indexNumber -DestinationImagePath "$Wim2Path" -CompressionType max
	Remove-Item -Path (get-childitem -Path ".\WindowsCached\sources\" | Where-Object {$_.Name -eq "install.wim" -or $_.Name -eq "install.esd"}).FullName -Force -ErrorAction Ignore
	Move-Item "$Wim2Path" ".\WindowsCached\sources\install.esd"

	$mkbat | Out-File  -filepath $batchfile -Encoding Oem
	Copy-Item -Path $Autounattend  -Destination $WindowsCached -Force -Verbose
	start-process "CMD.exe" -args @("/C","`"$batchfile`"") -Wait
	Remove-Item -Path $batchfile -Force -ErrorAction Ignore

	write-output "Creation completed!"

	Remove-Item -Path $WindowsCached -Force -Recurse
	Remove-Item -Path $WindowsScratch -Force -Recurse


}

if ($CMDs -match "Fix") {
	write-output "Cleaning up..."
	Dismount-WindowsImage -Path $WindowsScratch -discard
	Clear-WindowsCorruptMountPoint


	Remove-Item -Path $WindowsCached -Force -Recurse -ErrorAction Ignore
	Remove-Item -Path $WindowsScratch -Force -Recurse -ErrorAction Ignore
}
