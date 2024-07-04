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
$etfs = $CDir.Path + "\WindowsCached\boot\etfsboot.com"
$efisys = $CDir.Path + "\WindowsCached\efi\microsoft\boot\efisys.bin"
$SysprepScratch = $CDir.Path + "\WindowsScratch\Windows\System32\Sysprep"
$SCFile = $WorkPath + "\offlinereg.bat"
$SetupCPath = $WindowsScratch + "\Windows\Setup\Scripts"
$SetupCFile = $WindowsScratch + "\Windows\Setup\Scripts\SetupComplete.cmd"
$dismbat = $CDir.Path + "\dism.bat"	
$appxlog = $CDir.Path + "\appx-remove_$currentTime.txt"	
$WindowsPackageLog = $CDir.Path + "\wplog_$currentTime.txt"	
$OOBEappsDir = $CDir.Path + "\oobe\Setup"
$OOBEapps = $OOBEappsDir + "\*"

$DisabledAPPS = @(
"Microsoft.ZuneMusic",
"Microsoft.ZuneVideo",
"Microsoft.WindowsSoundRecorder",
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
"Microsoft.WindowsStore",
"Microsoft.StorePurchaseApp",
"Microsoft.XboxSpeechToTextOverlay",
"Microsoft.XboxGameOverlay",
"Microsoft.XboxIdentityProvider",
"Microsoft.GamingApp",
"Microsoft.XboxGamingOverlay",
"Microsoft.Xbox.TCUI",
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

$makeSetupC =@'
@echo off
setlocal enableDelayedExpansion 

del /s /q %WINDIR%\Setup\Scripts\SetupComplete.cmd
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
		try{
		write-output "Uninstalling $($app)"
		Get-AppXProvisionedPackage -path $WindowsScratch | where-object {$_.DisplayName -match $app} | Remove-AppxProvisionedPackage -LogPath $appxlog -ErrorAction Ignore >null

		}
		catch {
		Write-Error "Uninstalling $($app) failed"
		}
	}

	foreach ($app2 in $Applist2)
	{
		
		try{
		write-output "Uninstalling $($app2)"
		Get-WindowsPackage -Path $WindowsScratch | where-object {$_.PackageName -match $app2} | Remove-WindowsPackage -LogPath $WindowsPackageLog -ErrorAction Ignore >null

		}
		catch {
		Write-Error "Uninstalling $($app2) failed"
		}
		
	}
	
	If (!(Test-Path $SetupCPath)) {
		New-Item -ItemType Directory -Path $SetupCPath
		Copy-Item -Path $OOBEapps -Destination $SetupCPath -Verbose
	}
	
 
 
	write-output "Disabling Teams:"
 
 	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Microsoft\Windows\CurrentVersion\Communications" setvalue "ConfigureChatAutoInstall" 0 4
	}
	
	catch {
	Write-Error "ConfigureChatAutoInstall Failed"

	}
	write-output "Disabling Sponsored Apps:"
	
	
			try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'PreInstalledAppsEnabled' 0 4
	}
	
	catch {
		Write-Error "PreInstalledAppsEnabled Failed"
	}
		try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'OemPreInstalledAppsEnabled' 0 4
	}
	
	catch {
		Write-Error "OemPreInstalledAppsEnabled Failed"
	}

	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SilentInstalledAppsEnabled' 0 4
	}
	
	catch {
		Write-Error "SilentInstalledAppsEnabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\Windows\CloudContent" setvalue 'DisableWindowsConsumerFeatures' 1 4
	}
	
	catch {
		Write-Error "DisableWindowsConsumerFeatures Failed"
	
	}

	# try {
	# & "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Microsoft\PolicyManager\current\device\Start" setvalue 'ConfigureStartPins' "{^`"pinnedList^`": [{}]}"	1
	# }
	
	# catch {
		# Write-Error "ConfigureStartPins Failed"
	
	# }
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'ContentDeliveryAllowed' 0 4
	}
	
	catch {
		Write-Error "ContentDeliveryAllowed Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'FeatureManagementEnabled' 0 4
	}
	
	catch {
		Write-Error "FeatureManagementEnabled Failed"
	
	}

	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'PreInstalledAppsEverEnabled' 0 4
	}
	
	catch {
		Write-Error "PreInstalledAppsEverEnabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SoftLandingEnabled' 0 4
	}
	
	catch {
		Write-Error "SoftLandingEnabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SubscribedContentEnabled' 0 4
	}
	
	catch {
		Write-Error "SubscribedContentEnabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SubscribedContent-310093Enabled' 0 4
	}
	
	catch {
		Write-Error "SubscribedContent-310093Enabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SubscribedContent-338388Enabled' 0 4
	}
	
	catch {
		Write-Error "SubscribedContent-338388Enabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SubscribedContent-338389Enabled' 0 4
	}
	
	catch {
		Write-Error "SubscribedContent-338388Enabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SubscribedContent-338393Enabled' 0 4
	}
	
	catch {
		Write-Error "SubscribedContent-338393Enabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SubscribedContent-353694Enabled' 0 4
	}
	
	catch {
		Write-Error "SubscribedContent-353694Enabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SubscribedContent-353696Enabled' 0 4
	}
	
	catch {
		Write-Error "SubscribedContent-353696Enabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SubscribedContentEnabled' 0 4
	}
	
	catch {
		Write-Error "SubscribedContent-353696Enabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" setvalue 'SystemPaneSuggestionsEnabled' 0 4
	}
	
	catch {
		Write-Error "SystemPaneSuggestionsEnabled Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\PushToInstall" setvalue 'DisablePushToInstall' 1 4
	}
	
	catch {
		Write-Error "DisablePushToInstall Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\MRT" setvalue 'DontOfferThroughWUAU' 1 4
	}
	
	catch {
		Write-Error "DontOfferThroughWUAU Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" deletekey 'Subscriptions'
	}
	
	catch {
		Write-Error "Subscriptions Failed"
	
	}
	
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\Windows\CloudContent" setvalue 'DisableConsumerAccountStateContent' 1 4
	}
	
	catch {
		Write-Error "DisableConsumerAccountStateContent Failed"
	
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\Windows\CloudContent" setvalue 'DisableCloudOptimizedContent' 1 4
	}
	
	catch {
		Write-Error "DisableCloudOptimizedContent Failed"
	
	}
	
	write-output "Enabling Local Accounts on OOBE:"
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Microsoft\Windows\CurrentVersion\OOBE" setvalue "BypassNRO" 1 4
	}
	
	catch {
	Write-Error "BypassNRO Failed"
	}
	
	write-output "Disabling Reserved Storage:"
		try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Microsoft\Windows\CurrentVersion\ReserveManager" setvalue "ShippedWithReserves" 0 4
	
	}
	
	catch {
	Write-Error "ShippedWithReserves Failed"
	}
	
	write-output "Disable Copilot:"	
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\Windows\WindowsCopilot" setvalue "TurnOffWindowsCopilot" 1 4
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" setvalue "TurnOffWindowsCopilot" 1 4
	}
	
	catch {
	Write-Error "Disable Copilot Failed"
	}
	
	write-output "Disabling Chat icon:"
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "TaskbarMn" 0 4
	}
	
	catch {
	Write-Error "TaskbarMn Failed"
	}
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SOFTWARE" "Policies\Microsoft\Windows\Windows Chat" setvalue "ChatIcon" 3 4

	}
	
	catch {
	Write-Error "ChatIcon Failed"
	}
	write-output "Disabling Search icon:"
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "ShowCortanaButton" 0 4
	}
	
	catch {
	Write-Error "ShowCortanaButton Failed"
	}
	
	write-output "Disabling TaskViews icon:"
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "ShowTaskViewButton" 0 4
	}
	catch {
	Write-Error "ShowTaskViewButton Failed"
	}
	
	write-output "Aligning Taskbar to left:"
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "TaskbarAl" 0 4
	}
	catch {
	Write-Error "TaskbarAl Failed"
	}
	write-output "Disabling Widgets icon:"
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" setvalue "TaskbarDa" 0 4
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Users\Default\ntuser.dat" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" setvalue "MailPin" 0 4
	}
	catch {
	Write-Error "Disabling Widgets Failed"
	}
	write-output "Disabling Hibernate:"
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Control\Power" setvalue "HibernateEnabled" 0 4
	}
	catch {
	Write-Error "HibernateEnabled Failed"
	}
	
	write-output "Setting Time Service:"
	try {
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Services\W32Time" setvalue "Start" 2 4
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SYSTEM"  "CurrentControlSet\Services\tzautoupdate" setvalue "Start" 2 4
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Services\W32Time\Parameters" setvalue "Type" "NTP" 1
	& "$($PSScriptRoot)\bin\offlinereg-win64.exe" "$WindowsScratch\Windows\System32\config\SYSTEM" "CurrentControlSet\Services\W32Time\Parameters" setvalue "NtpServer" "time.windows.com,pool.ntp.org" 1
	}
	catch {
	Write-Error "Setting Time Service Failed"
	}

	$makeSetupC | Out-File -filepath $SetupCFile -Encoding Oem
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

	


	Export-WindowsImage -SourceImagePath (get-childitem -Path ".\WindowsCached\sources\" | Where-Object {$_.Name -eq "install.wim" -or $_.Name -eq "install.esd"}).FullName -SourceIndex $indexNumber -DestinationImagePath "$Wim2Path" -CompressionType max
	Remove-Item -Path (get-childitem -Path ".\WindowsCached\sources\" | Where-Object {$_.Name -eq "install.wim" -or $_.Name -eq "install.esd"}).FullName -Force -ErrorAction Ignore
	Move-Item "$Wim2Path" ".\WindowsCached\sources\install.esd"

	
	Copy-Item -Path $Autounattend  -Destination $WindowsCached -Force -Verbose

	& "$($PSScriptRoot)\bin\oscdimg.exe" -m -o -u2 -udfver102 -bootdata:2#p0,e,b"$etfs"`#pEF,e,b"$efisys" "$WindowsCached" "$ModImagePath"

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
