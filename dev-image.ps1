[CmdletBinding()]
Param (
    # Make this parameter mandatory, so no default value
    [Parameter(Mandatory=$true)]
    $CMDs
)
	$CDir = get-location
	$WorkPath = $CDir.Path
	$ImagePath = $CDir.Path + "\Windows_23H2.iso"
	$ModImagePath = $CDir.Path + "\Windows_23H2-trimmed.iso"
	$WimPath = $CDir.Path+ "\WindowsCached\sources\install.wim"
	$WimBootPath = $CDir.Path+ "\WindowsCached\sources\boot.wim"
	$WindowsCached = $CDir.Path + "\WindowsCached"
	$WindowsSXSCached = $CDir.Path + "\WindowsCached\sources\sxs" 
	$WindowsScratch = $CDir.Path + "\WindowsScratch"
	if ($CMDs -match "CreateISO") {
		
		
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
		
		 $Applist = @(
		"Microsoft.GamingApp*",
		"Microsoft.GetHelp*",
		"Microsoft.Getstarted*",
		"Microsoft.MicrosoftOfficeHub*",
		"Microsoft.MicrosoftSolitaireCollection*",
		"Microsoft.People*",
		"*windowsstore*",
		"Microsoft.WindowsAlarms*",
		"*Xbox*",
		"*king.com.CandyCrushSodaSaga*",
		"Microsoft.Todos*",
		"*Twitter*",
		"Microsoft.Bing*",
		"*Microsoft.Messaging*",
		"*Microsoft.BingFinance*",
		"*Microsoft.WindowsScan*",
		"*Microsoft.Reader*",
		"*Microsoft.CommsPhone*",
		"*Microsoft.ConnectivityStore*",
		"*Microsoft.WindowsReadingList*",
		"Clipchamp.Clipchamp*",
		"*Skype*",
		"*Tiktok*",
		"*Snapchat*",
		"microsoft.windowscommunicationsapps*",
		"Microsoft.WindowsFeedbackHub*",
		"MicrosoftCorporationII.MicrosoftFamily*",
		"MicrosoftTeams*",
		"Microsoft.549981C3F5F10*",
		"Microsoft.Zune*"
		)
		
		foreach ($app in $Applist)
		{
		Get-appxprovisionedpackage -Path $WindowsScratch | where-object {$_.packagename -like $app} | remove-appxprovisionedpackage -Path $WindowsScratch
		}
		echo Loading registry...
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zCOMPONENTS $WindowsScratch + "\Windows\System32\config\COMPONENTS" >nul'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zDEFAULT $WindowsScratch + "\Windows\System32\config\default" >nul'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zNTUSER $WindowsScratch + "\Users\Default\ntuser.dat" >nul'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zSOFTWARE $WindowsScratch + "\Windows\System32\config\SOFTWARE" >nul'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zSYSTEM $WindowsScratch + "\Windows\System32\config\SYSTEM" >nul'
		echo "Bypassing system requirements(on the system image):"
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f >nul 2>&1'
		echo Disabling Teams:
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d "0" /f >nul 2>&1'
		echo Disabling Sponsored Apps:
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d "{\"pinnedList\": [{}]}" /f >nul 2>&1'
		echo Enabling Local Accounts on OOBE:
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f >nul 2>&1'
		Copy-Item -Path $WorkPath + "\xml\autoattend.xml"  -Destination $WindowsScratch + "\Windows\System32\Sysprep" -Recurse -Force -Verbose
		echo Disabling Reserved Storage:
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f >nul 2>&1'
		echo Disabling Chat icon:
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f >nul 2>&1'
		echo Ocwen Tweaks:
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\CurrentControlSet\Services\CSC" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Policies\Microsoft\Windows\NetCache" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Software\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingLowDiskSpaceMB" /t REG_DWORD /d "20000" /f >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSOFTWARE\Software\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingOutlook" /t REG_DWORD /d "1" /f >nul 2>&1'
		
		echo Unmounting Registry...
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zCOMPONENTS >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zDRIVERS >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zDEFAULT >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zNTUSER >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zSCHEMA >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zSOFTWARE >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zSYSTEM >nul 2>&1'

		Repair-WindowsImage -Path $WindowsScratch -StartComponentCleanup -ResetBase
		Enable-WindowsOptionalFeature -Path $WindowsScratch -FeatureName "NetFx3" -Source $WindowsSXSCached
		Dismount-WindowsImage -Path $WindowsScratch -Save
		Export-WindowsImage -SourceImagePath $WimPath -SourceIndex $index -DestinationImagePath $WindowsCached + "\sources\install.esd" -CheckIntegrity -CompressionType max
		Mount-WindowsImage -ImagePath $WimBootPath -Index 2 -Path $WindowsScratch
		
		echo Loading registry...
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zCOMPONENTS $WindowsScratch + "\Windows\System32\config\COMPONENTS" >nul'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zDEFAULT $WindowsScratch + "\Windows\System32\config\default" >nul'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zNTUSER $WindowsScratch + "\Users\Default\ntuser.dat" >nul'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zSOFTWARE $WindowsScratch + "\Windows\System32\config\SOFTWARE" >nul'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg load HKLM\zSYSTEM $WindowsScratch + "\Windows\System32\config\SYSTEM" >nul'
		echo "Bypassing system requirements(on the system image):"
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f >nul 2>&1'
			Start-Process -Wait "CMD.exe" -ArgumentList '/C reg add"HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f >nul 2>&1'
		echo Tweaking complete! 
		echo Unmounting Registry...
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zCOMPONENTS >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zDRIVERS >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zDEFAULT >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zNTUSER >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zSCHEMA >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zSOFTWARE >nul 2>&1'
		Start-Process -Wait "CMD.exe" -ArgumentList '/C reg unload HKLM\zSYSTEM >nul 2>&1'

		Dismount-WindowsImage -Path $WindowsScratch -Save

		Copy-Item -Path $WorkPath + "\xml\autoattend.xml"  -Destination $WindowsCached -Recurse -Force -Verbose
		Start-Process -Wait -Path $WorkPath + "\bin\oscdimg.exe" -ArgumentList '-m -o -u2 -udfver102 -bootdata:2#p0,e,b"%~dp0Win11Space\boot\etfsboot.com"#pEF,e,b"%~dp0Win11Space\efi\microsoft\boot\efisys.bin" "%~dp0Win11Space" "%~dp0Windows_23H2.iso"'
		echo Creation completed!
		
		Remove-Item -Path $WindowsCached -Force -Recurse
		Remove-Item -Path $WindowsScratch -Force -Recurse
	
	
	}
	
	if ($CMDs -match "Fix") {
		
		Dismount-WindowsImage -Path $WindowsScratch -discard
		Clear-WindowsCorruptMountPoint
		
		
		Remove-Item -Path $WindowsCached -Force -Recurse
		Remove-Item -Path $WindowsScratch -Force -Recurse
	}
