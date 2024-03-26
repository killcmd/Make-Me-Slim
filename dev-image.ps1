[CmdletBinding()]
Param (
    # Make this parameter mandatory, so no default value
    [Parameter(Mandatory=$true)]
    $CMDs
)
	$CDir = get-location
	$WorkPath = $CDir.Path
	$Autounattend = $CDir.Path + "\xml\autounattend.xml"
	$ImagePath = $CDir.Path + "\Windows_23H2.iso"
	$ModImagePath = $CDir.Path + "\Windows_23H2-trimmed.iso"
	$WimPath = $CDir.Path + "\WindowsCached\sources\install.wim"
	$Wim2Path = $CDir.Path + "\WindowsCached\sources\install.wim-2"
	$WimBootPath = $CDir.Path+ "\WindowsCached\sources\boot.wim"
	$WindowsCached = $CDir.Path + "\WindowsCached"
	$WindowsSXSCached = $CDir.Path + "\WindowsCached\sources\sxs" 
	$WindowsScratch = $CDir.Path + "\WindowsScratch"
	$etfs = $CDir.Path + "\WindowsScratch\boot\etfsboot.com"
	$efisys = $CDir.Path + "\WindowsScratch\efi\microsoft\boot\efisys.bin"
	$SysprepScratch = $CDir.Path + "\WindowsScratch\Windows\System32\Sysprep"
	if ($CMDs -match "CreateISO") {
		
		write-output "Setting up image workspace..."
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
		
		$Applist2 = @(
		"Microsoft-Windows-Kernel-LA57-FoD-Package*"
		)
		
		foreach ($app2 in $Applist2)
		{
		Get-WindowsPackage -Path $WindowsScratch | where-object {$_.PackageName -like $app2} | Remove-WindowsPackage -Path $WindowsScratch
		}
$SCPath = $WindowsScratch + "\Windows\Setup\Scripts\"
$SCFile = $WindowsScratch + "\Windows\Setup\Scripts\SetupComplete.cmd"
$makeSC =@'
reg load HKLM\zNTUSER "%~dp0WindowsScratch\Users\Default\ntuser.dat" >nul
echo Disabling Teams:
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d "0" /f >nul 2>&1
echo Disabling Sponsored Apps:
Reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d "{\"pinnedList\": [{}]}" /f >nul 2>&1
echo Enabling Local Accounts on OOBE:
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f >nul 2>&1
echo Disabling Reserved Storage:
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f >nul 2>&1
echo Disabling Chat icon:
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f >nul 2>&1
Reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f >nul 2>&1
echo Disabling Hibernate:
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
echo Setting Time Service:
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v "Type" /t REG_SZ /d "NTP" /f >nul 2>&1
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v "NtpServer" /t REG_SZ /d "time.windows.com,pool.ntp.org" /f >nul 2>&1
shutdown /r /t 00
'@
		If (!(Test-Path $SCPath)) {
		New-Item -ItemType Directory -Path $SCPath
		}
		$makeSC | Out-File -filepath $SCFile -Encoding Oem
		Copy-Item -Path $Autounattend  -Destination $SysprepScratch -Force -Verbose
	    Repair-WindowsImage -Path $WindowsScratch -StartComponentCleanup -ResetBase
		Enable-WindowsOptionalFeature -Path $WindowsScratch -FeatureName "NetFx3" -Source $WindowsSXSCached
		Dismount-WindowsImage -Path $WindowsScratch -Save
		Export-WindowsImage -SourceImagePath $WimPath -SourceIndex $indexNumber -DestinationImagePath $Wim2Path -CheckIntegrity -CompressionType max
		Remove-Item -Path $WimPath -Force
		Move-Item -Path $Wim2Path -Destination $WimPath
		Mount-WindowsImage -ImagePath $WimBootPath -Index 2 -Path $WindowsScratch
		Dismount-WindowsImage -Path $WindowsScratch -Save
	$batchfile = $CDir.Path + "\mkimg.bat"	
	$mkbat = @'
	@echo off
	"%~dp0bin\oscdimg.exe" -m -o -u2 -udfver102 -bootdata:2#p0,e,b"%~dp0WindowsCached\boot\etfsboot.com"#pEF,e,b"%~dp0WindowsCached\efi\microsoft\boot\efisys.bin" "%~dp0WindowsCached" "%~dp0Windows_23H2-trimmed.iso"
'@
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
