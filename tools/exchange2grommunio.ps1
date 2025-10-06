<#
# A PowerShell script for Exchange to grommunio migration.
#
# Copyright 2022-2025 Walter Hofstaedtler & grommunio GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
# Authors: grommunio <dev@grommunio.com>
#          Walter Hofstaedtler <walter@hofstaedtler.com>
#>
<# Notice:
#
# This script assumes a correct setup with grommunio attached to the LDAP/AD.
# Script is compatible beginning with Windows Server 2012R2 and PowerShell 2.0.
#>
<# Instructions:
#
# 1. The mailboxes that will be migrated should already exist on the grommunio
#    side or should be automatically created by the parameter $CreateGrommunioMailbox.
#
# 2. Plink.exe must be located in the same directory as the script (latest
#    version available at
#    https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe).
#
# 2.1 Additionally you can use pageant.exe to make use of pubkey based ssh
#    authentication. The latest download is available at
#    https://the.earth.li/~sgtatham/putty/latest/w64/pageant.exe
#
# 3. The shared folder must be available from Windows and Linux (mount.cifs)
#    and have enough space for all .pst files. To conserve disk space, delete
#    the .pst file after each import by setting $DeletePST = $true.
#
# 4. Test the SSH login for plink.exe that it accepts the host key.
#
# 5. Set the variables - how should the migration proceed
#    Here you have to decide if the mailboxes should be created by the script and when the mailboxes should be created.
#
#    If the mailboxes are already created:
#      $CreateGrommunioMailbox = $false
#      $OnlyCreateGrommunioMailbox = $false
#    In this case, the script migrates the Exchange data into existing mailboxes, mailbox by mailbox.
#
#    The mailboxes should be created during the migration process:
#      $CreateGrommunioMailbox = $true
#      $OnlyCreateGrommunioMailbox = $false
#    In this case, the script creates the mailbox and migrates the Exchange data,
#    then creates the next mailbox and migrates the Exchange data, and so on.
#
#    If the mailboxes should be created by the script before the actual migration.
#    This is a 2 pass migration, first all mailboxes are created and in the 2nd pass the Exchange data is migrated:
#      $CreateGrommunioMailbox = $true
#      $OnlyCreateGrommunioMailbox = $true
#    This is especially useful for large migrations, the mailboxes are created in advance,
#    the users may work with Grommunio immediately but still have empty mailboxes,
#    new mails arrive in the mailboxes and the old mails are migrated one by one.
#    For the 2nd pass set the variables like this:
#      $CreateGrommunioMailbox = $false
#      $OnlyCreateGrommunioMailbox = $false
#
#    When the migration is running unattended:
#      $StopOnError = $false
#    Otherwise the script waits for a command from the Administrator in case of an error and that
#    the whole night long. Thereby valuable migration time is destroyed.
#
#    The other settings are explained in the variables.
#
# 6. Launch the script from an (elevated) Exchange Admin shell.
#
#       Optional: Manually launch the Exchange Admin Shell for advanced functionality.
#       The Exchange 2010 Management Shell reports an old PowerShell 2.0.
#       Unfortunately, PowerShell 2.0 is missing some important commands
#       which this script needs for advanced functionality.
#       If you are migrating from Exchange 2010 and want to record the output of the
#       Linux commands in the log, you need to start the PowerShell session with this command:
#       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -version 3.0 -noexit -command ". 'C:\Program Files\Microsoft\Exchange Server\V14\bin\RemoteExchange.ps1'; Connect-ExchangeServer -auto"
#
# 7. Test the migration.
#
# You may see this error:
#
#       New-MailboxExportRequest : The term 'New-MailboxExportRequest' is not
#       recognized as the name of a cmdlet, function, script file, or operable
#       program.
#
# Resolution:
#
# * Add the Administrator to the -Role "Mailbox Import Export"
# * New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "Administrator" | ft -AutoSize
# * After migration, you can reset the membership
# * Remove-RoleGroupMember "Exchange Mailbox Import Export" -Member Administrator
#
# To mount the Windows share on Linux:
#
# 1. install the cifs-utils package
#    SUSE: `zypper in -y cifs-utils`
#    Debian / Ubuntu: `apt install cifs-utils`
#    EL: `yum install cifs-utils`
#
# 2. Create the mount point <shared folder name> in /mnt.
#    mkdir /mnt/<shared folder name>
#
# 3. Mount the Windows share. This needs the Windows user and password.
#    # mount.cifs "//<SERVER FQDN>/<shared folder name>" /mnt/<shared folder name>
#      -v -o ro,username=<Windows user>,password=<Windows password>
#
#   To automount the Windows share, set $AutoMount = $true.
#
# 3.1 Alternatively add a fstab entry and credentials file on the Grommunio Host.
#    Remember so set $AutoMount = $false.
#
#    /etc/fstab - FSTAB(5)
#    ```
#    //SERVER/SHARE$ /mnt/pst cifs auto,_netdev,rw,credentials=/etc/cifscred.import      0       0
#    ```
#
#    /etc/cifscred.import - MOUNT.CIFS(8)
#    ```
#    domain=DOMAINNAME
#    username=USERNAME
#    password=PASSWORD
#    ```
#
# 4. Rinse and repeat!
#    You will likely run multiple tests before doing the actual migration.
#    To remove all Data from the Mailbox but not deleting the Accounts you can
#    run the following command. GROMOX-MBOP(8)
#             !!! ATTENTION - THIS WILL DESTROY ALL DATA !!!
#    # gromox-mbop foreach.here.mb \( echo-username \) \
#    \( XXXemptyfldXXX --nuke-folders IPM_SUBTREE \) \
#    \( purge-softdelete -r IPM_SUBTREE \) \( purge-datafiles \) \
#    \( vacuum \) \( recalc-sizes \) \( unload \)
#
#    (the "XXX" where placed on purpose as a safe option)
#
#

#>

# Check below for a individual configuration file so you won't have to make
# changes in this script directly.

# Variables to be set by the user of this script
#
$GrommunioServer = "grommunio.example.com"

# Shared folder for .pst files on Windows
# The Exchange subsystem needs write rights to this directory.
$WinSharedFolder = "\\<server FQDN>\<shared folder name>"

# Shared folder for .pst files on Linux - the mount point
$LinuxSharedFolder = "/mnt/<shared folder name>"

# Login for the grommunio side shell
$LinuxUser = "root"

# For cleartext password authentication
# set the $LinuxUser's password
# $LinuxUserPWD = "Secret_root_Password"
# For pubkey authentication without a passphrse set
# $LinuxUserSSHKey = "C:\grommunio\exch.ppk"
# For pubkey authentication which needs a password set
# $UsePageant = $true

# #$LinuxUserPWD = ""
# $LinuxUserSSHKey = "C:\grommunio\exch.ppk"
# $UsePageant = $true

# Import only these mailboxes, an array of mail addresses, case insensitive,
# $IgnoreMboxes will be honored.
# To import all mailboxes leave empty, to import only some mailboxes, populate
# $ImportMboxes or leave emtpy if you use the file below instead.
#[string] $ImportMboxes = 'TestI1@example.com','Testi2@example.com'
[string] $ImportMboxes = ''

# TODO: Those could all be called via plink.exe
# To populate a list of users present on the grommunio-host:
#  gromox-mbop foreach.mb echo-username > /mnt/pst/exchange2grommunio.import

# Also note that we will write the names of successfull imports into the
# file called 'exchange2grommunio.done' as with failed attempts the file
# 'exchange2grommunio.failed'. That allows you to do something like:
# % cp exchange2grommunio.{done,ignore}; cp exchange2grommunio.{failed,import}

# This file will only be processed if $ImportMboxes is empty, the file exists
# on the UNC Path and isn't empty.
$ImportFile = "exchange2grommunio.import"

# Ignore these mailboxes, an array of mail addresses, case insensitive
# [string] $IgnoreMboxes = 'TestX1@example.com','Testx2@example.com'
[string] $IgnoreMboxes = ''

# The same rules will apply for $IgnoreFile
# To populate this file with alread imported Mailboxes:
#  awk '/Import of mailbox.*done./ {print $7}' /mnt/pst/exchange2grommunio.log > /mnt/pst/exchange2grommunio.ignore
$IgnoreFile = "exchange2grommunio.ignore"

# Delete .pst files after import to save space.
$DeletePST = $true

# Wait after each mailbox import and allow exiting.
# See $StopMarker how to interrupt migration
$WaitAfterImport = $true

# Stops the script if a mailbox creation or import error occurs
# For unattended import $WaitAfterImport = $false and $StopOnError = $false must be set.
$StopOnError = $true

# Only needed if the script should automount the Windows share on Linux.
# Make sure that the cifs-utils package is installed.
$AutoMount = $true

# Windows user name. Make sure the Windows user exists and has at least read
# permissions on $WinSharedFolder.
$WindowsUser = "<Windows user>"

# Password for $WindowsUser. The password must not contain the characters "$"
# or "!", both of which cause problems in the Linux shell.
$WindowsPassword = "<Windows user password>"

# Create the grommunio mailbox
# LDAP must be configured and also be working. Do test LDAP before import.
$CreateGrommunioMailbox = $false

# Create only the mailboxes, but do not import data
# This sets CreateGrommunioMailbox = $true and $DeletePST = $false
$OnlyCreateGrommunioMailbox = $false

# The language with which all mailboxes are created.
# The languages can be found in: /usr/share/grommunio-admin-api/res/storelangs.json
$MailboxLanguage = "de_DE"

# Stop marker, if $WaitAfterImport = $false, create this file and migration will be interrupted after current mailbox
$StopMarker = "exchange2grommunio.STOP"

# Write timestamps and summary to this log file.
#
$LogFile = "exchange2grommunio.log"

# New-MailboxExportRequest accepts the -Priority parameter.
# Use "Normal" or "High" for Exchange 2010. We found "Normal" is much faster
# than "High".
#
$MigrationPriority = "Normal"

# From here on, no code or variables need changing by the user of this script.

<# SKEL exchange2grommunio.config.ps1
#$GrommunioServer = "grommunio.example.com"
#$WinSharedFolder = "\\<server FQDN>\<shared folder name>"
#$LinuxSharedFolder = "/mnt/<shared folder name>"
#$LinuxUser = "root"
#$LinuxUserPWD = "Secret_root_Password"
#$LinuxUserSSHKey = "C:\grommunio\exch.ppk"
#$UsePageant = $true
#[string] $ImportMboxes = 'TestI1@example.com','Testi2@example.com'
#[string] $ImportMboxes = ''
#$ImportFile = "exchange2grommunio.import"
#$ImportFile = "exchange2grommunio.failed"
#[string] $IgnoreMboxes = ''
#$IgnoreFile = "exchange2grommunio.ignore"
#$IgnoreFile = "exchange2grommunio.done"
#$DeletePST = $true
#$WaitAfterImport = $true
#$StopOnError = $true
#$AutoMount = $true
#$WindowsUser = "<Windows user>"
#$WindowsPassword = "<Windows user password>"
#$CreateGrommunioMailbox = $false
#$OnlyCreateGrommunioMailbox = $false
#$MailboxLanguage = "de_DE"
#$StopMarker = "exchange2grommunio.STOP"
#$LogFile = "exchange2grommunio.log"
#$MigrationPriority = "Normal"
#>
# Use configuration file named "exchange2grommunio.config.ps1" to override the
# configration values above instead of changing the values in this script.
if (Test-Path $PSScriptRoot/exchange2grommunio.config.ps1) {
	. $PSScriptRoot/exchange2grommunio.config.ps1
}

# Overwrite File locations (after eventually sourcing exchange2grommunio.config.ps1)
$StopMarker = Join-Path -Path $WinSharedFolder -ChildPath $StopMarker
$LogFile = Join-Path -Path $WinSharedFolder -ChildPath $LogFile

# Configure Import/Ignore Arrays from defined filename if the rules apply.
$ImportFile = Join-Path -Path $WinSharedFolder -ChildPath $ImportFile
if ((! $ImportMboxes) -and
	(Test-Path -Path $ImportFile) -and
	((Get-Content $ImportFile|Where-Object {$_.trim() -ne "" } ).Length -gt 0)
	) {
		$ImportMboxes = Get-Content $ImportFile
	}
$IgnoreFile = Join-Path -Path $WinSharedFolder -ChildPath $IgnoreFile
if ((! $IgnoreMboxes) -and
	(Test-Path -Path $IgnoreFile) -and
	((Get-Content $IgnoreFile|Where-Object {$_.trim() -ne "" } ).Length -gt 0)
	) {
		$IgnoreMboxes = Get-Content $IgnoreFile
	}


# Write a time stamp and the string to the log file, also write to screen with color.
#
function Write-MLog
{
	Param(
		[parameter(Mandatory=$True)]
		$LogString,
		[parameter(Mandatory=$True)]
		$Color
	)
	# $Color "none" writes to the log file only
	if ($Color -Ne "none") {
		Write-Host "$LogString" -fore $Color
	}
	# populate log file with error state
	$Level = switch ($Color)
	{
		"green"  { "INFO" }
		"yellow" { "WARN" }
		"red"    { "FAIL" }
		"white"  { "" }
		"none"   { "LOG " }
		default  { "????" }
	}
	# add line to log file
	Add-Content -Path $LogFile -Value "$("[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)) $Level $LogString"
}

function Write-UserLog
{
	Add-Content -Path $ImpLogFile -Value "$("[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)) $args"
}

# Check lock of file by Windows
#
function isLocked
{
	Param(
		[parameter(Mandatory=$True)]
		$filename
	)
	$LockedFile = $False
	$file = Get-Item (Resolve-Path $filename) -Force
	if ($file.Exists) {
		Try {
			$stream = New-Object system.IO.StreamReader $file
		}
		Catch {
			$LockedFile = $True
		}
		if ($LockedFile) {
			return $True
		} else {
			if ($stream) {
				$stream.Close()
			}
			return $False
		}
	}
}

# If we don't set $LinuxUserPWD we should either have pageant running with
# an imported ssh-key or we just use '-key keyfile' with plink.
# https://the.earth.li/~sgtatham/putty/0.83/htmldoc/Chapter7.html#plink
$PLINKARGS = @(
	if ($null -ne $Debug) {
		'-v'
	}
	if ($null -ne $LinuxUserPWD) {
		'-noagent'
		'-pw'
		"$LinuxUserPWD"
	} else {
		'-agent'
		if ($null -eq $UsePageant) {
			'-i'
			"$LinuxUserSSHKey"
		}
	}
		'-ssh'
		'-batch'
		"$LinuxUser@$GrommunioServer"
)

# Mount the Windows shared folder via CIFS
#
function Linux-Mount
{
	if ($AutoMount) {
		Write-MLog "mkdir -p $LinuxSharedFolder" green
		if ($PowerShellOld) {
			.\plink.exe @PLINKARGS "mkdir -p $LinuxSharedFolder"
		} else {
			.\plink.exe @PLINKARGS "mkdir -p $LinuxSharedFolder" 2>&1 | Foreach-Object ToString | Tee-Object -Variable TeeVar
			# Save plink output to $LogFile
			Write-MLog "---" none
			Add-Content -Path $LogFile -Value $TeeVar
			Write-MLog "---" none
		}
		$WinFolder = $WinSharedFolder.replace('\','/')
		Write-MLog "mount.cifs $LinuxSharedFolder" green
		if ($PowerShellOld) {
			.\plink.exe @PLINKARGS "mount.cifs -v '$WinFolder' '$LinuxSharedFolder' -o user='$WindowsUser',password='$WindowsPassword',ro"
		} else {
			.\plink.exe @PLINKARGS "mount.cifs -v '$WinFolder' '$LinuxSharedFolder' -o user='$WindowsUser',password='$WindowsPassword',ro" 2>&1 | Foreach-Object ToString | Tee-Object -Variable TeeVar
			# Save plink output to $LogFile
			Write-MLog "---" none
			Add-Content -Path $LogFile -Value $TeeVar
			Write-MLog "---" none
		}
		Write-MLog "" white
	}
}

# Unmount the Windows shared folder
#
function Linux-Umount
{
	if ($AutoMount) {
		Write-MLog "umount $LinuxSharedFolder" green
		if ($PowerShellOld) {
			.\plink.exe @PLINKARGS "umount $LinuxSharedFolder"
		} else {
			.\plink.exe @PLINKARGS "umount $LinuxSharedFolder" 2>&1 | Foreach-Object ToString | Tee-Object -Variable TeeVar
			# Save plink output to $LogFile
			Write-MLog "---" none
			Add-Content -Path $LogFile -Value $TeeVar
			Write-MLog "---" none
		}
		Write-MLog "" white
	}
}

# Test if plink.exe exists in $PSScriptRoot
#
function Test-Plink
{
	Write-MLog "" white
	# does plink.exe exist?
	if (!(Test-Path -Path $PSScriptRoot\plink.exe)) {
		Write-MLog "Error: plink.exe not found, need plink.exe in $PSScriptRoot." red
		exit 1
	}
}

# Test if pageant.exe exists in $PSScriptRoot
#
function Test-Pageant
{
	Write-MLog "" white
	# is pageant.exe running?
	if (!(Get-Process -ErrorAction ignore pageant)) {
		Write-MLog "Error: pageant.exe not running, either set \$LinuxUserPWD or start pageant.exe manually and import the key." red
		exit 1
	}
}

# Test if the Exchange cmdlets are loaded
#
$Exchange_Newer_2016_CU6 = $true
function Test-Exchange
{
	$Exchange_Cmdlets = $false
	if (Get-PSSnapin -Registered Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction SilentlyContinue) {
		# Exchange 2007 cmdlets are loaded
		$Exchange_Cmdlets = $true
	}
	if (Get-PSSnapin -Registered Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction SilentlyContinue) {
		# Exchange 2010 cmdlets are loaded
		$Exchange_Cmdlets = $true
	}
	if (Get-PSSnapin -Registered Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue) {
		# Exchange 2013, 2016, 2019 cmdlets are loaded
		$Exchange_Cmdlets = $true
	}
	if (!$Exchange_Cmdlets) {
		Write-MLog "Error: the Exchange cmdlets are not loaded. Launch this script from an Exchange Admin shell." red
		exit 1
	}
}

# The Main code
#
# Do we use an old PowerShell == Version 2.0?
#
$PowerShellOld = ($PSVersionTable.PSVersion.Major -eq 2)

# This construct works only in main. PS v2.0 does not provide $PSScriptRoot.
#
if (!$PSScriptRoot) {
	$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}

# Test if $WinSharedFolder is a valid path
#
if (!( $(Try { Test-Path $WinSharedFolder.trim() } Catch { $false }) )) {  #Returns $false if $null, "" or " "
	Write-Host ""
	Write-Host "'$WinSharedFolder' is not a valid path, please update variable `$WinSharedFolder and try again." -fore red
	exit 1
}

# Initialize variables for statistics
#
$MailboxesTotal = 0
$MailboxesSkipped = 0
$MailboxesCreated = 0
$MailboxesCreateFailed = 0
$MailboxesImported = 0
$MailboxesImportFailed = 0
$MailboxesExported = 0
$MailboxesExportFailed = 0
$MailboxesMB = 0
$CreateErrorsMBX = ""
$ImportErrorsMBX = ""
$ExportErrorsMBX = ""
$ScriptStartDate = (GET-DATE)

# Create / append Log
#
Write-MLog "" none
Write-MLog "" none
Write-MLog "===========================================================================" none
Write-MLog "" white
Write-MLog "" white
Write-Mlog "***** Exchange to grommunio Migration *****" green
Write-MLog "" white

if ($PowerShellOld) {
	Write-Mlog "We use an old V2.x PowerShell" yellow
} else {
	Write-Mlog "We use a new PowerShell, V.: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" green
}
Write-MLog "" white

if ($OnlyCreateGrommunioMailbox ) {
	$DeletePST = $false
	$CreateGrommunioMailbox = $true
}

# Remove all spaces before and after the mail address lists
#
$ImportMboxes = $ImportMboxes.trim()
$IgnoreMboxes = $IgnoreMboxes.trim()

# Document settings in log
#
Write-MLog "Settings" none
Write-MLog "`$GrommunioServer ...........: $GrommunioServer" none
Write-MLog "`$WinSharedFolder ...........: $WinSharedFolder" none
Write-MLog "`$LinuxSharedFolder .........: $LinuxSharedFolder" none
Write-MLog "`$LinuxUser .................: $LinuxUser" none
Write-MLog "`$ImportMboxes ..............: $ImportMboxes" none
Write-MLog "`$IgnoreMboxes ..............: $IgnoreMboxes" none
Write-MLog "`$DeletePST .................: $DeletePST" none
Write-MLog "`$WaitAfterImport ...........: $WaitAfterImport" none
Write-MLog "`$StopOnError ...............: $StopOnError" none
Write-MLog "`$AutoMount .................: $AutoMount" none
Write-MLog "`$WindowsUser ...............: $WindowsUser" none
Write-MLog "`$CreateGrommunioMailbox ....: $CreateGrommunioMailbox" none
Write-MLog "`$OnlyCreateGrommunioMailbox : $OnlyCreateGrommunioMailbox" none
Write-MLog "`$MailboxLanguage ...........: $MailboxLanguage" none
Write-MLog "`$StopMarker ................: $StopMarker" none

Write-MLog "`$LogFile ...................: $LogFile" none
Write-MLog "`$MigrationPriority .........: $MigrationPriority" none
Write-MLog "" none
Write-MLog "`$PowerShellOld .............: $PowerShellOld" none
Write-MLog "`$PSScriptRoot ..............: $PSScriptRoot" none
Write-MLog "`$Exchange_Newer_2016_CU6....: $Exchange_Newer_2016_CU6" none
Write-MLog "" none

# Check for prerequisites
#
Test-Plink
if ($UsePageant) {
	Test-Pageant
	if (Test-Path -Path $PSScriptRoot\pageant.exe) {
	.\pageant.exe  $LinuxUserSSHKey
	}
}
Test-Exchange
Linux-Mount

# If we get a create error, do not import the mailbox.
#
$SkipImportCreateError = $false

#
# The migration loop
#
foreach ($Mailbox in (Get-Mailbox | Sort-Object -Property Alias)) {
	$MigMBox = $Mailbox.PrimarySmtpAddress.ToString().ToLower()
	$LogPath = (Join-Path -Path $WinSharedFolder -ChildPath logs)
	New-Item -Path $LogPath -ErrorAction Ignore -Type Directory
	$ImpLogFile = Join-Path -Path $LogPath -ChildPath ($MigMbox + "." + (Get-Date -Format FileDate) + ".import.log")
	$ExpLogFile = Join-Path -Path $LogPath -ChildPath ($MigMbox + "." + (Get-Date -Format FileDate) + ".export.json")
	Write-Debug "`nMigMBox: $MigMBox`nImpLogFile: $ImpLogFile`nExpLogFile: $ExpLogFile"


	if ($ImportMboxes.length -gt 5) {
		# Use $ImportMboxes only if it contains a minimum of one mail address
		if ($ImportMboxes.ToLower().contains($MigMBox.ToLower())) {
			Write-MLog "Mailbox: $MigMBox found in `$ImportMboxes list." green
		} else {
			$MailboxesSkipped++
			$MailboxesTotal++
			Write-MLog "Ignoring mailbox: $MigMBox, mailbox not in `$ImportMboxes list." yellow
			continue
		}
	} # if ($ImportMboxes.length -gt 5)

	if ($IgnoreMboxes.ToLower().contains($MigMBox.ToLower())) {
		$MailboxesSkipped++
		$MailboxesTotal++
		Write-MLog "Ignoring mailbox: $MigMBox, found mailbox in `$IgnoreMboxes list." yellow
		continue
	}
	Write-MLog "" white
	# Clean up before exporting a mailbox
	# Remove all MailboxExportRequest, to make check for "Completed" more robust

	Write-MLog "Removing all MailboxExportRequests." green
	Get-MailboxExportRequest | Remove-MailboxExportRequest -Confirm:$false

	# Remove old / orphaned .pst file
	if (Test-Path -Path $WinSharedFolder\$MigMBox.pst) {
		Remove-Item -ErrorAction SilentlyContinue -Path $WinSharedFolder\$MigMBox.pst
		Write-MLog "Removing outdated $MigMBox.pst file." yellow
	}
	Write-MLog "" white

	if (!$OnlyCreateGrommunioMailbox ) {
		# Create a .pst file for every mailbox found on system.
		#
		Write-MLog "Exporting mailbox $MigMBox to file $MigMBox.pst..." green

		# -Mailbox
		#
		# The Mailbox parameter specifies the source mailbox where the
		# contents are being exported from.
		#
		# In Exchange 2016 CU7 or later, this parameter is the type
		# MailboxLocationIdParameter, so the easiest value that you can
		# use to identify the mailbox is the Alias value.
		#
		# In Exchange 2016 CU6 or earlier, this parameter is the type
		# MailboxOrMailUserIdParameter, so you can use any value that
		# uniquely identifies the mailbox.
		#
		# https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps
		#
		# Exchange 2010 only supports "Normal, High" for the -Priority parameter
		#
		if ($Exchange_Newer_2016_CU6) {
			$Mailbox = $Mailbox.Alias
		}

		New-MailboxExportRequest -Mailbox $Mailbox -FilePath $WinSharedFolder\$MigMBox.pst -Priority $MigrationPriority -ExcludeDumpster | Format-Table -HideTableHeaders
		Write-Host -NoNewline "[Wait] " -fore yellow
		$MailboxesTotal++

		# Wait until the .pst file is created.
		# We probably should include a timeout to detect hanging exports.
		$expPercent= 0; $OneHundredPercent = 0;
		while ($true) {
			$expRequest = (Get-MailboxExportRequest $Mailbox)
			$expPercent = ($expRequest |Get-MailboxExportRequestStatistics |Select-Object PercentComplete).PercentComplete
			$expStatus = ($expRequest).Status
			Write-Progress -Id 1 -Activity "Export: $Mailbox" -Status "$expPercent% Complete:" -PercentComplete $expPercent;
			Start-Sleep -Seconds 1
			Write-Debug "DEBUG: $expStatus / $expPercent"
			# Check if we didn't run into any issues while waiting
			# https://learn.microsoft.com/en-us/powershell/module/exchange/get-mailboxexportrequest?view=exchange-ps#-status
			if (($expStatus -eq ("Completed")) -and ($expPercent -eq 100)) {
				$MailboxesExport++
				break
			}
			if ($expPercent -eq 100) {
				$OneHundredPercent++
				Write-Debug "100% but not finished loop: $$OneHundredPercent"
			}
			if ($OneHundredPercent -gt 50) {
				break
			}
			if ($expStatus -iin ("AutoSuspended","CompletedWithWarning","Failed","Suspended")) {
				Write-MLog "Error: Export Result: $expStatus" red
				$expRequest | Get-MailboxExportRequestStatistics -IncludeReport -Diagnostic| ConvertTo-Json |Add-Content -Path $ExpLogFile + ".diagnostic"
				$MailboxesExportFailed++
				$ExportErrorsMBX += $MigMBox + ", "
				$SkipImportCreateError = $true
				break
			}

		}
		# End display of progress bar
		Write-Progress -Id 1 -Completed -Activity "Export: $Mailbox"

		# Export
		Get-MailboxExportRequest $Mailbox | Get-MailboxExportRequestStatistics -IncludeReport | ConvertTo-Json |Add-Content -Path $ExpLogFile
		Get-MailboxExportRequest $Mailbox | Remove-MailboxExportRequest -Confirm:$false
		Write-MLog "" white
		Write-MLog "Export of mailbox $MigMBox took $nTimeout seconds." green

		# Show size of exported mailbox in MB.
		if (Test-Path $WinSharedFolder\$MigMBox.pst) {
			if ((Get-Item $WinSharedFolder\$MigMBox.pst).length -gt 0mb) {
				$size = [math]::ceiling($(Get-Item $WinSharedFolder\$MigMBox.pst).length/(1024*1024))
				Write-MLog "Size of mailbox $MigMBox.pst is $size MB" green
			}
		} else {
			Write-MLog "Error mailbox $MigMBox.pst do not exist!" red
			# Do not import this mailbox
			$SkipImportCreateError = $true
		}

		Write-MLog "" white
		Write-Mlog "Wait until the file lock of .pst file is released." yellow

		# Wait until the file lock of .pst file is released, Timeout is 300 seconds.
		$nTimeout = 0
		Write-Host -NoNewline "[Unlock] " -fore yellow
		While ($nTimeout -lt 300) {
			if (isLocked $WinSharedFolder\$MigMBox.pst) {
				Write-Host -NoNewline "." -fore yellow
			} else {
				Write-Host -NoNewline " "
				Write-MLog "PST lock cleared, after $nTimeout seconds." green
				$MailboxesExported++
				break
			}
			start-sleep -seconds 2
			$nTimeout += 2
		}
	}

	Write-MLog "" white

	# If requested, create the grommunio mailbox.
	if ($CreateGrommunioMailbox) {
		Write-MLog "Create grommunio mailbox: $MigMBox." green
		if ($PowerShellOld) {
			.\plink.exe @PLINKARGS "grommunio-admin ldap downsync -l $MailboxLanguage $MigMBox"
			$CMDExitCode = $lastexitcode
		} else {
			.\plink.exe @PLINKARGS "grommunio-admin ldap downsync -l $MailboxLanguage $MigMBox" 2>&1 | Foreach-Object ToString | Tee-Object -Variable TeeVar
			$CMDExitCode = $lastexitcode
			# Save plink output to $LogFile
			Write-MLog "---" none
			Add-Content -Path $LogFile -Value $TeeVar
			Write-MLog "---" none
		}
		if ($CMDExitCode -eq 0) {
			Write-Mlog "Mailbox: $MigMBox created successfully." green
			$MailboxesCreated++
		} else {
			Write-MLog "Creation of mailbox: $MigMBox failed." red
			$MailboxesCreateFailed++
			$CreateErrorsMBX += $MigMBox + ", "
			if ($StopOnError) {
				$WaitAfterImport = $true
			}
			$SkipImportCreateError = $true
		}
	}

	if ( (!$SkipImportCreateError) -and (!$OnlyCreateGrommunioMailbox) ) {
		Write-MLog "" white
		$ImportStartDate=(GET-DATE)

		# Using plink, start importing this mailbox and .pst
		# file on the grommunio host.
		Write-MLog "Starting import of mailbox: $MigMBox in grommunio." green
		Write-UserLog "Starting import of mailbox: $MigMBox in grommunio."
		Write-UserLog ""
		if ($PowerShellOld) {
			.\plink.exe @PLINKARGS "gromox-e2ghelper -u $MigMBox -- -s $LinuxSharedFolder/$MigMBox.pst"
			$CMDExitCode = $lastexitcode
		} else {
			.\plink.exe @PLINKARGS "gromox-e2ghelper -u $MigMBox -- -s $LinuxSharedFolder/$MigMBox.pst" 2>&1 | Foreach-Object ToString | Tee-Object -Variable TeeVar
			$CMDExitCode = $lastexitcode
			# Save plink output to $LogFile
			Write-MLog "---" none
			#$TeeVar = $TeeVar.replace("`r`n`r","`r`n")
			#$TeeVar = $TeeVar.replace("`n`r`n","`r`n")
			Add-Content -Path $LogFile -Value $TeeVar
			Write-UserLog "$TeeVar"
			Write-MLog "---" none
		}
		if ($CMDExitCode -eq 0) {
			Write-MLog "Import of mailbox: $MigMBox done." green
			Write-UserLog "Import of mailbox: $MigMBox done."
			Add-Content -Path (Join-Path -Path $WinSharedFolder -ChildPath exchange2grommunio.done) -Value $MigMbox
			$MailboxesImported++
			$MailboxesMB += $size
		} else {
			Write-MLog "Mailbox: $MigMBox imported with errors." red
			Write-UserLog "Mailbox: $MigMBox imported with errors."
			$MailboxesImportFailed++
			Add-Content -Path (Join-Path -Path $WinSharedFolder -ChildPath exchange2grommunio.failed) -Value $MigMbox
			$ImportErrorsMBX += $MigMBox + ", "
			# Wait for admin to make a decision.
			if ($StopOnError) {
				$WaitAfterImport = $true
			}
		}
		# Show import time in seconds.
		$ImportEndDate = (GET-DATE)
		$Duration = [math]::ceiling($(NEW-TIMESPAN -Start $ImportStartDate -End $ImportEndDate).TotalSeconds)
		Write-MLog "Import of mailbox $MigMBox took $Duration seconds." green
		Write-UserLog "Import of mailbox $MigMBox took $Duration seconds."
	}

	# Try to import the next mailbox.
		$SkipImportCreateError = $false

	if ($DeletePST) {
		Write-MLog "Remove the imported .pst file: $WinSharedFolder\$MigMBox.pst to save disk space." green
		if (Test-Path -Path $WinSharedFolder\$MigMBox.pst) {
			Remove-Item -ErrorAction SilentlyContinue -Path $WinSharedFolder\$MigMBox.pst
		} else {
			Write-MLog "Error .pst file: $WinSharedFolder\$MigMBox.pst not found." red
		}
	}
	Write-MLog "" white
	Write-MLog "Total of $MailboxesTotal mailboxes processed, $MailboxesSkipped mailboxes skipped, $MailboxesCreated mailboxes created, $MailboxesImported mailboxes imported, " yellow
	Write-MLog "$MailboxesCreateFailed mailboxes creation failed, $MailboxesImportFailed imports failed. $MailboxesMB MB of mailbox data imported." yellow
	Write-MLog "" white

	# if $StopMarker exists, interrupt migration and ask the Admin
	if (Test-Path -Path $StopMarker) {
		$WaitAfterImport = $true
		Write-MLog "Stop marker: $StopMarker found, interrupting migration." yellow
	}

	if (!$WaitAfterImport) {
		continue
	}
	Write-MLog "" white
	$decision = "Y"
	$OK = $false
	while (!$OK) {
		Write-MLog "Do you want to proceed with the next mailbox [Y]es [A]bort [C]ontinue? " none
		$decision = $(Write-Host "Do you want to proceed with the next mailbox [Y]es [A]bort [C]ontinue? " -fore yellow -NoNewLine; Read-Host)
		$decision = $decision.ToUpper()
		switch ($decision) {
		"Y" {
			Write-MLog "Import next mailbox" green
			$OK = $true
		}
		"A" {
			Write-MLog "Exiting upon request." red
			$OK = $true
		}
		"C" {
			Write-MLog "Continue without prompts until an error" green
			$WaitAfterImport = $false
			$OK = $true
		}
		}
	}
	if ($decision -eq "A") {
		break
	}
}

Linux-Umount

# Remove all "Completed" MailboxExportRequests.
#
Get-MailboxExportRequest | Where-Object {$_.status -eq "Completed"} | Remove-MailboxExportRequest -Confirm:$false

# Calculate script run time
#
$ScriptEndDate = (GET-DATE)
$ScriptDuration = [math]::ceiling($(NEW-TIMESPAN -Start $ScriptStartDate -End $ScriptEndDate).TotalMinutes)

# Print summary
#
Write-MLog "" white
Write-MLog "Total of $MailboxesTotal mailboxes processed" green
Write-MLog "$MailboxesSkipped mailboxes skipped" yellow
if ($CreateGrommunioMailbox) {
	Write-MLog "$MailboxesCreated mailboxes created" green
	if ($MailboxesCreateFailed -ne 0) {
		Write-MLog "$MailboxesCreateFailed mailboxes creation failed" red
		Write-MLog "Affected mailboxes: $CreateErrorsMBX" red
	}
}
Write-MLog "$MailboxesImported mailboxes imported" green
if ($MailboxesImportFailed -ne 0) {
	Write-MLog "$MailboxesImportFailed mailboxes imported with errors or import failed" red
	Write-Mlog "Affected mailboxes: $ImportErrorsMBX" red
}
if ($MailboxesExportFailed -ne 0) {
	Write-MLog "$MailboxesExportFailed mailboxes couldn't be exported" red
	Write-Mlog "Affected mailboxes: $ExportErrorsMBX" red
}
Write-MLog "Imported a total of $MailboxesMB MB of mailbox data" green
Write-MLog "Total run time: $ScriptDuration minutes. Started: $ScriptStartDate, ended: $ScriptEndDate." green
Write-MLog "" white
Write-MLog "Remove possibly orphaned .pst files from $WinSharedFolder" yellow
Write-MLog "Import finished." green
Write-MLog "" white
